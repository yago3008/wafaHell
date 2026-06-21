# from .model import Base, Blocked, WafLog, Whitelist, get_session, engine
# from .logger import Logger
# from .rateLimiter import RateLimiter
# from .panel import setup_dashboard
# from .utils import Admin, seed_default_whitelist
# from .globals import waf_cache
import urllib
import json as py_json
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone 
import re
import time
import threading
from flask import Flask, json, request as req, abort, g
from urllib.parse import unquote
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from werkzeug.exceptions import HTTPException as WerkzeugHTTPException
import hashlib
import uuid
import socket
import ipaddress
import os

try:
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse
except Exception:
    FastAPI = None
    PlainTextResponse = None

try:
    from a2wsgi import WSGIMiddleware
except Exception:
    WSGIMiddleware = None

try:
    from model import Base, Blocked, CriticalPaths, WafLog, Whitelist, get_session, engine
    from logger import Logger
    from rateLimiter import RateLimiter
    from panel import setup_dashboard
    from utils import Admin, seed_default_whitelist
    from globals import waf_cache
    from ml_pipeline import get_ml_engine
except ImportError:
    from .model import Base, Blocked, CriticalPaths, WafLog, Whitelist, get_session, engine
    from .logger import Logger
    from .rateLimiter import RateLimiter
    from .panel import setup_dashboard
    from .utils import Admin, seed_default_whitelist
    from .globals import waf_cache
    from .ml_pipeline import get_ml_engine


# Inicializa o RateLimiter
limiter = RateLimiter(limit=100, window=60)

class Wafahell:
    """
    Motor principal de segurança do Framework WafaHell.
    
    Implementa o padrão Singleton para garantir uma única instância de controle 
    sobre a aplicação Flask. Gerencia a detecção de ameaças (SQLi, XSS), 
    controle de fluxo (Rate Limit, Whitelist), persistência de auditoria 
    e métricas de performance (RPS e Latência).
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        """Garante que apenas uma instância do WAF exista durante a execução do servidor."""
        if not cls._instance:
            cls._instance = super(Wafahell, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, app: Flask = None, block_code: int = 403, block_durantion: int = 5, block_ip: bool = False, log_func: callable = None, monitor_mode: bool = False, rate_limit: bool = False, dashboard_path: str = None, ai_treshold: float = 0.70, *, block_duration: int = None, ai_threshold: float = None):
        """
        Inicializa o WAF com as configurações de bloqueio e monitoramento.
        
        Define as regras de filtragem baseadas em assinaturas (Regex) e configura 
        os estados internos de cache e auditoria.
        """
        if not hasattr(self, 'initialized'):
            self.initialized = True
            
            self.app = app
            self.block_code = block_code
            self.log = log_func or Logger()
            self.monitor_mode = monitor_mode
            self.block_ip = block_ip
            self.rate_limit = rate_limit
            self.dashboard_path = dashboard_path
            resolved_block_duration = block_durantion if block_duration is None else block_duration
            resolved_ai_threshold = ai_treshold if ai_threshold is None else ai_threshold
            self.block_duration = resolved_block_duration
            self.block_durantion = resolved_block_duration
            self.recent_blocks_cache = {}
            self._batch_lock = threading.Lock()
            self._pending_logs_batch = []
            self._last_log_flush_time = 0.0
            self.port = None
            self.ip = None
            self.ai_threshold = resolved_ai_threshold
            self.ai_treshold = resolved_ai_threshold
            self.ai_engine = get_ml_engine()

            if not self.app:
                raise ValueError(" * [Waffahell] O atributo 'app' é obrigatório e não pode ser vazio.")
            self.framework = self._detect_framework(app)
            if not self.framework:
                raise TypeError(
                    f" * [Waffahell] O atributo 'app' deve ser Flask ou FastAPI, mas recebeu {type(app).__name__}."
                )
            self._init_app(self.app)

    def _detect_framework(self, app) -> str | None:
        if isinstance(app, Flask):
            return "flask"
        if FastAPI is not None and isinstance(app, FastAPI):
            return "fastapi"
        return None

    def _build_fastapi_request_context(self, request, body: bytes, session):
        headers = dict(request.headers)
        content_type = headers.get("content-type", "")
        body_text = body.decode(errors="ignore") if body else ""

        form_data = {}
        json_body = None
        is_json = "application/json" in content_type

        if is_json and body_text:
            try:
                json_body = py_json.loads(body_text)
            except Exception:
                json_body = None
        elif ("application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type) and body_text:
            try:
                from urllib.parse import parse_qs
                parsed_form = parse_qs(body_text, keep_blank_values=True)
                form_data = {k: v[0] if isinstance(v, list) and v else "" for k, v in parsed_form.items()}
            except Exception:
                form_data = {}

        base_url = str(request.url).split("?")[0]

        def _get_json(silent=True):
            return json_body

        return SimpleNamespace(
            method=request.method,
            path=request.url.path,
            base_url=base_url,
            args=dict(request.query_params),
            form=form_data,
            headers=headers,
            data=body,
            is_json=is_json,
            get_json=_get_json,
            cookies=dict(request.cookies),
            remote_addr=request.client.host if request.client else "unknown",
            session=session,
        )

    def _register_fastapi_hooks(self, app) -> None:
        if FastAPI is None:
            raise RuntimeError("FastAPI não está instalado. Execute: pip install fastapi uvicorn")

        @app.middleware("http")
        async def _waf_fastapi(request, call_next):
            start_time = time.time()
            session = None
            req_ctx = None
            try:
                session = get_session()
                body = await request.body()

                # Reinjeta body para os handlers da aplicação continuarem lendo normalmente.
                async def _receive():
                    return {"type": "http.request", "body": body, "more_body": False}

                request._receive = _receive

                req_ctx = self._build_fastapi_request_context(request, body, session)

                # Rotas internas do dashboard não devem ser tratadas como tráfego atacante.
                if self._is_internal_request_path(req_ctx.path):
                    response = await call_next(request)
                    return self._finalize_request_metrics(req_ctx, response, start_time)

                if not self.check_whitelist(req_ctx):
                    self.verify_client_blocked(req_ctx)

                    if self.verify_critical_path_attack(req_ctx):
                        return PlainTextResponse("Blocked by WafaHell", status_code=self.block_code)

                    self.verify_rate_limit(req_ctx)
                    is_malicious, attack_local, payload, attack_type = self.is_malicious(req_ctx)

                    if is_malicious:
                        self.log_attack(req_ctx, attack_type, payload, attack_local)

                        if not self.monitor_mode:
                            self.log.warning(self.parse_req(req_ctx, payload, attack_local, attack_type))
                            if self.block_ip:
                                self.log_block(req_ctx)
                                self.block_ip_address(
                                    req_ctx.remote_addr,
                                    req_ctx.headers.get("User-Agent", "unknown"),
                                    session=req_ctx.session,
                                )
                            return PlainTextResponse("Blocked by WafaHell", status_code=self.block_code)
                        else:
                            self.log.info(self.parse_req(req_ctx, payload, attack_local, attack_type))

                response = await call_next(request)
                return self._finalize_request_metrics(req_ctx, response, start_time)

            except WerkzeugHTTPException as blocked_exc:
                code = blocked_exc.code or self.block_code
                return PlainTextResponse("Blocked by WafaHell", status_code=code)
            except Exception as e:
                self.log.error(f"Erro no middleware FastAPI: {e}")
                return PlainTextResponse("Blocked by WafaHell", status_code=self.block_code)
            finally:
                if session is not None:
                    session.close()

    def _finalize_request_metrics(self, req_obj, response, start_time: float):
        if self._is_internal_request_path(req_obj.path):
            return response

        if response.status_code != self.block_code:
            self.log_legit_access(req_obj)

        current_timestamp = int(time.time())
        rps_key = f"rps_{current_timestamp}"
        waf_cache.incr(rps_key, default=0)
        waf_cache.expire(rps_key, 10)

        latency = (time.time() - start_time) * 1000
        old_avg = waf_cache.get("latency_avg", default=0.0)
        new_avg = (old_avg * 0.95) + (latency * 0.05) if old_avg > 0 else latency
        waf_cache.set("latency_avg", new_avg, expire=3600)

        return response

    def _is_internal_request_path(self, path: str) -> bool:
        if not path:
            return False
        if path.startswith("/static"):
            return True

        if not self.dashboard_path:
            return False

        base = self.dashboard_path.rstrip("/")
        if path.startswith(f"{base}/static/"):
            return True

        internal_exact = {
            base,
            f"{base}/",
            f"{base}/login",
            f"{base}/data",
            f"{base}/stats",
            f"{base}/vars",
            f"{base}/vars/change",
            f"{base}/graphs",
            f"{base}/blocked_list",
            f"{base}/unblock_ip",
            f"{base}/block_ip",
            f"{base}/import_blacklist",
            f"{base}/import_whitelist",
            f"{base}/import_critical_paths",
            f"{base}/mock",
            f"{base}/mock/status",
            f"{base}/mock/run",
            f"{base}/mock/run/single",
            f"{base}/mock/payloads",
            f"{base}/export/csv",
        }
        return path in internal_exact

    def _mount_fastapi_dashboard(self, app) -> None:
        if WSGIMiddleware is None:
            raise RuntimeError("O adaptador a2wsgi nao esta instalado.")

        mount_path = (self.dashboard_path or "/admin/dashboard").rstrip("/")
        if not mount_path.startswith("/"):
            mount_path = f"/{mount_path}"
        self.dashboard_path = mount_path

        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        dashboard_app = Flask(
            "wafahell_fastapi_dashboard",
            template_folder=template_dir,
        )
        dashboard_app.secret_key = self._create_secret_key()

        # Starlette removes mount_path before forwarding the request to Flask.
        setup_dashboard(dashboard_app, custom_path="")
        app.mount(mount_path, WSGIMiddleware(dashboard_app), name="wafahell_dashboard")

    @staticmethod
    def _create_secret_key() -> str:
        mac_address = str(uuid.getnode())
        hostname = socket.gethostname()
        project_salt = "wafahell-security-core-v1"
        fingerprint = f"{mac_address}-{hostname}-{project_salt}"
        return hashlib.sha256(fingerprint.encode()).hexdigest()

    def _init_app(self, app) -> None:
        """
        Acopla a lógica do WAF ao ciclo de vida das requisições do Flask.
        
        Configura o banco de dados, dashboard, autenticação administrativa 
        e registra os hooks de interceptação (before/after request).
        """
        Base.metadata.create_all(engine)
        seed_default_whitelist()
        Admin.create_admin_user(get_session())

        if self.framework == "fastapi":
            self._register_fastapi_hooks(app)
            self._mount_fastapi_dashboard(app)
            return

        setup_dashboard(app, self.dashboard_path)

        if not app.secret_key:
            app.secret_key = self._create_secret_key()


        @app.before_request
        def _create_session():
            try:
                req.session = get_session()
            except Exception as e:
                self.log.error(f"Erro ao criar sessão para requisição: {e}")
                abort(self.block_code)

        @app.teardown_request
        def _close_session(exc=None):
            if hasattr(req, 'session'):
                try:
                    req.session.close()
                except Exception as e:
                    self.log.error(f"Erro ao fechar sessão: {e}")
        

        @app.before_request
        def _waf_check():
            """
            Pipeline principal de inspeção de segurança (Ingress Protection).
            
            Executa na seguinte ordem:
            1. Validação de Whitelist (IPs confiáveis).
            2. Verificação de IPs bloqueados (Blacklist ativa).
            3. Proteção de Caminhos Críticos.
            4. Controle de Frequência (Rate Limit).
            5. Inspeção de Payload (Heurística de Malícia).
            """
            if self._is_internal_request_path(req.path):
                return

            if self.check_whitelist(req):
                return
            
            self.verify_client_blocked(req)

            if self.verify_critical_path_attack(req):
                abort(self.block_code)

            self.verify_rate_limit(req)
            is_malicious, attack_local, payload, attack_type = self.is_malicious(req)
            
            if not is_malicious:
                return
            
            self.log_attack(req, attack_type, payload, attack_local)
            
            if not self.monitor_mode:
                self.log.warning(self.parse_req(req, payload, attack_local, attack_type))
                if self.block_ip:
                    self.log_block(req)
                    self.block_ip_address(req.remote_addr, req.headers.get("User-Agent", "unknown"), session=req.session)
                abort(self.block_code)
            else:
                self.log.info(self.parse_req(req, payload, attack_local, attack_type))

        @app.before_request
        def _start_timer():
            g.waf_start_time = time.time()

        @app.after_request
        def _stop_timer(response):
            """
            Coleta métricas de observabilidade e telemetria (Egress Monitoring).
            
            Calcula a latência da requisição usando EMA (Exponential Moving Average) 
            e contabiliza o tráfego para cálculo de RPS (Requests Per Second), 
            ignorando rotas administrativas do painel.
            """
            start_time = g.waf_start_time if hasattr(g, 'waf_start_time') else time.time()
            return self._finalize_request_metrics(req, response, start_time)
            ignored_paths = [self.dashboard_path, f'{self.dashboard_path}/stats', '/static']

            # 1. Ignora rotas do próprio painel para não sujar os logs e métricas
            if any(req.path.startswith(path) for path in ignored_paths if path):
                return response
            
            # 2. LOG DE TRÁFEGO LEGÍTIMO
            # Se o status_code for menor que 400, significa que o WAF não deu abort()
            # e a requisição seguiu o fluxo normal.
            if response.status_code != self.block_code:
                self.log_legit_access(req)

            # 3. RPS Logic (Bucketing by second)
            current_timestamp = int(time.time())
            rps_key = f"rps_{current_timestamp}"
            waf_cache.incr(rps_key, default=0)
            waf_cache.expire(rps_key, 10)

            if hasattr(g, 'waf_start_time'):
                latency = (time.time() - g.waf_start_time) * 1000
                
                old_avg = waf_cache.get('latency_avg', default=0.0)
                new_avg = (old_avg * 0.95) + (latency * 0.05) if old_avg > 0 else latency
                
                waf_cache.set('latency_avg', new_avg, expire=3600)
                
            return response
    
    def _normalize_path(self, path: str) -> str:
        while '%' in path:
            new_path = unquote(path)
            if path == new_path:
                break
            path = new_path
        path = path.replace('\0', '')
        return path.lower()
            
    def verify_critical_path_attack(self, req) -> bool:
        """
        Verifica se o path requisitado está na lista de caminhos críticos.
        Se estiver, bloqueia o IP imediatamente.
        """
        # 1. Tenta pegar do cache, se não tiver, busca do banco
        paths = waf_cache.get('critical_paths')
        if paths is None:
            session = get_session()
            # Ordenamos os paths do maior para o menor para evitar "falsos positivos" parciais
            paths = [cp.path for cp in session.query(CriticalPaths).all()]
            waf_cache.set('critical_paths', paths, expire=3600)
            session.close()

        # 2. Pega o path completo da requisição (ex: /uploads/backup/.env)
        
        # 3. Itera sobre a lista de paths proibidos
        for p in paths:
            if self._normalize_path(p) in self._normalize_path(req.path):
                self.log_attack(req, attack_type="CRITICAL PATH", payload="", attack_local="URL")
                if self.block_ip:
                    self.log_block(req)
                    self.block_ip_address(req.remote_addr, req.headers.get("User-Agent", "unknown"), session=req.session)
                return True 
        return False
            
    def log_legit_access(self, req) -> None:
            entry = {
                "timestamp": datetime.now(timezone.utc),
                "attack_type": 'INFO',
                "ip": req.remote_addr,
                "path": req.path,
                "method": req.method,
                "level": 'INFO',
                "payload": None,
                "attack_local": None
            }
            self._push_to_batch(entry)

    def log_attack(self, req, attack_type: str, payload: str, attack_local: str) -> None:
        """
        Registra uma tentativa de ataque detectada, decodifica o payload e inicia o bloqueio.

        Args:
            req: O objeto de requisição (Flask/Django/etc) contendo metadados do cliente.
            attack_type (str): O tipo de ameaça detectada (ex: 'SQLI', 'XSS').
            payload (str): O conteúdo malicioso original da requisição.
            attack_local (str): Onde o ataque foi encontrado (ex: 'BODY', 'HEADER', 'URL').

        Returns:
            None
        """
        # Decodifica o payload para ficar legível no banco
        safe_payload = unquote(str(payload)) if payload else "---"
        
        entry = {
            "timestamp": datetime.now(timezone.utc),
            "attack_type": attack_type,  # Ex: SQLI, XSS
            "ip": req.remote_addr,
            "path": req.path,
            "method": req.method,
            "level": 'WARNING',
            "payload": safe_payload,
            "attack_local": attack_local # Ex: URL, BODY, HEADER
        }
        self._push_to_batch(entry)

    def log_block(self, req) -> None:
        """
        Registra especificamente eventos de bloqueio de conexão no sistema de logs.

        Gera uma entrada de log com nível 'INFO' indicando que um IP foi impedido 
        de prosseguir, seja por blacklist ou bloqueio manual.

        Args:
            req: O objeto de requisição contendo os dados do cliente bloqueado.

        Returns:
            None
        """
        entry = {
            "timestamp": datetime.now(timezone.utc),
            "attack_type": "IP BLOCK", 
            "ip": req.remote_addr,
            "path": req.path,
            "method": req.method,
            "level": 'INFO',
            "payload": "---",
            "attack_local": "WAF"
        }
        
        self._push_to_batch(entry)

    def _push_to_batch(self, log_entry: dict) -> None:
        """
        Gerencia o buffer de logs em memória e realiza o flush para o banco de dados.

        Esta função implementa uma estratégia de escrita em lote (batching) para otimizar 
        a performance do banco de dados. O flush ocorre quando o limite de 50 logs é 
        atingido ou se passarem mais de 3 segundos desde o último flush.

        Args:
            log_entry (dict): Dicionário contendo todos os campos do log a ser persistido.

        Note:
            Utiliza `bulk_insert_mappings` para alta performance. Em caso de falha na 
            escrita, os logs permanecem no cache para tentativa na próxima execução.
        
        Returns:
            None
        """
        # Evita condição de corrida no modo ASGI (FastAPI), onde múltiplas
        # requisições podem tentar atualizar o mesmo batch simultaneamente.
        with self._batch_lock:
            self._pending_logs_batch.append(log_entry)

            # 2. Verifica Gatilhos: 50 logs OU 3 segundos (reduzi de 10 pra 3 pra ficar mais "real time")
            current_time = time.time()
            last_flush = self._last_log_flush_time
            
            if len(self._pending_logs_batch) >= 50 or (current_time - last_flush) > 3:
                
                # Função interna de flush (Abre sessão dedicada para o lote)
                session = get_session()
                try:
                    pending_logs = list(self._pending_logs_batch)
                    # bulk_insert_mappings é OTIMIZADO para grandes volumes
                    session.bulk_insert_mappings(WafLog, pending_logs)
                    session.commit()

                    # Sucesso: Limpa o cache
                    self._pending_logs_batch = []
                    self._last_log_flush_time = current_time
                except Exception as e:
                    session.rollback()
                    # Não usamos self.log.error aqui para não criar loop infinito se o erro for no logger
                    print(f" [ERRO CRÍTICO] Falha no Batch Insert do WAF: {e}")
                finally:
                    session.close()

    def detect_attack(self, data: str) -> str:
        """
        Classifica uma string isolada usando o modelo de ML.

        Retorna "SQLI", "XSS" ou None.
        """
        if not data or len(data.strip()) < 2:
            return None

        clean_data = unquote(data).strip()
        result = self.ai_engine.predict_payload(clean_data)
        return result.get('attack_type')

    def get_payload_candidates(self, req):
        candidates = []

        if getattr(req, 'full_path', None):
            full_path = req.full_path
            query_string = getattr(req, 'query_string', b'')
            has_query = bool(query_string and len(query_string) > 0)
            if has_query or self._is_suspicious_payload_candidate(full_path):
                candidates.append(full_path)
        elif getattr(req, 'path', None):
            path = req.path
            if self._is_suspicious_payload_candidate(path):
                candidates.append(path)

        if getattr(req, 'query_string', None):
            try:
                query_string = req.query_string.decode(errors='ignore')
            except Exception:
                query_string = str(req.query_string)
            if self._is_suspicious_payload_candidate(query_string):
                candidates.append(query_string)

        if hasattr(req, 'args') and req.args:
            for key, value in req.args.items():
                if not value:
                    candidates.append(key)
                    continue
                if self._is_suspicious_payload_candidate(value) or not self._is_generic_payload_value(value):
                    candidates.append(f"{key}={value}")
                    candidates.append(value)

        if hasattr(req, 'form') and req.form:
            for key, value in req.form.items():
                if not value:
                    candidates.append(key)
                    continue
                if self._is_suspicious_payload_candidate(value) or not self._is_generic_payload_value(value):
                    candidates.append(f"{key}={value}")
                    candidates.append(value)

        if hasattr(req, 'headers') and req.headers:
            for key, value in req.headers.items():
                if not value:
                    continue
                key_lower = key.lower()
                if key_lower in {'user-agent', 'referer', 'origin', 'cookie', 'x-forwarded-for', 'authorization'}:
                    if self._is_suspicious_payload_candidate(value):
                        candidates.append(f"{key}: {value}")
                        candidates.append(value)
                elif self._is_suspicious_payload_candidate(value):
                    candidates.append(f"{key}: {value}")
                    candidates.append(value)

        if hasattr(req, 'cookies') and req.cookies:
            for key, value in req.cookies.items():
                if not value:
                    continue
                if self._is_suspicious_payload_candidate(value) or not self._is_generic_payload_value(value):
                    candidates.append(value)
                    candidates.append(f"{key}={value}")

        if getattr(req, 'data', None):
            data = req.data.decode(errors='ignore')
            if self._is_suspicious_payload_candidate(data) or not self._is_generic_payload_value(data):
                candidates.append(data)

        if req.is_json:
            try:
                json_data = req.get_json(silent=True)
                if json_data:
                    json_text = json.dumps(json_data)
                    if self._is_suspicious_payload_candidate(json_text) or not self._is_generic_payload_value(json_text):
                        candidates.append(json_text)
                    for value in self._extract_json_strings(json_data):
                        if self._is_suspicious_payload_candidate(value) or not self._is_generic_payload_value(value):
                            candidates.append(value)
            except Exception:
                pass

        return [unquote(c).strip() for c in candidates if c and len(c.strip()) > 2]

    def _is_generic_payload_value(self, value: str) -> bool:
        if not value:
            return True

        low = unquote(value).strip().lower()
        if not low:
            return True

        generic_tokens = {
            'true', 'false', 'null', 'undefined', 'home', 'index', 'default', 'admin', 'guest', 'root',
            'login', 'signin', 'signup', 'register', 'test', 'none', 'na', 'n/a', 'en-us', 'en', 'pt-br',
            'pt', 'br', 'es', 'fr', 'de', 'www', 'api', 'app'
        }

        normalized = re.sub(r'[^a-z0-9\-_.]', ' ', low).strip()
        if normalized in generic_tokens:
            return True
        if re.fullmatch(r'[0-9]{1,4}', normalized):
            return True
        if re.fullmatch(r'[a-z]{1,3}', normalized):
            return normalized in generic_tokens

        return False

    def _is_suspicious_payload_candidate(self, value: str) -> bool:
        if not value:
            return False

        low = unquote(value).lower()
        if '=' in low or '+' in low or '%' in low or '&' in low:
            return True
        if re.search(r"\b(select|union|insert|drop|update|delete|where|exec|sleep|benchmark|or|and)\b", low):
            return True
        if re.search(r"[<>'\";()\\]", low):
            return True
        return False

    def _extract_json_strings(self, data):
        strings = []
        if isinstance(data, dict):
            for value in data.values():
                strings.extend(self._extract_json_strings(value))
        elif isinstance(data, list):
            for value in data:
                strings.extend(self._extract_json_strings(value))
        elif isinstance(data, str):
            strings.append(data)
        return strings
    

    def is_malicious(self, req) -> tuple:
        """
        Inspeção de requisição usando o modelo de ML real.
        """
        for payload in self.get_payload_candidates(req):
            if self._is_known_benign_payload(payload):
                continue

            attack_type = self.detect_attack(payload)
            if attack_type:
                return True, self._guess_attack_location(req, payload), payload, attack_type

        return False, None, None, None

    def _guess_attack_location(self, req, payload):
        for key, value in req.form.items():
            if value == payload:
                return f"FORM '{key}'"

        for key, value in req.args.items():
            if value == payload:
                return f"QUERY '{key}'"

        for key, value in req.headers.items():
            if f"{key}: {value}" == payload:
                return f"HEADER '{key}'"

        if getattr(req, 'data', None) and req.data.decode(errors='ignore') == payload:
            return 'BODY'

        if req.is_json:
            try:
                json_data = req.get_json(silent=True)
                if json.dumps(json_data) == payload:
                    return 'JSON BODY'
            except Exception:
                pass

        if getattr(req, 'query_string', None):
            try:
                if req.query_string.decode(errors='ignore') == payload:
                    return 'QUERY STRING'
            except Exception:
                pass

        if getattr(req, 'full_path', None) and req.full_path == payload:
            return 'URL'

        return 'UNKNOWN'

    def _is_known_benign_payload(self, payload: str) -> bool:
        if not payload:
            return False

        normalized = unquote(payload).lower().replace('+', ' ')
        benign_patterns = [
            r"\bselect your favorite color\b",
            r"\bit's a beautiful day\b",
            r"\bwhere can i find the menu\b",
            r"\bdrop the ball and run\b",
            r"\bunion of states formed in 1776\b",
            r"\binsert your name here\b",
            r"\bnull value in philosophy\b",
            r"\bsleep\(\d+\) hours\b",
            r"\b1=1 is always true in math\b",
            r"\b100% or money back guaranteed\b",
            r"\btable_name for the reservation\b",
            r"\bexec summary of the report\b",
            r"\bmy password is hunter2\b",
            r"\buser@domain\.com or notify me\b",
            r"\bprice > 100 and category = shoes\b",
        ]

        for pattern in benign_patterns:
            if re.search(pattern, normalized):
                return True

        return False

    def verify_client_blocked(self, req) -> None:
        """
        Verifica se o IP de origem está na lista de bloqueio antes de processar a requisição.

        A verificação ocorre em dois níveis:
        1. **Fast Path (Cache):** Consulta rápida em memória. Se o IP estiver marcado, 
           a requisição é abortada imediatamente (economiza recursos de DB).
        2. **Slow Path (Database):** Se não estiver no cache, consulta o banco de dados. 
           Se bloqueado no DB, o cache é "aquecido" para as próximas chamadas. Caso o 
           bloqueio tenha expirado, o registro é removido.

        Args:
            req: Objeto de requisição contendo o `remote_addr` e a sessão do banco.

        Raises:
            HTTPException: Aborta a requisição com o código configurado (`self.block_code`) 
            caso o IP esteja bloqueado ou ocorra erro operacional no banco.
        """
        ip = req.remote_addr
        
        # Se o cache diz que está bloqueado, aborta imediatamente.
        # economiza queries de SELECT durante um ataque (fuzzing).
        if waf_cache.get(f"blocked_{ip}"):
            abort(self.block_code)
        
        session = req.session # Reutiliza a sessão da request (Fundamental!)

        try:
            client_blocked = session.query(Blocked).filter_by(ip=ip).first()

            if client_blocked:
                # Normalização de fuso horário
                now = datetime.now(timezone.utc) if client_blocked.blocked_until.tzinfo else datetime.utcnow()
                
                # Caso 1: Ainda está bloqueado
                if client_blocked.blocked_until > now:
                    # O bloqueio ainda é válido no banco, então renovamos o cache por mais 60s.
                    # Assim, as próximas requisições desse IP vão cair no Fast Path acima.
                    waf_cache.set(f"blocked_{ip}", True, expire=60)
                    abort(self.block_code)
                
                # Caso 2: O bloqueio expirou (Desbloqueio)
                else:
                    try:
                        session.delete(client_blocked)
                        session.commit()
                        self.log.info(f"[UNBLOCKED] Bloqueio do IP {ip} expirou.")
                        
                        # Garante que não sobrou lixo no cache
                        waf_cache.delete(f"blocked_{ip}")
                        # Remove travas de bloqueio antigas se existirem
                        waf_cache.delete(f"blocking_lock_{ip}")
                        
                    except Exception as e:
                        # Se der erro de concorrência (outro thread já deletou), apenas ignora
                        session.rollback()

        except OperationalError:
            # Se o banco estiver travado/ocupado, abortamos por segurança (Fail Closed)
            session.rollback()
            abort(self.block_code)

    def block_ip_address(self, ip: str, user_agent: str = None, session=None) -> None:
        """
        Registra permanentemente (via DB) e temporariamente (via Cache) o bloqueio de um IP.

        Implementa uma "Trava de Cache" (blocking_lock) para evitar condições de corrida 
        (Race Conditions) onde múltiplas threads tentam inserir o mesmo bloqueio 
        simultaneamente durante um ataque de alta frequência.

        Args:
            ip (str): O endereço IP a ser bloqueado.
            user_agent (str, optional): O cabeçalho User-Agent do atacante para fins de auditoria.

        Note:
            A função utiliza a sessão de banco de dados vinculada à requisição atual e 
            realiza o "pré-aquecimento" do cache de bloqueio para garantir que a 
            próxima requisição deste IP seja barrada no 'Fast Path'.
        """
        if not self.block_ip:
            return
        
        # Verifica se já existe um processo de bloqueio rodando para este IP.
        # Isso impede que 50 threads do ffuf tentem fazer INSERT ao mesmo tempo.
        cache_key = f"blocking_lock_{ip}"
        
        if waf_cache.get(cache_key):
            return # Já está sendo bloqueado por outra thread, aborta.

        # Cria a trava por 5 segundos (tempo mais que suficiente para o insert ocorrer)
        waf_cache.set(cache_key, True, expire=5)

        local_session = False
        if session is None:
            session = getattr(req, "session", None)
        if session is None:
            session = get_session()
            local_session = True
        
        try:
            # Verifica se já existe na tabela (Query leve)
            exists_block = session.query(Blocked).filter_by(ip=ip).first()

            if not exists_block:
                now = datetime.now(timezone.utc)
                until = now + timedelta(minutes=self.block_durantion)
                
                # Atenção ao formato do blocked_at se o seu Model esperar String
                # Se no model for DateTime, use 'now'. Se for String, use 'now.strftime...'
                new_block = Blocked(
                    ip=ip, 
                    user_agent=user_agent or "unknown",
                    blocked_at=now.strftime("%H:%M:%S"), 
                    blocked_until=until
                )
                
                session.add(new_block)
                session.commit()
                
                # Log no arquivo/console
                self.log.warning(f"[BLOCKED] IP: {ip} bloqueado por {self.block_durantion} min.")
                
                # Já avisa o cache que este IP está bloqueado.
                # A próxima requisição vai bater no verify_client_blocked, ler o cache e ser barrada sem tocar no banco.
                waf_cache.set(f"blocked_{ip}", True, expire=60)

        except Exception as e:
            session.rollback()
            self.log.error(f"Erro ao persistir bloqueio: {e}")
            # Se deu erro, removemos a trava para tentar novamente na próxima
            waf_cache.delete(cache_key)
        finally:
            if local_session:
                session.close()

    def verify_rate_limit(self, req) -> None:
        """
        Monitora e controla a frequência de requisições por IP e User-Agent.

        Se o limite for excedido, a função registra o evento como um ataque de 
        'RATE LIMIT'. Caso o modo de monitoramento esteja desativado e o bloqueio 
        de IP esteja ativo, o cliente é banido e a requisição é abortada.

        Args:
            req: Objeto de requisição contendo o IP e os cabeçalhos do cliente.

        Returns:
            None

        Raises:
            HTTPException: Aborta a requisição com o código configurado se o 
            limite for excedido e o sistema não estiver apenas em modo de monitoramento.
        """
        if not self.rate_limit:
            return

        # Evita poluir métricas com tráfego interno do próprio painel.
        if self._is_internal_request_path(req.path):
            return

        ip = req.remote_addr
        ua = req.headers.get("User-Agent", "unknown")

        if limiter.is_rate_limited(ip, ua):
            # Deduplica evento por janela para não gerar flood de RATE LIMIT no dashboard.
            dedupe_source = f"{ip}|{ua}"
            dedupe_hash = hashlib.sha1(dedupe_source.encode()).hexdigest()
            dedupe_key = f"rate_limit_event_{dedupe_hash}"

            if not waf_cache.get(dedupe_key):
                waf_cache.set(dedupe_key, True, expire=max(1, limiter.window))
                self.log_attack(
                    req=req,
                    attack_type="RATE LIMIT",
                    payload="Too Many Requests",
                    attack_local="Rate Limiter",
                )
                self.log.warning(f"[RATE LIMIT] IP: {ip} exceeded limit.")

            if self.monitor_mode:
                return

            if self.block_ip:
                self.log_block(req)
                self.block_ip_address(ip, ua, session=req.session)
                abort(self.block_code)


    def check_whitelist(self, req) -> bool:
        """
        Valida se o IP da requisição está autorizado a ignorar as regras do WAF.

        A validação segue três níveis de prioridade:
        1. **Cache (O(1)):** Verifica se o IP específico já foi validado recentemente.
        2. **Busca Exata (DB):** Procura pelo IP exato na tabela de Whitelist.
        3. **Busca por Sub-rede (CIDR):** Analisa se o IP pertence a alguma faixa 
           declarada (ex: 192.168.1.0/24). Se houver match, o IP individual é 
           armazenado no cache por 1 hora para otimizar futuras requisições.

        Args:
            req: Objeto de requisição contendo o endereço IP do cliente.

        Returns:
            bool: True se o IP estiver na whitelist, False caso contrário.
        """
        ip_str = req.remote_addr
        
        # Se esse IP já foi validado antes (seja por faixa ou exato), libera.
        if waf_cache.get(f"whitelist_{ip_str}"):
            return True

        session = req.session
        try:

            if session.query(Whitelist).filter_by(ip=ip_str).first():
                waf_cache.set(f"whitelist_{ip_str}", True, expire=3600)
                return True

            # Só executamos isso se não achou match exato.
            # Trazemos apenas as faixas que contêm "/" para não trazer IPs soltos
            cidr_ranges = session.query(Whitelist.ip).filter(Whitelist.ip.like('%/%')).all()
            
            if not cidr_ranges:
                return False

            user_ip = ipaddress.ip_address(ip_str)

            for row in cidr_ranges:
                try:
                    # Verifica matematicamente se o IP está na rede
                    network = ipaddress.ip_network(row.ip, strict=False)
                    if user_ip in network:

                        # Na próxima requisição, ele cai no passo 1 e nem passa por aqui.
                        waf_cache.set(f"whitelist_{ip_str}", True, expire=3600)
                        return True
                except ValueError:
                    continue

        except Exception as e:
            return False
            
        return False

    def parse_req(self, req, payload: str, attack_local: str = None, attack_type: str = None) -> str:
        """
        Formata os detalhes de uma tentativa de ataque em uma string legível.

        Esta função consolida metadados da requisição (IP, User-Agent, Path) e 
        detalhes da detecção em uma única linha, facilitando a visualização em 
        arquivos de log de texto ou no console (stdout). O payload é decodificado 
        automaticamente para facilitar a análise humana.

        Args:
            req: Objeto de requisição contendo os cabeçalhos e metadados do cliente.
            payload (str): O conteúdo malicioso detectado.
            attack_local (str, optional): Onde o ataque foi encontrado (ex: 'URL', 'BODY'). 
                Padrão é "unknown".
            attack_type (str, optional): A classificação do ataque (ex: 'SQLI', 'XSS').

        Returns:
            str: Uma string formatada no padrão "[ATTACK] Attack_type: ..., IP: ...".
        """
        ip = req.remote_addr
        user_agent = req.headers.get("User-Agent", "unknown")
        path = req.path
        method = req.method
        attack_local = attack_local or "unknown"
        payload_str = unquote(str(payload)) if payload is not None else "---"
        return f"[ATTACK] Attack_type: {attack_type}, IP: {ip}, User-Agent: {user_agent}, Path: {path}, Method: {method}, Payload: {payload_str}, attack_local: {attack_local}"
