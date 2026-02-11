# from .model import Base, Blocked, WafLog, Whitelist, get_session, engine
# from .logger import Logger
# from .rateLimiter import RateLimiter
# from .panel import setup_dashboard
# from .utils import Admin, seed_default_whitelist
# from .globals import waf_cache
import urllib
from model import Base, Blocked, CriticalPaths, WafLog, Whitelist, get_session, engine
from logger import Logger
from rateLimiter import RateLimiter
from panel import setup_dashboard
from utils import Admin, seed_default_whitelist
from globals import waf_cache
import joblib
from datetime import datetime, timedelta, timezone 
import re
import time
from flask import Flask, json, request as req, abort, g
from urllib.parse import unquote
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
import hashlib
import uuid
import socket
import ipaddress

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
    
    def __init__(self, app: Flask = None, block_code: int = 403, block_durantion: int = 5, block_ip: bool = False, log_func: callable = None, monitor_mode: bool = False,  rate_limit: bool = False, dashboard_path: str = None, ai_treshold: float = 0.80):
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
            self.block_durantion = block_durantion
            self.recent_blocks_cache = {}
            self.port = None
            self.ip = None
            self.ai_treshold = ai_treshold
            self.ai_model = joblib.load('wafahell_brain.pkl')

            if not self.app:
                raise ValueError(" * [Waffahell] O atributo 'app' é obrigatório e não pode ser vazio.")
            if not isinstance(app, Flask):
                raise TypeError(f" * [Waffahell] O atributo 'app' deve ser uma instância de Flask, mas recebeu {type(app).__name__}.")
            self._init_app(self.app)

    def _init_app(self, app) -> None:
        """
        Acopla a lógica do WAF ao ciclo de vida das requisições do Flask.
        
        Configura o banco de dados, dashboard, autenticação administrativa 
        e registra os hooks de interceptação (before/after request).
        """
        Base.metadata.create_all(engine)
        setup_dashboard(app, self.dashboard_path)
        seed_default_whitelist()
        Admin.create_admin_user(get_session())

        if not app.secret_key:
            def _create_secret_key():
                mac_address = str(uuid.getnode())
                hostname = socket.gethostname()
                project_salt = "wafahell-security-core-v1"
                fingerprint = f"{mac_address}-{hostname}-{project_salt}"
                return hashlib.sha256(fingerprint.encode()).hexdigest()
            app.secret_key = _create_secret_key()


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
                self.block_ip_address(req.remote_addr, req.headers.get("User-Agent", "unknown"))
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
                self.log_attack(req, attack_type="", payload="", attack_local="URL")
                if self.block_ip:
                    self.log_block(req)
                    self.block_ip_address(req.remote_addr, req.headers.get("User-Agent", "unknown"))
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
        safe_payload = unquote(payload) if payload else "---"
        
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
        self.log_block(req)
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
        # 1. Recupera os logs pendentes do cache global
        pending_logs = waf_cache.get('pending_logs_batch', default=[])
        pending_logs.append(log_entry)

        # 2. Verifica Gatilhos: 50 logs OU 3 segundos (reduzi de 10 pra 3 pra ficar mais "real time")
        current_time = time.time()
        last_flush = waf_cache.get('last_log_flush_time', default=0)
        
        if len(pending_logs) >= 50 or (current_time - last_flush) > 3:
            
            # Função interna de flush (Abre sessão dedicada para o lote)
            session = get_session()
            try:
                # bulk_insert_mappings é OTIMIZADO para grandes volumes
                session.bulk_insert_mappings(WafLog, pending_logs)
                session.commit()
                
                # Sucesso: Limpa o cache
                waf_cache.set('pending_logs_batch', [], expire=60)
                waf_cache.set('last_log_flush_time', current_time, expire=60)
            except Exception as e:
                session.rollback()
                # Não usamos self.log.error aqui para não criar loop infinito se o erro for no logger
                print(f" [ERRO CRÍTICO] Falha no Batch Insert do WAF: {e}")
                
                # Mantém os dados no cache para tentar na próxima requisição
                waf_cache.set('pending_logs_batch', pending_logs, expire=60)
            finally:
                session.close()
        else:
            # Apenas atualiza a lista no cache esperando o gatilho
            waf_cache.set('pending_logs_batch', pending_logs, expire=60)

    def detect_attack(self, data: str) -> bool:
        """
        Analisa uma string em busca de padrões de ataques conhecidos (XSS e SQLI).

        Varre o conteúdo fornecido utilizando expressões regulares definidas nas 
        regras do WAF. A verificação é case-insensitive.

        Args:
            data (str): O conteúdo textual a ser analisado (ex: valor de um input).

        Returns:
            str | None: Retorna o nome do tipo de ataque ("XSS" ou "SQLI") se 
            encontrado, ou None caso a string pareça segura.
        """
        if not data or len(data.strip()) < 2: # Ignora campos vazios ou irrelevantes
                return None

        # Normalização para a IA
        clean_data = urllib.parse.unquote(data).lower()

        # Predição
        # Se seu modelo for multiclasse (0: Benigno, 1: SQLI, 2: XSS)
        prediction = self.ai_model.predict([clean_data])[0]
        
        # Se seu modelo for apenas binário, você retornaria "ATTACK" ou None
        if prediction == 1: return "SQLI"
        if prediction == 2: return "XSS"
        
        return None

    def get_ai_features(self, req):
        # 1. Coleta das partes
        method = req.method
        url = req.base_url
        query_params = json.dumps(dict(req.args))
        form_data = json.dumps(dict(req.form))
        headers = json.dumps(dict(req.headers))
        
        # Trata Body Raw e Multipart (WebBoundary)
        body_raw = req.data.decode(errors="ignore") if req.data else ""
        
        # Trata JSON
        json_body = ""
        if req.is_json:
            jd = req.get_json(silent=True)
            json_body = json.dumps(jd) if jd else ""

        # 2. Construção da String Mestra (O que a IA vai analisar)
        # A ordem ajuda a IA a entender o contexto da requisição
        full_content = f"METHOD:{method} | URL:{url} | ARGS:{query_params} | " \
                    f"FORM:{form_data} | HEADERS:{headers} | BODY:{body_raw} | JSON:{json_body}"
        
        # 3. Normalização (Lower case e Unquote para evitar bypass de encoding)
        full_content = urllib.parse.unquote(full_content).lower()
    
        return full_content
    

    def is_malicious(self, req) -> tuple:
        """
        Realiza uma inspeção profunda em todos os componentes de uma requisição HTTP.

        A função verifica sequencialmente:
        1. URL base
        2. Campos de formulário (POST/PUT)
        3. Parâmetros de query (GET)
        4. Cabeçalhos (Headers)
        5. Corpo bruto (Raw Body)
        6. Conteúdo JSON

        Args:
            req: O objeto de requisição (ex: flask.Request) a ser inspecionado.

        Returns:
            tuple: Uma tupla contendo quatro elementos:
                - (bool): True se for malicioso, False caso contrário.
                - (str | None): Onde o ataque foi detectado (ex: "URL", "HEADER 'User-Agent'").
                - (str | None): O conteúdo específico que disparou o alerta.
                - (str | None): O tipo de ataque detectado ("XSS" ou "SQLI").
        """
        full_request_string = self.get_ai_features(req)
        prob_global = self.ai_model.predict_proba([full_request_string])[0][1]
        print(f"[DEBUG AI] TRESHOLD: {self.ai_treshold} | PROB: {prob_global}")
        if prob_global >= self.ai_treshold:
            attack = self.detect_attack(req.base_url)
            if attack:
                print(f"[DEBUG] Attack detected in URL: {attack}")
                return True, "URL", req.base_url, attack
            
            for key, value in req.form.items():
                attack = self.detect_attack(value)
                if attack:
                    print(f"[DEBUG] Attack detected in FORM '{key}': {attack}")
                    return True, f"FORM '{key}'", value, attack
            
            for key, value in req.args.items():
                attack = self.detect_attack(value)
                if attack:
                    print(f"[DEBUG] Attack detected in QUERY '{key}': {attack}")
                    return True, f"QUERY '{key}'", value, attack

            for key, value in req.headers.items():
                attack = self.detect_attack(value)
                if attack:
                    print(f"[DEBUG] Attack detected in HEADER '{key}': {attack}")
                    return True, f"HEADER '{key}'", value, attack

            if req.data:
                body_content = req.data.decode(errors="ignore")
                attack = self.detect_attack(body_content)
                if attack:
                    print(f"[DEBUG] Attack detected in BODY: {attack}")
                    return True, "BODY", body_content, attack
                
            if req.is_json:
                json_data = req.get_json(silent=True)
                if json_data:
                    import json
                    json_str = json.dumps(json_data)
                    attack = self.detect_attack(json_str)
                    if attack:
                        print(f"[DEBUG] Attack detected in JSON BODY: {attack}")
                        return True, "JSON BODY", json_str, attack

        return False, None, None, None

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

    def block_ip_address(self, ip: str, user_agent: str = None) -> None:
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

        # Usamos a sessão que já está aberta na requisição atual.
        session = req.session 
        
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
        if self.rate_limit:
                ip = req.remote_addr
                ua = req.headers.get("User-Agent", "unknown")
                
                if limiter.is_rate_limited(ip, ua):
                    self.log_attack(
                        req=req, 
                        attack_type="RATE LIMIT", 
                        payload="Too Many Requests", 
                        attack_local="Rate Limiter"
                    )
                    
                    self.log.warning(f"[RATE LIMIT] IP: {ip} exceeded limit.")

                    if self.monitor_mode:
                        return
                    
                    if self.block_ip:
                        self.block_ip_address(ip, ua)
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
        return f"[ATTACK] Attack_type: {attack_type}, IP: {ip}, User-Agent: {user_agent}, Path: {path}, Method: {method}, Payload: {unquote(payload)}, attack_local: {attack_local}"