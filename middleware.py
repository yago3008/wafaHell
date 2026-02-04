from datetime import datetime, timedelta, timezone 
import os
import re
import subprocess
import time
from flask import request as req, abort, g
from urllib.parse import unquote
from model import Base, Blocked, WafLog, Whitelist, get_session, engine
from logger import Logger
from rateLimiter import RateLimiter
from sqlalchemy.exc import OperationalError
from panel import setup_dashboard
from utils import Admin, seed_default_whitelist
from sqlalchemy import text
from globals import waf_cache
import hashlib
import uuid
import socket
import ipaddress

# Inicializa o RateLimiter
limiter = RateLimiter(limit=100, window=60)

class Wafahell:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Wafahell, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, app=None, block_code=403, block_durantion=5, block_ip=False, log_func=None, monitor_mode=False,  rate_limit=False, dashboard_path=None):
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

            self.rules_sqli = [
                r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDROP\b)",  
                r"' OR '1'='1"                                                                                                                                                                                                                                
            ]
            self.rules_xss = [
                r"<script.*?>.*?</script>",                    
                r"javascript:"
            ]

            if app is not None:
                self.init_app(app)

    def init_app(self, app):
        Base.metadata.create_all(engine)
        setup_dashboard(app, self.dashboard_path)
        seed_default_whitelist()
        Admin.create_admin_user(get_session())

        if not app.secret_key:
            def create_secret_key():
                mac_address = str(uuid.getnode())
                hostname = socket.gethostname()
                project_salt = "wafahell-security-core-v1"
                fingerprint = f"{mac_address}-{hostname}-{project_salt}"
                return hashlib.sha256(fingerprint.encode()).hexdigest()
            app.secret_key = create_secret_key()

        @app.before_request
        def create_session():
            try:
                req.session = get_session()
            except Exception as e:
                self.log.error(f"Erro ao criar sessão para requisição: {e}")
                abort(self.block_code)

        @app.teardown_request
        def close_session(exc=None):
            if hasattr(req, 'session'):
                try:
                    req.session.close()
                except Exception as e:
                    self.log.error(f"Erro ao fechar sessão: {e}")
        

        @app.before_request
        def waf_check():
            if self.check_whitelist(req):
                return
            self.verify_client_blocked(req)
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
        def start_timer():
            g.waf_start_time = time.time()

        @app.after_request
        def stop_timer(response):
            ignored_paths = [self.dashboard_path, f'{self.dashboard_path}/stats', '/static']

            # 1. Ignora rotas do próprio painel para não sujar os logs e métricas
            if any(req.path.startswith(path) for path in ignored_paths):
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

            # 4. Latency Logic
            if hasattr(g, 'waf_start_time'):
                latency = (time.time() - g.waf_start_time) * 1000
                
                # Exponential Moving Average
                old_avg = waf_cache.get('latency_avg', default=0.0)
                new_avg = (old_avg * 0.95) + (latency * 0.05) if old_avg > 0 else latency
                
                waf_cache.set('latency_avg', new_avg, expire=3600)
                
            return response
        
    def log_legit_access(self, req):
            entry = {
                "timestamp": datetime.now(timezone.utc),
                "attack_type": 'INFO',
                "ip": req.remote_addr,
                "path": req.path,
                "method": req.method,
                "level": 'INFO',
                "payload": None,       # INFO não tem payload
                "attack_local": None   # INFO não tem local de ataque
            }
            # Manda para o gerenciador de lote
            self._push_to_batch(entry)

    def log_attack(self, req, attack_type, payload, attack_local):
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

    def log_block(self, req):
        """
        Registra especificamente bloqueios de conexão (Blacklist/Manual Block).
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
        
        # Envia para o mesmo lote que os ataques normais
        self._push_to_batch(entry)

    def _push_to_batch(self, log_entry):
        """
        Função central que gerencia o Buffer de Logs (Memória -> Banco).
        Usada tanto por logs legítimos quanto por ataques.
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
        for pattern in self.rules_xss:
            if re.search(pattern, data, re.IGNORECASE):
                return "XSS"
        for pattern in self.rules_sqli:
            if re.search(pattern, data, re.IGNORECASE):
                return "SQLI"
        return None

    def is_malicious(self, req) -> tuple:
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
        ip = req.remote_addr
        
        # ---------------------------------------------------------
        # 1. FAST PATH: Cache Check (Memória/Disco)
        # ---------------------------------------------------------
        # Se o cache diz que está bloqueado, abortamos imediatamente.
        # Isso economiza 99% das queries de SELECT durante um ataque (fuzzing).
        if waf_cache.get(f"blocked_{ip}"):
            abort(self.block_code)

        # ---------------------------------------------------------
        # 2. SLOW PATH: Database Check
        # ---------------------------------------------------------
        # Só chegamos aqui se o IP não estiver no cache.
        # Pode ser um IP limpo OU um IP bloqueado cujo cache expirou (TTL).
        
        session = req.session # Reutiliza a sessão da request (Fundamental!)

        try:
            client_blocked = session.query(Blocked).filter_by(ip=ip).first()

            if client_blocked:
                # Normalização de fuso horário
                now = datetime.now(timezone.utc) if client_blocked.blocked_until.tzinfo else datetime.utcnow()
                
                # Caso 1: Ainda está bloqueado
                if client_blocked.blocked_until > now:
                    # RE-AQUECIMENTO DO CACHE:
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

    def block_ip_address(self, ip, user_agent=None):
        if not self.block_ip:
            return

        # 1. TRAVA DE CACHE (A Salvação do Fuzzing)
        # Verifica se já existe um processo de bloqueio rodando para este IP.
        # Isso impede que 50 threads do ffuf tentem fazer INSERT ao mesmo tempo.
        cache_key = f"blocking_lock_{ip}"
        
        if waf_cache.get(cache_key):
            return # Já está sendo bloqueado por outra thread, aborta.

        # Cria a trava por 5 segundos (tempo mais que suficiente para o insert ocorrer)
        waf_cache.set(cache_key, True, expire=5)

        # 2. REUTILIZAÇÃO DE SESSÃO
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
                
                # 3. PRÉ-AQUECIMENTO DE CACHE
                # Já avisa o cache que este IP está bloqueado.
                # A próxima requisição vai bater no verify_client_blocked, ler o cache e ser barrada sem tocar no banco.
                waf_cache.set(f"blocked_{ip}", True, expire=60)

        except Exception as e:
            session.rollback()
            self.log.error(f"Erro ao persistir bloqueio: {e}")
            # Se deu erro, removemos a trava para tentar novamente na próxima
            waf_cache.delete(cache_key)
        
        # IMPORTANTE:
        # Não usamos 'finally: session.close()' aqui!
        # Quem fecha é o @app.teardown_request no final do ciclo.

    def verify_rate_limit(self, req) -> None:
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
        ip_str = req.remote_addr
        
        # 1. CACHE (Velocidade Extrema)
        # Se esse IP já foi validado antes (seja por faixa ou exato), libera.
        if waf_cache.get(f"whitelist_{ip_str}"):
            return True

        session = req.session
        try:
            # 2. Busca Exata (Para IPs unitários como 8.8.8.8)
            # É muito rápido.
            if session.query(Whitelist).filter_by(ip=ip_str).first():
                waf_cache.set(f"whitelist_{ip_str}", True, expire=3600)
                return True

            # 3. Busca por Faixas (CIDR)
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
                        # ACHOU!
                        # Salva o IP DO USUÁRIO no cache. 
                        # Na próxima requisição, ele cai no passo 1 e nem passa por aqui.
                        waf_cache.set(f"whitelist_{ip_str}", True, expire=3600)
                        return True
                except ValueError:
                    continue

        except Exception as e:
            return False
            
        return False

    def parse_req(self, req, payload, attack_local=None, attack_type=None) -> str:
        ip = req.remote_addr
        user_agent = req.headers.get("User-Agent", "unknown")
        path = req.path
        method = req.method
        attack_local = attack_local or "unknown"
        return f"[ATTACK] Attack_type: {attack_type}, IP: {ip}, User-Agent: {user_agent}, Path: {path}, Method: {method}, Payload: {unquote(payload)}, attack_local: {attack_local}"