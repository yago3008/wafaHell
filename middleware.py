from datetime import datetime, timedelta, timezone 
import os
import re
import subprocess
import time
from flask import request as req, abort, g
from urllib.parse import unquote
from model import Base, Blocked, WafLog, get_session, engine
from logger import Logger
from rateLimiter import RateLimiter
from sqlalchemy.exc import OperationalError
from panel import setup_dashboard
from utils import Admin
from sqlalchemy import text
from globals import waf_cache
import hashlib
import uuid
import socket

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
            self.verify_client_blocked(req)
            self.verify_rate_limit(req)
            is_malicious, attack_local, payload, attack_type = self.is_malicious(req)
            
            if not is_malicious:
                return
            
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
            # if response.status_code != self.block_code:
            #     self.log_legit_access(req)

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
        # 1. Captura os dados da requisição atual
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "attack_type": 'INFO',
            "ip": req.remote_addr,
            "path": req.path,
            "method": req.method,
            "level": 'INFO'
        }

        # 2. Função aninhada para descarregar no banco (Flush)
        def flush_to_db(logs_to_save):
            session = get_session()
            try:
                # bulk_insert_mappings é muito mais rápido que session.add() em loop
                session.bulk_insert_mappings(WafLog, logs_to_save)
                session.commit()
            except Exception as e:
                session.rollback()
                self.log.error(f"Error in WAF batch insert: {e}")
            finally:
                session.close()

        # 3. Gerenciamento do Cache (Memória)
        # Recupera os logs pendentes do cache global
        pending_logs = waf_cache.get('pending_logs_batch', default=[])
        pending_logs.append(log_entry)

        # 4. Gatilhos para o Flush:
        # Se chegamos a 50 logs OU se o último flush foi há mais de 10 segundos
        current_time = time.time()
        last_flush = waf_cache.get('last_log_flush_time', default=0)
        
        if len(pending_logs) >= 50 or (current_time - last_flush) > 10:
            flush_to_db(pending_logs)
            # Reseta o cache e o timer
            waf_cache.set('pending_logs_batch', [], expire=60)
            waf_cache.set('last_log_flush_time', current_time, expire=60)
        else:
            # Apenas atualiza a lista no cache
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
        session = req.session
        try:
            client_blocked = session.query(Blocked).filter_by(
                ip=req.remote_addr,
            ).first()

            if client_blocked:

                now = datetime.now(timezone.utc) if client_blocked.blocked_until.tzinfo else datetime.utcnow()
                
                if client_blocked.blocked_until <= now:
                    # --- TRAVA DE DESBLOQUEIO (Anti-Race Condition) ---
                    # Usamos um marcador no cache para saber se alguém já está desbloqueando este IP
                    cache_key = f"unblocking_{req.remote_addr}"
                    if cache_key in self.recent_blocks_cache:
                        return # Outra thread já está limpando este IP, apenas saia
                    
                    self.recent_blocks_cache[cache_key] = True
                    # --------------------------------------------------

                    try:
                        session.delete(client_blocked)
                        session.commit()
                        
                        # Limpa os caches de controle deste IP
                        self.recent_blocks_cache.pop(req.remote_addr, None)
                        self.recent_blocks_cache.pop(cache_key, None)
                        
                        self.log.info(f"[UNBLOCKED] IP {req.remote_addr} bloqueio expirou.")
                    except Exception as e:
                        session.rollback()
                        self.recent_blocks_cache.pop(cache_key, None)
                        raise e
                    return

                # Se chegou aqui, ainda está bloqueado
                abort(self.block_code)

        except OperationalError:
            session.rollback()
            abort(self.block_code)

        try:
                        
            client_blocked = session.query(Blocked).filter_by(
                ip=req.remote_addr,
                user_agent=req.headers.get("User-Agent")
            ).first()

            if not client_blocked:
                return

            # Normaliza o tempo para comparação
            now = datetime.now(timezone.utc) if client_blocked.blocked_until.tzinfo else datetime.utcnow()
            
            if client_blocked.blocked_until <= now:
                # --- TRAVA DE DESBLOQUEIO (Anti-Race Condition) ---
                # Usamos um marcador no cache para saber se alguém já está desbloqueando este IP
                cache_key = f"unblocking_{req.remote_addr}"
                if cache_key in self.recent_blocks_cache:
                    return # Outra thread já está limpando este IP, apenas saia
                
                self.recent_blocks_cache[cache_key] = True
                # --------------------------------------------------

                try:
                    session.delete(client_blocked)
                    session.commit()
                    
                    # Limpa os caches de controle deste IP
                    self.recent_blocks_cache.pop(req.remote_addr, None)
                    self.recent_blocks_cache.pop(cache_key, None)
                    
                    self.log.info(f"[UNBLOCKED] IP {req.remote_addr} bloqueio expirou.")
                except Exception as e:
                    session.rollback()
                    self.recent_blocks_cache.pop(cache_key, None)
                    raise e
                return
                
            abort(self.block_code)

        except OperationalError:
            session.rollback()
            abort(self.block_code)

    def block_ip_address(self, ip, user_agent=None):
        if not self.block_ip:
            return

        # 1. Trava de Memória (ajuda, mas não resolve 100% em multi-processo)
        now_ts = datetime.now().timestamp()
        if ip in self.recent_blocks_cache:
            if now_ts - self.recent_blocks_cache[ip] < 5:
                return 
        self.recent_blocks_cache[ip] = now_ts

        session = get_session()
        try:
            # 2. TRAVA DE BANCO: Verifica se já houve um log desse IP nos últimos 2 segundos
            # Isso evita que as 6 threads do ffuf que passaram pela trava de memória gravem no banco
            
            time_threshold = datetime.now(timezone.utc) - timedelta(seconds=2)
            
            # Buscamos na tabela de LOGS (WafLog) se já existe um registro recente
           
            exists_recent_log = session.query(WafLog).filter(
                WafLog.ip == ip,
                WafLog.attack_type.in_(['RATE LIMIT', 'IP BLOCK']),
                WafLog.timestamp >= time_threshold
            ).first()

            if not exists_recent_log:
                # Só prossegue se não houver log recente
                exists_block = session.query(Blocked).filter_by(ip=ip).first()
                if not exists_block:
                    now = datetime.now(timezone.utc)
                    until = now + timedelta(minutes=self.block_durantion)
                    
                    new_block = Blocked(
                        ip=ip, user_agent=user_agent,
                        blocked_at=now, blocked_until=until
                    )
                    session.add(new_block)
                    session.commit()
                    self.log.warning(f"[RATE LIMIT] IP: {ip} exceeded limit.")
                    self.log.warning(f"[BLOCKED] IP: {ip}, UA: {user_agent}")
                    
                    
                    
        except Exception as e:
            session.rollback()
            self.log.error(f"Erro ao persistir bloqueio: {e}")
        finally:
            session.close()

    def verify_rate_limit(self, req) -> None:
        if self.rate_limit:
                ip = req.remote_addr
                ua = req.headers.get("User-Agent", "unknown")
                
                if limiter.is_rate_limited(ip, ua):
                    if self.monitor_mode:
                        self.log.warning(f"[RATE LIMIT] IP: {ip} exceeded limit.")
                        return
                    
                    
                    if self.block_ip:
                        self.block_ip_address(ip, ua)
                        abort(self.block_code)

                    self.log.warning(f"[RATE LIMIT] IP: {ip} exceeded limit.")

    def parse_req(self, req, payload, attack_local=None, attack_type=None) -> str:
        ip = req.remote_addr
        user_agent = req.headers.get("User-Agent", "unknown")
        path = req.path
        method = req.method
        attack_local = attack_local or "unknown"
        return f"[ATTACK] Attack_type: {attack_type}, IP: {ip}, User-Agent: {user_agent}, Path: {path}, Method: {method}, Payload: {unquote(payload)}, attack_local: {attack_local}"