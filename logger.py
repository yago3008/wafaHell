from datetime import datetime
import logging
from model import WafLog, get_session
import re 
# Handler customizado para salvar no SQLite via SQLAlchemy
class SQLAlchemyHandler(logging.Handler):
    def __init__(self):
            super().__init__()
            self.session = get_session()
            # Regex para extrair dados da string formatada pelo parse_req
            self.attr_pattern = re.compile(
                r"Attack_type: (?P<type>.*?), IP: (?P<ip>.*?), .*?Path: (?P<path>.*?), Method: (?P<method>.*?), Payload: (?P<payload>.*?), attack_local: (?P<local>.*)"
            )

    def emit(self, record):
            session = self.session # Certifique-se de instanciar a sessão
            try:
                msg = record.getMessage()
                
                # Valores padrão
                ip, path, method, payload, local, attack_type = (None, None, None, msg, None, "Info")

                # Expandimos a condição para incluir [BLOCKED]
                if any(tag in msg for tag in ["[ATTACK]", "[RATE LIMIT]", "[BLOCKED]"]):
                    
                    def extract(key, text):
                        # Regex ajustada para capturar até a vírgula ou fim da tag, permitindo espaços internos
                        match = re.search(rf"{key}:?\s*([^,\]]+)", text)
                        return match.group(1).strip() if match else None

                    ip = extract("IP", msg)
                    
                    if "[BLOCKED]" in msg:
                        attack_type = "IP BLOCK"
                        ua = extract("UA", msg)
                        payload = f"IP Bloqueado. User-Agent: {ua}" if ua else "IP Bloqueado"
                        path = "---"
                        method = "---"
                    elif "[RATE LIMIT]" in msg:
                        attack_type = "RATE LIMIT"
                        payload = "Exceeded request limit"
                        path = extract("Path", msg)
                        method = extract("Method", msg)

                        bucket = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
                        log_entry = WafLog(
                            level=record.levelname,
                            attack_type=attack_type,
                            ip=ip,
                            path=path,
                            method=method,
                            payload=payload,
                            attack_local=local,
                            time_bucket=bucket
                        )
                        
                        session.add(log_entry)
                        session.commit()
                    else:
                        # Lógica para [ATTACK]
                        attack_type = extract("Attack_type", msg) or "Unknown"
                        path = extract("Path", msg)
                        method = extract("Method", msg)
                        
                        # Captura o local completo (ex: HEADER 'User-Agent')
                        local_match = re.search(r"attack_local:\s*(.+)$", msg)
                        local = local_match.group(1).strip() if local_match else extract("attack_local", msg)
                        
                        # Regex específica para payloads que podem conter vírgulas
                        payload_match = re.search(r"Payload: (.*?), attack_local:", msg)
                        payload = payload_match.group(1) if payload_match else extract("Payload", msg)
                    
                if not "[RATE LIMIT]" in msg:   
                    log_entry = WafLog(
                        level=record.levelname,
                        attack_type=attack_type,
                        ip=ip,
                        path=path,
                        method=method,
                        payload=payload,
                        attack_local=local,
                        # time_bucket fica None aqui para não filtrar ataques normais no banco
                    )

                    session.add(log_entry)
                    session.commit()
                    
            except Exception as e:
                session.rollback()
            finally:
                session.close()

class Logger:
    def __init__(self, name="WAF", log_file="waf.log", level=logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False

        if not self.logger.handlers:
            formatter = logging.Formatter(
                "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S - %d/%m/%Y"
            )

            # Handler 1: Console
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            # Handler 2: Arquivo
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            # # Handler 3: Banco de Dados (A Mágica acontece aqui)
            # db_handler = SQLAlchemyHandler()
            # db_handler.setLevel(logging.INFO) # Salva INFO, WARNING e acima no DB
            # self.logger.addHandler(db_handler)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)

    def debug(self, msg):
        self.logger.debug(msg)
