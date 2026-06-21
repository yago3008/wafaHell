try:
    from model import WafLog, get_session
except ImportError:
    from .model import WafLog, get_session
from datetime import datetime
import logging
import re 

class SQLAlchemyHandler(logging.Handler):
    """
    Handler customizado para interceptar logs do Python e persistir 
    automaticamente no banco de dados SQLite via SQLAlchemy.
    """
    def __init__(self):
        """
        Inicializa o handler de banco de dados, estabelece a sessão 
        e compila o padrão Regex para extração de logs complexos.
        """
        super().__init__()
        self.session = get_session()
        self.attr_pattern = re.compile(
            r"Attack_type: (?P<type>.*?), IP: (?P<ip>.*?), .*?Path: (?P<path>.*?), Method: (?P<method>.*?), Payload: (?P<payload>.*?), attack_local: (?P<local>.*)"
        )

    def emit(self, record):
        """
        Método chamado automaticamente pelo logger para cada mensagem.
        Realiza o parse da string da mensagem, identifica o tipo de ataque
        (SQLi, Rate Limit, Block) e salva no banco de dados WafLog.
        """
        session = self.session 
        try:
            msg = record.getMessage()
            
            # Valores padrão de inicialização
            ip, path, method, payload, local, attack_type = (None, None, None, msg, None, "Info")

            if any(tag in msg for tag in ["[ATTACK]", "[RATE LIMIT]", "[BLOCKED]"]):
                
                def extract(key, text):
                    """
                    Função auxiliar interna para extrair valores baseada em chaves 
                    específicas dentro de uma string de log formatada.
                    """
                    match = re.search(rf"{key}:?\s*([^,\]]+)", text)
                    return match.group(1).strip() if match else None

                ip = extract("IP", msg)
                
                if "[BLOCKED]" in msg:
                    attack_type = "IP BLOCK"
                    ua = extract("UA", msg)
                    payload = f"IP Bloqueado. User-Agent: {ua}" if ua else "IP Bloqueado"
                    path, method = "---", "---"

                elif "[RATE LIMIT]" in msg:
                    attack_type = "RATE LIMIT"
                    payload = "Exceeded request limit"
                    path = extract("Path", msg)
                    method = extract("Method", msg)

                    # Rate limits usam buckets de tempo para controle de frequência
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
                    # Lógica de extração detalhada para ataques (SQLi, XSS, etc)
                    attack_type = extract("Attack_type", msg) or "Unknown"
                    path = extract("Path", msg)
                    method = extract("Method", msg)
                    
                    local_match = re.search(r"attack_local:\s*(.+)$", msg)
                    local = local_match.group(1).strip() if local_match else extract("attack_local", msg)
                    
                    payload_match = re.search(r"Payload: (.*?), attack_local:", msg)
                    payload = payload_match.group(1) if payload_match else extract("Payload", msg)
                
            # Persistência final para logs que não são Rate Limit (evita duplicidade)
            if not "[RATE LIMIT]" in msg:   
                log_entry = WafLog(
                    level=record.levelname,
                    attack_type=attack_type,
                    ip=ip,
                    path=path,
                    method=method,
                    payload=payload,
                    attack_local=local
                )
                session.add(log_entry)
                session.commit()
                
        except Exception as e:
            session.rollback()
        finally:
            session.close()

class Logger:
    """
    Classe Wrapper de Logging para o WafaHell. 
    Gerencia saídas simultâneas para o console (Terminal) e arquivo local (.log).
    """
    def __init__(self, name="WAF", log_file="waf.log", level=logging.INFO):
        """
        Configura o logger principal, define o formato das mensagens 
        e acopla os handlers de Console, Arquivo e Banco de Dados.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False

        if not self.logger.handlers:
            formatter = logging.Formatter(
                "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S - %d/%m/%Y"
            )

            # Handler 1: Console (Visualização em tempo real)
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            # Handler 2: Arquivo (Persistência em texto puro)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            # Persistencia para dashboard ocorre via batch no middleware.

    def info(self, msg: str) -> None:
        """Registra uma mensagem informativa de rotina."""
        self.logger.info(msg)

    def warning(self, msg: str) -> None:
        """Registra avisos e comportamentos suspeitos que não geram bloqueio."""
        self.logger.warning(msg)

    def error(self, msg: str) -> None:
        """Registra falhas no processamento ou erros de validação."""
        self.logger.error(msg)

    def critical(self, msg: str) -> None:
        """Registra ataques confirmados e eventos de alta severidade."""
        self.logger.critical(msg)

    def debug(self, msg: str) -> None:
        """Registra informações detalhadas para desenvolvedores em modo de teste."""
        self.logger.debug(msg)
