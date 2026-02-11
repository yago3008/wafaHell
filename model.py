from datetime import datetime
from sqlalchemy import (
    DateTime, Text, create_engine,
    Column, Integer, String, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

DATABASE_URL = "sqlite:///wafahell.db"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True
)

SessionLocal = scoped_session(
    sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False
    )
)

Base = declarative_base()

# =========================
# MODELS
# =========================

class Blocked(Base):
    """
    Entidade responsável por armazenar IPs e User-Agents que foram 
    temporariamente suspensos pelo WAF devido a violações persistentes.
    """
    __tablename__ = "blocks"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    blocked_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now().strftime("%H:%M:%S")
    )
    blocked_until = Column(DateTime, nullable=False)

    def __repr__(self):
        return (
            f"<Blocked(ip='{self.ip}', "
            f"user_agent='{self.user_agent}', "
            f"blocked_at='{self.blocked_at}', "
            f"blocked_until='{self.blocked_until}')>"
        )

class Whitelist(Base):
    """
    Lista de IPs confiáveis (Whitelisting). Requisições vindas destes IPs 
    ignoram as checagens de segurança padrão do motor do WafaHell.
    """
    __tablename__ = "whitelist"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, nullable=False, unique=True)
    added_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    def __repr__(self):
        return f"<Whitelist(ip='{self.ip}', added_at='{self.added_at}')>"

class CriticalPaths(Base):
    """
    Armazena endpoints sensíveis da aplicação (ex: /login, /admin). 
    Acessos a estes caminhos podem sofrer inspeção mais rigorosa.
    """
    __tablename__ = "critical_paths"
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, nullable=False, unique=True)
    added_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    def __repr__(self):
        return f"<CriticalPaths(path='{self.path}', added_at='{self.added_at}')>"

class WafLog(Base):
    """
    Repositório central de eventos de segurança. Registra ataques detectados, 
    o payload utilizado, local da detecção (Headers/Body) e metadados do atacante.
    Possui uma UniqueConstraint para evitar inundação de logs idênticos no mesmo minuto.
    """
    __tablename__ = "waf_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    time_bucket = Column(String(20), index=True) 
    
    attack_type = Column(String(50))
    ip = Column(String(50))
    path = Column(String(200))
    method = Column(String(10))
    payload = Column(Text)
    attack_local = Column(String(50))
    level = Column(String(20))

    __table_args__ = (
        UniqueConstraint('ip', 'attack_type', 'time_bucket', name='uix_ip_attack_time'),
    )


class AdminUser(Base):
    """
    Credenciais administrativas para acesso ao Dashboard do WafaHell. 
    Gerencia o acesso ao painel de controle e visualização de métricas.
    """
    __tablename__ = "admin_user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String(50), nullable=False, unique=True)
    password = Column(String(255), nullable=False)

    def __repr__(self):
        return f"<AdminUser(login='{self.login}')>"


# =========================
# DB INIT / SESSION
# =========================

def init_db() -> None:
    """
    Varre todos os modelos herdados de 'Base' e cria as tabelas no 
    banco de dados SQLite caso elas ainda não existam.
    """
    Base.metadata.create_all(bind=engine)


def get_session() -> scoped_session:
    """
    Provê uma sessão de banco de dados thread-safe gerenciada pelo scoped_session. 
    Deve ser fechada após o uso para retornar a conexão ao pool.
    """
    return SessionLocal()