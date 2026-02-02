from datetime import datetime
from sqlalchemy import (
    DateTime, Text, create_engine,
    Column, Integer, String, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# =========================
# CONFIGURAÇÃO GLOBAL
# =========================

DATABASE_URL = "sqlite:///wafaHell.db"

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


class WafLog(Base):
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
    __tablename__ = "admin_user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String(50), nullable=False, unique=True)
    password = Column(String(255), nullable=False)

    def __repr__(self):
        return f"<AdminUser(login='{self.login}')>"


# =========================
# DB INIT / SESSION
# =========================

def init_db():
    """Cria as tabelas uma única vez"""
    Base.metadata.create_all(bind=engine)


def get_session():
    """Retorna uma sessão reutilizável"""
    return SessionLocal()

