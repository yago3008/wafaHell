from datetime import datetime, timedelta, timezone
import secrets
import string
import time
from werkzeug.security import generate_password_hash
from sqlalchemy.orm import Session
from sqlalchemy import text, func, case
from model import WafLog, Blocked
from model import AdminUser
from functools import wraps
from flask import session, redirect, url_for, request
from model import get_session
from globals import waf_cache
import geoip2.database
import os

class Admin:
    @staticmethod
    def generate_secure_password(length=64):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def create_admin_user(session: Session):
        admin = session.query(AdminUser).filter_by(login="admin").first()
        if admin:
            return
        raw_password = "admin" #Admin.generate_secure_password(64)
        hashed_password = generate_password_hash(raw_password)

        admin = AdminUser(
            login="admin",
            password=hashed_password
        )

        session.add(admin)
        session.commit()

        print("* [WafaHell] Usuario admin criado com sucesso.")
        print("* [WafaHell] Salve essa senha em um lugar seguro, não será mostrada novamente")
        print("Senha: ", raw_password)

def admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        print(f"DEBUG: Session logged_in status: {session.get('logged_in')}") # Adicione isso
        if not session.get("logged_in"):
            print("DEBUG: Redirecting to login...")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

class Dashboard:
    def __init__(self):
        self.db_session = get_session()
        self.geo_db_path = os.path.join(os.path.dirname(__file__), 'GeoLite2-Country.mmdb')
        
    def dashboard_setup(self):
        json = {}
        def get_server_info():
            server_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            node_id = "WAF-01"
            avg_latency = waf_cache.get('latency_avg', default=0.0)
            system_status = "critical" if avg_latency > 500 else "degraded" if avg_latency > 200 else "healthy"
            return {
                "server_time": server_time,
                "node_id": node_id,
                "average_latency_ms": round(float(avg_latency), 2),
                "system_status": system_status
            }
        
        def get_kpis():
            now = datetime.now(timezone.utc)
            last_24h = now - timedelta(hours=24)
            prev_24h = now - timedelta(hours=48)

            # --- TOTAIS DE HOJE ---
            total_today = self.db_session.query(func.count(WafLog.id)).filter(WafLog.timestamp >= last_24h).scalar() or 0
            blocked_today = self.db_session.query(func.count(WafLog.id)).filter(
                WafLog.timestamp >= last_24h, 
                WafLog.attack_type != 'INFO'
            ).scalar() or 0

            # --- TOTAIS DE ONTEM (Para Tendência) ---
            total_yesterday = self.db_session.query(func.count(WafLog.id)).filter(
                WafLog.timestamp >= prev_24h, 
                WafLog.timestamp < last_24h
            ).scalar() or 0
            
            blocked_yesterday = self.db_session.query(func.count(WafLog.id)).filter(
                WafLog.timestamp >= prev_24h, 
                WafLog.timestamp < last_24h,
                WafLog.attack_type != 'INFO'
            ).scalar() or 0

            # --- CÁLCULO DE TENDÊNCIA (%) ---
            def calc_trend(current, previous):
                if previous == 0:
                    return 100.0 if current > 0 else 0.0
                return round(((current - previous) / previous * 100), 1)

            trend_total = calc_trend(total_today, total_yesterday)
            trend_attacks = calc_trend(blocked_today, blocked_yesterday)

            # --- INFOS COMPLEMENTARES ---
            from globals import waf_cache
            # Latência e RPS vindos do Cache Global
            last_second_timestamp = int(time.time()) - 1
            rps_key = f"rps_{last_second_timestamp}"

            # 2. Lê o valor real do cache para esse segundo específico
            current_rps = waf_cache.get(rps_key, default=0)

            # 3. Lógica do Pico (Peak)
            # Aqui continuamos usando uma chave fixa 'rps_peak_hour' para guardar o recorde
            peak_rps = waf_cache.get('rps_peak_hour', default=0)

            if current_rps > peak_rps:
                peak_rps = current_rps
                # Atualiza o recorde no cache por 1 hora
                waf_cache.set('rps_peak_hour', peak_rps, expire=3600)
            
            # Dados da Blacklist
            total_blacklist = self.db_session.query(func.count(Blocked.id)).scalar() or 0
            # Como blocked_at é String formatada no seu modelo, comparamos com o horário
            added_today = self.db_session.query(func.count(Blocked.id)).filter(
                Blocked.blocked_until >= now # Um IP "adicionado hoje" é tecnicamente um ainda bloqueado
            ).scalar() or 0

            return {
                "total_requests_24h": {
                    "value": total_today,
                    "trend_percent": trend_total
                },
                "attacks_mitigated_24h": {
                    "value": blocked_today,
                    "trend_percent": trend_attacks # Adicionado aqui
                },
                "throughput": {
                    "current_req_per_sec": current_rps,
                    "peak_last_hour": peak_rps
                },
                "blacklist_count": {
                    "total_ips": total_blacklist,
                    "added_today": added_today
                }
            }
        
        def get_traffic_chart():
            now = datetime.now(timezone.utc)
            start_time = now - timedelta(minutes=40)

            # Query para agrupar por minuto
            # No SQLite usamos strftime, no Postgres/MySQL seria date_format ou similar
            query = self.db_session.query(
                func.strftime('%H:%M', WafLog.timestamp).label('minute'),
                func.count(WafLog.id).label('total'),
                func.sum(case({WafLog.attack_type == 'INFO': 1}, else_=0)).label('legit'),
                func.sum(case({WafLog.attack_type != 'INFO': 1}, else_=0)).label('attacks')
            ).filter(WafLog.timestamp >= start_time)\
            .group_by('minute')\
            .order_by('minute').all()

            labels = []
            series_legit = []
            series_attacks = []

            # Preenche os arrays para o gráfico
            for row in query:
                labels.append(row.minute)
                series_legit.append(row.legit or 0)
                series_attacks.append(row.attacks or 0)

            # Caso não existam dados nos últimos 40 min, retorna arrays vazios para não quebrar o front
            return {
                "labels": labels,
                "series_legit": series_legit,
                "series_attacks": series_attacks
            }

        def get_distribution_vectors():
            now = datetime.now(timezone.utc)
            last_24h = now - timedelta(hours=24)

            # 1. Buscamos a contagem agrupada por tipo de ataque
            # Filtramos para não incluir tráfego legítimo (INFO)
            query = self.db_session.query(
                WafLog.attack_type,
                func.count(WafLog.id).label('count')
            ).filter(
                WafLog.timestamp >= last_24h,
                WafLog.attack_type != 'INFO'
            ).group_by(WafLog.attack_type).all()

            # 2. Calculamos o total de ataques para obter a porcentagem
            total_attacks = sum(row.count for row in query)
            
            distribution = []
            
            for row in query:
                percentage = round((row.count / total_attacks * 100), 1) if total_attacks > 0 else 0
                distribution.append({
                    "label": row.attack_type,
                    "count": row.count,
                    "percentage": percentage
                })

            # Caso não haja ataques, retornamos uma lista vazia ou um placeholder
            return distribution

        def get_top_geo():
            def resolve_ip(ip):
                try:         
                    if not os.path.exists(self.geo_db_path):
                        print("ERRO: Arquivo GeoLite2-Country.mmdb não encontrado!")
                        return "XX", "Unknown"
                        
                    with geoip2.database.Reader(self.geo_db_path) as reader:
                        response = reader.country(ip)
                        return response.country.iso_code, response.country.name
                except Exception as e:
                    print(f"Erro na consulta GeoIP: {e}") # Isso vai te dizer se o banco está corrompido ou o IP é inválido
                    return "XX", "Unknown"
                
            now = datetime.now(timezone.utc)
            last_24h = now - timedelta(hours=24)

            # 1. Busca todos os ataques agrupados por IP
            query = self.db_session.query(
                WafLog.ip,
                func.count(WafLog.id).label('count')
            ).filter(
                WafLog.timestamp >= last_24h,
                WafLog.attack_type != 'INFO'
            ).group_by(WafLog.ip).all()

            geo_stats = {}
            total_attacks = 0

            # 2. Processa cada IP real usando o GeoIP2
            for row in query:
                code, name = resolve_ip(row.ip)
                
                if code not in geo_stats:
                    geo_stats[code] = {"name": name, "count": 0}
                
                geo_stats[code]["count"] += row.count
                total_attacks += row.count

            # 3. Formata o Top 5
            top_geo = []
            sorted_geo = sorted(geo_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:5]

            for code, data in sorted_geo:
                percentage = round((data["count"] / total_attacks * 100), 1) if total_attacks > 0 else 0
                top_geo.append({
                    "country_code": code,
                    "country_name": data["name"],
                    "count": data["count"],
                    "percentage": percentage
                })

            return top_geo
        
        def get_top_offenders():
            now = datetime.now(timezone.utc)
            last_24h = now - timedelta(hours=24)

            # 1. Agrupamos por IP e contamos os hits e os tipos de ataques diferentes
            # Ignoramos tráfego INFO
            query = self.db_session.query(
                WafLog.ip,
                func.count(WafLog.id).label('hits_count'),
                func.count(func.distinct(WafLog.attack_type)).label('unique_vectors')
            ).filter(
                WafLog.timestamp >= last_24h,
                WafLog.attack_type != 'INFO'
            ).group_by(WafLog.ip).order_by(text('hits_count DESC')).limit(5).all()

            offenders = []
            for row in query:
                # 2. Lógica de Risk Score (0 a 100)
                # Baseada em volume e diversidade de ataques
                # Ex: Cada vetor único vale 20 pontos + 1 ponto para cada 50 hits (até o teto de 100)
                vector_points = row.unique_vectors * 20
                hit_points = row.hits_count // 50
                risk_score = min(100, vector_points + hit_points)

                offenders.append({
                    "ip": row.ip,
                    "risk_score": int(risk_score),
                    "hits_count": row.hits_count
                })

            return offenders

        try:
            json['meta'] = get_server_info()
            json['kpis'] = get_kpis()
            json['traffic_chart'] = get_traffic_chart()
            json['distribution_vectors'] = get_distribution_vectors()
            json['top_geo'] = get_top_geo()
            json['top_offenders'] = get_top_offenders()
            
            return json

        except Exception as e:
            print(f"Erro no Dashboard: {e}")
            return {"error": str(e)}
            
        finally:
            self.db_session.close()