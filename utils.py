# from .model import WafLog, Blocked, Whitelist, AdminUser, get_session
# from .globals import waf_cache
import os
import hashlib
import uuid

from datetime import datetime, timedelta, timezone
import secrets
import socket
import string
import time
import tomllib
from werkzeug.security import generate_password_hash
from sqlalchemy.orm import Session
from sqlalchemy import literal, text, func, case
from functools import wraps
from flask import session, redirect, url_for, request
import geoip2.database

try:
    from model import WafLog, Blocked, Whitelist, AdminUser, get_session
    from globals import waf_cache
except ImportError:
    from .model import WafLog, Blocked, Whitelist, AdminUser, get_session
    from .globals import waf_cache


def b_print(msg: str) -> None:
    """
    Exibe uma mensagem formatada no console com a identidade visual do WafaHell.
    
    Esta função padroniza os logs de sistema utilizando sequências de escape ANSI 
    para colorir o prefixo em verde e o conteúdo da mensagem em branco, garantindo 
    que as notificações do WAF sejam facilmente distinguíveis dos logs padrão 
    da aplicação servidora (como os do Flask/Werkzeug).

    Args:
        msg (str): O conteúdo da mensagem a ser exibido no terminal.
    """
    VERDE = '\033[92m'
    BRANCO = '\033[97m'
    RESET = '\033[0m'
    print(f"{VERDE} * [WafaHell] {BRANCO}{msg}{RESET}")



class Admin:
    """
    Classe utilitária para gestão de credenciais administrativas do WafaHell.
    
    Responsável por gerar senhas criptograficamente seguras e garantir a 
    existência de um usuário administrador inicial (Bootstrap) no banco de dados.
    """
    @staticmethod
    def generate_secure_password(length: int = 64) -> str:
        """
        Gera uma sequência aleatória de alta entropia para uso em chaves e senhas.
        
        Utiliza o módulo 'secrets' do Python para garantir que a geração seja 
        criptograficamente forte, adequada para gerenciar segredos de segurança.

        Args:
            length (int): O comprimento da senha a ser gerada. Padrão: 64.

        Returns:
            str: Uma string contendo letras, dígitos e caracteres especiais.
        """
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def create_admin_user(session: Session) -> None:
        """
        Provisiona o usuário administrador padrão ('admin') caso ele não exista.
        
        A senha é gerada de forma determinística baseada na 'impressão digital' 
        do hardware (MAC Address + Hostname), garantindo que cada instalação 
        do WafaHell tenha uma senha única e exclusiva. O segredo é armazenado 
        utilizando hashes seguros para proteção contra vazamentos de banco de dados.

        Args:
            session (Session): Sessão ativa do SQLAlchemy para persistência.
        """
        admin = session.query(AdminUser).filter_by(login="admin").first()
        if admin:
            return
        raw_password = hashlib.sha256(f"{uuid.getnode()}-{socket.gethostname()}-wafahell-security-core-v1".encode()).hexdigest()
        hashed_password = generate_password_hash(raw_password)

        admin = AdminUser(
            login="admin",
            password=hashed_password
        )

        session.add(admin)
        session.commit()

        b_print("Usuario admin criado com sucesso.")
        b_print("Salve essa senha em um lugar seguro, não será mostrada novamente.")
        b_print(f"Senha: {raw_password}")

def admin(fn: callable) -> callable:
    """
    Decorador de controle de acesso para rotas administrativas.

    Esta função atua como um Middleware de autorização em nível de rota. 
    Ela verifica a existência de uma sessão ativa ('logged_in') antes de 
    permitir a execução da função original. Caso o usuário não esteja 
    autenticado, ele é redirecionado para a página de login.

    O decorador utiliza 'functools.wraps' para garantir que os metadados da 
    função original (como o nome e a docstring) sejam preservados, o que 
    é essencial para o correto funcionamento do roteamento do Flask.

    Args:
        fn (function): A função da rota que deve ser protegida.

    Returns:
        function: O wrapper que valida a sessão antes de chamar a função 'fn'.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            mounted_path = f"{request.script_root.rstrip('/')}{request.path}"
            return redirect(url_for("login", next=mounted_path))
        return fn(*args, **kwargs)
    return wrapper

class Dashboard:
    def __init__(self):
        self.geo_db_path = os.path.join(os.path.dirname(__file__), 'GeoLite2-Country.mmdb')
        self.attack_types = ("SQLI", "XSS", "RATE LIMIT", "CRITICAL PATH")
        
    def dashboard_setup(self: object) -> dict:
        """
    Prepara o conjunto de metadados e configurações globais para a interface do Dashboard.
    
    Esta função consolida informações do estado atual do WAF e realiza a leitura 
    dinâmica da versão do software diretamente dos arquivos de configuração do 
    projeto, garantindo que o painel exiba dados sempre atualizados.

    Returns:
        dict: Um objeto JSON contendo variáveis de ambiente e metadados do sistema.
    """
        json = {}

        def get_waf_version() -> str:
            """
        Localiza e extrai a versão atual do WafaHell do arquivo 'pyproject.toml'.
        
        Utiliza caminhos absolutos para navegar na estrutura de diretórios do projeto 
        e o módulo 'tomllib' para realizar o parse do arquivo de configuração padrão 
        do ecossistema Python moderno. Em caso de ausência do arquivo, retorna uma 
        versão de fallback para evitar falhas na renderização do painel.

        Returns:
            str: A versão do projeto (ex: '1.2.3') ou 'v.0.0.0' em caso de erro.
        """
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            toml_path = os.path.join(base_path, "pyproject.toml")
            
            try:
                with open(toml_path, "rb") as f:
                    data = tomllib.load(f)
                    return data["project"]["version"]
            except FileNotFoundError:
                return "v.0.0.0"
        
        def get_server_info() -> dict:
            """
            Coleta metadados operacionais e o estado de saúde (health check) do servidor.

            Realiza a leitura da latência média armazenada no cache para determinar 
            o status do sistema (Healthy, Degraded ou Critical) e identifica o nó 
            da rede via Hostname.

            Returns:
                dict: Dicionário contendo timestamp UTC, ID do nó, latência em ms, 
                      status de saúde do sistema e versão do WAF.
            """
            server_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            node_id = socket.gethostname()
            avg_latency = waf_cache.get('latency_avg', default=0.0)
            system_status = "critical" if avg_latency > 500 else "degraded" if avg_latency > 200 else "healthy"
            return {
                "server_time": server_time,
                "node_id": node_id,
                "average_latency_ms": round(float(avg_latency), 2),
                "system_status": system_status,
                "version": get_waf_version()
            }
        
        def get_kpis() -> dict:
            """
            Calcula os Indicadores Chave de Desempenho (KPIs) de segurança e tráfego.

            Esta função realiza uma análise comparativa entre as últimas 24h e o 
            período anterior de 48h para gerar tendências percentuais de ataques 
            e requisições. Além disso, monitora métricas de throughput em tempo 
            real (RPS) e o estado atual da Blacklist.

            A lógica inclui:
            - Cálculo de tendência (Trend %) para volume de tráfego e ameaças;
            - Monitoramento de RPS (Requisições por Segundo) atual e pico (Peak);
            - Contagem de ativos na Blacklist com validação de expiração;
            - Integração entre persistência (SQLAlchemy) e cache volátil (WafCache).

            Returns:
                dict: Conjunto de métricas estruturadas para alimentação dos 
                      cards informativos do Dashboard.
            """
            now = datetime.now(timezone.utc)
            last_24h = now - timedelta(hours=24)
            prev_24h = now - timedelta(hours=48)
            session = get_session()
            
            try:
                # --- TOTAIS DE HOJE ---
                total_today = session.query(func.count(WafLog.id)).filter(WafLog.timestamp >= last_24h).scalar() or 0
                blocked_today = session.query(func.count(WafLog.id)).filter(
                    WafLog.timestamp >= last_24h,
                    WafLog.attack_type.in_(self.attack_types)
                ).scalar() or 0

                # --- TOTAIS DE ONTEM (Para Tendência) ---
                total_yesterday = session.query(func.count(WafLog.id)).filter(
                    WafLog.timestamp >= prev_24h, 
                    WafLog.timestamp < last_24h
                ).scalar() or 0
                
                blocked_yesterday = session.query(func.count(WafLog.id)).filter(
                    WafLog.timestamp >= prev_24h, 
                    WafLog.timestamp < last_24h,
                    WafLog.attack_type.in_(self.attack_types)
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
                total_blacklist = session.query(func.count(Blocked.id))\
                    .filter(Blocked.blocked_until > now)\
                    .scalar() or 0
                # Como blocked_at é String formatada no seu modelo, comparamos com o horário
                added_today = session.query(func.count(Blocked.id)).filter(
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
            
            except Exception as e:
                print(f"Erro no Dashboard: {e}")
            finally:
                session.close()
                
        def get_traffic_chart() -> dict:
            """
            Gera os dados de séries temporais para o gráfico de tráfego dos últimos 40 minutos.

            Esta função realiza uma agregação granular por minuto diretamente no banco de dados, 
            separando o tráfego legítimo (INFO) das tentativas de ataque detectadas. O uso 
            da cláusula 'CASE' no SQL permite a contagem condicional em uma única varredura 
            (scan) na tabela, otimizando a performance da query.

            Returns:
                dict: Conjunto de dados estruturado com:
                    - labels: Lista de horários (HH:MM).
                    - series_legit: Volume de requisições normais.
                    - series_attacks: Volume de ameaças mitigadas.
            """
            now = datetime.now(timezone.utc)
            # Arredonda para o minuto atual para ficar limpo (ex: 10:05:00)
            end_date = now.replace(second=0, microsecond=0)
            start_date = end_date - timedelta(minutes=40)
            
            session = get_session()
            
            try:
                # 2. Query otimizada com group_concat para pegar IPs
                query = session.query(
                    func.strftime('%H:%M', WafLog.timestamp).label('minute'),
                    func.count(WafLog.id).label('total'),
                    func.sum(case((WafLog.attack_type == 'INFO', 1), else_=0)).label('legit'),
                    func.sum(case((WafLog.attack_type.in_(self.attack_types), 1), else_=0)).label('attacks'),
                    # Agrega IPs maliciosos numa string separada por vírgula
                    func.group_concat(
                        case((WafLog.attack_type.in_(self.attack_types), WafLog.ip), else_=literal(None)),
                        ','
                    ).label('attack_ips_str')
                ).filter(
                    WafLog.timestamp >= start_date,
                    WafLog.timestamp <= now # Garante não pegar dados futuros se houver drift
                )\
                .group_by('minute')\
                .all()

                # Transforma resultado do banco em um Dicionário para busca rápida
                # Ex: {'10:05': {'legit': 10, ...}, '10:06': ...}
                data_map = {
                    row.minute: {
                        # Fallback para cenários com logs sem attack_type='INFO':
                        # considera legítimo todo evento que não foi classificado como ataque.
                        'legit': max(0, int((row.total or 0) - (row.attacks or 0))),
                        'attacks': row.attacks or 0,
                        'ips': list(set(row.attack_ips_str.split(','))) if row.attack_ips_str else []
                    }
                    for row in query
                }

                # 3. Preenchimento de Lacunas (Gap Filling)
                # Cria os arrays finais garantindo que todos os 40 minutos existam, mesmo vazios
                labels = []
                series_legit = []
                series_attacks = []
                series_attack_ips = []

                # Loop de 0 a 40 minutos atrás
                current_step = start_date
                while current_step <= end_date:
                    step_label = current_step.strftime('%H:%M')
                    
                    # Se tiver dados no banco para esse minuto, usa. Se não, usa 0 e lista vazia.
                    step_data = data_map.get(step_label, {'legit': 0, 'attacks': 0, 'ips': []})
                    
                    labels.append(step_label)
                    series_legit.append(step_data['legit'])
                    series_attacks.append(step_data['attacks'])
                    series_attack_ips.append(step_data['ips']) # Sempre adiciona uma lista, mesmo que vazia []
                    
                    current_step += timedelta(minutes=1)

                return {
                        "labels": labels,
                        "series_legit": series_legit,
                        "series_attacks": series_attacks,
                        "series_attack_ips": series_attack_ips
                    }
                    
            except Exception as e:
                print(f"Erro no Dashboard: {e}")
                # Retorna estrutura vazia válida para não quebrar o JS
                return {"traffic_chart": {"labels": [], "series_legit": [], "series_attacks": [], "series_attack_ips": []}}
            finally:
                session.close()

        def get_distribution_vectors() -> list:
            """
            Calcula a distribuição percentual dos vetores de ataque (SQLi, XSS, etc.) 
            nas últimas 24 horas.

            A função agrupa as ameaças mitigadas por tipo e calcula a relevância 
            estatística de cada vetor em relação ao total de ataques. Estes dados 
            são fundamentais para identificar o foco predominante de tentativas 
            de invasão contra a aplicação protegida.

            Returns:
                list: Lista de dicionários contendo o rótulo do ataque, a contagem 
                      absoluta e a participação percentual no tráfego malicioso.
            """
            now = datetime.now(timezone.utc)
            last_24h = now - timedelta(hours=24)
            session = get_session()
            try:
                # 1. Buscamos a contagem agrupada por tipo de ataque
                # Filtramos para não incluir tráfego legítimo (INFO)
                query = session.query(
                    WafLog.attack_type,
                    func.count(WafLog.id).label('count')
                ).filter(
                    WafLog.timestamp >= last_24h,
                    WafLog.attack_type.in_(self.attack_types)
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
            except Exception as e:
                print(f"Erro no Dashboard: {e}")
            finally:
                session.close()

        def get_top_geo() -> tuple:
            """
            Realiza a geolocalização dos ataques para identificar as origens geográficas das ameaças.
            
            Esta função cruza os endereços IP registrados nos logs com o banco de dados binário 
            GeoLite2 (MaxMind) para extrair o código ISO e o nome do país. Os dados são 
            agrupados e ordenados para retornar os 5 países com maior volume de tráfego malicioso.

            Returns:
                list: Top 5 países contendo código, nome, contagem absoluta e percentual.
            """
            def resolve_ip(ip):
                try:         
                    if not os.path.exists(self.geo_db_path):
                        print("ERRO: Arquivo GeoLite2-Country.mmdb não encontrado!")
                        return "XX", "Unknown"
                        
                    with geoip2.database.Reader(self.geo_db_path) as reader:
                        response = reader.country(ip)
                        return response.country.iso_code, response.country.name
                except Exception as e:
                    print(f"Erro na consulta GeoIP: {e}")
                    return "XX", "Unknown"
                
            session = get_session()
            # 1. Busca todos os ataques agrupados por IP
            try:
                query = session.query(
                    WafLog.ip,
                    func.count(WafLog.id).label('count')
                ).filter(
                    WafLog.attack_type.in_(self.attack_types)
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
            except Exception as e:
                print(f"Erro no Dashboard: {e}")
            finally:
                session.close()
        
        def get_top_offenders() -> list:
            """
            Identifica os principais agressores (Top Offenders) e calcula um Score de Risco.

            A função analisa o comportamento de IPs específicos nas últimas 24h, levando em 
            conta não apenas o volume (hits), mas a diversidade de vetores de ataque utilizados 
            (ex: se um IP tentou SQLi e XSS simultaneamente, seu risco é maior).

            Lógica de Score (0-100):
            - Multiplicador de diversidade: 20 pontos por vetor único de ataque.
            - Multiplicador de volume: 1 ponto para cada 50 requisições maliciosas.
            - Teto: 100 pontos (Risco Crítico).

            Returns:
                list: Lista dos 5 IPs com maior pontuação de risco e seus respectivos metadados.
            """
            session = get_session()
            # 1. Agrupamos por IP e contamos os hits e os tipos de ataques diferentes
            # Ignoramos tráfego INFO
            try:
                query = session.query(
                    WafLog.ip,
                    func.count(WafLog.id).label('hits_count'),
                    func.count(func.distinct(WafLog.attack_type)).label('unique_vectors')
                ).filter(
                    WafLog.attack_type.in_(self.attack_types)
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
            except Exception as e:
                print(f"Erro no Dashboard: {e}")
            finally:
                session.close()

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
        
def seed_default_whitelist() -> None:
    """
    Popula a Whitelist com IPs essenciais (Localhost, DNS públicos, etc)
    Executar na inicialização do app.
    """
    # Lista de IPs Padrão (Adicione aqui IPs unitários que confia)
    DEFAULT_IPS = [
        # --- Localhost / Loopback (Essencial) ---
        #"127.0.0.1",
        "::1",
        "0.0.0.0",

        # Redes Privadas (As gigantes)
        "10.0.0.0/8",      # 16 milhões de IPs
        "172.16.0.0/12",   # 1 milhão de IPs
        "192.168.0.0/16",  # 65 mil IPs
        
        # --- DNS Públicos (Google) ---
        "8.8.8.8",
        "8.8.4.4",
        
        # --- DNS Públicos (Cloudflare) ---
        "1.1.1.1",
        "1.0.0.1",
        
        # --- DNS Públicos (OpenDNS) ---
        "208.67.222.222",
        "208.67.220.220",
        
        # --- DNS Públicos (Quad9) ---
        "9.9.9.9",
        "149.112.112.112"
    ]

    session = get_session()
    try:
        # 1. Descobre o que já existe no banco para não duplicar
        existing_query = session.query(Whitelist.ip).filter(Whitelist.ip.in_(DEFAULT_IPS)).all()
        existing_ips = {row.ip for row in existing_query}
        
        # 2. Filtra apenas os novos
        ips_to_insert = set(DEFAULT_IPS) - existing_ips
        
        if not ips_to_insert:
            b_print("Whitelist padrão já está atualizada.")
            return

        # 3. Prepara Bulk Insert e Cache
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        bulk_data = []
        
        for ip in ips_to_insert:
            bulk_data.append({
                "ip": ip,
                "added_at": now_str
            })
            # Já coloca no cache para funcionar imediatamente
            waf_cache.set(f"whitelist_{ip}", True, expire=3600)

        # 4. Grava no Banco
        session.bulk_insert_mappings(Whitelist, bulk_data)
        session.commit()
        
        b_print(f"Seed Whitelist: {len(ips_to_insert)} IPs padrão adicionados.")

    except Exception as e:
        session.rollback()
        print(f"Erro ao semear whitelist: {e}")
    finally:
        session.close()
