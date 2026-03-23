# from .model import AdminUser, WafLog, Whitelist, get_session, Blocked
# from .globals import waf_cache
# from .utils import Dashboard, admin, b_print
import random
import time
import requests
from model import AdminUser, CriticalPaths, WafLog, Whitelist, get_session, Blocked
from globals import waf_cache
from utils import Dashboard, admin, b_print
from datetime import datetime, timedelta, timezone
import re
from flask import Flask, request, jsonify, make_response, flash, session, redirect, render_template
from sqlalchemy import func
import csv
import io
from werkzeug.security import check_password_hash

dashboard = Dashboard()
DEFAULT_TARGET = "http://127.0.0.1:5001/hello" ## MUDAR

def get_logs_and_stats(ip_filter: str = None, type_filter: str = None, limit: int = 100) -> tuple[list, dict]:
    """
    Consulta o banco de dados para extrair logs de auditoria e gerar métricas 
    agrupadas por tipo de ameaça para o Dashboard.

    A função realiza queries dinâmicas que se adaptam aos filtros de busca (IP ou Tipo)
    e formata os objetos do SQLAlchemy para dicionários compatíveis com JSON, 
    além de mapear os tipos internos do WAF para labels visuais (ATTACK, BLOCKED, INFO).

    Args:
        ip_filter (str, optional): Filtra os resultados por um endereço IP específico.
        type_filter (str, optional): Filtra os logs por tipo (ex: 'SQLI', 'XSS').
        limit (int): Número máximo de registros para a listagem principal.

    Returns:
        tuple: (list, dict) Contendo a lista de logs formatados e o dicionário de estatísticas.
    """
    session = get_session()
    try:
        log_query = session.query(WafLog).order_by(WafLog.id.desc())
        stat_query = session.query(func.count(WafLog.id))

        if ip_filter:
            log_query = log_query.filter(WafLog.ip == ip_filter)
            stat_query = stat_query.filter(WafLog.ip == ip_filter)
        if type_filter:
            log_query = log_query.filter(WafLog.attack_type == type_filter)
            stat_query = stat_query.filter(WafLog.attack_type == type_filter)

        db_logs = log_query.limit(limit).all()
        
        # Estatísticas Dinâmicas
        stats = {
            "total": stat_query.scalar() or 0,
            # Agora attacks conta tudo que não é 'Info' ou 'System'
            "attacks": stat_query.filter(WafLog.attack_type.in_(['SQLI', 'XSS', 'RATE LIMIT'])).scalar() or 0,
            "sqli": stat_query.filter(WafLog.attack_type == 'SQLI').scalar() or 0,
            "xss": stat_query.filter(WafLog.attack_type == 'XSS').scalar() or 0,
            "rate_limit": stat_query.filter(WafLog.attack_type == 'RATE LIMIT').scalar() or 0,
            "blocks": stat_query.filter(WafLog.attack_type == 'IP BLOCK').scalar() or 0
            }

        formatted_logs = []
        for log in db_logs:
            # Determinamos o "Tipo" visual para o HTML
            display_type = "INFO"
            if log.attack_type in ['SQLI', 'XSS', 'RATE LIMIT']:
                display_type = "ATTACK"
            elif log.attack_type == 'IP BLOCK':
                display_type = "BLOCKED" # Mudança aqui para o dashboard

            formatted_logs.append({
                "timestamp": log.timestamp.strftime("%H:%M:%S - %d/%m/%Y"),
                "type": display_type,
                "details": {
                    "attack_type": log.attack_type,
                    "ip": log.ip or "---",
                    "path": log.path or "---",
                    "method": log.method or "---",
                    "payload": log.payload or "---",
                    "attack_local": log.attack_local or "---"
                }
            })
        return formatted_logs, stats
    finally:
        session.close()

def setup_dashboard(app: Flask, custom_path: str = None) -> None:

    target_path = custom_path or '/admin/dashboard'

    @app.route(target_path + "/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("user")
            password = request.form.get("password")
            db_session = get_session()
            try:
                admin = db_session.query(AdminUser).filter(AdminUser.login == username).first()

                if admin and check_password_hash(admin.password, password):
                    session["logged_in"] = True
                    next_page = request.args.get("next", target_path)
                    return redirect(next_page)
                else:
                    flash("Acesso Negado: Credenciais Inválidas", "error")
                    return redirect(request.url)
            finally:
                db_session.close()

        return render_template("login.html")
    
    @app.route(target_path + '/data')
    @admin
    def wafahell_data():
        ip_f = request.args.get('ip')
        type_f = request.args.get('type')
        logs, stats = get_logs_and_stats(ip_filter=ip_f, type_filter=type_f)
        return jsonify({"logs": logs, "stats": stats})

    @app.route(target_path)
    @admin
    def wafahell_dashboard():
        ip_f = request.args.get('ip')
        type_f = request.args.get('type')
        logs, stats = get_logs_and_stats(ip_filter=ip_f, type_filter=type_f)
        return render_template('dashboard.html', logs=logs, stats=stats, filters={'ip': ip_f, 'type': type_f})
    
    @app.route(target_path + '/export/csv')
    @admin
    def export_csv():
        try:
            ip_filter = request.args.get('ip')
            type_filter = request.args.get('type')
            
            session = get_session()
            query = session.query(WafLog)
            
            if ip_filter:
                query = query.filter(WafLog.ip == ip_filter)
            if type_filter:
                query = query.filter(WafLog.attack_type == type_filter)
                
            logs = query.order_by(WafLog.timestamp.desc()).all()
            session.close()

            # Criamos o CSV em memória
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Cabeçalho
            writer.writerow(['Data/Hora', 'Tipo', 'IP', 'Endpoint', 'Metodo', 'Payload'])
            
            for log in logs:
                writer.writerow([
                    log.timestamp,
                    log.attack_type,
                    log.ip,
                    log.path,
                    log.method,
                    log.payload
                ])

            response = make_response(output.getvalue())
            response.headers["Content-Disposition"] = f"attachment; filename=waf_logs_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            response.headers["Content-type"] = "text/csv"
            return response
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            session.close()
    
    @app.route(target_path + '/block_ip', methods=['POST'])
    @admin
    def block_ip() -> bool:
        data = request.get_json()
        ip = data.get('ip')
        block_time = data.get('block_time_minutes', 5)

        if not ip:
            return jsonify({"status": "error", "message": "IP ausente"}), 400

        session = get_session()

        try:
            exists = session.query(Blocked).filter_by(ip=ip, user_agent="MANUAL_BLOCK").first()
            if exists:
                exists.blocked_until = datetime.now(timezone.utc) + timedelta(minutes=int(block_time))
                session.commit()
                return jsonify({"status": "success", "message": "Tempo de bloqueio atualizado"})

            now = datetime.now(timezone.utc)
            until = now + timedelta(minutes=int(block_time))

            new_block = Blocked(
                ip=ip,
                user_agent="MANUAL_BLOCK",
                blocked_until=until
            )
            
            session.add(new_block)
            session.commit()
            return jsonify({"status": "success", "message": "IP bloqueado com sucesso"})
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            session.close()

    @app.route(target_path + '/blocked_list', methods=['GET'])
    @admin
    def get_blocked_list():
        session = get_session()
        try:
            now = datetime.now(timezone.utc)
            blocks = session.query(Blocked).filter(Blocked.blocked_until > now).all()
            
            data = []
            for b in blocks:
                # Calcula tempo restante
                remaining = b.blocked_until.replace(tzinfo=timezone.utc) - now
                mins, secs = divmod(remaining.total_seconds(), 60)
                
                data.append({
                    "ip": b.ip,
                    "user_agent": b.user_agent[:30] + '...' if len(b.user_agent) > 30 else b.user_agent,
                    "expires_in": f"{int(mins)}m {int(secs)}s"
                })
            return jsonify(data)
        finally:
            session.close()

    @app.route(target_path + '/unblock_ip', methods=['POST'])
    @admin
    def manual_unblock():
        data = request.get_json()
        ip = data.get('ip')
        session = get_session()
        try:
            session.query(Blocked).filter(Blocked.ip == ip).delete()
            session.commit()
            
            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            session.close()

    @app.route(target_path + '/graphs', methods=['GET'])
    @admin
    def graphs():
        return render_template('graphs.html')
    
    @app.route(target_path + '/stats', methods=['GET'])
    @admin
    def api_stats():
        return jsonify(dashboard.dashboard_setup())
    
    @app.route(target_path + '/vars', methods=['GET'])
    @admin
    def get_vars():
        from middleware import Wafahell
        waf = Wafahell()

        output = {}
        allowed_types = (str, int, float, bool, list, dict)
        blacklisted_keys = {'app', 'log', 'recent_blocks_cache', '_instance', 'initialized', 'dashboard_path', 'ai_treshold'}

        for key, value in vars(waf).items():
            if key not in blacklisted_keys and isinstance(value, allowed_types):
                output[key] = value
                
        return output

    @app.route(target_path + '/vars/change', methods=['POST'])
    @admin
    def vars_change():
        data = request.json
        key = data.get('key')
        value = data.get('value')

        from middleware import Wafahell
        waf = Wafahell()

        if hasattr(waf, key):
            
            setattr(waf, key, value)
            
            return {"status": "success", "message": f"{key} updated", "newValue": value}
        
        return {"status": "error", "message": "Invalid variable"}, 400
    
    @app.route(target_path + '/import_blacklist', methods=['POST'])
    @admin
    def import_blacklist():
        data = request.get_json()
        raw_ips = data.get('ips', [])
        
        if not raw_ips:
            return jsonify({"status": "error", "message": "Nenhum IP fornecido."}), 400

        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        valid_ips = set(ip for ip in raw_ips if ip_regex.match(ip))
        
        if not valid_ips:
            return jsonify({"status": "error", "message": "Nenhum IP válido encontrado."}), 400

        session = get_session()
        try:
            existing_query = session.query(Blocked.ip).filter(Blocked.ip.in_(valid_ips)).all()
            existing_ips = {row.ip for row in existing_query}
            
            ips_to_insert = valid_ips - existing_ips
            
            if not ips_to_insert:
                return jsonify({"status": "success", "message": "Todos os IPs já estavam na blacklist."})

            now = datetime.now(timezone.utc)
            until = now + timedelta(days=3600) 
            
            bulk_data = []
            for ip in ips_to_insert:
                bulk_data.append({
                    "ip": ip,
                    "user_agent": "MANUAL_IMPORT_LIST",
                    "blocked_at": now.strftime("%H:%M:%S"), 
                    "blocked_until": until
                })
                
                waf_cache.set(f"blocked_{ip}", True, expire=60)

            session.bulk_insert_mappings(Blocked, bulk_data)
            session.commit()
            
            count = len(ips_to_insert)
            b_print(f"Blacklist importada: {count} novos IPs.")
            
            return jsonify({
                "status": "success", 
                "message": f"Sucesso! {count} novos IPs adicionados à Blacklist."
            })

        except Exception as e:
            session.rollback()
            print(f"Erro na importação: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            session.close()

    @app.route(target_path + '/import_whitelist', methods=['POST'])
    @admin
    def import_whitelist():
        data = request.get_json()
        raw_ips = data.get('ips', [])
        
        if not raw_ips:
            return jsonify({"status": "error", "message": "Nenhum IP fornecido."}), 400

        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        valid_ips = set(ip for ip in raw_ips if ip_regex.match(ip))
        
        if not valid_ips:
            return jsonify({"status": "error", "message": "Nenhum IP válido encontrado."}), 400

        session = get_session()
        try:
            existing_query = session.query(Whitelist.ip).filter(Whitelist.ip.in_(valid_ips)).all()
            existing_ips = {row.ip for row in existing_query}
            
            ips_to_insert = valid_ips - existing_ips
            
            if not ips_to_insert:
                return jsonify({"status": "success", "message": "Todos os IPs já estavam na whitelist."})

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            bulk_data = []
            
            for ip in ips_to_insert:
                bulk_data.append({
                    "ip": ip,
                    "added_at": now_str
                })
                waf_cache.set(f"whitelist_{ip}", True, expire=3600)

            session.bulk_insert_mappings(Whitelist, bulk_data)
            session.commit()
            
            count = len(ips_to_insert)
            
            return jsonify({
                "status": "success", 
                "message": f"Sucesso! {count} IPs adicionados à Whitelist."
            })

        except Exception as e:
            session.rollback()
            print(f"Erro whitelist: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            session.close()

    @app.route(target_path + '/import_critical_paths', methods=['POST'])
    @admin
    def import_critical_paths():
        """
    Configura e registra dinamicamente todas as rotas da interface administrativa (Dashboard) 
    na instância principal do Flask.

    Este método encapsula toda a lógica de endpoints do WAF, incluindo:
    - Autenticação de administradores (Login/Session);
    - Visualização de logs e estatísticas em tempo real;
    - Gestão de Blacklist e Whitelist (bloqueio/desbloqueio manual e importação em massa);
    - Exportação de dados para relatórios CSV;
    - Alteração dinâmica de variáveis de configuração do Middleware via API.

    Args:
        app (Flask): A instância da aplicação Flask onde o Dashboard será injetado.
        custom_path (str, optional): O prefixo da URL para o painel. 
                                     Padrão: '/admin/dashboard'.

    Note:
        Todas as rotas críticas são protegidas pelo decorador '@admin', que valida 
        se existe uma sessão ativa antes de permitir o acesso.
    """
        data = request.get_json()
        raw_paths = data.get('paths', [])
        
        if not raw_paths:
            return jsonify({"status": "error", "message": "Nenhum path fornecido."}), 400

        valid_paths = set(path.strip() for path in raw_paths if path.strip())
        
        if not valid_paths:
            return jsonify({"status": "error", "message": "Nenhum path válido encontrado."}), 400

        session = get_session()
        try:
            for p in valid_paths:
                exists = session.query(CriticalPaths).filter_by(path=p).first()
                if not exists:
                    new_path = CriticalPaths(path=p)
                    session.add(new_path)
            
            session.commit()

            all_paths = [cp.path for cp in session.query(CriticalPaths).all()]
            waf_cache.set('critical_paths', all_paths, expire=3600)

            return jsonify({
                "status": "success", 
                "message": f"Sucesso! {len(valid_paths)} caminhos críticos importados."
            })
        
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            session.close()

    b_print(f"Dashboard e API de dados prontos em: {target_path}")

    USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "sqlmap/1.9.11#stable (https://sqlmap.org)",
    "curl/8.1.2",
    "python-requests/2.31.0",
    "Nikto/2.1.6",
    "Go-http-client/1.1",
    ]

    PARAM_NAMES  = ["id", "user", "nome", "search", "q", "page", "category", "token", "ref", "lang"]
    NOISE_VALUES = ["1", "true", "en-US", "default", "home", "42", "admin", "index", "null", "undefined"]

    # ─────────────────────────────────────────────
    #  PAYLOADS
    # ─────────────────────────────────────────────
    SQLI_PAYLOADS = [
        # Boolean based
        ("' OR '1'='1",                                                    "Boolean — OR clássico"),
        ("' OR '1'='1' --",                                                "Boolean — OR com comentário"),
        ("' OR 1=1 --",                                                    "Boolean — OR numérico"),
        ("admin' --",                                                      "Boolean — bypass de login"),
        ("' OR 'x'='x",                                                    "Boolean — OR string"),
        ("1 OR 1=1",                                                       "Boolean — sem aspas"),
        ("' AND 1=1 --",                                                   "Boolean — AND verdadeiro"),
        ("' AND 1=2 --",                                                   "Boolean — AND falso"),
        ("') OR ('1'='1",                                                  "Boolean — com parêntese"),
        ("1; --",                                                          "Terminação de query"),
        # UNION based
        ("' UNION SELECT NULL --",                                         "UNION — 1 coluna"),
        ("' UNION SELECT NULL,NULL --",                                    "UNION — 2 colunas"),
        ("' UNION SELECT NULL,NULL,NULL --",                               "UNION — 3 colunas"),
        ("' UNION SELECT username,password FROM users --",                 "UNION — exfiltração"),
        ("1 UNION ALL SELECT 1,2,3 --",                                   "UNION ALL"),
        ("' UNION SELECT table_name FROM information_schema.tables --",    "UNION — info_schema"),
        # Error based
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",               "Error — EXTRACTVALUE"),
        ("' AND UPDATEXML(1,CONCAT(0x7e,DATABASE()),1) --",               "Error — UPDATEXML"),
        ("'; SELECT * FROM users WHERE 'a'='a",                           "Error — query adicional"),
        # Time based
        ("'; SELECT PG_SLEEP(3) --",                                       "Time — pg_sleep PostgreSQL"),
        ("'; WAITFOR DELAY '0:0:3' --",                                    "Time — WAITFOR SQL Server"),
        ("' AND SLEEP(3) --",                                              "Time — SLEEP MySQL"),
        ("' AND (SELECT 5264 FROM (SELECT(SLEEP(3)))x) --",               "Time — SLEEP subquery"),
        ("'; exec master..xp_cmdshell('ping 127.0.0.1') --",              "Time — xp_cmdshell"),
        # Stacked queries
        ("'; DROP TABLE users --",                                         "Stacked — DROP TABLE"),
        ("'; INSERT INTO logs VALUES('hacked') --",                        "Stacked — INSERT"),
        ("'; UPDATE users SET password='pwned' --",                        "Stacked — UPDATE"),
        # Obfuscação
        ("'/**/OR/**/'1'='1",                                             "Obfusc — comentários inline"),
        ("' OR 0x31=0x31 --",                                             "Obfusc — hex comparison"),
        ("' oR '1'='1",                                                    "Obfusc — case mixing"),
        ("'\tor\t'1'='1",                                                  "Obfusc — tabs"),
    ]

    BENIGN_EDGE_CASES = [
        ("SELECT your favorite color",          "Edge — SELECT em texto natural"),
        ("It's a beautiful day",                "Edge — apóstrofo em frase"),
        ("user@domain.com OR notify me",        "Edge — OR em linguagem natural"),
        ("price > 100 AND category = shoes",    "Edge — filtro legítimo de loja"),
        ("WHERE can I find the menu?",          "Edge — WHERE em pergunta"),
        ("DROP the ball and run",               "Edge — DROP em linguagem natural"),
        ("UNION of states formed in 1776",      "Edge — UNION histórico"),
        ("INSERT your name here",               "Edge — INSERT em instrução"),
        ("NULL value in philosophy",            "Edge — NULL conceitual"),
        ("sleep(8) hours for recovery",         "Edge — sleep() em texto"),
        ("1=1 is always true in math",          "Edge — 1=1 em explicação"),
        ("100% OR money back guaranteed",       "Edge — OR comercial"),
        ("table_name for the reservation",      "Edge — table_name em contexto"),
        ("exec summary of the report",          "Edge — exec em inglês"),
        ("my password is hunter2",              "Edge — senha fraca legítima"),
    ]

    # ─────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────
    def random_headers(extra=None):
        h = {"User-Agent": random.choice(USER_AGENTS)}
        if extra:
            h.update(extra)
        return h

    def random_noise_params():
        num  = random.randint(0, 3)
        keys = random.sample(PARAM_NAMES, min(num, len(PARAM_NAMES)))
        return {k: random.choice(NOISE_VALUES) for k in keys}

    def build_request_configs(payload, target_url):
        param = random.choice(PARAM_NAMES)
        noise = random_noise_params()
        return [
            {"method": "GET",  "url": target_url, "params": {**noise, param: payload}, "headers": random_headers(), "vector": f"GET ?{param}"},
            {"method": "POST", "url": target_url, "data":   {**noise, param: payload}, "headers": random_headers(), "vector": f"POST form[{param}]"},
            {"method": "POST", "url": target_url, "json":   {**noise, param: payload}, "headers": random_headers({"Content-Type": "application/json"}), "vector": f"POST JSON[{param}]"},
            {"method": "GET",  "url": target_url, "params": noise, "cookies": {param: payload}, "headers": random_headers(), "vector": f"Cookie[{param}]"},
            {"method": "GET",  "url": target_url, "params": noise, "headers": {"User-Agent": payload}, "vector": "Header[User-Agent]"},
        ]

    def send_request(config):
        t0 = time.perf_counter()
        try:
            r = requests.request(
                method=config["method"],
                url=config.get("url"),
                params=config.get("params"),
                data=config.get("data"),
                json=config.get("json"),
                cookies=config.get("cookies"),
                headers=config.get("headers"),
                timeout=6,
            )
            return r.status_code, (time.perf_counter() - t0) * 1000
        except requests.exceptions.ConnectionError: return -1, 0
        except requests.exceptions.Timeout:         return -2, 6000
        except Exception:                           return -3, 0

    def classify_result(status, expected_block):
        if status < 0:
            return "error"
        if expected_block:
            return "blocked" if status == 403 else "passed"
        else:
            return "false_positive" if status == 403 else "allowed"

    def run_tests(payload_list, expected_block, target_url):
        results = []
        for payload, desc in payload_list:
            config = random.choice(build_request_configs(payload, target_url))
            status, latency = send_request(config)
            results.append({
                "payload":    payload,
                "desc":       desc,
                "vector":     config["vector"],
                "status":     status,
                "latency_ms": round(latency, 1),
                "result":     classify_result(status, expected_block),
            })
            time.sleep(random.uniform(0.03, 0.15))
        return results

    # ─────────────────────────────────────────────
    #  ROTAS
    # ─────────────────────────────────────────────

    @app.route(target_path + "/mock/run", methods=["POST"])
    @admin
    def run_mock():
        """
        Executa o mock completo (SQLi + edge cases).
        Body JSON opcional: { "target_url": "http://..." }
        """
        body       = request.get_json(silent=True) or {}
        target_url = body.get("target_url", DEFAULT_TARGET)

        sqli_results = run_tests(SQLI_PAYLOADS,       expected_block=True,  target_url=target_url)
        edge_results = run_tests(BENIGN_EDGE_CASES,    expected_block=False, target_url=target_url)

        sqli_blocked = sum(1 for r in sqli_results if r["result"] == "blocked")
        sqli_passed  = sum(1 for r in sqli_results if r["result"] == "passed")
        sqli_err     = sum(1 for r in sqli_results if r["result"] == "error")
        edge_allowed = sum(1 for r in edge_results if r["result"] == "allowed")
        edge_fp      = sum(1 for r in edge_results if r["result"] == "false_positive")

        det_rate = round(sqli_blocked / len(sqli_results) * 100, 2) if sqli_results else 0
        fp_rate  = round(edge_fp / len(edge_results) * 100, 2)      if edge_results else 0
        lat_vals = [r["latency_ms"] for r in sqli_results if r["latency_ms"] > 0]
        avg_lat  = round(sum(lat_vals) / len(lat_vals), 1)           if lat_vals else 0

        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "target":    target_url,
            "summary": {
                "sqli_total":          len(sqli_results),
                "sqli_blocked":        sqli_blocked,
                "sqli_passed":         sqli_passed,
                "sqli_errors":         sqli_err,
                "detection_rate_pct":  det_rate,
                "edge_total":          len(edge_results),
                "edge_allowed":        edge_allowed,
                "false_positives":     edge_fp,
                "fp_rate_pct":         fp_rate,
                "avg_latency_ms":      avg_lat,
            },
            "sqli_results": sqli_results,
            "edge_results": edge_results,
        })


    @app.route(target_path + "/mock/payloads", methods=["GET"])
    @admin
    def list_payloads():
        """Retorna todos os payloads disponíveis, separados por categoria."""
        return jsonify({
            "sqli":  [{"payload": p, "desc": d} for p, d in SQLI_PAYLOADS],
            "edge":  [{"payload": p, "desc": d} for p, d in BENIGN_EDGE_CASES],
        })


    @app.route(target_path + "/mock/run/single", methods=["POST"])
    @admin
    def run_single():
        """
        Dispara um único payload num vetor específico.
        Body JSON: {
            "target_url": "http://...",
            "payload": "' OR 1=1 --",
            "vector": "GET" | "POST_FORM" | "POST_JSON" | "COOKIE" | "USER_AGENT",
            "param": "id"          (opcional, default aleatório)
            "expected_block": true  (opcional, default true)
        }
        """
        body           = request.get_json(silent=True) or {}
        target_url     = body.get("target_url",    DEFAULT_TARGET)
        payload        = body.get("payload",       "' OR 1=1 --")
        vector_key     = body.get("vector",        "GET").upper()
        param          = body.get("param",         random.choice(PARAM_NAMES))
        expected_block = body.get("expected_block", True)
        noise          = random_noise_params()

        vector_map = {
            "GET":        {"method": "GET",  "url": target_url, "params": {**noise, param: payload}, "headers": random_headers(), "vector": f"GET ?{param}"},
            "POST_FORM":  {"method": "POST", "url": target_url, "data":   {**noise, param: payload}, "headers": random_headers(), "vector": f"POST form[{param}]"},
            "POST_JSON":  {"method": "POST", "url": target_url, "json":   {**noise, param: payload}, "headers": random_headers({"Content-Type": "application/json"}), "vector": f"POST JSON[{param}]"},
            "COOKIE":     {"method": "GET",  "url": target_url, "params": noise, "cookies": {param: payload}, "headers": random_headers(), "vector": f"Cookie[{param}]"},
            "USER_AGENT": {"method": "GET",  "url": target_url, "params": noise, "headers": {"User-Agent": payload}, "vector": "Header[User-Agent]"},
        }

        config = vector_map.get(vector_key, vector_map["GET"])
        status, latency = send_request(config)

        return jsonify({
            "payload":    payload,
            "vector":     config["vector"],
            "status":     status,
            "latency_ms": round(latency, 1),
            "result":     classify_result(status, expected_block),
        })


    @app.route(target_path + "/mock/status", methods=["GET"])
    @admin
    def status():
        target_url = request.args.get("target", DEFAULT_TARGET)
        try:
            r = requests.get(target_url, timeout=3)
            return jsonify({"online": True, "status_code": r.status_code, "target": target_url})
        except Exception as e:
            return jsonify({"online": False, "error": str(e), "target": target_url})
    
    @app.route(target_path + '/mock', methods=['GET'])
    @admin
    def mock_simulator():
        return render_template('mock.html')