from datetime import datetime, timedelta, timezone
from flask import render_template_string, request, jsonify, make_response, flash, session, redirect, render_template
from model import AdminUser, WafLog, get_session, Blocked
from sqlalchemy import func
import csv
import io
from utils import Dashboard, admin
from werkzeug.security import check_password_hash

dashboard = Dashboard()

def get_logs_and_stats(ip_filter=None, type_filter=None, limit=100):
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

def setup_dashboard(app, custom_path=None):
    target_path = custom_path or '/admin/dashboard'

    @app.route(target_path + "/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("user")
            password = request.form.get("password")
            db_session = get_session()
            try:
                admin = db_session.query(AdminUser).filter(AdminUser.login == username).first()

                # 3. Valida (Aqui você deveria usar hash, mas vamos focar na lógica)
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

    # Rota 2: Retorna o HTML inicial
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
        block_time = data.get('block_time_minutes', 5) # Pega do JSON ou assume 5

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
            # Pega todos os IPs bloqueados que ainda não expiraram
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
            # Remove da tabela
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
        blacklisted_keys = {'app', 'log', 'recent_blocks_cache', '_instance', 'initialized', 'dashboard_path', 'rules_sqli', 'rules_xss'}

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
            
            print(f" * [WafaHell] Variable '{key}' changed to: {value}")
            
            return {"status": "success", "message": f"{key} updated", "newValue": value}
        
        return {"status": "error", "message": "Invalid variable"}, 400

    print(f" * [WafaHell] Dashboard e API de dados prontos em: {target_path}")

