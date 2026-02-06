# from .model import AdminUser, WafLog, Whitelist, get_session, Blocked
# from .globals import waf_cache
# from .utils import Dashboard, admin
from model import AdminUser, CriticalPaths, WafLog, Whitelist, get_session, Blocked
from globals import waf_cache
from utils import Dashboard, admin
from datetime import datetime, timedelta, timezone
import re
from flask import request, jsonify, make_response, flash, session, redirect, render_template
from sqlalchemy import func
import csv
import io
from werkzeug.security import check_password_hash
from utils import b_print

dashboard = Dashboard()


def get_logs_and_stats(ip_filter=None, type_filter=None, limit=100):
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
            
            return {"status": "success", "message": f"{key} updated", "newValue": value}
        
        return {"status": "error", "message": "Invalid variable"}, 400
    
    @app.route(target_path + '/import_blacklist', methods=['POST'])
    @admin
    def import_blacklist():
        data = request.get_json()
        raw_ips = data.get('ips', [])
        
        if not raw_ips:
            return jsonify({"status": "error", "message": "Nenhum IP fornecido."}), 400

        # 1. Validação e Limpeza (Regex IPv4)
        # Usamos set() para remover duplicatas enviadas no mesmo arquivo
        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        valid_ips = set(ip for ip in raw_ips if ip_regex.match(ip))
        
        if not valid_ips:
            return jsonify({"status": "error", "message": "Nenhum IP válido encontrado."}), 400

        session = get_session()
        try:
            # 2. Filtragem de Duplicatas no Banco
            # Descobre quais desses IPs já estão bloqueados para não dar erro de Unique Key
            existing_query = session.query(Blocked.ip).filter(Blocked.ip.in_(valid_ips)).all()
            existing_ips = {row.ip for row in existing_query}
            
            # Apenas os novos IPs
            ips_to_insert = valid_ips - existing_ips
            
            if not ips_to_insert:
                return jsonify({"status": "success", "message": "Todos os IPs já estavam na blacklist."})

            # 3. Preparação dos Dados (Bulk)
            # Definimos um tempo padrão de 30 dias para importações manuais de lista
            now = datetime.now(timezone.utc)
            until = now + timedelta(days=3600) 
            
            bulk_data = []
            for ip in ips_to_insert:
                bulk_data.append({
                    "ip": ip,
                    "user_agent": "MANUAL_IMPORT_LIST",
                    # Mantendo o formato string que você usa no Model
                    "blocked_at": now.strftime("%H:%M:%S"), 
                    "blocked_until": until
                })
                
                # 4. Atualização IMEDIATA do Cache (Fast Path)
                # Isso garante que o bloqueio funcione no milissegundo seguinte,
                # sem precisar esperar a próxima query no banco.
                waf_cache.set(f"blocked_{ip}", True, expire=60)

            # 5. Inserção em Massa (Muito Rápido)
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

        # 1. Validação (Regex)
        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        valid_ips = set(ip for ip in raw_ips if ip_regex.match(ip))
        
        if not valid_ips:
            return jsonify({"status": "error", "message": "Nenhum IP válido encontrado."}), 400

        session = get_session()
        try:
            # 2. Verifica Duplicatas no Banco
            existing_query = session.query(Whitelist.ip).filter(Whitelist.ip.in_(valid_ips)).all()
            existing_ips = {row.ip for row in existing_query}
            
            ips_to_insert = valid_ips - existing_ips
            
            if not ips_to_insert:
                return jsonify({"status": "success", "message": "Todos os IPs já estavam na whitelist."})

            # 3. Prepara Bulk Insert e Cache
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            bulk_data = []
            
            for ip in ips_to_insert:
                bulk_data.append({
                    "ip": ip,
                    "added_at": now_str
                })
                # Cache Warm-up: Marca o IP como "VIP" no cache por 1 hora
                # Isso evita consulta ao banco quando este IP acessar
                waf_cache.set(f"whitelist_{ip}", True, expire=3600)

            # 4. Grava no Banco
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

        # Limpa e valida paths
        valid_paths = set(path.strip() for path in raw_paths if path.strip())
        
        if not valid_paths:
            return jsonify({"status": "error", "message": "Nenhum path válido encontrado."}), 400

        session = get_session()
        try:
            # 1. Salva no Banco de Dados (ignora duplicados se houver UNIQUE no model)
            for p in valid_paths:
                # Verifica se já existe para não dar erro de Unique
                exists = session.query(CriticalPaths).filter_by(path=p).first()
                if not exists:
                    new_path = CriticalPaths(path=p)
                    session.add(new_path)
            
            session.commit()

            # 2. Busca TODOS os paths do banco para atualizar o cache completo
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

