from middleware import WafaHell
from flask import Flask, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)


app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1
)

@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def home():
    return "<h1>Bem-vindo à minha aplicação Flask!</h1><p>Acesse /hello?nome=test</p>"

@app.route('/hello', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def hello():
    nome = request.args.get('nome', 'Visitante')
    return f"<h1>Olá, {nome}!</h1>"

@app.route('/admin/dashboard')
def dashboard():
    return "<h1>Dashboard Personalizado</h1><p>Este é o painel de controle personalizado.</p>"

if __name__ == '__main__':
    WafaHell(app, dashboard_path='/hell/dashboard', block_durantion=1, rate_limit=True, block_ip=True)
    app.run(debug=True, host='0.0.0.0', port=5001)
