try:
    from middleware import Wafahell
except ImportError:
    from .middleware import Wafahell
from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)


app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1
)


@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/hello', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def hello():
    nome = request.args.get('nome', 'Visitante')
    return f"<h1>Olá, {nome}!</h1>"

@app.route('/.env')
def env():
    return '''
            DB_PASSWORD=supersecretpassword
            API_KEY=abcdef
            SECRET_KEY=123456
            '''

if __name__ == '__main__':
    Wafahell(app=app, dashboard_path='/hell/dashboard', block_duration=1, ai_threshold=0.70)
    app.run(debug=True, host='0.0.0.0', port=12001)
