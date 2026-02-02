import requests

# Configuração do alvo
BASE_URL = "http://127.0.0.1:5000/hello"

# Definição dos payloads de teste (SQLi e XSS clássicos)
payloads = {
    "URL Query": {"url": f"{BASE_URL}?id=1' OR '1'='1"},
    "Form Data": {"method": "POST", "data": {"user": "<script>alert(1)</script>"}},
    "JSON Body": {"method": "POST", "json": {"search": "SELECT * FROM users"}},
    "Cookies": {"method": "POST", "cookies": {"session": "UNION SELECT NULL,NULL--"}},
    "Custom Header": {"method": "POST", "headers": {"User-Agent": "'; DROP TABLE logs;--"}},
    "Multipart File": {"method": "POST", "files": {"file": ("README.md", "payload: <script>alert('XSS')</script>")}},
}

def run_mock():
    print(f"🚀 Iniciando Mock de Testes WafaHell no alvo: {BASE_URL}\n")
    print(f"{'VETOR DE TESTE':<20} | {'STATUS':<10} | {'RESULTADO'}")
    print("-" * 55)

    for test_name, config in payloads.items():
        try:
            # Prepara a requisição
            url = config.get("url", BASE_URL)
            method = config.get("method", "GET")
            
            # Executa a requisição com os parâmetros dinâmicos
            response = requests.request(
                method=method,
                url=url,
                data=config.get("data"),
                json=config.get("json"),
                cookies=config.get("cookies"),
                headers=config.get("headers"),
                files=config.get("files"),
                timeout=5
            )

            # Validação: 403 significa que o WAF bloqueou (Sucesso no teste)
            if response.status_code == 403:
                status_txt = "✅ BLOQUEADO"
                result_txt = "Sucesso (WAF Ativo)"
            else:
                status_txt = f"❌ {response.status_code}"
                result_txt = "Falha (Vulnerável!)"

            print(f"{test_name:<20} | {status_txt:<10} | {result_txt}")

        except Exception as e:
            print(f"{test_name:<20} | ⚠️ ERRO      | {str(e)}")

if __name__ == "__main__":
    run_mock()