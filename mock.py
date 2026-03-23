import requests
import random
import time
import json
from datetime import datetime

# ─────────────────────────────────────────────
#  CONFIGURAÇÃO
# ─────────────────────────────────────────────
BASE_URL = "http://127.0.0.1:5001/hello"

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

PARAM_NAMES = ["id", "user", "nome", "search", "q", "page", "category", "token", "ref", "lang"]
NOISE_VALUES = ["1", "true", "en-US", "default", "home", "42", "admin", "index", "null", "undefined"]

# ─────────────────────────────────────────────
#  PAYLOADS MALICIOSOS — SQLi
# ─────────────────────────────────────────────
SQLI_PAYLOADS = [
    # Boolean based
    ("' OR '1'='1",                         "Boolean — OR clássico"),
    ("' OR '1'='1' --",                     "Boolean — OR com comentário"),
    ("' OR 1=1 --",                         "Boolean — OR numérico"),
    ("admin' --",                           "Boolean — bypass de login"),
    ("' OR 'x'='x",                         "Boolean — OR string"),
    ("1 OR 1=1",                            "Boolean — sem aspas"),
    ("' AND 1=1 --",                        "Boolean — AND verdadeiro"),
    ("' AND 1=2 --",                        "Boolean — AND falso"),
    ("') OR ('1'='1",                       "Boolean — com parêntese"),
    ("1; --",                               "Terminação de query"),
    # UNION based
    ("' UNION SELECT NULL --",              "UNION — 1 coluna"),
    ("' UNION SELECT NULL,NULL --",         "UNION — 2 colunas"),
    ("' UNION SELECT NULL,NULL,NULL --",    "UNION — 3 colunas"),
    ("' UNION SELECT username,password FROM users --", "UNION — exfiltração"),
    ("1 UNION ALL SELECT 1,2,3 --",        "UNION ALL"),
    ("' UNION SELECT table_name FROM information_schema.tables --", "UNION — info_schema"),
    # Error based
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",  "Error — EXTRACTVALUE"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,DATABASE()),1) --",  "Error — UPDATEXML"),
    ("'; SELECT * FROM users WHERE 'a'='a",              "Error — query adicional"),
    # Time based
    ("'; SELECT PG_SLEEP(3) --",            "Time — pg_sleep PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:3' --",         "Time — WAITFOR SQL Server"),
    ("' AND SLEEP(3) --",                   "Time — SLEEP MySQL"),
    ("' AND (SELECT 5264 FROM (SELECT(SLEEP(3)))x) --",  "Time — SLEEP subquery"),
    ("'; exec master..xp_cmdshell('ping 127.0.0.1') --", "Time — xp_cmdshell"),
    # Stacked queries
    ("'; DROP TABLE users --",              "Stacked — DROP TABLE"),
    ("'; INSERT INTO logs VALUES('hacked') --", "Stacked — INSERT"),
    ("'; UPDATE users SET password='pwned' --",  "Stacked — UPDATE"),
    # Obfuscação
    ("'/**/OR/**/'1'='1",                   "Obfusc — comentários inline"),
    ("' OR 0x31=0x31 --",                   "Obfusc — hex comparison"),
    ("' oR '1'='1",                         "Obfusc — case mixing"),
    ("'\tor\t'1'='1",                       "Obfusc — tabs"),
]

# ─────────────────────────────────────────────
#  EDGE CASES — Benignos suspeitos
# ─────────────────────────────────────────────
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
#  CORES ANSI
# ─────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

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

def build_request_configs(payload):
    param = random.choice(PARAM_NAMES)
    noise = random_noise_params()
    return [
        {"method": "GET",  "url": BASE_URL, "params": {**noise, param: payload}, "headers": random_headers(), "vector": f"GET ?{param}"},
        {"method": "POST", "url": BASE_URL, "data":   {**noise, param: payload}, "headers": random_headers(), "vector": f"POST form[{param}]"},
        {"method": "POST", "url": BASE_URL, "json":   {**noise, param: payload}, "headers": random_headers({"Content-Type": "application/json"}), "vector": f"POST JSON[{param}]"},
        {"method": "GET",  "url": BASE_URL, "params": noise, "cookies": {param: payload}, "headers": random_headers(), "vector": f"Cookie[{param}]"},
        {"method": "GET",  "url": BASE_URL, "params": noise, "headers": {"User-Agent": payload}, "vector": "Header[User-Agent]"},
    ]

def send_request(config):
    t0 = time.perf_counter()
    try:
        r = requests.request(
            method=config["method"], url=config.get("url", BASE_URL),
            params=config.get("params"), data=config.get("data"),
            json=config.get("json"), cookies=config.get("cookies"),
            headers=config.get("headers"), timeout=6,
        )
        return r.status_code, (time.perf_counter() - t0) * 1000
    except requests.exceptions.ConnectionError: return -1, 0
    except requests.exceptions.Timeout:         return -2, 6000
    except Exception:                           return -3, 0

def result_label(status, expected_block):
    if status == -1: return "⚠  SEM CONEXÃO",      C.YELLOW
    if status == -2: return "⏱  TIMEOUT",           C.YELLOW
    if status == -3: return "⚠  ERRO",              C.YELLOW
    if expected_block:
        return ("✅ BLOQUEADO", C.GREEN) if status == 403 else (f"❌ PASSOU ({status})", C.RED)
    else:
        return (f"⚠  FALSO POSITIVO (403)", C.YELLOW) if status == 403 else (f"✅ PERMITIDO ({status})", C.GREEN)

# ─────────────────────────────────────────────
#  PRINT HELPERS
# ─────────────────────────────────────────────
def print_header():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{C.BOLD}{C.CYAN}{'═'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  WafaHell Mock — SQLi Attack Simulator{C.RESET}")
    print(f"{C.GRAY}  Alvo : {BASE_URL}{C.RESET}")
    print(f"{C.GRAY}  Hora : {now}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*72}{C.RESET}\n")

def print_section(title, color=C.MAGENTA):
    print(f"\n{color}{C.BOLD}  ▸ {title}{C.RESET}")
    print(f"  {C.GRAY}{'─'*68}{C.RESET}")
    print(f"  {'VETOR':<22}  {'TÉCNICA':<30}  {'RESULTADO':<22}  {'LAT':>7}")
    print(f"  {C.GRAY}{'─'*22}  {'─'*30}  {'─'*22}  {'─'*7}{C.RESET}")

def print_row(vector, desc, result, color, latency):
    v = vector[:22].ljust(22)
    d = desc[:30].ljust(30)
    lat = f"{latency:>6.0f}ms" if latency > 0 else "      —"
    print(f"  {C.DIM}{v}{C.RESET}  {C.WHITE}{d}{C.RESET}  {color}{result:<22}{C.RESET}  {C.GRAY}{lat}{C.RESET}")

# ─────────────────────────────────────────────
#  RUNNERS
# ─────────────────────────────────────────────
def run_sqli_tests(results):
    print_section("PAYLOADS MALICIOSOS — SQLi", C.RED)
    for payload, desc in SQLI_PAYLOADS:
        config = random.choice(build_request_configs(payload))
        status, latency = send_request(config)
        result_txt, color = result_label(status, expected_block=True)
        print_row(config["vector"], desc, result_txt, color, latency)
        cat = "blocked" if status == 403 else ("error" if status < 0 else "passed")
        results["sqli"].append({"payload": payload, "desc": desc, "vector": config["vector"],
                                 "status": status, "latency_ms": round(latency, 1), "result": cat})
        time.sleep(random.uniform(0.05, 0.2))

def run_edge_case_tests(results):
    print_section("EDGE CASES — Benignos suspeitos (não devem bloquear)", C.YELLOW)
    for payload, desc in BENIGN_EDGE_CASES:
        config = random.choice(build_request_configs(payload))
        status, latency = send_request(config)
        result_txt, color = result_label(status, expected_block=False)
        print_row(config["vector"], desc, result_txt, color, latency)
        cat = "false_positive" if status == 403 else ("error" if status < 0 else "allowed")
        results["edge"].append({"payload": payload, "desc": desc, "vector": config["vector"],
                                 "status": status, "latency_ms": round(latency, 1), "result": cat})
        time.sleep(random.uniform(0.05, 0.15))

# ─────────────────────────────────────────────
#  SUMÁRIO
# ─────────────────────────────────────────────
def print_summary(results):
    sqli = results["sqli"]
    edge = results["edge"]

    sqli_blocked = sum(1 for r in sqli if r["result"] == "blocked")
    sqli_passed  = sum(1 for r in sqli if r["result"] == "passed")
    sqli_err     = sum(1 for r in sqli if r["result"] == "error")
    edge_allowed = sum(1 for r in edge if r["result"] == "allowed")
    edge_fp      = sum(1 for r in edge if r["result"] == "false_positive")

    det_rate = (sqli_blocked / len(sqli) * 100) if sqli else 0
    fp_rate  = (edge_fp / len(edge) * 100) if edge else 0
    avg_lat  = (sum(r["latency_ms"] for r in sqli if r["latency_ms"] > 0) /
                max(1, sum(1 for r in sqli if r["latency_ms"] > 0)))

    print(f"\n{C.BOLD}{C.CYAN}{'═'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SUMÁRIO{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*72}{C.RESET}")

    print(f"\n  {C.BOLD}SQLi Detection{C.RESET}")
    print(f"    Total testado    : {len(sqli)}")
    print(f"    {C.GREEN}Bloqueados       : {sqli_blocked}{C.RESET}")
    print(f"    {C.RED}Passaram         : {sqli_passed}{C.RESET}")
    print(f"    {C.YELLOW}Erros            : {sqli_err}{C.RESET}")
    dr_color = C.GREEN if det_rate >= 80 else (C.YELLOW if det_rate >= 60 else C.RED)
    print(f"    {dr_color}{C.BOLD}Taxa de detecção : {det_rate:.1f}%{C.RESET}")

    print(f"\n  {C.BOLD}Edge Cases{C.RESET}")
    print(f"    Total testado    : {len(edge)}")
    print(f"    {C.GREEN}Permitidos       : {edge_allowed}{C.RESET}")
    fp_color = C.GREEN if fp_rate == 0 else (C.YELLOW if fp_rate <= 20 else C.RED)
    print(f"    {fp_color}Falsos positivos : {edge_fp} ({fp_rate:.1f}%){C.RESET}")

    print(f"\n  {C.BOLD}Performance{C.RESET}")
    print(f"    Latência média   : {avg_lat:.1f}ms")

    passed = [r for r in sqli if r["result"] == "passed"]
    if passed:
        print(f"\n  {C.BOLD}{C.RED}⚠  Não detectados ({len(passed)}):{C.RESET}")
        for r in passed:
            print(f"    {C.RED}• [{r['vector']:<20}] {r['desc']}{C.RESET}")
            print(f"      {C.GRAY}{r['payload'][:65]}{C.RESET}")

    fp_list = [r for r in edge if r["result"] == "false_positive"]
    if fp_list:
        print(f"\n  {C.BOLD}{C.YELLOW}⚠  Falsos positivos ({len(fp_list)}):{C.RESET}")
        for r in fp_list:
            print(f"    {C.YELLOW}• [{r['vector']:<20}] {r['desc']}{C.RESET}")
            print(f"      {C.GRAY}{r['payload'][:65]}{C.RESET}")

    output_file = f"mock_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "target": BASE_URL,
            "summary": {
                "sqli_total": len(sqli), "sqli_blocked": sqli_blocked,
                "sqli_passed": sqli_passed, "detection_rate_pct": round(det_rate, 2),
                "edge_total": len(edge), "false_positives": edge_fp,
                "fp_rate_pct": round(fp_rate, 2), "avg_latency_ms": round(avg_lat, 1),
            },
            "sqli_results": sqli,
            "edge_results": edge,
        }, f, indent=2, ensure_ascii=False)

    print(f"\n  {C.GRAY}Resultado salvo em: {output_file}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*72}{C.RESET}\n")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def run_mock():
    results = {"sqli": [], "edge": []}
    print_header()
    run_sqli_tests(results)
    run_edge_case_tests(results)
    print_summary(results)

if __name__ == "__main__":
    run_mock()