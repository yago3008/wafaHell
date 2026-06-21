import argparse
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path

ROOT = Path(r"C:\Users\yago.martins.SOOW\Documents\TCC\wafaHell\wafaHell")
DB_CANDIDATES = [ROOT / "wafahell.db", ROOT / "wafaHell.db"]


def cleanup_state():
    for db in DB_CANDIDATES:
        if db.exists():
            db.unlink()
    log_file = ROOT / "waf.log"
    if log_file.exists():
        log_file.unlink()
    cache_dir = ROOT / "waf_cache_temp"
    if cache_dir.exists():
        shutil.rmtree(cache_dir, ignore_errors=True)


def db_path() -> Path:
    for db in DB_CANDIDATES:
        if db.exists():
            return db
    return DB_CANDIDATES[0]


def read_db_summary():
    db = db_path()
    if not db.exists():
        return {"counts": {}, "recent": [], "total": 0}

    conn = sqlite3.connect(str(db))
    cur = conn.cursor()

    cur.execute("SELECT attack_type, COUNT(*) FROM waf_logs GROUP BY attack_type ORDER BY COUNT(*) DESC")
    counts = {row[0] or "NULL": int(row[1]) for row in cur.fetchall()}

    cur.execute("SELECT attack_type, path, payload FROM waf_logs ORDER BY id DESC LIMIT 15")
    recent = [
        {
            "attack_type": row[0],
            "path": row[1],
            "payload": (row[2] or "")[:80],
        }
        for row in cur.fetchall()
    ]

    cur.execute("SELECT COUNT(*) FROM waf_logs")
    total = int(cur.fetchone()[0])

    conn.close()
    return {"counts": counts, "recent": recent, "total": total}


def run_sequence(http_get):
    headers = {"User-Agent": "compare-suite/1.0"}

    initial_payloads = [
        ("benign", "ok"),
        ("sqli_1", "' OR '1'='1' --"),
        ("sqli_2", '1"  )  )   )  and elt ( 3114 = 3114,sleep ( 5  )  )  #'),
        ("xss_1", "<script>alert(1)</script>"),
        ("xss_2", '"/><svg/onload=alert(1)>'),
    ]

    initial_status = {}
    for name, payload in initial_payloads:
        r = http_get("/hello", {"nome": payload}, headers)
        initial_status[name] = int(r.status_code)

    rl_markers = {}
    for i in range(120):
        r = http_get("/hello", {"nome": f"rl_{i}"}, headers)
        if i in (0, 98, 99, 100, 119):
            rl_markers[str(i)] = int(r.status_code)

    # Forca flush final do batch por tempo
    time.sleep(4)
    flush_resp = http_get("/hello", {"nome": "flush"}, headers)

    summary = read_db_summary()

    return {
        "initial_status": initial_status,
        "rl_markers": rl_markers,
        "flush_status": int(flush_resp.status_code),
        "db_total": summary["total"],
        "db_counts": summary["counts"],
        "db_recent": summary["recent"],
    }


def run_flask():
    from flask import Flask, request
    from middleware import Wafahell

    Wafahell._instance = None

    app = Flask("compare_flask")

    @app.route("/hello", methods=["GET"])
    def hello():
        return f"ok {request.args.get('nome', '')}"

    Wafahell(
        app=app,
        dashboard_path="/hell/dashboard",
        block_durantion=1,
        block_ip=False,
        monitor_mode=False,
        rate_limit=True,
        block_code=403,
    )

    client = app.test_client()

    def _get(path, params, headers):
        return client.get(path, query_string=params, headers=headers)

    return run_sequence(_get)


def run_fastapi():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from middleware import Wafahell

    Wafahell._instance = None

    app = FastAPI()

    @app.get("/hello")
    async def hello(nome: str = ""):
        return {"ok": nome}

    Wafahell(
        app=app,
        dashboard_path="/hell/dashboard",
        block_durantion=1,
        block_ip=False,
        monitor_mode=False,
        rate_limit=True,
        block_code=403,
    )

    client = TestClient(app)

    def _get(path, params, headers):
        return client.get(path, params=params, headers=headers)

    return run_sequence(_get)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", choices=["flask", "fastapi"], required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    cleanup_state()

    if args.framework == "flask":
        result = run_flask()
    else:
        result = run_fastapi()

    payload = {"framework": args.framework, **result}
    out_path = Path(args.out)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
