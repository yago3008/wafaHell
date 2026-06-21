from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

try:
    from middleware import Wafahell
except ImportError:
    from .middleware import Wafahell


app = FastAPI(title="WafaHell FastAPI Demo")


@app.api_route(
    "/hello",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    response_class=HTMLResponse,
)
async def hello(request: Request):
    nome = request.query_params.get("nome", "Visitante")
    return f"<h1>Ola, {nome}!</h1>"


@app.get("/.env", response_class=PlainTextResponse)
async def env():
    return (
        "DB_PASSWORD=supersecretpassword\n"
        "API_KEY=abcdef\n"
        "SECRET_KEY=123456\n"
    )


# Simula uso da lib com FastAPI (mesma ideia do app.py do Flask)
Wafahell(app=app, dashboard_path="/hell/dashboard", block_durantion=1)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5002)
