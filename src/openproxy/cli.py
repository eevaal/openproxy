import httpx
import typer
import uvicorn

from .core.config import load_config

app = typer.Typer()

@app.command()
def version():
    print("OpenProxy version 0.1.0")

@app.command()
def status():
    if is_running():
        print("OpenProxy is running")
    else:
        print("OpenProxy is not running")



@app.command()
def start():
    if not is_running():
        config = load_config("config.yaml")
        uvicorn.run("openproxy.main:app", host=config["server"]["host"], port=config["server"]["port"], reload=True)
    else:
        print("OpenProxy is already running")


def is_running() -> bool:
    with httpx.Client(trust_env=False) as client:
            try:
                config = load_config("config.yaml")
                response = client.get(f"http://{config['server']['host']}:{config['server']['port']}/health", timeout=2)
                return response.status_code == 200
            except httpx.RequestError:
                return False

if __name__ == "__main__":
    app()
