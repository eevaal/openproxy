import os
from pathlib import Path
from typing import Annotated

import httpx
import typer
import uvicorn
import yaml

from openproxy import __version__
from openproxy.api.models import HealthResponse, public_config
from openproxy.core.config import (
    CONFIG_ENV,
    AppConfig,
    ConfigError,
    load_config,
    resolve_config_path,
)
from openproxy.main import create_app

app = typer.Typer(no_args_is_help=True)
config_app = typer.Typer(help="Validate or display effective configuration.")
app.add_typer(config_app, name="config")
ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Path to a YAML configuration.")
]


def _load_config(path: Path | None) -> AppConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None


def is_running(config: AppConfig | None = None) -> bool:
    active = config if config is not None else load_config()
    try:
        with httpx.Client(trust_env=False, timeout=2, follow_redirects=False) as client:
            response = client.get(active.server.health_url)
        if response.status_code != 200:
            return False
        health = HealthResponse.model_validate(response.json())
        return bool(health.version)
    except (httpx.RequestError, ValueError):
        return False


@app.command()
def version() -> None:
    """Show the installed project version."""
    typer.echo(f"OpenProxy version {__version__}")


@app.command()
def status(config: ConfigOption = None) -> None:
    """Check the configured instance (exit 1 when unavailable)."""
    if is_running(_load_config(config)):
        typer.echo("OpenProxy is running")
    else:
        typer.echo("OpenProxy is not running or the service is not OpenProxy")
        raise typer.Exit(code=1)


@app.command()
def start(
    config: ConfigOption = None,
    reload: Annotated[
        bool, typer.Option(help="Enable auto-reload for development.")
    ] = False,
) -> None:
    """Run the management server in the foreground."""
    active = _load_config(config)
    if is_running(active):
        typer.echo("OpenProxy is already running")
        return
    try:
        if reload:
            # Absolute paths survive the development reloader's child process.
            path = resolve_config_path(config)
            previous = os.environ.get(CONFIG_ENV)
            if path is not None:
                os.environ[CONFIG_ENV] = str(path)
            try:
                uvicorn.run(
                    "openproxy.main:create_app",
                    factory=True,
                    reload=True,
                    host=active.server.host,
                    port=active.server.port,
                )
            finally:
                if previous is None:
                    os.environ.pop(CONFIG_ENV, None)
                else:
                    os.environ[CONFIG_ENV] = previous
        else:
            uvicorn.run(
                create_app(active),
                host=active.server.host,
                port=active.server.port,
                reload=False,
            )
    except OSError as exc:
        typer.echo(f"Cannot start OpenProxy: {exc.strerror}", err=True)
        raise typer.Exit(code=1) from None


@config_app.command("validate")
def config_validate(config: ConfigOption = None) -> None:
    """Validate YAML and all supported settings."""
    _load_config(config)
    typer.echo("Configuration is valid")


@config_app.command("show")
def config_show(config: ConfigOption = None) -> None:
    """Show effective public settings with defaults; does not query a server."""
    active = _load_config(config)
    typer.echo(
        yaml.safe_dump(public_config(active).model_dump(), sort_keys=False), nl=False
    )


if __name__ == "__main__":
    app()
