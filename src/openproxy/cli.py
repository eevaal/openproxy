import logging
import os
import platform
import sys
from contextvars import ContextVar
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
from openproxy.core.diagnostics import Check, check_address, check_port
from openproxy.core.logging import LEVEL_ENV, configure_logging, logging_config
from openproxy.main import create_app

app = typer.Typer(no_args_is_help=True)
config_app = typer.Typer(help="Validate or display effective configuration.")
app.add_typer(config_app, name="config")
ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Path to a YAML configuration.")
]


quiet_mode: ContextVar[bool] = ContextVar("quiet", default=False)


@app.callback()
def options(
    ctx: typer.Context,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Enable DEBUG logs.")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="Only warnings and errors.")
    ] = False,
) -> None:
    if verbose and quiet:
        raise typer.BadParameter("--verbose and --quiet are mutually exclusive")
    token = quiet_mode.set(quiet)
    ctx.call_on_close(lambda: quiet_mode.reset(token))
    previous = os.environ.get(LEVEL_ENV)
    if verbose or quiet:
        os.environ[LEVEL_ENV] = "DEBUG" if verbose else "WARNING"

    def restore() -> None:
        if previous is None:
            os.environ.pop(LEVEL_ENV, None)
        else:
            os.environ[LEVEL_ENV] = previous

    ctx.call_on_close(restore)


def echo(message: str) -> None:
    if not quiet_mode.get():
        typer.echo(message)


def _load_config(path: Path | None) -> AppConfig:
    try:
        active = load_config(path)
        configure_logging(active.logging)
        logging.getLogger("openproxy.cli").debug("Configuration validated")
        return active
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


def proxy_check(active: AppConfig, running: bool) -> Check:
    if not active.proxy.enabled:
        return Check("PASS", "Proxy disabled")
    if not running:
        result = check_port(active.proxy)
        return Check(result.status, "Proxy port: " + result.message)
    try:
        with httpx.Client(trust_env=False, timeout=2, follow_redirects=False) as client:
            url = (
                active.server.health_url.removesuffix("/health")
                + "/api/v1/proxy/status"
            )
            response = client.get(url)
        data = response.json()
        if (
            response.status_code == 200
            and data.get("enabled") is True
            and data.get("running") is True
        ):
            return Check("PASS", "Proxy running")
    except (httpx.RequestError, ValueError, AttributeError):
        return Check("FAIL", "Proxy status unavailable")
    return Check("FAIL", "Proxy not running")


@app.command()
def status(config: ConfigOption = None) -> None:
    """Check the configured instance (exit 1 when unavailable)."""
    active = _load_config(config)
    if is_running(active):
        echo("OpenProxy is running")
        check = proxy_check(active, True)
        if not quiet_mode.get() or check.status != "PASS":
            typer.echo(f"{check.status} {check.message}")
        if check.status == "FAIL":
            raise typer.Exit(code=1)
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
        check = proxy_check(active, True)
        if check.status == "FAIL":
            typer.echo(f"FAIL {check.message}", err=True)
            raise typer.Exit(code=1)
        echo("OpenProxy is already running")
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
                    log_config=logging_config(active.logging),
                    access_log=False,
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
                log_config=logging_config(active.logging),
                access_log=False,
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
    echo("Configuration is valid")


@config_app.command("show")
def config_show(config: ConfigOption = None) -> None:
    """Show effective public settings with defaults; does not query a server."""
    active = _load_config(config)
    typer.echo(
        yaml.safe_dump(public_config(active).model_dump(), sort_keys=False), nl=False
    )


@app.command()
def doctor(config: ConfigOption = None) -> None:
    """Check configuration, runtime and local server readiness."""
    checks = [
        Check(
            "PASS" if sys.version_info >= (3, 12) else "FAIL",
            f"Python {platform.python_version()}",
        ),
        Check("PASS", f"OpenProxy {__version__}"),
    ]
    try:
        active = _load_config(config)
    except typer.Exit:
        typer.echo("FAIL Configuration")
        raise
    checks.append(Check("PASS", "Configuration"))
    address = check_address(active.server)
    checks.append(address)
    running = is_running(active) if address.status != "FAIL" else False
    if running:
        checks.append(Check("PASS", "OpenProxy is running; port belongs to OpenProxy"))
    else:
        checks.append(
            Check("WARN", "OpenProxy is not running or service is not OpenProxy")
        )
        if address.status != "FAIL":
            checks.append(check_port(active.server))
    if not active.server.is_loopback:
        checks.append(
            Check("WARN", "External interface: protect management API access")
        )
    checks.append(proxy_check(active, running))
    for check in checks:
        if not quiet_mode.get() or check.status != "PASS":
            typer.echo(f"{check.status} {check.message}")
    if any(check.status == "FAIL" for check in checks):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
