import os
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import httpx
import pytest
import uvicorn
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from openproxy import __version__, cli
from openproxy.core.config import CONFIG_ENV, AppConfig, load_config
from openproxy.main import create_app

runner = CliRunner()


def mock_http(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    real_client = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["timeout"] == 2
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)


def test_version() -> None:
    result = runner.invoke(cli.app, ["version"])
    assert result.exit_code == 0
    assert __version__ == "0.4.0"
    assert __version__ in result.output


def test_config_commands(tmp_path: Path) -> None:
    path = tmp_path / "settings.yaml"
    path.write_text("server: {port: 9010}")
    result = runner.invoke(cli.app, ["config", "validate", "--config", str(path)])
    assert result.exit_code == 0
    assert "valid" in result.output
    result = runner.invoke(cli.app, ["config", "show", "-c", str(path)])
    assert result.exit_code == 0
    assert yaml.safe_load(result.output) == {
        "server": {"host": "127.0.0.1", "port": 9010},
        "logging": {"level": "INFO", "format": "text"},
    }


@pytest.mark.parametrize(
    "command", [["start"], ["status"], ["config", "validate"], ["config", "show"]]
)
def test_config_errors(command: list[str]) -> None:
    result = runner.invoke(cli.app, [*command, "--config", "missing.yaml"])
    assert result.exit_code == 2
    assert "Cannot read" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "text", ["", "server: [", "server: {port: true}", "server: {host: bad/host}"]
)
def test_invalid_yaml_cli(tmp_path: Path, text: str) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(text)
    result = runner.invoke(cli.app, ["config", "validate", "-c", str(path)])
    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "Traceback" not in result.output


def test_status_custom_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "status.yaml"
    path.write_text("server: {host: '::', port: 9040}")

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://[::1]:9040/health"
        return httpx.Response(
            200,
            json={"status": "healthy", "name": "OpenProxy", "version": __version__},
        )

    mock_http(monkeypatch, handler)
    result = runner.invoke(cli.app, ["status", "-c", str(path)])
    assert result.exit_code == 0


def test_status_running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://invalid:1234")
    monkeypatch.setenv("ALL_PROXY", "http://invalid:1234")

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://127.0.0.1:8000/health"
        return httpx.Response(
            200,
            json={
                "status": "healthy",
                "name": "OpenProxy",
                "version": "0.1.0",
            },
        )

    mock_http(monkeypatch, handler)
    assert cli.is_running(AppConfig())
    result = runner.invoke(cli.app, ["status"])
    assert result.exit_code == 0
    assert "OpenProxy is running" in result.output


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
def test_status_unavailable(
    monkeypatch: pytest.MonkeyPatch, error: type[httpx.RequestError]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error("Unavailable", request=request)

    mock_http(monkeypatch, handler)
    result = runner.invoke(cli.app, ["status"])
    assert result.exit_code == 1
    assert "not running" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="<html>Other service</html>"),
        httpx.Response(200, json={"status": "healthy"}),
        httpx.Response(
            200, json={"status": "healthy", "name": "Other", "version": "1"}
        ),
        httpx.Response(200, json={"status": "healthy", "name": "OpenProxy"}),
        httpx.Response(
            200, json={"status": "healthy", "name": "OpenProxy", "version": ""}
        ),
        httpx.Response(200, json=[]),
        httpx.Response(
            503, json={"status": "healthy", "name": "OpenProxy", "version": "1"}
        ),
        httpx.Response(302, headers={"location": "https://example.com"}),
    ],
)
def test_status_foreign_service(
    monkeypatch: pytest.MonkeyPatch, response: httpx.Response
) -> None:
    mock_http(monkeypatch, lambda request: response)
    result = runner.invoke(cli.app, ["status"])
    assert result.exit_code == 1
    assert "not OpenProxy" in result.output


def test_start_uses_same_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "custom.yaml"
    path.write_text("server: {port: 9020}")
    probe = Mock(return_value=False)
    monkeypatch.setattr(cli, "is_running", probe)
    run = Mock()
    monkeypatch.setattr(uvicorn, "run", run)
    result = runner.invoke(cli.app, ["start", "--config", str(path)])
    assert result.exit_code == 0
    assert run.call_args.kwargs["access_log"] is False
    assert "log_config" in run.call_args.kwargs
    assert {
        k: v
        for k, v in run.call_args.kwargs.items()
        if k not in {"log_config", "access_log"}
    } == {
        "host": "127.0.0.1",
        "port": 9020,
        "reload": False,
    }
    with TestClient(run.call_args.args[0]) as client:
        assert run.call_args.args[0].state.config is probe.call_args.args[0]
        assert client.get("/api/v1/config").json()["server"]["port"] == 9020


def test_start_already_running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "is_running", lambda config: True)
    run = Mock()
    monkeypatch.setattr(uvicorn, "run", run)
    result = runner.invoke(cli.app, ["start"])
    assert result.exit_code == 0
    assert "already running" in result.output
    run.assert_not_called()


def test_start_port_occupied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "is_running", lambda config: False)
    monkeypatch.setattr(uvicorn, "run", Mock(side_effect=OSError(48, "Address in use")))
    result = runner.invoke(cli.app, ["start"])
    assert result.exit_code == 1
    assert "Address in use" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("previous", [None, "/previous/config.yaml"])
def test_reload_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, previous: str | None
) -> None:
    path = tmp_path / "dev.yaml"
    path.write_text("server: {port: 9030}")
    if previous is not None:
        monkeypatch.setenv(CONFIG_ENV, previous)
    monkeypatch.setattr(cli, "is_running", lambda config: False)

    def run(target: str, **kwargs: Any) -> None:
        assert target == "openproxy.main:create_app"
        assert kwargs.pop("access_log") is False
        assert kwargs.pop("log_config")["version"] == 1
        assert kwargs == {
            "factory": True,
            "reload": True,
            "host": "127.0.0.1",
            "port": 9030,
        }
        assert os.environ[CONFIG_ENV] == str(path)
        other = tmp_path / "other"
        other.mkdir()
        monkeypatch.chdir(other)
        assert load_config().server.port == 9030
        with TestClient(create_app()) as client:
            assert client.get("/api/v1/config").json()["server"]["port"] == 9030

    monkeypatch.setattr(uvicorn, "run", run)
    result = runner.invoke(cli.app, ["start", "--reload", "-c", "dev.yaml"])
    assert result.exit_code == 0, result.output
    assert os.environ.get(CONFIG_ENV) == previous


def test_reload_restores_environment_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "dev.yaml"
    path.write_text("{}")
    monkeypatch.setenv(CONFIG_ENV, "/previous/config.yaml")
    monkeypatch.setattr(cli, "is_running", lambda config: False)
    monkeypatch.setattr(uvicorn, "run", Mock(side_effect=OSError(48, "Address in use")))
    result = runner.invoke(cli.app, ["start", "--reload", "-c", str(path)])
    assert result.exit_code == 1
    assert os.environ[CONFIG_ENV] == "/previous/config.yaml"
