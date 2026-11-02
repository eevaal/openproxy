from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from openproxy import __version__
from openproxy.core.config import AppConfig, ConfigError, ServerConfig
from openproxy.main import create_app


def test_api_and_lifespan() -> None:
    config = AppConfig(server=ServerConfig(port=9000))
    app = create_app(config)
    assert not hasattr(app.state, "config")
    with TestClient(app) as client:
        assert app.state.config is config
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {
            "status": "healthy",
            "name": "OpenProxy",
            "version": __version__,
        }
        response = client.get("/api/v1/info")
        assert response.status_code == 200
        info = response.json()
        assert info["name"] == "OpenProxy"
        assert info["version"] == __version__
        assert info["telemetry_enabled"] is False
        assert info["proxy_implemented"] is False
        response = client.get("/api/v1/config")
        assert response.status_code == 200
        assert response.json() == {"server": {"host": "127.0.0.1", "port": 9000}}
        assert client.get("/").json()["name"] == "OpenProxy"
        schema = client.get("/openapi.json").json()
        assert schema["info"]["version"] == __version__
        assert "/api/v1/config" in schema["paths"]
    assert not hasattr(app.state, "config")


def test_factory_loads_file_once(tmp_path: Path) -> None:
    path = tmp_path / "api.yaml"
    path.write_text("server: {port: 9001}")
    with TestClient(create_app(config_path=path)) as client:
        path.write_text("server: {port: 9002}")
        assert client.get("/api/v1/config").json()["server"]["port"] == 9001
    with TestClient(create_app(config_path=path)) as client:
        assert client.get("/api/v1/config").json()["server"]["port"] == 9002


def test_app_instances_are_isolated() -> None:
    with (
        TestClient(create_app(AppConfig(server=ServerConfig(port=9001)))) as first,
        TestClient(create_app()) as second,
    ):
        assert first.get("/api/v1/config").json()["server"]["port"] == 9001
        assert second.get("/api/v1/config").json()["server"]["port"] == 8000


def test_invalid_config_fails_startup(tmp_path: Path) -> None:
    app = create_app(config_path=tmp_path / "missing.yaml")
    with pytest.raises(ConfigError), TestClient(app):
        pytest.fail("Invalid configuration must prevent startup")


def test_external_interface_warning(caplog: pytest.LogCaptureFixture) -> None:
    config = AppConfig(server=ServerConfig(host="0.0.0.0"))
    with TestClient(create_app(config)):
        assert "no authentication" in caplog.text
        assert "protect access" in caplog.text


def test_default_has_no_external_warning(caplog: pytest.LogCaptureFixture) -> None:
    with TestClient(create_app()):
        assert "non-loopback" not in caplog.text
