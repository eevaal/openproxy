from pathlib import Path

import pytest
from pydantic import ValidationError

from openproxy.core.config import (
    CONFIG_ENV,
    AppConfig,
    ConfigError,
    ServerConfig,
    load_config,
)


def test_valid_config(tmp_path: Path) -> None:
    path = tmp_path / "custom.yaml"
    path.write_text("server:\n  host: 127.0.0.2\n  port: 9000\n")
    config = load_config(path)
    assert config.server.host == "127.0.0.2"
    assert config.server.port == 9000
    with pytest.raises(ValidationError):
        config.server.port = 1234


def test_defaults_and_missing_file(tmp_path: Path) -> None:
    assert load_config() == AppConfig()
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path / "missing.yaml")


def test_partial_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    for text in ("{}", "server: {}", "server: {port: 9000}"):
        path.write_text(text)
        assert load_config(path).server.host == "127.0.0.1"


@pytest.mark.parametrize("text", ["", "# comment", "null"])
def test_empty_yaml(tmp_path: Path, text: str) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text(text)
    with pytest.raises(ConfigError, match="empty"):
        load_config(path)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("server: [", "Invalid YAML"),
        ("- item", "YAML mapping"),
        ("false", "YAML mapping"),
        ("server: null", "server"),
        ("server: []", "server"),
        ("server: {host: 123}", "server.host"),
        ("server: {host: ''}", "host"),
        ("server: {host: 'https://localhost'}", "host"),
        ("server: {host: '999.1.1.1'}", "host"),
        ("server: {host: 'example.com'}", "host"),
        ("server: {port: '8000'}", "server.port"),
        ("server: {port: true}", "server.port"),
        ("server: {port: 1.5}", "server.port"),
        ("server: {port: 0}", "server.port"),
        ("server: {port: -1}", "server.port"),
        ("server: {port: 65536}", "server.port"),
        ("server: {prot: 8000}", "Extra inputs"),
        ("unknown: value", "Extra inputs"),
    ],
)
def test_invalid_config(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(text)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_absolute_path_and_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "settings.yaml"
    path.write_text("server: {port: 9001}")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    assert load_config(path).server.port == 9001
    monkeypatch.setenv(CONFIG_ENV, str(path))
    assert load_config().server.port == 9001
    explicit = other / "explicit.yaml"
    explicit.write_text("server: {port: 9002}")
    assert load_config(explicit).server.port == 9002


def test_unreadable_and_invalid_encoding(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path)
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"\xff")
    with pytest.raises(ConfigError, match="invalid UTF-8"):
        load_config(path)


def test_errors_do_not_echo_values(tmp_path: Path) -> None:
    path = tmp_path / "secret.yaml"
    for text in ("server: {port: private-secret}", "server: [private-secret"):
        path.write_text(text)
        with pytest.raises(ConfigError) as error:
            load_config(path)
        assert "private-secret" not in str(error.value)


@pytest.mark.parametrize("port", [1, 65535])
def test_port_boundaries(port: int) -> None:
    assert ServerConfig(port=port).port == port


@pytest.mark.parametrize(
    ("host", "url", "local"),
    [
        ("localhost", "http://localhost:8000/health", True),
        ("127.0.0.2", "http://127.0.0.2:8000/health", True),
        ("::1", "http://[::1]:8000/health", True),
        ("::", "http://[::1]:8000/health", False),
        ("0.0.0.0", "http://127.0.0.1:8000/health", False),
        ("192.0.2.1", "http://192.0.2.1:8000/health", False),
    ],
)
def test_host_urls(host: str, url: str, local: bool) -> None:
    server = ServerConfig(host=host)
    assert server.health_url == url
    assert server.is_loopback is local
