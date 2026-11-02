import errno
import json
import logging
import socket
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from openproxy import cli
from openproxy.core import diagnostics
from openproxy.core.config import AppConfig, ConfigError, LoggingConfig, load_config
from openproxy.core.logging import configure_logging

runner = CliRunner()


@pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARNING", "ERROR"])
def test_levels(level: str, capsys: pytest.CaptureFixture[str]) -> None:
    settings = LoggingConfig.model_validate({"level": level})
    configure_logging(settings)
    configure_logging(settings)
    logger = logging.getLogger("openproxy.test")
    for value in (10, 20, 30, 40):
        logger.log(value, "event")
    output = capsys.readouterr().err
    assert output.count("event") == (50 - logging.getLevelName(level)) // 10
    assert len(logging.getLogger("openproxy").handlers) == 1


def test_json_excludes_extra_and_exception_details(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(LoggingConfig(format="json"))
    logging.getLogger("openproxy.test").error(
        "Operation failed",
        extra={"password": "private-password"},
        exc_info=ValueError("private-exception"),
    )
    output = capsys.readouterr().err
    record = json.loads(output)
    assert set(record) == {"time", "level", "component", "message"}
    assert record["level"] == "ERROR"
    assert "private-" not in output


@pytest.mark.parametrize("section", ["{level: TRACE}", "{format: xml}", "{level: 1}"])
def test_invalid_logging(tmp_path: Path, section: str) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(f"logging: {section}")
    with pytest.raises(ConfigError):
        load_config(path)


def test_old_config(tmp_path: Path) -> None:
    path = tmp_path / "old.yaml"
    path.write_text("server: {port: 8001}")
    assert load_config(path).logging == LoggingConfig()


@pytest.mark.parametrize("running", [True, False])
def test_doctor(monkeypatch: pytest.MonkeyPatch, running: bool) -> None:
    monkeypatch.setattr(cli, "is_running", lambda config: running)
    monkeypatch.setattr(
        cli, "check_address", lambda server: diagnostics.Check("PASS", "address")
    )
    bind = Mock(return_value=diagnostics.Check("PASS", "port"))
    monkeypatch.setattr(cli, "check_port", bind)
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "PASS Python" in result.output
    assert "PASS OpenProxy" in result.output
    assert bind.call_count == (0 if running else 1)


@pytest.mark.parametrize("failure", ["address", "port"])
def test_doctor_failure(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    monkeypatch.setattr(cli, "is_running", lambda config: False)
    monkeypatch.setattr(
        cli,
        "check_address",
        lambda server: diagnostics.Check(
            "FAIL" if failure == "address" else "PASS", "address"
        ),
    )
    monkeypatch.setattr(
        cli, "check_port", lambda server: diagnostics.Check("FAIL", "port")
    )
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_bind_failure_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(
            return_value=[
                (2, 1, 6, "", ("127.0.0.1", 8000)),
            ]
        ),
    )
    probe = Mock()
    probe.__enter__ = Mock(return_value=probe)
    probe.__exit__ = Mock(return_value=False)
    probe.bind.side_effect = OSError(errno.EADDRINUSE, "secret-token")
    monkeypatch.setattr(socket, "socket", Mock(return_value=probe))
    check = diagnostics.check_port(AppConfig().server)
    assert check.status == "FAIL"
    assert "secret-token" not in check.message
    probe.listen.assert_not_called()
    probe.__exit__.assert_called_once()


def test_modes() -> None:
    result = runner.invoke(cli.app, ["--verbose", "config", "validate"])
    assert result.exit_code == 0
    assert "DEBUG" in result.output
    result = runner.invoke(cli.app, ["--quiet", "config", "validate"])
    assert result.exit_code == 0
    assert result.output == ""
    result = runner.invoke(cli.app, ["--quiet", "--verbose", "version"])
    assert result.exit_code == 2


def test_doctor_invalid_config(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("logging: {level: secret-token}")
    result = runner.invoke(cli.app, ["doctor", "-c", str(path)])
    assert result.exit_code == 2
    assert "FAIL Configuration" in result.output
    assert "secret-token" not in result.output


def test_bind_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(
            return_value=[
                (2, 1, 6, "", ("127.0.0.1", 8000)),
            ]
        ),
    )
    probe = Mock()
    probe.__enter__ = Mock(return_value=probe)
    probe.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(socket, "socket", Mock(return_value=probe))
    assert diagnostics.check_port(AppConfig().server).status == "PASS"
    probe.bind.assert_called_once_with(("127.0.0.1", 8000))
    probe.__exit__.assert_called_once()


def test_address_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", Mock(side_effect=OSError("secret")))
    assert diagnostics.check_address(AppConfig().server).status == "FAIL"


def test_quiet_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "is_running", lambda config: True)
    monkeypatch.setattr(
        cli, "check_address", lambda server: diagnostics.Check("PASS", "address")
    )
    result = runner.invoke(cli.app, ["--quiet", "doctor"])
    assert result.exit_code == 0
    assert result.output == ""


def test_warning_level_override(tmp_path: Path) -> None:
    path = tmp_path / "logging.yaml"
    path.write_text("logging: {level: ERROR, format: json}")
    result = runner.invoke(
        cli.app, ["--verbose", "config", "validate", "-c", str(path)]
    )
    assert result.exit_code == 0
    assert '"level": "DEBUG"' in result.output
    result = runner.invoke(cli.app, ["config", "validate", "-c", str(path)])
    assert result.exit_code == 0
    assert "DEBUG" not in result.output


@pytest.mark.parametrize("format", ["text", "json"])
@pytest.mark.parametrize(
    ("template", "args", "expected"),
    [
        ("Started server process [%d]", (12345,), "Started server process [12345]"),
        (
            "Uvicorn running on %s://%s:%d",
            ("http", "127.0.0.1", 8000),
            "Uvicorn running on http://127.0.0.1:8000",
        ),
    ],
)
def test_uvicorn_interpolation(
    format: str,
    template: str,
    args: tuple[object, ...],
    expected: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(LoggingConfig.model_validate({"format": format}))
    logging.getLogger("uvicorn.error").info(template, *args)
    output = capsys.readouterr().err
    message = json.loads(output)["message"] if format == "json" else output
    assert expected in message
    assert "%s" not in message
    assert "%d" not in message


def test_formatters_preserve_record_arguments() -> None:
    from openproxy.core.logging import JsonFormatter, TextFormatter

    record = logging.LogRecord(
        "other.library", logging.INFO, "", 0, "Value %s: %d", ("example", 42), None
    )
    for formatter in (TextFormatter(), JsonFormatter()):
        assert "Value example: 42" in formatter.format(record)
        assert record.msg == "Value %s: %d"
        assert record.args == ("example", 42)
    assert record.getMessage() == "Value example: 42"


@pytest.mark.parametrize("format", ["text", "json"])
def test_verbose_doctor_config_privacy(tmp_path: Path, format: str) -> None:
    path = tmp_path / "settings.yaml"
    path.write_text(
        f"logging: {{format: {format}}}\nserver: {{port: private-password-token}}\n"
    )
    result = runner.invoke(cli.app, ["--verbose", "doctor", "-c", str(path)])
    assert result.exit_code == 2
    assert "private-password-token" not in result.output
    assert "FAIL Configuration" in result.output
