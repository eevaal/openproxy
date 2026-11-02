"""Validated configuration shared by CLI and ASGI."""

import os
from ipaddress import ip_address
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

CONFIG_ENV = "OPENPROXY_CONFIG"


class ConfigError(ValueError):
    """An expected configuration error safe to display to the user."""


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if value == "localhost":
            return value
        try:
            address = ip_address(value)
        except ValueError:
            raise ValueError("host must be an IPv4/IPv6 address or localhost") from None
        if "%" in value:
            raise ValueError("scoped IPv6 addresses are not supported")
        return str(address)

    @property
    def is_loopback(self) -> bool:
        return self.host == "localhost" or ip_address(self.host).is_loopback

    @property
    def health_url(self) -> str:
        # Probe loopback when the server binds to a wildcard address.
        host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(self.host, self.host)
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{self.port}/health"


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    server: ServerConfig = Field(default_factory=ServerConfig)


def resolve_config_path(file_path: str | Path | None = None) -> Path | None:
    """Explicit/environment paths must exist; implicit config.yaml is optional."""
    configured = file_path if file_path is not None else os.environ.get(CONFIG_ENV)
    if configured is not None:
        return Path(configured).expanduser().resolve()
    default = Path("config.yaml").resolve()
    return default if default.exists() else None


def load_config(file_path: str | Path | None = None) -> AppConfig:
    path = resolve_config_path(file_path)
    if path is None:
        return AppConfig()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) else "invalid UTF-8"
        raise ConfigError(f"Cannot read configuration '{path}': {reason}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        # Parser messages may contain raw input, including secrets.
        raise ConfigError(f"Invalid YAML in configuration '{path}'") from None
    if data is None:
        raise ConfigError(f"Configuration file '{path}' is empty")
    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a YAML mapping")
    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(map(str, error['loc']))}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"Invalid configuration '{path}': {details}") from None
