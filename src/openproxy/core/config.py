"""Validated configuration shared by CLI and ASGI."""

import os
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from openproxy.rules.models import Rule

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


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["text", "json"] = "text"


class ProxyConfig(ServerConfig):
    enabled: bool = False
    port: int = Field(default=8080, ge=1, le=65535)
    connect_timeout: float = Field(default=10, gt=0, le=300)
    read_timeout: float = Field(default=30, gt=0, le=3600)
    request_timeout: float = Field(default=300, gt=0, le=86400)
    shutdown_timeout: float = Field(default=5, gt=0, le=60)
    max_connections: int = Field(default=100, ge=1, le=10000)
    unmatched_action: Literal["block", "forward"] = "block"
    allowed_connect_ports: list[int] = Field(default_factory=lambda: [443])
    allow_private_targets: bool = False
    allow_external_bind: bool = False

    @model_validator(mode="after")
    def valid_proxy(self) -> "ProxyConfig":
        if any(
            type(p) is not int or not 1 <= p <= 65535
            for p in self.allowed_connect_ports
        ):
            raise ValueError("CONNECT ports must be between 1 and 65535")
        if self.enabled and not self.is_loopback and not self.allow_external_bind:
            raise ValueError("external proxy requires allow_external_bind")
        return self


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid(self) -> "AppConfig":
        if self.proxy.enabled and self.proxy.port == self.server.port:
            raise ValueError("API and proxy ports must differ")
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("rule IDs must be unique")
        return self


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
