"""Public response contracts; config output is an explicit allowlist."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from openproxy.core.config import AppConfig, LoggingConfig


class HealthResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    status: Literal["healthy"]
    name: Literal["OpenProxy"]
    version: str


class InfoResponse(BaseModel):
    name: Literal["OpenProxy"] = "OpenProxy"
    version: str
    description: str = "Local network management and monitoring core"
    telemetry_enabled: Literal[False] = False
    proxy_implemented: Literal[False] = False


class PublicServerConfig(BaseModel):
    host: str
    port: int


class ConfigResponse(BaseModel):
    server: PublicServerConfig
    logging: LoggingConfig


def public_config(config: AppConfig) -> ConfigResponse:
    """Do not automatically expose future credentials or local file paths."""
    return ConfigResponse(
        server=PublicServerConfig(host=config.server.host, port=config.server.port),
        logging=LoggingConfig(level=config.logging.level, format=config.logging.format),
    )
