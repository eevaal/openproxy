"""ASGI factory: each app owns its validated configuration snapshot."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from openproxy import __version__
from openproxy.api.routes import health_router, v1_router
from openproxy.core.config import AppConfig, load_config
from openproxy.core.logging import configure_logging

EXTERNAL_WARNING = (
    "OpenProxy is listening on a non-loopback interface. The management API has "
    "no authentication; protect access with a firewall or an authenticated gateway."
)


def create_app(
    config: AppConfig | None = None, *, config_path: str | Path | None = None
) -> FastAPI:
    if config is not None and config_path is not None:
        raise ValueError("Pass config or config_path, not both")

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        active = config if config is not None else load_config(config_path)
        configure_logging(active.logging)
        logger = logging.getLogger("openproxy.server")
        logger.info("Server starting")
        application.state.config = active
        if not active.server.is_loopback:
            logging.getLogger("openproxy").warning(EXTERNAL_WARNING)
        try:
            logger.info("Server ready")
            yield
        finally:
            logger.info("Server stopped")
            del application.state.config

    application = FastAPI(
        title="OpenProxy",
        description="Local network management and monitoring core",
        version=__version__,
        lifespan=lifespan,
    )
    application.include_router(health_router)
    application.include_router(v1_router)
    return application


# Importing the module does not read configuration files.
app = create_app()
