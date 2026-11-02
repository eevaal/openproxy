from fastapi import APIRouter, Request

from openproxy import __version__
from openproxy.api.models import (
    ConfigResponse,
    HealthResponse,
    InfoResponse,
    public_config,
)
from openproxy.proxy.server import ProxyStatus, Stats

health_router = APIRouter()
v1_router = APIRouter(prefix="/api/v1")


@health_router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="healthy", name="OpenProxy", version=__version__)


@health_router.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    # Preserve the original discovery endpoint.
    return {"name": "OpenProxy", "status": "development", "local": "true"}


@v1_router.get("/info", response_model=InfoResponse)
async def info() -> InfoResponse:
    return InfoResponse(version=__version__)


@v1_router.get("/config", response_model=ConfigResponse)
async def config(request: Request) -> ConfigResponse:
    return public_config(request.app.state.config)


@v1_router.get("/proxy/status", response_model=ProxyStatus)
async def proxy_status(request: Request) -> ProxyStatus:
    return request.app.state.proxy.status()  # type: ignore[no-any-return]


@v1_router.get("/proxy/stats", response_model=Stats)
async def proxy_stats(request: Request) -> Stats:
    return request.app.state.proxy.stats.model_copy()  # type: ignore[no-any-return]
