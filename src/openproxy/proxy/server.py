"""One HTTP exchange per socket; bounded tasks, streaming and graceful shutdown."""

import asyncio
import logging
from urllib.parse import urlsplit

import h11
from pydantic import BaseModel

from openproxy.core.config import AppConfig
from openproxy.proxy.forward import forward
from openproxy.proxy.network import close
from openproxy.proxy.protocol import event, send
from openproxy.proxy.responses import respond
from openproxy.proxy.tunnel import tunnel
from openproxy.rules.engine import select_rule
from openproxy.rules.models import Response

logger = logging.getLogger("openproxy.proxy")


class Stats(BaseModel):
    active_connections: int = 0
    total_connections: int = 0
    mock_responses: int = 0
    forwarded_requests: int = 0
    blocked_requests: int = 0
    errors: int = 0


class ProxyStatus(BaseModel):
    enabled: bool
    running: bool


class ProxyServer:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.stats = Stats()
        self.listener: asyncio.Server | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.stopping = False

    def status(self) -> ProxyStatus:
        return ProxyStatus(
            enabled=self.config.proxy.enabled,
            running=self.listener is not None and self.listener.is_serving(),
        )

    async def start(self) -> None:
        if self.config.proxy.enabled:
            self.listener = await asyncio.start_server(
                self.accept, self.config.proxy.host, self.config.proxy.port
            )
            logger.info("Proxy started")
            if not self.config.proxy.is_loopback:
                logger.warning("External proxy enabled: restrict network access")

    async def stop(self) -> None:
        self.stopping = True
        if self.listener:
            self.listener.close()
        if self.tasks:
            _, pending = await asyncio.wait(
                self.tasks, timeout=self.config.proxy.shutdown_timeout
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        if self.listener:
            await self.listener.wait_closed()
        logger.info("Proxy stopped")

    def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self.stopping:
            writer.close()
            return
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.stats.total_connections += 1
        if self.stats.active_connections >= self.config.proxy.max_connections:
            writer.write(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            try:
                await writer.drain()
                writer.write_eof()
                await asyncio.wait_for(reader.read(16384), 0.1)
            except (OSError, TimeoutError):
                logger.debug("Rejected peer closed")
            await close(writer)
            return
        self.stats.active_connections += 1
        connection = h11.Connection(h11.SERVER, max_incomplete_event_size=16384)
        settings = self.config.proxy
        try:
            request = await event(connection, reader, settings.read_timeout)
            if not isinstance(request, h11.Request):
                raise ValueError("Expected request")
            raw = list(request.headers)
            if any(k == b"content-length" for k, _ in raw) and any(
                k == b"transfer-encoding" for k, _ in raw
            ):
                raise ValueError("Ambiguous framing")
            method = request.method.decode("ascii")
            if method == "CONNECT":
                target = urlsplit("//" + request.target.decode("ascii"))
                if (
                    not target.hostname
                    or target.port is None
                    or target.path
                    or target.query
                    or target.username
                ):
                    raise ValueError("Invalid CONNECT authority")
                if (
                    target.port not in settings.allowed_connect_ports
                    or settings.unmatched_action != "forward"
                ):
                    raise PermissionError("CONNECT denied")
                self.stats.forwarded_requests += 1
                await tunnel(
                    connection,
                    reader,
                    writer,
                    target.hostname,
                    target.port,
                    connection.trailing_data[0],
                    settings,
                )
                return
            if method not in {
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
            }:
                raise ValueError("Unsupported method")
            target = urlsplit(request.target.decode("ascii"))
            if target.scheme:
                if target.scheme != "http" or not target.netloc:
                    raise ValueError("Only HTTP absolute targets")
            else:
                if not request.target.startswith(b"/"):
                    raise ValueError("Invalid target")
                host = next(v for k, v in raw if k == b"host").decode("ascii")
                target = urlsplit("http://" + host + request.target.decode("ascii"))
            if (
                not target.hostname
                or target.username
                or target.password
                or target.fragment
            ):
                raise ValueError("Invalid target")
            port = target.port or 80
            if not 1 <= port <= 65535:
                raise ValueError("Invalid port")
            rule = select_rule(
                self.config.rules,
                method,
                target.hostname,
                target.path or "/",
                target.query,
            )
            action = rule.action if rule else settings.unmatched_action
            if rule:
                logger.debug("Rule applied: %s", rule.id)
            if action != "forward":
                if any(k == b"expect" for k, _ in raw):
                    await send(
                        connection,
                        writer,
                        h11.InformationalResponse(status_code=100, headers=[]),
                        settings.read_timeout,
                    )
                while True:
                    part = await event(connection, reader, settings.read_timeout)
                    if isinstance(part, h11.EndOfMessage):
                        break
                    if not isinstance(part, h11.Data):
                        raise h11.RemoteProtocolError("Incomplete request body")
                if action == "mock":
                    self.stats.mock_responses += 1
                else:
                    self.stats.blocked_requests += 1
                response = (
                    rule.response if rule and rule.response else Response(status=403)
                )
                await respond(
                    connection, writer, response, method, settings.read_timeout
                )
            else:
                if any(k == b"expect" for k, _ in raw):
                    await send(
                        connection,
                        writer,
                        h11.InformationalResponse(status_code=100, headers=[]),
                        settings.read_timeout,
                    )
                self.stats.forwarded_requests += 1
                path = target.path or "/"
                if target.query:
                    path += "?" + target.query
                await forward(
                    request,
                    connection,
                    reader,
                    writer,
                    target.hostname,
                    port,
                    path,
                    settings,
                )
        except (OSError, TimeoutError, ValueError, h11.ProtocolError) as exc:
            self.stats.errors += 1
            code = (
                504
                if isinstance(exc, TimeoutError)
                else 403
                if isinstance(exc, PermissionError)
                else 400
                if isinstance(exc, (ValueError, h11.RemoteProtocolError))
                else 502
            )
            logger.warning("Proxy exchange failed (%d)", code)
            if connection.our_state in (h11.IDLE, h11.ERROR):
                writer.write(
                    (
                        f"HTTP/1.1 {code} Error\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n"
                    ).encode()
                )
            elif connection.our_state == h11.SEND_RESPONSE:
                try:
                    await respond(
                        connection,
                        writer,
                        Response(status=code),
                        "GET",
                        settings.read_timeout,
                    )
                except (OSError, TimeoutError, h11.ProtocolError):
                    logger.debug("Peer closed during error response")
        finally:
            await close(writer)
            self.stats.active_connections -= 1
