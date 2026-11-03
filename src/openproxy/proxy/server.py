"""One HTTP exchange per socket; bounded tasks, streaming and graceful shutdown."""

import asyncio
import logging
import ssl
from typing import cast

import h11
from pydantic import BaseModel

from openproxy.core.config import AppConfig
from openproxy.proxy.forward import forward
from openproxy.proxy.inspection import build_contexts
from openproxy.proxy.network import close
from openproxy.proxy.protocol import event, send
from openproxy.proxy.responses import respond
from openproxy.proxy.targets import authority, http_target
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
    https_inspection_connections: int = 0
    https_mock_responses: int = 0
    tls_handshake_failures: int = 0
    https_forwarding_errors: int = 0


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
        self.inspection_contexts: dict[str, ssl.SSLContext] = {}
        self.upstream_tls: ssl.SSLContext | None = None

    def status(self) -> ProxyStatus:
        return ProxyStatus(
            enabled=self.config.proxy.enabled,
            running=not self.stopping
            and self.listener is not None
            and self.listener.is_serving(),
        )

    async def start(self) -> None:
        if self.config.proxy.enabled:
            inspection = self.config.proxy.https_inspection
            if inspection.enabled:
                self.inspection_contexts, self.upstream_tls = build_contexts(inspection)
            host = self.config.proxy.host
            if inspection.enabled and host == "localhost":
                host = "127.0.0.1"
            self.listener = await asyncio.start_server(
                self.accept, host, self.config.proxy.port
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
        if len(self.tasks) >= self.config.proxy.max_connections + 16:
            self.stats.total_connections += 1
            writer.transport.abort()
            return  # Bound rejection tasks as well as active exchanges.
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.finished)

    def finished(self, task: asyncio.Task[None]) -> None:
        self.tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.stats.errors += 1
            logger.error("Proxy task failed")  # Never expose exception/peer details.

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
                await asyncio.wait_for(writer.drain(), 0.1)
                writer.write_eof()
                await asyncio.wait_for(reader.read(16384), 0.1)
            except (OSError, TimeoutError):
                logger.debug("Rejected peer closed")
            finally:
                await close(writer)
            return
        self.stats.active_connections += 1
        connection = h11.Connection(h11.SERVER, max_incomplete_event_size=16384)
        settings = self.config.proxy
        try:
            async with asyncio.timeout(settings.request_timeout):
                request, host_header = await self.read_request(connection, reader)
                destination = None
                if request.method == b"CONNECT":
                    authority(host_header.decode("ascii"))
                    host, port = authority(
                        request.target.decode("ascii"), explicit_port=True
                    )
                    if any(
                        k == b"transfer-encoding"
                        or (k == b"content-length" and v != b"0")
                        for k, v in request.headers
                    ):
                        raise ValueError("CONNECT cannot have an HTTP body")
                    if port not in settings.allowed_connect_ports:
                        raise PermissionError("CONNECT port denied")

                    context = self.inspection_contexts.get(host)
                    if context is None:
                        if settings.unmatched_action != "forward":
                            raise PermissionError("CONNECT denied")
                        self.stats.forwarded_requests += 1
                        await tunnel(
                            connection,
                            reader,
                            writer,
                            host,
                            port,
                            connection.trailing_data[0],
                            settings,
                        )
                        return

                    if authority(host_header.decode("ascii"), default_port=443) != (
                        host,
                        port,
                    ):
                        raise PermissionError("Host does not match CONNECT")
                    if connection.trailing_data[0]:
                        raise ValueError("Unexpected data before TLS handshake")
                    if not await self.upgrade(connection, reader, writer, context):
                        return
                    destination = (host, port)
                    connection = h11.Connection(
                        h11.SERVER, max_incomplete_event_size=16384
                    )
                    request, host_header = await self.read_request(connection, reader)

                await self.dispatch(
                    connection, reader, writer, request, host_header, destination
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
            if connection.our_state is h11.IDLE:
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
            try:
                await close(writer)
            finally:
                self.stats.active_connections -= 1

    async def read_request(
        self, connection: h11.Connection, reader: asyncio.StreamReader
    ) -> tuple[h11.Request, bytes]:
        request = await event(connection, reader, self.config.proxy.read_timeout)
        if not isinstance(request, h11.Request):
            raise ValueError("Expected request")
        names = {k for k, _ in request.headers}
        if b"content-length" in names and b"transfer-encoding" in names:
            raise ValueError("Ambiguous framing")
        host_header = next((v for k, v in request.headers if k == b"host"), b"")
        return request, host_header

    async def upgrade(
        self,
        connection: h11.Connection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        context: ssl.SSLContext,
    ) -> bool:
        settings = self.config.proxy
        # Pause the raw transport before checking for plaintext that h11 did
        # not read. start_tls replaces the protocol and resumes the transport.
        cast(asyncio.Transport, writer.transport).pause_reading()
        try:
            async with asyncio.timeout(0):
                await reader.read(1)
        except TimeoutError:
            pass  # A read that would wait means the buffer was empty.
        else:
            raise ValueError("Unexpected data or EOF before TLS handshake")
        await send(
            connection,
            writer,
            h11.Response(status_code=200, headers=[], reason=b"Connection Established"),
            settings.read_timeout,
        )
        established = False
        try:
            await writer.start_tls(
                context,
                ssl_handshake_timeout=settings.https_inspection.handshake_timeout,
                ssl_shutdown_timeout=1,
            )
            established = True
        except (OSError, TimeoutError):
            self.stats.tls_handshake_failures += 1
            self.stats.errors += 1
            logger.debug("Inspection TLS handshake failed")
        finally:
            if not established:
                writer.transport.abort()
        if established:
            self.stats.https_inspection_connections += 1
        return established

    async def dispatch(
        self,
        connection: h11.Connection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: h11.Request,
        host_header: bytes,
        destination: tuple[str, int] | None,
    ) -> None:
        settings = self.config.proxy
        method = request.method.decode("ascii")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError("Unsupported method")
        scheme = "https" if destination is not None else "http"
        target, host, port = http_target(request.target, host_header, scheme=scheme)
        if destination is not None and (
            (host, port) != destination
            or authority(host_header.decode("ascii"), default_port=443) != destination
        ):
            raise PermissionError("HTTPS request authority does not match CONNECT")

        rule = select_rule(
            self.config.rules, method, host, target.path or "/", target.query
        )
        action = rule.action if rule else settings.unmatched_action
        if rule:
            logger.debug("Rule applied: %s", rule.id)

        if any(k == b"expect" for k, _ in request.headers):
            await send(
                connection,
                writer,
                h11.InformationalResponse(status_code=100, headers=[]),
                settings.read_timeout,
            )

        if action == "forward":
            self.stats.forwarded_requests += 1
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            tls = None
            if destination is not None:
                tls = self.upstream_tls
                if tls is None:
                    raise RuntimeError("Inspection upstream context missing")
            try:
                await forward(
                    request,
                    connection,
                    reader,
                    writer,
                    host,
                    port,
                    path,
                    settings,
                    tls=tls,
                )
            except (OSError, TimeoutError, h11.ProtocolError):
                if destination is not None:
                    self.stats.https_forwarding_errors += 1
                    if (
                        connection.our_state is h11.SEND_RESPONSE
                        and connection.their_state is h11.SEND_BODY
                    ):
                        # A TLS close while application data is still arriving can
                        # reset the stream before the client receives the error.
                        await self.discard_body(connection, reader)
                raise
            return

        await self.discard_body(connection, reader)
        if action == "mock":
            self.stats.mock_responses += 1
            if destination is not None:
                self.stats.https_mock_responses += 1
        else:
            self.stats.blocked_requests += 1
        response = rule.response if rule and rule.response else Response(status=403)
        await respond(connection, writer, response, method, settings.read_timeout)

    async def discard_body(
        self, connection: h11.Connection, reader: asyncio.StreamReader
    ) -> None:
        while True:
            part = await event(connection, reader, self.config.proxy.read_timeout)
            if isinstance(part, h11.EndOfMessage):
                return
            if not isinstance(part, h11.Data):
                raise h11.RemoteProtocolError("Incomplete request body")
