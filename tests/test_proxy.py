import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from openproxy.core.config import AppConfig, ProxyConfig
from openproxy.main import create_app
from openproxy.proxy import network
from openproxy.proxy.server import ProxyServer
from openproxy.rules.engine import select_rule
from openproxy.rules.models import Rule


def config(**kwargs: Any) -> AppConfig:
    return AppConfig(
        proxy=ProxyConfig(enabled=True, **kwargs).model_copy(update={"port": 0})
    )


@asynccontextmanager
async def proxy(config: AppConfig) -> AsyncIterator[tuple[ProxyServer, int]]:
    server = ProxyServer(config)
    await server.start()
    assert server.listener is not None
    port = server.listener.sockets[0].getsockname()[1]
    try:
        yield server, port
    finally:
        await server.stop()
        assert server.stats.active_connections == 0
        assert not server.tasks


async def exchange(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 3)
    finally:
        await network.close(writer)


def test_mock_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    denied = AsyncMock(side_effect=AssertionError("No upstream permitted"))
    # Mocking connect itself also proves that no DNS/connect is attempted.
    monkeypatch.setattr("openproxy.proxy.forward.connect", denied)
    rule = Rule.model_validate(
        {
            "id": "mock",
            "match": {"host": "API.EXAMPLE.TEST.", "path": "/status"},
            "action": "mock",
            "response": {"body": {"ok": True}},
        }
    )

    async def run() -> None:
        settings = config().model_copy(update={"rules": [rule]})
        async with proxy(settings) as (server, port):
            results = await asyncio.gather(
                *[
                    exchange(
                        port,
                        (
                            b"GET http://api.example.test/status HTTP/1.1\r\n"
                            b"Host: ignored\r\n\r\n"
                        ),
                    )
                    for _ in range(12)
                ]
            )
            assert all(b'{"ok": true}' in result for result in results)
            assert b"content-length: 12" in results[0].lower()
            assert server.stats.mock_responses == 12
        denied.assert_not_awaited()

    asyncio.run(run())


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
)
def test_forward(method: str) -> None:
    async def run() -> None:
        received: list[bytes] = []

        async def upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                head = await reader.readuntil(b"\r\n\r\n")
                body = await reader.readexactly(4) if method != "HEAD" else b""
                received.append(head + body)
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Upstream: yes\r\n\r\n"
                )
                if method != "HEAD":
                    writer.write(b"data")
                await writer.drain()
            finally:
                await network.close(writer)

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        async with upstream_server:
            up = upstream_server.sockets[0].getsockname()[1]
            async with proxy(
                config(unmatched_action="forward", allow_private_targets=True)
            ) as (_, port):
                body = b"data" if method != "HEAD" else b""
                result = await exchange(
                    port,
                    (
                        f"{method} http://127.0.0.1:{up}/test?a=1 HTTP/1.1\r\n"
                        "Host: wrong\r\nX-Test: value\r\nConnection: x-secret\r\n"
                        "X-Secret: hidden\r\nProxy-Authorization: hidden\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n"
                    ).encode()
                    + body,
                )
                assert b"200" in result
                assert b"x-upstream: yes" in result.lower()
                assert received and b"x-test: value" in received[0].lower()
                assert b"hidden" not in received[0]
                if method != "HEAD":
                    assert result.endswith(b"data")

    asyncio.run(run())


def test_streaming_chunked() -> None:
    async def run() -> None:
        async def upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            import h11

            from openproxy.proxy.protocol import event

            conn = h11.Connection(h11.SERVER)
            assert isinstance(await event(conn, reader, 1), h11.Request)
            body = bytearray()
            while True:
                item = await event(conn, reader, 1)
                if isinstance(item, h11.EndOfMessage):
                    break
                body.extend(item.data)
            assert body == b"abcd"
            writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            for _ in range(128):
                writer.write(b"10000\r\n" + b"x" * 65536 + b"\r\n")
                await writer.drain()
            writer.write(b"0\r\n\r\n")
            await network.close(writer)

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        async with upstream_server:
            up = upstream_server.sockets[0].getsockname()[1]
            async with proxy(
                config(unmatched_action="forward", allow_private_targets=True)
            ) as (_, port):
                async with httpx.AsyncClient(
                    proxy=f"http://127.0.0.1:{port}", trust_env=False
                ) as client:

                    async def body() -> AsyncIterator[bytes]:
                        yield b"ab"
                        yield b"cd"

                    async with client.stream(
                        "POST", f"http://127.0.0.1:{up}/", content=body()
                    ) as response:
                        assert response.status_code == 200
                        length = 0
                        async for chunk in response.aiter_bytes():
                            length += len(chunk)
                        assert length == 128 * 65536

    asyncio.run(run())


@pytest.mark.parametrize("status", [200, 204, 304])
@pytest.mark.parametrize("method", ["GET", "POST", "HEAD"])
def test_mock_bodies(status: int, method: str) -> None:
    async def run() -> None:
        rule = Rule.model_validate(
            {
                "id": "a",
                "action": "mock",
                "response": {"status": status, "body": "hello"},
            }
        )
        async with proxy(config().model_copy(update={"rules": [rule]})) as (_, port):
            data = await exchange(
                port, f"{method} / HTTP/1.1\r\nHost: example.test\r\n\r\n".encode()
            )
            assert str(status).encode() in data
            assert data.endswith(b"hello") == (method != "HEAD" and status == 200)

    asyncio.run(run())


def test_rules() -> None:
    def rule(id: str, priority: int = 0, enabled: bool = True) -> Rule:
        return Rule.model_validate(
            {
                "id": id,
                "priority": priority,
                "enabled": enabled,
                "action": "block",
                "match": {
                    "host": "EXAMPLE.test.",
                    "method": "GET",
                    "path": "/a%2Fb",
                    "query": {"q": "a b"},
                },
            }
        )

    rules = [rule("disabled", 100, False), rule("first", 1), rule("second", 1)]
    assert select_rule(rules, "GET", "example.test", "/a%2Fb", "q=a+b") == rules[1]
    assert select_rule(rules, "POST", "example.test", "/a%2Fb", "q=a+b") is None
    assert select_rule(rules, "GET", "example.test", "/a/b", "q=a+b") is None
    assert select_rule(rules, "GET", "other.test", "/a%2Fb", "q=a+b") is None
    assert select_rule(rules, "GET", "example.test", "/a%2Fb", "q=a+b&q=x") is None


@pytest.mark.parametrize(
    "raw",
    [
        b"broken\r\n\r\n",
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        ),
        b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
    ],
)
def test_malformed(raw: bytes) -> None:
    async def run() -> None:
        async with proxy(config()) as (_, port):
            result = await exchange(port, raw)
            assert b"400" in result

    asyncio.run(run())


def test_policy_and_default_block() -> None:
    async def run() -> None:
        for action in ("block", "forward"):
            async with proxy(config(unmatched_action=action)) as (server, port):
                result = await exchange(
                    port, b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\n\r\n"
                )
                assert b"403" in result
                assert server.stats.blocked_requests == (action == "block")

    asyncio.run(run())


def test_connect() -> None:
    async def run() -> None:
        async def echo(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
            await network.close(writer)

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        async with upstream:
            up = upstream.sockets[0].getsockname()[1]
            async with proxy(
                config(
                    unmatched_action="forward",
                    allow_private_targets=True,
                    allowed_connect_ports=[up],
                )
            ) as (_, port):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(
                    (
                        f"CONNECT 127.0.0.1:{up} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{up}\r\n\r\n"
                    ).encode()
                    + b"early"
                )
                await writer.drain()
                assert b"200" in await reader.readuntil(b"\r\n\r\n")
                assert await reader.readexactly(5) == b"early"
                writer.write(b"later")
                await writer.drain()
                assert await reader.readexactly(5) == b"later"
                writer.write_eof()
                assert await asyncio.wait_for(reader.read(), 1) == b""
                await network.close(writer)

    asyncio.run(run())


def test_limits_shutdown_timeout() -> None:
    async def run() -> None:
        async with proxy(
            config(max_connections=1, read_timeout=0.1, shutdown_timeout=0.1)
        ) as (server, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\n")
            await writer.drain()
            while server.stats.active_connections == 0:
                await asyncio.sleep(0)
            result = await exchange(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert b"503" in result
            assert b"504" in await asyncio.wait_for(reader.read(), 1)
            await network.close(writer)

    asyncio.run(run())


def test_api_lifecycle() -> None:
    app = create_app(config())
    with TestClient(app) as client:
        assert client.get("/api/v1/proxy/status").json() == {
            "enabled": True,
            "running": True,
        }
        assert client.get("/api/v1/proxy/stats").json()["active_connections"] == 0
    assert not hasattr(app.state, "proxy")


@pytest.mark.parametrize(
    "data",
    [
        {"proxy": {"enabled": True, "port": 8000}},
        {"proxy": {"port": 65536}},
        {"proxy": {"enabled": True, "host": "0.0.0.0"}},
        {"rules": [{"id": "a", "action": "block"}, {"id": "a", "action": "block"}]},
        {"rules": [{"id": "a", "action": "mock"}]},
    ],
)
def test_config_validation(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate(data)


@pytest.mark.parametrize("mode", ["timeout", "closed", "early"])
def test_upstream_failures(mode: str) -> None:
    async def run() -> None:
        async def upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
                if mode == "timeout":
                    await reader.read()  # Closed by the timed-out proxy.
                elif mode == "early":
                    writer.write(b"HTTP/1.1 413 Rejected\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
            finally:
                await network.close(writer)

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        async with upstream_server:
            up = upstream_server.sockets[0].getsockname()[1]
            async with proxy(
                config(
                    unmatched_action="forward",
                    allow_private_targets=True,
                    read_timeout=0.1,
                )
            ) as (_, port):
                result = await exchange(
                    port,
                    (
                        f"POST http://127.0.0.1:{up}/ HTTP/1.1\r\n"
                        "Host: x\r\nContent-Length: 100\r\n\r\n"
                    ).encode(),
                )
                assert (
                    str(
                        504 if mode == "timeout" else 413 if mode == "early" else 502
                    ).encode()
                    in result
                )

    asyncio.run(run())


def test_shutdown_cancels_stalled_clients() -> None:
    async def run() -> None:
        server = ProxyServer(config(shutdown_timeout=0.05))
        await server.start()
        assert server.listener is not None
        port = server.listener.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\n")
        await writer.drain()
        while server.stats.active_connections == 0:
            await asyncio.sleep(0)
        await server.stop()
        assert await asyncio.wait_for(reader.read(), 1) == b""
        assert server.stats.active_connections == 0
        assert not server.tasks
        await network.close(writer)

    asyncio.run(run())


def test_private_dns_rejected_before_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop,
            "getaddrinfo",
            AsyncMock(
                return_value=[
                    (2, 1, 6, "", ("8.8.8.8", 80)),
                    (2, 1, 6, "", ("169.254.169.254", 80)),
                ]
            ),
        )
        opening = AsyncMock()
        monkeypatch.setattr(asyncio, "open_connection", opening)
        with pytest.raises(PermissionError):
            await network.connect("example.test", 80, ProxyConfig())
        opening.assert_not_awaited()

    asyncio.run(run())


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
        "::ffff:127.0.0.1",
    ],
)
def test_address_policy(address: str, monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            asyncio.get_running_loop(),
            "getaddrinfo",
            AsyncMock(return_value=[(2, 1, 6, "", (address, 80))]),
        )
        opening = AsyncMock()
        monkeypatch.setattr(asyncio, "open_connection", opening)
        with pytest.raises(PermissionError):
            await network.connect("example.test", 80, ProxyConfig())
        opening.assert_not_awaited()

    asyncio.run(run())


def test_pinned_dns_address(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        resolve = AsyncMock(return_value=[(2, 1, 6, "", ("93.184.216.34", 80))])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        opening = AsyncMock(return_value=(object(), object()))
        monkeypatch.setattr(asyncio, "open_connection", opening)
        await network.connect("example.test", 80, ProxyConfig())
        assert opening.call_args.args == ("93.184.216.34", 80)
        resolve.assert_awaited_once()

    asyncio.run(run())


def test_unavailable_upstream() -> None:
    import socket

    async def run() -> None:
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            up = reserved.getsockname()[1]
            async with proxy(
                config(
                    unmatched_action="forward",
                    allow_private_targets=True,
                    connect_timeout=0.2,
                )
            ) as (server, port):
                result = await exchange(
                    port,
                    (
                        f"GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n"
                    ).encode(),
                )
                assert b"502" in result or b"504" in result
                assert server.stats.errors == 1

    asyncio.run(run())


def test_proxy_api_counts() -> None:
    rule = Rule.model_validate(
        {"id": "a", "action": "mock", "response": {"body": "ok"}}
    )
    app = create_app(config().model_copy(update={"rules": [rule]}))
    with TestClient(app) as api:
        port = app.state.proxy.listener.sockets[0].getsockname()[1]
        with httpx.Client(proxy=f"http://127.0.0.1:{port}", trust_env=False) as client:
            assert client.get("http://mock.test/").text == "ok"
        stats = api.get("/api/v1/proxy/stats").json()
        assert stats["mock_responses"] == 1
        assert stats["total_connections"] == 1


def test_proxy_logs_privacy(capsys: pytest.CaptureFixture[str]) -> None:
    from openproxy.core.config import LoggingConfig
    from openproxy.core.logging import configure_logging

    configure_logging(LoggingConfig(level="DEBUG"))

    async def run() -> None:
        rule = Rule.model_validate(
            {
                "id": "safe-id",
                "action": "mock",
                "response": {"body": "private-response"},
            }
        )
        async with proxy(config().model_copy(update={"rules": [rule]})) as (_, port):
            result = await exchange(
                port,
                (
                    b"POST /?token=private-query HTTP/1.1\r\nHost: mock.test\r\n"
                    b"Authorization: private-auth\r\nCookie: private-cookie\r\n"
                    b"Content-Length: 12\r\n\r\nprivate-body"
                ),
            )
            assert b"private-response" in result

    asyncio.run(run())
    logs = capsys.readouterr().err
    assert "safe-id" in logs
    assert "private-" not in logs


def test_status_detects_engine_failure(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from openproxy import cli

    path = tmp_path / "proxy.yaml"
    path.write_text("proxy: {enabled: true}")
    monkeypatch.setattr(cli, "is_running", lambda config: True)
    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"enabled": True, "running": False}
                )
            ),
            **kwargs,
        ),
    )
    result = CliRunner().invoke(cli.app, ["status", "-c", str(path)])
    assert result.exit_code == 1
    assert "Proxy not running" in result.output


@pytest.mark.parametrize("settings", [{}, {"unmatched_action": "forward"}])
def test_connect_denied(settings: dict[str, Any]) -> None:
    async def run() -> None:
        async with proxy(config(**settings)) as (_, port):
            result = await exchange(
                port, b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: x\r\n\r\n"
            )
            assert b"403" in result

    asyncio.run(run())


def test_proxy_startup_failure() -> None:
    import socket

    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        reserved.listen()
        port = reserved.getsockname()[1]
        app = create_app(AppConfig(proxy=ProxyConfig(enabled=True, port=port)))
        with pytest.raises(OSError), TestClient(app):
            pytest.fail("Startup must fail when proxy cannot bind")
        assert not hasattr(app.state, "proxy")
