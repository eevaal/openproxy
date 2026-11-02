"""Regression cases from the v0.3.1 protocol and lifecycle audit."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import ValidationError

from openproxy.core.config import ProxyConfig
from openproxy.proxy import network
from openproxy.proxy.protocol import headers
from openproxy.proxy.targets import authority
from openproxy.rules.models import Match, Response
from tests.test_proxy import config, exchange, proxy


@pytest.mark.parametrize(
    "target",
    [
        "x:0",
        "x:",
        "x:443#secret",
        "x:443?query",
        "x:443/",
        "user@x:443",
        "x%00:443",
        "x\\evil:443",
        "x..:443",
        "[::1]evil:443",
        "[v1.x]:443",
    ],
)
def test_invalid_authority(target: str) -> None:
    with pytest.raises(ValueError):
        authority(target, explicit_port=True)


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x/path\r\n\r\n",
        b"GET http://x:0/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"CONNECT x:443#secret HTTP/1.1\r\nHost: x\r\n\r\n",
        b"CONNECT x:443 HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\ndata",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\n" + b"X: a\r\n" * 101 + b"\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 17000 + b"\r\n\r\n",
    ],
)
def test_malformed_rejected_without_upstream(
    raw: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    opening = AsyncMock(side_effect=AssertionError("unexpected network access"))
    monkeypatch.setattr("openproxy.proxy.forward.connect", opening)
    monkeypatch.setattr("openproxy.proxy.tunnel.connect", opening)

    async def run() -> None:
        async with proxy(config()) as (server, port):
            response = await exchange(port, raw)
            assert b"400" in response
            assert server.stats.errors == 1
        opening.assert_not_awaited()

    asyncio.run(run())


def test_proxy_connection_nominated_headers() -> None:
    assert headers(
        [
            (b"proxy-connection", b"x-private"),
            (b"x-private", b"secret"),
            (b"x-ok", b"yes"),
        ]
    ) == [(b"x-ok", b"yes")]


@pytest.mark.parametrize(
    "host", ["", "x..", "http://x", "x:80", "bad host", "-bad.test"]
)
def test_invalid_rule_host(host: str) -> None:
    with pytest.raises(ValidationError):
        Match(host=host)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "\ud800"])
def test_invalid_mock_json(value: float | str) -> None:
    with pytest.raises(ValidationError):
        Response(body=value)


def test_duplicate_response_headers() -> None:
    with pytest.raises(ValidationError):
        Response(headers={"Content-Type": "a", "content-type": "b"})


@pytest.mark.parametrize(
    "address",
    [
        "fec0::1",
        "64:ff9b::a00:1",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    ],
)
def test_transition_addresses_denied(
    address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            asyncio.get_running_loop(),
            "getaddrinfo",
            AsyncMock(return_value=[(10, 1, 6, "", (address, 443, 0, 0))]),
        )
        opening = AsyncMock()
        monkeypatch.setattr(asyncio, "open_connection", opening)
        with pytest.raises(PermissionError):
            await network.connect("example.test", 443, ProxyConfig())
        opening.assert_not_awaited()

    asyncio.run(run())


def test_slow_headers_have_absolute_deadline() -> None:
    async def run() -> None:
        async with proxy(config(read_timeout=0.05)) as (_, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            async def drip() -> None:
                try:
                    for byte in b"GET / HTTP/1.1\r\nHost: x\r\n\r\n":
                        writer.write(bytes([byte]))
                        await writer.drain()
                        await asyncio.sleep(0.01)
                except OSError:
                    return

            sender = asyncio.create_task(drip())
            try:
                assert b"504" in await asyncio.wait_for(reader.read(), 0.2)
            finally:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)
                await network.close(writer)

    asyncio.run(run())


def test_total_deadline_bounds_endless_body() -> None:
    async def run() -> None:
        async with proxy(config(request_timeout=0.05)) as (_, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\na"
            )
            await writer.drain()
            assert b"504" in await asyncio.wait_for(reader.read(), 0.5)
            await network.close(writer)

    asyncio.run(run())


def test_rejection_tasks_are_bounded() -> None:
    async def run() -> None:
        async with proxy(config(max_connections=1)) as (server, _):
            peer = Mock()
            for _ in range(100):
                server.accept(asyncio.StreamReader(), peer)
            assert len(server.tasks) <= 17
            assert peer.transport.abort.call_count == 83
            # Close mocked transports without running fake StreamWriter methods.
            tasks = list(server.tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(run())


def test_truncated_response_never_gets_second_status() -> None:
    async def run() -> None:
        async def upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
            await network.close(writer)

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        async with upstream_server:
            upstream_port = upstream_server.sockets[0].getsockname()[1]
            async with proxy(
                config(unmatched_action="forward", allow_private_targets=True)
            ) as (_, port):
                result = await exchange(
                    port,
                    (
                        f"GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\n"
                        "Host: x\r\n\r\n"
                    ).encode(),
                )
                assert result.count(b"HTTP/1.1") == 1
                assert result.endswith(b"short")

    asyncio.run(run())


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_disconnect_releases_upstream(direction: str) -> None:
    async def run() -> None:
        released = asyncio.Event()

        async def upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
                if direction == "upload":
                    await reader.read()
                else:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n"
                    )
                    while True:
                        writer.write(b"x" * 16384)
                        await writer.drain()
                        await asyncio.sleep(0)
            except OSError:
                return
            finally:
                await network.close(writer)
                released.set()

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        async with upstream_server:
            up = upstream_server.sockets[0].getsockname()[1]
            async with proxy(
                config(unmatched_action="forward", allow_private_targets=True)
            ) as (server, port):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                body_headers = (
                    "Content-Length: 999999999\r\n" if direction == "upload" else ""
                )
                writer.write(
                    (
                        f"POST http://127.0.0.1:{up}/ HTTP/1.1\r\n"
                        f"Host: x\r\n{body_headers}\r\n"
                    ).encode()
                )
                await writer.drain()
                if direction == "download":
                    await reader.readuntil(b"\r\n\r\n")
                writer.transport.abort()
                await asyncio.wait_for(released.wait(), 2)
                await asyncio.wait_for(asyncio.gather(*list(server.tasks)), 2)
                assert server.stats.active_connections == 0

    asyncio.run(run())


def test_shutdown_during_mock_delay() -> None:
    from openproxy.proxy.server import ProxyServer
    from openproxy.rules.models import Rule

    async def run() -> None:
        rule = Rule(id="delay", action="mock", response=Response(delay=60))
        server = ProxyServer(
            config(shutdown_timeout=0.02).model_copy(update={"rules": [rule]})
        )
        await server.start()
        assert server.listener is not None
        port = server.listener.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        while server.stats.mock_responses == 0:
            await asyncio.sleep(0)
        await asyncio.wait_for(server.stop(), 1)
        assert await reader.read() == b""
        assert not server.status().running
        assert server.stats.active_connections == 0
        assert not server.tasks
        await network.close(writer)

    asyncio.run(run())


def test_local_seeded_target_fuzz() -> None:
    import random

    async def run() -> None:
        randomizer = random.Random(31)
        async with proxy(config(read_timeout=0.05)) as (_, port):
            for _ in range(32):
                target = bytes(
                    randomizer.choice(b"/abc:?#@%\\\x00\x7f") for _ in range(12)
                )
                result = await exchange(
                    port, b"GET " + target + b" HTTP/1.1\r\nHost: x\r\n\r\n"
                )
                assert result.startswith((b"HTTP/1.1 400", b"HTTP/1.1 403"))
            assert b"403" in await exchange(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")

    asyncio.run(run())


@pytest.mark.parametrize("format", ["text", "json"])
def test_error_logs_exclude_secrets(
    format: str, capsys: pytest.CaptureFixture[str]
) -> None:
    from openproxy.core.config import LoggingConfig
    from openproxy.core.logging import configure_logging
    from openproxy.rules.models import Rule

    configure_logging(
        LoggingConfig.model_validate({"format": format, "level": "DEBUG"})
    )

    async def run() -> None:
        rule = Rule(
            id="safe",
            action="mock",
            response=Response(
                headers={"Set-Cookie": "secret-response-cookie"},
                body="secret-response-body",
            ),
        )
        async with proxy(config().model_copy(update={"rules": [rule]})) as (_, port):
            request = (
                b"POST /?token=secret-query HTTP/1.1\r\nHost: x\r\n"
                b"Authorization: secret-auth\r\nProxy-Authorization: secret-proxy\r\n"
                b"Cookie: secret-cookie\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n"
            )
            assert b"400" in await exchange(port, request)
            assert b"200" in await exchange(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")

    asyncio.run(run())
    output = capsys.readouterr().err
    assert "secret-" not in output
    assert "Proxy exchange failed" in output


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_request_deadline_validation(timeout: float) -> None:
    with pytest.raises(ValidationError):
        ProxyConfig(request_timeout=timeout)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_utf8_mock_length(method: str) -> None:
    from openproxy.rules.models import Rule

    async def run() -> None:
        body = "Привет"
        rule = Rule(id="utf8", action="mock", response=Response(body=body))
        async with proxy(config().model_copy(update={"rules": [rule]})) as (_, port):
            response = await exchange(
                port, f"{method} / HTTP/1.1\r\nHost: x\r\n\r\n".encode()
            )
            head, payload = response.split(b"\r\n\r\n", 1)
            assert b"content-length: 12" in head.lower()
            assert b"charset=utf-8" in head
            assert payload == (body.encode() if method == "GET" else b"")

    asyncio.run(run())


def test_failed_transport_close_aborts() -> None:
    async def run() -> None:
        writer = Mock()
        writer.wait_closed = AsyncMock(side_effect=TimeoutError)
        await network.close(writer)
        writer.close.assert_called_once()
        writer.transport.abort.assert_called_once()

    asyncio.run(run())
