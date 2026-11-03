"""Local TLS integration tests with explicit, ephemeral trust roots."""

import asyncio
import socket
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import h11
import httpx
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from openproxy.cli import app
from openproxy.core.config import ConfigError, HTTPSInspectionConfig, load_config
from openproxy.main import create_app
from openproxy.proxy.inspection import InspectionError, build_contexts
from openproxy.proxy.network import close
from openproxy.proxy.protocol import event, send
from openproxy.proxy.server import ProxyServer
from openproxy.rules.models import Response, Rule
from tests.test_proxy import config, exchange, proxy

HOST = "api.example.test"


def certificate(folder: Path, name: str, *, expired: bool = False) -> tuple[Path, Path]:
    folder.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = folder / "cert.pem", folder / "cert.key"
    cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.touch(mode=0o600)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@pytest.fixture
def inspection(tmp_path: Path) -> HTTPSInspectionConfig:
    cert, key = certificate(tmp_path / "inspection", HOST)
    return HTTPSInspectionConfig(
        enabled=True,
        hosts=[HOST],
        certificate_file=str(cert),
        private_key_file=str(key),
    )


def client_context(inspection: HTTPSInspectionConfig) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=inspection.certificate_file)


def rule(action: str = "mock", status: int = 200, priority: int = 10) -> Rule:
    return Rule.model_validate(
        {
            "id": f"{action}-{priority}",
            "priority": priority,
            "match": {"host": HOST, "path": "/check", "query": {"mode": "test"}},
            "action": action,
            "response": None
            if action == "forward"
            else {"status": status, "body": {"success": status == 200}},
        }
    )


@asynccontextmanager
async def tls_client(
    port: int,
    settings: HTTPSInspectionConfig,
    *,
    sni: str = HOST,
    connect_port: int = 443,
    trust: bool = True,
    version: ssl.TLSVersion | None = None,
) -> AsyncIterator[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        authority = f"{HOST}:{connect_port}"
        writer.write(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        )
        assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200 ")
        context = client_context(settings) if trust else ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        if version is not None:
            context.minimum_version = context.maximum_version = version
        await writer.start_tls(context, server_hostname=sni, ssl_handshake_timeout=2)
        yield reader, writer
    finally:
        await close(writer)


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
)
def test_https_mock_without_dns_or_upstream(
    method: str,
    inspection: HTTPSInspectionConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        settings = config(https_inspection=inspection).model_copy(
            update={"rules": [rule("block", 403, 0), rule()]}
        )
        async with proxy(settings) as (server, port):
            dns = AsyncMock(side_effect=AssertionError("Unexpected DNS lookup"))
            upstream = AsyncMock(side_effect=AssertionError("Unexpected upstream"))
            monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", dns)
            monkeypatch.setattr("openproxy.proxy.forward.connect", upstream)
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}",
                verify=client_context(inspection),
                trust_env=False,
            ) as client:
                responses = await asyncio.gather(
                    *(
                        client.request(
                            method, f"https://{HOST}/check?mode=test", content=b"data"
                        )
                        for _ in range(4)
                    )
                )
                assert all(r.status_code == 200 for r in responses)
                if method == "HEAD":
                    assert all(
                        not r.content and int(r.headers["content-length"]) > 0
                        for r in responses
                    )
                else:
                    assert all(r.json() == {"success": True} for r in responses)
                assert all(
                    r.headers["content-type"] == "application/json" for r in responses
                )
            assert server.stats.https_inspection_connections == 4
            assert server.stats.https_mock_responses == 4
            dns.assert_not_awaited()
            upstream.assert_not_awaited()

    asyncio.run(run())


@pytest.mark.parametrize(
    "rules,expected",
    [([rule("block", 403)], 403), ([rule(status=403)], 403), ([], 403)],
)
def test_https_block_and_mock_403(
    inspection: HTTPSInspectionConfig,
    rules: list[Rule],
    expected: int,
) -> None:
    async def run() -> None:
        async with proxy(
            config(https_inspection=inspection).model_copy(update={"rules": rules})
        ) as (_, port):
            async with tls_client(port, inspection) as (reader, writer):
                writer.write(
                    f"GET /check?mode=test HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
                )
                response = await reader.read()
                assert response.startswith(f"HTTP/1.1 {expected} ".encode())
                if rules:
                    assert b'{"success": false}' in response

    asyncio.run(run())


@pytest.mark.parametrize(
    "kind", ["trusted", "wrong-name", "untrusted", "private-denied"]
)
def test_https_forwarding(
    kind: str,
    inspection: HTTPSInspectionConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "wrong.example.test" if kind == "wrong-name" else HOST
    cert, key = certificate(tmp_path / "upstream", name)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(cert, key)
    sni: list[str | None] = []

    def capture_sni(
        connection: ssl.SSLSocket | ssl.SSLObject,
        name: str | None,
        context: ssl.SSLContext,
    ) -> None:
        sni.append(name)

    server_tls.sni_callback = capture_sni
    if kind != "untrusted":
        inspection = inspection.model_copy(update={"upstream_ca_file": str(cert)})

    async def run() -> None:
        upstream_requests: list[bytes] = []

        async def origin(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            conn = h11.Connection(h11.SERVER)
            try:
                request = await event(conn, reader, 2)
                assert isinstance(request, h11.Request)
                upstream_requests.append(request.target)
                count = 0
                while isinstance(part := await event(conn, reader, 2), h11.Data):
                    count += len(part.data)
                assert count == 256 * 1024
                await send(conn, writer, h11.Response(status_code=200, headers=[]), 2)
                for _ in range(16):
                    await send(conn, writer, h11.Data(data=b"x" * 16384), 2)
                await send(conn, writer, h11.EndOfMessage(), 2)
            finally:
                await close(writer)

        upstream = await asyncio.start_server(origin, "127.0.0.1", 0, ssl=server_tls)
        upstream_port = upstream.sockets[0].getsockname()[1]
        settings = config(
            https_inspection=inspection,
            allowed_connect_ports=[upstream_port],
            allow_private_targets=kind != "private-denied",
        ).model_copy(update={"rules": [rule("forward")]})
        async with upstream, proxy(settings) as (server, port):
            dns = AsyncMock(
                return_value=[
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("127.0.0.1", upstream_port),
                    )
                ]
            )
            monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", dns)

            async def body() -> AsyncIterator[bytes]:
                for _ in range(16):
                    yield b"a" * 16384

            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}",
                verify=client_context(inspection),
                trust_env=False,
            ) as client:
                response = await client.post(
                    f"https://{HOST}:{upstream_port}/check?mode=test", content=body()
                )
            dns.assert_awaited_once_with(HOST, upstream_port, type=socket.SOCK_STREAM)
            if kind == "trusted":
                assert response.status_code == 200
                assert response.content == b"x" * (256 * 1024)
                assert upstream_requests == [b"/check?mode=test"]
                assert sni == [HOST]
                assert server.stats.https_forwarding_errors == 0
            else:
                assert response.status_code == (
                    403 if kind == "private-denied" else 502
                )
                assert upstream_requests == []
                assert server.stats.https_forwarding_errors == 1
                assert sni == ([] if kind == "private-denied" else [HOST])

    asyncio.run(run())


@pytest.mark.parametrize(
    "sni,trust", [(HOST, False), ("wrong.example.test", True), ("127.0.0.1", True)]
)
def test_tls_handshake_rejects_bad_sni_or_trust(
    inspection: HTTPSInspectionConfig,
    sni: str,
    trust: bool,
) -> None:
    async def run() -> None:
        async with proxy(config(https_inspection=inspection)) as (server, port):
            with pytest.raises((ssl.SSLError, ConnectionResetError)):
                async with tls_client(port, inspection, sni=sni, trust=trust):
                    pytest.fail("TLS handshake accepted")
            await asyncio.wait_for(asyncio.gather(*list(server.tasks)), 2)
            assert server.stats.tls_handshake_failures == 1
            assert server.stats.https_inspection_connections == 0

    asyncio.run(run())


@pytest.mark.parametrize(
    "request_line,header,code",
    [
        ("GET /check?mode=test HTTP/1.1", "wrong.example.test", 403),
        ("GET https://wrong.example.test/check HTTP/1.1", HOST, 403),
        ("GET /check HTTP/1.1", f"{HOST}:444", 403),
        ("CONNECT api.example.test:443 HTTP/1.1", HOST, 400),
        ("INVALID", HOST, 400),
    ],
)
def test_malformed_or_misdirected_http_inside_tls(
    inspection: HTTPSInspectionConfig,
    request_line: str,
    header: str,
    code: int,
) -> None:
    async def run() -> None:
        async with proxy(config(https_inspection=inspection)) as (_, port):
            async with tls_client(port, inspection) as (reader, writer):
                tls = writer.get_extra_info("ssl_object")
                assert tls.selected_alpn_protocol() == "http/1.1"
                writer.write(f"{request_line}\r\nHost: {header}\r\n\r\n".encode())
                assert (await reader.read()).startswith(f"HTTP/1.1 {code} ".encode())

    asyncio.run(run())


def test_tls_timeout_and_connection_limit(inspection: HTTPSInspectionConfig) -> None:
    async def run() -> None:
        configured = inspection.model_copy(update={"handshake_timeout": 0.3})
        async with proxy(config(https_inspection=configured, max_connections=1)) as (
            server,
            port,
        ):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(
                    f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
                )
                assert b"200" in await reader.readuntil(b"\r\n\r\n")
                assert b"503" in await exchange(
                    port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                )
                assert await asyncio.wait_for(reader.read(), 2) == b""
                await asyncio.wait_for(asyncio.gather(*list(server.tasks)), 2)
                assert server.stats.tls_handshake_failures == 1
                assert server.stats.active_connections == 0
            finally:
                await close(writer)

    asyncio.run(run())


def test_shutdown_cancels_handshake(inspection: HTTPSInspectionConfig) -> None:
    async def run() -> None:
        async with proxy(
            config(https_inspection=inspection, shutdown_timeout=0.05)
        ) as (_, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
            )
            assert b"200" in await reader.readuntil(b"\r\n\r\n")
        try:
            assert await asyncio.wait_for(reader.read(), 2) == b""
        finally:
            await close(writer)

    asyncio.run(run())


@pytest.mark.parametrize(
    "target,code",
    [(f"{HOST}:444", 403), (f"{HOST}:443#x", 400), ("outside.example.test:443", 403)],
)
def test_connect_policy(
    inspection: HTTPSInspectionConfig, target: str, code: int
) -> None:
    async def run() -> None:
        async with proxy(config(https_inspection=inspection)) as (_, port):
            response = await exchange(
                port, f"CONNECT {target} HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
            )
            assert response.startswith(f"HTTP/1.1 {code} ".encode())

    asyncio.run(run())


def test_legacy_tunnel_with_inspection_enabled(
    inspection: HTTPSInspectionConfig,
) -> None:
    async def run() -> None:
        async def echo(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await reader.readexactly(4)
            writer.write(data)
            await close(writer)

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        up = upstream.sockets[0].getsockname()[1]
        async with (
            upstream,
            proxy(
                config(
                    https_inspection=inspection,
                    allow_private_targets=True,
                    unmatched_action="forward",
                    allowed_connect_ports=[up],
                )
            ) as (server, port),
        ):
            assert (
                await exchange(
                    port,
                    (
                        f"CONNECT 127.0.0.1:{up} HTTP/1.1\r\n"
                        "Host: localhost\r\n\r\nping"
                    ).encode(),
                )
            ).endswith(b"ping")
            assert server.stats.https_inspection_connections == 0

    asyncio.run(run())


@pytest.mark.parametrize(
    "problem", ["expired", "wrong-san", "key-permissions", "missing", "wrong-key"]
)
def test_certificate_validation(
    problem: str,
    tmp_path: Path,
    inspection: HTTPSInspectionConfig,
) -> None:
    cert, key = certificate(
        tmp_path / "other",
        "other.example.test" if problem == "wrong-san" else HOST,
        expired=problem == "expired",
    )
    if problem == "key-permissions":
        key.chmod(0o644)
    if problem == "missing":
        cert.unlink()
    if problem == "wrong-key":
        key = Path(inspection.private_key_file or "")
    with pytest.raises(InspectionError) as error:
        build_contexts(
            inspection.model_copy(
                update={"certificate_file": str(cert), "private_key_file": str(key)}
            )
        )
    assert str(tmp_path) not in str(error.value)


@pytest.mark.parametrize(
    "hosts", [["*.example.test"], ["127.0.0.1"], [HOST, HOST.upper()], ["https://x"]]
)
def test_invalid_allowlist(hosts: list[str]) -> None:
    with pytest.raises(ValidationError):
        HTTPSInspectionConfig(hosts=hosts)


def test_config_doctor_and_api_privacy(
    tmp_path: Path,
    inspection: HTTPSInspectionConfig,
) -> None:
    path = tmp_path / "proxy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "proxy": {
                    "enabled": True,
                    "https_inspection": {
                        "enabled": True,
                        "hosts": [HOST],
                        "certificate_file": "inspection/cert.pem",
                        "private_key_file": "inspection/cert.key",
                    },
                },
            }
        )
    )
    loaded = load_config(path)
    assert loaded.proxy.https_inspection == inspection
    with TestClient(create_app(config(https_inspection=inspection))) as api:
        assert "private_key" not in api.get("/api/v1/config").text
        assert api.get("/api/v1/proxy/stats").json()["tls_handshake_failures"] == 0
    Path(inspection.private_key_file or "").unlink()
    with pytest.raises(ConfigError, match="Invalid HTTPS inspection"):
        load_config(path)
    result = CliRunner().invoke(app, ["doctor", "--config", str(path)])
    assert result.exit_code == 2
    assert "Invalid HTTPS inspection" in result.output
    assert "cert.key" not in result.output


def test_inspection_disabled_by_default() -> None:
    assert not config().proxy.https_inspection.enabled


def test_query_miss(inspection: HTTPSInspectionConfig) -> None:
    async def run() -> None:
        settings = config(https_inspection=inspection).model_copy(
            update={"rules": [rule()]}
        )
        async with proxy(settings) as (server, port):
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}",
                verify=client_context(inspection),
                trust_env=False,
            ) as client:
                response = await client.get(f"https://{HOST}/check?mode=other")
            assert response.status_code == 403
            assert server.stats.https_mock_responses == 0

    asyncio.run(run())


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_tls_mock_no_body(method: str, inspection: HTTPSInspectionConfig) -> None:
    async def run() -> None:
        no_body = Rule(
            id="empty", action="mock", response=Response(status=204, body="ignored")
        )
        settings = config(https_inspection=inspection).model_copy(
            update={"rules": [no_body]}
        )
        async with proxy(settings) as (_, port):
            async with tls_client(port, inspection) as (reader, writer):
                writer.write(f"{method} / HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())
                head, body = (await reader.read()).split(b"\r\n\r\n", 1)
                assert head.startswith(b"HTTP/1.1 204 ")
                assert b"content-length" not in head.lower()
                assert body == b""

    asyncio.run(run())


def test_tls_client_disconnect_releases_slot(inspection: HTTPSInspectionConfig) -> None:
    async def run() -> None:
        async with proxy(config(https_inspection=inspection, max_connections=1)) as (
            server,
            port,
        ):
            async with tls_client(port, inspection) as (_, writer):
                writer.write(
                    (
                        f"POST / HTTP/1.1\r\nHost: {HOST}\r\n"
                        "Content-Length: 10\r\n\r\nx"
                    ).encode()
                )
                await writer.drain()
                writer.transport.abort()
            await asyncio.wait_for(asyncio.gather(*list(server.tasks)), 2)
            assert server.stats.active_connections == 0
            assert server.stats.https_inspection_connections == 1

    asyncio.run(run())


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_inspection_log_privacy(
    inspection: HTTPSInspectionConfig,
    log_format: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from openproxy.core.config import LoggingConfig
    from openproxy.core.logging import configure_logging

    configure_logging(
        LoggingConfig.model_validate({"format": log_format, "level": "DEBUG"})
    )

    async def run() -> None:
        mock = Rule(id="safe-id", action="mock", response=Response(body="private-body"))
        async with proxy(
            config(https_inspection=inspection).model_copy(update={"rules": [mock]})
        ) as (_, port):
            async with tls_client(port, inspection) as (reader, writer):
                writer.write(
                    f"GET /?token=private-query HTTP/1.1\r\nHost: {HOST}\r\n".encode()
                    + b"Authorization: Bearer private-token\r\n"
                    b"Cookie: private-cookie\r\n\r\n"
                )
                assert b"private-body" in await reader.read()

    asyncio.run(run())
    output = capsys.readouterr().err
    assert "safe-id" in output
    assert "private-" not in output
    assert inspection.private_key_file is not None
    assert inspection.private_key_file not in output


def test_inspection_requires_loopback(inspection: HTTPSInspectionConfig) -> None:
    with pytest.raises(ValidationError, match="loopback"):
        config(https_inspection=inspection, host="0.0.0.0", allow_external_bind=True)


def test_tls_key_logging_stays_disabled(
    inspection: HTTPSInspectionConfig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log = tmp_path / "sslkeys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(log))
    contexts, upstream = build_contexts(inspection)
    assert upstream.keylog_filename is None
    assert contexts[HOST].keylog_filename is None
    assert not log.exists()


def test_tls_upgrade_rejects_buffered_plaintext(
    inspection: HTTPSInspectionConfig,
) -> None:
    async def run() -> None:
        server = ProxyServer(config(https_inspection=inspection))
        contexts, _ = build_contexts(inspection)
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(
            f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
        )
        assert isinstance(conn.next_event(), h11.Request)
        # These bytes are still in asyncio's reader, outside h11.trailing_data.
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
        writer = Mock(spec=asyncio.StreamWriter)
        writer.transport = Mock()
        with pytest.raises(ValueError, match="Unexpected data"):
            await server.upgrade(conn, reader, writer, contexts[HOST])
        writer.write.assert_not_called()
        writer.start_tls.assert_not_awaited()

    asyncio.run(run())


def test_conflicting_framing_inside_tls(inspection: HTTPSInspectionConfig) -> None:
    async def run() -> None:
        async with proxy(config(https_inspection=inspection)) as (_, port):
            async with tls_client(port, inspection) as (reader, writer):
                writer.write(
                    f"POST / HTTP/1.1\r\nHost: {HOST}\r\n".encode()
                    + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                assert (await reader.read()).startswith(b"HTTP/1.1 400 ")

    asyncio.run(run())


@pytest.mark.parametrize(
    ("version", "negotiated"),
    [(ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1_3, "TLSv1.3")],
)
def test_supported_tls_versions(
    inspection: HTTPSInspectionConfig,
    version: ssl.TLSVersion,
    negotiated: str,
) -> None:
    async def run() -> None:
        mock = Rule(id="tls-version", action="mock", response=Response(body="ok"))
        settings = config(https_inspection=inspection).model_copy(
            update={"rules": [mock]}
        )
        async with proxy(settings) as (_, port):
            async with tls_client(port, inspection, version=version) as (
                reader,
                writer,
            ):
                assert writer.get_extra_info("ssl_object").version() == negotiated
                writer.write(f"GET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())
                assert (await reader.read()).endswith(b"\r\n\r\nok")

    asyncio.run(run())
