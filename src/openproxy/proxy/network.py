"""Resolve once, validate all answers, then connect to numeric IPs only."""

import asyncio
import socket
import ssl
from ipaddress import IPv6Address, ip_address, ip_network

from openproxy.core.config import ProxyConfig


async def connect(
    host: str, port: int, settings: ProxyConfig, *, tls: ssl.SSLContext | None = None
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    async with asyncio.timeout(settings.connect_timeout):
        answers = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
        if not answers:
            raise OSError("No destination")
        for _, _, _, _, address in answers:
            ip = ip_address(address[0])
            unsafe_transition = isinstance(ip, IPv6Address) and (
                ip.is_site_local
                or ip.sixtofour is not None
                or ip.teredo is not None
                or ip in ip_network("64:ff9b::/96")
                or ip in ip_network("64:ff9b:1::/48")
            )
            effective = (
                ip.ipv4_mapped if isinstance(ip, IPv6Address) and ip.ipv4_mapped else ip
            )
            if not settings.allow_private_targets and (
                not effective.is_global or effective.is_multicast or unsafe_transition
            ):
                raise PermissionError("Destination denied")
        last: OSError | None = None
        for family, _, _, _, address in answers:
            try:
                if tls is not None:
                    return await asyncio.open_connection(
                        str(address[0]),
                        port,
                        family=family,
                        flags=socket.AI_NUMERICHOST,
                        ssl=tls,
                        server_hostname=host,
                        ssl_handshake_timeout=settings.https_inspection.handshake_timeout,
                        ssl_shutdown_timeout=1,
                    )
                return await asyncio.open_connection(
                    str(address[0]), port, family=family, flags=socket.AI_NUMERICHOST
                )
            except OSError as exc:
                last = exc
        raise OSError("Destination unavailable") from last


async def close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        async with asyncio.timeout(1):
            await writer.wait_closed()
    except (OSError, TimeoutError):
        writer.transport.abort()
        return  # Peer reset or stalled transport; close was already requested.
