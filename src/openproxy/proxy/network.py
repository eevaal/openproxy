"""Resolve once, validate all answers, then connect to numeric IPs only."""

import asyncio
import socket
from ipaddress import ip_address

from openproxy.core.config import ProxyConfig


async def connect(
    host: str, port: int, settings: ProxyConfig
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    async with asyncio.timeout(settings.connect_timeout):
        answers = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
        if not answers:
            raise OSError("No destination")
        for _, _, _, _, address in answers:
            ip = ip_address(address[0])
            if not settings.allow_private_targets and (
                not ip.is_global or ip.is_multicast
            ):
                raise PermissionError("Destination denied")
        last: OSError | None = None
        for family, _, _, _, address in answers:
            try:
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
        return  # Peer reset or stalled transport; close was already requested.
