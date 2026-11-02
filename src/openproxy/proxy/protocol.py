"""Bounded h11 event I/O and hop-by-hop header filtering."""

import asyncio
from typing import Any

import h11

HOP = {
    b"connection",
    b"proxy-connection",
    b"keep-alive",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
    b"proxy-authorization",
    b"proxy-authenticate",
}


def headers(items: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    excluded = HOP.copy()
    for key, value in items:
        if key.lower() in (b"connection", b"proxy-connection"):
            excluded.update(token.strip().lower() for token in value.split(b","))
    return [(k, v) for k, v in items if k.lower() not in excluded]


async def event(
    connection: h11.Connection, reader: asyncio.StreamReader, timeout: float
) -> Any:
    # One deadline for the whole event, not a fresh timeout for each TCP byte.
    async with asyncio.timeout(timeout):
        while True:
            item = connection.next_event()
            if item is not h11.NEED_DATA:
                if isinstance(
                    item, (h11.Request, h11.Response, h11.InformationalResponse)
                ):
                    size = sum(len(k) + len(v) + 4 for k, v in item.headers)
                    if isinstance(item, h11.Request):
                        size += len(item.target)
                    if len(item.headers) > 100 or size > 16384:
                        raise h11.RemoteProtocolError("Header limits exceeded")
                return item
            data = await reader.read(16384)
            connection.receive_data(data)


async def send(
    connection: h11.Connection, writer: asyncio.StreamWriter, item: Any, timeout: float
) -> None:
    data = connection.send(item)
    if data:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout)
