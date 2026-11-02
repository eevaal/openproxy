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
        if key.lower() == b"connection":
            excluded.update(token.strip().lower() for token in value.split(b","))
    return [(k, v) for k, v in items if k.lower() not in excluded]


async def event(
    connection: h11.Connection, reader: asyncio.StreamReader, timeout: float
) -> Any:
    while True:
        item = connection.next_event()
        if item is not h11.NEED_DATA:
            return item
        data = await asyncio.wait_for(reader.read(65536), timeout)
        connection.receive_data(data)


async def send(
    connection: h11.Connection, writer: asyncio.StreamWriter, item: Any, timeout: float
) -> None:
    data = connection.send(item)
    if data:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout)
