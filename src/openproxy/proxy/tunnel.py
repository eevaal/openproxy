import asyncio

import h11

from openproxy.core.config import ProxyConfig
from openproxy.proxy.network import close, connect
from openproxy.proxy.protocol import send


async def tunnel(
    connection: h11.Connection,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    initial: bytes,
    settings: ProxyConfig,
) -> None:
    upstream_reader, upstream_writer = await connect(host, port, settings)
    try:
        await send(
            connection,
            writer,
            h11.Response(status_code=200, headers=[], reason=b"Connection Established"),
            settings.read_timeout,
        )
        if initial:
            upstream_writer.write(initial)
            await upstream_writer.drain()

        async def pump(
            source: asyncio.StreamReader, destination: asyncio.StreamWriter
        ) -> None:
            while data := await asyncio.wait_for(
                source.read(65536), settings.read_timeout
            ):
                destination.write(data)
                await asyncio.wait_for(destination.drain(), settings.read_timeout)
            if destination.can_write_eof():
                destination.write_eof()

        tasks = [
            asyncio.create_task(pump(reader, upstream_writer)),
            asyncio.create_task(pump(upstream_reader, writer)),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await close(upstream_writer)
