import asyncio
import ssl

import h11

from openproxy.core.config import ProxyConfig
from openproxy.proxy.network import close, connect
from openproxy.proxy.protocol import event, headers, send


async def forward(
    request: h11.Request,
    incoming: h11.Connection,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    target: str,
    settings: ProxyConfig,
    *,
    tls: ssl.SSLContext | None = None,
) -> None:
    upstream_reader, upstream_writer = await connect(host, port, settings, tls=tls)
    outgoing = h11.Connection(h11.CLIENT)
    try:
        items = headers(list(request.headers))
        items = [(k, v) for k, v in items if k != b"host"]
        if any(k == b"transfer-encoding" for k, _ in request.headers):
            items.append((b"transfer-encoding", b"chunked"))
        authority = f"[{host}]" if ":" in host else host
        items += [(b"host", f"{authority}:{port}".encode()), (b"connection", b"close")]
        await send(
            outgoing,
            upstream_writer,
            h11.Request(
                method=request.method, target=target.encode("ascii"), headers=items
            ),
            settings.read_timeout,
        )

        async def upload() -> None:
            while True:
                item = await event(incoming, reader, settings.read_timeout)
                if isinstance(item, h11.Data):
                    await send(outgoing, upstream_writer, item, settings.read_timeout)
                elif isinstance(item, h11.EndOfMessage):
                    await send(
                        outgoing,
                        upstream_writer,
                        h11.EndOfMessage(),
                        settings.read_timeout,
                    )
                    return
                else:
                    raise h11.RemoteProtocolError("Incomplete request")

        async def download() -> None:
            while True:
                item = await event(outgoing, upstream_reader, settings.read_timeout)
                if isinstance(item, h11.InformationalResponse):
                    if item.status_code == 101:
                        raise h11.RemoteProtocolError("Upgrade unsupported")
                    continue
                if isinstance(item, h11.Response):
                    items = headers(list(item.headers)) + [(b"connection", b"close")]
                    await send(
                        incoming,
                        writer,
                        h11.Response(status_code=item.status_code, headers=items),
                        settings.read_timeout,
                    )
                elif isinstance(item, (h11.Data, h11.EndOfMessage)):
                    await send(incoming, writer, item, settings.read_timeout)
                    if isinstance(item, h11.EndOfMessage):
                        return
                else:
                    raise h11.RemoteProtocolError("Incomplete upstream response")

        tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if tasks[1].done():
                try:
                    tasks[1].result()
                except h11.RemoteProtocolError:
                    raise OSError("Invalid upstream response") from None
            else:
                tasks[0].result()
                try:
                    await tasks[1]
                except h11.RemoteProtocolError:
                    raise OSError("Invalid upstream response") from None
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await close(upstream_writer)
