import asyncio
import json

import h11

from openproxy.proxy.protocol import headers, send
from openproxy.rules.models import Response


async def respond(
    connection: h11.Connection,
    writer: asyncio.StreamWriter,
    response: Response,
    method: str,
    timeout: float,
) -> None:
    await asyncio.sleep(response.delay)
    body = (
        response.body.encode()
        if isinstance(response.body, str)
        else b""
        if response.body is None
        else json.dumps(response.body, allow_nan=False).encode()
    )
    items = headers(
        [
            (k.lower().encode(), v.encode())
            for k, v in response.headers.items()
            if k.lower() != "content-length"
        ]
    )
    if not any(k == b"content-type" for k, _ in items):
        items.append(
            (
                b"content-type",
                b"text/plain; charset=utf-8"
                if isinstance(response.body, str)
                else b"application/json",
            )
        )
    if response.status in (204, 205, 304):
        body = b""
    if response.status not in (204, 304):
        items.append((b"content-length", str(len(body)).encode()))
    items.append((b"connection", b"close"))
    await send(
        connection,
        writer,
        h11.Response(status_code=response.status, headers=items),
        timeout,
    )
    if method != "HEAD" and body:
        await send(connection, writer, h11.Data(data=body), timeout)
    await send(connection, writer, h11.EndOfMessage(), timeout)
