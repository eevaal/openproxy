"""Non-destructive local bind checks. No listen, reuse options or settings changes."""

import socket
from dataclasses import dataclass
from typing import Literal

from openproxy.core.config import ServerConfig


@dataclass(frozen=True)
class Check:
    status: Literal["PASS", "WARN", "FAIL"]
    message: str


def check_address(server: ServerConfig) -> Check:
    try:
        addresses = socket.getaddrinfo(
            server.host,
            server.port,
            type=socket.SOCK_STREAM,
        )
    except OSError:
        return Check("FAIL", "Server address cannot be resolved locally")
    if not addresses:
        return Check("FAIL", "Server address has no usable addresses")
    return Check("PASS", "Server address is valid")


def check_port(server: ServerConfig) -> Check:
    try:
        addresses = socket.getaddrinfo(
            server.host,
            server.port,
            type=socket.SOCK_STREAM,
        )
        for family, kind, protocol, _, address in addresses:
            with socket.socket(family, kind, protocol) as probe:
                probe.bind(address)
    except OSError:
        return Check("FAIL", "Cannot bind server port: occupied, unavailable or denied")
    return Check("PASS", "Server port can be bound")
