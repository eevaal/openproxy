"""Validate authority before URL splitting can discard or reinterpret characters."""

from ipaddress import IPv6Address
from urllib.parse import SplitResult, urlsplit

from openproxy.rules.models import normalize_host


def authority(value: str, *, explicit_port: bool = False) -> tuple[str, int]:
    if (
        not value
        or any(c in value for c in "/?#@\\%")
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
    ):
        raise ValueError("Invalid authority")
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("Invalid IPv6 authority")
        IPv6Address(value[1:end])
        suffix = value[end + 1 :]
    else:
        _, separator, port_part = value.partition(":")
        suffix = separator + port_part
    if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
        raise ValueError("Invalid authority port")
    parsed = urlsplit("//" + value)
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Invalid authority")
    host = normalize_host(parsed.hostname)
    if explicit_port and parsed.port is None:
        raise ValueError("Explicit port required")
    if value.endswith(":"):
        raise ValueError("Empty port")
    port = parsed.port if parsed.port is not None else 80
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return host, port


def http_target(raw: bytes, host_header: bytes) -> tuple[SplitResult, str, int]:
    text = raw.decode("ascii")
    if any(ord(c) <= 32 or ord(c) == 127 for c in text) or "\\" in text or "#" in text:
        raise ValueError("Invalid request target")
    authority(host_header.decode("ascii"))
    if text.startswith("/"):
        # Parse origin-form as a path, even when it begins with //.
        path, separator, query = text.partition("?")
        target = SplitResult(
            "http", host_header.decode("ascii"), path, query if separator else "", ""
        )
    else:
        target = urlsplit(text)
        if target.scheme != "http" or not target.netloc:
            raise ValueError("Only HTTP absolute targets")
    host, port = authority(target.netloc)
    return target, host, port
