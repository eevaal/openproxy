"""Strict declarative rules; paths are compared in encoded HTTP form."""

import json
import re
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


def normalize_host(host: str) -> str:
    value = host.removesuffix(".").lower()
    try:
        return str(ip_address(value))
    except ValueError:
        value = value.encode("idna").decode("ascii")
        if len(value) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ValueError("invalid DNS host") from None
        return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Match(StrictModel):
    host: str | None = None
    path: str | None = None
    method: (
        Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] | None
    ) = None
    query: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid(self) -> "Match":
        if self.path is not None and not self.path.startswith("/"):
            raise ValueError("path must start with /")
        if self.host is not None:
            normalize_host(self.host)
        return self


class Response(StrictModel):
    status: int = Field(default=200, ge=200, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = None
    delay: float = Field(default=0, ge=0, le=60)

    @model_validator(mode="after")
    def valid(self) -> "Response":
        names = [key.lower() for key in self.headers]
        if len(set(names)) != len(names):
            raise ValueError("duplicate response header")
        try:
            if isinstance(self.body, str):
                self.body.encode("utf-8")
            json.dumps(self.body, allow_nan=False).encode("utf-8")
        except (ValueError, UnicodeError):
            raise ValueError("body must be valid finite UTF-8 JSON or text") from None
        for name, value in self.headers.items():
            if (
                not name
                or any(
                    c
                    not in (
                        "!#$%&'*+-.^_`|~0123456789"
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    )
                    for c in name
                )
                or any(ord(c) < 32 or ord(c) > 126 for c in value)
            ):
                raise ValueError("invalid response header")
        return self


class Rule(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    enabled: bool = True
    priority: int = 0
    match: Match = Field(default_factory=Match)
    action: Literal["mock", "forward", "block"]
    response: Response | None = None

    @model_validator(mode="after")
    def valid(self) -> "Rule":
        if self.action == "mock" and self.response is None:
            raise ValueError("mock action requires response")
        if self.action == "forward" and self.response is not None:
            raise ValueError("forward action cannot have response")
        return self
