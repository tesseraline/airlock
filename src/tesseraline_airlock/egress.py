"""The second door: every outbound request goes through the egress proxy.

The gateway connects to the proxy with mutual TLS and names the destination in the Host header; the proxy asks its
own policy about the destination and opens a verified TLS connection to it. The gateway never connects to the
internet by itself.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Resolver = Callable[..., list[Any]]  # socket.getaddrinfo, or a stand-in for tests


class EgressRefusedError(ValueError):
    """The URL is not one the gateway sends out (wrong scheme, user info, an address instead of a name)."""


@dataclass(frozen=True, slots=True)
class Target:
    """A normalised outbound URL: https only, a lower-case host name, an explicit port."""

    host: str
    port: int
    path: str

    @property
    def authority(self) -> str:
        """`host` or `host:port`, as sent in the Host header."""
        return self.host if self.port == 443 else f"{self.host}:{self.port}"  # noqa: PLR2004

    @property
    def url(self) -> str:
        """The normalised URL."""
        return f"https://{self.authority}{self.path}"


def normalise(url: str) -> Target:
    """Parse a URL once, so the policy and the request see the same host and path.

    Refuses anything that is not plain `https://name[:port]/path`.

    Examples:
        >>> normalise("HTTPS://Example.COM/a?b=1").url
        'https://example.com/a?b=1'
        >>> normalise("https://good.example@evil.example/")
        Traceback (most recent call last):
        ...
        tesseraline_airlock.egress.EgressRefusedError: user info in URL
    """
    if any(c in url for c in "\\\r\n\t ") or not url.isascii():
        raise EgressRefusedError("characters not allowed in URL")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "https":
        raise EgressRefusedError("only https URLs")
    if "@" in parts.netloc:
        raise EgressRefusedError("user info in URL")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or not all(label and len(label) <= 63 for label in host.split(".")):  # noqa: PLR2004
        raise EgressRefusedError("no host name")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise EgressRefusedError("an address instead of a host name")
    port = parts.port or 443
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return Target(host, port, path)


@dataclass(frozen=True, slots=True)
class Reply:
    """An answer from the destination, cut to the limit."""

    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool


def private_address(host: str, port: int, resolve: Resolver = socket.getaddrinfo) -> str:
    """The first address of `host` that is not public, or "" when every address is public.

    Not public: private, loopback, link-local (such as cloud metadata), multicast, reserved. A name that does not
    resolve here counts as public: the egress proxy resolves it and refuses what it cannot reach.
    """
    try:
        infos = resolve(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return ""
    for info in infos:
        address = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if not address.is_global:
            return str(address)
    return ""


class Egress:
    """Sends requests through the egress proxy (or, for tests, straight to the destination).

    Before a request leaves, the destination's name is resolved and refused when it points at a private address,
    unless the host is listed in `private_hosts` (services you run yourself). This catches an allowed name that
    points inside, such as a cloud metadata address. The proxy resolves the name again, so a name that changes
    its address between the two lookups is not caught here (see the threat model, T9).
    """

    def __init__(
        self,
        proxy: str | None,
        context: ssl.SSLContext,
        *,
        timeout: float = 20.0,
        private_hosts: frozenset[str] = frozenset(),
        resolve: Resolver = socket.getaddrinfo,
    ) -> None:
        self._proxy = urllib.parse.urlsplit(proxy) if proxy else None
        self._context = context
        self._timeout = timeout
        self._private_hosts = private_hosts
        self._resolve = resolve

    def open(
        self, method: str, target: Target, headers: dict[str, str], body: bytes | None = None
    ) -> tuple[http.client.HTTPSConnection, http.client.HTTPResponse]:
        """Start a request and return the open connection and response; the caller reads and closes them."""
        if target.host not in self._private_hosts and target.authority not in self._private_hosts:
            inside = private_address(target.host, target.port, self._resolve)
            if inside:
                raise EgressRefusedError(f"{target.host} resolves to a non-public address")
        if self._proxy is not None:
            connection = http.client.HTTPSConnection(
                self._proxy.hostname or "", self._proxy.port or 443, context=self._context, timeout=self._timeout
            )
        else:
            connection = http.client.HTTPSConnection(
                target.host, target.port, context=self._context, timeout=self._timeout
            )
        connection.putrequest(method, target.path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", target.authority)
        for name, value in headers.items():
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        return connection, connection.getresponse()

    def fetch(
        self, method: str, target: Target, headers: dict[str, str], body: bytes | None = None, limit: int = 64_000
    ) -> Reply:
        """Make a request and read at most `limit` bytes of the answer."""
        connection, response = self.open(method, target, headers, body)
        try:
            data = response.read(limit + 1)
            return Reply(
                response.status, {k.lower(): v for k, v in response.getheaders()}, data[:limit], len(data) > limit
            )
        finally:
            connection.close()
