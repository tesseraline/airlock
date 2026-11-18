"""Where the gateway gets the secrets its tools and model routes use.

A secret is read once, kept in memory and never handed to the agent. `SecretStore` is a Protocol, so a store for
another backend (a cloud secret manager, a file for tests) is a class with one method.
"""

from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

from tesseraline_invariants import Secret


@dataclass(frozen=True, slots=True)
class SecretValue:
    """One secret from the store. Its repr never shows the value."""

    name: str
    value: Secret[str] = field(repr=False)


class SecretStore(Protocol):
    """Gives the gateway a secret by name."""

    def get(self, name: str) -> SecretValue:
        """Return the secret called `name`; raise `KeyError` when the store has none."""
        ...


class StaticStore:
    """Secrets given in code; for tests and local experiments."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, name: str) -> SecretValue:
        """Return the secret called `name`."""
        return SecretValue(name, self._values[name])


class VaultCertStore:
    """HashiCorp Vault, KV version 2, logged in with the gateway's TLS client certificate.

    The certificate is the identity: no token is handed to the gateway. Vault answers the login with a short-lived
    token; the store logs in again when the token is close to expiry. Values are cached in memory.
    """

    def __init__(
        self,
        url: str,
        context: ssl.SSLContext,
        *,
        mount: str = "secret",
        prefix: str = "airlock",
        role: str = "airlock-gateway",
        timeout: float = 5.0,
        cache_seconds: float = 300.0,
    ) -> None:
        self._url = url.rstrip("/")
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
        )
        self._mount, self._prefix, self._role, self._timeout = mount, prefix, role, timeout
        self._token = ""
        self._token_until = 0.0
        self._cache: dict[str, tuple[float, SecretValue]] = {}
        self._ttl = cache_seconds  # a rotated secret is read again after this
        self._lock = threading.Lock()

    def _call(self, token: str, path: str, body: bytes | None = None) -> dict[str, object]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(  # noqa: S310 - the URL is the configured https Vault address
            f"{self._url}{path}",
            data=body,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            data: dict[str, object] = json.loads(response.read())
            return data

    def _login(self) -> None:
        auth = self._call("", "/v1/auth/cert/login", json.dumps({"name": self._role}).encode())["auth"]
        assert isinstance(auth, dict)  # noqa: S101 - Vault's documented answer
        self._token = str(auth["client_token"])
        self._token_until = time.monotonic() + max(30.0, float(auth.get("lease_duration", 300)) * 0.8)

    def get(self, name: str) -> SecretValue:
        """Return the secret called `name` (field `value` of `<mount>/data/<prefix>/<name>`)."""
        cached = self._cache.get(name)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1]
        with self._lock:  # one login at a time; readers never see a half-replaced token
            if not self._token or time.monotonic() > self._token_until:
                self._login()
            token = self._token
        data = self._call(token, f"/v1/{self._mount}/data/{self._prefix}/{name}")["data"]
        assert isinstance(data, dict)  # noqa: S101
        fields = data["data"]
        if not isinstance(fields, dict) or "value" not in fields:
            raise KeyError(name)
        value = str(fields["value"])
        if any(c in value for c in "\r\n\0"):
            raise ValueError(f"secret {name} contains a line break")  # it would break the header it goes into
        secret = SecretValue(name, value)
        self._cache[name] = (time.monotonic() + self._ttl, secret)
        return secret
