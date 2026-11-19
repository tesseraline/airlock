"""`airlock mcp-bridge`: an MCP server on stdio that forwards to the gateway's `/mcp` over mutual TLS.

An MCP client starts the bridge as a local process and talks to it on stdin and stdout, one JSON-RPC message per
line. The bridge serves both client eras:

- modern clients (revision 2026-07-28) send the version in each request's `_meta`; the bridge forwards as is;
- legacy clients (2025-11-25 and earlier) open with `initialize`; the bridge answers it from the gateway's
  `server/discover`, then adds the modern `_meta` to each request and removes modern-only result fields.

The bridge opens no network port. Where its client certificate comes from is the integrator's choice: anything that
implements `Credentials`. The default reads files and loads them again when the certificate file changes.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import sys
import urllib.parse
import uuid
from pathlib import Path
from typing import IO, Protocol

from tesseraline_airlock.mcp import CLIENT_INFO_KEY, VERSION, VERSION_KEY
from tesseraline_airlock.tls import client_context

LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
MODERN_ONLY = ("resultType", "ttlMs", "cacheScope")
MAX_LINE = 64_000  # the gateway's limit for one /mcp request


class Credentials(Protocol):
    """Gives the bridge the TLS context for its connection to the gateway."""

    def context(self) -> ssl.SSLContext:
        """A client context that presents the agent's certificate and trusts the gateway's CA."""
        ...


class FileCredentials:
    """Certificate, key and CA from files; loaded again when the certificate file changes (for rotation)."""

    def __init__(self, cert: str, key: str, ca: str) -> None:
        self._cert, self._key, self._ca = cert, key, ca
        self._stamp = -1.0
        self._context: ssl.SSLContext | None = None

    def context(self) -> ssl.SSLContext:
        """The current context, rebuilt when the certificate file is newer than the one loaded."""
        stamp = Path(self._cert).stat().st_mtime
        if self._context is None or stamp != self._stamp:
            self._context, self._stamp = client_context(self._cert, self._key, self._ca), stamp
        return self._context


def _error(rid: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


class Bridge:
    """Translates between one MCP client on stdio and the gateway."""

    def __init__(self, gateway: str, credentials: Credentials, *, timeout: float = 120.0, model: str = "") -> None:
        url = urllib.parse.urlsplit(gateway)
        if url.scheme != "https" or not url.hostname:
            raise ValueError("the gateway address must be https://host[:port]")
        self._host, self._port, self._timeout = url.hostname, url.port or 443, timeout
        self._credentials = credentials
        self._session = f"mcp-{uuid.uuid4().hex[:12]}"  # groups this client's calls in the observability log
        self._legacy = False
        self._model = model[:80]  # the model the operator says the client uses; logged as reported, not measured
        self._client_info: dict[str, object] = {"name": "mcp-client", "version": "unknown"}

    def _post(self, message: dict[str, object]) -> dict[str, object] | None:
        body = json.dumps(message).encode()
        connection = http.client.HTTPSConnection(
            self._host, self._port, context=self._credentials.context(), timeout=self._timeout
        )
        try:
            connection.request(
                "POST",
                "/mcp",
                body,
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": VERSION,
                    "X-Airlock-Session": self._session,
                    **({"X-Airlock-Model": self._model} if self._model else {}),
                },
            )
            response = connection.getresponse()
            data = response.read(1_000_000)
        finally:
            connection.close()
        if response.status == 202 or not data:  # noqa: PLR2004 - a notification
            return None
        try:
            answer = json.loads(data)
        except (ValueError, RecursionError):
            answer = None
        rid = message.get("id")
        # only a JSON-RPC answer reaches the client; a 403, 413 or 404 body becomes an error that carries the id
        if (
            not isinstance(answer, dict)
            or answer.get("jsonrpc") != "2.0"
            or ("result" not in answer and "error" not in answer)
        ):
            return _error(rid, -32603, f"gateway answered HTTP {response.status}")
        answer["id"] = rid
        return answer

    def _modern_meta(self) -> dict[str, object]:
        return {
            VERSION_KEY: VERSION,
            CLIENT_INFO_KEY: self._client_info,
            "io.modelcontextprotocol/clientCapabilities": {},
        }

    def handle(self, message: object) -> dict[str, object] | None:  # noqa: PLR0911 - one answer per case, read top down
        """Answer one message from the client; None for a notification."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "not a JSON-RPC 2.0 message (batches are not accepted)")
        rid, method = message.get("id"), message.get("method")
        if "id" not in message:  # notifications (initialized, cancelled, ...) need no gateway call
            return None
        if isinstance(rid, bool) or not isinstance(rid, str | int) or len(str(rid)) > 200:  # noqa: PLR2004
            return _error(None, -32600, "id must be a string or an integer")
        if method == "initialize":
            return self._initialize(rid, message.get("params"))
        if method == "ping":
            return {"jsonrpc": "2.0", "id": rid, "result": {}}
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        assert isinstance(params, dict)  # noqa: S101 - narrowed above
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        assert isinstance(meta, dict)  # noqa: S101
        modern = VERSION_KEY in meta
        if not modern:  # a legacy client after its handshake: speak modern to the gateway for it
            params = {**params, "_meta": {**meta, **self._modern_meta()}}
        try:
            answer = self._post({**message, "params": params})
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as error:
            return _error(rid, -32603, f"gateway unavailable ({type(error).__name__})")
        if answer is not None and not modern and isinstance(answer.get("result"), dict):
            result = answer["result"]
            assert isinstance(result, dict)  # noqa: S101 - checked in the condition above
            answer["result"] = {k: v for k, v in result.items() if k not in MODERN_ONLY}
        return answer

    def _initialize(self, rid: object, params: object) -> dict[str, object]:
        params = params if isinstance(params, dict) else {}
        requested = str(params.get("protocolVersion", ""))
        info = params.get("clientInfo")
        if isinstance(info, dict):
            self._client_info = {"name": str(info.get("name", ""))[:80], "version": str(info.get("version", ""))[:40]}
        try:
            discover = self._post(
                {
                    "jsonrpc": "2.0",
                    "id": "bridge-discover",
                    "method": "server/discover",
                    "params": {"_meta": self._modern_meta()},
                }
            )
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as error:
            return _error(rid, -32603, f"gateway unavailable ({type(error).__name__})")
        result = discover.get("result") if isinstance(discover, dict) else None
        if not isinstance(result, dict):
            return _error(rid, -32603, "gateway did not answer server/discover")
        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        assert isinstance(meta, dict)  # noqa: S101
        self._legacy = True
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": requested if requested in LEGACY_VERSIONS else LEGACY_VERSIONS[0],
                "capabilities": {"tools": {}},
                "serverInfo": meta.get("io.modelcontextprotocol/serverInfo", {"name": "tesseraline-airlock"}),
                "instructions": result.get("instructions", ""),
            },
        }

    def run(self, stdin: IO[bytes], stdout: IO[str]) -> None:
        """Serve the client until stdin closes. Each message is one line; nothing else is written to stdout.

        Lines are read as bytes with a length limit, so a client that never sends a newline cannot fill the memory,
        and an undecodable byte gets an error instead of ending the bridge.
        """
        while line := stdin.readline(MAX_LINE + 1):
            reply: dict[str, object] | None
            if len(line) > MAX_LINE and not line.endswith(b"\n"):
                while (rest := stdin.readline(MAX_LINE + 1)) and not rest.endswith(b"\n"):
                    pass  # drop the rest of the oversized line
                reply = _error(None, -32600, "message too large")
            elif not line.strip():
                continue
            else:
                try:
                    reply = self.handle(json.loads(line.decode("utf-8")))
                except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
                    reply = _error(None, -32700, "not JSON")
            if reply is not None:
                stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
                stdout.flush()


def main(gateway: str, cert: str, key: str, ca: str, model: str = "") -> int:
    """Run the bridge on this process's stdin and stdout."""
    for path in (cert, key, ca):
        if not os.path.exists(path):  # noqa: PTH110
            sys.stderr.write(f"airlock mcp-bridge: {path} not found\n")
            return 2
    Bridge(gateway, FileCredentials(cert, key, ca), model=model).run(sys.stdin.buffer, sys.stdout)
    return 0
