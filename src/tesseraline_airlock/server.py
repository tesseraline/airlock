"""The HTTPS server: mutual TLS on every connection, the agent's name from its certificate.

TLS handshakes run in the connection's own thread, so a slow client cannot hold up the others. On SIGHUP the
gateway loads its certificates again for new connections.
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, ClassVar

from tesseraline_airlock import mcp, records
from tesseraline_airlock.gateway import AuditUnavailableError, Gateway
from tesseraline_airlock.model import ModelRoute, UsageReader
from tesseraline_airlock.tls import agent_name, server_context

if TYPE_CHECKING:
    from types import FrameType

MAX_BODY = 1_000_000
MAX_TOOL_BODY = 64_000
MAX_CONNECTIONS = int(os.environ.get("AIRLOCK_MAX_CONNECTIONS", "64"))  # handled at once; more are closed
MAX_MODEL_ANSWER = 32_000_000  # bytes of one model answer passed to the agent
ROUTE_PATH = re.compile(r"^[A-Za-z0-9._~/-]*(\?[A-Za-z0-9._~=&-]*)?$")


@dataclass(frozen=True, slots=True)
class CertFiles:
    """A context and the files it was loaded from, so SIGHUP can load them again."""

    context: ssl.SSLContext
    cert: str
    key: str
    ca: str

    def reload(self) -> None:
        """Load the certificate and key again (client side; a CA added here is trusted in addition)."""
        self.context.load_cert_chain(self.cert, self.key)
        self.context.load_verify_locations(self.ca)

    def fresh_server_context(self) -> ssl.SSLContext:
        """A new server context from the files, so a replaced CA stops being trusted at once."""
        return server_context(self.cert, self.key, self.ca)


class TLSServer(ThreadingHTTPServer):
    """A threading server that wraps each accepted socket in TLS inside its own thread."""

    daemon_threads = True
    context: ssl.SSLContext
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request: socket.socket | tuple[bytes, socket.socket], client_address: object) -> None:
        """Refuse a connection when MAX_CONNECTIONS are already being handled."""
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """Free the slot when the connection is done."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def finish_request(self, request: socket.socket | tuple[bytes, socket.socket], client_address: object) -> None:
        """Do the TLS handshake (10 s limit), then handle the request."""
        assert isinstance(request, socket.socket)  # noqa: S101
        request.settimeout(10)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            request.close()
            return
        tls.settimeout(60)
        super().finish_request(tls, client_address)


class Handler(BaseHTTPRequestHandler):
    """Routes: POST /v1/call, POST /v1/model/<route>/<path>, GET /healthz."""

    gateway: ClassVar[Gateway]
    routes: ClassVar[dict[str, ModelRoute]]
    server_version = "airlock"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
        """Access lines go to the developer log, without query strings."""
        return

    def _agent(self) -> str | None:
        assert isinstance(self.connection, ssl.SSLSocket)  # noqa: S101
        return agent_name(self.connection.getpeercert())  # type: ignore[arg-type]

    def _send(self, status: int, body: str, content_type: str = "application/json") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.gateway.dev("info", "http", f"{self.command} {self.path.split('?')[0]} {status}")

    def _length(self) -> int | None:
        """The request's Content-Length; None for a chunked body, a negative or a malformed value."""
        if self.headers.get("Transfer-Encoding"):
            return None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        return length if length >= 0 else None

    def _body(self, limit: int) -> bytes | None:
        length = self._length()
        if length is None:
            self.close_connection = True
            self._send(400, records.error_body(uuid.uuid4().hex[:16], 400, "a Content-Length of 0 or more is required"))
            return None
        if length > limit:
            self.close_connection = True
            self._send(413, records.error_body(uuid.uuid4().hex[:16], 413, "request body too large"))
            return None
        return self.rfile.read(length) if length else b""

    def do_GET(self) -> None:
        """Health check."""
        if self.path == "/healthz":
            ok = self.gateway.policy.healthy()
            self._send(200 if ok else 503, json.dumps({"policy": "up" if ok else "down"}))
        else:
            self._send(404, records.error_body(uuid.uuid4().hex[:16], 404, "not found"))

    def do_POST(self) -> None:
        """Tool calls and model requests."""
        agent = self._agent()
        if agent is None:
            self._drain()
            self.gateway.security("certificate_without_agent_name")
            self._send(403, records.error_body(uuid.uuid4().hex[:16], 403, "certificate names no agent"))
            return
        session = self.headers.get("X-Airlock-Session", "")
        if self.path == "/v1/call":
            raw = self._body(MAX_TOOL_BODY)
            if raw is None:
                return
            try:
                body = json.loads(raw or b"{}")
            except (ValueError, RecursionError):
                body = None
            if not isinstance(body, dict):
                self._send(400, records.error_body(uuid.uuid4().hex[:16], 400, "body is not a JSON object"))
                return
            status, text = self.gateway.call_tool(agent, body, session, self.headers.get("X-Airlock-Model", ""))
            self._send(status, text)
        elif self.path.startswith("/v1/model/"):
            self._model(agent, session)
        elif self.path == "/mcp":
            raw = self._body(MAX_TOOL_BODY)
            if raw is None:
                return
            status, text = mcp.handle(
                self.gateway,
                agent,
                raw,
                self.headers.get("MCP-Protocol-Version", ""),
                session,
                self.headers.get("X-Airlock-Model", ""),
            )
            if status == 202:  # noqa: PLR2004 - a notification gets no body
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(status, text)
        else:
            self._drain()
            self._send(404, records.error_body(uuid.uuid4().hex[:16], 404, "not found"))

    def _drain(self) -> None:
        """Read and drop a request body we answer early, so the client is not cut off mid-send."""
        length = self._length()
        if length and length <= MAX_BODY:
            self.rfile.read(length)
        self.close_connection = True

    def _model(self, agent: str, session: str) -> None:  # noqa: PLR0912, PLR0915 - one request, read top to bottom
        started = time.monotonic()
        name, _, path = self.path[len("/v1/model/") :].partition("/")
        route = self.routes.get(name)
        raw = self._body(MAX_BODY)
        if raw is None:
            return
        if route is None:
            self._send(404, records.error_body(uuid.uuid4().hex[:16], 404, "no such model route"))
            return
        segments = path.split("?")[0].split("/")
        if not ROUTE_PATH.match(path) or "//" in path or any(part in ("..", ".") for part in segments):
            self.gateway.security("model_route_path_refused", name)
            self._send(400, records.error_body(uuid.uuid4().hex[:16], 400, "model route path refused"))
            return
        try:
            request = json.loads(raw or b"{}")
        except (ValueError, RecursionError):
            request = None
        model_field = request.get("model", "") if isinstance(request, dict) else None
        if not isinstance(model_field, str) or len(model_field) > 80:  # noqa: PLR2004
            # the policy must see the model the provider will see: no answer, no request
            reason = "body must be a JSON object with a short string model"
            self._send(400, records.error_body(uuid.uuid4().hex[:16], 400, reason))
            return
        asked = model_field
        forwarded = json.dumps(request, ensure_ascii=False).encode()  # exactly what the policy judged
        try:
            call = self.gateway.begin(
                agent,
                f"model:{name}",
                {"path": "/" + path, "model": asked},
                session,
                {"requested": asked},
                kind="model",
            )
        except AuditUnavailableError:
            self._send(503, records.error_body(uuid.uuid4().hex[:16], 503, "audit log unavailable; call refused"))
            return
        if not call.allow:
            self._send(200, records.response_body(call))
            self.gateway.observe(replace(call, ms=int((time.monotonic() - started) * 1000)))
            return
        usage, size, status, sent = UsageReader(), 0, 502, False
        error: str | None = None
        try:
            key = self.gateway.store.get(route.secret).value
            target = route.target(path)
            connection, response = self.gateway.egress.open(
                "POST", target, route.headers(dict(self.headers.items()), key), forwarded
            )
            status = response.status
            try:
                kind = response.getheader("Content-Type", "application/json")
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Connection", "close")
                self.end_headers()
                sent = True
                if "text/event-stream" in kind:
                    scrubber = records.StreamScrubber([key])
                    while chunk := response.read1(16_384):
                        usage.feed_stream(chunk)
                        size += len(chunk)
                        if size > MAX_MODEL_ANSWER:
                            error = "AnswerTooLarge"
                            break
                        self.wfile.write(scrubber.feed(chunk))
                        self.wfile.flush()
                    self.wfile.write(scrubber.finish())
                else:
                    data = response.read(MAX_MODEL_ANSWER)
                    usage.feed_json(data)
                    text, scrubbed = records.scrub(data.decode("utf-8", "replace"), [key])
                    if scrubbed:
                        self.gateway.security("secret_scrubbed", f"model:{name}: {scrubbed}")
                    text, _ = self.gateway.redact(text)
                    out = text.encode()
                    size = len(out)
                    self.wfile.write(out)
            finally:
                connection.close()
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError) as exc:
            # the agent closed the connection while the answer was on its way: nothing left to send
            error = "ClientDisconnected" if sent else type(exc).__name__
            self.gateway.dev(
                "info" if sent else "error", "model_route_closed" if sent else "model_route_failed", f"{name}: {error}"
            )
            self.close_connection = True
            if not sent:
                self._send(502, records.error_body(call.request_id, 502, "model upstream failed"))
        except Exception as exc:  # any failure on the way out is reduced to its class name
            error = type(exc).__name__
            self.gateway.dev("error", "model_route_failed", f"{name}: {error}")
            self.close_connection = True
            if not sent:
                self._send(502, records.error_body(call.request_id, 502, "model upstream failed"))
        self.gateway.tokens.add(agent, usage.input_tokens + usage.output_tokens)
        model = {"requested": asked} | (usage.as_dict() if usage.model or usage.output_tokens else {})
        self.gateway.observe(
            replace(
                call,
                ms=int((time.monotonic() - started) * 1000),
                output_bytes=size,
                error=error,
                model=model,
                reason=call.reason if status < 400 else f"{call.reason}; upstream {status}",  # noqa: PLR2004
            )
        )


def serve(
    gateway: Gateway,
    routes: dict[str, ModelRoute],
    server_tls: CertFiles,
    port: int,
    reloadable: list[CertFiles],
    host: str = "0.0.0.0",  # noqa: S104 - inside its own container; the network decides who reaches it
) -> None:
    """Run the gateway until stopped."""
    Handler.gateway = gateway
    Handler.routes = routes
    server = TLSServer((host, port), Handler)
    server.context = server_tls.context

    def reload(signum: int, frame: FrameType | None) -> None:  # noqa: ARG001
        try:
            fresh = server_tls.fresh_server_context()
            for files in reloadable:
                files.reload()
        except (OSError, ssl.SSLError) as error:
            gateway.dev("error", "certificate_reload_failed", type(error).__name__)
            return
        server.context = fresh  # new connections use the new certificate and only the new CA
        gateway.dev("info", "certificates_reloaded")

    signal.signal(signal.SIGHUP, reload)
    gateway.dev(
        "info",
        "listening",
        f"port {port}, tools: {', '.join(sorted(gateway.tools))}, model routes: {', '.join(sorted(routes)) or 'none'}",
    )
    server.serve_forever()
