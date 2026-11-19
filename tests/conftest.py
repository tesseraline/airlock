from __future__ import annotations

import json
import ssl
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tesseraline_airlock.policy import Decision

SCRIPT = Path(__file__).parents[1] / "examples/terraform/docker/scripts/make-certs.sh"


@pytest.fixture(scope="session")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("certs")
    subprocess.run(["sh", str(SCRIPT), str(out), "1"], check=True, capture_output=True)
    other = tmp_path_factory.mktemp("other-ca")  # a second CA the gateway does not trust
    subprocess.run(["sh", str(SCRIPT), str(other), "1"], check=True, capture_output=True)
    (out / "other").symlink_to(other)
    return out


class FakePolicy:
    """Allows the tools in `allowed`; records every request it was asked."""

    def __init__(self, allowed: set[str], up: bool = True) -> None:
        self.allowed, self.up, self.asked = allowed, up, []

    def decide(self, request):
        self.asked.append(request)
        if not self.up:
            return Decision(False, "policy engine unavailable (URLError)")
        ok = request["tool"] in self.allowed
        return Decision(
            ok, "allowed" if ok else f"tool {request['tool']} is not given to agent {request['agent']}", "v1"
        )

    def healthy(self):
        return self.up

    def tools_for(self, agent):
        return sorted(self.allowed) if self.up else []


@pytest.fixture
def https_server(certs: Path) -> Iterator[callable]:
    """Start a small HTTPS server (as demo-api) with a given handler class; returns its port."""
    started = []

    def start(handler: type[BaseHTTPRequestHandler]) -> int:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs / "demo-api.pem", certs / "demo-api-key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return server.server_address[1]

    yield start
    for server in started:
        server.shutdown()


class EchoHandler(BaseHTTPRequestHandler):
    """Answers with the request's headers, like an API that reflects what it got."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": dict(self.headers.items())}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
