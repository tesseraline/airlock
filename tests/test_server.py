from __future__ import annotations

import http.client
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

from conftest import EchoHandler, FakePolicy
from tesseraline_airlock.egress import Egress
from tesseraline_airlock.fetch import HostCredential, make_fetch
from tesseraline_airlock.gateway import Gateway, Logs
from tesseraline_airlock.model import ModelRoute
from tesseraline_airlock.secrets import StaticStore
from tesseraline_airlock.server import CertFiles, Handler, TLSServer
from tesseraline_airlock.sinks import MemorySink
from tesseraline_airlock.tls import client_context, server_context

KEY = "demo-key-123456"


class ModelHandler(BaseHTTPRequestHandler):
    """A pretend model API: answers JSON or a stream, and echoes the key it got (it must be scrubbed)."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        got = self.headers.get("x-api-key", "")
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for event in (
                {"type": "message_start", "message": {"model": "demo-1", "usage": {"input_tokens": 7}}},
                {"type": "delta", "text": "hello"},
                {"type": "message_delta", "usage": {"output_tokens": 3}},
            ):
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
            return
        out = json.dumps({"model": "demo-1", "echo": got, "usage": {"input_tokens": 5, "output_tokens": 2}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def running(certs, https_server):
    """The gateway on a free port with mTLS; egress goes straight to local test servers."""
    echo_port = https_server(EchoHandler)
    model_port = https_server(ModelHandler)
    pem = lambda n: str(certs / f"{n}.pem")
    key = lambda n: str(certs / f"{n}-key.pem")
    logs = Logs(MemorySink(), MemorySink(), MemorySink())
    egress = Egress(
        None, client_context(pem("gateway"), key("gateway"), pem("ca")), private_hosts=frozenset({"localhost"})
    )
    fetch = make_fetch({f"localhost:{echo_port}": HostCredential("Authorization", "api", "Bearer {secret}")})
    gateway = Gateway(
        policy=FakePolicy({"fetch", "model:demo"}),
        store=StaticStore({"api": "tok-secret-987", "model": KEY}),
        egress=egress,
        tools=[fetch],
        logs=logs,
    )
    Handler.gateway = gateway
    Handler.routes = {
        "demo": ModelRoute("demo", f"https://localhost:{model_port}", "model", header="x-api-key", template="{secret}")
    }
    server = TLSServer(("127.0.0.1", 0), Handler)
    server.context = CertFiles(server_context(pem("gateway"), key("gateway"), pem("ca")), "", "", "").context
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], echo_port, logs
    server.shutdown()


def post(port, path, body, context, headers=None):
    connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=10)
    connection.request("POST", path, json.dumps(body), {"Content-Type": "application/json", **(headers or {})})
    response = connection.getresponse()
    return response.status, response.read().decode()


def agent_context(certs, name="agent"):
    return client_context(str(certs / f"{name}.pem"), str(certs / f"{name}-key.pem"), str(certs / "ca.pem"))


def test_no_client_certificate_no_connection(certs, running):
    port, _, _ = running
    context = ssl.create_default_context(cafile=str(certs / "ca.pem"))
    with pytest.raises((ssl.SSLError, ConnectionError, http.client.HTTPException)):
        post(port, "/v1/call", {"tool": "fetch", "args": {}}, context)


def test_certificate_from_another_ca_is_refused(certs, running):
    port, _, _ = running
    other = certs / "other"
    context = client_context(str(other / "agent.pem"), str(other / "agent-key.pem"), str(certs / "ca.pem"))
    with pytest.raises((ssl.SSLError, ConnectionError, http.client.HTTPException)):
        post(port, "/v1/call", {"tool": "fetch", "args": {}}, context)


def test_certificate_without_agent_name_gets_403(certs, running):
    port, _, _ = running
    status, _ = post(port, "/v1/call", {"tool": "fetch", "args": {}}, agent_context(certs, "gateway"))
    assert status == 403


def test_fetch_adds_the_credential_and_the_agent_never_sees_it(certs, running):
    port, echo_port, logs = running
    status, body = post(
        port,
        "/v1/call",
        {"tool": "fetch", "args": {"url": f"https://localhost:{echo_port}/items"}},
        agent_context(certs),
        {"X-Airlock-Session": "s-9"},
    )
    answer = json.loads(body)
    assert status == 200 and answer["allow"] is True
    assert "Bearer [redacted]" in answer["output"]  # the upstream echoed it; the gateway removed it
    assert "tok-secret-987" not in body
    assert logs.audit.records[-1]["agent"] == "researcher"
    assert logs.observability.records[-1]["output"]["scrubbed"] == 1


def test_model_route_json_scrubs_and_measures(certs, running):
    port, _, logs = running
    status, body = post(port, "/v1/model/demo/v1/messages", {"model": "demo-1", "messages": []}, agent_context(certs))
    assert status == 200 and KEY not in body and json.loads(body)["echo"] == "[redacted]"
    model = logs.observability.records[-1]["model"]
    assert model["name"] == "demo-1" and model["input_tokens"] == 5 and model["measured"] is True


def test_model_route_streams(certs, running):
    port, _, logs = running
    status, body = post(port, "/v1/model/demo/v1/messages", {"model": "demo-1", "stream": True}, agent_context(certs))
    assert status == 200 and body.count("data:") == 3
    time.sleep(0.1)
    model = logs.observability.records[-1]["model"]
    assert (model["input_tokens"], model["output_tokens"]) == (7, 3)


def test_unknown_route_and_path(certs, running):
    port, _, _ = running
    assert post(port, "/v1/model/nope/x", {}, agent_context(certs))[0] == 404
    assert post(port, "/v1/other", {}, agent_context(certs))[0] == 404


def test_agent_closing_a_stream_early_is_recorded(certs, running):
    port, _, logs = running
    connection = http.client.HTTPSConnection("localhost", port, context=agent_context(certs), timeout=10)
    connection.request(
        "POST",
        "/v1/model/demo/v1/messages",
        json.dumps({"model": "demo-1", "stream": True}),
        {"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    response.read(10)
    connection.close()
    for _ in range(50):
        if logs.observability.records and logs.observability.records[-1]["tool"] == "model:demo":
            break
        time.sleep(0.05)
    assert logs.observability.records[-1]["tool"] == "model:demo"


def raw_request(port, certs, head: bytes, body: bytes = b"") -> bytes:
    """Send bytes as they are and read the answer (for malformed requests http.client would not send)."""
    import socket as _socket

    context = agent_context(certs)
    with (
        _socket.create_connection(("localhost", port), timeout=10) as sock,
        context.wrap_socket(sock, server_hostname="localhost") as tls,
    ):
        tls.sendall(head + body)
        data = b""
        while chunk := tls.recv(4096):
            data += chunk
        return data


def test_unparsable_model_body_is_refused_not_passed(certs, running):
    port, _, logs = running
    before = len(logs.audit.records)
    connection = http.client.HTTPSConnection("localhost", port, context=agent_context(certs), timeout=10)
    connection.request(
        "POST",
        "/v1/model/demo/v1/messages",
        b'{"model": "big-expensive", "m": "\xff"}',
        {"Content-Type": "application/json"},
    )
    assert connection.getresponse().status == 400
    for body in ({"model": ["a"]}, {"model": "x" * 81}, [1, 2]):
        assert post(port, "/v1/model/demo/v1/messages", body, agent_context(certs))[0] == 400
    assert len(logs.audit.records) == before  # nothing reached the policy or the upstream


def test_negative_or_chunked_length_is_refused(certs, running):
    port, _, _ = running
    answer = raw_request(port, certs, b"POST /v1/call HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", b"{}")
    assert answer.startswith(b"HTTP/1.0 400") or answer.startswith(b"HTTP/1.1 400")
    answer = raw_request(
        port, certs, b"POST /v1/call HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", b"2\r\n{}\r\n0\r\n\r\n"
    )
    assert b" 400 " in answer.split(b"\r\n")[0]


@pytest.mark.parametrize(
    "path",
    ["/v1/model/demo/../admin", "/v1/model/demo/v1/%2e%2e/admin", "/v1/model/demo/v1//messages", "/v1/model/demo/./v1"],
)
def test_model_route_path_is_confined(certs, running, path):
    port, _, _ = running
    assert post(port, path, {"model": "demo-1"}, agent_context(certs))[0] == 400


def test_stream_scrubber_catches_a_secret_split_across_chunks():
    from tesseraline_airlock.records import StreamScrubber

    s = StreamScrubber(["sk-ABCDEFGH"])
    out = s.feed(b"data: key=sk-ABC") + s.feed(b"DEFGH end\n") + s.finish()
    assert out == b"data: key=[redacted] end\n"
