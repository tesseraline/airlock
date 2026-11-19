from __future__ import annotations

import http.client
import io
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


def run_bridge(port, certs, lines):
    from tesseraline_airlock.mcp_bridge import Bridge, FileCredentials

    bridge = Bridge(
        f"https://localhost:{port}",
        FileCredentials(str(certs / "agent.pem"), str(certs / "agent-key.pem"), str(certs / "ca.pem")),
    )
    out = io.StringIO()
    bridge.run(io.BytesIO("".join(json.dumps(m) + "\n" for m in lines).encode()), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_bridge_serves_a_legacy_client(certs, running):
    port, echo_port, logs = running
    answers = run_bridge(
        port,
        certs,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "old", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "fetch", "arguments": {"url": f"https://localhost:{echo_port}/items"}},
            },
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
        ],
    )
    assert [a["id"] for a in answers] == [1, 2, 3, 4]  # the notification got no answer
    assert answers[0]["result"]["protocolVersion"] == "2025-06-18"
    assert [t["name"] for t in answers[1]["result"]["tools"]] == ["fetch"]
    assert "resultType" not in answers[1]["result"]  # modern-only fields removed for a legacy client
    assert "Bearer [redacted]" in answers[2]["result"]["content"][0]["text"]
    assert logs.observability.records[-1]["client"] == "old"


def test_bridge_passes_a_modern_client_through(certs, running):
    port, _, _ = running
    meta = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "new", "version": "1"},
        }
    }
    answers = run_bridge(
        port,
        certs,
        [
            {"jsonrpc": "2.0", "id": "a", "method": "server/discover", "params": meta},
            {"jsonrpc": "2.0", "id": "b", "method": "tools/list", "params": meta},
        ],
    )
    assert answers[0]["result"]["supportedVersions"] == ["2026-07-28"]
    assert answers[1]["result"]["resultType"] == "complete"


def test_bridge_without_a_reachable_gateway_answers_with_an_error(certs):
    answers = run_bridge(1, certs, [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}])
    assert answers[0]["error"]["code"] == -32603


def run_bridge_raw(port, certs, data: bytes):
    from tesseraline_airlock.mcp_bridge import Bridge, FileCredentials

    bridge = Bridge(
        f"https://localhost:{port}",
        FileCredentials(str(certs / "agent.pem"), str(certs / "agent-key.pem"), str(certs / "ca.pem")),
    )
    out = io.StringIO()
    bridge.run(io.BytesIO(data), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_bridge_turns_a_non_json_rpc_gateway_answer_into_an_error_with_the_id(certs, running):
    from tesseraline_airlock.mcp_bridge import Bridge, FileCredentials

    port, _, _ = running
    # a certificate that names no agent: the gateway answers 403 with a body that is not JSON-RPC
    bridge = Bridge(
        f"https://localhost:{port}",
        FileCredentials(str(certs / "gateway.pem"), str(certs / "gateway-key.pem"), str(certs / "ca.pem")),
    )
    out = io.StringIO()
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/list",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
    }
    bridge.run(io.BytesIO((json.dumps(message) + "\n").encode()), out)
    answer = json.loads(out.getvalue())
    assert (answer["id"], answer["error"]["code"]) == (7, -32603)
    assert "HTTP 403" in answer["error"]["message"]


def test_bridge_survives_bad_bytes_and_oversized_lines(certs, running):
    port, _, _ = running
    ping = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode()
    data = b"\xff\xfe not utf-8\n" + b"x" * 70_000 + b"\n" + ping + b"\n"
    answers = run_bridge_raw(port, certs, data)
    assert [a.get("error", {}).get("code") for a in answers] == [-32700, -32600, None]
    assert answers[2] == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_bridge_reports_the_operators_model_label(certs, running):
    from tesseraline_airlock.mcp_bridge import Bridge, FileCredentials

    port, echo_port, logs = running
    bridge = Bridge(
        f"https://localhost:{port}",
        FileCredentials(str(certs / "agent.pem"), str(certs / "agent-key.pem"), str(certs / "ca.pem")),
        model="example-model",
    )
    out = io.StringIO()
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
            "name": "fetch",
            "arguments": {"url": f"https://localhost:{echo_port}/items"},
        },
    }
    bridge.run(io.BytesIO((json.dumps(call) + "\n").encode()), out)
    assert logs.observability.records[-1]["model"] == {"reported": "example-model"}
