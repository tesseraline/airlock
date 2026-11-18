"""A pretend outside API for the example: one endpoint that needs a token, one that acts like a model API.

GET  /items         needs "Authorization: Bearer <token>"; echoes the header back, so the example can show that
                    the gateway removes the token before the agent sees the answer.
POST /v1/messages   needs "x-api-key: <key>"; answers like a small chat model, as JSON or as a stream.
"""

import json
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = Path("/secrets/demo-api-token").read_text().strip()
MODEL_KEY = Path("/secrets/model-key").read_text().strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "demo-api"
    sys_version = ""

    def log_message(self, fmt, *args):  # noqa: ARG002
        sys.stdout.write(f"{time.strftime('%H:%M:%S')} {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        got = self.headers.get("Authorization", "")
        if self.path.split("?")[0] != "/items":
            return self._json(404, {"error": "not found"})
        if got != f"Bearer {TOKEN}":
            return self._json(401, {"error": "token missing or wrong"})
        return self._json(
            200, {"items": [{"sku": "A-100", "stock": 12}, {"sku": "B-200", "stock": 0}], "received_authorization": got}
        )

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path != "/v1/messages":
            return self._json(404, {"error": "not found"})
        if self.headers.get("x-api-key") != MODEL_KEY:
            return self._json(401, {"error": "key missing or wrong"})
        text = "This is a pretend model answer."
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            events = [
                {
                    "type": "message_start",
                    "message": {"model": body.get("model", "demo-1"), "usage": {"input_tokens": 12}},
                }
            ]
            events += [{"type": "content_block_delta", "delta": {"text": word + " "}} for word in text.split()]
            events += [{"type": "message_delta", "usage": {"output_tokens": len(text.split())}}]
            for event in events:
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.05)
            return None
        return self._json(
            200,
            {
                "model": body.get("model", "demo-1"),
                "content": [{"type": "text", "text": text}],
                "usage": {"input_tokens": 12, "output_tokens": len(text.split())},
            },
        )


server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/certs/demo-api.pem", "/certs/demo-api-key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
print("demo-api on :8443", flush=True)
server.serve_forever()
