"""MCP on the gateway: `POST /mcp`, revision 2026-07-28 only (stateless, the version in each request's `_meta`).

Methods: `server/discover`, `tools/list`, `tools/call`. `tools/list` shows only the tools the policy gives the
agent; `tools/call` runs through the same steps as `/v1/call`. A refusal is a tool result with `isError: true`.
Clients that speak an older, handshake-based revision use `airlock mcp-bridge`, which translates.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tesseraline_airlock.gateway import Gateway

VERSION = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"
SERVER_INFO = {"name": "tesseraline-airlock", "version": "0.1.0"}

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602
UNSUPPORTED_VERSION = -32022


def _error(rid: object, code: int, message: str, data: object = None) -> dict[str, object]:
    error: dict[str, object] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": error}


def _result(rid: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": rid, "result": {"resultType": "complete", **result}}


class _Reply(Exception):  # noqa: N818 - an early answer, not a failure
    """Carries an HTTP status and body out of the checks."""

    def __init__(self, status: int, body: dict[str, object] | None) -> None:
        self.status, self.body = status, body


def _parse(raw: bytes, header_version: str) -> tuple[object, str, dict[str, object], dict[str, object]]:
    """The request's id, method, params and _meta; raises _Reply for anything that is not a modern request."""
    try:
        message = json.loads(raw or b"null")
    except (ValueError, RecursionError):
        raise _Reply(400, _error(None, PARSE_ERROR, "body is not JSON")) from None
    if isinstance(message, list):
        raise _Reply(400, _error(None, INVALID_REQUEST, "batches are not accepted"))
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        raise _Reply(400, _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 request"))
    if "id" not in message:  # a notification: nothing to answer
        raise _Reply(202, None)
    rid, params = message.get("id"), message.get("params") or {}
    if isinstance(rid, bool) or not isinstance(rid, str | int) or len(str(rid)) > 200:  # noqa: PLR2004
        raise _Reply(400, _error(None, INVALID_REQUEST, "id must be a string or an integer"))
    if not isinstance(params, dict):
        raise _Reply(200, _error(rid, INVALID_PARAMS, "params must be an object"))
    found = params.get("_meta")
    meta: dict[str, object] = found if isinstance(found, dict) else {}
    version = str(meta.get(VERSION_KEY, ""))  # the request's own _meta decides; a header, if sent, must agree
    if version != VERSION or (header_version and header_version != version):
        data = {"supported": [VERSION], "requested": version}
        raise _Reply(200, _error(rid, UNSUPPORTED_VERSION, "Unsupported protocol version", data))
    return rid, str(message["method"]), params, meta


def _discover() -> dict[str, object]:
    return {
        "supportedVersions": [VERSION],
        "capabilities": {"tools": {}},
        "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
        "instructions": "Tools behind a policy gateway; a refused call says why.",
    }


def _list(gateway: Gateway, agent: str) -> dict[str, object]:
    allowed = set(gateway.policy.tools_for(agent))
    tools = [
        {"name": t.name, "description": t.description, "inputSchema": t.schema}
        for name, t in sorted(gateway.tools.items())
        if name in allowed
    ]
    gateway.observe_list(agent, len(tools))
    return {"tools": tools}


def _call(
    gateway: Gateway,
    agent: str,
    rid: object,
    params: dict[str, object],
    meta: dict[str, object],
    session: str,
    model: str = "",
) -> dict[str, object]:
    name, arguments = params.get("name"), params.get("arguments", {})
    if not isinstance(name, str) or not isinstance(arguments, dict):
        return _error(rid, INVALID_PARAMS, "expected name and arguments")
    client = meta.get(CLIENT_INFO_KEY)
    client_name = str(client.get("name", ""))[:80] if isinstance(client, dict) else ""
    status, body = gateway.call_tool(agent, {"tool": name, "args": arguments}, session, model, client=client_name)
    answer = json.loads(body)
    if status == 400:  # noqa: PLR2004 - a malformed tool name or arguments
        return _error(rid, INVALID_PARAMS, str(answer.get("reason", "invalid request")))
    if status != 200:  # noqa: PLR2004 - the audit log refused
        return _error(rid, -32603, str(answer.get("reason", "call refused")))
    allowed = bool(answer.get("allow"))
    text = answer.get("output", "") if allowed else f"refused by policy: {answer.get('reason', '')}"
    failed = not allowed or bool(answer.get("error"))  # a refusal or a failed tool is a tool error
    return _result(rid, {"content": [{"type": "text", "text": text}], "isError": failed})


def handle(
    gateway: Gateway, agent: str, raw: bytes, header_version: str, session: str, model: str = ""
) -> tuple[int, str]:
    """Answer one MCP HTTP request. Returns the HTTP status and the JSON body ("" for a notification)."""
    try:
        rid, method, params, meta = _parse(raw, header_version)
    except _Reply as reply:
        return reply.status, json.dumps(reply.body) if reply.body is not None else ""
    if method == "server/discover":
        return 200, json.dumps(_result(rid, _discover()))
    if method == "tools/list":
        return 200, json.dumps(_result(rid, _list(gateway, agent)))
    if method == "tools/call":
        return 200, json.dumps(_call(gateway, agent, rid, params, meta, session, model))
    return 200, json.dumps(_error(rid, METHOD_NOT_FOUND, f"Method not found: {method[:64]}"))
