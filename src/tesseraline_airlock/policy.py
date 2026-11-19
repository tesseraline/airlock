"""The first door: the policy engine decides every tool call. No answer is a refusal."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Decision:
    """The policy's answer."""

    allow: bool
    reason: str
    version: str = ""


class Policy(Protocol):
    """Decides whether a call may run."""

    def decide(self, request: dict[str, object]) -> Decision:
        """Answer for one call; must never raise."""
        ...

    def healthy(self) -> bool:
        """Tell whether the policy engine answers."""
        ...

    def tools_for(self, agent: str) -> list[str]:
        """The tools the agent may see (for MCP tools/list); empty on any failure."""
        ...


class OpaPolicy:
    """Open Policy Agent over HTTPS with mutual TLS.

    Asks `POST <url>/v1/data/<package path>/decision` and expects `{"allow": bool, "reason": str}`. A timeout, a
    connection error, an HTTP error or an answer of another shape is a refusal (fail closed).
    """

    def __init__(
        self, url: str, context: ssl.SSLContext | None, *, path: str = "airlock/tools/decision", timeout: float = 2.0
    ) -> None:
        self._base = url.rstrip("/")
        self._url = f"{self._base}/v1/data/{path}"
        handlers: list[urllib.request.BaseHandler] = [urllib.request.ProxyHandler({})]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)
        self._timeout = timeout

    def decide(self, request: dict[str, object]) -> Decision:
        """Ask OPA; any failure is a refusal."""
        body = json.dumps({"input": request}).encode()
        try:
            http = urllib.request.Request(self._url, body, {"Content-Type": "application/json"})  # noqa: S310
            with self._opener.open(http, timeout=self._timeout) as response:
                answer = json.loads(response.read())
                result = answer.get("result") if isinstance(answer, dict) else None
            if not isinstance(result, dict):
                result = None
        except Exception as error:  # whatever goes wrong, the answer is no
            return Decision(False, f"policy engine unavailable ({type(error).__name__})")
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            return Decision(False, "policy gave no decision")
        reason = str(result.get("reason", "")) or ("allowed" if result["allow"] else "refused")
        return Decision(result["allow"], reason, str(result.get("version", "")))

    def tools_for(self, agent: str) -> list[str]:
        """Ask the same decision path with `kind: list`; any failure lists nothing (fail closed)."""
        body = json.dumps({"input": {"kind": "list", "agent": agent}}).encode()
        try:
            http = urllib.request.Request(self._url, body, {"Content-Type": "application/json"})  # noqa: S310
            with self._opener.open(http, timeout=self._timeout) as response:
                answer = json.loads(response.read())
        except Exception:
            return []
        result = answer.get("result") if isinstance(answer, dict) else None
        tools = result.get("tools") if isinstance(result, dict) else None
        return [t for t in tools if isinstance(t, str)] if isinstance(tools, list) else []

    def healthy(self) -> bool:
        """`GET /health` on the OPA server."""
        try:
            with self._opener.open(f"{self._base}/health", timeout=self._timeout) as response:
                return bool(response.status == 200)  # noqa: PLR2004
        except (urllib.error.URLError, OSError):
            return False
