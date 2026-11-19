"""The gateway: identity in, policy decision, audit record, the tool, scrubbed output, the logs.

Order for every tool call: count, ask the policy, write the audit record (if it cannot be written, refuse), run the
tool, scrub its output, write the observability record, answer. The model route follows the same order around a
pass-through request.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import re
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from tesseraline_airlock import records
from tesseraline_airlock.limits import CallCounter, TokenMeter
from tesseraline_airlock.records import Call
from tesseraline_airlock.sinks import NullSink, Sink
from tesseraline_airlock.tools import Tool, ToolContext, check_description

if TYPE_CHECKING:
    from tesseraline_airlock.egress import Egress
    from tesseraline_airlock.policy import Policy
    from tesseraline_airlock.redact import Redactor
    from tesseraline_airlock.secrets import SecretStore

SESSION = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


@dataclass(frozen=True, slots=True)
class Logs:
    """The three logs. Any of them can be any `Sink`."""

    developer: Sink
    audit: Sink
    observability: Sink

    @classmethod
    def none(cls) -> Logs:
        """Three sinks that drop everything."""
        return cls(NullSink(), NullSink(), NullSink())


class AuditUnavailableError(Exception):
    """The audit record could not be written, so the call does not run."""


def now_iso() -> str:
    """UTC time with milliseconds."""
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Gateway:
    """Runs tool calls for authenticated agents."""

    def __init__(
        self,
        *,
        policy: Policy,
        store: SecretStore,
        egress: Egress,
        tools: list[Tool],
        logs: Logs,
        output_limit: int = 16_000,
        redactor: Redactor | None = None,
    ) -> None:
        self.policy, self.store, self.egress, self.logs = policy, store, egress, logs
        for t in tools:
            check_description(t)  # a description that could carry instructions stops the start (threat M2)
        self.tools = {t.name: t for t in tools}
        self.counter = CallCounter()
        self.tokens = TokenMeter()
        self.redactor = redactor
        self.output_limit = output_limit
        self._steps: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    # --- logs ---
    def dev(self, level: str, event: str, detail: str = "") -> None:
        """A developer log record; never fails the caller."""
        with contextlib.suppress(Exception):  # the developer log must not stop the gateway
            self.logs.developer.write(json.loads(records.developer_entry(level, event, detail)) | {"ts": now_iso()})

    def security(self, event: str, detail: str = "") -> None:
        """A security event in the developer log: one event name, `security`, for a SIEM to alert on."""
        self.dev("warning", "security", f"{event}: {detail}" if detail else event)

    def redact(self, text: str) -> tuple[str, int]:
        """Apply the optional PII redactor; any failure of it withholds the text (fail closed)."""
        if self.redactor is None:
            return text, 0
        try:
            return self.redactor.redact(text)
        except Exception as error:  # a broken redactor must not let the text through
            self.dev("error", "redactor_failed", type(error).__name__)
            return "[withheld: the redactor failed]", 1

    def observe_list(self, agent: str, count: int) -> None:
        """An observability record for an MCP tools/list (no decision to audit: listing runs nothing)."""
        self.observe(
            Call(
                request_id=uuid.uuid4().hex[:16],
                ts=now_iso(),
                agent=agent,
                tool="mcp:tools/list",
                arg_sizes={},
                arg_hashes={},
                allow=True,
                reason=f"{count} tools listed",
            )
        )

    def audit(self, call: Call) -> None:
        """Write the audit record; raise `AuditUnavailableError` when it cannot be written."""
        try:
            self.logs.audit.write(json.loads(records.audit_entry(call)))
        except Exception as error:
            self.security("audit_write_failed", type(error).__name__)
            raise AuditUnavailableError from error

    def observe(self, call: Call) -> None:
        """Write the observability record; never fails the caller."""
        try:
            self.logs.observability.write(json.loads(records.observability_entry(call)))
        except Exception as error:
            self.dev("warning", "observability_write_failed", type(error).__name__)

    # --- calls ---
    def step(self, agent: str, session: str) -> int:
        """The position of this call within its session (kept for the last 10 000 sessions)."""
        if not session:
            return 0
        with self._lock:
            key = (agent, session)
            self._steps[key] = self._steps.get(key, 0) + 1
            self._steps.move_to_end(key)
            while len(self._steps) > 10_000:  # noqa: PLR2004
                self._steps.popitem(last=False)
            return self._steps[key]

    def begin(
        self, agent: str, tool: str, args: dict[str, object], session: str, model: dict[str, object], kind: str = "tool"
    ) -> Call:
        """Count, ask the policy and write the audit record. Returns the call with its decision."""
        session = session if SESSION.match(session) else ""
        count, token = self.counter.reserve(agent, tool)
        question: dict[str, object] = {
            "kind": kind,
            "agent": agent,
            "tool": tool,
            "args": args,
            "calls_last_hour": count,
        }
        if kind == "model":
            question["tokens_last_hour"] = self.tokens.used(agent)
        decision = self.policy.decide(question)
        call = Call(
            request_id=uuid.uuid4().hex[:16],
            ts=now_iso(),
            agent=agent,
            tool=tool,
            arg_sizes={k: len(json.dumps(v, ensure_ascii=False)) for k, v in args.items()},
            arg_hashes={k: records.digest(v) for k, v in args.items()},
            allow=decision.allow,
            reason=decision.reason,
            session=session,
            step=self.step(agent, session),
            model=model,
            policy_hash=decision.version,
        )
        if not call.allow:
            self.counter.release(agent, tool, token)
        try:
            self.audit(call)
        except AuditUnavailableError:
            if call.allow:
                self.counter.release(agent, tool, token)  # the call does not run, so it does not count
            raise
        return call

    def call_tool(
        self, agent: str, body: dict[str, object], session: str = "", reported_model: str = "", client: str = ""
    ) -> tuple[int, str]:
        """Handle `POST /v1/call`. Returns the HTTP status and the JSON body."""
        started = time.monotonic()
        tool, args = body.get("tool"), body.get("args", {})
        if not isinstance(tool, str) or not TOOL_NAME.match(tool) or not isinstance(args, dict):
            return 400, records.error_body(uuid.uuid4().hex[:16], 400, 'expected {"tool": name, "args": {...}}')
        model: dict[str, object] = {"reported": reported_model[:80]} if reported_model else {}
        registered = self.tools.get(tool)
        if registered is not None and registered.prepare is not None:
            try:
                args = registered.prepare(dict(args))
            except ValueError as error:
                call = Call(
                    request_id=uuid.uuid4().hex[:16],
                    ts=now_iso(),
                    agent=agent,
                    tool=tool,
                    arg_sizes={},
                    arg_hashes={k: records.digest(v) for k, v in args.items()},
                    allow=False,
                    reason=f"arguments refused: {error}",
                    session=session if SESSION.match(session) else "",
                )
                try:
                    self.audit(call)
                except AuditUnavailableError:
                    return 503, records.error_body(call.request_id, 503, "audit log unavailable; call refused")
                self.observe(call)
                return 200, records.response_body(call)
        try:
            call = replace(self.begin(agent, tool, args, session, model), client=client[:80])
        except AuditUnavailableError:
            return 503, records.error_body(uuid.uuid4().hex[:16], 503, "audit log unavailable; call refused")
        if call.allow:
            call = self._run(call, args)
        call = replace(call, ms=int((time.monotonic() - started) * 1000))
        self.observe(call)
        return 200, records.response_body(call)

    def _run(self, call: Call, args: dict[str, object]) -> Call:
        tool = self.tools.get(call.tool)
        if tool is None:
            return replace(call, output="no such tool in this gateway", error="UnknownTool")
        context = ToolContext(self.egress, self.store)
        error = None
        try:
            output = tool.function(args, context)
        except Exception as exc:
            output, error = f"tool failed: {type(exc).__name__}", type(exc).__name__
            self.dev("error", "tool_failed", f"{call.tool}: {type(exc).__name__}")
        output, scrubbed = records.scrub(str(output), context.used_secrets)
        if scrubbed:
            self.security("secret_scrubbed", f"{call.tool}: {scrubbed}")
        output, redacted = self.redact(output)
        size = len(output.encode())
        truncated = len(output) > self.output_limit
        return replace(
            call,
            output=output[: self.output_limit],
            output_bytes=size,
            truncated=truncated,
            scrubbed=scrubbed,
            redacted=redacted,
            error=error,
        )
