"""Everything that leaves the gateway as text: the answer to the agent and the entries of the three logs.

Each builder carries a `never_contains(Secret)` promise: whatever secret the call used, it must not appear in the
built text. `invariants check` runs these builders on generated inputs; `scrub` removes known secret values from
tool output at run time, as a second layer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from tesseraline_invariants import Secret, invariant, never_contains


@dataclass(frozen=True, slots=True)
class Call:
    """One handled request, as the builders see it.

    `secret` is the value the tool or model route used, if any. It is here so the promises can test that no
    builder lets it through.
    """

    request_id: str
    ts: str
    agent: str
    tool: str
    arg_sizes: dict[str, int]
    arg_hashes: dict[str, str]
    allow: bool
    reason: str
    ms: int = 0
    output: str = ""
    output_bytes: int = 0
    truncated: bool = False
    scrubbed: int = 0
    redacted: int = 0
    error: str | None = None
    session: str = ""
    client: str = ""  # the MCP client's own name for itself, as reported
    step: int = 0
    model: dict[str, object] = field(default_factory=dict)
    policy_hash: str = ""
    secret: Secret[str] | None = field(default=None, repr=False)


def scrub(text: str, secrets: list[str]) -> tuple[str, int]:
    """Replace every known secret value in `text` with `[redacted]`; return the text and the number replaced.

    Examples:
        >>> scrub("key=abc123 ok", ["abc123"])
        ('key=[redacted] ok', 1)
    """
    count = 0
    for value in sorted({s for s in secrets if len(s) >= 4}, key=len, reverse=True):  # noqa: PLR2004 - no tiny values
        found = text.count(value)
        if found:
            count += found
            text = text.replace(value, "[redacted]")
    return text, count


class StreamScrubber:
    """Scrubs secrets from a stream, keeping back enough bytes to catch a secret split across two chunks."""

    def __init__(self, secrets: list[str]) -> None:
        self._secrets = [s.encode() for s in secrets if len(s) >= 4]  # noqa: PLR2004
        self._keep = max((len(s) for s in self._secrets), default=1) - 1
        self._held = b""

    def feed(self, chunk: bytes) -> bytes:
        """Return what can be sent now; the tail that could start a secret is held back."""
        data = self._held + chunk
        for secret in self._secrets:
            data = data.replace(secret, b"[redacted]")
        cut = max(0, len(data) - self._keep)
        out, self._held = data[:cut], data[cut:]
        return out

    def finish(self) -> bytes:
        """Return the held tail at the end of the stream."""
        out, self._held = self._held, b""
        return out


def digest(value: object) -> str:
    """SHA-256 of a JSON value, for the audit log (the value itself is not stored)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _dump(data: dict[str, object]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@invariant(never_contains(Secret), dry_run=True)
def response_body(call: Call) -> str:
    """The JSON the agent receives."""
    return _dump(
        {
            "request_id": call.request_id,
            "allow": call.allow,
            "reason": call.reason,
            "error": call.error,
            "output": call.output if call.allow else f"refused by policy: {call.reason}",
        }
    )


@invariant(never_contains(Secret), dry_run=True)
def error_body(request_id: str, status: int, message: str, secret: Secret[str] | None = None) -> str:  # noqa: ARG001
    """The JSON for a request the gateway could not handle. `secret` is in the signature only for the promise."""
    return _dump({"request_id": request_id, "allow": False, "reason": message, "status": status})


@invariant(never_contains(Secret), dry_run=True)
def audit_entry(call: Call) -> str:
    """One audit record: who, what, the decision and why. Argument values only as hashes."""
    return _dump(
        {
            "ts": call.ts,
            "request_id": call.request_id,
            "agent": call.agent,
            "tool": call.tool,
            "decision": "allow" if call.allow else "deny",
            "reason": call.reason,
            "args": call.arg_hashes,
            "policy": call.policy_hash,
        }
    )


@invariant(never_contains(Secret), dry_run=True)
def observability_entry(call: Call) -> str:
    """One observability record: timing, sizes and outcome, no content."""
    return _dump(
        {
            "ts": call.ts,
            "ms": call.ms,
            "request_id": call.request_id,
            "session": call.session,
            "client": call.client,
            "step": call.step,
            "agent": call.agent,
            "model": call.model,
            "tool": call.tool,
            "decision": "allow" if call.allow else "deny",
            "reason": call.reason,
            "args": {name: {"bytes": size} for name, size in call.arg_sizes.items()},
            "output": {
                "bytes": call.output_bytes,
                "truncated": call.truncated,
                "scrubbed": call.scrubbed,
                "redacted": call.redacted,
            },
            "error": call.error,
        }
    )


@invariant(never_contains(Secret), dry_run=True)
def developer_entry(level: str, event: str, detail: str, secret: Secret[str] | None = None) -> str:  # noqa: ARG001
    """One developer log record. Never carries argument values; `secret` is in the signature only for the promise."""
    return _dump({"level": level, "event": event, "detail": detail})
