"""The one tool airlock ships: download a page from an allowed host, through the egress proxy.

For hosts that need a credential the gateway adds it from the secret store (`credentials`); the agent never
sees it. The policy decides which hosts the agent may name; the egress proxy checks the host again.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from tesseraline_airlock.egress import EgressRefusedError, normalise
from tesseraline_airlock.tools import Tool, ToolContext


@dataclass(frozen=True, slots=True)
class HostCredential:
    """A header the gateway adds for one host, from a named secret. `template` holds `{secret}`."""

    header: str
    secret: str
    template: str = "{secret}"


def make_fetch(credentials: Mapping[str, HostCredential] | None = None, limit: int = 4000) -> Tool:
    """Build the `fetch` tool. `credentials` maps a host (`name` or `name:port`) to the header it gets."""
    table = dict(credentials or {})

    def prepare(args: dict[str, object]) -> dict[str, object]:
        target = normalise(str(args.get("url", "")))
        return {"url": target.url, "host": target.authority}

    def fetch(args: Mapping[str, object], context: ToolContext) -> str:
        """Download a page over https from an allowed host."""
        try:
            target = normalise(str(args.get("url", "")))
        except EgressRefusedError as error:
            return f"fetch refused: {error}"
        headers = {"User-Agent": "airlock-fetch", "Accept": "text/html, text/plain, application/json"}
        credential = table.get(target.authority)
        if credential is not None:
            headers[credential.header] = credential.template.format(secret=context.secret(credential.secret))
        try:
            reply = context.egress.fetch("GET", target, headers, limit=limit)
        except EgressRefusedError as error:
            return f"fetch refused: {error}"
        except OSError as error:
            return f"fetch failed: {type(error).__name__}"
        if reply.status == 403 and reply.headers.get("x-airlock-egress") == "denied":  # noqa: PLR2004
            return "fetch refused by the egress policy"
        text = reply.body.decode("utf-8", "replace")
        return f"HTTP {reply.status}\n{text}" + ("\n[cut]" if reply.truncated else "")

    schema: dict[str, object] = {
        "type": "object",
        "properties": {"url": {"type": "string", "description": "An https URL on a host the policy allows."}},
        "required": ["url"],
        "additionalProperties": False,
    }
    return Tool("fetch", fetch, "Download a page over https from an allowed host.", prepare, schema)
