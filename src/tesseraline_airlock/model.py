"""The model route: the agent talks to a model behind a provider's API without holding the key.

`POST /v1/model/<route>/<path>` is checked by the policy like a tool call (tool `model:<route>`), then passed to
the route's upstream through the egress proxy with the key added from the secret store. Requests and answers pass
through unchanged, streaming included; the gateway reads the model name and token counts on the way.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from tesseraline_airlock.egress import Target, normalise

DEFAULT_FORWARD = ("content-type", "accept")


@dataclass(frozen=True, slots=True)
class ModelRoute:
    """One upstream model API. `template` holds `{secret}`; `forward` lists the agent's headers passed on."""

    name: str
    upstream: str
    secret: str
    header: str = "authorization"
    template: str = "Bearer {secret}"
    forward: tuple[str, ...] = DEFAULT_FORWARD
    extra: dict[str, str] = field(default_factory=dict)

    def target(self, path: str) -> Target:
        """The upstream URL for `path`, normalised."""
        return normalise(self.upstream.rstrip("/") + "/" + path.lstrip("/"))

    def headers(self, incoming: dict[str, str], key: str) -> dict[str, str]:
        """Headers sent upstream: the allowed ones from the agent, fixed extras and the key."""
        sent = {name: value for name, value in incoming.items() if name.lower() in self.forward}
        sent.update(self.extra)
        sent[self.header] = self.template.format(secret=key)
        return sent


class UsageReader:
    """Collects the model name and token counts from a JSON answer or a stream of server-sent events."""

    def __init__(self) -> None:
        self.model = ""
        self.input_tokens = 0
        self.output_tokens = 0
        self._buffer = b""

    def _take(self, data: object) -> None:
        if not isinstance(data, dict):
            return
        for holder in (data, data.get("message")):
            if isinstance(holder, dict):
                if isinstance(holder.get("model"), str):
                    self.model = holder["model"]
                usage = holder.get("usage")
                if isinstance(usage, dict):
                    self.input_tokens = int(
                        usage.get("input_tokens", usage.get("prompt_tokens", self.input_tokens)) or 0
                    )
                    self.output_tokens = int(
                        usage.get("output_tokens", usage.get("completion_tokens", self.output_tokens)) or 0
                    )

    def feed_stream(self, chunk: bytes) -> None:
        """Read `data:` lines of server-sent events as they pass."""
        self._buffer = (self._buffer + chunk)[-65_536:]
        *lines, self._buffer = self._buffer.split(b"\n")
        for line in lines:
            if line.startswith(b"data:") and b"{" in line:
                try:
                    self._take(json.loads(line[5:].strip()))
                except ValueError:
                    continue

    def feed_json(self, body: bytes) -> None:
        """Read a complete JSON answer."""
        try:
            self._take(json.loads(body))
        except ValueError:
            return

    def as_dict(self) -> dict[str, object]:
        """The fields for the observability record."""
        return {
            "name": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "measured": True,
        }


def load_routes(config: dict[str, object]) -> dict[str, ModelRoute]:
    """Model routes from the gateway's JSON configuration (`model_routes`)."""
    routes: dict[str, ModelRoute] = {}
    raw = config.get("model_routes", {})
    if not isinstance(raw, dict):
        return routes
    for name, spec in raw.items():
        routes[name] = ModelRoute(
            name=name,
            upstream=spec["upstream"],
            secret=spec["secret"],
            header=spec.get("header", "authorization"),
            template=spec.get("template", "Bearer {secret}"),
            forward=tuple(h.lower() for h in spec.get("forward", DEFAULT_FORWARD)),
            extra=dict(spec.get("extra_headers", {})),
        )
    return routes
