"""Tools live in the gateway. A tool is a function marked `@tool`; the agent can only ask for it by name."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tesseraline_airlock.egress import Egress
    from tesseraline_airlock.secrets import SecretStore


@dataclass(frozen=True, slots=True)
class ToolContext:
    """What a running tool may use: the egress client and the secret store, nothing else of the gateway."""

    egress: Egress
    store: SecretStore
    used_secrets: list[str] = field(default_factory=list)  # values the tool read; scrubbed from its output

    def secret(self, name: str) -> str:
        """Read a secret for this call; its value is scrubbed from the tool's output."""
        value = self.store.get(name).value
        self.used_secrets.append(value)
        return value


ToolFunction = Callable[[Mapping[str, object], ToolContext], str]
Prepare = Callable[[dict[str, object]], dict[str, object]]


@dataclass(frozen=True, slots=True)
class Tool:
    """A registered tool."""

    name: str
    function: ToolFunction
    description: str = ""
    prepare: Prepare | None = None  # normalises the arguments once; the policy and the tool see the result


def tool(
    name: str | None = None, *, description: str = "", prepare: Prepare | None = None
) -> Callable[[ToolFunction], Tool]:
    """Mark a function as a tool. The function gets the arguments and a `ToolContext` and returns text.

    `prepare` may normalise the arguments (raise `ValueError` to refuse them); the policy is asked about the
    prepared arguments and the tool receives the same.
    """

    def wrap(function: ToolFunction) -> Tool:
        return Tool(name or function.__name__, function, description or (function.__doc__ or "").strip(), prepare)

    return wrap


def load(module: str) -> list[Tool]:
    """Every `Tool` defined at the top level of `module` (as given to `airlock serve --tools`)."""
    loaded = importlib.import_module(module)
    return [value for value in vars(loaded).values() if isinstance(value, Tool)]
