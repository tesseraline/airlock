"""Tools live in the gateway. A tool is a function marked `@tool`; the agent can only ask for it by name."""

from __future__ import annotations

import importlib
import re
import unicodedata
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
    schema: dict[str, object] = field(default_factory=lambda: {"type": "object"})  # JSON Schema of the arguments


def tool(
    name: str | None = None,
    *,
    description: str = "",
    prepare: Prepare | None = None,
    schema: dict[str, object] | None = None,
) -> Callable[[ToolFunction], Tool]:
    """Mark a function as a tool. The function gets the arguments and a `ToolContext` and returns text.

    `prepare` may normalise the arguments (raise `ValueError` to refuse them); the policy is asked about the
    prepared arguments and the tool receives the same. `schema` describes the arguments for MCP clients.
    """

    def wrap(function: ToolFunction) -> Tool:
        text = description or (function.__doc__ or "").strip()
        return Tool(name or function.__name__, function, text, prepare, schema or {"type": "object"})

    return wrap


MAX_DESCRIPTION = 1000


TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_LINES = 12


def _check_text(where: str, text: str) -> None:
    folded = unicodedata.normalize("NFKC", text)  # fullwidth and similar look-alikes become their plain form
    if len(text) > MAX_DESCRIPTION:
        raise ValueError(f"{where}: longer than {MAX_DESCRIPTION} characters")
    if text.count("\n") >= MAX_LINES:
        raise ValueError(f"{where}: more than {MAX_LINES} lines")
    if any(not c.isprintable() and c != "\n" for c in text):
        raise ValueError(f"{where}: control characters")
    if any(c in folded for c in "<>`") or any(line.lstrip().startswith("#") for line in folded.splitlines()):
        raise ValueError(f"{where}: markup")


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def check_description(t: Tool) -> None:
    """Refuse a tool whose name, description or argument schema could carry instructions in disguise (threat M2).

    The name must be letters, digits, `_`, `-` or `.`. Every string in the description and the schema is checked
    after Unicode folding: no control characters, no markup (`<`, `>`, backticks, Markdown headings), at most
    MAX_DESCRIPTION characters and MAX_LINES lines. A failure raises ValueError, so the gateway does not start.
    """
    if not TOOL_NAME.match(t.name):
        raise ValueError(f"tool {t.name[:64]!r}: name must be letters, digits, '_', '-' or '.'")
    _check_text(f"tool {t.name}: description", t.description)
    for text in _strings(t.schema):
        _check_text(f"tool {t.name}: schema", text)


def load(module: str) -> list[Tool]:
    """Every `Tool` defined at the top level of `module` (as given to `airlock serve --tools`)."""
    loaded = importlib.import_module(module)
    return [value for value in vars(loaded).values() if isinstance(value, Tool)]
