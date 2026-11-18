"""An optional hook for personal data.

Airlock ships no detector. `Redactor` is a Protocol, so a detector you already trust (a PII library, a service in
your network) is a class with one method. Without one, nothing changes.

The redactor runs on tool output and on complete model answers, after the secrets are removed. Streamed model
answers pass without it, because a name or number can be split across chunks.
"""

from __future__ import annotations

from typing import Protocol


class Redactor(Protocol):
    """Removes personal data from text."""

    def redact(self, text: str) -> tuple[str, int]:
        """Return the text with personal data replaced, and how many items were replaced."""
        ...
