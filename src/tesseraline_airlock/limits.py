"""Counts calls per agent and tool over the last hour. The policy compares the count with its limit."""

from __future__ import annotations

import contextlib
import threading
import time
from collections import defaultdict, deque


class CallCounter:
    """A sliding one-hour window per (agent, tool). Kept in memory; a restart clears it."""

    def __init__(self, window: float = 3600.0) -> None:
        self._window = window
        self._calls: defaultdict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def count(self, agent: str, tool: str, now: float | None = None) -> int:
        """Calls of `tool` by `agent` within the window (creates no entry)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            calls = self._calls.get((agent, tool))
            if not calls:
                return 0
            while calls and calls[0] <= now - self._window:
                calls.popleft()
            return len(calls)

    def reserve(self, agent: str, tool: str, now: float | None = None) -> tuple[int, float]:
        """Count the calls so far and hold a place for this one, in one step, so parallel calls see each other.

        Returns the count before this call and the token to `release` if the call is refused.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            calls = self._calls[(agent, tool)]
            while calls and calls[0] <= now - self._window:
                calls.popleft()
            before = len(calls)
            calls.append(now)
            return before, now

    def release(self, agent: str, tool: str, token: float) -> None:
        """Give back a held place (the call was refused)."""
        with self._lock:
            calls = self._calls.get((agent, tool))
            if calls is not None:
                with contextlib.suppress(ValueError):
                    calls.remove(token)
                if not calls:
                    del self._calls[(agent, tool)]


class TokenMeter:
    """Model tokens per agent over the last hour, as measured on the model route.

    The policy compares the sum with the agent's budget before the next model request.
    """

    def __init__(self, window: float = 3600.0) -> None:
        self._window = window
        self._used: dict[str, deque[tuple[float, int]]] = {}
        self._lock = threading.Lock()

    def used(self, agent: str, now: float | None = None) -> int:
        """Tokens `agent` used within the window."""
        now = time.monotonic() if now is None else now
        with self._lock:
            entries = self._used.get(agent)
            if not entries:
                return 0
            while entries and entries[0][0] <= now - self._window:
                entries.popleft()
            return sum(n for _, n in entries)

    def add(self, agent: str, tokens: int, now: float | None = None) -> None:
        """Record the tokens of one finished model request."""
        if tokens > 0:
            with self._lock:
                self._used.setdefault(agent, deque()).append((time.monotonic() if now is None else now, tokens))
