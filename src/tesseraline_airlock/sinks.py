"""Where log records go. `Sink` is a Protocol: a sink for Loki, OTLP or anything else is one class with `write`.

The gateway writes three logs, each to its own sink: developer, audit and observability. A record is a plain
dict that is already free of secrets.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Protocol


class Sink(Protocol):
    """Takes one log record."""

    def write(self, record: dict[str, object]) -> None:
        """Store `record`. Raise when it could not be stored (the audit log depends on that)."""
        ...


class NullSink:
    """Drops every record."""

    def write(self, record: dict[str, object]) -> None:
        """Do nothing."""


class MemorySink:
    """Keeps records in a list; for tests."""

    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def write(self, record: dict[str, object]) -> None:
        """Append `record`."""
        self.records.append(record)


class JsonlSink:
    """Appends one JSON line per record to a file. With `sync=True` each line is flushed to disk before returning."""

    def __init__(self, path: str | Path, *, sync: bool = False) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._sync = sync
        self._lock = threading.Lock()

    def write(self, record: dict[str, object]) -> None:
        """Append `record` as one line in a single write.

        If the write or the sync fails, the file is cut back to where it was, so a failed record leaves no partial
        line, and the error is raised.
        """
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()
        with self._lock:
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                start = os.fstat(fd).st_size
                try:
                    if os.write(fd, line) != len(line):
                        raise OSError("short write")  # noqa: TRY301 - handled by the cut-back below
                    if self._sync:
                        os.fsync(fd)
                except OSError:
                    with contextlib.suppress(OSError):
                        os.ftruncate(fd, start)
                    raise
            finally:
                os.close(fd)


class HashChainSink:
    """Adds `prev` (the hash of the previous record) and `hash` to each record, then writes it to `inner`.

    A removed or altered record breaks the chain, which `verify_chain` shows. The chain continues across restarts
    when the last hash of the existing file is passed as `last`.
    """

    def __init__(self, inner: Sink, last: str = "") -> None:
        self._inner = inner
        self._last = last
        self._lock = threading.Lock()

    def write(self, record: dict[str, object]) -> None:
        """Chain and write `record`; the chain advances only when the write succeeds."""
        with self._lock:
            chained = {**record, "prev": self._last}
            digest = hashlib.sha256(json.dumps(chained, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self._inner.write({**chained, "hash": digest})
            self._last = digest


def last_hash(path: str | Path) -> str:
    """The `hash` of the last record in a JSON Lines audit file, or "" for a new file."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return ""
    if not lines:
        return ""
    try:
        return str(json.loads(lines[-1])["hash"])
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"the last line of {path} is not an audit record; run `airlock audit verify`") from error


def verify_chain(path: str | Path) -> tuple[bool, int]:
    """Check an audit file's chain. Returns (intact, number of the first bad line or of lines read)."""
    previous = ""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
            digest = record.pop("hash", "")
        except (ValueError, AttributeError):
            return False, number
        if record.get("prev") != previous:
            return False, number
        if hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != digest:
            return False, number
        previous = digest
    return True, len(lines)
