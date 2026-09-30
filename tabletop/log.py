"""Append-only, hash-chained event log (JSON lines).

Each event carries ``seq``, ``prev_hash`` and ``hash`` (SHA-256 of its canonical JSON without the
``hash`` key). The file is only ever opened for reading or for appending: there is no function here
that rewrites or truncates it. Editing a past line breaks the chain, and the judge reports where.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ZERO = "0" * 64


def canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def event_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({k: v for k, v in event.items() if k != "hash"})).hexdigest()


def read(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def broken_links(events: list[dict[str, Any]]) -> list[int]:
    """Indexes of the events whose hash, previous hash or sequence number does not hold."""
    bad, prev = [], ZERO
    for i, ev in enumerate(events):
        if ev.get("seq") != i + 1 or ev.get("prev_hash") != prev or ev.get("hash") != event_hash(ev):
            bad.append(i)
        prev = ev.get("hash", "")
    return bad


class Log:
    def __init__(self, path: Path):
        self.path = path

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        events = read(self.path) if self.path.exists() else []
        ev = dict(event, seq=len(events) + 1, prev_hash=events[-1]["hash"] if events else ZERO)
        ev["hash"] = event_hash(ev)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(ev, sort_keys=True, ensure_ascii=True) + "\n")
        return ev
