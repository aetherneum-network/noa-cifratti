"""Shared helpers of the scenario checks (standard library only, no network, no clock).

Every scenario folder holds ``scenario.json`` (how to run it), ``input/`` (seed, reference date and
fixtures), ``expected/`` (the exact output), ``check.py`` and a one-paragraph ``run.md``. A check
runs the real tool on the input, compares the result with ``expected/`` byte for byte and then
asserts the scenario's pass condition in plain code, so that a wrong ``expected`` file cannot pass.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus import fakes  # noqa: E402
from corpus.gitwrite import RepoWriter  # noqa: E402
from corpus.world import BY_KEY, EPOCH_BASE, TZ, author  # noqa: E402
from noascan import report as nreport  # noqa: E402

UPDATE = "--update" in sys.argv          # author only: rewrite expected/ from the current output


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ext(p: Path) -> str:
    s = os.path.abspath(str(p))
    return "\\\\?\\" + s if os.name == "nt" and not s.startswith("\\\\?\\") else s


WORK_ROOT = ROOT / "build" / "scenarios"   # tools/rebuild.py points this elsewhere to rebuild in another folder


def workdir(sid: str) -> Path:
    """A fresh directory under the pack's own build/ (ignored by git, never outside the repository)."""
    p = WORK_ROOT / sid
    if p.exists():
        shutil.rmtree(_ext(p))
    p.mkdir(parents=True)
    return p


def rng(sid: str, seed: int, what: str) -> random.Random:
    return random.Random(f"noa-scenario/v1/{sid}/{seed}/{what}")


def fake(sid: str, seed: int, cls: str, n: int = 0, domain: str = "corp.example") -> str:
    """An inert planted value of class ``cls``: a pure function of the scenario id and its seed."""
    return fakes.make(cls, rng(sid, seed, f"{cls}/{n}"), domain)


def fake_uri(sid: str, seed: int, domain: str, n: int = 0) -> tuple[str, str]:
    return fakes.connection_uri(rng(sid, seed, f"uri/{n}"), domain)


def build_repo(root: Path, company: str, commits: list[tuple[str, dict[str, bytes | str]]], offset: int = 0) -> list[str]:
    """Write a linear history on ``main`` and check out the last snapshot. Returns the commit ids."""
    w = RepoWriter(root)
    ids: list[str] = []
    snapshot: dict[str, bytes] = {}
    for i, (message, files) in enumerate(commits):
        snapshot = {p: (d.encode("utf-8") if isinstance(d, str) else d) for p, d in files.items()}
        name, email = author(BY_KEY[company], i)
        ids.append(w.commit(w.tree(snapshot), ids[-1:], name, email, EPOCH_BASE + offset + i * 5400, TZ, message))
    w.ref("refs/heads/main", ids[-1])
    w.checkout(snapshot)
    return ids


def expect(path: Path, actual: Any, failures: list[str]) -> None:
    """Compare ``actual`` with the committed expected file, byte for byte."""
    text = nreport.dumps(actual)
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
        return
    if not path.is_file():
        failures.append(f"missing expected file {path.name}")
    elif path.read_bytes().replace(b"\r\n", b"\n") != text.encode("ascii"):
        failures.append(f"output differs from expected/{path.name}")


def result(sid: str, failures: list[str], line: str, details: dict[str, Any] | None = None) -> tuple[bool, str, dict]:
    ok = not failures
    text = f"{sid} {'PASS' if ok else 'FAIL'} - {line}" + ("" if ok else " | " + "; ".join(failures))
    return ok, text, details or {}


def main(check: Callable[[], tuple[bool, str, dict]]) -> None:
    try:
        ok, line, _ = check()
    except Exception as exc:                    # a crashing check is a failing check
        ok, line = False, f"FAIL - {type(exc).__name__}: {exc}"
    print(line.encode("ascii", "replace").decode("ascii"))
    sys.exit(0 if ok else 1)
