"""Gold labels: what the seeding plan says was planted, written without any secret value.

``fingerprint`` is a deliberate second copy of the scanner's definition (``noascan/fingerprint.py``):
the generator does not import the scanner. A test checks that the two agree.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from corpus.repos import RepoPlan


def fingerprint(value: str) -> str:
    return hashlib.sha256(b"noascan/fp/v1\x00" + value.encode("utf-8")).hexdigest()[:16]


def block_fingerprint(value: str) -> str:
    """Key blocks are fingerprinted on their stripped lines, so indentation does not matter."""
    return fingerprint("\n".join(line.strip() for line in value.split("\n")))


def expected_verdict(plan: RepoPlan) -> tuple[str, list[str]]:
    """The verdict the declared policy requires, from the plan alone: (expected, acceptable)."""
    secrets = [p for p in plan.plants if p.kind == "secret"]
    defects = [p for p in plan.plants if p.kind in ("config", "pycode")]
    if any(p.covered for p in secrets) or any(p.severity in ("high", "critical") for p in defects):
        return "BLOCKED", ["BLOCKED"]
    hidden = any(not p.covered for p in secrets)
    if any(p.severity == "medium" for p in defects):
        return "NEEDS_REVIEW", ["NEEDS_REVIEW", "BLOCKED"] if hidden else ["NEEDS_REVIEW"]
    if any(p.kind == "boundary" for p in plan.plants):
        # a best-effort hit inside an unreadable carrier may legitimately raise the verdict
        return "NOT_COVERED", ["NOT_COVERED", "NEEDS_REVIEW", "BLOCKED"] if hidden else ["NOT_COVERED"]
    if hidden:  # out-of-coverage technique: nothing is promised, anything but a wrong claim is acceptable
        return "UNSPECIFIED", ["BLOCKED", "NEEDS_REVIEW", "NOT_COVERED", "CLEAN"]
    return "CLEAN", ["CLEAN"]


def repo_record(plan: RepoPlan) -> dict:
    expected, acceptable = expected_verdict(plan)
    secrets = [p for p in plan.plants if p.kind == "secret"]
    return {"repo": plan.name, "company": plan.company, "archetype": plan.archetype, "head": plan.head,
            "refs": dict(sorted(plan.refs.items())), "commits": len(plan.commits),
            "has_covered_secret": any(p.covered for p in secrets),
            "has_uncovered_secret": any(not p.covered for p in secrets),
            "has_boundary_file": any(p.kind == "boundary" for p in plan.plants),
            "expected_verdict": expected, "acceptable_verdicts": acceptable}


def label_records(plan: RepoPlan) -> list[dict]:
    out = []
    for p in plan.plants:
        rec = {"repo": plan.name, "kind": p.kind, "class": p.cls, "path": p.path, "line": p.line,
               "decoy": p.kind == "decoy", "covered": p.covered, "technique": p.technique, "in_head": p.in_head}
        if p.kind in ("config", "pycode"):
            rec.update(severity=p.severity, subject=p.subject)
        if p.kind == "secret":
            fp = block_fingerprint(p.value) if p.cls == "armored_key_block" else fingerprint(p.value)
            rec.update(severity=p.severity, carrier=p.carrier, first_commit=p.first_commit, first_line=p.first_line,
                       blob=p.blob, fingerprint=fp)
        out.append(rec)
    return out


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=True) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
