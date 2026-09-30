"""Scripted tabletop transcripts: clean, or with one or two planted procedure violations.

The generator writes the hash chain with its own few lines (it does not import ``tabletop/``), so the
judge's chain verification is checked against an independent writer. Gold is the hand-written table
``FAULTS`` below: fault -> the violations a reader of the playbook would expect. It is not derived
from the judge.
"""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from corpus.world import COMPANIES

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOKS = ["compromised_key", "rogue_container", "leaked_endpoint"]
ZERO = "0" * 64

# fault -> list of (code, step) expected. "-" as step = the log as a whole.
FAULTS = {
    "compromised_key": {
        "rotated_not_revoked": [("ROTATED_NOT_REVOKED", "revoke_old_key")],
        "skip_inventory": [("STEP_SKIPPED", "inventory_usages")],
        "rotate_before_quorum": [("ORDER_VIOLATED", "rotate_key")],
        "quorum_short": [("QUORUM_NOT_MET", "assemble_quorum")],
        "evidence_missing": [("EVIDENCE_MISSING", "revoke_old_key")],
        "identifier_transposed": [("IDENTIFIER_MISMATCH", "revoke_old_key")],
    },
    "rogue_container": {
        "restart_before_preserve": [("EVIDENCE_DESTROYED", "restart_container")],
        "skip_preserve": [("STEP_SKIPPED", "preserve_evidence"), ("EVIDENCE_DESTROYED", "restart_container")],
        "no_consent": [("CONSENT_MISSING", "restart_container")],
        "skip_isolate": [("STEP_SKIPPED", "isolate_network")],
        "evidence_missing": [("EVIDENCE_MISSING", "preserve_evidence")],
    },
    "leaked_endpoint": {
        "identifier_transposed": [("IDENTIFIER_MISMATCH", "handoff_to_owner")],
        "skip_verify": [("STEP_SKIPPED", "verify_from_outside")],
        "all_clear_before_verify": [("ORDER_VIOLATED", "all_clear")],
        "evidence_missing": [("EVIDENCE_MISSING", "close_exposure")],
    },
}
SECOND_FAULTS = ["first_step_evidence_missing", "chain_tampered"]


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def chain(events: list[dict]) -> list[dict]:
    prev = ZERO
    out = []
    for seq, ev in enumerate(events, 1):
        ev = dict(ev, seq=seq, prev_hash=prev)
        ev["hash"] = hashlib.sha256(canonical(ev)).hexdigest()
        prev = ev["hash"]
        out.append(ev)
    return out


def transpose(identifier: str) -> str:
    """Swap two adjacent digits (the classic hand-off slip): EP-4172 -> EP-4712."""
    head, digits = identifier.rsplit("-", 1)
    i = next(i for i in range(len(digits) - 1) if digits[i] != digits[i + 1])
    return f"{head}-{digits[:i]}{digits[i + 1]}{digits[i]}{digits[i + 2:]}"


def _subject(rng: random.Random, playbook: str) -> str:
    prefix = {"compromised_key": "K", "rogue_container": "CT", "leaked_endpoint": "EP"}[playbook]
    while True:
        digits = "".join(rng.choice("0123456789") for _ in range(4))
        if len(set(digits)) > 1:
            return f"{prefix}-{digits}"


def build(seed: int, idx: int, as_of: str) -> tuple[list[dict], dict]:
    """Return (events, gold) for transcript ``idx``."""
    rng = random.Random(f"noa-corpus/v1/{seed}/tabletop/{idx}")
    playbook = PLAYBOOKS[idx % len(PLAYBOOKS)]
    pb = json.loads((ROOT / "playbooks" / f"{playbook}.json").read_text(encoding="utf-8"))
    company = COMPANIES[(idx // len(PLAYBOOKS)) % len(COMPANIES)]
    subject = _subject(rng, playbook)
    faults: list[str] = []
    if rng.random() >= 0.42:
        faults.append(rng.choice(sorted(FAULTS[playbook])))
        if rng.random() < 0.2:
            faults.append(rng.choice(SECOND_FAULTS))
    first = pb["steps"][0]["id"]
    start = datetime.fromisoformat(as_of) - timedelta(days=rng.randrange(1, 20), minutes=rng.randrange(0, 600))

    events = []
    for step in pb["steps"]:
        ev = {"actor": f"{step['role']}@{company['domain']}", "step": step["id"],
              "subject": {pb["subject_field"]: subject}, "evidence": list(step["evidence"])}
        if "quorum" in step:
            n = 2 if "quorum_short" in faults else rng.choice([3, 3, 4])
            ev["approvals"] = [f"custodian-{k}@{company['domain']}" for k in sorted(rng.sample(range(1, 6), n))]
        if step.get("destructive") and "no_consent" not in faults:
            ev["consent"] = {"by": f"human:approver@{company['domain']}", "for": step["id"]}
        events.append(ev)

    def drop(step_id: str) -> None:
        events[:] = [e for e in events if e["step"] != step_id]

    def move_before(step_id: str, other: str) -> None:
        ev = next(e for e in events if e["step"] == step_id)
        events.remove(ev)
        events.insert(next(i for i, e in enumerate(events) if e["step"] == other), ev)

    def event(step_id: str) -> dict:
        return next(e for e in events if e["step"] == step_id)

    expected: list[tuple[str, str]] = []
    for fault in faults:
        if fault in FAULTS[playbook]:
            expected += FAULTS[playbook][fault]
        if fault == "rotated_not_revoked":
            drop("revoke_old_key")
        elif fault == "skip_inventory":
            drop("inventory_usages")
        elif fault == "rotate_before_quorum":
            move_before("rotate_key", "assemble_quorum")
        elif fault == "evidence_missing":
            step_id = FAULTS[playbook][fault][0][1]
            event(step_id)["evidence"] = event(step_id)["evidence"][:-1]
        elif fault == "identifier_transposed":
            step_id = FAULTS[playbook][fault][0][1]
            event(step_id)["subject"] = {pb["subject_field"]: transpose(subject)}
        elif fault == "restart_before_preserve":
            move_before("restart_container", "preserve_evidence")
        elif fault == "skip_preserve":
            drop("preserve_evidence")
        elif fault == "skip_isolate":
            drop("isolate_network")
        elif fault == "skip_verify":
            drop("verify_from_outside")
        elif fault == "all_clear_before_verify":
            move_before("all_clear", "verify_from_outside")
        elif fault == "first_step_evidence_missing":
            event(first)["evidence"] = []
            expected.append(("EVIDENCE_MISSING", first))

    for i, ev in enumerate(events):
        ev["at"] = (start + timedelta(minutes=7 * i)).isoformat()
        if "consent" in ev:
            ev["consent"]["at"] = (start + timedelta(minutes=7 * i - 2)).isoformat()
    chained = chain(events)
    if "chain_tampered" in faults:
        victim = chained[rng.randrange(1, len(chained))]
        victim["at"] = (datetime.fromisoformat(victim["at"]) + timedelta(minutes=1)).isoformat()  # edited after the fact
        expected.append(("LOG_CHAIN_BROKEN", victim["step"]))
    gold = {"transcript": f"T{idx:03d}", "playbook": playbook, "company": company["key"], "faults": faults,
            "expected_verdict": "FAILED" if expected else "PASSED",
            "expected_violations": sorted([list(v) for v in set(expected)])}
    return chained, gold


def write(events: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for ev in events:
            fh.write(json.dumps(ev, sort_keys=True, ensure_ascii=True) + "\n")
