"""Scripted tabletop runner: plays a script of actions against a playbook and writes the log.

The roles are scripted (a JSON file); no model plays them. The runner is deliberately not the
judge: it records what the script does, in order, with the timestamps of the script (never the
clock). It refuses exactly two things, and logs the refusal instead of the step:

* a destructive step without the recorded consent of a human (``consent.by`` = ``human:...``,
  ``consent.for`` = the step) - an agent does not authorise its own irreversible action;
* a destructive step while the evidence-preserving step it depends on is not in the log.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tabletop import log as tlog
from tabletop.judge import human_consent


def run(playbook: dict[str, Any], script: dict[str, Any], out: Path) -> dict[str, Any]:
    """Play ``script`` and append to the log at ``out``. Returns a summary (executed / refused)."""
    steps = {s["id"]: s for s in playbook["steps"]}
    log = tlog.Log(out)
    done: set[str] = set()
    executed, refused = [], []
    for action in script["actions"]:
        step_id = action.get("step", "")
        base = {"actor": action.get("actor", ""), "step": step_id, "at": action.get("at", ""),
                "subject": {playbook["subject_field"]: action.get("subject", script.get("subject", ""))}}
        step = steps.get(step_id)
        reason = ""
        if step is None:
            reason = "UNKNOWN_STEP"
        elif step.get("destructive") and not human_consent(action, step_id):
            reason = "CONSENT_MISSING"
        elif step.get("destructive") and any(steps[p].get("preserves_evidence") and p not in done for p in step["requires"]):
            reason = "EVIDENCE_NOT_PRESERVED"
        if reason:
            log.append(dict(base, type="refused", reason=reason))
            refused.append({"step": step_id, "reason": reason})
            continue
        event = dict(base, evidence=list(action.get("evidence", [])))
        for key in ("approvals", "consent", "artifacts"):
            if key in action:
                event[key] = action[key]
        log.append(event)
        done.add(step_id)
        executed.append(step_id)
    return {"executed": executed, "refused": refused}


def load_script(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
