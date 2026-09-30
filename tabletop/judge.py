"""Judge a tabletop transcript against its playbook.

    python -m tabletop.judge TRANSCRIPT.jsonl --playbook NAME --as-of ISO [--artifacts DIR] [--json OUT]

The playbook (``playbooks/*.json``) says what must happen; ``rules/judge.json`` says, in order, how
a departure is named. The judge reads the transcript and nothing else: it does not run anything.
A transcript with at least one violation is FAILED and its closing step is BLOCKED.

Exit code 0 = PASSED, 1 = FAILED, 64 = usage or unreadable input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from noascan import __version__, report, rules_engine  # noqa: E402
from noascan.secrets import SecretRules  # noqa: E402
from tabletop import log as tlog  # noqa: E402


def load_playbook(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "playbooks" / f"{name}.json").read_text(encoding="utf-8"))


def human_consent(event: dict[str, Any], step_id: str) -> bool:
    consent = event.get("consent")
    return (isinstance(consent, dict) and str(consent.get("by", "")).startswith("human:")
            and consent.get("for") == step_id)


def _predicates(playbook: dict[str, Any], pos: dict[str, int], events: list[dict[str, Any]]):
    steps = {s["id"]: s for s in playbook["steps"]}
    paired = {inv["then"]: inv for inv in playbook.get("invariants", []) if inv.get("type") == "paired"}

    def ev(step: dict[str, Any]) -> dict[str, Any]:
        return events[pos[step["id"]]]

    def quorum_short(step: dict[str, Any]) -> bool:
        q = step.get("quorum")
        if not q or step["id"] not in pos:
            return False
        distinct = {a for a in ev(step).get("approvals", []) if str(a).startswith(q["role_prefix"])}
        return len(distinct) < q["min_distinct"]

    def destroyed(step: dict[str, Any]) -> bool:
        if not step.get("destructive") or step["id"] not in pos:
            return False
        return any(steps[p].get("preserves_evidence") and (p not in pos or pos[p] > pos[step["id"]])
                   for p in step["requires"])

    return {
        "step_absent_but_its_pair_ran": lambda s: s["id"] not in pos and s["id"] in paired and paired[s["id"]]["first"] in pos,
        "step_absent": lambda s: s["id"] not in pos,
        "destructive_before_preservation": destroyed,
        "prerequisite_ran_later": lambda s: any(p in pos and pos[p] > pos[s["id"]] for p in s["requires"]),
        "destructive_without_human_consent": lambda s: bool(s.get("destructive")) and not human_consent(ev(s), s["id"]),
        "quorum_not_met": quorum_short,
        "evidence_incomplete": lambda s: bool(set(s["evidence"]) - set(ev(s).get("evidence", []))),
    }, paired


def judge(events: list[dict[str, Any]], playbook: dict[str, Any], as_of: str, *,
          rules: dict[str, Any] | None = None, artifacts: Path | None = None,
          secret_rules: SecretRules | None = None) -> dict[str, Any]:
    report.reference_date(as_of)
    rules = rules or rules_engine.load("judge")
    srules = secret_rules or SecretRules(rules_engine.load("secrets"))

    def safe(text: Any) -> str:
        return report.safe(str(text), srules)

    steps = playbook["steps"]
    order = {s["id"]: i for i, s in enumerate(steps)}
    executed = [i for i, e in enumerate(events) if e.get("type", "step") == "step"]
    pos: dict[str, int] = {}
    for i in executed:
        pos.setdefault(events[i].get("step", ""), i)
    predicates, paired = _predicates(playbook, pos, events)
    found: dict[tuple[str, str], dict[str, Any]] = {}

    def add(code: str, step: str, rule: str, detail: str, index: int | None = None) -> None:
        rec = found.setdefault((code, step), {"code": code, "step": safe(step), "rule": rule,
                                              "seq": events[index].get("seq") if index is not None else None,
                                              "details": []})
        rec["details"].append(safe(detail))

    # 1. the procedure, step by step: first matching rule wins ------------------------------------------------------
    for step in steps:
        for rule in rules["rules"]:
            test = predicates.get(rule["when"])
            if test is None:
                raise rules_engine.RuleError(f"judge: rule {rule['id']} uses an unknown condition {rule['when']!r}")
            if not test(step):
                continue
            code = paired[step["id"]]["code"] if rule.get("code_from") == "invariant" else rule["code"]
            detail = {"step_absent_but_its_pair_ran": f"{paired.get(step['id'], {}).get('first', '')} ran and this step never did",
                      "step_absent": "the step is not in the transcript",
                      "destructive_before_preservation": "a destructive step ran before the evidence was preserved",
                      "prerequisite_ran_later": "a prerequisite of this step ran after it",
                      "destructive_without_human_consent": "no recorded consent of a human for this destructive step",
                      "quorum_not_met": "fewer distinct custodians than the quorum requires",
                      "evidence_incomplete": "required evidence is missing: "
                                             + ", ".join(sorted(set(step["evidence"]) - set(events[pos[step["id"]]].get("evidence", []))))
                                             if step["id"] in pos else ""}[rule["when"]]
            add(code, step["id"], rule["id"], detail, pos.get(step["id"]))
            break
    for i in executed:
        if events[i].get("step") not in order:
            add("UNKNOWN_STEP", str(events[i].get("step")), "J-UNKNOWN-STEP", "the playbook has no such step", i)

    # 2. one subject from the opening to the closing: events and cited artifacts --------------------------------------
    field = playbook["subject_field"]
    code = next((inv["code"] for inv in playbook.get("invariants", []) if inv.get("type") == "same_subject"), None)
    reference, ref_source = None, ""

    def artifact_subjects(index: int):
        for art in events[index].get("artifacts", []) if artifacts is not None else []:
            name = str(art.get("file", ""))
            path = (artifacts / name).resolve()
            if artifacts.resolve() not in path.parents or not path.is_file():
                add("ARTIFACT_MISSING", events[index].get("step", ""), "J-ARTIFACT", f"cited file {name} is not among the artifacts", index)
                continue
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                add("ARTIFACT_MISSING", events[index].get("step", ""), "J-ARTIFACT", f"cited file {name} is not readable", index)
                continue
            yield name, str(doc.get("author", "")), doc.get(field)

    if code and executed:
        first = executed[0]
        reference = events[first].get("subject", {}).get(field)
        ref_source = f"event {events[first].get('seq')} by {events[first].get('actor', '')}"
        for name, author, value in artifact_subjects(first):
            ref_source = f"file {name} by {author}"
            if value != reference:
                add(code, events[first].get("step", ""), "J-IDENTIFIER",
                    f"{field} {reference} in event {events[first].get('seq')} by {events[first].get('actor', '')}; "
                    f"{field} {value} in file {name} by {author}", first)
        for i in executed[1:]:
            e = events[i]
            value = e.get("subject", {}).get(field)
            if value != reference:
                add(code, e.get("step", ""), "J-IDENTIFIER",
                    f"{field} {reference} in {ref_source}; {field} {value} in event {e.get('seq')} by {e.get('actor', '')}", i)
            for name, author, value in artifact_subjects(i):
                if value != reference:
                    add(code, e.get("step", ""), "J-IDENTIFIER",
                        f"{field} {reference} in {ref_source}; {field} {value} in file {name} by {author}", i)

    # 3. the log itself -------------------------------------------------------------------------------------------
    for i in tlog.broken_links(events):
        add("LOG_CHAIN_BROKEN", str(events[i].get("step", "")), "J-CHAIN",
            "the event does not match its hash or the previous event's hash", i)

    violations = sorted(found.values(), key=lambda v: (order.get(v["step"], len(order)), v["code"]))
    closing = next((s["id"] for s in steps if s.get("closes")), "")
    failed = bool(violations)
    return {
        "tool": "noascan", "version": __version__, "report": "tabletop-judgement", "as_of": as_of,
        "playbook": playbook["id"], "playbook_version": playbook["version"],
        "rules": {"judge": {"version": rules["version"], "sha256": rules_engine.digest(rules)},
                  "playbook": {"version": playbook["version"], "sha256": rules_engine.digest(playbook)}},
        "subject": safe(reference) if reference is not None else "", "events": len(events),
        "refused": [{"step": safe(e.get("step", "")), "reason": safe(e.get("reason", "")), "seq": e.get("seq")}
                    for e in events if e.get("type") == "refused"],
        "violations": violations, "verdict": "FAILED" if failed else "PASSED",
        "closing_step": closing, "closure": "BLOCKED" if failed else "ALLOWED", "exit_code": 1 if failed else 0,
        "statement": "a paper exercise: it shows the playbook is coherent and departures are seen, not that a real incident would be handled",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Judge a tabletop transcript against its playbook.")
    ap.add_argument("transcript", type=Path)
    ap.add_argument("--playbook", required=True)
    ap.add_argument("--as-of", required=True)
    ap.add_argument("--artifacts", type=Path)
    ap.add_argument("--json", type=Path)
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 64 if exc.code else 0
    try:
        out = judge(tlog.read(args.transcript), load_playbook(args.playbook), args.as_of, artifacts=args.artifacts)
    except (OSError, ValueError, KeyError, rules_engine.RuleError) as exc:
        print(f"error: {type(exc).__name__}", file=sys.stderr)
        return 64
    print(f"tabletop {out['playbook']}: {out['verdict']}; closure {out['closure']}; violations {len(out['violations'])}")
    for v in out["violations"]:
        print(f"  {v['code']:<22} {v['step']}: {v['details'][0]}")
    if args.json:
        report.write(args.json, out)
    return out["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
