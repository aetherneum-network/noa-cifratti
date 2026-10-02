"""Blast radius and the release gate. Both are ordered rule files: first match wins.

``CLEAN`` is the last gate rule and is reached only when every counter is zero: nothing found,
nothing left unread, no exception used. There is no other code path that produces it.
"""
from __future__ import annotations

from typing import Any

from noascan.rules_engine import RuleError, first_match


def grade(kind: str, cls: str, blast: dict[str, Any]) -> tuple[int, str, str]:
    """(radius, severity, rule id) of a finding or of a threat-model asset."""
    def hit(rule: dict[str, Any]) -> bool:
        when = rule.get("when", {})
        if "class_in" in when and cls not in when["class_in"]:
            return False
        if "kind_in" in when and kind not in when["kind_in"]:
            return False
        return True

    rule = first_match(blast["rules"], hit)
    if rule is None:
        raise RuleError("blast_radius: no rule matched and there is no default rule")
    return int(rule["radius"]), str(rule["severity"]), str(rule["id"])


def counters(findings: list[dict[str, Any]], not_covered: int, exceptions: int, gate: dict[str, Any]) -> dict[str, int]:
    block, review = gate["blocking"], gate["review"]
    blocking = [f for f in findings if f["kind"] in block["kinds"] or f["severity"] in block["severities"]]
    rest = [f for f in findings if f not in blocking]
    reviewing = [f for f in rest if f["kind"] in review["kinds"] or f["severity"] in review["severities"]]
    unplaced = len(rest) - len(reviewing)   # a finding no rule places is treated as blocking, never dropped
    return {"blocking": len(blocking) + unplaced, "review": len(reviewing), "not_covered": not_covered,
            "exceptions": exceptions}


def decide(count: dict[str, int], rules: list[dict[str, Any]]) -> tuple[str, str, int]:
    """(verdict, rule id, exit code). ``when`` keys are ``<counter>_min``; an empty ``when`` always matches."""
    def hit(rule: dict[str, Any]) -> bool:
        for key, minimum in rule.get("when", {}).items():
            if not key.endswith("_min") or key[:-4] not in count:
                raise RuleError(f"gate: rule {rule['id']} tests an unknown counter {key!r}")
            if count[key[:-4]] < minimum:
                return False
        return True

    rule = first_match(rules, hit)
    if rule is None:
        raise RuleError("gate: no rule matched and there is no default rule")
    return str(rule["verdict"]), str(rule["id"]), int(rule["exit_code"])
