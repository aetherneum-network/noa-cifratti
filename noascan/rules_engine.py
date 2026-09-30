"""Ordered rule files: first match wins, exceptions on top.

Every decision of the pack lives in a JSON file under ``rules/`` (or ``playbooks/``). A wrong
output is fixed by changing a rule, never by editing the output. This module loads those files,
checks their shape, applies patches (scenario S09) and answers "which rule decided".
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"


class RuleError(ValueError):
    """A rule file is malformed. Malformed rules stop the run: they never degrade to 'no finding'."""


def load(name: str | Path) -> dict[str, Any]:
    path = Path(name) if isinstance(name, Path) or str(name).endswith(".json") else RULES_DIR / f"{name}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleError(f"cannot read rule file {path.name}: {type(exc).__name__}") from exc
    return validate(data, path.name)


def validate(data: dict[str, Any], label: str = "rules") -> dict[str, Any]:
    for key in ("file", "version", "as_of", "rules"):
        if key not in data:
            raise RuleError(f"{label}: missing key {key!r}")
    if not isinstance(data["rules"], list):
        raise RuleError(f"{label}: 'rules' must be an ordered list")
    seen: set[str] = set()
    for rule in data["rules"]:
        rid = rule.get("id") if isinstance(rule, dict) else None
        if not rid or rid in seen:
            raise RuleError(f"{label}: rule ids must be present and unique (offending id: {rid!r})")
        seen.add(rid)
    return data


def digest(data: dict[str, Any]) -> str:
    """SHA-256 of the canonical form of a rule set: goes into every report next to the version."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()


def first_match(rules: Iterable[dict[str, Any]], test: Callable[[dict[str, Any]], bool]) -> dict[str, Any] | None:
    for rule in rules:
        if test(rule):
            return rule
    return None


def patched(data: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Return a patched copy. ``patch`` = {"rule": id, "set": {...}} - the only supported edit is
    replacing keys of one existing rule, so a patch can never silently add or reorder rules."""
    out = copy.deepcopy(data)
    rule = first_match(out["rules"], lambda r: r["id"] == patch.get("rule"))
    if rule is None:
        raise RuleError(f"patch targets an unknown rule: {patch.get('rule')!r}")
    if not isinstance(patch.get("set"), dict) or "id" in patch["set"]:
        raise RuleError("patch needs a 'set' object and may not rename the rule")
    rule.update(patch["set"])
    return validate(out, f"{data['file']} (patched)")
