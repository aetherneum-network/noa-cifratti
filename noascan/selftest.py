"""Inline tests of the rule files: every rule carries the lines it must match, ignore or leave alone.

A rule change that breaks its own examples fails here before any corpus is scanned. The probe
values are generated on the fly from a fixed seed by ``corpus/fakes.py``: no credential-looking
string is stored in a rule file, only a ``{{placeholder}}``.
"""
from __future__ import annotations

import base64
import random
import re
from typing import Any

from noascan import config, pycode
from noascan.secrets import SecretRules, scan_text

_SLOT = re.compile(r"\{\{([a-z0-9_]+)(?::([a-z_]+))?\}\}")


def render(template: str, seed: str = "noascan/selftest/v1") -> str:
    from corpus import fakes   # the generator of inert probe values; imported only by the self-test

    rng = random.Random(seed + "/" + template)
    values: dict[str, str] = {}

    def value(cls: str) -> str:
        if cls not in values:
            values[cls] = fakes.make(cls, rng)
        return values[cls]

    def fill(m: re.Match) -> str:
        name, arg = m.group(1), m.group(2)
        if name == "uri":
            return fakes.connection_uri(rng, "corp.example")[0]
        if name == "block":
            return fakes.armored_key_block(rng)
        if name in ("sha256", "data_uri", "public_id"):
            return {"sha256": fakes.sha256_hex, "data_uri": fakes.data_uri, "public_id": fakes.public_id}[name](rng)
        if name == "b64":
            return base64.b64encode(value(arg).encode("ascii")).decode("ascii")
        if name == "hex":
            return value(arg).encode("ascii").hex()
        if name == "pct":
            return "".join(f"%{b:02X}" for b in value(arg).encode("ascii"))
        if name == "rev":
            return value(arg)[::-1]
        if name in ("half1", "half2"):
            v = value(arg)
            return v[:len(v) // 2] if name == "half1" else v[len(v) // 2:]
        return value(name)

    return _SLOT.sub(fill, template)


def run_secrets(data: dict[str, Any]) -> list[str]:
    rules = SecretRules(data)
    failures: list[str] = []
    for rule in data["rules"]:
        tests = rule.get("tests", {})
        path = tests.get("path", "probe.txt")
        if not any(tests.get(k) for k in ("match", "no_match", "ignore")):
            failures.append(f"secrets/{rule['id']}: the rule has no inline test")
        for n, line in enumerate(tests.get("match", [])):
            hits = scan_text(path, render(line), rules)
            if not any(h.rule == rule["id"] for h in hits):
                failures.append(f"secrets/{rule['id']}: match example {n} was not matched by this rule")
        for kind in ("no_match", "ignore"):
            for n, line in enumerate(tests.get(kind, [])):
                hits = scan_text(path, render(line), rules)
                if hits:
                    failures.append(f"secrets/{rule['id']}: {kind} example {n} produced a finding ({hits[0].rule})")
    return failures


def run_config(data: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for rule in data["rules"]:
        tests = rule.get("tests", {})
        aspect = rule.get("aspect", rule["target"])
        if not any(tests.get(k) for k in ("match", "no_match", "ignore")):
            failures.append(f"config/{rule['id']}: the rule has no inline test")
        for kind in ("match", "no_match", "ignore"):
            for n, subject in enumerate(tests.get(kind, [])):
                decided = [r for r in config.decide(rule["target"], subject, data) if r.get("aspect", r["target"]) == aspect]
                winner = decided[0]["id"] if decided else None
                reported = bool(decided) and decided[0]["action"] == "report"
                ok = (winner == rule["id"]) if kind in ("match", "ignore") else not reported
                if not ok:
                    failures.append(f"config/{rule['id']}: {kind} example {n} was decided by {winner}")
    return failures


def run_pycode(data: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for rule in data["rules"]:
        tests = rule.get("tests", {})
        if not any(tests.get(k) for k in ("match", "no_match", "ignore")):
            failures.append(f"pycode/{rule['id']}: the rule has no inline test")
        for kind in ("match", "no_match", "ignore"):
            for n, source in enumerate(tests.get(kind, [])):
                found = pycode.review(source, data)
                if found is None:
                    failures.append(f"pycode/{rule['id']}: {kind} example {n} does not parse")
                elif kind == "match" and not any(f.rule == rule["id"] for f in found):
                    failures.append(f"pycode/{rule['id']}: match example {n} was not matched by this rule")
                elif kind != "match" and found:
                    failures.append(f"pycode/{rule['id']}: {kind} example {n} produced a finding ({found[0].rule})")
    return failures


def run_all(raw: dict[str, dict[str, Any]]) -> list[str]:
    return run_secrets(raw["secrets"]) + run_config(raw["config"]) + run_pycode(raw["pycode"])
