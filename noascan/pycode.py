"""Dangerous calls in Python source, driven by ``rules/pycode.json``.

The source is parsed with the standard-library ``ast`` module and never executed or imported.
Comments and string literals cannot match. Names are resolved through the file's own import
aliases only (``import subprocess as sp``; ``from os import system``): there is no data flow.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from noascan.rules_engine import RuleError


@dataclass(frozen=True)
class CodeFinding:
    rule: str
    cls: str
    line: int
    call: str      # the resolved dotted name: an identifier from the source, never a literal


def _aliases(tree: ast.AST) -> dict[str, str]:
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                names[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                names[a.asname or a.name] = f"{node.module}.{a.name}"
    return names


def _dotted(node: ast.AST, aliases: dict[str, str]) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


def _matches(rule: dict[str, Any], name: str, call: ast.Call) -> bool:
    if "calls" in rule and name not in rule["calls"]:
        return False
    if "calls_prefix" in rule and not any(name.startswith(p) for p in rule["calls_prefix"]):
        return False
    if "attr" in rule and name.rsplit(".", 1)[-1] != rule["attr"]:
        return False
    for key, want in rule.get("keyword", {}).items():
        got = next((k.value for k in call.keywords if k.arg == key), None)
        if not isinstance(got, ast.Constant) or got.value != want or type(got.value) is not type(want):
            return False
    if not any(k in rule for k in ("calls", "calls_prefix", "attr", "keyword")):
        raise RuleError(f"pycode: rule {rule['id']} has no condition")
    return True


def review(text: str, rules: dict[str, Any]) -> list[CodeFinding] | None:
    """Findings in one source file, or ``None`` when the file does not parse (the caller abstains)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    aliases = _aliases(tree)
    out: list[CodeFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func, aliases)
        for rule in rules["rules"]:
            if _matches(rule, name, node):
                if rule["action"] == "report":
                    out.append(CodeFinding(rule["id"], rule["class"], node.lineno, name))
                break
    out.sort(key=lambda f: (f.line, f.rule, f.call))
    return out
