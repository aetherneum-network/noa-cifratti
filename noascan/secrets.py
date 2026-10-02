"""Secret detection on text, driven by ``rules/secrets.json``, and the coverage decision on bytes,
driven by ``rules/coverage.json``.

Two properties are structural, not statistical:

* a ``Hit`` has no field that could hold the matched text - only a fingerprint, a length and a line;
* a file the scanner could not read as UTF-8 text in full is returned as NOT_COVERED with a reason,
  whatever a best-effort pass did or did not find in it.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from noascan.fingerprint import block_fingerprint, fingerprint
from noascan.rules_engine import RuleError

_LITERAL = re.compile(r"\"([^\"\\]*)\"|'([^'\\]*)'")


@dataclass(frozen=True)
class Hit:
    rule: str
    action: str          # "report" | "suspect"
    cls: str
    line: int
    fingerprint: str
    length: int
    via: str = ""        # "", "base64", "hex", "percent", "reversed", "concat"


class SecretRules:
    """Compiled view of ``rules/secrets.json`` (order preserved)."""

    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.limits = data.get("limits", {})
        self.max_block = int(self.limits.get("max_block_lines", 80))
        self.compiled: list[dict[str, Any]] = []
        for rule in data["rules"]:
            flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
            kind, action = rule.get("kind"), rule.get("action")
            if kind not in ("line", "block", "decode", "concat") or action not in ("ignore", "report", "suspect"):
                raise RuleError(f"secrets: rule {rule['id']} has an unknown kind or action")
            c = {"id": rule["id"], "kind": kind, "action": action, "cls": rule.get("class", ""),
                 "globs": rule.get("path_globs"), "encoding": rule.get("encoding", "")}
            try:
                if kind == "block":
                    c["begin"], c["end"] = re.compile(rule["begin"], flags), re.compile(rule["end"], flags)
                else:
                    c["regex"] = re.compile(rule["pattern"], flags)
                    if "secret" not in c["regex"].groupindex:
                        raise RuleError(f"secrets: rule {rule['id']} has no group named 'secret'")
            except (re.error, KeyError) as exc:
                raise RuleError(f"secrets: rule {rule['id']} does not compile: {type(exc).__name__}") from exc
            if action != "ignore" and not c["cls"]:
                raise RuleError(f"secrets: rule {rule['id']} reports without a class")
            self.compiled.append(c)

    @property
    def covered_classes(self) -> list[str]:
        return sorted({c["cls"] for c in self.compiled if c["action"] == "report"})


def _applies(rule: dict[str, Any], path: str | None) -> bool:
    """A rule limited to some paths also applies when the path is unknown: fail toward detection."""
    if path is None or not rule["globs"]:
        return True
    return any(fnmatchcase(path, g) for g in rule["globs"])


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < b and a < span[1] for a, b in taken)


def _decode(token: str, encoding: str) -> str | None:
    if encoding == "reversed":
        return token[::-1]
    try:
        if encoding == "base64":
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        else:                                   # "hex", or "percent" (%41%42...) which is hex with separators
            raw = bytes.fromhex(token.replace("%", "") if encoding == "percent" else token)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    return text if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text) else None


def scan_text(path: str | None, text: str, rules: SecretRules, _inner: bool = False) -> list[Hit]:
    """All hits in ``text``, rule order respected. ``path`` (posix) only selects path-limited rules."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    claimed: list[list[tuple[int, int]]] = [[] for _ in lines]
    consumed = [False] * len(lines)
    hits: list[Hit] = []
    for rule in rules.compiled:
        if not _applies(rule, path) or (_inner and rule["kind"] in ("decode", "concat")):
            continue
        if rule["kind"] == "block":
            i = 0
            while i < len(lines):
                begin = None if consumed[i] else rule["begin"].search(lines[i])
                if not begin:
                    i += 1
                    continue
                same = rule["end"].search(lines[i], begin.end())
                if same:
                    body, last = [lines[i][begin.start():same.end()]], i
                else:
                    stop = min(len(lines), i + 1 + rules.max_block)
                    last = next((j for j in range(i + 1, stop) if rule["end"].search(lines[j])), stop - 1)
                    body = [lines[i][begin.start():]]  # an unterminated block is reported up to the limit
                    if last > i:
                        end = rule["end"].search(lines[last])
                        body += [*lines[i + 1:last], lines[last][:end.end()] if end else lines[last]]
                for j in range(i, last + 1):
                    consumed[j] = True
                if rule["action"] != "ignore":
                    hits.append(Hit(rule["id"], rule["action"], rule["cls"], i + 1, block_fingerprint(body),
                                    sum(len(b.strip()) for b in body)))
                i = last + 1
            continue
        for n, line in enumerate(lines):
            if consumed[n]:
                continue
            for m in rule["regex"].finditer(line):
                span = m.span("secret")
                if span[0] == span[1] or _overlaps(span, claimed[n]):
                    continue
                token, via = m.group("secret"), ""
                if rule["kind"] == "decode":
                    decoded = _decode(token, rule["encoding"])
                    if decoded is None or not any(h.action == "report" for h in scan_text(None, decoded, rules, True)):
                        continue
                    via = rule["encoding"]
                elif rule["kind"] == "concat":
                    joined = "".join(a or b for a, b in _LITERAL.findall(token))
                    if not any(h.action == "report" for h in scan_text(None, joined, rules, True)):
                        continue
                    via = "concat"
                claimed[n].append(span)
                if rule["action"] != "ignore":
                    hits.append(Hit(rule["id"], rule["action"], rule["cls"], n + 1, fingerprint(token),
                                    span[1] - span[0], via))
    hits.sort(key=lambda h: (h.line, h.rule, h.fingerprint))
    return hits


# ---- coverage -----------------------------------------------------------------------------------------------------

_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")


def classify(data: bytes, coverage: dict[str, Any], limits: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Decide whether ``data`` is inside coverage.

    Returns ``(reason, rule_id, text)``. ``reason`` is None for a covered file. ``text`` is what the
    secret rules may run on: the full text for a covered file, a best-effort rendering (or None)
    for a file outside coverage.
    """
    max_bytes = int(limits.get("max_file_bytes", 1048576))
    max_line = int(limits.get("max_line_chars", 65536))
    utf8: str | None
    try:
        utf8 = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        utf8 = None
    for rule in coverage["rules"]:
        test = rule.get("test")
        if test == "size_over_limit":
            hit = len(data) > max_bytes
        elif test == "magic":
            hit = any(data.startswith(bytes.fromhex(h)) for h in rule["magic_hex"])
        elif test == "bom_utf16_utf32":
            hit = data.startswith(_BOMS)
        elif test == "contains_nul":
            hit = b"\x00" in data
        elif test == "not_utf8":
            hit = utf8 is None
        elif test == "line_over_limit":
            hit = any(len(ln) > max_line for ln in data.split(b"\n"))
        elif test == "prefix":
            hit = data.startswith(rule["prefix"].encode("utf-8"))
        else:
            raise RuleError(f"coverage: rule {rule.get('id')} has an unknown test")
        if not hit:
            continue
        effort = rule.get("best_effort", "none")
        text: str | None = None
        if effort == "prefix":
            text = data[:max_bytes].decode("utf-8", "replace")
        elif effort == "utf16":
            try:
                text = data.decode("utf-16")
            except UnicodeDecodeError:
                text = None
        elif effort == "latin1":
            text = data.decode("latin-1").replace("\x00", "\n")
        elif effort == "utf8":
            text = utf8
        return rule["reason"], rule["id"], text
    return None, None, utf8
