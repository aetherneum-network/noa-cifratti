"""Reports: deterministic JSON, no absolute path, no clock, and never the text of a finding.

Two independent barriers keep secret values out of what is written:

1. findings are built from ``Hit`` objects, which have no field for the matched text;
2. every string that comes from the scanned content (paths, subjects, author names, details) goes
   through ``safe()``, which re-scans it with the same rules and replaces it with a fingerprint
   if it would itself be a finding (a file *named* after a token, for instance).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from noascan.secrets import SecretRules, scan_text


def safe(text: str, rules: SecretRules) -> str:
    if not text:
        return text
    hits = [h for h in scan_text(None, text, rules) if h.action in ("report", "suspect")]
    if hits:
        return "[masked:" + ",".join(sorted({h.fingerprint for h in hits})) + "]"
    return text


def reference_date(as_of: str) -> str:
    """Refuse a missing or unreadable reference date: the clock is never read, so the date must be given."""
    if not as_of or not isinstance(as_of, str):
        raise ValueError("as_of is mandatory: a report without its reference date is not a receipt")
    try:
        datetime.fromisoformat(as_of)
    except ValueError:
        raise ValueError("as_of must be an ISO 8601 date or date-time") from None
    return as_of


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(dumps(obj))


def summary(report: dict[str, Any]) -> str:
    """A short ASCII rendering for the terminal. Same guarantees as the JSON: fingerprints only."""
    lines = [f"noascan {report['version']}  target={report['target']}  as_of={report['as_of']}",
             f"verdict: {report['verdict']}  (rule {report['gate_rule']}, exit code {report['exit_code']})",
             "counters: " + ", ".join(f"{k}={v}" for k, v in sorted(report["counters"].items()))]
    scope = report.get("scope", {})
    if scope:
        lines.append(f"read: {scope['worktree_files']} files, history {scope['history']} "
                     f"({scope['commits_read']} commits, {scope.get('tags_read', 0)} annotated tags, {scope['blobs_read']} blobs)")
    for f in report.get("findings", []):
        if f.get("object"):
            where = f"({f['object_type']} {f['object'][:12]} {f['part']})"   # a commit or tag object, not a file
        else:
            where = f["path"] or "(object not in any tree)"
        extra = f" commit={f['commit'][:12]}" if f.get("commit") else ""
        state = "" if f.get("in_worktree", True) else " [history only]"
        mark = f" fp={f['fingerprint']}" if f.get("fingerprint") else f" subject={f.get('subject', '')}"
        lines.append(f"  r{f['radius']} {f['severity']:<8} {f['kind']:<7} {f['class']:<42} {where}:{f['line']}{mark}{extra}{state}")
    for n in report.get("coverage", {}).get("not_covered", []):
        lines.append(f"  NOT_COVERED {n['reason']:<22} {n['path']}")
    for e in report.get("exceptions", []):
        lines.append(f"  EXCEPTION   {e['id']:<22} {e['path']}")
    return "\n".join(lines) + "\n"
