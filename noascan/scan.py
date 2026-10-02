"""The scan: working tree, git history, configuration, Python source -> findings -> gate.

What is read, stated in full:

* every file of the working tree (symbolic links are not followed), and its name;
* every file under ``.git`` that is not an object or the index (a remote URL with a credential
  in ``.git/config`` is a leak like any other; the reflog, ``COMMIT_EDITMSG`` and the like are files);
* every blob in the git object database, reachable or not, through two read-only git commands;
* the full text of every commit and annotated-tag object in the database, reachable or not, in two
  parts, header and message, each read like a file with no path (so that every rule applies).

What could not be read in full as UTF-8 text is listed as NOT_COVERED with a reason, and a
repository with one such entry cannot be CLEAN.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from noascan import __version__, config, gate, gitio, history, pycode, report, rules_engine
from noascan.secrets import Hit, SecretRules, classify, scan_text

RULE_FILES = ("secrets", "coverage", "gate", "blast_radius", "config", "pycode", "surface")


@dataclass
class RuleSet:
    raw: dict[str, dict[str, Any]]
    secrets: SecretRules

    @classmethod
    def load(cls, overrides: dict[str, dict[str, Any]] | None = None) -> "RuleSet":
        raw = {name: rules_engine.load(name) for name in RULE_FILES}
        raw.update(overrides or {})
        return cls(raw, SecretRules(raw["secrets"]))

    def stamp(self, names: tuple[str, ...] = RULE_FILES) -> dict[str, dict[str, str]]:
        return {n: {"version": self.raw[n]["version"], "sha256": rules_engine.digest(self.raw[n])} for n in names}


def read_tree(root: Path, exclude: tuple[str, ...] = ()) -> tuple[dict[str, bytes | None], list[dict[str, str]]]:
    """(files, notes). ``files`` maps a posix path to its bytes (None: not readable as a regular file)."""
    files: dict[str, bytes | None] = {}
    notes: list[dict[str, str]] = []
    if not os.path.isdir(root):
        # a mistyped target must never read as "nothing found"
        raise NotADirectoryError("the target is not a directory: nothing was read")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for d in sorted(dirnames):
            rel = rel_dir + d
            if rel in exclude or d in exclude:
                continue
            if rel == ".git/objects":
                continue                                   # read through git, object by object
            if d == ".git" and rel_dir:
                notes.append({"path": rel, "reason": "nested_repository", "rule": "SCAN-NESTED-REPO"})
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                notes.append({"path": rel, "reason": "symlink", "rule": "SCAN-SYMLINK"})
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = rel_dir + name
            if rel in exclude or name in exclude or rel == ".git/index":   # the index holds paths and object ids only
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                notes.append({"path": rel, "reason": "symlink", "rule": "SCAN-SYMLINK"})
                continue
            try:
                with open(full, "rb") as fh:
                    files[rel] = fh.read()
            except OSError:
                files[rel] = None
    return files, notes


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Blobs:
    """Classify and scan each (path, content) once."""

    def __init__(self, rs: RuleSet):
        self.rs = rs
        self.cache: dict[tuple[str | None, str], tuple[str | None, str | None, list[Hit], str | None]] = {}

    def look(self, path: str | None, data: bytes) -> tuple[str | None, str | None, list[Hit], str | None]:
        """(not-covered reason, coverage rule, hits, full text if covered)."""
        key = (path, _sha(data))
        if key not in self.cache:
            reason, rule, text = classify(data, self.rs.raw["coverage"], self.rs.secrets.limits)
            hits = scan_text(path, text, self.rs.secrets) if text is not None else []
            self.cache[key] = (reason, rule, hits, text if reason is None else None)
        return self.cache[key]


def _allow(entries: list[dict[str, Any]], kind: str, path: str, **match: str) -> dict[str, Any] | None:
    return rules_engine.first_match(entries, lambda e: e.get("type") == kind and e.get("path") == path
                                    and all(e.get(k) == v for k, v in match.items()))


def scan(root: Path, as_of: str, *, label: str | None = None, read_history: bool = True,
         exclude: tuple[str, ...] = (), allowlist: dict[str, Any] | None = None,
         rules: RuleSet | None = None) -> dict[str, Any]:
    """Scan ``root`` and return the report (a plain dict; ``report.write`` makes it a file)."""
    report.reference_date(as_of)
    rs = rules or RuleSet.load()
    blobs = _Blobs(rs)
    blast = rs.raw["blast_radius"]

    def safe(text: str) -> str:
        return report.safe(text, rs.secrets)

    records: dict[tuple, dict[str, Any]] = {}
    not_covered: dict[tuple[str, str], dict[str, str]] = {}

    def add_hit(hit: Hit, path: str | None, intro: history.Introduction | None) -> None:
        kind = "secret" if hit.action == "report" else "suspect"
        key = (kind, hit.cls, hit.fingerprint, path)
        rec = records.get(key)
        if rec is None:
            radius, severity, _ = gate.grade(kind, hit.cls, blast)
            rec = records[key] = {"kind": kind, "class": hit.cls, "rule": hit.rule, "severity": severity,
                                  "radius": radius, "path": safe(path or ""), "line": hit.line,
                                  "fingerprint": hit.fingerprint, "length": hit.length, "via": hit.via,
                                  "in_worktree": intro is None, "commit": "", "author": "", "date": "", "blob": "",
                                  "reachable": True, "raw_path": path}
        if intro is not None and not rec["commit"] and not rec["blob"]:
            rec.update(commit=intro.commit or "", author=safe(intro.author), date=intro.date, blob=intro.blob,
                       reachable=intro.reachable)

    def add_text_hit(hit: Hit, obj: history.ObjectText) -> None:
        """A finding in the header or the message of a commit or tag object: located by object id and part."""
        kind = "secret" if hit.action == "report" else "suspect"
        key = (kind, hit.cls, hit.fingerprint, None, obj.oid, obj.part)
        if key in records:
            return
        radius, severity, _ = gate.grade(kind, hit.cls, blast)
        records[key] = {"kind": kind, "class": hit.cls, "rule": hit.rule, "severity": severity, "radius": radius,
                        "path": "", "line": hit.line, "fingerprint": hit.fingerprint, "length": hit.length,
                        "via": hit.via, "in_worktree": False, "commit": obj.oid if obj.kind == "commit" else "",
                        "author": safe(obj.author), "date": obj.date, "blob": "", "reachable": obj.reachable,
                        "object": obj.oid, "object_type": obj.kind, "part": obj.part, "raw_path": None}

    named: set[tuple[str, bool]] = set()

    def add_name(path: str | None, intro: history.Introduction | None) -> None:
        """A credential used as a file or directory name is a leak like any other: names are scanned too."""
        if not path or (path, intro is None) in named:
            return
        named.add((path, intro is None))
        for hit in scan_text(None, path, rs.secrets):
            add_hit(replace(hit, line=0, via=(hit.via + " in " if hit.via else "") + "file name"), path, intro)

    def add_gap(path: str, reason: str, rule: str, where: str, digest: str = "") -> None:
        not_covered.setdefault((path, digest or reason), {"path": safe(path), "reason": reason, "rule": rule,
                                                          "where": where, "sha256": digest, "raw_path": path})

    # 1. working tree -----------------------------------------------------------------------------------------
    files, notes = read_tree(root, exclude)
    for note in notes:
        add_gap(note["path"], note["reason"], note["rule"], "worktree")
    covered_text: dict[str, str] = {}
    for path in sorted(files):
        data = files[path]
        add_name(path, None)
        if data is None:
            add_gap(path, "unreadable", "SCAN-UNREADABLE", "worktree")
            continue
        reason, rule, hits, text = blobs.look(path, data)
        if reason is not None:
            add_gap(path, reason, rule or "", "worktree", _sha(data))
        elif text is not None and not path.startswith(".git/"):
            covered_text[path] = text
        for hit in hits:
            add_hit(hit, path, None)

    # 2. history ----------------------------------------------------------------------------------------------
    hist_state, blobs_read, commits_read, tags_read = "skipped", 0, 0, 0
    git_entry = root / ".git"
    if not read_history:
        if os.path.lexists(git_entry) and ".git" not in exclude:
            # a history that exists and was not read is a gap, not a pass: the verdict cannot be CLEAN
            add_gap(".git", "history_not_read", "SCAN-HISTORY-NOT-READ", "history")
    else:
        if not os.path.lexists(git_entry):
            hist_state = "absent"
        else:
            try:
                hist = history.read(root)
            except gitio.GitError as exc:
                hist_state = "unreadable"
                add_gap(".git", "history_unreadable", "SCAN-HISTORY-UNREADABLE", "history", str(exc)[:80])
            else:
                hist_state, blobs_read, commits_read, tags_read = "read", len(hist.blobs), len(hist.commits), hist.tags_read
                for note in hist.notes:
                    add_gap(note["detail"], note["reason"], "SCAN-HISTORY-" + note["reason"].upper().replace("_", "-"),
                            "history", note["detail"])
                for intro in hist.introductions:
                    add_name(intro.path, intro)
                    data = hist.blobs.get(intro.blob)
                    if data is None:
                        continue
                    reason, rule, hits, _ = blobs.look(intro.path, data)
                    if reason is not None:
                        add_gap(intro.path or f"(blob {intro.blob[:12]} in no tree)", reason, rule or "", "history", _sha(data))
                    for hit in hits:
                        add_hit(hit, intro.path, intro)
                # the header and the message of each commit and tag object, with the same rules and the same
                # coverage decision as a file; no path, so that no rule is skipped for want of one
                for obj in hist.texts:
                    reason, rule, hits, _ = blobs.look(None, obj.data)
                    if reason is not None:
                        add_gap(f"({obj.kind} {obj.oid[:12]} {obj.part})", reason, rule or "", "history", _sha(obj.data))
                    for hit in hits:
                        add_text_hit(hit, obj)

    # 3. configuration and Python source (working tree, covered files only) ----------------------------------------
    model = config.parse(covered_text, rs.raw["config"])
    for path, reason in model.errors:
        add_gap(path, reason, "SCAN-CONFIG-NOT-PARSEABLE", "worktree", reason)
    for f in config.review(model, rs.raw["config"]):
        radius, severity, _ = gate.grade("config", f.cls, blast)
        records[("config", f.cls, f.subject, f.path)] = {
            "kind": "config", "class": f.cls, "rule": f.rule, "severity": severity, "radius": radius,
            "path": safe(f.path), "line": f.line, "subject": safe(f.subject), "in_worktree": True, "raw_path": f.path}
    for path in sorted(covered_text):
        if not path.endswith(".py"):
            continue
        found = pycode.review(covered_text[path], rs.raw["pycode"])
        if found is None:
            add_gap(path, "python_not_parseable", "SCAN-PYTHON-NOT-PARSEABLE", "worktree", "python_not_parseable")
            continue
        for c in found:
            radius, severity, _ = gate.grade("pycode", c.cls, blast)
            records[("pycode", c.cls, f"{c.line}:{c.call}", path)] = {
                "kind": "pycode", "class": c.cls, "rule": c.rule, "severity": severity, "radius": radius,
                "path": safe(path), "line": c.line, "subject": safe(c.call), "in_worktree": True, "raw_path": path}

    # 4. exceptions: exact path + exact fingerprint (or content hash), each with a reason ----------------------------
    entries = (allowlist or {}).get("rules", [])
    exceptions: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    for rec in records.values():
        entry = None
        if rec["in_worktree"] and rec["raw_path"]:       # history is never excepted: only what is on disk, by exact path
            pin = {"fingerprint": rec["fingerprint"]} if rec["kind"] in ("secret", "suspect") else {"subject": rec["subject"]}
            entry = _allow(entries, "finding", rec["raw_path"], **pin, **{"class": rec["class"]})
        if entry:
            exceptions.append({"id": entry["id"], "path": rec["path"], "class": rec["class"],
                               "fingerprint": rec.get("fingerprint", ""), "reason": entry["reason"]})
        else:
            findings.append(rec)
    gaps: list[dict[str, str]] = []
    for gap in not_covered.values():
        entry = _allow(entries, "not_covered", gap["raw_path"], sha256=gap["sha256"]) if gap["where"] == "worktree" else None
        if entry:
            exceptions.append({"id": entry["id"], "path": gap["path"], "class": gap["reason"],
                               "fingerprint": "", "reason": entry["reason"]})
        else:
            gaps.append(gap)
    for name in exclude:
        exceptions.append({"id": "EXCLUDED-BY-CALLER", "path": name, "class": "excluded", "fingerprint": "",
                           "reason": "excluded on the command line: not read"})

    for rec in findings + gaps:
        rec.pop("raw_path", None)
    findings.sort(key=lambda f: (-f["radius"], f["path"], f["line"], f["kind"], f["class"],
                                 f.get("fingerprint", ""), f.get("subject", ""), f.get("object", ""), f.get("part", "")))
    for i, rec in enumerate(findings, 1):
        rec["id"] = f"F{i:03d}"
    gaps.sort(key=lambda g: (g["path"], g["where"], g["reason"], g["sha256"]))
    exceptions.sort(key=lambda e: (e["path"], e["id"], e["fingerprint"]))

    count = gate.counters(findings, len(gaps), len(exceptions), rs.raw["gate"])
    verdict, rule_id, exit_code = gate.decide(count, rs.raw["gate"]["rules"])
    return {
        "tool": "noascan", "version": __version__, "report": "scan", "as_of": as_of,
        "target": safe(label if label is not None else root.name),
        "scope": {"worktree_files": len(files), "history": hist_state, "commits_read": commits_read,
                  "tags_read": tags_read, "blobs_read": blobs_read,
                  "object_texts": "header and message of every commit and annotated tag" if hist_state == "read" else "not read",
                  "config_and_code": "working tree only",
                  "statement": "internal consistency on synthetic data; no claim about any real system"},
        "rules": rs.stamp(("secrets", "coverage", "gate", "blast_radius", "config", "pycode")),
        "coverage": {"secret_classes": rs.secrets.covered_classes, "not_covered": gaps},
        "findings": findings, "exceptions": exceptions, "counters": count,
        "verdict": verdict, "gate_rule": rule_id, "exit_code": exit_code,
    }
