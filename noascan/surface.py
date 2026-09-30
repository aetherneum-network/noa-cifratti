"""Attack-surface delta of a patch: "if the patch grows the surface, you have lost".

The surface of a tree is a set of items (see ``rules/surface.json``). Two trees are compared:

    delta = added + weakened - removed - strengthened

A route that loses forward-auth is *weakened*; one that gains it is *strengthened*. A file that
cannot be read in the patched tree and was not there before makes the comparison NOT_COVERED.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from noascan import __version__, config, gate, report
from noascan.scan import RuleSet, _sha, read_tree
from noascan.secrets import classify, scan_text


def surface_of(root: Path, rs: RuleSet) -> tuple[dict[str, list[str]], dict[str, str]]:
    """(items -> flags, unreadable path -> reason/sha key)."""
    rules = rs.raw["surface"]
    files, notes = read_tree(root)
    items: dict[str, list[str]] = {}
    unreadable: dict[str, str] = {n["path"]: n["reason"] for n in notes}
    covered: dict[str, str] = {}
    for path in sorted(files):
        data = files[path]
        for hit in scan_text(None, path, rs.secrets):            # a credential used as a file name
            if hit.action == "report":
                items[f"secret:{report.safe(path, rs.secrets)}#{hit.fingerprint}"] = []
        if data is None:
            unreadable[path] = "unreadable"
            continue
        reason, _, text = classify(data, rs.raw["coverage"], rs.secrets.limits)
        if reason is not None:
            unreadable[path] = f"{reason}:{_sha(data)}"
        else:
            covered[path] = text or ""
        if text is not None:
            for hit in scan_text(path, text, rs.secrets):
                if hit.action == "report":
                    items[f"secret:{report.safe(path, rs.secrets)}#{hit.fingerprint}"] = []
    model = config.parse(covered, rs.raw["config"])
    for path, reason in model.errors:
        unreadable[path] = reason
    for _, r in model.routers:
        if r["entrypoint"] != "public":
            continue
        flags = []
        if "forward-auth" not in r["middlewares"]:
            flags.append("no_forward_auth")
        if config._prefix_hit(r["path_prefix"], rules["debug_prefixes"]):
            flags.append("debug")
        items[report.safe(f"route:{r['host']}{r['path_prefix']}", rs.secrets)] = flags
    private = tuple(rules["private_bind_prefixes"])
    for _, s in model.services:
        for entry in s["published"]:
            bind, port = config.published(entry)
            if not bind.startswith(private):
                items[report.safe(f"port:{s['name']}:{bind}:{port}", rs.secrets)] = []
        if any(re.search(rules["socket_regex"], m.split(":", 1)[0]) for m in s["mounts"]):
            items[report.safe(f"socket:{s['name']}", rs.secrets)] = []
    for path, _, key, value in model.env:
        if key == "DEBUG" and value.lower() in rules["debug_values"]:
            items[f"debugflag:{report.safe(path, rs.secrets)}"] = []
    return items, unreadable


def delta(before: Path, after: Path, as_of: str, rules: RuleSet | None = None,
          labels: tuple[str, str] = ("before", "after")) -> dict[str, Any]:
    report.reference_date(as_of)
    rs = rules or RuleSet.load()
    a, a_gaps = surface_of(before, rs)
    b, b_gaps = surface_of(after, rs)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    weakened = sorted(k for k in set(a) & set(b) if "no_forward_auth" in b[k] and "no_forward_auth" not in a[k])
    strengthened = sorted(k for k in set(a) & set(b) if "no_forward_auth" in a[k] and "no_forward_auth" not in b[k])
    unreadable_added = sorted(report.safe(p, rs.secrets) for p, key in b_gaps.items() if a_gaps.get(p) != key)
    count = {"delta": len(added) + len(weakened) - len(removed) - len(strengthened),
             "grown": len(added) + len(weakened), "unreadable_added": len(unreadable_added)}
    verdict, rule_id, exit_code = gate.decide(count, rs.raw["surface"]["rules"])
    blast = rs.raw["blast_radius"]

    def entry(item: str, change: str) -> dict[str, Any]:
        kind = item.split(":", 1)[0]
        flags = b.get(item, a.get(item, []))
        cls = dict([("route", "debug_route_public" if "debug" in flags else
                     "admin_route_without_forward_auth" if "no_forward_auth" in flags else "public_site"),
                    ("port", "internal_port_published_on_all_interfaces"), ("socket", "runtime_socket_mounted"),
                    ("debugflag", "debug_flag_enabled"), ("secret", "service_credential")])[kind]
        radius, severity, _ = gate.grade("surface", cls, blast)
        return {"item": item, "change": change, "flags": flags, "radius": radius, "severity": severity}

    entries = ([entry(i, "added") for i in added] + [entry(i, "weakened") for i in weakened]
               + [entry(i, "removed") for i in removed] + [entry(i, "strengthened") for i in strengthened])
    return {
        "tool": "noascan", "version": __version__, "report": "surface", "as_of": as_of,
        "before": labels[0], "after": labels[1],
        "rules": rs.stamp(("secrets", "coverage", "config", "surface", "blast_radius")),
        "surface_before": len(a), "surface_after": len(b),
        "added": added, "removed": removed, "weakened": weakened, "strengthened": strengthened,
        "unreadable_added": unreadable_added, "entries": entries, "counters": count, "delta": count["delta"],
        "verdict": verdict, "gate_rule": rule_id, "exit_code": exit_code,
    }
