"""Command line of noascan.

    python -m noascan scan DIR --as-of ISO [--tree-only] [--exclude NAME ...] [--allowlist FILE] [--json OUT]
    python -m noascan surface BEFORE AFTER --as-of ISO [--json OUT]
    python -m noascan rules-diff DIR --patch FILE --as-of ISO [--json OUT]
    python -m noascan rules-test

Exit codes of ``scan``: 0 CLEAN or EXCEPTIONS_ONLY, 2 NEEDS_REVIEW or NOT_COVERED, 3 BLOCKED,
64 usage or rule-file error. ``--as-of`` is mandatory: the tool never reads the clock.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from noascan import __version__, report, rules_engine, selftest, surface
from noascan.scan import RuleSet, scan


def finding_key(f: dict[str, Any]) -> str:
    return "|".join([f["kind"], f["class"], f["path"], f.get("fingerprint") or f.get("subject", "")])


def rules_diff(root: Path, as_of: str, patch: dict[str, Any], label: str | None = None) -> dict[str, Any]:
    """Scan twice - current rules, patched rules - and report exactly which findings change."""
    base = RuleSet.load()
    target = patch.get("file", "secrets")
    changed = RuleSet.load({target: rules_engine.patched(base.raw[target], patch)})
    before, after = scan(root, as_of, label=label, rules=base), scan(root, as_of, label=label, rules=changed)
    a = {finding_key(f): f for f in before["findings"]}
    b = {finding_key(f): f for f in after["findings"]}

    def slim(f: dict[str, Any]) -> dict[str, Any]:
        return {k: f[k] for k in ("kind", "class", "rule", "path", "line", "fingerprint", "subject", "severity") if k in f}

    return {
        "tool": "noascan", "version": __version__, "report": "rules-diff", "as_of": as_of, "target": before["target"],
        "patch": {"file": target, "rule": patch["rule"], "keys": sorted(patch["set"])},
        "rules_before": base.stamp((target,)), "rules_after": changed.stamp((target,)),
        "inline_tests_failing_after": selftest.run_all(changed.raw),
        "findings_before": len(a), "findings_after": len(b),
        "lost": [slim(a[k]) for k in sorted(set(a) - set(b))],
        "gained": [slim(b[k]) for k in sorted(set(b) - set(a))],
        "rule_changed": [{"finding": slim(b[k]), "was": a[k]["rule"]} for k in sorted(set(a) & set(b))
                         if a[k]["rule"] != b[k]["rule"]],
        "verdict_before": before["verdict"], "verdict_after": after["verdict"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="noascan", description="Verification tooling on synthetic repositories.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan", help="scan a directory (working tree and git history)")
    p.add_argument("dir", type=Path)
    p.add_argument("--tree-only", action="store_true", help="do not read the git history: if one exists the verdict is NOT_COVERED, never CLEAN")
    p.add_argument("--exclude", action="append", default=[], help="name or relative path not to read (counted as an exception)")
    p.add_argument("--allowlist", type=Path)
    p.add_argument("--label")
    p = sub.add_parser("surface", help="attack-surface delta between two trees")
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p = sub.add_parser("rules-diff", help="which findings change if one rule is patched")
    p.add_argument("dir", type=Path)
    p.add_argument("--patch", type=Path, required=True)
    sub.add_parser("rules-test", help="run the inline tests of the rule files")
    for name in ("scan", "surface", "rules-diff"):
        sub.choices[name].add_argument("--as-of", required=True, help="reference date and time (ISO 8601); never the clock")
        sub.choices[name].add_argument("--json", type=Path, help="write the JSON report here")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 64 if exc.code else 0
    try:
        if args.cmd == "rules-test":
            failures = selftest.run_all(RuleSet.load().raw)
            print(f"inline rule tests: {len(failures)} failing")
            for line in failures:
                print("  " + line)
            return 1 if failures else 0
        if args.cmd == "scan":
            allow = rules_engine.load(args.allowlist) if args.allowlist else None
            out = scan(args.dir, args.as_of, label=args.label, read_history=not args.tree_only,
                       exclude=tuple(args.exclude), allowlist=allow)
            sys.stdout.write(report.summary(out))
        elif args.cmd == "surface":
            out = surface.delta(args.before, args.after, args.as_of)
            print(f"surface delta: {out['delta']:+d}  verdict: {out['verdict']}  (rule {out['gate_rule']})")
            for e in out["entries"]:
                print(f"  {e['change']:<12} r{e['radius']} {e['item']}")
        else:
            out = rules_diff(args.dir, args.as_of, json.loads(args.patch.read_text(encoding="utf-8")))
            print(f"rules-diff: lost {len(out['lost'])}, gained {len(out['gained'])}; "
                  f"verdict {out['verdict_before']} -> {out['verdict_after']}")
    except (rules_engine.RuleError, OSError, ValueError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 64
    if args.json:
        report.write(args.json, out)
    return int(out.get("exit_code", 0))


if __name__ == "__main__":
    sys.exit(main())
