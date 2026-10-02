"""Check a threat model against the topology it claims to describe.

    python threatmodel/check.py --as-of ISO [--target DIR] [--model FILE] [--json OUT]
    python threatmodel/check.py --render            # the table embedded in SECURITY.md

The model is a document; this check is what keeps it honest. It fails when

* the topology has an entry point the model does not know (``ENTRY_POINT_NOT_IN_MODEL``);
* the model lists an entry point the topology no longer has (``STALE_ENTRY_POINT``);
* an entry point or an asset has no threat (``ENTRY_POINT_WITHOUT_THREAT``, ``ASSET_WITHOUT_THREAT``);
* a threat is neither mitigated nor accepted, a mitigation cannot be observed in the topology, or
  an accepted risk lacks owner, date or a review date still in the future at ``as_of``.

Exit code 0 = PASSED, 1 = FAILED, 64 = usage or unreadable input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from noascan import __version__, config, gate, report, rules_engine  # noqa: E402
from noascan.scan import RuleSet, read_tree  # noqa: E402
from noascan.secrets import classify, scan_text  # noqa: E402

CATEGORIES = ("spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service",
              "elevation_of_privilege")


class Topology:
    def __init__(self, root: Path, rs: RuleSet):
        files, _ = read_tree(root)
        covered: dict[str, str] = {}
        self.secrets = 0
        self.unreadable: list[str] = []
        for path in sorted(files):
            data = files[path]
            self.secrets += sum(1 for h in scan_text(None, path, rs.secrets) if h.action == "report")   # names too
            reason, _, text = (("unreadable", None, None) if data is None
                               else classify(data, rs.raw["coverage"], rs.secrets.limits))
            if reason is not None:
                self.unreadable.append(path)
            elif text is not None:
                covered[path] = text
                self.secrets += sum(1 for h in scan_text(path, text, rs.secrets) if h.action == "report")
        self.model = config.parse(covered, rs.raw["config"])
        self.unreadable += [p for p, _ in self.model.errors]
        self.surface = rs.raw["surface"]
        self.routers = {f"route:{r['entrypoint']}:{r['host']}{r['path_prefix']}": r for _, r in self.model.routers}
        self.services = {s["name"]: s for _, s in self.model.services}
        self.middlewares = {m["name"]: m for _, m in self.model.middlewares}
        self.env = {(p, k): v for p, _, k, v in self.model.env}

    def entry_points(self) -> list[str]:
        items = list(self.routers)
        for name, svc in self.services.items():
            for entry in svc["published"]:
                bind, port = config.published(entry)
                items.append(f"port:{name}:{bind}:{port}")
            if self._socket(svc):
                items.append(f"socket:{name}")
        return sorted(items)

    def _socket(self, svc: dict[str, Any]) -> bool:
        return any(re.search(self.surface["socket_regex"], m.split(":", 1)[0]) for m in svc["mounts"])

    def holds(self, check: dict[str, Any]) -> bool:
        """Is the mitigation observable in the topology? Unknown check types never hold."""
        kind = check.get("type")
        private = tuple(self.surface["private_bind_prefixes"])
        if kind == "route_has_middleware":
            router = self.routers.get(check["item"])
            return router is not None and check["middleware"] in router["middlewares"]
        if kind == "middleware_setting":
            mw = self.middlewares.get(check["name"])
            return mw is not None and mw.get(check["key"]) == check["value"] and type(mw.get(check["key"])) is type(check["value"])
        if kind == "port_bind_private":
            svc = self.services.get(check["service"])
            return svc is not None and all(config.published(p)[0].startswith(private) for p in svc["published"])
        if kind == "no_published_port":
            svc = self.services.get(check["service"])
            return svc is not None and not svc["published"]
        if kind == "service_not_on_network":
            svc = self.services.get(check["service"])
            return svc is not None and check["network"] not in svc["networks"]
        if kind == "no_socket_mount":
            return bool(self.services) and not any(self._socket(s) for s in self.services.values())
        if kind == "env_flag_off":
            value = self.env.get((check["path"], check["key"]))
            return value is not None and value.lower() not in self.surface["debug_values"]
        if kind == "no_public_debug_route":
            return not any(r["entrypoint"] == "public" and config._prefix_hit(r["path_prefix"], self.surface["debug_prefixes"])
                           for r in self.routers.values())
        if kind == "no_covered_secret_in_tree":
            return self.secrets == 0 and not self.unreadable
        if kind == "playbook_invariant":
            try:
                pb = json.loads((ROOT / "playbooks" / f"{check['playbook']}.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return False
            return any(inv.get("code") == check["code"] for inv in pb.get("invariants", []))
        return False


def check(model: dict[str, Any], target: Path, as_of: str, rs: RuleSet | None = None) -> dict[str, Any]:
    report.reference_date(as_of)
    rs = rs or RuleSet.load()
    topo = Topology(target, rs)
    failures: list[dict[str, str]] = []

    def fail(code: str, subject: str, detail: str) -> None:
        failures.append({"code": code, "subject": report.safe(subject, rs.secrets), "detail": report.safe(detail, rs.secrets)})

    if not model.get("as_of"):
        fail("MODEL_WITHOUT_DATE", "model", "the model does not say when it was true")
    elif model["as_of"][:10] > as_of[:10]:
        fail("MODEL_DATED_IN_THE_FUTURE", "model", f"model as_of {model['as_of']} is later than the run")
    for path in topo.unreadable:
        fail("TOPOLOGY_NOT_READABLE", path, "a file of the target could not be read: the model cannot be checked against it")

    known = {ep["item"]: ep for ep in model.get("entry_points", [])}
    ep_ids = {ep["id"] for ep in model.get("entry_points", [])}
    assets = {a["id"]: a for a in model.get("assets", [])}
    actual = topo.entry_points()
    for item in actual:
        if item not in known:
            fail("ENTRY_POINT_NOT_IN_MODEL", item, "the topology exposes it and no entry point of the model describes it")
    for item, ep in known.items():
        if item not in actual:
            fail("STALE_ENTRY_POINT", ep["id"], f"{item} is in the model and not in the topology")
    threats = model.get("threats", [])
    for ep in model.get("entry_points", []):
        if not any(t.get("entry_point") == ep["id"] for t in threats):
            fail("ENTRY_POINT_WITHOUT_THREAT", ep["id"], f"{ep['item']} has no threat associated")
    for asset_id in assets:
        if not any(t.get("asset") == asset_id for t in threats):
            fail("ASSET_WITHOUT_THREAT", asset_id, "no threat names this asset")

    rows = []
    for t in threats:
        tid = t.get("id", "?")
        if t.get("entry_point") not in ep_ids or t.get("asset") not in assets:
            fail("THREAT_WITH_UNKNOWN_REFERENCE", tid, "entry point or asset is not declared in the model")
            continue
        if t.get("category") not in CATEGORIES:
            fail("THREAT_WITH_UNKNOWN_CATEGORY", tid, str(t.get("category")))
        radius, severity, rule = gate.grade("asset", assets[t["asset"]]["class"], rs.raw["blast_radius"])
        disposition = t.get("disposition")
        if disposition == "mitigated":
            checks = t.get("checks", [])
            if not checks:
                fail("MITIGATION_NOT_VERIFIABLE", tid, "a mitigation without an observable check is a statement, not a control")
            for c in checks:
                if not topo.holds(c):
                    fail("MITIGATION_NOT_IN_TOPOLOGY", tid, f"check {c.get('type')} does not hold in the target")
        elif disposition == "accepted":
            if not all(t.get(k) for k in ("owner", "date", "review_by", "rationale")):
                fail("ACCEPTED_WITHOUT_OWNER_OR_DATE", tid, "an accepted risk needs owner, date, review date and rationale")
            elif t["review_by"] < as_of[:10]:
                fail("ACCEPTED_RISK_REVIEW_OVERDUE", tid, f"review was due on {t['review_by']}")
        else:
            fail("THREAT_WITHOUT_DISPOSITION", tid, "neither mitigated nor accepted")
        rows.append({"id": tid, "radius": radius, "severity": severity, "blast_rule": rule, "asset": t["asset"],
                     "entry_point": t["entry_point"], "category": t.get("category", ""), "disposition": disposition or "",
                     "owner": t.get("owner", ""), "review_by": t.get("review_by", "")})
    rows.sort(key=lambda r: (-r["radius"], r["id"]))
    failures.sort(key=lambda f: (f["code"], f["subject"], f["detail"]))
    return {
        "tool": "noascan", "version": __version__, "report": "threatmodel", "as_of": as_of,
        "model_as_of": model.get("as_of", ""), "model_version": model.get("version", ""),
        "rules": rs.stamp(("blast_radius", "config", "surface")),
        "entry_points_in_topology": actual, "threats": rows, "failures": failures,
        "verdict": "FAILED" if failures else "PASSED", "exit_code": 1 if failures else 0,
    }


def render(model: dict[str, Any], rs: RuleSet | None = None) -> str:
    """The Markdown table embedded in SECURITY.md (a test keeps the two identical)."""
    rs = rs or RuleSet.load()
    assets = {a["id"]: a for a in model["assets"]}
    eps = {e["id"]: e for e in model["entry_points"]}
    rows = []
    for t in model["threats"]:
        radius, _, _ = gate.grade("asset", assets[t["asset"]]["class"], rs.raw["blast_radius"])
        if t["disposition"] == "mitigated":
            answer = "mitigated: " + t["mitigation"]
        else:
            answer = f"accepted by {t['owner']} on {t['date']}, review by {t['review_by']}: {t['rationale']}"
        rows.append((-radius, t["id"], f"| {t['id']} | {radius} | {assets[t['asset']]['name']} | `{eps[t['entry_point']]['item']}` "
                                       f"| {t['category']} | {t['statement']} | {answer} |"))
    head = ["| # | Radius | Asset | Entry point | Category | Threat | Answer |", "|---|---|---|---|---|---|---|"]
    return "\n".join(head + [r[2] for r in sorted(rows)]) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check threatmodel/model.json against the synthetic target.")
    ap.add_argument("--as-of")
    ap.add_argument("--target", type=Path, default=ROOT / "threatmodel" / "target")
    ap.add_argument("--model", type=Path, default=ROOT / "threatmodel" / "model.json")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--render", action="store_true")
    args = ap.parse_args(argv)
    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        if args.render:
            sys.stdout.write(render(model))
            return 0
        if not args.as_of:
            print("error: --as-of is mandatory", file=sys.stderr)
            return 64
        out = check(model, args.target, args.as_of)
    except (OSError, ValueError, KeyError, rules_engine.RuleError) as exc:
        print(f"error: {type(exc).__name__}", file=sys.stderr)
        return 64
    print(f"threat model (as of {out['model_as_of']}): {out['verdict']}; threats {len(out['threats'])}, "
          f"entry points in topology {len(out['entry_points_in_topology'])}, failures {len(out['failures'])}")
    for f in out["failures"]:
        print(f"  {f['code']:<28} {f['subject']}: {f['detail']}")
    if args.json:
        report.write(args.json, out)
    return out["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
