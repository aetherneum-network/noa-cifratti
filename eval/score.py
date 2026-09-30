"""Score the pack against a generated corpus and its gold labels.

    python eval/score.py --suite dev                      # seed and sizes from corpus/config.json
    python eval/score.py --suite holdout                  # eval/seeds.json
    python eval/score.py --suite stress                   # perturbed corpus: diagnosis, declared as such
    python eval/score.py --suite blind --seed N --runner NAME     # see eval/BLIND_PROTOCOL.md

What is measured is *internal consistency on synthetic data*: the scanner, the surface delta and the
judge against labels that come from the seeding plan. It says nothing about any real system.

Output is deterministic (no clock, no timing): ``--json`` writes it, ``--record`` appends the key
numbers to ``eval/history.json`` together with ``--run-date`` (the date is given, never read).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus import generate, gold, repos  # noqa: E402
from noascan import report, surface  # noqa: E402
from noascan.scan import RuleSet, scan  # noqa: E402
from tabletop import judge as tjudge, log as tlog  # noqa: E402

SEEDS = json.loads((ROOT / "eval" / "seeds.json").read_text(encoding="utf-8"))
FREEZE_TAG = "v2.0.0-freeze"
FROZEN_PATHS = ["noascan", "rules", "playbooks", "tabletop", "threatmodel", "corpus", "eval/score.py", "eval/manual.py",
                "eval/seeds.json"]


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def prf(tp: int, fp: int, fn: int) -> dict[str, Any]:
    return {"tp": tp, "fp": fp, "fn": fn, "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn)}


def score(corpus_dir: Path, gold_dir: Path, seed: int, perturbed: bool, as_of: str) -> dict[str, Any]:
    rs = RuleSet.load()
    repo_gold = gold.read_jsonl(gold_dir / "repos.jsonl")
    labels = gold.read_jsonl(gold_dir / "labels.jsonl")
    by_repo: dict[str, list[dict]] = {}
    for rec in labels:
        by_repo.setdefault(rec["repo"], []).append(rec)

    classes = rs.secrets.covered_classes
    sec = {c: {"tp": 0, "fp": 0, "fn": 0} for c in classes}
    review = {"config": {}, "pycode": {}}
    verdicts = {"agree": 0, "acceptable": 0, "wrong": 0}
    never_event, clean_with_hidden, clean_false_alarm = [], [], []
    location = {"checked": 0, "path_ok": 0, "commit_ok": 0, "line_ok": 0}
    techniques: dict[str, dict[str, int]] = {}
    decoys = {"planted": 0, "flagged": 0, "by_kind": {}}
    suspects_unmatched = 0
    fp_examples: list[dict[str, Any]] = []
    leaks = 0
    confusion: dict[str, dict[str, int]] = {}

    for idx, rg in enumerate(repo_gold, 1):
        root = corpus_dir / "repos" / rg["repo"]
        out = scan(root, as_of, rules=rs)
        text = report.dumps(out) + report.summary(out)
        plan = repos.plan_repo(seed, idx, perturbed)          # the harness knows the values; the reports must not
        for p in plan.plants:
            if p.kind != "secret":
                continue
            needles = [ln for ln in p.value.split("\n") if not ln.startswith("-----")] if "\n" in p.value else [p.value]
            leaks += sum(1 for n in needles if n and n in text)

        recs = by_repo.get(rg["repo"], [])
        gold_sec = [r for r in recs if r["kind"] == "secret"]
        found_sec = [f for f in out["findings"] if f["kind"] == "secret"]
        matched: set[int] = set()
        for g in gold_sec:
            tech = techniques.setdefault(g["technique"], {"planted": 0, "covered": 0, "found_as_secret": 0,
                                                          "found_in_other_form": 0, "suspect_at_path": 0,
                                                          "repo_clean": 0})
            tech["planted"] += 1
            tech["covered"] += int(g["covered"])
            hit = next((i for i, f in enumerate(found_sec) if f["fingerprint"] == g["fingerprint"] and f["class"] == g["class"]
                        and (f["path"] == g["path"] or g["carrier"] == "dangling_blob")), None)
            if hit is not None:
                matched.add(hit)
                tech["found_as_secret"] += 1
                f = found_sec[hit]
                if g["covered"]:     # a carrier outside coverage has no line to compare
                    location["checked"] += 1
                    location["path_ok"] += int(f["path"] == g["path"] or g["carrier"] == "dangling_blob")
                    location["commit_ok"] += int(f["commit"] == g["first_commit"])
                    location["line_ok"] += int(f["line"] == (g["line"] if g["in_head"] else g["first_line"]))
            if any(f["kind"] == "suspect" and f["path"] == g["path"] for f in out["findings"]):
                tech["suspect_at_path"] += 1
            tech["repo_clean"] += int(out["verdict"] == "CLEAN")
            if g["covered"]:
                sec[g["class"]]["tp" if hit is not None else "fn"] += 1
        decoy_at = {(r["path"], r["line"]): r["class"] for r in recs if r["decoy"]}
        decoys["planted"] += len(decoy_at)
        flagged_decoys: set[tuple[str, int]] = set()
        hidden_at = {(g["path"], g["class"]): g["technique"] for g in gold_sec if not g["covered"]}
        for i, f in enumerate(found_sec):
            if i in matched:
                continue
            if (f["path"], f["class"]) in hidden_at:
                # a plant outside coverage, found in a different form (other fingerprint): not a false positive
                techniques[hidden_at[(f["path"], f["class"])]]["found_in_other_form"] += 1
                continue
            sec.setdefault(f["class"], {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
            kind = decoy_at.get((f["path"], f["line"]), "")
            if len(fp_examples) < 12:
                fp_examples.append({"repo": rg["repo"], "class": f["class"], "rule": f["rule"], "path": f["path"],
                                    "line": f["line"], "decoy_kind": kind})
        for f in out["findings"]:
            if f["kind"] in ("secret", "suspect") and (f["path"], f["line"]) in decoy_at:
                flagged_decoys.add((f["path"], f["line"]))
            if f["kind"] == "suspect" and not any(g["path"] == f["path"] for g in gold_sec):
                suspects_unmatched += 1
        for key in flagged_decoys:
            decoys["flagged"] += 1
            decoys["by_kind"][decoy_at[key]] = decoys["by_kind"].get(decoy_at[key], 0) + 1

        for kind in ("config", "pycode"):
            want = {(r["class"], r["path"], r["subject"] if kind == "config" else str(r["line"])) for r in recs if r["kind"] == kind}
            got = {(f["class"], f["path"], f["subject"] if kind == "config" else str(f["line"]))
                   for f in out["findings"] if f["kind"] == kind}
            for cls, _, _ in want | got:
                review[kind].setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})
            for key in want & got:
                review[kind][key[0]]["tp"] += 1
            for key in want - got:
                review[kind][key[0]]["fn"] += 1
            for key in got - want:
                review[kind][key[0]]["fp"] += 1

        verdict = out["verdict"]
        confusion.setdefault(rg["expected_verdict"], {}).setdefault(verdict, 0)
        confusion[rg["expected_verdict"]][verdict] += 1
        if verdict == rg["expected_verdict"]:
            verdicts["agree"] += 1
        elif verdict in rg["acceptable_verdicts"]:
            verdicts["acceptable"] += 1
        else:
            verdicts["wrong"] += 1
        if verdict == "CLEAN" and rg["has_covered_secret"]:
            never_event.append(rg["repo"])
        if verdict == "CLEAN" and rg["has_uncovered_secret"] and not rg["has_covered_secret"]:
            clean_with_hidden.append(rg["repo"])
        if rg["expected_verdict"] == "CLEAN" and verdict != "CLEAN":
            clean_false_alarm.append(rg["repo"])

    def table(counts: dict[str, dict[str, int]]) -> dict[str, Any]:
        rows = {c: prf(**v) for c, v in sorted(counts.items())}
        rows["ALL"] = prf(sum(v["tp"] for v in counts.values()), sum(v["fp"] for v in counts.values()),
                          sum(v["fn"] for v in counts.values()))
        return rows

    # surface delta -------------------------------------------------------------------------------------------------
    pairs = gold.read_jsonl(gold_dir / "patches.jsonl")
    surf = {"pairs": len(pairs), "items_exact": 0, "delta_exact": 0, "gate_agree": 0}
    for g in pairs:
        out = surface.delta(corpus_dir / "patches" / g["pair"] / "before", corpus_dir / "patches" / g["pair"] / "after", as_of, rs)
        surf["items_exact"] += int(all(out[k] == g[k] for k in ("added", "removed", "weakened", "strengthened")))
        surf["delta_exact"] += int(out["delta"] == g["delta"])
        surf["gate_agree"] += int(out["verdict"] == g["expected_gate"])

    # tabletop judge ------------------------------------------------------------------------------------------------
    transcripts = gold.read_jsonl(gold_dir / "tabletops.jsonl")
    tab = {"transcripts": len(transcripts), "gold_failed": 0, "verdict_agree": 0, "violations_exact": 0,
           "failed_called_passed": 0, "passed_called_failed": 0}
    playbooks: dict[str, dict] = {}
    for g in transcripts:
        pb = playbooks.setdefault(g["playbook"], tjudge.load_playbook(g["playbook"]))
        out = tjudge.judge(tlog.read(corpus_dir / "tabletops" / f"{g['transcript']}.jsonl"), pb, as_of, secret_rules=rs.secrets)
        got = sorted([v["code"], v["step"]] for v in out["violations"])
        tab["gold_failed"] += int(g["expected_verdict"] == "FAILED")
        tab["verdict_agree"] += int(out["verdict"] == g["expected_verdict"])
        tab["violations_exact"] += int(got == g["expected_violations"])
        tab["failed_called_passed"] += int(g["expected_verdict"] == "FAILED" and out["verdict"] == "PASSED")
        tab["passed_called_failed"] += int(g["expected_verdict"] == "PASSED" and out["verdict"] == "FAILED")

    return {
        "seed": seed, "perturbed": perturbed, "as_of": as_of, "rules": rs.stamp(),
        "statement": "internal consistency on synthetic data; no claim about any real system",
        "repos": len(repo_gold), "secrets_by_class": table(sec),
        "secret_location": location, "decoys": decoys, "suspects_without_a_plant_at_path": suspects_unmatched,
        "false_positive_examples": fp_examples,
        "techniques": dict(sorted(techniques.items())),
        "config_by_class": table(review["config"]), "pycode_by_class": table(review["pycode"]),
        "verdicts": verdicts, "verdict_confusion_expected_to_got": {k: dict(sorted(v.items())) for k, v in sorted(confusion.items())},
        "never_event_clean_with_covered_secret": {"count": len(never_event), "repos": never_event},
        "clean_with_only_out_of_coverage_secret": {"count": len(clean_with_hidden), "repos": clean_with_hidden},
        "clean_repos_not_called_clean": {"count": len(clean_false_alarm), "repos": clean_false_alarm[:20]},
        "secret_values_in_reports": leaks,
        "surface": surf, "tabletop": tab,
    }


def key_numbers(res: dict[str, Any]) -> dict[str, Any]:
    """The few numbers that go to eval/history.json (the full result stays in eval/results-*.json)."""
    s, c, p = res["secrets_by_class"]["ALL"], res["config_by_class"]["ALL"], res["pycode_by_class"]["ALL"]
    return {"repos": res["repos"], "secrets": s, "config": c, "pycode": p,
            "never_event": res["never_event_clean_with_covered_secret"]["count"],
            "clean_with_only_out_of_coverage_secret": res["clean_with_only_out_of_coverage_secret"]["count"],
            "clean_repos_not_called_clean": res["clean_repos_not_called_clean"]["count"],
            "verdicts": res["verdicts"], "secret_values_in_reports": res["secret_values_in_reports"],
            "surface": res["surface"], "tabletop": res["tabletop"]}


def frozen_state() -> tuple[bool, str]:
    """(is the code identical to the freeze tag?, short explanation). Read-only git commands."""
    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)

    if git("rev-parse", "--verify", "--quiet", f"refs/tags/{FREEZE_TAG}").returncode != 0:
        return False, f"tag {FREEZE_TAG} not found"
    diff = git("diff", "--quiet", FREEZE_TAG, "--", *FROZEN_PATHS)
    if diff.returncode != 0:
        return False, f"frozen paths differ from {FREEZE_TAG}"
    return True, git("rev-parse", f"{FREEZE_TAG}^{{commit}}").stdout.strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score the pack on a generated corpus (synthetic data only).")
    ap.add_argument("--suite", required=True, choices=["dev", "holdout", "stress", "blind"])
    ap.add_argument("--seed", type=int)
    ap.add_argument("--runner", help="who runs a blind evaluation (a different hand than the author)")
    ap.add_argument("--perturb", action="store_true", help="blind suite only: also hide the secrets (corpus/perturb.py)")
    ap.add_argument("--repos", type=int)
    ap.add_argument("--transcripts", type=int)
    ap.add_argument("--pairs", type=int)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--record", action="store_true", help="append the key numbers to eval/history.json")
    ap.add_argument("--run-date", help="date and time of the run (ISO 8601), given by the runner")
    ap.add_argument("--note", default="")
    args = ap.parse_args(argv)

    cfg = generate.CONFIG
    sizes = (args.repos or cfg["repos"], args.transcripts or cfg["transcripts"], args.pairs or cfg["patch_pairs"])
    freeze = ""
    if args.suite == "blind":
        if args.seed is None or not args.runner:
            print("error: a blind run needs --seed and --runner", file=sys.stderr)
            return 64
        if args.seed in SEEDS["author_seeds"].values():
            print("error: this seed was used by the author during development; choose another one", file=sys.stderr)
            return 64
        ok, freeze = frozen_state()
        if not ok:
            print(f"error: not a blind run: {freeze}", file=sys.stderr)
            return 64
        seed, perturbed = args.seed, args.perturb
    else:
        seed, perturbed = SEEDS["author_seeds"][args.suite], args.suite == "stress"
    if args.record and not args.run_date:
        print("error: --record needs --run-date (the clock is never read)", file=sys.stderr)
        return 64

    out_dir = ROOT / "build" / "corpus" / f"{args.suite}-{seed}"
    generate.generate(seed, out_dir, out_dir / "gold", cfg["as_of"], *sizes, perturb=perturbed)
    res = score(out_dir, out_dir / "gold", seed, perturbed, cfg["as_of"])
    res = dict(res, suite=args.suite, sizes={"repos": sizes[0], "transcripts": sizes[1], "patch_pairs": sizes[2]})
    k = key_numbers(res)
    print(f"suite {args.suite} seed {seed}{' (perturbed)' if perturbed else ''}: {sizes[0]} repositories, "
          f"{sizes[1]} transcripts, {sizes[2]} patch pairs")
    print(f"  secrets  precision {k['secrets']['precision']} recall {k['secrets']['recall']} "
          f"(tp {k['secrets']['tp']}, fp {k['secrets']['fp']}, fn {k['secrets']['fn']})")
    print(f"  config   precision {k['config']['precision']} recall {k['config']['recall']}; "
          f"pycode precision {k['pycode']['precision']} recall {k['pycode']['recall']}")
    print(f"  verdicts {k['verdicts']}; never-event (CLEAN with a covered secret): {k['never_event']}; "
          f"CLEAN with only out-of-coverage secrets: {k['clean_with_only_out_of_coverage_secret']}")
    print(f"  secret values found in reports: {k['secret_values_in_reports']}")
    print(f"  surface {k['surface']}")
    print(f"  tabletop {k['tabletop']}")
    if args.json:
        report.write(args.json, res)
    if args.record:
        path = ROOT / "eval" / "history.json"
        hist = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"runs": []}
        hist["runs"].append({"run": len(hist["runs"]) + 1, "run_date": args.run_date, "suite": args.suite, "seed": seed,
                             "perturbed": perturbed, "runner": args.runner or SEEDS["author"], "freeze_commit": freeze,
                             "sizes": res["sizes"], "rules": [{"file": n, "sha256_12": v["sha256"][:12]} for n, v in res["rules"].items()],
                             "numbers": k, "note": args.note})
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(hist, indent=2, ensure_ascii=True) + "\n")
    return 0 if k["never_event"] == 0 and k["secret_values_in_reports"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
