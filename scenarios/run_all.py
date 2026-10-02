"""Run the ten scenario checks; print one PASS/FAIL line each and a total. Exit 1 if any fails.

    python scenarios/run_all.py [S01 S04 ...] [--json reports/scenarios.json]

The JSON report holds no timing and no path of this machine: two runs give the same bytes.
"""
import importlib.util
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

IDS = [f"S{i:02d}" for i in range(1, 11)]


def load_check(sid):
    spec = importlib.util.spec_from_file_location(f"scenario_{sid}", HERE / sid / "check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.check


def run_all(ids=IDS, quiet=False):
    results = []
    for sid in ids:
        t = time.perf_counter()
        try:
            ok, line, details = load_check(sid)()
        except Exception as exc:  # a crashing check is a failing check
            ok, line, details = False, f"{sid} FAIL - {type(exc).__name__}: {exc}", {}
        line = line.encode("ascii", "replace").decode("ascii")
        results.append({"id": sid, "ok": ok, "line": line, "details": details})
        if not quiet:
            print(f"{line}  [{time.perf_counter() - t:.1f}s]", flush=True)
    if not quiet:
        print(f"\nScenarios: {sum(1 for r in results if r['ok'])}/{len(results)} PASS")
    return results


def main(argv):
    out = None
    if "--json" in argv:
        i = argv.index("--json")
        out = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    ids = [a for a in argv if not a.startswith("--")] or IDS
    results = run_all(ids)
    if out is not None:
        titles = {sid: json.loads((HERE / sid / "scenario.json").read_text(encoding="utf-8"))["title"] for sid in ids}
        doc = {"report": "scenarios", "passed": sum(1 for r in results if r["ok"]), "total": len(results),
               "scenarios": [{"id": r["id"], "title": titles[r["id"]], "result": "PASS" if r["ok"] else "FAIL",
                              "line": r["line"]} for r in results]}
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="ascii", newline="\n") as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
