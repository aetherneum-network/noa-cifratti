"""S02 - Studio Cartografico Lunaria: five planted secrets among twelve decoys."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from noascan.scan import scan  # noqa: E402
from scenarios import _common as c  # noqa: E402

SID = "S02"


def check():
    labels = c.load(HERE / "input" / "labels.json")
    out = scan(HERE / "input" / "tree", labels["as_of"], label="tile-server")

    failures: list[str] = []
    c.expect(HERE / "expected" / "scan.json", out, failures)
    want = {(s["path"], s["line"], s["class"], s["fingerprint"]) for s in labels["secrets"]}
    got = {(f["path"], f["line"], f["class"], f["fingerprint"]) for f in out["findings"] if f["kind"] == "secret"}
    decoys = {(d["path"], d["line"]): d["kind"] for d in labels["decoys"]}
    others = [f for f in out["findings"] if f["kind"] != "secret"]
    on_decoys = [f for f in out["findings"] if (f["path"], f["line"]) in decoys]
    blocking_on_decoys = [f for f in on_decoys if f["kind"] == "secret"]
    if len(want) != 5 or len(decoys) != 12:
        failures.append("fixture error: the labels do not describe 5 secrets and 12 decoys")
    if want - got:
        failures.append(f"{len(want - got)} planted secrets not found")
    if got - want:
        failures.append(f"{len(got - want)} secret findings that were never planted")
    if blocking_on_decoys:
        failures.append(f"{len(blocking_on_decoys)} decoys reported as secrets")
    if len(on_decoys) > labels["max_false_positives"]:
        failures.append(f"{len(on_decoys)} findings on decoy lines, more than {labels['max_false_positives']}")
    if [f for f in others if (f["path"], f["line"]) not in decoys]:
        failures.append("a review finding sits on a line that is neither a plant nor a decoy")
    if out["verdict"] != "BLOCKED":
        failures.append(f"verdict is {out['verdict']}, not BLOCKED")
    line = (f"{len(want & got)}/5 planted secrets found; decoys reported as secrets: {len(blocking_on_decoys)}/12; "
            f"decoys sent to review: {len(on_decoys) - len(blocking_on_decoys)} "
            f"({', '.join(sorted(decoys[(f['path'], f['line'])] for f in on_decoys)) or 'none'}); verdict {out['verdict']}")
    return c.result(SID, failures, line, {"found": len(want & got), "on_decoys": len(on_decoys)})


if __name__ == "__main__":
    c.main(check)
