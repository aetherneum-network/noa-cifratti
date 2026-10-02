"""S05 - Studio Cartografico Lunaria: a new entry point that the threat model does not know."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from scenarios import _common as c  # noqa: E402
from threatmodel import check as tm  # noqa: E402

SID = "S05"


def check():
    p = c.load(HERE / "input" / "params.json")
    model = c.load(c.ROOT / "threatmodel" / "model.json")
    changed = tm.check(model, HERE / "input" / "target", p["as_of"])
    own = tm.check(model, c.ROOT / "threatmodel" / "target", p["as_of"])

    failures: list[str] = []
    c.expect(HERE / "expected" / "changed_topology.json", changed, failures)
    c.expect(HERE / "expected" / "own_topology.json", own, failures)
    codes = [(f["code"], f["subject"]) for f in changed["failures"]]
    if changed["verdict"] != "FAILED" or changed["exit_code"] != 1:
        failures.append(f"the check on the changed topology is {changed['verdict']}, not FAILED")
    if codes != [("ENTRY_POINT_NOT_IN_MODEL", p["new_entry_point"])]:
        failures.append("the failure does not name the new entry point, or names something else too")
    if not model.get("as_of") or changed["model_as_of"] != model["as_of"] or changed["as_of"] != p["as_of"]:
        failures.append("the report does not carry the date of the model and the reference date")
    if own["verdict"] != "PASSED" or own["failures"]:
        failures.append("the model does not pass on its own topology")
    line = (f"new entry point {p['new_entry_point']} -> {changed['verdict']} ({codes[0][0] if codes else 'no code'}); "
            f"model dated {changed['model_as_of']}; the model passes on its own topology "
            f"({len(own['threats'])} threats, {len(own['entry_points_in_topology'])} entry points)")
    return c.result(SID, failures, line, {"changed": changed["verdict"], "own": own["verdict"]})


if __name__ == "__main__":
    c.main(check)
