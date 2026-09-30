"""S04 - Officina Brennero: a "fix" that opens a debug route and adds a credential."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from noascan import surface  # noqa: E402
from scenarios import _common as c  # noqa: E402

SID = "S04"


def check():
    p = c.load(HERE / "input" / "params.json")
    inp = HERE / "input"
    fix = surface.delta(inp / "before", inp / "after_fix", p["as_of"], labels=("before", "after_fix"))
    reduce = surface.delta(inp / "before", inp / "after_reduce", p["as_of"], labels=("before", "after_reduce"))

    failures: list[str] = []
    c.expect(HERE / "expected" / "fix.json", fix, failures)
    c.expect(HERE / "expected" / "reduce.json", reduce, failures)
    if fix["delta"] != 2:
        failures.append(f"delta of the 'fix' is {fix['delta']:+d}, not +2")
    if fix["verdict"] != "BLOCKED" or fix["exit_code"] != 3:
        failures.append(f"the 'fix' is {fix['verdict']}, not BLOCKED")
    if sorted(fix["added"]) != sorted(p["expected_added"]):
        failures.append("the two added entries are not the debug route and the credential")
    if [e["item"] for e in fix["entries"] if e["change"] == "added"] != fix["added"] or fix["removed"] or fix["weakened"]:
        failures.append("the report lists changes other than the two added entries")
    if reduce["delta"] >= 0 or reduce["exit_code"] != 0:
        failures.append(f"the reducing patch does not pass (delta {reduce['delta']:+d}, {reduce['verdict']})")
    line = (f"'fix' delta {fix['delta']:+d} {fix['verdict']} with {len(fix['added'])} entries (debug route, credential by "
            f"fingerprint); reducing patch delta {reduce['delta']:+d} {reduce['verdict']}")
    return c.result(SID, failures, line, {"fix": fix["delta"], "reduce": reduce["delta"]})


if __name__ == "__main__":
    c.main(check)
