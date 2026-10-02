"""S08 - Studio Cartografico Lunaria, tabletop "leaked endpoint": the identifier is transposed in the hand-off."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from scenarios import _common as c  # noqa: E402
from tabletop import judge as tjudge  # noqa: E402
from tabletop.log import read  # noqa: E402

SID = "S08"


def check():
    p = c.load(HERE / "input" / "params.json")
    playbook = tjudge.load_playbook(p["playbook"])
    events = read(HERE / "input" / "transcript.jsonl")
    out = tjudge.judge(events, playbook, p["as_of"], artifacts=HERE / "input" / "artifacts")

    failures: list[str] = []
    c.expect(HERE / "expected" / "judgement.json", out, failures)
    got = [(v["code"], v["step"]) for v in out["violations"]]
    details = " | ".join(d for v in out["violations"] for d in v["details"])
    if got != [("IDENTIFIER_MISMATCH", "handoff_to_owner")]:
        failures.append(f"violations are {got}, not the identifier mismatch at the hand-off")
    if out["closure"] != "BLOCKED" or out["closing_step"] != "all_clear":
        failures.append("the all-clear is not blocked")
    for needle in ("alert.json", "handoff.json", p["alerted"], p["handed_off"]):
        if needle not in details:
            failures.append(f"the judgement does not cite {needle}")
    authors = {word for word in details.replace(";", " ").split() if "@" in word}
    if len(authors) < 2:
        failures.append("the judgement does not cite the two authors")
    cited = sorted(n for n in ("alert.json", "handoff.json", "receipt.json") if n in details)
    line = (f"identifier {p['alerted']} alerted, {p['handed_off']} handed off -> {out['verdict']} at "
            f"{got[0][1] if got else '?'}; all-clear {out['closure']}; cited files {', '.join(cited)} and {len(authors)} authors")
    return c.result(SID, failures, line, {"closure": out["closure"], "authors": sorted(authors)})


if __name__ == "__main__":
    c.main(check)
