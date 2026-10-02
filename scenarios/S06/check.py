"""S06 - Cooperativa Tessile Arvale, tabletop "compromised key": the key is rotated and never revoked."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from scenarios import _common as c  # noqa: E402
from tabletop import judge as tjudge  # noqa: E402
from tabletop.log import read  # noqa: E402

SID = "S06"


def check():
    p = c.load(HERE / "input" / "params.json")
    playbook = tjudge.load_playbook(p["playbook"])
    faulty = tjudge.judge(read(HERE / "input" / "faulty.jsonl"), playbook, p["as_of"])
    clean = tjudge.judge(read(HERE / "input" / "clean.jsonl"), playbook, p["as_of"])

    failures: list[str] = []
    c.expect(HERE / "expected" / "faulty.json", faulty, failures)
    c.expect(HERE / "expected" / "clean.json", clean, failures)
    got = [(v["code"], v["step"]) for v in faulty["violations"]]
    if faulty["verdict"] != "FAILED" or faulty["closure"] != "BLOCKED":
        failures.append(f"the faulty transcript is {faulty['verdict']} with closure {faulty['closure']}")
    if got != [("ROTATED_NOT_REVOKED", "revoke_old_key")]:
        failures.append(f"violations are {got}, not the missing revocation alone")
    if clean["verdict"] != "PASSED" or clean["violations"] or clean["closure"] != "ALLOWED":
        failures.append("the clean transcript does not pass")
    line = (f"rotated, not revoked -> {faulty['verdict']} on step {got[0][1] if got else '?'} "
            f"({got[0][0] if got else '?'}), closure {faulty['closure']}; clean transcript {clean['verdict']}")
    return c.result(SID, failures, line, {"faulty": faulty["verdict"], "clean": clean["verdict"]})


if __name__ == "__main__":
    c.main(check)
