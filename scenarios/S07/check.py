"""S07 - Officina Brennero, tabletop "rogue container": restart before the evidence is preserved."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from scenarios import _common as c  # noqa: E402
from tabletop import judge as tjudge, runner  # noqa: E402
from tabletop.log import read  # noqa: E402

SID = "S07"


def check():
    p = c.load(HERE / "input" / "params.json")
    playbook = tjudge.load_playbook(p["playbook"])
    work = c.workdir(SID)
    faulty = tjudge.judge(read(HERE / "input" / "faulty.jsonl"), playbook, p["as_of"])
    no_consent = runner.run(playbook, runner.load_script(HERE / "input" / "script_no_consent.json"), work / "no_consent.jsonl")
    judged_no_consent = tjudge.judge(read(work / "no_consent.jsonl"), playbook, p["as_of"])
    with_consent = runner.run(playbook, runner.load_script(HERE / "input" / "script_clean.json"), work / "clean.jsonl")
    judged_clean = tjudge.judge(read(work / "clean.jsonl"), playbook, p["as_of"])

    failures: list[str] = []
    c.expect(HERE / "expected" / "faulty.json", faulty, failures)
    c.expect(HERE / "expected" / "no_consent.json", {"run": no_consent, "judgement": judged_no_consent}, failures)
    c.expect(HERE / "expected" / "clean.json", {"run": with_consent, "judgement": judged_clean}, failures)
    got = [(v["code"], v["step"]) for v in faulty["violations"]]
    if faulty["verdict"] != "FAILED" or ("EVIDENCE_DESTROYED", "restart_container") not in got:
        failures.append(f"the restart before preservation is not judged EVIDENCE_DESTROYED (got {got})")
    if no_consent["refused"] != [{"step": "restart_container", "reason": "CONSENT_MISSING"}]:
        failures.append("the runner did not refuse the destructive step without a human's consent")
    if "restart_container" in no_consent["executed"]:
        failures.append("the destructive step ran without consent")
    if judged_no_consent["closure"] != "BLOCKED" or len(judged_no_consent["refused"]) != 1:
        failures.append("the refused run is not blocked, or the refusal is not in the log")
    if with_consent["refused"] or judged_clean["verdict"] != "PASSED":
        failures.append("the ordered run with a human's consent does not pass")
    line = (f"restart before preservation -> {faulty['verdict']} ({got[0][0] if got else '?'}); destructive step without "
            f"human consent -> refused by the runner ({no_consent['refused'][0]['reason'] if no_consent['refused'] else '?'}), "
            f"closure {judged_no_consent['closure']}; ordered run with consent {judged_clean['verdict']}")
    return c.result(SID, failures, line, {"faulty": faulty["verdict"], "refused": len(no_consent["refused"])})


if __name__ == "__main__":
    c.main(check)
