"""S09 - Cooperativa Tessile Arvale: a secret rule is narrowed; only the expected findings may change."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from corpus import gold  # noqa: E402
from noascan.__main__ import rules_diff  # noqa: E402
from scenarios import _common as c  # noqa: E402

SID = "S09"


def check():
    p = c.load(HERE / "input" / "params.json")
    patch = c.load(HERE / "input" / "patch.json")
    seed = p["seed"]
    env_pw, yml_pw, sh_pw = (c.fake(SID, seed, "assigned_password", n) for n in range(3))
    token = c.fake(SID, seed, "vendor_api_token")
    files = {"README.md": "# yarn-inventory\n\nCooperativa Tessile Arvale (a fictitious company).\n",
             "deploy/prod.env": f"LOG_LEVEL=warn\nSMTP_PASSWORD={env_pw}\n",
             "deploy/values.yml": f"app:\n  replicas: 2\n  dbPassword: {yml_pw}\n",
             "scripts/backup.sh": f"#!/bin/sh\nexport BACKUP_PASSWORD={sh_pw}\ntar -cf - data\n",
             "src/settings.py": f'NBX_API_TOKEN = "{token}"\n'}
    root = c.workdir(SID) / "yarn-inventory"
    c.build_repo(root, p["company"], [("initial import", files)])
    out = rules_diff(root, p["as_of"], patch)

    failures: list[str] = []
    c.expect(HERE / "expected" / "rules_diff.json", out, failures)
    lost = sorted((f["path"], f["fingerprint"]) for f in out["lost"])
    expected = sorted([("deploy/values.yml", gold.fingerprint(yml_pw)), ("scripts/backup.sh", gold.fingerprint(sh_pw))])
    if lost != expected:
        failures.append(f"lost findings are not the two expected ones ({len(lost)} lost)")
    if out["gained"] or out["rule_changed"]:
        failures.append("the patch gained findings or moved a finding to another rule")
    if out["findings_before"] != 4 or out["findings_after"] != 2:
        failures.append(f"findings {out['findings_before']} -> {out['findings_after']}, expected 4 -> 2")
    if out["rules_before"] == out["rules_after"]:
        failures.append("the report does not show that the rule file changed")
    line = (f"rule {patch['rule']} narrowed: findings {out['findings_before']} -> {out['findings_after']}; lost exactly the "
            f"{len(expected)} expected (values.yml, backup.sh), gained {len(out['gained'])}; rule's own examples no longer "
            f"matched: {len(out['inline_tests_failing_after'])} (reported)")
    return c.result(SID, failures, line, {"lost": len(lost), "gained": len(out["gained"])})


if __name__ == "__main__":
    c.main(check)
