"""S01 - Officina Brennero: a secret is committed and removed by a later commit."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from corpus import gold  # noqa: E402
from noascan.scan import scan  # noqa: E402
from scenarios import _common as c  # noqa: E402

SID = "S01"


def check():
    p = c.load(HERE / "input" / "params.json")
    token = c.fake(SID, p["seed"], "vendor_api_token")
    env = "# production settings\nLOG_LEVEL=warn\nDEBUG=false\n"
    base = {"README.md": "# workshop-orders\n\nOfficina Brennero S.r.l. (a fictitious company).\n",
            "src/app.py": "def main():\n    return 0\n", "deploy/prod.env": env}
    leaked = dict(base, **{"deploy/prod.env": env + f"NBX_API_TOKEN={token}\n"})
    removed = dict(base, **{"deploy/prod.env": env + "# the gateway token now comes from the secret store\n"})
    root = c.workdir(SID) / "workshop-orders"
    ids = c.build_repo(root, p["company"], [("initial import", base),
                                            ("add the gateway token to the production settings", leaked),
                                            ("remove the token from the environment file", removed)])
    full = scan(root, p["as_of"])
    tree = scan(root, p["as_of"], read_history=False)

    failures: list[str] = []
    c.expect(HERE / "expected" / "scan.json", full, failures)
    c.expect(HERE / "expected" / "scan_tree_only.json", tree, failures)
    secrets = [f for f in full["findings"] if f["kind"] == "secret"]
    if full["verdict"] != "BLOCKED" or full["exit_code"] != 3:
        failures.append(f"history scan verdict is {full['verdict']}, not BLOCKED")
    if len(secrets) != 1:
        failures.append(f"{len(secrets)} secret findings instead of 1")
    else:
        f = secrets[0]
        if f["commit"] != ids[1]:
            failures.append("the finding does not name the commit that introduced the secret")
        if f["path"] != "deploy/prod.env" or f["line"] != 4:
            failures.append("the finding does not name the path and line")
        if f["in_worktree"]:
            failures.append("the finding is wrongly said to be in the working tree")
        if f["fingerprint"] != gold.fingerprint(token) or f["class"] != "vendor_api_token":
            failures.append("class or fingerprint differ from the planted value")
    if token in (root / "deploy" / "prod.env").read_text(encoding="utf-8"):
        failures.append("fixture error: the working tree still holds the token")
    if tree["findings"]:
        failures.append("the tree-only scan found something in a working tree that holds nothing")
    if tree["verdict"] != "NOT_COVERED":
        failures.append(f"tree-only scan of a repository with an unread history says {tree['verdict']}, not NOT_COVERED")
    line = (f"secret removed by a later commit is found in history (commit {ids[1][:12]}, deploy/prod.env:4); "
            f"verdict {full['verdict']}; tree-only scan: {len(tree['findings'])} findings, verdict {tree['verdict']}")
    return c.result(SID, failures, line, {"commit": ids[1], "verdict": full["verdict"], "tree_only": tree["verdict"]})


if __name__ == "__main__":
    c.main(check)
