"""S10 (boundary) - Officina Brennero: an encrypted archive and a file that is not UTF-8."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from corpus import gold  # noqa: E402
from noascan.scan import scan  # noqa: E402
from scenarios import _common as c  # noqa: E402

SID = "S10"


def write(root: Path, files: dict[str, bytes]) -> Path:
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    return root


def check():
    p = c.load(HERE / "input" / "params.json")
    seed, as_of = p["seed"], p["as_of"]
    token = c.fake(SID, seed, "vendor_api_token")
    r = c.rng(SID, seed, "archive")
    archive = b"Salted__" + bytes(r.randrange(256) for _ in range(512))        # looks like an encrypted archive
    latin1 = "Note di officina: verificare la città e il listino.\n".encode("latin-1")
    plain = {"README.md": b"# workshop-orders\n\nOfficina Brennero S.r.l. (a fictitious company).\n",
             "src/app.py": b"def main():\n    return 0\n", "deploy/prod.env": b"LOG_LEVEL=warn\nDEBUG=false\n"}
    boundary = dict(plain, **{"backup/orders.enc": archive, "docs/legacy-notes.txt": latin1})
    with_token = dict(boundary, **{"docs/legacy-notes.txt": latin1 + f"NBX_API_TOKEN={token}\n".encode("latin-1")})
    work = c.workdir(SID)
    control = scan(write(work / "control", plain), as_of, label="workshop-orders")
    edge = scan(write(work / "boundary", boundary), as_of, label="workshop-orders")
    hot = scan(write(work / "with_token", with_token), as_of, label="workshop-orders")

    failures: list[str] = []
    c.expect(HERE / "expected" / "control.json", control, failures)
    c.expect(HERE / "expected" / "boundary.json", edge, failures)
    c.expect(HERE / "expected" / "with_token.json", hot, failures)
    gaps = sorted((g["path"], g["reason"]) for g in edge["coverage"]["not_covered"])
    if control["verdict"] != "CLEAN":
        failures.append(f"control tree is {control['verdict']}, not CLEAN: the scenario would prove nothing")
    if edge["verdict"] != "NOT_COVERED" or edge["exit_code"] != 2:
        failures.append(f"boundary tree is {edge['verdict']}, not NOT_COVERED")
    if gaps != [("backup/orders.enc", "archive_or_encrypted"), ("docs/legacy-notes.txt", "not_utf8")]:
        failures.append("the two files are not both listed as not covered, each with its reason")
    if edge["findings"]:
        failures.append("findings reported on a tree that holds none")
    if hot["verdict"] != "BLOCKED" or [f["fingerprint"] for f in hot["findings"]] != [gold.fingerprint(token)]:
        failures.append("a covered-class token inside the non-UTF-8 file is not reported")
    if "CLEAN" in (edge["verdict"], hot["verdict"]):
        failures.append("NEVER-EVENT: CLEAN on a tree that was not read in full")
    line = (f"encrypted archive and non-UTF-8 file -> {edge['verdict']} ({len(gaps)} files listed with a reason), never "
            f"CLEAN; same tree without them {control['verdict']}; token inside the non-UTF-8 file -> {hot['verdict']}")
    return c.result(SID, failures, line, {"boundary": edge["verdict"], "control": control["verdict"]})


if __name__ == "__main__":
    c.main(check)
