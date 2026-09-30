"""Scan this repository with its own scanner and write ``reports/scan.json``.

    python tools/selfscan.py            # write the report, print the summary
    python tools/selfscan.py --check    # scan again and compare with the committed report

The scan is of the working tree. The git history is excluded on the command line, and said so in
the report: the scenario fixtures are committed inert values and the allowlist pins each of them
by exact path and fingerprint, which a history scan (never excepted) would report one by one. The
best possible verdict is therefore EXCEPTIONS_ONLY, never CLEAN. The count of files read is left
out of the comparison: it changes whenever a document is added.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from noascan import report, rules_engine  # noqa: E402
from noascan.scan import scan  # noqa: E402

EXCLUDE = (".git", "build", "__pycache__")
REPORT = ROOT / "reports" / "scan.json"


def run() -> dict:
    as_of = json.loads((ROOT / "corpus" / "config.json").read_text(encoding="utf-8"))["as_of"]
    return scan(ROOT, as_of, label="noa-cifratti", read_history=False, exclude=EXCLUDE,
                allowlist=rules_engine.load(ROOT / "rules" / "allowlist.json"))


def comparable(doc: dict) -> dict:
    doc = json.loads(json.dumps(doc))
    doc.get("scope", {}).pop("worktree_files", None)
    return doc


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = run()
    if "--check" in argv:
        same = REPORT.is_file() and comparable(json.loads(REPORT.read_text(encoding="ascii"))) == comparable(out)
        print(f"self-scan: {out['verdict']}; committed report {'matches' if same else 'DIFFERS'}")
        return 0 if same and out["exit_code"] == 0 else 1
    report.write(REPORT, out)
    sys.stdout.write(report.summary(out))
    return out["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
