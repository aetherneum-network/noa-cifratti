"""Two independent rebuilds in two different folders, compared byte for byte.

    python tools/rebuild.py [--small]

Each rebuild regenerates the dev corpus from its seed, scores it, runs the ten scenarios and scans
this repository, writing everything under its own folder (``build/rebuild/...``, two folders of
different depth and name length). The two folders must hold the same files with the same bytes.

Two digests are printed:

* ``outputs sha256`` - over the corpus manifest (logical content: refs, object ids, working-tree
  bytes), the gold files, the full scoring result and the scenario report. This is the number
  recorded in the README; it does not depend on the machine.
* ``corpus files sha256`` - over every generated file, compressed git objects included. Their
  bytes depend on the zlib build, so this digest is compared between the two folders only.

``--small`` rebuilds a reduced corpus (used by the test suite; its digest is not the recorded one).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "eval") not in sys.path:
    sys.path.insert(0, str(ROOT / "eval"))

from corpus import generate  # noqa: E402
from noascan import report  # noqa: E402
from scenarios import _common, run_all  # noqa: E402
from tools import selfscan  # noqa: E402
import score  # noqa: E402

FOLDERS = ("a", "second-folder/nested/b")
RECORDED = ("MANIFEST.sha256", "gold/labels.jsonl", "gold/patches.jsonl", "gold/repos.jsonl", "gold/tabletops.jsonl",
            "results-dev.json", "scenarios.json")


def tree_digest(root: Path, only: tuple[str, ...] | None = None) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    files = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            full = Path(dirpath) / name
            files.append((full.relative_to(root).as_posix(), full))
    for rel, full in sorted(files):
        if only is not None and rel not in only:
            continue
        with open(full, "rb") as fh:
            h.update(f"{rel}\x00{hashlib.sha256(fh.read()).hexdigest()}\n".encode("utf-8"))
        n += 1
    return h.hexdigest(), n


def rebuild(out: Path, sizes: tuple[int, int, int]) -> None:
    cfg = generate.CONFIG
    generate.rmtree(out)
    lines = generate.generate(cfg["seed"], out / "corpus", out / "gold", cfg["as_of"], *sizes)
    generate.write_manifest(out / "MANIFEST.sha256", lines, cfg["seed"])
    res = score.score(out / "corpus", out / "gold", cfg["seed"], False, cfg["as_of"])
    report.write(out / "results-dev.json", res)
    saved = _common.WORK_ROOT
    _common.WORK_ROOT = out / "scenario-work"
    try:
        results = run_all.run_all(quiet=True)
    finally:
        _common.WORK_ROOT = saved
    report.write(out / "scenarios.json", {"passed": sum(1 for r in results if r["ok"]), "total": len(results),
                                          "scenarios": [{"id": r["id"], "ok": r["ok"], "line": r["line"]} for r in results]})
    report.write(out / "scan.json", selfscan.run())


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cfg = generate.CONFIG
    small = "--small" in argv
    sizes = (24, 18, 12) if small else (cfg["repos"], cfg["transcripts"], cfg["patch_pairs"])
    base = ROOT / "build" / ("rebuild-small" if small else "rebuild")
    digests = []
    for folder in FOLDERS:
        out = base / folder
        rebuild(out, sizes)
        recorded, n_rec = tree_digest(out, RECORDED)
        everything, n_all = tree_digest(out)
        digests.append((recorded, everything))
        print(f"rebuild in build/{base.name}/{folder}: {n_all} files; outputs sha256 {recorded} ({n_rec} files); "
              f"all files sha256 {everything}")
    same_outputs, same_all = digests[0][0] == digests[1][0], digests[0][1] == digests[1][1]
    scen = json.loads((base / FOLDERS[0] / "scenarios.json").read_text(encoding="ascii"))
    print(f"seed {cfg['seed']}, as_of {cfg['as_of']}, sizes {sizes}{' (small: not the recorded digest)' if small else ''}")
    print(f"scenarios in the rebuild: {scen['passed']}/{scen['total']} PASS")
    print(f"outputs identical: {same_outputs}; every file identical: {same_all}")
    print(f"outputs sha256: {digests[0][0]}")
    return 0 if same_outputs and same_all and scen["passed"] == scen["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
