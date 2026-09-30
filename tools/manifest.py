"""Hash manifest of the proof pack (``MANIFEST.sha256``).

    python tools/manifest.py --write --tag v2.0.0-freeze    # list every file tracked at that tag, with its SHA-256
    python tools/manifest.py --check                        # re-hash the listed files in the working tree

The manifest names the tag and the commit it describes. A commit cannot contain its own id, so
the manifest is committed *after* the commit it lists; files added later (the manifest itself, the
blind protocol, the measurement history, the test of the freeze) are not in it and are named in its header. The list of
files and their content come from git (``ls-tree``, ``cat-file``: read-only), so the hashes are
those of the committed bytes whatever the line-ending settings of the machine.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "MANIFEST.sha256"


def git(*args: str) -> bytes:
    cp = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
    if cp.returncode != 0:
        raise SystemExit(f"error: git {args[0]} failed with exit code {cp.returncode}")
    return cp.stdout


def lines_at(rev: str) -> list[str]:
    out = []
    for entry in git("ls-tree", "-r", "-z", rev).split(b"\x00"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, oid = meta.split()
        if kind != b"blob":
            continue
        out.append(f"{hashlib.sha256(git('cat-file', 'blob', oid.decode('ascii'))).hexdigest()}  {path.decode('utf-8')}")
    return sorted(out, key=lambda ln: ln.split("  ", 1)[1])


def bundle(lines: list[str]) -> str:
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write or check MANIFEST.sha256.")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--tag", default="v2.0.0-freeze")
    args = ap.parse_args(argv)
    if args.write:
        commit = git("rev-parse", f"{args.tag}^{{commit}}").decode("ascii").strip()
        lines = lines_at(commit)
        with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"# proof pack manifest - tag {args.tag} - commit {commit}\n")
            fh.write(f"# files: {len(lines)} - bundle sha256 (of the lines below): {bundle(lines)}\n")
            fh.write("# not listed, because added after that commit: MANIFEST.sha256, eval/BLIND_PROTOCOL.md, "
                     "eval/history.json, tests/test_freeze.py\n")
            fh.write("\n".join(lines) + "\n")
        print(f"manifest written: {len(lines)} files at {args.tag} ({commit}); bundle sha256 {bundle(lines)}")
        return 0
    text = MANIFEST.read_text(encoding="utf-8").splitlines()
    lines = [ln for ln in text if ln and not ln.startswith("#")]
    bad = []
    for ln in lines:
        digest, rel = ln.split("  ", 1)
        path = ROOT / rel
        data = path.read_bytes() if path.is_file() else None
        if data is None or hashlib.sha256(data).hexdigest() != digest:
            if data is None or hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest() != digest:
                bad.append(rel)
    declared = next((ln.rsplit(" ", 1)[1] for ln in text if ln.startswith("# files:")), "")
    print(f"manifest: {len(lines)} files listed, {len(bad)} differ; bundle sha256 {bundle(lines)}"
          f"{'' if declared == bundle(lines) else ' (DIFFERS from the declared one)'}")
    for rel in bad[:20]:
        print("  " + rel)
    return 1 if bad or declared != bundle(lines) else 0


if __name__ == "__main__":
    sys.exit(main())
