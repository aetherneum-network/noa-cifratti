"""Hash manifest of the proof pack (``MANIFEST.sha256``).

    python tools/manifest.py --write --tag v2.0.1-freeze --rev TREE   # list the files of that tree, with their SHA-256
    python tools/manifest.py --check                                   # re-hash the listed files in the working tree

The manifest travels inside the commit that carries the freeze tag. A commit cannot contain its own
id and a file cannot contain its own hash, so the manifest names the tag (not the commit) and lists
every file of the tagged commit except the ones in ``NOT_LISTED``, each with its reason in the
header. ``--rev`` is any commit or tree git can resolve: the tag itself once it exists, or, before
the commit is made, the id of the staged tree. Writing the same tag again from the tag gives the
same bytes.

The list of files and their content come from git (``ls-tree``, ``cat-file``: read-only), so the
hashes are those of the committed bytes whatever the line-ending settings of the machine. The
manifest is refused if a frozen path (``eval/score.py``) differs from the tag the blind harness
checks: a new freeze tag may change documents, never what decides a result.

``--check`` re-hashes the listed files in the working tree and, when the tag named in the header is
in the clone, also compares the list with the tagged commit.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "MANIFEST.sha256"
sys.path.insert(0, str(ROOT / "eval"))

import score  # noqa: E402

# Ordered: the header names them in this order.
NOT_LISTED = (
    ("MANIFEST.sha256", "a file cannot hold its own hash"),
    ("eval/BLIND_PROTOCOL.md", "it names the tagged commit, so it is completed after the tag"),
    ("eval/history.json", "every recorded run is appended to it"),
)
HEADER = re.compile(r"^# proof pack manifest - tag (\S+) - ")


def _run(*args: str) -> subprocess.CompletedProcess:
    """A git query whose exit code is the answer."""
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, stdin=subprocess.DEVNULL, timeout=120)


def git(*args: str) -> bytes:
    """A git query that must succeed; its output."""
    cp = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
    if cp.returncode != 0:
        raise SystemExit(f"error: git {args[0]} failed with exit code {cp.returncode}")
    return cp.stdout


def lines_at(rev: str) -> list[str]:
    """``<sha256>  <path>`` for every file of ``rev`` that the manifest lists, sorted by path."""
    skipped = {name for name, _ in NOT_LISTED}
    out = []
    for entry in git("ls-tree", "-r", "-z", rev).split(b"\x00"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, oid = meta.split()
        if kind != b"blob" or path.decode("utf-8") in skipped:
            continue
        out.append(f"{hashlib.sha256(git('cat-file', 'blob', oid.decode('ascii'))).hexdigest()}  {path.decode('utf-8')}")
    return sorted(out, key=lambda ln: ln.split("  ", 1)[1])


def bundle(lines: list[str]) -> str:
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def render(tag: str, rev: str) -> str:
    """The text of the manifest for ``tag``, from the files of ``rev``."""
    if _run("diff", "--quiet", score.FREEZE_TAG, rev, "--", *score.FROZEN_PATHS).returncode != 0:
        raise SystemExit(f"error: a frozen path differs from {score.FREEZE_TAG} (or that tag is missing): no manifest written")
    first = git("rev-parse", f"{score.FREEZE_TAG}^{{commit}}").decode("ascii").strip()
    lines = lines_at(rev)
    head = [
        f"# proof pack manifest - tag {tag} - every file of the tagged commit except the ones named below",
        f"# files: {len(lines)} - bundle sha256 (of the lines below): {bundle(lines)}",
        "# not listed: " + "; ".join(f"{name} ({why})" for name, why in NOT_LISTED),
        f"# identical to {score.FREEZE_TAG} (commit {first}), the tag the blind harness checks: " + ", ".join(score.FROZEN_PATHS),
    ]
    return "\n".join(head + lines) + "\n"


def tag_of(text: str) -> str:
    m = HEADER.match(text)
    return m.group(1) if m else ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write or check MANIFEST.sha256.")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--tag", help="with --write: the freeze tag the manifest is for")
    ap.add_argument("--rev", help="with --write: the commit or tree to list (default: the tag)")
    args = ap.parse_args(argv)
    if args.write:
        if not args.tag:
            print("error: --write needs --tag", file=sys.stderr)
            return 64
        text = render(args.tag, args.rev or f"{args.tag}^{{commit}}")
        with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print(f"manifest written for {args.tag}: {text.splitlines()[1][2:]}")
        return 0
    whole = MANIFEST.read_text(encoding="utf-8")
    text = whole.splitlines()
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
    tag = tag_of(whole)
    same_as_tag = True
    if not tag:
        same_as_tag = False
        print("the header does not name a tag")
    elif _run("rev-parse", "--verify", "--quiet", f"refs/tags/{tag}").returncode != 0:
        print(f"tag {tag} is not in this clone: the list was not compared with the tagged commit")
    else:
        same_as_tag = render(tag, f"{tag}^{{commit}}") == whole
        print(f"tag {tag}: the manifest {'is' if same_as_tag else 'IS NOT'} the list of the tagged commit")
    return 1 if bad or declared != bundle(lines) or not same_as_tag else 0


if __name__ == "__main__":
    sys.exit(main())
