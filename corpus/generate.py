"""Generate the synthetic corpus: mini-repositories, tabletop transcripts, patch pairs, gold labels.

    python corpus/generate.py                 # dev corpus (corpus/config.json) -> build/corpus/dev
    python corpus/generate.py --check         # regenerate elsewhere and compare with corpus/MANIFEST.sha256
    python corpus/generate.py --seed N --out DIR [--perturb]    # any other suite; gold goes to DIR/gold

Everything is a pure function of the seed and of ``as_of`` (no clock, no network, no ``git`` process).
The manifest hashes *logical* content - refs, object ids, working-tree bytes - not the compressed
object files, whose bytes may legitimately differ between zlib builds.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus import gold, patches, repos, tabletops  # noqa: E402

CONFIG = json.loads((ROOT / "corpus" / "config.json").read_text(encoding="utf-8"))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_digest(files: dict[str, bytes]) -> str:
    return sha("\n".join(f"{sha(data)}  {path}" for path, data in sorted(files.items())).encode("utf-8"))


def rmtree(path: Path) -> None:
    if path.exists():
        shutil.rmtree("\\\\?\\" + str(path.resolve()) if sys.platform == "win32" else path)


def generate(seed: int, out: Path, gold_dir: Path, as_of: str, n_repos: int, n_transcripts: int, n_pairs: int,
             perturb: bool = False) -> list[str]:
    """Write the corpus and its gold; return the manifest lines."""
    rmtree(out)
    manifest: list[str] = []
    repo_records, label_records = [], []
    for i in range(1, n_repos + 1):
        plan = repos.plan_repo(seed, i, perturb)
        repos.materialise(plan, out / "repos")
        head = next(c for c in reversed(plan.commits) if c.line == "main").snapshot
        logical = {"refs": dict(sorted(plan.refs.items())), "head": plan.head, "objects": plan.object_ids,
                   "worktree": _tree_digest(head)}
        manifest.append(f"{sha(json.dumps(logical, sort_keys=True).encode('ascii'))}  repos/{plan.name}")
        repo_records.append(gold.repo_record(plan))
        label_records += gold.label_records(plan)
    transcript_records = []
    for i in range(1, n_transcripts + 1):
        events, rec = tabletops.build(seed, i, as_of)
        path = out / "tabletops" / f"{rec['transcript']}.jsonl"
        tabletops.write(events, path)
        manifest.append(f"{sha(path.read_bytes())}  tabletops/{path.name}")
        transcript_records.append(rec)
    pair_records = []
    for i in range(1, n_pairs + 1):
        before, after, rec = patches.build(seed, i)
        patches.write_tree(before, out / "patches" / rec["pair"] / "before")
        patches.write_tree(after, out / "patches" / rec["pair"] / "after")
        manifest.append(f"{sha((_tree_digest(before) + _tree_digest(after)).encode('ascii'))}  patches/{rec['pair']}")
        pair_records.append(rec)
    for name, records in (("repos.jsonl", repo_records), ("labels.jsonl", label_records),
                          ("tabletops.jsonl", transcript_records), ("patches.jsonl", pair_records)):
        gold.write_jsonl(gold_dir / name, records)
        manifest.append(f"{sha((gold_dir / name).read_bytes())}  gold/{name}")
    meta = {"seed": seed, "as_of": as_of, "perturbed": perturb, "repos": n_repos, "transcripts": n_transcripts,
            "patch_pairs": n_pairs, "generator": "noa-corpus/v1"}
    with open(out / "corpus.json", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return manifest


def write_manifest(path: Path, lines: list[str], seed: int) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# corpus manifest - seed {seed} - sha256 of logical content (see corpus/generate.py)\n")
        fh.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=CONFIG["seed"])
    ap.add_argument("--out", type=Path)
    ap.add_argument("--as-of", default=CONFIG["as_of"])
    ap.add_argument("--repos", type=int, default=CONFIG["repos"])
    ap.add_argument("--transcripts", type=int, default=CONFIG["transcripts"])
    ap.add_argument("--pairs", type=int, default=CONFIG["patch_pairs"])
    ap.add_argument("--perturb", action="store_true", help="stress suite: hide the secrets (corpus/perturb.py)")
    ap.add_argument("--check", action="store_true", help="regenerate and compare with corpus/MANIFEST.sha256")
    args = ap.parse_args(argv)
    sizes = (args.repos, args.transcripts, args.pairs)
    is_dev = (args.seed == CONFIG["seed"] and not args.perturb
              and sizes == (CONFIG["repos"], CONFIG["transcripts"], CONFIG["patch_pairs"]) and args.as_of == CONFIG["as_of"])
    if args.check:
        out = ROOT / "build" / "corpus" / "_check"
        lines = generate(CONFIG["seed"], out, out / "gold", CONFIG["as_of"], CONFIG["repos"], CONFIG["transcripts"],
                         CONFIG["patch_pairs"])
        committed = [ln for ln in (ROOT / "corpus" / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
                     if ln and not ln.startswith("#")]
        bad = sorted(set(lines) ^ set(committed))
        gold_bad = [n for n in ("repos.jsonl", "labels.jsonl", "tabletops.jsonl", "patches.jsonl")
                    if (out / "gold" / n).read_bytes() != (ROOT / "corpus" / "gold" / n).read_bytes()]
        print(f"entries: {len(lines)}; mismatches vs MANIFEST.sha256: {len(bad)}; gold files differing: {len(gold_bad)}")
        for ln in bad[:10]:
            print("  " + ln)
        return 0 if not bad and not gold_bad else 1
    out = args.out or ROOT / "build" / "corpus" / ("dev" if is_dev else f"seed-{args.seed}{'-perturbed' if args.perturb else ''}")
    out = out.resolve()
    default_dev = is_dev and args.out is None
    gold_dir = ROOT / "corpus" / "gold" if default_dev else out / "gold"
    lines = generate(args.seed, out, gold_dir, args.as_of, *sizes, perturb=args.perturb)
    write_manifest(ROOT / "corpus" / "MANIFEST.sha256" if default_dev else out / "MANIFEST.sha256", lines, args.seed)
    print(f"corpus seed {args.seed}{' (perturbed)' if args.perturb else ''}: {args.repos} repositories, "
          f"{args.transcripts} transcripts, {args.pairs} patch pairs; manifest entries: {len(lines)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
