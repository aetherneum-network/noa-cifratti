"""Independent check of the gold labels: re-read every labelled position and confirm the bytes.

    python corpus/reference_plan.py [--seed N] [--dir DIR] [--perturb]

Gold labels never contain a secret value, so they cannot be checked by reading them. This script
re-creates the seeding plan in memory (values included), then - without the scanner and without
the ``git`` program - opens the loose object named by each label (zlib) and the working-tree file,
and confirms that the planted value really is at the labelled path and line, and that the
label's fingerprint is the fingerprint of that value. Nothing is printed except counts.
"""
from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus import generate, gold, repos  # noqa: E402


def read_object(repo: Path, oid: str) -> bytes:
    raw = zlib.decompress((repo / ".git" / "objects" / oid[:2] / oid[2:]).read_bytes())
    return raw[raw.index(b"\x00") + 1:]


def value_at(data: bytes, plant: repos.Plant, line: int) -> bool:
    """Is the planted value at ``line`` (1-based) of ``data``?"""
    if plant.technique.startswith("carrier_"):
        return True                      # a carrier outside coverage has no line: presence of the file is the label
    lines = data.decode("utf-8").split("\n")
    if line < 1 or line > len(lines):
        return False
    if plant.cls == "armored_key_block" and plant.technique in ("plain", "unseen_format"):
        body = plant.value.split("\n")
        return all(body[j] in lines[line - 1 + j] for j in range(len(body)))
    if plant.value and plant.technique in ("plain", "unseen_format"):
        return plant.value in lines[line - 1]
    return lines[line - 1].strip() == plant.marker


def verify(seed: int, corpus_dir: Path, gold_dir: Path, perturbed: bool) -> tuple[int, int, list[str]]:
    labels = gold.read_jsonl(gold_dir / "labels.jsonl")
    records = gold.read_jsonl(gold_dir / "repos.jsonl")
    by_repo: dict[str, list[dict]] = {}
    for rec in labels:
        by_repo.setdefault(rec["repo"], []).append(rec)
    checked, problems = 0, []
    for idx, record in enumerate(records, 1):
        plan = repos.plan_repo(seed, idx, perturbed)
        root = corpus_dir / "repos" / plan.name
        recs = by_repo.get(plan.name, [])
        if plan.name != record["repo"] or len(recs) != len(plan.plants):
            problems.append(f"{record['repo']}: the plan and the gold do not describe the same plants")
            continue
        for plant, rec in zip(plan.plants, recs):
            checked += 1
            where = f"{plan.name}:{rec['path']}"
            if (rec["kind"], rec["class"], rec["path"]) != (plant.kind, plant.cls, plant.path):
                problems.append(f"{where}: label and plan differ")
                continue
            if rec["in_head"]:
                data = (root / rec["path"]).read_bytes()          # the file must exist for every label in HEAD
                by_line = rec["kind"] in ("secret", "decoy", "pycode") and not plant.technique.startswith("carrier_")
                if by_line and not value_at(data, plant, rec["line"]):
                    problems.append(f"{where}: the working tree does not hold the plant at line {rec['line']}")
                if rec["kind"] == "config" and rec["line"] < 1:
                    problems.append(f"{where}: the configuration subject is not located")
            if rec["kind"] == "secret":
                fp = gold.block_fingerprint(plant.value) if plant.cls == "armored_key_block" else gold.fingerprint(plant.value)
                if fp != rec["fingerprint"]:
                    problems.append(f"{where}: fingerprint of the planted value differs from the label")
                if not rec["blob"] or not value_at(read_object(root, rec["blob"]), plant, rec["first_line"]):
                    problems.append(f"{where}: the labelled blob does not hold the plant at line {rec['first_line']}")
                if rec["first_commit"]:
                    commit = read_object(root, rec["first_commit"])
                    if not commit.startswith(b"tree "):
                        problems.append(f"{where}: the labelled commit is not a commit object")
    return checked, len(records), problems


def main(argv: list[str] | None = None) -> int:
    cfg = generate.CONFIG
    ap = argparse.ArgumentParser(description="Re-read every gold label and confirm the planted bytes.")
    ap.add_argument("--seed", type=int, default=cfg["seed"])
    ap.add_argument("--dir", type=Path, default=ROOT / "build" / "corpus" / "dev")
    ap.add_argument("--gold", type=Path)
    ap.add_argument("--perturb", action="store_true")
    args = ap.parse_args(argv)
    default_dev = args.dir == ROOT / "build" / "corpus" / "dev"
    gold_dir = args.gold or (ROOT / "corpus" / "gold" if default_dev else args.dir / "gold")
    checked, n_repos, problems = verify(args.seed, args.dir, gold_dir, args.perturb)
    print(f"reference plan, seed {args.seed}: {n_repos} repositories, {checked} labels re-read, {len(problems)} not confirmed")
    for line in problems[:20]:
        print("  " + line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
