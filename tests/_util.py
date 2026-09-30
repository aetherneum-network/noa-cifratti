"""Helpers of the tests: temporary folders inside the pack's own ``build/``, inert values, child processes."""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus import fakes  # noqa: E402
from corpus.gitwrite import RepoWriter  # noqa: E402
from corpus.world import BY_KEY, EPOCH_BASE, TZ, author  # noqa: E402

AS_OF = json.loads((ROOT / "corpus" / "config.json").read_text(encoding="utf-8"))["as_of"]
DEV_SEED = json.loads((ROOT / "corpus" / "config.json").read_text(encoding="utf-8"))["seed"]
TMP = ROOT / "build" / "test-tmp"
COMPANY = BY_KEY["brennero"]
DOMAIN = COMPANY["domain"]
CLEAN_FILES = {"README.md": "# workshop-orders\n\nA fictitious project.\n", "src/app.py": "def main():\n    return 0\n",
               "deploy/prod.env": "LOG_LEVEL=warn\nDEBUG=false\n"}


def ext(path: Path) -> str:
    s = os.path.abspath(str(path))
    return "\\\\?\\" + s if os.name == "nt" and not s.startswith("\\\\?\\") else s


def tmp(name: str) -> Path:
    """A fresh, empty folder under build/test-tmp (never outside the repository)."""
    p = TMP / name
    if p.exists():
        shutil.rmtree(ext(p))
    p.mkdir(parents=True)
    return p


def fake(cls: str, n: int = 0) -> str:
    """An inert value of a covered class, from a fixed test seed (see SYNTHETIC.md)."""
    return fakes.make(cls, random.Random(f"noa-tests/v1/{cls}/{n}"), DOMAIN)


def fake_uri(n: int = 0) -> tuple[str, str]:
    return fakes.connection_uri(random.Random(f"noa-tests/v1/uri/{n}"), DOMAIN)


def carrier(cls: str, n: int = 0) -> tuple[str, str, str]:
    """(path, file text, planted value) - the plainest covered form of each class."""
    if cls == "connection_uri_password":
        uri, pw = fake_uri(n)
        return "deploy/values.yml", f'app:\n  databaseUrl: "{uri}"\n', pw
    value = fake(cls, n)
    if cls == "armored_key_block":
        return "keys/deploy.txt", value + "\n", value
    if cls == "assigned_password":
        return "src/settings.py", "ADMIN_PASSWORD = " + json.dumps(value) + "\n", value
    return "deploy/integration.env", f"LOG_LEVEL=warn\nINTEGRATION_CREDENTIAL={value}\n", value


def as_bytes(files: dict[str, bytes | str]) -> dict[str, bytes]:
    return {p: (d.encode("utf-8") if isinstance(d, str) else d) for p, d in files.items()}


def write_tree(root: Path, files: dict[str, bytes | str]) -> Path:
    for rel, data in as_bytes(files).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    return root


class Repo:
    """A small repository written object by object (no git process)."""

    def __init__(self, name: str):
        self.root = tmp(name)
        self.w = RepoWriter(self.root)
        self.n = 0

    def commit(self, files: dict[str, bytes | str], parents: list[str] | None = None, message: str = "change",
               who: tuple[str, str] | None = None) -> str:
        name, email = who or author(COMPANY, self.n)
        oid = self.w.commit(self.w.tree(as_bytes(files)), parents or [], name, email, EPOCH_BASE + self.n * 3600, TZ, message)
        self.n += 1
        return oid

    def main(self, oid: str, files: dict[str, bytes | str]) -> "Repo":
        self.w.ref("refs/heads/main", oid)
        self.w.checkout(as_bytes(files))
        return self


def linear(name: str, snapshots: list[dict[str, bytes | str]]) -> tuple[Path, list[str]]:
    r = Repo(name)
    ids: list[str] = []
    for snap in snapshots:
        ids.append(r.commit(snap, ids[-1:]))
    r.main(ids[-1], snapshots[-1])
    return r.root, ids


def child_env() -> dict[str, str]:
    """The environment the Council executor gives a scenario, plus the socket block for children."""
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG")
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}
    env.update(PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT / "tests" / "offline"))
    return env


def run(args: list[str], cwd: Path = ROOT, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=str(cwd), env=child_env(), capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=timeout)


def pack_sources() -> list[Path]:
    """Every Python file of the pack outside the tests and the build folder."""
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT).parts
        if rel[0] in ("build", "tests", ".git") or "__pycache__" in rel:
            continue
        out.append(path)
    return out
