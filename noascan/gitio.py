"""Read-only access to a git repository through the ``git`` program (the only external program used).

Only two plumbing commands are ever run, both read-only: ``show-ref --head`` and
``cat-file --batch-all-objects --batch``. No network command exists in this module. The object
database is always named explicitly (``--git-dir``), so git never walks up into a parent repository.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class GitError(RuntimeError):
    """git could not read the repository. Callers turn this into NOT_COVERED, never into 'no finding'."""


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    return env


def _run(git_dir: Path, *args: str) -> subprocess.CompletedProcess:
    exe = shutil.which("git")
    if exe is None:
        raise GitError("git executable not found")
    cmd = [exe, "--no-pager", f"--git-dir={git_dir}", "-c", "core.fsmonitor=false", "-c", "gc.auto=0", *args]
    try:
        return subprocess.run(cmd, capture_output=True, env=_env(), stdin=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git {args[0]} did not run: {type(exc).__name__}") from exc


def version() -> str:
    exe = shutil.which("git")
    if exe is None:
        return "not found"
    out = subprocess.run([exe, "--version"], capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    return out.stdout.decode("ascii", "replace").strip()


def show_ref(git_dir: Path) -> tuple[str | None, dict[str, str]]:
    """(HEAD object id or None, {ref name: object id}). A repository without refs is not an error."""
    cp = _run(git_dir, "show-ref", "--head")
    if cp.returncode not in (0, 1):
        raise GitError(f"git show-ref failed with exit code {cp.returncode}")
    head, refs = None, {}
    for line in cp.stdout.decode("utf-8", "replace").splitlines():
        oid, _, name = line.partition(" ")
        if name == "HEAD":
            head = oid
        elif name:
            refs[name] = oid
    return head, refs


def all_objects(git_dir: Path) -> dict[str, tuple[str, bytes]]:
    """Every object in the object database, reachable or not: {id: (type, content)}."""
    cp = _run(git_dir, "cat-file", "--batch-all-objects", "--batch")
    if cp.returncode != 0:
        raise GitError(f"git cat-file failed with exit code {cp.returncode}")
    out, pos, objects = cp.stdout, 0, {}
    while pos < len(out):
        nl = out.index(b"\n", pos)
        parts = out[pos:nl].split()
        if len(parts) != 3:
            raise GitError("unexpected cat-file header")
        oid, kind, size = parts[0].decode("ascii"), parts[1].decode("ascii"), int(parts[2])
        objects[oid] = (kind, out[nl + 1:nl + 1 + size])
        pos = nl + 1 + size + 1
    return objects
