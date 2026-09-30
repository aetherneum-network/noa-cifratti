"""Write a git repository as loose objects with the standard library only (no ``git`` process).

Object ids are SHA-1 over ``"<type> <size>\\0" + content``: a pure function of the bytes written here
(LF line endings, fixed dates, fixed identities). The scanner never uses this module: it reads the
repositories back through ``git`` itself (``noascan/gitio.py``), which is also how the generator's
ids are checked against git's own (tests/test_corpus.py).

The generated repositories have no index file: they exist to be read, not worked in.
"""
from __future__ import annotations

import hashlib
import zlib
from pathlib import Path


def object_id(kind: str, data: bytes) -> str:
    return hashlib.sha1(f"{kind} {len(data)}".encode("ascii") + b"\x00" + data).hexdigest()


class RepoWriter:
    def __init__(self, root: Path):
        self.root = root
        self.git = root / ".git"
        (self.git / "objects").mkdir(parents=True, exist_ok=True)
        (self.git / "refs" / "heads").mkdir(parents=True, exist_ok=True)
        (self.git / "refs" / "tags").mkdir(parents=True, exist_ok=True)
        self._write(self.git / "HEAD", b"ref: refs/heads/main\n")
        self._write(self.git / "config",
                    b"[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n")
        self.objects: dict[str, str] = {}

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def _store(self, kind: str, data: bytes) -> str:
        oid = object_id(kind, data)
        if oid not in self.objects:
            self.objects[oid] = kind
            raw = f"{kind} {len(data)}".encode("ascii") + b"\x00" + data
            self._write(self.git / "objects" / oid[:2] / oid[2:], zlib.compress(raw, 6))
        return oid

    def blob(self, data: bytes) -> str:
        return self._store("blob", data)

    def tree(self, files: dict[str, bytes]) -> str:
        """``files`` maps posix paths to blob bytes; nested trees are built recursively."""
        here: dict[str, bytes] = {}
        sub: dict[str, dict[str, bytes]] = {}
        for path, data in files.items():
            head, _, rest = path.partition("/")
            if rest:
                sub.setdefault(head, {})[rest] = data
            else:
                here[head] = data
        entries = [(name, "100644", self.blob(data)) for name, data in here.items()]
        entries += [(name, "40000", self.tree(children)) for name, children in sub.items()]
        # git orders tree entries by name, with directories compared as if they ended in "/"
        entries.sort(key=lambda e: (e[0] + "/" if e[1] == "40000" else e[0]).encode("utf-8"))
        raw = b"".join(f"{mode} {name}".encode("utf-8") + b"\x00" + bytes.fromhex(oid) for name, mode, oid in entries)
        return self._store("tree", raw)

    def commit(self, tree: str, parents: list[str], name: str, email: str, ts: int, tz: str, message: str) -> str:
        lines = [f"tree {tree}"] + [f"parent {p}" for p in parents]
        lines += [f"author {name} <{email}> {ts} {tz}", f"committer {name} <{email}> {ts} {tz}", "", message, ""]
        return self._store("commit", "\n".join(lines).encode("utf-8"))

    def tag_object(self, target: str, tag: str, name: str, email: str, ts: int, tz: str, message: str) -> str:
        body = f"object {target}\ntype commit\ntag {tag}\ntagger {name} <{email}> {ts} {tz}\n\n{message}\n"
        return self._store("tag", body.encode("utf-8"))

    def ref(self, name: str, oid: str) -> None:
        self._write(self.git / name, oid.encode("ascii") + b"\n")

    def checkout(self, files: dict[str, bytes]) -> None:
        for path, data in files.items():
            self._write(self.root / path, data)
