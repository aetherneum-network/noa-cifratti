"""Git history, read-only: every blob in the object database, with the commit and path that introduced it,
and the full text of every commit and annotated-tag object.

Coverage, stated: all objects present in the object database are read - commits reachable from any
ref, commits no ref reaches any more, and blobs no tree points to (staged once, never committed).
The text of each commit and annotated-tag object is kept in two parts, ``header`` (author, committer,
tagger, tag name, an embedded signed tag, a signature) and ``message``, so that the scan reads
them like files (``History.texts``); before 2.0.2 they were parsed for dates and targets only and a
value written in a message was never read (finding T19 of the blind run of 2026-09-30).
What is *not* in the database (shallow history, submodules, LFS content) is reported as NOT_COVERED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from noascan import gitio


@dataclass(frozen=True)
class Commit:
    oid: str
    tree: str
    parents: tuple[str, ...]
    author: str
    date: str
    ts: int


@dataclass(frozen=True)
class Introduction:
    blob: str
    path: str | None          # None: the blob is in no tree (dangling)
    commit: str | None
    author: str
    date: str
    reachable: bool
    in_head: bool


@dataclass(frozen=True)
class ObjectText:
    """One part of the text of a commit or annotated-tag object, read like a file by the scan."""
    oid: str
    kind: str            # "commit" | "tag"
    part: str            # "header" | "message"
    data: bytes          # the raw bytes of that part, undecoded
    author: str          # the author of a commit, the tagger of a tag
    date: str
    reachable: bool      # a ref reaches the commit, or points (through tags) to the tag


@dataclass
class History:
    head: str | None
    refs: dict[str, str]
    commits: dict[str, Commit]
    blobs: dict[str, bytes]
    introductions: list[Introduction] = field(default_factory=list)
    notes: list[dict[str, str]] = field(default_factory=list)   # reasons why part of the history is NOT_COVERED
    texts: list[ObjectText] = field(default_factory=list)       # headers and messages of commits and annotated tags
    tags_read: int = 0


def _iso(ts: int, tz: str) -> str:
    sign = -1 if tz.startswith("-") else 1
    offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
    return datetime.fromtimestamp(ts, timezone(offset)).isoformat()


def _identity(rest: str) -> tuple[str, int, str]:
    """(name, timestamp, ISO date) of an ``author``/``committer``/``tagger`` header value."""
    name, _, tail = rest.rpartition("> ")
    try:
        when, tz = tail.split()
        return name.split(" <")[0], int(when), _iso(int(when), tz)
    except ValueError:
        return name.split(" <")[0], 0, ""


def _split(data: bytes) -> tuple[bytes, bytes]:
    """(header, message) of a commit or tag object: the header ends at the first empty line."""
    header, _, message = data.partition(b"\n\n")
    return header, message


def _parse_commit(oid: str, data: bytes) -> Commit:
    header, _ = _split(data)
    tree, parents, author, date, ts = "", [], "", "", 0
    for line in header.decode("utf-8", "replace").split("\n"):
        key, _, rest = line.partition(" ")
        if key == "tree":
            tree = rest
        elif key == "parent":
            parents.append(rest)
        elif key == "author":
            author, ts, date = _identity(rest)
    return Commit(oid, tree, tuple(parents), author, date, ts)


def _tagger(data: bytes) -> tuple[str, str]:
    """(tagger name, ISO date) of a tag object; empty strings when it has no tagger line."""
    for line in _split(data)[0].decode("utf-8", "replace").split("\n"):
        key, _, rest = line.partition(" ")
        if key == "tagger":
            name, _, date = _identity(rest)
            return name, date
    return "", ""


def _parse_tree(data: bytes) -> list[tuple[str, str, str]]:
    out, pos = [], 0
    while pos < len(data):
        space = data.index(b" ", pos)
        nul = data.index(b"\x00", space)
        out.append((data[pos:space].decode("ascii"), data[space + 1:nul].decode("utf-8", "replace"),
                    data[nul + 1:nul + 21].hex()))
        pos = nul + 21
    return out


def read(root: Path) -> History:
    """Load the whole object database of ``root/.git``. Raises ``gitio.GitError`` if git cannot read it."""
    git_dir = root / ".git"
    if not git_dir.is_dir():
        raise gitio.GitError("no .git directory")
    head, refs = gitio.show_ref(git_dir)
    objects = gitio.all_objects(git_dir)
    h = History(head, refs, {}, {})
    trees: dict[str, list[tuple[str, str, str]]] = {}
    tags: dict[str, str] = {}
    for oid, (kind, data) in objects.items():
        if kind == "commit":
            h.commits[oid] = _parse_commit(oid, data)
        elif kind == "tree":
            trees[oid] = _parse_tree(data)
        elif kind == "blob":
            h.blobs[oid] = data
        elif kind == "tag":
            first = data.split(b"\n", 1)[0].decode("ascii", "replace")
            tags[oid] = first.partition(" ")[2]
    if (git_dir / "shallow").exists():
        h.notes.append({"reason": "shallow_history", "detail": "the clone is shallow: older commits are not present"})

    flat_cache: dict[str, dict[str, str]] = {}

    def flatten(tree: str, prefix: str = "") -> dict[str, str]:
        key = tree + "\x00" + prefix
        if key in flat_cache:
            return flat_cache[key]
        out: dict[str, str] = {}
        if tree not in trees:
            h.notes.append({"reason": "missing_object", "detail": f"tree {tree[:12]} is not in the object database"})
        for mode, name, oid in trees.get(tree, []):
            path = prefix + name
            if mode == "40000":
                out.update(flatten(oid, path + "/"))
            elif mode == "160000":
                h.notes.append({"reason": "submodule", "detail": f"{path}: content lives in another repository"})
            else:
                out[path] = oid
                if oid not in h.blobs:
                    h.notes.append({"reason": "missing_object", "detail": f"{path}: blob {oid[:12]} is not in the object database"})
        flat_cache[key] = out
        return out

    def peel(oid: str | None) -> str | None:
        seen = 0
        while oid in tags and seen < 10:
            oid, seen = tags[oid], seen + 1
        return oid if oid in h.commits else None

    reachable: set[str] = set()
    stack = [c for c in (peel(o) for o in [head, *refs.values()]) if c]
    while stack:
        oid = stack.pop()
        if oid in reachable:
            continue
        reachable.add(oid)
        for parent in h.commits[oid].parents:
            if parent in h.commits:
                stack.append(parent)
            else:
                h.notes.append({"reason": "missing_object", "detail": f"parent commit {parent[:12]} is not in the object database"})
    head_commit = peel(head)
    head_files = flatten(h.commits[head_commit].tree) if head_commit else {}
    head_pairs = set(head_files.items())

    seen_blobs: set[str] = set()
    for commit in sorted(h.commits.values(), key=lambda c: (c.ts, c.oid)):
        files = flatten(commit.tree)
        inherited: set[tuple[str, str]] = set()
        for parent in commit.parents:
            if parent in h.commits:
                inherited |= set(flatten(h.commits[parent].tree).items())
        for path, blob in sorted(files.items()):
            seen_blobs.add(blob)
            if (path, blob) not in inherited:
                h.introductions.append(Introduction(blob, path, commit.oid, commit.author, commit.date,
                                                    commit.oid in reachable, (path, blob) in head_pairs))
    for blob in sorted(set(h.blobs) - seen_blobs):   # in no commit's tree: staged once, or left by a rewrite
        h.introductions.append(Introduction(blob, None, None, "", "", False, False))

    # the text of every commit and annotated-tag object, reachable or not: header and message
    reachable_tags: set[str] = set()
    for oid in [head, *refs.values()]:
        seen = 0
        while oid in tags and oid not in reachable_tags and seen < 10:
            reachable_tags.add(oid)
            oid, seen = tags[oid], seen + 1
    for commit in sorted(h.commits.values(), key=lambda c: (c.ts, c.oid)):
        header, message = _split(objects[commit.oid][1])
        for part, data in (("header", header), ("message", message)):
            if data:
                h.texts.append(ObjectText(commit.oid, "commit", part, data, commit.author, commit.date,
                                          commit.oid in reachable))
    for oid in sorted(tags):
        header, message = _split(objects[oid][1])
        tagger, date = _tagger(objects[oid][1])
        for part, data in (("header", header), ("message", message)):
            if data:
                h.texts.append(ObjectText(oid, "tag", part, data, tagger, date, oid in reachable_tags))
    h.tags_read = len(tags)
    unique = {(n["reason"], n["detail"]) for n in h.notes}
    h.notes = [{"reason": r, "detail": d} for r, d in sorted(unique)]
    return h
