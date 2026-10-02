"""Git history: what the pure-Python writer produces is what git reads, and introductions are attributed."""
import shutil
import subprocess
import unittest

from tests import _util as u
from noascan import gitio, history
from noascan.scan import scan


def git(root, *args):
    return subprocess.run([shutil.which("git"), f"--git-dir={root / '.git'}", *args], capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=60, env=gitio._env())


class WriterAgainstGit(unittest.TestCase):
    def test_git_accepts_the_written_repository_and_agrees_on_every_id(self):
        files = dict(u.CLEAN_FILES, **{"a/b/c.txt": "deep\n", "a.txt": "x\n", "a-b/z.txt": "sorted after a.txt, before a/\n"})
        root, ids = u.linear("hist-writer", [u.CLEAN_FILES, files])
        self.assertEqual(git(root, "fsck", "--strict", "--no-dangling").returncode, 0)
        log = git(root, "log", "--format=%H", "refs/heads/main").stdout.decode("ascii").split()
        self.assertEqual(log, list(reversed(ids)))
        listed = git(root, "ls-tree", "-r", "--name-only", ids[1]).stdout.decode("utf-8").split("\n")
        self.assertEqual(sorted(p for p in listed if p), sorted(files))

    def test_only_read_only_git_commands_are_ever_run(self):
        source = (u.ROOT / "noascan" / "gitio.py").read_text(encoding="utf-8")
        self.assertEqual(sorted(set(__import__("re").findall(r'_run\(git_dir, "([a-z-]+)"', source))), ["cat-file", "show-ref"])
        for word in ("fetch", "pull", "push", "clone", "remote", "checkout", "reset", "commit"):
            self.assertNotIn(f'"{word}"', source)

    def test_git_environment_is_neutralised(self):
        env = gitio._env()
        self.assertEqual((env["GIT_TERMINAL_PROMPT"], env["GIT_CONFIG_NOSYSTEM"]), ("0", "1"))
        self.assertEqual([k for k in env if k.upper().startswith("GIT_") and k not in
                          ("GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS")], [])


class Introductions(unittest.TestCase):
    def test_first_commit_author_and_date_of_each_blob(self):
        one = dict(u.CLEAN_FILES, **{"notes.txt": "v1\n"})
        two = dict(u.CLEAN_FILES, **{"notes.txt": "v2\n"})
        three = dict(u.CLEAN_FILES, **{"notes.txt": "v1\n"})          # back to the first content
        root, ids = u.linear("hist-intro", [one, two, three])
        h = history.read(root)
        notes = [(i.commit, i.in_head) for i in h.introductions if i.path == "notes.txt"]
        self.assertEqual(notes, [(ids[0], True), (ids[1], False), (ids[2], True)])
        first = next(i for i in h.introductions if i.commit == ids[0] and i.path == "notes.txt")
        self.assertEqual((first.author, first.date, first.reachable), ("Brennero Dev A", "2026-09-01T09:00:00+02:00", True))
        self.assertEqual(h.notes, [])

    def test_a_repository_without_commits_is_read_and_is_not_an_error(self):
        r = u.Repo("hist-empty")
        h = history.read(r.root)
        self.assertEqual((h.head, h.commits, h.introductions), (None, {}, []))
        self.assertEqual(scan(r.root, u.AS_OF)["verdict"], "CLEAN")

    def test_no_git_directory_is_an_error_for_the_reader_and_absent_for_the_scan(self):
        root = u.write_tree(u.tmp("hist-none"), u.CLEAN_FILES)
        with self.assertRaises(gitio.GitError):
            history.read(root)
        self.assertEqual(scan(root, u.AS_OF)["scope"]["history"], "absent")

    def test_the_scan_never_walks_up_into_the_enclosing_repository(self):
        # the temporary tree lives inside this pack's own git repository: its history must not be read
        out = scan(u.write_tree(u.tmp("hist-enclosed"), u.CLEAN_FILES), u.AS_OF)
        self.assertEqual((out["scope"]["history"], out["scope"]["commits_read"], out["scope"]["blobs_read"]), ("absent", 0, 0))

    def test_merge_commit_does_not_reintroduce_inherited_blobs(self):
        r = u.Repo("hist-merge")
        base = r.commit(u.CLEAN_FILES)
        left = r.commit(dict(u.CLEAN_FILES, **{"l.txt": "left\n"}), [base])
        right = r.commit(dict(u.CLEAN_FILES, **{"r.txt": "right\n"}), [base])
        merged = dict(u.CLEAN_FILES, **{"l.txt": "left\n", "r.txt": "right\n"})
        merge = r.commit(merged, [left, right])
        r.main(merge, merged)
        h = history.read(r.root)
        self.assertEqual([i.path for i in h.introductions if i.commit == merge], [])
        self.assertEqual(sorted(i.commit for i in h.introductions if i.path in ("l.txt", "r.txt")), sorted([left, right]))


if __name__ == "__main__":
    unittest.main()
