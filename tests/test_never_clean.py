"""The never-event: CLEAN on a repository that holds a planted secret of a covered class.

Every test here tries to make it happen - by hiding the value where a lazy scanner does not
look, or by making part of the repository unreadable - and asserts that the scanner reports
(BLOCKED / NEEDS_REVIEW) or abstains (NOT_COVERED / EXCEPTIONS_ONLY). Never CLEAN.
"""
import base64
import gzip
import io
import itertools
import os
import shutil
import unittest
import zipfile
from unittest import mock

from tests import _util as u
from corpus import fakes, gold
from noascan import gate, rules_engine
from noascan.scan import RuleSet, scan

NOT_CLEAN = ("BLOCKED", "NEEDS_REVIEW", "NOT_COVERED", "EXCEPTIONS_ONLY")


def fp(cls: str, value: str) -> str:
    return gold.block_fingerprint(value) if cls == "armored_key_block" else gold.fingerprint(value)


class Control(unittest.TestCase):
    def test_a_clean_tree_is_clean(self):
        out = scan(u.write_tree(u.tmp("nc-control-tree"), u.CLEAN_FILES), u.AS_OF)
        self.assertEqual((out["verdict"], out["exit_code"]), ("CLEAN", 0))
        self.assertEqual(out["counters"], {"blocking": 0, "review": 0, "not_covered": 0, "exceptions": 0})

    def test_a_clean_repository_with_history_is_clean(self):
        root, _ = u.linear("nc-control-repo", [u.CLEAN_FILES, dict(u.CLEAN_FILES, **{"NOTES.md": "second commit\n"})])
        out = scan(root, u.AS_OF)
        self.assertEqual(out["verdict"], "CLEAN")
        self.assertEqual((out["scope"]["history"], out["scope"]["commits_read"]), ("read", 2))


class EveryCoveredClass(unittest.TestCase):
    def test_classes_under_test_are_the_declared_coverage(self):
        self.assertEqual(sorted(fakes.SECRET_CLASSES), RuleSet.load().secrets.covered_classes)

    def test_in_the_working_tree(self):
        for cls in fakes.SECRET_CLASSES:
            with self.subTest(cls=cls):
                path, text, value = u.carrier(cls)
                out = scan(u.write_tree(u.tmp(f"nc-tree-{cls}"), dict(u.CLEAN_FILES, **{path: text})), u.AS_OF)
                self.assertEqual(out["verdict"], "BLOCKED")
                self.assertIn((cls, fp(cls, value), path), [(f["class"], f["fingerprint"], f["path"]) for f in out["findings"]])

    def test_removed_by_a_later_commit(self):
        for cls in fakes.SECRET_CLASSES:
            with self.subTest(cls=cls):
                path, text, value = u.carrier(cls)
                root, ids = u.linear(f"nc-hist-{cls}", [u.CLEAN_FILES, dict(u.CLEAN_FILES, **{path: text}), u.CLEAN_FILES])
                out = scan(root, u.AS_OF)
                hit = [f for f in out["findings"] if f["class"] == cls and f["fingerprint"] == fp(cls, value)]
                self.assertEqual(out["verdict"], "BLOCKED")
                self.assertEqual([(f["commit"], f["path"], f["in_worktree"]) for f in hit], [(ids[1], path, False)])


class HidingPlaces(unittest.TestCase):
    def setUp(self):
        self.path, self.text, self.value = u.carrier("vendor_api_token")
        self.dirty = dict(u.CLEAN_FILES, **{self.path: self.text})

    def found(self, out):
        return [f for f in out["findings"] if f.get("fingerprint") == gold.fingerprint(self.value)]

    def test_on_a_branch_that_is_not_checked_out(self):
        r = u.Repo("nc-branch")
        base = r.commit(u.CLEAN_FILES)
        side = r.commit(self.dirty, [base])
        r.w.ref("refs/heads/feature/integration", side)
        out = scan(r.main(base, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertEqual([(f["commit"], f["reachable"]) for f in self.found(out)], [(side, True)])

    def test_only_under_an_annotated_tag(self):
        r = u.Repo("nc-tag")
        base = r.commit(u.CLEAN_FILES)
        side = r.commit(self.dirty, [base])
        r.w.ref("refs/tags/v0.1", r.w.tag_object(side, "v0.1", "Brennero Ops", f"ops@{u.DOMAIN}", u.EPOCH_BASE, u.TZ, "tag"))
        out = scan(r.main(base, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertTrue(self.found(out)[0]["reachable"])

    def test_in_a_commit_no_ref_reaches(self):
        r = u.Repo("nc-unreachable")
        base = r.commit(u.CLEAN_FILES)
        lost = r.commit(self.dirty, [base])          # left behind by a history rewrite
        out = scan(r.main(base, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertEqual([(f["commit"], f["reachable"]) for f in self.found(out)], [(lost, False)])

    def test_in_a_blob_no_tree_points_to(self):
        r = u.Repo("nc-dangling-blob")
        base = r.commit(u.CLEAN_FILES)
        blob = r.w.blob(self.text.encode("utf-8"))   # staged once, never committed
        out = scan(r.main(base, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertEqual([(f["blob"], f["path"], f["in_worktree"]) for f in self.found(out)], [(blob, "", False)])

    def test_in_the_remote_url_of_the_git_configuration(self):
        root, _ = u.linear("nc-git-config", [u.CLEAN_FILES])
        uri, pw = u.fake_uri()
        with open(root / ".git" / "config", "ab") as fh:
            fh.write(f'[remote "origin"]\n\turl = {uri}\n'.encode("utf-8"))
        out = scan(root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertIn((".git/config", gold.fingerprint(pw)), [(f["path"], f["fingerprint"]) for f in out["findings"]])

    def test_as_a_file_name(self):
        out = scan(u.write_tree(u.tmp("nc-file-name"), dict(u.CLEAN_FILES, **{f"backup/{self.value}.txt": "x\n"})), u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertEqual([(f["via"], f["path"].startswith("[masked:")) for f in self.found(out)], [("file name", True)])

    def test_as_a_directory_name_in_history_only(self):
        root, _ = u.linear("nc-dir-name", [dict(u.CLEAN_FILES, **{f"dump/{self.value}/a.txt": "x\n"}), u.CLEAN_FILES])
        out = scan(root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertFalse(self.found(out)[0]["in_worktree"])

    def test_in_a_nested_repository(self):
        root = u.write_tree(u.tmp("nc-nested"), u.CLEAN_FILES)
        inner = u.RepoWriter(root / "vendor" / "lib")
        inner.ref("refs/heads/main", inner.commit(inner.tree(u.as_bytes(self.dirty)), [], "A", "a@corp.example", 1, "+0000", "x"))
        out = scan(root, u.AS_OF)
        self.assertEqual(out["verdict"], "NOT_COVERED")
        self.assertIn(("vendor/lib/.git", "nested_repository"), [(g["path"], g["reason"]) for g in out["coverage"]["not_covered"]])

    def test_encoded_split_or_reversed_goes_to_review(self):
        v = self.value
        forms = {"base64": "blob = " + base64.b64encode(v.encode()).decode(), "hex": "blob = " + v.encode().hex(),
                 "percent": "https://hooks.corp.example/in?k=" + "".join(f"%{b:02X}" for b in v.encode()),
                 "reversed": "PAYLOAD=" + v[::-1], "concat": f'key = "{v[:20]}" + "{v[20:]}"'}
        for name, line in forms.items():
            with self.subTest(form=name):
                out = scan(u.write_tree(u.tmp(f"nc-form-{name}"), dict(u.CLEAN_FILES, **{"docs/notes.md": line + "\n"})), u.AS_OF)
                self.assertEqual(out["verdict"], "NEEDS_REVIEW")
                self.assertEqual([f["kind"] for f in out["findings"]], ["suspect"])


class UnreadableParts(unittest.TestCase):
    """Whatever could not be read in full makes the verdict NOT_COVERED at best - with or without a secret in it."""

    def setUp(self):
        self.token = u.fake("vendor_api_token", 3)
        self.line = f"NBX_API_TOKEN={self.token}\n".encode("ascii")

    def verdict(self, name: str, files: dict) -> dict:
        return scan(u.write_tree(u.tmp(name), dict(u.CLEAN_FILES, **files)), u.AS_OF)

    def reasons(self, out) -> list[str]:
        return sorted(g["reason"] for g in out["coverage"]["not_covered"])

    def test_archives_and_encrypted_files(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr(zipfile.ZipInfo("prod.env", (2026, 9, 30, 0, 0, 0)), self.line)
        samples = {"zip": buf.getvalue(), "gzip": gzip.compress(self.line, mtime=0), "salted": b"Salted__" + bytes(range(64)),
                   "age": b"age-encryption.org/v1\n-> X25519 synthetic\n", "empty-zip": b"PK\x05\x06" + bytes(18)}
        for name, data in samples.items():
            with self.subTest(kind=name):
                out = self.verdict(f"nc-archive-{name}", {"backup/data.bin": data})
                self.assertEqual(out["verdict"], "NOT_COVERED")
                self.assertEqual(self.reasons(out), ["archive_or_encrypted"])

    def test_binary_utf16_and_single_byte_text_are_read_best_effort_and_still_not_covered(self):
        samples = {"binary": (b"\x00\x01\x02" + self.line + b"\x00", "binary"),
                   "utf16": (b"\xff\xfe" + self.line.decode().encode("utf-16-le"), "utf16_or_utf32"),
                   "latin1": ("città\n".encode("latin-1") + self.line, "not_utf8")}
        for name, (data, reason) in samples.items():
            with self.subTest(kind=name):
                out = self.verdict(f"nc-besteffort-{name}", {"docs/legacy.txt": data})
                self.assertEqual(out["verdict"], "BLOCKED")            # found by the best-effort reading
                self.assertEqual(self.reasons(out), [reason])          # and the file is still listed as not covered
                clean = self.verdict(f"nc-besteffort-{name}-empty", {"docs/legacy.txt": data.replace(self.token.encode(), b"x")
                                                                     if name != "utf16" else b"\xff\xfe" + "ok\n".encode("utf-16-le")})
                self.assertEqual(clean["verdict"], "NOT_COVERED")

    def test_utf32(self):
        out = self.verdict("nc-utf32", {"docs/legacy.txt": b"\xff\xfe\x00\x00" + self.line.decode().encode("utf-32-le")})
        self.assertIn(out["verdict"], ("BLOCKED", "NOT_COVERED"))
        self.assertEqual(self.reasons(out), ["utf16_or_utf32"])

    def test_secret_beyond_the_size_limit(self):
        limit = RuleSet.load().secrets.limits["max_file_bytes"]
        out = self.verdict("nc-oversized", {"data/export.csv": b"a,b\n" * (limit // 4 + 10) + self.line})
        self.assertEqual(out["verdict"], "NOT_COVERED")
        self.assertEqual(self.reasons(out), ["oversized"])

    def test_line_longer_than_the_limit(self):
        out = self.verdict("nc-long-line", {"data/min.js": b"x" * 70000 + b" " + self.line})
        self.assertIn(out["verdict"], ("BLOCKED", "NOT_COVERED"))
        self.assertEqual(self.reasons(out), ["line_too_long"])

    def test_lfs_pointer(self):
        pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 12345\n"
        out = self.verdict("nc-lfs", {"data/model.bin": pointer})
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["lfs_pointer"]))

    def test_python_and_configuration_that_do_not_parse(self):
        out = self.verdict("nc-syntax", {"src/broken.py": "def f(:\n    pass\n"})
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["python_not_parseable"]))
        out = self.verdict("nc-config", {"config/gateway/routes.json": '{"schema": "gateway-routes/v1", "routers": [\n'})
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["config_not_parseable"]))
        out = self.verdict("nc-config-shape", {"config/services.json": '{"schema": "services/v1", "services": [{"plane": "x"}]}\n'})
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["config_not_parseable"]))

    def test_symbolic_link(self):
        root = u.write_tree(u.tmp("nc-symlink"), u.CLEAN_FILES)
        outside = u.write_tree(u.tmp("nc-symlink-target"), {"prod.env": self.line})
        try:
            os.symlink(outside / "prod.env", root / "linked.env")
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links cannot be created on this machine")
        out = scan(root, u.AS_OF)
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["symlink"]))
        self.assertEqual(out["findings"], [])        # the link is not followed: nothing outside the tree is read


class UnreadableHistory(unittest.TestCase):
    def setUp(self):
        self.path, self.text, self.value = u.carrier("vendor_api_token", 5)
        self.dirty = dict(u.CLEAN_FILES, **{self.path: self.text})

    def reasons(self, out) -> list[str]:
        return sorted(g["reason"] for g in out["coverage"]["not_covered"])

    def test_history_not_read_on_request(self):
        root, _ = u.linear("nc-tree-only", [self.dirty, u.CLEAN_FILES])
        out = scan(root, u.AS_OF, read_history=False)
        self.assertEqual((out["verdict"], self.reasons(out), out["scope"]["history"]), ("NOT_COVERED", ["history_not_read"], "skipped"))

    def test_git_program_missing(self):
        root, _ = u.linear("nc-no-git", [self.dirty, u.CLEAN_FILES])
        with mock.patch("noascan.gitio.shutil.which", return_value=None):
            out = scan(root, u.AS_OF)
        self.assertEqual((out["verdict"], self.reasons(out), out["scope"]["history"]), ("NOT_COVERED", ["history_unreadable"], "unreadable"))

    def test_git_directory_is_a_file(self):
        root = u.write_tree(u.tmp("nc-gitfile"), dict(u.CLEAN_FILES, **{".git": "gitdir: ../elsewhere/.git/modules/x\n"}))
        out = scan(root, u.AS_OF)
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["history_unreadable"]))

    def test_corrupt_object(self):
        root, ids = u.linear("nc-corrupt", [self.dirty, u.CLEAN_FILES])
        (root / ".git" / "objects" / ids[0][:2] / ids[0][2:]).write_bytes(b"not a zlib stream")
        out = scan(root, u.AS_OF)
        self.assertIn(out["verdict"], ("NOT_COVERED", "BLOCKED"))
        self.assertTrue(out["coverage"]["not_covered"])

    def test_object_missing_from_the_database(self):
        r = u.Repo("nc-missing")
        first = r.commit(self.dirty)
        second = r.commit(u.CLEAN_FILES, [first])
        r.main(second, u.CLEAN_FILES)
        blob = r.w.blob(self.text.encode("utf-8"))
        os.remove(r.root / ".git" / "objects" / blob[:2] / blob[2:])     # the one object that held the secret
        out = scan(r.root, u.AS_OF)
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["missing_object"]))

    def test_shallow_clone(self):
        root, ids = u.linear("nc-shallow", [u.CLEAN_FILES])
        (root / ".git" / "shallow").write_bytes(ids[0].encode("ascii") + b"\n")
        out = scan(root, u.AS_OF)
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["shallow_history"]))

    def test_submodule(self):
        r = u.Repo("nc-submodule")
        blob = r.w.blob(b"readme\n")
        raw = b"100644 README.md\x00" + bytes.fromhex(blob) + b"160000 vendor\x00" + bytes.fromhex("ab" * 20)
        tree = r.w._store("tree", raw)
        oid = r.w.commit(tree, [], "Brennero Ops", f"ops@{u.DOMAIN}", u.EPOCH_BASE, u.TZ, "add submodule")
        r.w.ref("refs/heads/main", oid)
        r.w.checkout({"README.md": b"readme\n"})
        out = scan(r.root, u.AS_OF)
        self.assertEqual((out["verdict"], self.reasons(out)), ("NOT_COVERED", ["submodule"]))


class Exceptions(unittest.TestCase):
    def setUp(self):
        self.path, self.text, self.value = u.carrier("vendor_api_token", 7)
        self.dirty = dict(u.CLEAN_FILES, **{self.path: self.text})
        self.entry = {"id": "AL-T-1", "type": "finding", "path": self.path, "class": "vendor_api_token",
                      "fingerprint": gold.fingerprint(self.value), "reason": "test fixture"}

    def allow(self, *entries):
        return {"file": "allowlist", "version": "t", "as_of": "2026-09-30", "rules": list(entries)}

    def test_an_excepted_finding_is_never_clean(self):
        out = scan(u.write_tree(u.tmp("nc-allow"), self.dirty), u.AS_OF, allowlist=self.allow(self.entry))
        self.assertEqual((out["verdict"], out["findings"], len(out["exceptions"])), ("EXCEPTIONS_ONLY", [], 1))

    def test_an_exception_needs_the_exact_path_class_and_fingerprint(self):
        for key, wrong in (("path", "deploy/other.env"), ("class", "vendor_test_key"), ("fingerprint", "0" * 16)):
            with self.subTest(key=key):
                out = scan(u.write_tree(u.tmp(f"nc-allow-{key}"), self.dirty), u.AS_OF, allowlist=self.allow(dict(self.entry, **{key: wrong})))
                self.assertEqual(out["verdict"], "BLOCKED")

    def test_history_is_never_excepted(self):
        root, _ = u.linear("nc-allow-history", [self.dirty, u.CLEAN_FILES])
        out = scan(root, u.AS_OF, allowlist=self.allow(self.entry))
        self.assertEqual(out["verdict"], "BLOCKED")

    def test_an_excluded_folder_is_never_clean(self):
        root = u.write_tree(u.tmp("nc-exclude"), dict(u.CLEAN_FILES, **{"vendor/" + self.path: self.text}))
        out = scan(root, u.AS_OF, exclude=("vendor",))
        self.assertEqual((out["verdict"], [e["id"] for e in out["exceptions"]]), ("EXCEPTIONS_ONLY", ["EXCLUDED-BY-CALLER"]))

    def test_an_unread_file_pinned_by_hash_stops_matching_when_it_changes(self):
        data = b"Salted__" + bytes(range(40))
        import hashlib
        entry = {"id": "AL-T-2", "type": "not_covered", "path": "backup/x.enc", "sha256": hashlib.sha256(data).hexdigest(), "reason": "t"}
        same = scan(u.write_tree(u.tmp("nc-pin-same"), dict(u.CLEAN_FILES, **{"backup/x.enc": data})), u.AS_OF, allowlist=self.allow(entry))
        changed = scan(u.write_tree(u.tmp("nc-pin-changed"), dict(u.CLEAN_FILES, **{"backup/x.enc": data + b"!"})), u.AS_OF,
                       allowlist=self.allow(entry))
        self.assertEqual((same["verdict"], changed["verdict"]), ("EXCEPTIONS_ONLY", "NOT_COVERED"))


class Gate(unittest.TestCase):
    def test_clean_needs_every_counter_at_zero(self):
        rules = rules_engine.load("gate")["rules"]
        for combo in itertools.product((0, 1, 3), repeat=4):
            count = dict(zip(("blocking", "review", "not_covered", "exceptions"), combo))
            verdict, _, code = gate.decide(count, rules)
            self.assertEqual(verdict == "CLEAN", not any(combo), count)
            self.assertIn(verdict, ("CLEAN",) + NOT_CLEAN)
            self.assertEqual(code == 0, verdict in ("CLEAN", "EXCEPTIONS_ONLY"))

    def test_clean_is_the_last_rule_and_the_only_one_without_conditions(self):
        rules = rules_engine.load("gate")["rules"]
        self.assertEqual([r["verdict"] for r in rules if not r.get("when")], ["CLEAN"])
        self.assertEqual(rules[-1]["verdict"], "CLEAN")

    def test_a_finding_no_rule_places_counts_as_blocking(self):
        g = rules_engine.load("gate")
        count = gate.counters([{"kind": "unheard-of", "severity": "unheard-of"}], 0, 0, g)
        self.assertEqual((count["blocking"], gate.decide(count, g["rules"])[0]), (1, "BLOCKED"))

    def test_a_gate_without_a_default_or_with_an_unknown_counter_stops_the_run(self):
        with self.assertRaises(rules_engine.RuleError):
            gate.decide({"blocking": 0}, [{"id": "X", "when": {"blocking_min": 1}, "verdict": "BLOCKED", "exit_code": 3}])
        with self.assertRaises(rules_engine.RuleError):
            gate.decide({"blocking": 0}, [{"id": "X", "when": {"nonsense_min": 1}, "verdict": "BLOCKED", "exit_code": 3}])

    def test_broken_rules_stop_the_scan_instead_of_finding_nothing(self):
        path, text, _ = u.carrier("vendor_api_token", 9)
        root = u.write_tree(u.tmp("nc-broken-rules"), dict(u.CLEAN_FILES, **{path: text}))
        base = RuleSet.load()
        broken = dict(base.raw["secrets"], rules=[dict(base.raw["secrets"]["rules"][6], pattern="(?P<secret>[unclosed")])
        with self.assertRaises(rules_engine.RuleError):
            scan(root, u.AS_OF, rules=RuleSet.load({"secrets": broken}))
        with self.assertRaises(ValueError):
            scan(root, "")


class GeneratedCorpus(unittest.TestCase):
    """The same property on generated repositories of the dev seed (a small slice; eval/score.py runs all 200)."""

    def test_no_clean_verdict_on_a_repository_with_a_covered_secret(self):
        from corpus import generate
        out = u.tmp("nc-corpus")
        generate.generate(u.DEV_SEED, out / "corpus", out / "gold", u.AS_OF, 30, 0, 0)
        labels = gold.read_jsonl(out / "gold" / "labels.jsonl")
        with_secret = {rec["repo"] for rec in labels if rec["kind"] == "secret" and rec.get("covered", True)}
        verdicts = {}
        for rec in gold.read_jsonl(out / "gold" / "repos.jsonl"):
            verdicts[rec["repo"]] = scan(out / "corpus" / "repos" / rec["repo"], u.AS_OF)["verdict"]
        self.assertGreaterEqual(len(with_secret), 10)
        self.assertEqual([r for r in sorted(with_secret) if verdicts[r] == "CLEAN"], [])
        self.assertIn("CLEAN", verdicts.values())
        shutil.rmtree(u.ext(out))


if __name__ == "__main__":
    unittest.main()
