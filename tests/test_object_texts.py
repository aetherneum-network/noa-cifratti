"""Commit and tag objects are read like files: header and message (finding T19, blind run of 2026-09-30).

Up to 2.0.1 the history reader parsed a commit for its tree, parents, author and date, and a tag for
its target, and never read their text: a value of a covered class written only in a commit message
or in an annotated-tag message left the repository CLEAN, and COVERAGE.md did not say so. Every
repository here is synthetic and built in the test; every value is inert (see SYNTHETIC.md). Each
test also checks that no value appears in the report or in its summary.
"""
import unittest

from tests import _util as u
from corpus import fakes, gold
from noascan import report
from noascan.scan import scan


def fp(cls: str, value: str) -> str:
    return gold.block_fingerprint(value) if cls == "armored_key_block" else gold.fingerprint(value)


def needles(value: str) -> list[str]:
    return [ln for ln in value.split("\n") if ln and not ln.startswith("-----")]


def located(out, cls, value):
    """(object type, object id, part, line) of the secret findings of that value, in commit or tag objects."""
    return [(f["object_type"], f["object"], f["part"], f["line"]) for f in out["findings"]
            if f.get("object") and f["kind"] == "secret" and f["class"] == cls and f["fingerprint"] == fp(cls, value)]


class Base(unittest.TestCase):
    def assertNoValueIn(self, out, *values):
        text = report.dumps(out) + report.summary(out)
        self.assertEqual([n for v in values for n in needles(v) if n in text], [])


class OnlyInAMessage(Base):
    """The value is in no file of any commit and not in the working tree: only in a message."""

    def test_every_covered_class_only_in_a_commit_message(self):
        for cls in fakes.SECRET_CLASSES:
            with self.subTest(cls=cls):
                _, text, value = u.carrier(cls, 21)
                r = u.Repo(f"ot-commit-{cls}")
                base = r.commit(u.CLEAN_FILES)
                c = r.commit(dict(u.CLEAN_FILES, **{"NOTES.md": "second\n"}), [base], message="Rotate credentials\n\n" + text)
                out = scan(r.main(c, dict(u.CLEAN_FILES, **{"NOTES.md": "second\n"})).root, u.AS_OF)
                self.assertEqual(out["verdict"], "BLOCKED")
                first_line = 3 + next(i for i, ln in enumerate(text.split("\n")) if needles(value)[0] in ln or "-----BEGIN" in ln)
                self.assertEqual(located(out, cls, value), [("commit", c, "message", first_line)])
                f = next(f for f in out["findings"] if f.get("object") == c)
                self.assertEqual((f["path"], f["commit"], f["in_worktree"], f["reachable"], f["blob"]), ("", c, False, True, ""))
                self.assertNoValueIn(out, value)

    def test_every_covered_class_only_in_an_annotated_tag_message(self):
        for cls in fakes.SECRET_CLASSES:
            with self.subTest(cls=cls):
                _, text, value = u.carrier(cls, 22)
                r = u.Repo(f"ot-tag-{cls}")
                c = r.commit(u.CLEAN_FILES)
                tag = r.w.tag_object(c, "v0.1", "Brennero Ops", f"ops@{u.DOMAIN}", u.EPOCH_BASE + 60, u.TZ,
                                     "release candidate\n\n" + text)
                r.w.ref("refs/tags/v0.1", tag)
                out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
                self.assertEqual(out["verdict"], "BLOCKED")
                self.assertEqual([loc[:3] for loc in located(out, cls, value)], [("tag", tag, "message")])
                f = next(f for f in out["findings"] if f.get("object") == tag)
                self.assertEqual((f["commit"], f["reachable"], f["author"], f["date"]), ("", True, "Brennero Ops", "2026-09-01T09:01:00+02:00"))
                self.assertEqual(out["scope"]["tags_read"], 1)
                self.assertNoValueIn(out, value)

    def test_the_summary_names_the_object_and_the_part_never_a_file(self):
        token = u.fake("vendor_api_token", 23)
        r = u.Repo("ot-summary")
        c = r.commit(u.CLEAN_FILES, message=f"Add tiles\n\nkey was {token}")
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        text = report.summary(out)
        self.assertIn(f"(commit {c[:12]} message):3 fp={gold.fingerprint(token)}", text)
        self.assertNotIn("(object not in any tree)", text)
        self.assertIn("1 commits, 0 annotated tags", text)
        self.assertNoValueIn(out, token)


class WhereElseInGitMetadata(Base):
    """Siblings of the same defect: other places where git keeps text that is not a file of a tree."""

    def setUp(self):
        self.token = u.fake("vendor_api_token", 24)

    def test_a_commit_no_ref_reaches_and_a_tag_whose_ref_was_deleted(self):
        r = u.Repo("ot-unreachable")
        base = r.commit(u.CLEAN_FILES)
        lost = r.commit(u.CLEAN_FILES, [base], message=f"amended away\n\n{self.token}")     # left behind by an amend
        tag = r.w.tag_object(base, "v0.2", "Brennero Ops", f"ops@{u.DOMAIN}", u.EPOCH_BASE, u.TZ, f"rc\n\n{self.token}")
        out = scan(r.main(base, u.CLEAN_FILES).root, u.AS_OF)                                 # no ref names the tag
        self.assertEqual(out["verdict"], "BLOCKED")
        found = sorted((f["object_type"], f["object"], f["reachable"]) for f in out["findings"] if f.get("object"))
        self.assertEqual(found, sorted([("commit", lost, False), ("tag", tag, False)]))
        self.assertNoValueIn(out, self.token)

    def test_author_committer_and_tagger_fields_are_read(self):
        r = u.Repo("ot-identity")
        c = r.commit(u.CLEAN_FILES, message="initial import", who=(f"Dev {self.token}", f"dev@{u.DOMAIN}"))
        tag = r.w.tag_object(c, "v0.3", f"Ops {self.token}", f"ops@{u.DOMAIN}", u.EPOCH_BASE, u.TZ, "rc")
        r.w.ref("refs/tags/v0.3", tag)
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        found = [(f["object_type"], f["part"]) for f in out["findings"] if f.get("object")]
        self.assertEqual(sorted(found), [("commit", "header"), ("tag", "header")])
        self.assertTrue(all(f["author"].startswith("[masked:") for f in out["findings"] if f.get("object")))
        self.assertNoValueIn(out, self.token)

    def test_a_signed_tag_embedded_in_a_merge_commit_whose_tag_object_is_absent(self):
        r = u.Repo("ot-mergetag")
        base = r.commit(u.CLEAN_FILES)
        side = r.commit(dict(u.CLEAN_FILES, **{"side.txt": "side\n"}), [base])
        merged = dict(u.CLEAN_FILES, **{"side.txt": "side\n"})
        tree = r.w.tree(u.as_bytes(merged))
        embedded = [f"object {side}", "type commit", "tag v0.4", f"tagger Brennero Ops <ops@{u.DOMAIN}> {u.EPOCH_BASE} {u.TZ}",
                    "", "signed release", "", f"key {self.token}"]
        ident = f"Brennero Dev A <dev-a@{u.DOMAIN}> {u.EPOCH_BASE + 7200} {u.TZ}"
        raw = "\n".join([f"tree {tree}", f"parent {base}", f"parent {side}", f"author {ident}", f"committer {ident}",
                         "mergetag " + embedded[0], *(" " + ln for ln in embedded[1:]), "", "Merge tag v0.4", ""])
        merge = r.w._store("commit", raw.encode("utf-8"))
        out = scan(r.main(merge, merged).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertEqual([(f["object"], f["part"]) for f in out["findings"] if f.get("object")], [(merge, "header")])
        self.assertNoValueIn(out, self.token)

    def test_a_stash_commit_message(self):
        r = u.Repo("ot-stash")
        base = r.commit(u.CLEAN_FILES)
        stash = r.commit(u.CLEAN_FILES, [base], message=f"On main: try {self.token}")
        r.w.ref("refs/stash", stash)
        out = scan(r.main(base, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual([(f["object"], f["part"], f["reachable"]) for f in out["findings"] if f.get("object")],
                         [(stash, "message", True)])
        self.assertNoValueIn(out, self.token)

    def test_a_git_note_is_a_blob_and_the_notes_commit_a_commit(self):
        path, text, value = u.carrier("vendor_api_token", 25)
        r = u.Repo("ot-notes")
        c = r.commit(u.CLEAN_FILES)
        notes = r.commit({c: text}, message="Notes added by 'git notes add'")
        r.w.ref("refs/notes/commits", notes)
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "BLOCKED")
        self.assertEqual([(f["path"], f["commit"], f["in_worktree"]) for f in out["findings"] if f["kind"] == "secret"],
                         [(c, notes, False)])       # the note is a file named after the annotated commit
        self.assertNoValueIn(out, value)

    def test_the_reflog_is_read_as_a_file(self):
        root, ids = u.linear("ot-reflog", [u.CLEAN_FILES])
        (root / ".git" / "logs").mkdir()
        (root / ".git" / "logs" / "HEAD").write_text(
            f"{'0' * 40} {ids[0]} Brennero Dev A <dev-a@{u.DOMAIN}> {u.EPOCH_BASE} {u.TZ}\tcommit: key {self.token}\n", encoding="utf-8")
        out = scan(root, u.AS_OF)
        self.assertEqual([(f["path"], f["in_worktree"]) for f in out["findings"]], [(".git/logs/HEAD", True)])
        self.assertNoValueIn(out, self.token)


class SameCoverageDecisionAsAFile(Base):
    def test_a_message_that_is_not_utf8_is_not_covered_never_clean(self):
        r = u.Repo("ot-latin1")
        tree = r.w.tree(u.as_bytes(u.CLEAN_FILES))
        ident = f"Brennero Dev A <dev-a@{u.DOMAIN}> {u.EPOCH_BASE} {u.TZ}"
        raw = f"tree {tree}\nauthor {ident}\ncommitter {ident}\nencoding ISO-8859-1\n\n".encode("ascii") + b"Caf\xe9 notes\n"
        c = r.w._store("commit", raw)
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(out["verdict"], "NOT_COVERED")
        self.assertEqual([(g["path"], g["reason"], g["where"]) for g in out["coverage"]["not_covered"]],
                         [(f"(commit {c[:12]} message)", "not_utf8", "history")])

    def test_a_path_limited_rule_applies_to_a_message(self):
        # an unquoted assignment is covered only in environment-like files; a message has no path, so it applies
        value = u.fake("assigned_password", 26)
        r = u.Repo("ot-bare")
        c = r.commit(u.CLEAN_FILES, message=f"Rotate mail credentials\n\nSMTP_PASSWORD={value}")
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual(located(out, "assigned_password", value), [("commit", c, "message", 3)])
        self.assertNoValueIn(out, value)

    def test_a_value_hidden_in_a_message_in_another_form_is_a_suspect_as_in_a_file(self):
        import base64
        token = u.fake("vendor_api_token", 27)
        r = u.Repo("ot-encoded")
        c = r.commit(u.CLEAN_FILES, message="seed " + base64.b64encode(token.encode()).decode())
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual((out["verdict"], [(f["kind"], f["class"], f["part"]) for f in out["findings"]]),
                         ("NEEDS_REVIEW", [("suspect", "encoded_secret", "message")]))


class NegativeControl(Base):
    def test_messages_tags_and_identities_without_a_value_stay_clean(self):
        r = u.Repo("ot-control")
        base = r.commit(u.CLEAN_FILES, message="initial import")
        c = r.commit(dict(u.CLEAN_FILES, **{"NOTES.md": "x\n"}), [base],
                     message="Rotate the gateway token\n\nThe old token is revoked; the new one lives in the secret store.")
        r.w.ref("refs/tags/v1.0", r.w.tag_object(c, "v1.0", "Brennero Ops", f"ops@{u.DOMAIN}", u.EPOCH_BASE + 60, u.TZ,
                                                 "release 1.0\n\npassword policy unchanged"))
        out = scan(r.main(c, dict(u.CLEAN_FILES, **{"NOTES.md": "x\n"})).root, u.AS_OF)
        self.assertEqual((out["verdict"], out["findings"], out["coverage"]["not_covered"]), ("CLEAN", [], []))
        self.assertEqual((out["scope"]["commits_read"], out["scope"]["tags_read"], out["scope"]["object_texts"]),
                         (2, 1, "header and message of every commit and annotated tag"))

    def test_signatures_in_a_signed_commit_and_a_signed_tag_are_not_findings(self):
        # a signature block sits in the header of a signed commit and at the end of a signed tag's message:
        # it is neither a key block nor an encrypted message, so it is read and stays silent
        import base64
        import hashlib
        body = base64.b64encode(b"".join(hashlib.sha512(f"noa-tests/v1/signature/{i}".encode()).digest() for i in range(4))).decode()
        block = ["-----BEGIN PGP SIGNATURE-----", "", *[body[i:i + 64] for i in range(0, len(body), 64)], "=noa1",
                 "-----END PGP SIGNATURE-----"]
        r = u.Repo("ot-signed")
        tree = r.w.tree(u.as_bytes(u.CLEAN_FILES))
        ident = f"Brennero Dev A <dev-a@{u.DOMAIN}> {u.EPOCH_BASE} {u.TZ}"
        raw = "\n".join([f"tree {tree}", f"author {ident}", f"committer {ident}", "gpgsig " + block[0],
                         *(" " + ln for ln in block[1:]), "", "Signed import", ""])
        c = r.w._store("commit", raw.encode("utf-8"))
        r.w.ref("refs/tags/v1.0", r.w.tag_object(c, "v1.0", "Brennero Ops", f"ops@{u.DOMAIN}", u.EPOCH_BASE + 60, u.TZ,
                                                 "release 1.0\n" + "\n".join(block) + "\n"))
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF)
        self.assertEqual((out["verdict"], out["findings"], out["coverage"]["not_covered"]), ("CLEAN", [], []))
        self.assertEqual((out["scope"]["commits_read"], out["scope"]["tags_read"]), (1, 1))

    def test_a_tree_only_scan_says_it_did_not_read_them(self):
        token = u.fake("vendor_api_token", 28)
        r = u.Repo("ot-tree-only")
        c = r.commit(u.CLEAN_FILES, message=f"key {token}")
        out = scan(r.main(c, u.CLEAN_FILES).root, u.AS_OF, read_history=False)
        self.assertEqual((out["verdict"], out["scope"]["object_texts"], out["findings"]), ("NOT_COVERED", "not read", []))


if __name__ == "__main__":
    unittest.main()
