"""Command line: exit codes are the contract a pipeline reads."""
import contextlib
import io
import json
import unittest

from tests import _util as u
from noascan.__main__ import main


def call(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class ExitCodes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        token = u.fake("vendor_api_token", 41)
        cls.token = token
        cls.clean = u.write_tree(u.tmp("cli-clean"), u.CLEAN_FILES)
        cls.blocked = u.write_tree(u.tmp("cli-blocked"), dict(u.CLEAN_FILES, **{"deploy/prod.env": f"DEBUG=false\nAPI_TOKEN={token}\n"}))
        cls.gap = u.write_tree(u.tmp("cli-gap"), dict(u.CLEAN_FILES, **{"backup/dump.enc": b"Salted__" + bytes(range(64))}))
        cls.review = u.write_tree(u.tmp("cli-review"), dict(u.CLEAN_FILES, **{"notes.txt": "token, reversed: " + token[::-1] + "\n"}))

    def test_scan_verdicts(self):
        for root, verdict, code in ((self.clean, "CLEAN", 0), (self.blocked, "BLOCKED", 3), (self.gap, "NOT_COVERED", 2),
                                    (self.review, "NEEDS_REVIEW", 2)):
            with self.subTest(verdict=verdict):
                got, out, _ = call("scan", root, "--as-of", u.AS_OF)
                self.assertEqual(got, code)
                self.assertIn(f"verdict: {verdict} ", out)
                self.assertNotIn(self.token, out)

    def test_exceptions_only_is_zero_and_is_said(self):
        got, out, _ = call("scan", self.gap, "--as-of", u.AS_OF, "--exclude", "backup")
        self.assertEqual(got, 0)
        self.assertIn("verdict: EXCEPTIONS_ONLY", out)
        self.assertIn("EXCLUDED-BY-CALLER", out)

    def test_tree_only_on_a_repository_is_not_clean(self):
        root, _ = u.linear("cli-history", [dict(u.CLEAN_FILES, **{"deploy/prod.env": f"API_TOKEN={self.token}\n"}), u.CLEAN_FILES])
        self.assertEqual(call("scan", root, "--as-of", u.AS_OF)[0], 3)
        got, out, _ = call("scan", root, "--as-of", u.AS_OF, "--tree-only")
        self.assertEqual(got, 2)
        self.assertIn("verdict: NOT_COVERED", out)
        self.assertIn("history_not_read", out)

    def test_a_target_that_cannot_be_read_is_an_error_not_a_clean_scan(self):
        for target in (u.TMP / "cli-does-not-exist", self.clean / "README.md"):
            with self.subTest(target=target.name):
                got, out, err = call("scan", target, "--as-of", u.AS_OF)
                self.assertEqual(got, 64)
                self.assertNotIn("CLEAN", out)
                self.assertIn("not a directory", err)
        self.assertEqual(call("surface", self.clean, u.TMP / "cli-does-not-exist", "--as-of", u.AS_OF)[0], 64)

    def test_usage_errors(self):
        self.assertEqual(call("scan", self.clean)[0], 64)                                   # no reference date
        self.assertEqual(call("scan", self.clean, "--as-of", "")[0], 64)
        self.assertEqual(call("scan", self.clean, "--as-of", "yesterday")[0], 64)
        self.assertEqual(call("frobnicate")[0], 64)
        self.assertEqual(call()[0], 64)
        self.assertEqual(call("scan", self.clean, "--as-of", u.AS_OF, "--allowlist", u.TMP / "cli-no-such-allowlist.json")[0], 64)
        bad = u.tmp("cli-badallow") / "allow.json"
        bad.write_text('{"file": "allowlist", "version": "1"}', encoding="utf-8")
        self.assertEqual(call("scan", self.clean, "--as-of", u.AS_OF, "--allowlist", bad)[0], 64)

    def test_the_json_report_is_written_and_matches_the_exit_code(self):
        out = u.tmp("cli-json") / "sub" / "report.json"
        got, _, _ = call("scan", self.blocked, "--as-of", u.AS_OF, "--json", out, "--label", "workshop-orders")
        doc = json.loads(out.read_text(encoding="ascii"))
        self.assertEqual((got, doc["exit_code"], doc["verdict"], doc["target"]), (3, 3, "BLOCKED", "workshop-orders"))
        self.assertNotIn(self.token, out.read_text(encoding="ascii"))

    def test_surface(self):
        self.assertEqual(call("surface", self.clean, self.clean, "--as-of", u.AS_OF)[0], 0)
        got, out, _ = call("surface", self.clean, self.blocked, "--as-of", u.AS_OF)
        self.assertEqual(got, 3)
        self.assertIn("verdict: BLOCKED", out)
        self.assertNotIn(self.token, out)
        self.assertEqual(call("surface", self.blocked, self.clean, "--as-of", u.AS_OF)[0], 0)

    def test_rules_test_and_rules_diff(self):
        got, out, _ = call("rules-test")
        self.assertEqual((got, out.strip()), (0, "inline rule tests: 0 failing"))
        patch = u.ROOT / "scenarios" / "S09" / "input" / "patch.json"
        got, out, _ = call("rules-diff", self.blocked, "--patch", patch, "--as-of", u.AS_OF)
        self.assertEqual(got, 0)
        self.assertIn("rules-diff: lost 0, gained 0", out)
        self.assertEqual(call("rules-diff", self.blocked, "--patch", u.TMP / "cli-no-patch.json", "--as-of", u.AS_OF)[0], 64)

    def test_the_module_runs_as_a_program(self):
        proc = u.run(["-m", "noascan", "scan", str(self.blocked), "--as-of", u.AS_OF])
        self.assertEqual(proc.returncode, 3)
        self.assertNotIn(self.token.encode(), proc.stdout + proc.stderr)
        proc = u.run(["-m", "noascan", "scan", str(self.clean), "--as-of", u.AS_OF])
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"read: 3 files, history absent", proc.stdout)


if __name__ == "__main__":
    unittest.main()
