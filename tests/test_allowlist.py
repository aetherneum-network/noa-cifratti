"""The allowlist is narrow, justified, used, and never turns a finding into CLEAN."""
import hashlib
import json
import re
import unittest

from tests import _util as u
from noascan import rules_engine
from tools import selfscan

ALLOW = rules_engine.load(u.ROOT / "rules" / "allowlist.json")
FIXTURE = re.compile(r"^(?:corpus/|scenarios/S\d\d/input/)")


class Entries(unittest.TestCase):
    def test_every_entry_is_pinned_and_justified(self):
        for e in ALLOW["rules"]:
            with self.subTest(entry=e["id"]):
                self.assertIn(e["type"], ("finding", "not_covered"))
                self.assertGreaterEqual(len(e["reason"]), 20)
                self.assertNotIn("*", e["path"])
                self.assertFalse(e["path"].startswith("/") or ".." in e["path"])
                if e["type"] == "finding":
                    self.assertTrue(e["class"])
                    self.assertTrue(bool(re.fullmatch(r"[0-9a-f]{16}", e.get("fingerprint", ""))) != bool(e.get("subject")))
                else:
                    self.assertRegex(e["sha256"], r"^[0-9a-f]{64}$")

    def test_findings_are_excepted_only_inside_fixtures(self):
        outside = [e["id"] for e in ALLOW["rules"] if e["type"] == "finding" and not FIXTURE.match(e["path"])]
        self.assertEqual(outside, [])

    def test_a_file_outside_coverage_is_excepted_by_its_exact_bytes(self):
        for e in ALLOW["rules"]:
            if e["type"] == "not_covered":
                self.assertEqual(hashlib.sha256((u.ROOT / e["path"]).read_bytes()).hexdigest(), e["sha256"], e["id"])

    def test_ids_are_unique_and_the_file_names_no_value(self):
        ids = [e["id"] for e in ALLOW["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        text = (u.ROOT / "rules" / "allowlist.json").read_text(encoding="utf-8")
        for marker in ("nbxsyn_", "QPSYN-", "hvnsyn_", "nbxdb://"):
            self.assertNotIn(marker, text)


class SelfScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = selfscan.run()

    def test_the_pack_scans_itself_and_the_best_verdict_is_exceptions_only(self):
        c = self.out["counters"]
        self.assertEqual((c["blocking"], c["review"], c["not_covered"]), (0, 0, 0), json.dumps(self.out["findings"])[:1500])
        self.assertEqual((self.out["verdict"], self.out["exit_code"]), ("EXCEPTIONS_ONLY", 0))
        self.assertNotEqual(self.out["verdict"], "CLEAN")

    def test_every_entry_is_used_and_every_exception_is_listed(self):
        used = {e["id"] for e in self.out["exceptions"]}
        self.assertEqual(sorted({e["id"] for e in ALLOW["rules"]} - used), [])
        self.assertEqual(sorted(used - {e["id"] for e in ALLOW["rules"]}), ["EXCLUDED-BY-CALLER"])
        excluded = sorted(e["path"] for e in self.out["exceptions"] if e["id"] == "EXCLUDED-BY-CALLER")
        self.assertEqual(excluded, sorted(selfscan.EXCLUDE))

    def test_without_the_allowlist_the_pack_is_blocked_by_its_own_fixtures(self):
        from noascan.scan import scan
        out = scan(u.ROOT, u.AS_OF, label="noa-cifratti", read_history=False, exclude=selfscan.EXCLUDE)
        self.assertEqual(out["verdict"], "BLOCKED")
        paths = {f["path"] for f in out["findings"]} | {g["path"] for g in out["coverage"]["not_covered"]}
        self.assertEqual(sorted(p for p in paths if not FIXTURE.match(p) and p != "avatar.jpg"), [])

    def test_the_committed_report_is_current(self):
        committed = json.loads(selfscan.REPORT.read_text(encoding="ascii"))
        self.assertEqual(selfscan.comparable(committed), selfscan.comparable(self.out))

    def test_the_report_names_the_pack_not_the_folder_it_sits_in(self):
        text = json.dumps(self.out)
        self.assertEqual(self.out["target"], "noa-cifratti")
        self.assertNotIn(str(u.ROOT), text)
        self.assertNotIn(u.ROOT.as_posix(), text)


if __name__ == "__main__":
    unittest.main()
