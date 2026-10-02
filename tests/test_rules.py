"""The rule files: shape, order, inline tests, patches."""
import copy
import json
import unittest

from tests import _util as u
from corpus import repos
from noascan import rules_engine, selftest
from noascan.scan import RULE_FILES, RuleSet
from noascan.secrets import SecretRules, scan_text

ALL_FILES = RULE_FILES + ("judge", "allowlist")


class Shape(unittest.TestCase):
    def test_every_rule_file_loads_and_is_dated(self):
        for name in ALL_FILES:
            with self.subTest(file=name):
                data = rules_engine.load(name)
                self.assertEqual(data["file"], name)
                self.assertRegex(data["as_of"], r"^\d{4}-\d{2}-\d{2}$")
                self.assertTrue(data["version"])

    def test_inline_tests_pass_and_every_rule_has_one(self):
        self.assertEqual(selftest.run_all(RuleSet.load().raw), [])

    def test_a_broken_rule_fails_its_own_inline_test(self):
        raw = copy.deepcopy(RuleSet.load().raw)
        rule = next(r for r in raw["secrets"]["rules"] if r["id"] == "SEC-NBX-TOKEN")
        rule["pattern"] = rule["pattern"].replace("nbxsyn_tk_", "nbxsyn_zz_")
        self.assertTrue(any("SEC-NBX-TOKEN" in f for f in selftest.run_all(raw)))

    def test_no_credential_looking_string_is_stored_in_a_rule_file(self):
        rs = RuleSet.load()
        for name in ALL_FILES:
            with self.subTest(file=name):
                text = (u.ROOT / "rules" / f"{name}.json").read_text(encoding="utf-8")
                self.assertEqual([h.rule for h in scan_text(f"rules/{name}.json", text, rs.secrets) if h.action == "report"], [])

    def test_malformed_files_raise(self):
        for bad in ({"file": "x", "version": "1", "as_of": "2026-09-30"},
                    {"file": "x", "version": "1", "as_of": "2026-09-30", "rules": {}},
                    {"file": "x", "version": "1", "as_of": "2026-09-30", "rules": [{"id": "A"}, {"id": "A"}]},
                    {"file": "x", "version": "1", "as_of": "2026-09-30", "rules": [{"no": "id"}]}):
            with self.assertRaises(rules_engine.RuleError):
                rules_engine.validate(bad)
        with self.assertRaises(rules_engine.RuleError):
            rules_engine.load(u.ROOT / "rules" / "does-not-exist.json")

    def test_secret_rules_refuse_unknown_kinds_missing_groups_and_classless_reports(self):
        base = {"file": "secrets", "version": "t", "as_of": "2026-09-30"}
        for rule in ({"id": "A", "kind": "line", "action": "explode", "pattern": "(?P<secret>x)"},
                     {"id": "A", "kind": "line", "action": "report", "class": "c", "pattern": "x"},
                     {"id": "A", "kind": "line", "action": "report", "pattern": "(?P<secret>x)"},
                     {"id": "A", "kind": "sideways", "action": "report", "class": "c", "pattern": "(?P<secret>x)"}):
            with self.assertRaises(rules_engine.RuleError):
                SecretRules(dict(base, rules=[rule]))


class Order(unittest.TestCase):
    def test_exceptions_sit_on_top_of_the_secret_rules(self):
        actions = [r["action"] for r in rules_engine.load("secrets")["rules"]]
        first_report = next(i for i, a in enumerate(actions) if a != "ignore")
        self.assertNotIn("ignore", actions[first_report:])
        self.assertGreaterEqual(first_report, 1)

    def test_first_match_wins_on_a_line(self):
        rs = RuleSet.load()
        token = u.fake("vendor_api_token")
        hits = scan_text("deploy/prod.env", f"API_TOKEN={token}\n", rs.secrets)
        self.assertEqual([(h.rule, h.cls) for h in hits], [("SEC-NBX-TOKEN", "vendor_api_token")])   # not also SEC-ASSIGN-BARE

    def test_an_exception_placed_after_the_rule_no_longer_applies(self):
        raw = copy.deepcopy(rules_engine.load("secrets"))
        line = "DATABASE_URL=nbxdb://app_rw:${DB_PASSWORD}@db.corp.example:5432/app\n"
        self.assertEqual(scan_text(".env.example", line, SecretRules(raw)), [])
        ref = next(r for r in raw["rules"] if r["id"] == "X-URI-REFERENCE")
        raw["rules"].remove(ref)
        raw["rules"].append(ref)
        self.assertEqual([h.cls for h in scan_text(".env.example", line, SecretRules(raw))], ["connection_uri_password"])

    def test_rule_limited_to_paths_applies_when_the_path_is_unknown(self):
        rs = RuleSet.load()
        line = f"SMTP_PASSWORD={u.fake('assigned_password')}\n"
        self.assertEqual(len(scan_text("deploy/prod.env", line, rs.secrets)), 1)
        self.assertEqual(scan_text("docs/notes.md", line, rs.secrets), [])
        self.assertEqual(len(scan_text(None, line, rs.secrets)), 1)


class Patches(unittest.TestCase):
    def test_a_patch_replaces_keys_of_one_existing_rule_only(self):
        data = rules_engine.load("secrets")
        out = rules_engine.patched(data, {"rule": "SEC-ASSIGN-BARE", "set": {"path_globs": ["*.env"]}})
        self.assertEqual([r["id"] for r in out["rules"]], [r["id"] for r in data["rules"]])
        self.assertNotEqual(rules_engine.digest(out), rules_engine.digest(data))
        self.assertNotEqual(next(r for r in data["rules"] if r["id"] == "SEC-ASSIGN-BARE")["path_globs"], ["*.env"])
        for bad in ({"rule": "NOPE", "set": {}}, {"rule": "SEC-ASSIGN-BARE"}, {"rule": "SEC-ASSIGN-BARE", "set": {"id": "X"}}):
            with self.assertRaises(rules_engine.RuleError):
                rules_engine.patched(data, bad)

    def test_digest_is_stable_and_in_every_report_stamp(self):
        rs = RuleSet.load()
        stamp = rs.stamp()
        self.assertEqual(sorted(stamp), sorted(RULE_FILES))
        for name, entry in stamp.items():
            self.assertEqual(entry["sha256"], rules_engine.digest(json.loads((u.ROOT / "rules" / f"{name}.json").read_text("utf-8"))))


class Mirrors(unittest.TestCase):
    def test_generator_and_rules_agree_on_the_size_limit(self):
        self.assertEqual(repos.MAX_FILE_BYTES, rules_engine.load("secrets")["limits"]["max_file_bytes"])

    def test_every_class_the_generator_plants_has_a_blast_radius_above_the_default(self):
        from noascan import gate
        blast = rules_engine.load("blast_radius")
        default = blast["rules"][-1]["id"]
        for cls in list(repos.SEVERITY) + list(repos.CONFIG_DEFECTS) + list(repos.PY_DEFECTS):
            with self.subTest(cls=cls):
                kind = "secret" if cls in repos.SEVERITY else "config" if cls in repos.CONFIG_DEFECTS else "pycode"
                self.assertNotEqual(gate.grade(kind, cls, blast)[2], default)


if __name__ == "__main__":
    unittest.main()
