"""No value of a finding may leave the scanner: structure first, then a search of every output."""
import dataclasses
import json
import unittest

from tests import _util as u
from corpus import fakes, gold
from noascan import report
from noascan.scan import RuleSet, scan
from noascan.secrets import Hit, scan_text


class Structure(unittest.TestCase):
    def test_a_hit_has_no_field_for_the_matched_text(self):
        self.assertEqual([f.name for f in dataclasses.fields(Hit)], ["rule", "action", "cls", "line", "fingerprint", "length", "via"])
        rs = RuleSet.load()
        for cls in fakes.SECRET_CLASSES:
            path, text, value = u.carrier(cls)
            for hit in scan_text(path, text, rs.secrets):
                for field in dataclasses.astuple(hit):
                    self.assertNotIn(value.split("\n")[1] if "\n" in value else value, str(field))

    def test_fingerprint_is_domain_separated_and_short(self):
        import hashlib
        v = u.fake("vendor_api_token")
        self.assertEqual(len(gold.fingerprint(v)), 16)
        self.assertNotEqual(gold.fingerprint(v), hashlib.sha256(v.encode()).hexdigest()[:16])
        from noascan.fingerprint import block_fingerprint, fingerprint
        self.assertEqual(fingerprint(v), gold.fingerprint(v))          # generator and scanner agree without sharing code
        block = u.fake("armored_key_block")
        self.assertEqual(block_fingerprint(["  " + ln for ln in block.split("\n")]), gold.block_fingerprint(block))

    def test_safe_masks_a_string_that_would_itself_be_a_finding(self):
        rs = RuleSet.load()
        v = u.fake("vendor_webhook_secret")
        self.assertEqual(report.safe(f"backup/{v}.txt", rs.secrets), f"[masked:{gold.fingerprint(v)}]")
        self.assertEqual(report.safe("deploy/prod.env", rs.secrets), "deploy/prod.env")
        self.assertEqual(report.safe("", rs.secrets), "")


class Outputs(unittest.TestCase):
    def test_no_value_in_report_or_summary_whatever_carries_it(self):
        values = {cls: u.carrier(cls, 11) for cls in fakes.SECRET_CLASSES}
        files = dict(u.CLEAN_FILES)
        for cls, (path, text, _) in values.items():
            files[f"{cls}/{path}"] = text
        token = u.fake("vendor_api_token", 12)
        r = u.Repo("rs-outputs")
        first = r.commit(files, message=f"add settings ({token})", who=(f"Dev {token}", f"dev@{u.DOMAIN}"))
        second = r.commit(u.CLEAN_FILES, [first])
        r.main(second, u.CLEAN_FILES)
        out = scan(r.root, u.AS_OF)
        text = report.dumps(out) + report.summary(out)
        needles = [token] + [ln for _, _, v in values.values() for ln in v.split("\n") if not ln.startswith("-----")]
        self.assertEqual([n for n in needles if n in text], [])
        self.assertEqual(len([f for f in out["findings"] if f["kind"] == "secret"]), len(values))
        self.assertTrue(all(f["author"].startswith("[masked:") for f in out["findings"] if f["kind"] == "secret"))

    def test_report_is_deterministic_ascii_and_carries_date_rules_and_scope(self):
        path, text, _ = u.carrier("vendor_payment_key")
        root = u.write_tree(u.tmp("rs-deterministic"), dict(u.CLEAN_FILES, **{path: text, "docs/caffè.md": "ok\n"}))
        a, b = report.dumps(scan(root, u.AS_OF)), report.dumps(scan(root, u.AS_OF))
        self.assertEqual(a, b)
        a.encode("ascii")
        doc = json.loads(a)
        self.assertEqual(doc["as_of"], u.AS_OF)
        self.assertEqual(sorted(doc["rules"]), ["blast_radius", "config", "coverage", "gate", "pycode", "secrets"])
        self.assertIn("no claim about any real system", doc["scope"]["statement"])
        self.assertNotIn(str(u.ROOT), a)
        self.assertNotIn(u.ROOT.as_posix(), a)

    def test_written_file_has_lf_line_endings(self):
        out = u.tmp("rs-write") / "r.json"
        report.write(out, {"b": 1, "a": "x"})
        self.assertEqual(out.read_bytes(), b'{\n  "a": "x",\n  "b": 1\n}\n')


if __name__ == "__main__":
    unittest.main()
