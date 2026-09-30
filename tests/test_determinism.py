"""Two rebuilds in two different folders give the same bytes (small corpus here; the full one is run by hand and by CI)."""
import re
import unittest

from tests import _util as u


class DoubleRebuild(unittest.TestCase):
    def test_small_double_rebuild_is_byte_identical(self):
        proc = u.run(["tools/rebuild.py", "--small"], timeout=600)
        text = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, text[-3000:] + proc.stderr.decode("utf-8", "replace")[-3000:])
        self.assertIn("every file identical", text)
        digests = re.findall(r"outputs sha256\s*:?\s*([0-9a-f]{64})", text)
        self.assertTrue(digests)
        self.assertEqual(len(set(digests)), 1)

    def test_the_readme_records_the_digest_of_the_full_rebuild(self):
        readme = (u.ROOT / "README.md").read_text(encoding="utf-8")
        recorded = re.findall(r"outputs sha256[^0-9a-f]*([0-9a-f]{64})", readme)
        self.assertEqual(len(recorded), 1)
        self.assertIn("not verified on another operating system", readme)


if __name__ == "__main__":
    unittest.main()
