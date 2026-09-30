"""The evaluation harness: what it refuses, what it records, and a small end-to-end measurement."""
import contextlib
import io
import json
import sys
import unittest
from unittest import mock

from tests import _util as u

sys.path.insert(0, str(u.ROOT / "eval"))
import score  # noqa: E402
from corpus import generate  # noqa: E402

SEEDS = json.loads((u.ROOT / "eval" / "seeds.json").read_text(encoding="utf-8"))
NOT_AN_AUTHOR_SEED = 7        # never generated here: every call below is refused before any corpus is written


def call(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(generate, "generate", side_effect=AssertionError("a refused run must not generate a corpus")):
        code = score.main([str(a) for a in args])
    return code, err.getvalue()


class BlindProtocol(unittest.TestCase):
    def test_the_author_seeds_are_refused_for_a_blind_run(self):
        for name, seed in SEEDS["author_seeds"].items():
            with self.subTest(seed=name):
                code, err = call("--suite", "blind", "--seed", seed, "--runner", "someone-else")
                self.assertEqual(code, 64)
                self.assertIn("used by the author", err)

    def test_a_blind_run_needs_a_seed_and_a_runner(self):
        self.assertEqual(call("--suite", "blind", "--seed", NOT_AN_AUTHOR_SEED)[0], 64)
        self.assertEqual(call("--suite", "blind", "--runner", "someone-else")[0], 64)

    def test_a_blind_run_needs_the_freeze_tag(self):
        with mock.patch.object(score, "FREEZE_TAG", "v0.0.0-no-such-tag"):
            code, err = call("--suite", "blind", "--seed", NOT_AN_AUTHOR_SEED, "--runner", "someone-else")
        self.assertEqual(code, 64)
        self.assertIn("not a blind run", err)
        self.assertIn("not found", err)

    def test_recording_needs_the_date_of_the_run(self):
        code, err = call("--suite", "dev", "--record")
        self.assertEqual(code, 64)
        self.assertIn("--run-date", err)

    def test_the_frozen_paths_cover_everything_that_decides_a_result(self):
        self.assertEqual(score.FREEZE_TAG, "v2.0.0-freeze")
        for path in ("noascan", "rules", "playbooks", "tabletop", "threatmodel", "corpus", "eval/score.py", "eval/manual.py",
                     "eval/seeds.json"):
            self.assertIn(path, score.FROZEN_PATHS)
            self.assertTrue((u.ROOT / path).exists())


class CommittedResults(unittest.TestCase):
    def test_each_author_suite_has_a_result_made_with_the_current_rules(self):
        from noascan.scan import RuleSet
        current = RuleSet.load().stamp()
        for suite, seed in SEEDS["author_seeds"].items():
            with self.subTest(suite=suite):
                res = json.loads((u.ROOT / "eval" / f"results-{suite}.json").read_text(encoding="ascii"))
                self.assertEqual((res["suite"], res["seed"], res["perturbed"]), (suite, seed, suite == "stress"))
                self.assertEqual(res["rules"], current)
                self.assertEqual(res["as_of"], u.AS_OF)
                self.assertEqual(res["never_event_clean_with_covered_secret"], {"count": 0, "repos": []})
                self.assertEqual(res["secret_values_in_reports"], 0)
                self.assertEqual(res["sizes"], {"repos": 200, "transcripts": 150, "patch_pairs": 120})


class Measurement(unittest.TestCase):
    def test_a_small_dev_corpus_end_to_end(self):
        out = u.tmp("eval-small") / "c"
        generate.generate(u.DEV_SEED, out, out / "gold", u.AS_OF, 30, 24, 18)
        res = score.score(out, out / "gold", u.DEV_SEED, False, u.AS_OF)
        k = score.key_numbers(res)
        self.assertEqual(k["never_event"], 0)
        self.assertEqual(k["secret_values_in_reports"], 0)
        self.assertEqual(k["secrets"]["fn"], 0)
        self.assertEqual(k["verdicts"]["agree"] + k["verdicts"]["acceptable"] + k["verdicts"]["wrong"], 30)
        self.assertEqual((k["surface"]["items_exact"], k["surface"]["gate_agree"]), (18, 18))
        self.assertEqual((k["tabletop"]["verdict_agree"], k["tabletop"]["violations_exact"]), (24, 24))
        self.assertEqual(k["tabletop"]["failed_called_passed"], 0)
        self.assertIn("no claim about any real system", res["statement"])

    def test_the_harness_sees_a_never_event_when_there_is_one(self):
        # the same corpus, judged by a scanner that answers CLEAN to everything: the harness must count it, not hide it
        from noascan.scan import scan
        out = u.tmp("eval-blind-scanner") / "c"
        generate.generate(u.DEV_SEED, out, out / "gold", u.AS_OF, 30, 2, 2)
        template = scan(u.write_tree(u.tmp("eval-blind-template"), u.CLEAN_FILES), u.AS_OF)
        self.assertEqual(template["verdict"], "CLEAN")
        with mock.patch.object(score, "scan", side_effect=lambda *a, **k: json.loads(json.dumps(template))):
            res = score.score(out, out / "gold", u.DEV_SEED, False, u.AS_OF)
        self.assertGreater(res["never_event_clean_with_covered_secret"]["count"], 0)
        self.assertGreater(res["secrets_by_class"]["ALL"]["fn"], 0)
        self.assertEqual(res["secrets_by_class"]["ALL"]["recall"], 0.0)

    def test_ratios(self):
        self.assertIsNone(score.ratio(0, 0))
        self.assertEqual(score.prf(3, 1, 0), {"tp": 3, "fp": 1, "fn": 0, "precision": 0.75, "recall": 1.0})


if __name__ == "__main__":
    unittest.main()
