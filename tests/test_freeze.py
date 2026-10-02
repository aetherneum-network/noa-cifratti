"""After the freeze: the tag, the blind protocol, the history of the measurements and the manifest."""
import contextlib
import io
import json
import re
import subprocess
import sys
import unittest
from unittest import mock

from tests import _util as u

sys.path.insert(0, str(u.ROOT / "eval"))
import score  # noqa: E402
from tools import manifest  # noqa: E402

SEEDS = json.loads((u.ROOT / "eval" / "seeds.json").read_text(encoding="utf-8"))
HISTORY = json.loads((u.ROOT / "eval" / "history.json").read_text(encoding="utf-8"))


MANIFEST_TEXT = (u.ROOT / "MANIFEST.sha256").read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
MANIFEST_TAG = manifest.tag_of(MANIFEST_TEXT)               # the tag the manifest travels with: the first freeze or a later one
PROTOCOL = (u.ROOT / "eval" / "BLIND_PROTOCOL.md").read_text(encoding="utf-8")


def git(*args):
    return subprocess.run(["git", "-C", str(u.ROOT), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)


def tag_present(tag: str = score.FREEZE_TAG) -> bool:
    return git("rev-parse", "--verify", "--quiet", f"refs/tags/{tag}").returncode == 0


class Freeze(unittest.TestCase):
    @unittest.skipUnless(tag_present(), "the freeze tag is not in this clone")
    def test_the_frozen_paths_are_still_what_was_tagged(self):
        ok, detail = score.frozen_state()
        self.assertTrue(ok, detail)
        self.assertRegex(detail, r"^[0-9a-f]{40}$")

    @unittest.skipUnless(tag_present(), "the freeze tag is not in this clone")
    def test_the_manifest_lists_the_tagged_files_and_they_are_unchanged(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(manifest.main(["--check"]), 0)
        self.assertIn(", 0 differ;", out.getvalue())
        self.assertRegex(MANIFEST_TAG, r"^v2\.0\.\d+-freeze$")
        head = [ln for ln in MANIFEST_TEXT.splitlines() if ln.startswith("#")]
        self.assertEqual(len(head), 4)
        if MANIFEST_TAG == score.FREEZE_TAG:       # a new code freeze (2.0.2): the manifest cannot name its own commit
            self.assertIn(f"{MANIFEST_TAG} is itself the tag the blind harness checks", head[3])
        else:
            self.assertIn(f"identical to {score.FREEZE_TAG} (commit {score.frozen_state()[1]})", head[3])
        for path in score.FROZEN_PATHS:
            self.assertIn(path, head[3])
        listed = [ln.split("  ", 1)[1] for ln in MANIFEST_TEXT.splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(listed, sorted(listed))
        for name, why in manifest.NOT_LISTED:
            self.assertNotIn(name, listed)
            self.assertIn(f"{name} ({why})", head[2])     # left out, and said so in the header with the reason
        for name in ("README.md", "CLAIMS.md", "CHANGELOG.md", "tests/test_docs.py", "tests/test_freeze.py",
                     "tools/manifest.py", "eval/score.py", "rules/gate.json"):
            self.assertIn(name, listed)

    @unittest.skipUnless(tag_present(MANIFEST_TAG), "the tag the manifest names is not in this clone")
    def test_the_manifest_is_the_list_of_the_commit_its_tag_points_to(self):
        self.assertEqual(manifest.render(MANIFEST_TAG, f"{MANIFEST_TAG}^{{commit}}"), MANIFEST_TEXT)
        self.assertEqual(git("cat-file", "-t", f"refs/tags/{MANIFEST_TAG}").stdout.strip(), "tag")     # annotated

    @unittest.skipUnless(tag_present() and tag_present(MANIFEST_TAG), "the freeze tags are not in this clone")
    def test_a_later_freeze_tag_changes_no_path_that_decides_a_result(self):
        self.assertEqual(git("diff", "--quiet", score.FREEZE_TAG, MANIFEST_TAG, "--", *score.FROZEN_PATHS).returncode, 0)
        changed = git("diff", "--name-only", score.FREEZE_TAG, MANIFEST_TAG).stdout.split()
        for path in changed:
            with self.subTest(path=path):
                self.assertFalse(any(path == frozen or path.startswith(frozen + "/") for frozen in score.FROZEN_PATHS))

    def test_the_protocol_names_a_tag_and_the_commit_it_points_to(self):
        m = re.search(r'^git rev-parse "(v[0-9.]+-freeze)\^\{commit\}"\s+# must print ([0-9a-f]{40})$', PROTOCOL, re.M)
        self.assertIsNotNone(m)
        tag, commit = m.groups()
        self.assertIn(f"The tag `{tag}` (commit `{commit}`)", PROTOCOL)
        if not tag_present(tag):
            self.skipTest("the tag the protocol names is not in this clone")
        self.assertEqual(git("rev-parse", f"{tag}^{{commit}}").stdout.strip(), commit)
        if git("diff", "--quiet", score.FREEZE_TAG, tag, "--", *score.FROZEN_PATHS).returncode != 0:
            # A new code freeze (2.0.2): the protocol names a tag and its commit, so it can name the new tag
            # only in the commit after it (MANIFEST.sha256 leaves it out for that reason). Allowed at the
            # tagged commit itself, or before the tag exists, and only if the protocol says it is not valid yet.
            frozen = git("rev-parse", "--verify", "--quiet", f"{score.FREEZE_TAG}^{{commit}}").stdout.strip()
            self.assertIn(frozen, ("", git("rev-parse", "HEAD").stdout.strip()),
                          "after the freeze tag, the protocol must name the tag the harness checks")
            self.assertIn(f"`{score.FREEZE_TAG}`: this file is not yet valid for a blind run", PROTOCOL)

    def test_the_protocol_names_the_command_and_the_refusals(self):
        text = (u.ROOT / "eval" / "BLIND_PROTOCOL.md").read_text(encoding="utf-8")
        for phrase in ("python eval/score.py --suite blind --seed", "python eval/manual.py values --seed",
                       "python eval/manual.py score --seed", "--runner", "--record --run-date", score.FREEZE_TAG,
                       "git rev-parse", "python tools/manifest.py --check", "once", "[TO CONFIRM]"):
            self.assertIn(phrase, text)
        for seed in SEEDS["author_seeds"].values():
            self.assertIn(str(seed), text)

    def test_no_blind_run_is_recorded_by_the_author(self):
        for r in HISTORY["runs"]:
            if r["runner"] == SEEDS["author"]:
                self.assertIn(r["suite"], SEEDS["author_seeds"])
                self.assertEqual(r["freeze_commit"], "")


@unittest.skipUnless(tag_present(), "the freeze tag is not in this clone")
class BlindCommands(unittest.TestCase):
    """The commands of the protocol run to the end. They are tried here on the dev seed, with the list of
    author seeds emptied for the duration of the test: no seed a different hand could use is generated."""

    def call(self, module, *args):
        out, err = io.StringIO(), io.StringIO()
        allow_the_dev_seed = mock.patch.dict(score.SEEDS["author_seeds"], clear=True)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), allow_the_dev_seed:
            code = module.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_the_generated_part_runs_and_names_the_freeze_commit(self):
        out = u.tmp("freeze-blind") / "result.json"
        code, text, err = self.call(score, "--suite", "blind", "--seed", u.DEV_SEED, "--runner", "a-test", "--repos", 12,
                                    "--transcripts", 6, "--pairs", 6, "--json", out)
        self.assertEqual(code, 0, err)
        self.assertIn(f"suite blind seed {u.DEV_SEED}: 12 repositories", text)
        res = json.loads(out.read_text(encoding="ascii"))
        self.assertEqual((res["suite"], res["never_event_clean_with_covered_secret"]["count"]), ("blind", 0))

    def test_the_hand_planted_part_prints_the_values_and_scores_a_filled_form(self):
        import manual
        root = u.tmp("freeze-manual-root")
        with mock.patch.object(manual, "ROOT", root):
            code, text, err = self.call(manual, "values", "--seed", u.DEV_SEED, "--runner", "a-test")
            self.assertEqual(code, 0, err)
            form_path = root / "build" / f"blind-manual-{u.DEV_SEED}" / "hidden.json"
            form = json.loads(form_path.read_text(encoding="ascii"))
            plants = manual.plants(u.DEV_SEED)
            self.assertEqual(len([ln for ln in text.splitlines() if ln.startswith("M")]), 20)
            token = next(p for p in plants if p["class"] == "vendor_api_token")
            self.assertIn(token["value"], text)                       # the runner needs the values: they are printed, never stored
            self.assertNotIn(token["value"], form_path.read_text(encoding="ascii"))
            repo = u.write_tree(u.tmp("freeze-manual-repo"), dict(u.CLEAN_FILES, **{
                "deploy/integration.env": "\n".join(["LOG_LEVEL=warn", "INTEGRATION_CREDENTIAL=" + token["value"], ""])}))
            for entry in form["plants"]:
                if entry["id"] == token["id"]:
                    entry.update(hidden=True, form="plain", where="deploy/integration.env")
            form_path.write_text(json.dumps(form), encoding="ascii")
            out = u.tmp("freeze-manual-out") / "result.json"
            code, text, err = self.call(manual, "score", "--seed", u.DEV_SEED, "--runner", "a-test", "--repo", repo,
                                        "--hidden", form_path, "--json", out)
        self.assertEqual(code, 0, err)
        self.assertIn("plain 1/1 found", text)
        self.assertNotIn(token["value"], out.read_text(encoding="ascii"))
        self.assertFalse((root / "eval" / "history.json").exists())   # nothing recorded without --record


class History(unittest.TestCase):
    def test_runs_are_numbered_dated_and_attributed(self):
        runs = HISTORY["runs"]
        self.assertEqual([r["run"] for r in runs], list(range(1, len(runs) + 1)))
        for r in runs:
            with self.subTest(run=r["run"]):
                self.assertRegex(r["run_date"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$")
                self.assertTrue(r["runner"])
                self.assertTrue(r["rules"])
                if r["suite"] in SEEDS["author_seeds"]:
                    self.assertEqual(r["seed"], SEEDS["author_seeds"][r["suite"]])
                    self.assertEqual(r["runner"], SEEDS["author"])
                else:
                    self.assertIn(r["suite"], ("blind", "blind-manual"))
                    self.assertNotIn(r["seed"], SEEDS["author_seeds"].values())
                    self.assertNotEqual(r["runner"], SEEDS["author"])
                    self.assertTrue(r["freeze_commit"])

    def test_the_bad_first_runs_are_still_there(self):
        first = HISTORY["runs"][0]
        self.assertEqual((first["suite"], first["numbers"]["secrets"]["fp"]), ("dev", 45))
        self.assertLess(first["numbers"]["secrets"]["precision"], 1.0)
        self.assertGreaterEqual(len([r for r in HISTORY["runs"] if r["suite"] == "stress"]), 2)

    def test_the_never_event_never_happened_in_a_recorded_run(self):
        for r in HISTORY["runs"]:
            self.assertEqual(r["numbers"]["never_event"], 0, r["run"])
            self.assertEqual(r["numbers"]["secret_values_in_reports"], 0, r["run"])

    def test_the_last_author_run_of_each_suite_is_the_committed_result(self):
        for suite in SEEDS["author_seeds"]:
            last = [r for r in HISTORY["runs"] if r["suite"] == suite and r["runner"] == SEEDS["author"]][-1]
            res = json.loads((u.ROOT / "eval" / f"results-{suite}.json").read_text(encoding="ascii"))
            self.assertEqual(last["numbers"], score.key_numbers(res), suite)
            self.assertEqual({e["file"]: e["sha256_12"] for e in last["rules"]}, {n: v["sha256"][:12] for n, v in res["rules"].items()})


if __name__ == "__main__":
    unittest.main()
