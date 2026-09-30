"""The ten scenarios: structure, results, and the way an external executor would run them."""
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest

from tests import _util as u
from scenarios import _common, make_inputs, run_all

IDS = [f"S{i:02d}" for i in range(1, 11)]
BASE = u.ROOT / "scenarios"


class Structure(unittest.TestCase):
    def test_there_are_exactly_ten_scenarios(self):
        self.assertEqual(sorted(p.name for p in BASE.iterdir() if p.is_dir() and p.name.startswith("S")), IDS)
        self.assertEqual(run_all.IDS, IDS)

    def test_each_scenario_has_what_an_executor_needs(self):
        for sid in IDS:
            with self.subTest(scenario=sid):
                folder = BASE / sid
                doc = json.loads((folder / "scenario.json").read_text(encoding="utf-8"))
                self.assertEqual((doc["id"], doc["run"]), (sid, ["python", "check.py"]))
                self.assertTrue(doc["title"])
                self.assertLessEqual(doc["timeout_s"], 120)
                self.assertIn(doc["kind"], ("demonstration", "negative", "boundary"))
                self.assertTrue((folder / "check.py").is_file())
                self.assertTrue(any((folder / "input").iterdir()))
                self.assertTrue(any((folder / "expected").iterdir()))

    def test_run_md_is_one_paragraph_and_names_the_lessons(self):
        for sid in IDS:
            with self.subTest(scenario=sid):
                title, _, body = (BASE / sid / "run.md").read_text(encoding="utf-8").strip().partition("\n\n")
                self.assertTrue(title.startswith(f"# {sid} - ") and "\n" not in title)
                self.assertTrue(body and "\n" not in body)               # one paragraph, on one line
                for phrase in ("Failure reproduced.", "Pass criterion.", "python check.py", "(synthetic)"):
                    self.assertIn(phrase, body)

    def test_the_date_and_the_seed_live_in_the_input(self):
        for sid in IDS:
            with self.subTest(scenario=sid):
                docs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((BASE / sid / "input").glob("*.json"))]
                dated = [d for d in docs if isinstance(d, dict) and "as_of" in d]
                self.assertEqual([d["as_of"] for d in dated], [u.AS_OF])          # one place, one date
                self.assertIn(dated[0].get("seed", u.DEV_SEED), (u.DEV_SEED,))   # a seed, when values are drawn, is the dev seed
                source = (BASE / sid / "check.py").read_text(encoding="utf-8")
                for word in ("datetime.now", "time.time", "date.today", "import time"):
                    self.assertNotIn(word, source)

    def test_there_is_a_negative_and_a_boundary_scenario(self):
        kinds = {sid: json.loads((BASE / sid / "scenario.json").read_text(encoding="utf-8"))["kind"] for sid in IDS}
        self.assertIn("negative", kinds.values())
        self.assertIn("boundary", kinds.values())

    def test_expected_files_hold_no_path_of_the_machine_and_no_timing(self):
        for sid in IDS:
            for path in sorted((BASE / sid / "expected").iterdir()):
                text = path.read_text(encoding="ascii")
                self.assertNotIn(str(u.ROOT), text)
                self.assertNotIn(u.ROOT.as_posix(), text)
                self.assertNotIn("elapsed", text)
                self.assertTrue(text.endswith("\n") and "\r" not in text.replace("\r\n", "\n"))

    def test_the_committed_inputs_are_what_the_author_tool_writes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = make_inputs.main(["--check"])
        self.assertEqual(rc, 0, out.getvalue())


class Results(unittest.TestCase):
    def test_every_check_passes_in_process(self):
        results = run_all.run_all(quiet=True)
        self.assertEqual([r["id"] for r in results if not r["ok"]], [])
        self.assertEqual(len(results), 10)
        for r in results:
            self.assertTrue(r["line"].startswith(f"{r['id']} PASS - "))

    def test_each_scenario_runs_the_way_the_council_executor_runs_it(self):
        # cwd = the scenario folder, a minimal environment, "python" = this interpreter, sockets blocked
        for sid in IDS:
            with self.subTest(scenario=sid):
                proc = u.run(["check.py"], cwd=BASE / sid)
                self.assertEqual(proc.returncode, 0, proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace"))
                self.assertTrue(proc.stdout.decode("ascii").startswith(f"{sid} PASS - "))

    def test_one_scenario_with_exactly_the_executor_environment(self):
        keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG")
        env = {k: v for k, v in os.environ.items() if k.upper() in keep}
        env.update(PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([sys.executable, "check.py"], cwd=str(BASE / "S03"), env=env, capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))

    def test_a_different_output_fails_the_comparison(self):
        failures: list[str] = []
        _common.expect(BASE / "S10" / "expected" / "control.json", {"verdict": "CLEAN"}, failures)
        self.assertEqual(failures, ["output differs from expected/control.json"])
        _common.expect(BASE / "S10" / "expected" / "absent.json", {}, failures)
        self.assertEqual(failures[-1], "missing expected file absent.json")

    def test_a_crashing_check_is_a_failing_check(self):
        results = run_all.run_all(ids=["S99"], quiet=True)
        self.assertEqual([(r["id"], r["ok"]) for r in results], [("S99", False)])
        self.assertIn("FAIL", results[0]["line"])

    def test_the_report_of_the_runner_is_the_same_bytes_twice(self):
        out = u.tmp("scen-report")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run_all.main(["S02", "S05", "--json", str(out / "a.json")]), 0)
            self.assertEqual(run_all.main(["S02", "S05", "--json", str(out / "b.json")]), 0)
        a = (out / "a.json").read_bytes()
        self.assertEqual(a, (out / "b.json").read_bytes())
        doc = json.loads(a)
        self.assertEqual((doc["passed"], doc["total"]), (2, 2))
        self.assertNotIn(b"[0.", a)
        self.assertNotIn(str(u.ROOT).encode(), a)

    def test_the_committed_report_is_current(self):
        committed = json.loads((u.ROOT / "reports" / "scenarios.json").read_text(encoding="ascii"))
        results = run_all.run_all(quiet=True)
        self.assertEqual((committed["passed"], committed["total"]), (10, 10))
        self.assertEqual([s["line"] for s in committed["scenarios"]], [r["line"] for r in results])


if __name__ == "__main__":
    unittest.main()
