"""Tabletop: the judge names every departure, the runner refuses two things, the log is append-only."""
import ast
import copy
import json
import unittest

from tests import _util as u
from corpus import tabletops
from noascan import rules_engine
from tabletop import judge as tjudge
from tabletop import log as tlog
from tabletop import model_roles, runner

PLAYBOOKS = {name: tjudge.load_playbook(name) for name in tabletops.PLAYBOOKS}


def found(out):
    return sorted((v["code"], v["step"]) for v in out["violations"])


def clean_script(name, subject="SUBJ-1001"):
    """A script that follows the playbook in order, with every evidence, quorum and consent."""
    pb = PLAYBOOKS[name]
    actions = []
    for i, step in enumerate(pb["steps"]):
        action = {"actor": f"{step['role']}@{u.DOMAIN}", "step": step["id"], "at": f"2026-10-12T10:{i:02d}:00+02:00",
                  "evidence": list(step["evidence"])}
        if step.get("quorum"):
            action["approvals"] = [f"{step['quorum']['role_prefix']}:{n}" for n in range(step["quorum"]["min_distinct"])]
        if step.get("destructive"):
            action["consent"] = {"by": "human:founder", "for": step["id"]}
        actions.append(action)
    return {"subject": subject, "actions": actions}


def play(name, script, label):
    out = u.tmp(f"tt-{label}") / "log.jsonl"
    summary = runner.run(PLAYBOOKS[name], script, out)
    return summary, tlog.read(out) if out.exists() else []


class Judge(unittest.TestCase):
    def test_a_script_that_follows_the_playbook_passes(self):
        for name in PLAYBOOKS:
            with self.subTest(playbook=name):
                summary, events = play(name, clean_script(name), f"clean-{name}")
                self.assertEqual(summary["refused"], [])
                out = tjudge.judge(events, PLAYBOOKS[name], u.AS_OF)
                self.assertEqual((out["verdict"], out["closure"], out["violations"], out["exit_code"]), ("PASSED", "ALLOWED", [], 0))
                self.assertEqual(out["closing_step"], next(s["id"] for s in PLAYBOOKS[name]["steps"] if s.get("closes")))

    def test_generated_transcripts_match_their_gold(self):
        seen = set()
        for idx in range(1, 61):
            events, gold_rec = tabletops.build(u.DEV_SEED, idx, u.AS_OF)
            seen.update(gold_rec["faults"])
            with self.subTest(transcript=gold_rec["transcript"], faults=gold_rec["faults"]):
                out = tjudge.judge(events, PLAYBOOKS[gold_rec["playbook"]], u.AS_OF)
                self.assertEqual(out["verdict"], gold_rec["expected_verdict"])
                self.assertEqual(found(out), sorted(tuple(v) for v in gold_rec["expected_violations"]))
                self.assertEqual(out["closure"], "ALLOWED" if out["verdict"] == "PASSED" else "BLOCKED")
        self.assertGreaterEqual(len(seen), 8)                       # the slice exercises most kinds of fault

    def test_every_fault_of_every_playbook_is_named(self):
        named = {(pb, code) for pb, faults in tabletops.FAULTS.items() for pairs in faults.values() for code, _ in pairs}
        reached = set()
        for idx in range(1, 151):
            events, gold_rec = tabletops.build(u.DEV_SEED, idx, u.AS_OF)
            out = tjudge.judge(events, PLAYBOOKS[gold_rec["playbook"]], u.AS_OF)
            reached.update((gold_rec["playbook"], v["code"]) for v in out["violations"])
        self.assertEqual(sorted(named - reached), [])

    def test_rotation_without_revocation_is_named_by_the_invariant_not_as_a_skipped_step(self):
        script = clean_script("compromised_key")
        script["actions"] = [a for a in script["actions"] if a["step"] not in ("revoke_old_key", "verify_old_key_rejected")]
        _, events = play("compromised_key", script, "norevoke")
        out = tjudge.judge(events, PLAYBOOKS["compromised_key"], u.AS_OF)
        self.assertIn(("ROTATED_NOT_REVOKED", "revoke_old_key"), found(out))
        self.assertNotIn(("STEP_SKIPPED", "revoke_old_key"), found(out))
        self.assertEqual(out["closure"], "BLOCKED")

    def test_order_of_the_rules_decides_the_name(self):
        rules = copy.deepcopy(rules_engine.load("judge"))
        rules["rules"] = [r for r in rules["rules"] if r["id"] != "J-PAIRED-MISSING"]
        script = clean_script("compromised_key")
        script["actions"] = [a for a in script["actions"] if a["step"] not in ("revoke_old_key", "verify_old_key_rejected")]
        _, events = play("compromised_key", script, "norevoke-rules")
        out = tjudge.judge(events, PLAYBOOKS["compromised_key"], u.AS_OF, rules=rules)
        self.assertIn(("STEP_SKIPPED", "revoke_old_key"), found(out))

    def test_quorum_counts_distinct_custodians(self):
        script = clean_script("compromised_key")
        quorum = next(a for a in script["actions"] if a["step"] == "assemble_quorum")
        quorum["approvals"] = ["custodian:0", "custodian:0", "custodian:1", "operator:9"]
        _, events = play("compromised_key", script, "quorum")
        self.assertEqual(found(tjudge.judge(events, PLAYBOOKS["compromised_key"], u.AS_OF)), [("QUORUM_NOT_MET", "assemble_quorum")])

    def test_one_subject_from_opening_to_closing(self):
        script = clean_script("leaked_endpoint", subject="EP-4172")
        script["actions"][2]["subject"] = "EP-1472"
        _, events = play("leaked_endpoint", script, "subject")
        out = tjudge.judge(events, PLAYBOOKS["leaked_endpoint"], u.AS_OF)
        self.assertEqual([v["code"] for v in out["violations"]], ["IDENTIFIER_MISMATCH"])
        self.assertIn("EP-4172", out["violations"][0]["details"][0])
        self.assertIn("EP-1472", out["violations"][0]["details"][0])

    def test_cited_artifacts_are_read_and_a_missing_one_is_a_violation(self):
        script = clean_script("leaked_endpoint", subject="EP-4172")
        script["actions"][0]["artifacts"] = [{"file": "alert.json"}]
        script["actions"][1]["artifacts"] = [{"file": "../outside.json"}]
        _, events = play("leaked_endpoint", script, "artifacts")
        art = u.tmp("tt-artifacts-dir")
        (art / "alert.json").write_text(json.dumps({"author": "monitor", "endpoint_id": "EP-4127"}), encoding="utf-8")
        out = tjudge.judge(events, PLAYBOOKS["leaked_endpoint"], u.AS_OF, artifacts=art)
        self.assertEqual(sorted(v["code"] for v in out["violations"]), ["ARTIFACT_MISSING", "IDENTIFIER_MISMATCH"])

    def test_unknown_step_and_unknown_rule_condition(self):
        script = clean_script("rogue_container")
        script["actions"].insert(1, {"actor": "operator", "step": "improvise", "at": "2026-10-12T10:00:30+02:00"})
        summary, events = play("rogue_container", script, "unknown")
        self.assertEqual(summary["refused"], [{"step": "improvise", "reason": "UNKNOWN_STEP"}])
        forged = [dict(e) for e in events if e.get("type") != "refused"]
        forged.insert(1, {"actor": "operator", "step": "improvise", "subject": forged[0]["subject"], "evidence": []})
        self.assertIn("UNKNOWN_STEP", [v["code"] for v in tjudge.judge(forged, PLAYBOOKS["rogue_container"], u.AS_OF)["violations"]])
        rules = copy.deepcopy(rules_engine.load("judge"))
        rules["rules"][0]["when"] = "moon_phase"
        with self.assertRaises(rules_engine.RuleError):
            tjudge.judge(events, PLAYBOOKS["rogue_container"], u.AS_OF, rules=rules)

    def test_as_of_is_mandatory_and_the_judgement_is_dated(self):
        _, events = play("rogue_container", clean_script("rogue_container"), "asof")
        with self.assertRaises(ValueError):
            tjudge.judge(events, PLAYBOOKS["rogue_container"], "")
        out = tjudge.judge(events, PLAYBOOKS["rogue_container"], u.AS_OF)
        self.assertEqual(out["as_of"], u.AS_OF)
        self.assertEqual(sorted(out["rules"]), ["judge", "playbook"])
        self.assertIn("paper exercise", out["statement"])


class Runner(unittest.TestCase):
    def destructive(self):
        pb = PLAYBOOKS["rogue_container"]
        return next(s for s in pb["steps"] if s.get("destructive"))

    def test_destructive_step_without_consent_is_refused_and_logged(self):
        step = self.destructive()
        script = clean_script("rogue_container")
        next(a for a in script["actions"] if a["step"] == step["id"]).pop("consent")
        summary, events = play("rogue_container", script, "noconsent")
        self.assertEqual(summary["refused"], [{"step": step["id"], "reason": "CONSENT_MISSING"}])
        self.assertNotIn(step["id"], summary["executed"])
        self.assertEqual([e["reason"] for e in events if e.get("type") == "refused"], ["CONSENT_MISSING"])
        out = tjudge.judge(events, PLAYBOOKS["rogue_container"], u.AS_OF)
        self.assertEqual((out["verdict"], out["closure"]), ("FAILED", "BLOCKED"))
        self.assertEqual([r["reason"] for r in out["refused"]], ["CONSENT_MISSING"])

    def test_consent_must_come_from_a_human_and_name_the_step(self):
        step = self.destructive()
        for consent in ({"by": "agent:noa", "for": step["id"]}, {"by": "human:founder", "for": "another_step"},
                        {"by": "human:founder"}, "yes", None, {"by": "", "for": step["id"]}):
            with self.subTest(consent=consent):
                script = clean_script("rogue_container")
                next(a for a in script["actions"] if a["step"] == step["id"])["consent"] = consent
                summary, _ = play("rogue_container", script, "consent-forms")
                self.assertEqual(summary["refused"], [{"step": step["id"], "reason": "CONSENT_MISSING"}])

    def test_destructive_step_before_the_evidence_is_preserved_is_refused(self):
        step = self.destructive()
        script = clean_script("rogue_container")
        script["actions"] = [a for a in script["actions"] if a["step"] != "preserve_evidence"]
        summary, _ = play("rogue_container", script, "noevidence")
        self.assertEqual(summary["refused"], [{"step": step["id"], "reason": "EVIDENCE_NOT_PRESERVED"}])

    def test_the_runner_writes_the_times_of_the_script_never_the_clock(self):
        script = clean_script("rogue_container")
        _, first = play("rogue_container", script, "clock-a")
        _, second = play("rogue_container", script, "clock-b")
        self.assertEqual(first, second)
        self.assertEqual([e["at"] for e in first], [a["at"] for a in script["actions"]])


class Log(unittest.TestCase):
    def test_editing_a_past_event_breaks_the_chain_where_it_happened(self):
        _, events = play("rogue_container", clean_script("rogue_container"), "tamper")
        self.assertEqual(tlog.broken_links(events), [])
        events[2]["evidence"] = ["rewritten"]
        self.assertEqual(tlog.broken_links(events), [2])
        out = tjudge.judge(events, PLAYBOOKS["rogue_container"], u.AS_OF)
        self.assertIn("LOG_CHAIN_BROKEN", [v["code"] for v in out["violations"]])

    def test_removing_or_reordering_events_is_seen(self):
        _, events = play("rogue_container", clean_script("rogue_container"), "reorder")
        self.assertNotEqual(tlog.broken_links(events[:1] + events[2:]), [])
        self.assertNotEqual(tlog.broken_links([events[1], events[0]] + events[2:]), [])

    def test_rehashing_one_event_is_not_enough(self):
        _, events = play("rogue_container", clean_script("rogue_container"), "rehash")
        events[1]["evidence"] = ["rewritten"]
        events[1]["hash"] = tlog.event_hash(events[1])
        self.assertEqual(tlog.broken_links(events), [2])              # the next event still points at the old hash

    def test_the_log_module_can_only_read_or_append(self):
        tree = ast.parse((u.ROOT / "tabletop" / "log.py").read_text(encoding="utf-8"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        modes = sorted(ast.literal_eval(c.args[1]) if len(c.args) > 1 else "r" for c in calls
                       if isinstance(c.func, ast.Name) and c.func.id == "open")
        self.assertEqual(modes, ["a", "r"])
        names = {c.func.attr for c in calls if isinstance(c.func, ast.Attribute)}
        self.assertEqual(names & {"truncate", "unlink", "remove", "rename", "replace", "write_text", "write_bytes", "rmtree"}, set())
        path = u.tmp("tt-append") / "log.jsonl"
        log = tlog.Log(path)
        log.append({"step": "a"})
        before = path.read_bytes()
        log.append({"step": "b"})
        self.assertTrue(path.read_bytes().startswith(before))


class ModelHook(unittest.TestCase):
    def test_the_hook_is_off_and_even_an_explicit_call_fails(self):
        self.assertIs(model_roles.ENABLED, False)
        self.assertEqual(model_roles.ALLOWED_MODELS, ("claude-opus-5-5", "claude-fable-5-1"))
        with self.assertRaises(ValueError):
            model_roles.role_player("some-other-model", "operator")
        for model in model_roles.ALLOWED_MODELS:
            with self.assertRaises(RuntimeError):
                model_roles.role_player(model, "operator")

    def test_no_switch_in_the_environment_and_nobody_imports_the_hook(self):
        tree = ast.parse((u.ROOT / "tabletop" / "model_roles.py").read_text(encoding="utf-8"))
        imported = [a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names]
        self.assertEqual(imported, ["annotations"])                 # no os, no client, no network module
        assigned = [t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)]
        self.assertEqual(assigned, ["ENABLED", "ALLOWED_MODELS"])    # ENABLED is a constant, set once, to False
        users = [p.relative_to(u.ROOT).as_posix() for p in u.pack_sources()
                 if "model_roles" in p.read_text(encoding="utf-8") and p.name != "model_roles.py"]
        self.assertEqual(users, [])


class CommandLine(unittest.TestCase):
    def test_exit_codes(self):
        base = u.ROOT / "scenarios" / "S06" / "input"
        names = sorted(p.name for p in base.glob("*.jsonl"))
        self.assertEqual(len(names), 2)
        results = {n: u.run(["-m", "tabletop.judge", str(base / n), "--playbook", "compromised_key", "--as-of", u.AS_OF]).returncode
                   for n in names}
        self.assertEqual(sorted(results.values()), [0, 1])
        self.assertEqual(u.run(["-m", "tabletop.judge", str(base / "missing.jsonl"), "--playbook", "compromised_key",
                                "--as-of", u.AS_OF]).returncode, 64)
        self.assertEqual(u.run(["-m", "tabletop.judge", str(base / names[0]), "--playbook", "compromised_key"]).returncode, 64)


if __name__ == "__main__":
    unittest.main()
