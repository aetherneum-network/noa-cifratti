"""Configuration review, Python review and the attack-surface delta."""
import copy
import json
import unittest

from tests import _util as u
from corpus import patches
from noascan import config, pycode, rules_engine, surface
from noascan.scan import RuleSet, scan

HOST = "app." + u.DOMAIN


def routes(*routers, trust=False):
    return json.dumps({"schema": "gateway-routes/v1",
                       "entrypoints": {"public": {"bind": "0.0.0.0:443"}, "admin": {"bind": "10.77.0.1:8443"}},
                       "middlewares": {"forward-auth": {"type": "forward-auth", "trust_forward_header": trust}},
                       "routers": [{"name": n, "entrypoint": ep, "host": HOST, "path_prefix": prefix, "middlewares": mws}
                                   for n, ep, prefix, mws in routers]}, indent=2) + "\n"


def services(*items):
    return json.dumps({"schema": "services/v1", "networks": ["public", "app", "data", "admin"],
                       "services": [{"name": n, "plane": plane, "networks": nets, "published": pub, "mounts": mounts}
                                    for n, plane, nets, pub, mounts in items]}, indent=2) + "\n"


BASE = {"README.md": "# x\n", "deploy/prod.env": "LOG_LEVEL=warn\nDEBUG=false\n",
        "config/gateway/routes.json": routes(("site", "public", "/", []), ("portal", "public", "/admin", ["forward-auth"])),
        "config/services.json": services(("gateway", "public", ["public", "app"], ["0.0.0.0:443:443"], []),
                                         ("db", "data", ["data"], [], ["dbdata:/var/lib/db"]))}


def review(files):
    rs = RuleSet.load()
    return [(f.rule, f.subject) for f in config.review(config.parse(files, rs.raw["config"]), rs.raw["config"])]


class ConfigReview(unittest.TestCase):
    def test_a_sound_configuration_has_no_finding(self):
        self.assertEqual(review(BASE), [])

    def test_each_defect_is_reported_by_its_rule(self):
        cases = {
            "CFG-DEBUG-ROUTE": ("config/gateway/routes.json", routes(("dbg", "public", "/debug", [])), "dbg"),
            "CFG-ADMIN-NO-AUTH": ("config/gateway/routes.json", routes(("portal", "public", "/admin", [])), "portal"),
            "CFG-FWD-AUTH-TRUST": ("config/gateway/routes.json", routes(("site", "public", "/", []), trust=True), "forward-auth"),
            "CFG-RUNTIME-SOCKET": ("config/services.json",
                                   services(("agent", "app", ["app"], [], ["/var/run/runtime.sock:/var/run/runtime.sock"])), "agent"),
            "CFG-PORT-ALL-IFACES": ("config/services.json", services(("db", "data", ["data"], ["5432:5432"], [])), "db"),
            "CFG-BRIDGE-PUBLIC-DATA": ("config/services.json", services(("api", "app", ["public", "data"], [], [])), "api"),
            "CFG-DEBUG-FLAG": ("deploy/prod.env", "DEBUG=True\n", "DEBUG"),
        }
        for rule, (path, text, subject) in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(review(dict(BASE, **{path: text})), [(rule, subject)])

    def test_exception_on_top_admin_entrypoint_is_not_a_public_exposure(self):
        text = routes(("panel", "admin", "/admin", []))
        self.assertEqual(review(dict(BASE, **{"config/gateway/routes.json": text})), [])
        raw = copy.deepcopy(rules_engine.load("config"))
        raw["rules"] = [r for r in raw["rules"] if r["id"] != "CFG-X-ADMIN-ENTRYPOINT"]
        model = config.parse({"config/gateway/routes.json": text}, raw)
        self.assertEqual(config.review(model, raw), [])          # still nothing: the rules below require entrypoint public

    def test_prefix_match_is_on_path_segments(self):
        self.assertEqual(review(dict(BASE, **{"config/gateway/routes.json": routes(("a", "public", "/administrators", []))})), [])
        self.assertEqual(review(dict(BASE, **{"config/gateway/routes.json": routes(("a", "public", "/admin/users", []))})),
                         [("CFG-ADMIN-NO-AUTH", "a")])

    def test_string_true_is_not_boolean_true(self):
        text = routes(("site", "public", "/", [])).replace('"trust_forward_header": false', '"trust_forward_header": "false"')
        self.assertEqual(review(dict(BASE, **{"config/gateway/routes.json": text})), [])

    def test_published_forms(self):
        self.assertEqual(config.published("10.77.0.1:8443:8443"), ("10.77.0.1", "8443"))
        self.assertEqual(config.published("5432:5432"), ("0.0.0.0", "5432"))
        self.assertEqual(config.published("[::]:443:443"), ("::", "443"))

    def test_unknown_condition_raises_instead_of_passing(self):
        raw = copy.deepcopy(rules_engine.load("config"))
        raw["rules"][1]["when"]["colour"] = "red"
        with self.assertRaises(rules_engine.RuleError):
            config.review(config.parse(dict(BASE, **{"config/gateway/routes.json": routes(("dbg", "public", "/debug", []))}), raw), raw)

    def test_broken_schema_file_is_a_gap_not_a_pass(self):
        broken = '{"schema": "services/v1", "services": [ {"name": '
        root = u.write_tree(u.tmp("cfg-broken"), dict(BASE, **{"config/services.json": broken}))
        out = scan(root, u.AS_OF)
        self.assertEqual(out["verdict"], "NOT_COVERED")
        self.assertEqual([(n["path"], n["reason"]) for n in out["coverage"]["not_covered"]], [("config/services.json", "config_not_parseable")])

    def test_config_findings_reach_the_verdict(self):
        root = u.write_tree(u.tmp("cfg-verdict"), dict(BASE, **{"deploy/prod.env": "DEBUG=1\n"}))
        out = scan(root, u.AS_OF)
        self.assertEqual([(f["kind"], f["rule"], f["path"], f["line"]) for f in out["findings"]],
                         [("config", "CFG-DEBUG-FLAG", "deploy/prod.env", 1)])
        self.assertNotIn(out["verdict"], ("CLEAN", "EXCEPTIONS_ONLY"))


SNIPPETS = {
    "PY-EVAL": "def f(x):\n    return eval(x)\n",
    "PY-SHELL-TRUE": "import subprocess as sp\n\ndef f(c):\n    return sp.run(c, shell=True)\n",
    "PY-OS-SYSTEM": "from os import system\n\ndef f(c):\n    system(c)\n",
    "PY-PICKLE": "import pickle\n\ndef f(b):\n    return pickle.loads(b)\n",
    "PY-TLS-VERIFY-OFF": "def f(client, url):\n    return client.get(url, verify=False)\n",
    "PY-DEBUG-SERVER": "def f(app):\n    app.run(debug=True)\n",
    "PY-BIND-ALL": "def f(server):\n    server.serve(host='0.0.0.0', port=8080)\n",
}


class PythonReview(unittest.TestCase):
    def setUp(self):
        self.rules = rules_engine.load("pycode")

    def test_each_pattern_is_reported_by_its_rule_with_the_line(self):
        for rule, text in SNIPPETS.items():
            with self.subTest(rule=rule):
                found = pycode.review(text, self.rules)
                self.assertEqual([f.rule for f in found], [rule])
                self.assertEqual(found[0].line, len(text.rstrip("\n").split("\n")))

    def test_safe_lookalikes_are_not_reported(self):
        for text in ("import ast\n\ndef f(x):\n    return ast.literal_eval(x)\n",
                     "import subprocess\n\ndef f(c):\n    return subprocess.run(c, shell=False)\n",
                     "def f(client, url):\n    return client.get(url, verify=True)\n",
                     "def f(app):\n    app.run(debug=False)\n",
                     "def f(server):\n    server.serve(host='127.0.0.1')\n",
                     "NOTE = 'never call eval(x) or os.system(c)'\n",
                     "# eval(x)\n"):
            with self.subTest(text=text):
                self.assertEqual(pycode.review(text, self.rules), [])

    def test_aliases_are_resolved(self):
        found = pycode.review("import pickle as p\nfrom subprocess import run as go\n\ndef f(b, c):\n    go(c, shell=True)\n    return p.load(b)\n",
                              self.rules)
        self.assertEqual([f.rule for f in found], ["PY-SHELL-TRUE", "PY-PICKLE"])

    def test_unparseable_source_abstains(self):
        self.assertIsNone(pycode.review("def f(:\n", self.rules))
        root = u.write_tree(u.tmp("py-unparseable"), dict(u.CLEAN_FILES, **{"src/broken.py": "def f(:\n"}))
        out = scan(root, u.AS_OF)
        self.assertEqual((out["verdict"], [n["reason"] for n in out["coverage"]["not_covered"]]), ("NOT_COVERED", ["python_not_parseable"]))

    def test_the_review_never_runs_the_code_it_reads(self):
        marker = u.tmp("py-noexec") / "marker.txt"
        text = f"open({json.dumps(str(marker))}, 'w').write('ran')\n"
        self.assertEqual(pycode.review(text, self.rules), [])
        self.assertFalse(marker.exists())


class Surface(unittest.TestCase):
    def delta(self, name, before, after):
        a = u.write_tree(u.tmp(f"surf-{name}-a"), before)
        b = u.write_tree(u.tmp(f"surf-{name}-b"), after)
        return surface.delta(a, b, u.AS_OF)

    def test_identical_trees_pass_with_zero(self):
        out = self.delta("same", BASE, BASE)
        self.assertEqual((out["delta"], out["verdict"], out["exit_code"], out["entries"]), (0, "PASS", 0, []))

    def test_every_way_to_grow_is_blocked(self):
        token = u.fake("vendor_api_token", 21)
        grown = {
            "route": {"config/gateway/routes.json": routes(("site", "public", "/", []), ("portal", "public", "/admin", ["forward-auth"]),
                                                           ("new", "public", "/export", []))},
            "auth removed": {"config/gateway/routes.json": routes(("site", "public", "/", []), ("portal", "public", "/admin", []))},
            "port": {"config/services.json": services(("gateway", "public", ["public", "app"], ["0.0.0.0:443:443"], []),
                                                      ("db", "data", ["data"], ["5432:5432"], ["dbdata:/var/lib/db"]))},
            "socket": {"config/services.json": services(("gateway", "public", ["public", "app"], ["0.0.0.0:443:443"],
                                                         ["/var/run/runtime.sock:/var/run/runtime.sock"]),
                                                        ("db", "data", ["data"], [], ["dbdata:/var/lib/db"]))},
            "debug flag": {"deploy/prod.env": "LOG_LEVEL=warn\nDEBUG=true\n"},
            "secret": {"deploy/prod.env": f"LOG_LEVEL=warn\nDEBUG=false\nAPI_TOKEN={token}\n"},
            "secret as file name": {f"backup/{token}.txt": "rotated\n"},
        }
        for name, change in grown.items():
            with self.subTest(change=name):
                out = self.delta("grow", BASE, dict(BASE, **change))
                self.assertGreaterEqual(out["delta"], 1)
                self.assertEqual((out["verdict"], out["gate_rule"], out["exit_code"]), ("BLOCKED", "SURF-GROWS", 3))
                self.assertNotIn(token, json.dumps(out))

    def test_a_private_bind_is_not_surface(self):
        after = dict(BASE, **{"config/services.json": services(("gateway", "public", ["public", "app"], ["0.0.0.0:443:443"], []),
                                                                ("db", "data", ["data"], ["127.0.0.1:5432:5432"], ["dbdata:/var/lib/db"]))})
        self.assertEqual(self.delta("private", BASE, after)["delta"], 0)

    def test_reducing_passes_and_the_delta_is_negative(self):
        after = dict(BASE, **{"config/gateway/routes.json": routes(("site", "public", "/", []))})
        out = self.delta("shrink", BASE, after)
        self.assertEqual((out["delta"], out["verdict"], out["removed"]), (-1, "PASS", [f"route:{HOST}/admin"]))

    def test_a_swap_that_keeps_the_count_is_not_a_pass(self):
        after = dict(BASE, **{"config/gateway/routes.json": routes(("site", "public", "/", []), ("x", "public", "/export", []))})
        out = self.delta("swap", BASE, after)
        self.assertEqual((out["delta"], out["verdict"], out["gate_rule"]), (0, "NEEDS_REVIEW", "SURF-MOVES"))

    def test_a_growth_cannot_hide_behind_a_removal(self):
        after = dict(BASE, **{"config/gateway/routes.json": routes(("x", "public", "/export", []), ("y", "public", "/export2", []))})
        self.assertEqual(self.delta("hide", BASE, after)["verdict"], "NEEDS_REVIEW")     # +2 -2: moved, reviewed by a human

    def test_a_new_unreadable_file_makes_the_comparison_not_covered(self):
        after = dict(BASE, **{"backup/dump.enc": b"Salted__" + bytes(range(64))})
        out = self.delta("unreadable", BASE, after)
        self.assertEqual((out["verdict"], out["gate_rule"], out["unreadable_added"]), ("NOT_COVERED", "SURF-UNREADABLE", ["backup/dump.enc"]))
        same = self.delta("unreadable-both", after, after)
        self.assertEqual(same["verdict"], "PASS")                 # the same unreadable file on both sides is not a change

    def test_generated_pairs_match_their_gold(self):
        for idx in range(1, 13):
            before, after, gold_rec = patches.build(u.DEV_SEED, idx)
            with self.subTest(pair=gold_rec["pair"], ops=gold_rec["ops"]):
                out = self.delta("gold", {p: d for p, d in before.items()}, {p: d for p, d in after.items()})
                self.assertEqual((out["delta"], out["verdict"]), (gold_rec["delta"], gold_rec["expected_gate"]))
                for key in ("added", "removed", "weakened", "strengthened"):
                    self.assertEqual(out[key], sorted(gold_rec[key]))

    def test_as_of_is_mandatory(self):
        a = u.write_tree(u.tmp("surf-asof"), BASE)
        with self.assertRaises(ValueError):
            surface.delta(a, a, "")


if __name__ == "__main__":
    unittest.main()
