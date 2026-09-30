"""The threat model is checked against a topology: every failure code is provoked by a mutation."""
import copy
import json
import shutil
import unittest

from tests import _util as u
from threatmodel import check as tm

MODEL = json.loads((u.ROOT / "threatmodel" / "model.json").read_text(encoding="utf-8"))
TARGET = u.ROOT / "threatmodel" / "target"
ROUTES = "config/gateway/routes.json"
SERVICES = "config/services.json"


def codes(out):
    return sorted({f["code"] for f in out["failures"]})


def target_copy(name, edit=None, path=None, files=None):
    root = u.tmp(name)
    shutil.copytree(TARGET, root, dirs_exist_ok=True)
    if edit is not None:
        doc = json.loads((root / path).read_text(encoding="utf-8"))
        edit(doc)
        (root / path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    u.write_tree(root, files or {})
    return root


def mutated(fn):
    model = copy.deepcopy(MODEL)
    fn(model)
    return model


def threat(model, tid):
    return next(t for t in model["threats"] if t["id"] == tid)


class OwnModel(unittest.TestCase):
    def test_the_shipped_model_passes_on_the_shipped_target(self):
        out = tm.check(MODEL, TARGET, u.AS_OF)
        self.assertEqual((out["verdict"], out["failures"], out["exit_code"]), ("PASSED", [], 0))
        self.assertEqual(len(out["threats"]), len(MODEL["threats"]))
        self.assertEqual(out["entry_points_in_topology"], sorted(e["item"] for e in MODEL["entry_points"]))

    def test_rows_are_ordered_by_blast_radius(self):
        radii = [t["radius"] for t in tm.check(MODEL, TARGET, u.AS_OF)["threats"]]
        self.assertEqual(radii, sorted(radii, reverse=True))
        self.assertGreater(radii[0], radii[-1])

    def test_security_md_embeds_exactly_the_rendered_table(self):
        text = (u.ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn(tm.render(MODEL), text)

    def test_every_threat_is_stated_and_answered(self):
        for t in MODEL["threats"]:
            with self.subTest(threat=t["id"]):
                self.assertTrue(t["statement"])
                self.assertTrue(t.get("mitigation") or t.get("rationale"))
                self.assertIn(t["category"], tm.CATEGORIES)

    def test_as_of_is_mandatory(self):
        with self.assertRaises(ValueError):
            tm.check(MODEL, TARGET, "")


class TopologyChanges(unittest.TestCase):
    """The model stays as it is; the topology moves under it."""

    def test_a_new_public_route(self):
        def edit(doc):
            doc["routers"].append({"name": "upload", "entrypoint": "public", "host": "tiles.lunaria-carto.example",
                                   "path_prefix": "/upload", "middlewares": [], "service": "app"})
        out = tm.check(MODEL, target_copy("tm-route", edit, ROUTES), u.AS_OF)
        self.assertEqual([(f["code"], f["subject"]) for f in out["failures"]],
                         [("ENTRY_POINT_NOT_IN_MODEL", "route:public:tiles.lunaria-carto.example/upload")])

    def test_a_new_published_port_even_on_a_private_address(self):
        def edit(doc):
            next(s for s in doc["services"] if s["name"] == "db")["published"] = ["10.77.0.1:5432:5432"]
        out = tm.check(MODEL, target_copy("tm-port", edit, SERVICES), u.AS_OF)
        self.assertEqual(codes(out), ["ENTRY_POINT_NOT_IN_MODEL", "MITIGATION_NOT_IN_TOPOLOGY"])

    def test_a_mounted_runtime_socket(self):
        def edit(doc):
            next(s for s in doc["services"] if s["name"] == "app")["mounts"] = ["/var/run/runtime.sock:/var/run/runtime.sock"]
        out = tm.check(MODEL, target_copy("tm-socket", edit, SERVICES), u.AS_OF)
        self.assertEqual(codes(out), ["ENTRY_POINT_NOT_IN_MODEL", "MITIGATION_NOT_IN_TOPOLOGY"])
        self.assertIn("socket:app", [f["subject"] for f in out["failures"]])

    def test_a_removed_route_makes_the_model_stale(self):
        def edit(doc):
            doc["routers"] = [r for r in doc["routers"] if r["name"] != "api"]
        out = tm.check(MODEL, target_copy("tm-stale", edit, ROUTES), u.AS_OF)
        self.assertEqual([(f["code"], f["subject"]) for f in out["failures"]], [("STALE_ENTRY_POINT", "EP-API")])

    def test_each_mitigation_is_observed_and_fails_when_it_is_gone(self):
        def drop_auth(doc):
            next(r for r in doc["routers"] if r["name"] == "admin-ui")["middlewares"] = []

        def trust(doc):
            doc["middlewares"]["forward-auth"]["trust_forward_header"] = True

        def public_admin_port(doc):
            next(s for s in doc["services"] if s["name"] == "admin")["published"] = ["0.0.0.0:8443:8443"]

        def db_public(doc):
            next(s for s in doc["services"] if s["name"] == "db")["networks"] = ["data", "public"]

        def no_rate_limit(doc):
            next(r for r in doc["routers"] if r["name"] == "app")["middlewares"] = []

        cases = {"T03": (drop_auth, ROUTES), "T04": (trust, ROUTES), "T06": (db_public, SERVICES), "T10": (no_rate_limit, ROUTES)}
        for tid, (edit, path) in cases.items():
            with self.subTest(threat=tid):
                out = tm.check(MODEL, target_copy(f"tm-mit-{tid}", edit, path), u.AS_OF)
                self.assertEqual([(f["code"], f["subject"]) for f in out["failures"]], [("MITIGATION_NOT_IN_TOPOLOGY", tid)])
        out = tm.check(MODEL, target_copy("tm-mit-T05", public_admin_port, SERVICES), u.AS_OF)
        self.assertIn(("MITIGATION_NOT_IN_TOPOLOGY", "T05"), [(f["code"], f["subject"]) for f in out["failures"]])

    def test_debug_flag_and_debug_route(self):
        out = tm.check(MODEL, target_copy("tm-debug", files={"deploy/prod.env": "LOG_LEVEL=warn\nDEBUG=true\n"}), u.AS_OF)
        self.assertEqual([(f["code"], f["subject"]) for f in out["failures"]], [("MITIGATION_NOT_IN_TOPOLOGY", "T07")])
        out = tm.check(MODEL, target_copy("tm-noflag", files={"deploy/prod.env": "LOG_LEVEL=warn\n"}), u.AS_OF)
        self.assertEqual(codes(out), ["MITIGATION_NOT_IN_TOPOLOGY"])          # an absent flag is not an observed "off"

    def test_a_secret_in_the_tree_or_in_a_file_name(self):
        token = u.fake("vendor_api_token", 31)
        for name, files in (("content", {"deploy/prod.env": f"DEBUG=false\nAPI_TOKEN={token}\n"}),
                            ("filename", {f"backup/{token}.txt": "x\n"})):
            with self.subTest(where=name):
                out = tm.check(MODEL, target_copy(f"tm-secret-{name}", files=files), u.AS_OF)
                self.assertEqual([(f["code"], f["subject"]) for f in out["failures"]], [("MITIGATION_NOT_IN_TOPOLOGY", "T01")])
                self.assertNotIn(token, json.dumps(out))

    def test_an_unreadable_topology_is_a_failure_not_a_pass(self):
        out = tm.check(MODEL, target_copy("tm-unreadable", files={"backup/dump.enc": b"Salted__" + bytes(range(64))}), u.AS_OF)
        self.assertIn("TOPOLOGY_NOT_READABLE", codes(out))
        out = tm.check(MODEL, target_copy("tm-broken", files={SERVICES: '{"schema": "services/v1", "services": ['}), u.AS_OF)
        self.assertIn("TOPOLOGY_NOT_READABLE", codes(out))
        self.assertEqual(out["verdict"], "FAILED")


class ModelChanges(unittest.TestCase):
    """The topology stays as it is; the model is made worse."""

    def one(self, fn, as_of=u.AS_OF):
        return codes(tm.check(mutated(fn), TARGET, as_of))

    def test_entry_point_without_threat(self):
        self.assertEqual(self.one(lambda m: m["threats"].remove(threat(m, "T05"))), ["ENTRY_POINT_WITHOUT_THREAT"])

    def test_asset_without_threat(self):
        self.assertEqual(self.one(lambda m: m["assets"].append({"id": "A-LOGS", "name": "audit logs", "class": "data_store"})),
                         ["ASSET_WITHOUT_THREAT"])

    def test_threat_with_unknown_reference(self):
        self.assertIn("THREAT_WITH_UNKNOWN_REFERENCE", self.one(lambda m: threat(m, "T02").update(asset="A-NOPE")))
        self.assertIn("THREAT_WITH_UNKNOWN_REFERENCE", self.one(lambda m: threat(m, "T02").update(entry_point="EP-NOPE")))

    def test_threat_with_unknown_category(self):
        self.assertEqual(self.one(lambda m: threat(m, "T02").update(category="bad_vibes")), ["THREAT_WITH_UNKNOWN_CATEGORY"])

    def test_mitigation_without_a_check_or_with_an_unknown_check(self):
        self.assertEqual(self.one(lambda m: threat(m, "T02").update(checks=[])), ["MITIGATION_NOT_VERIFIABLE"])
        self.assertEqual(self.one(lambda m: threat(m, "T02").update(checks=[{"type": "trust_me"}])), ["MITIGATION_NOT_IN_TOPOLOGY"])
        self.assertEqual(self.one(lambda m: threat(m, "T01")["checks"].__setitem__(
            1, {"type": "playbook_invariant", "playbook": "compromised_key", "code": "NO_SUCH_CODE"})), ["MITIGATION_NOT_IN_TOPOLOGY"])

    def test_accepted_risk_needs_owner_dates_and_rationale(self):
        for key in ("owner", "date", "review_by", "rationale"):
            with self.subTest(missing=key):
                self.assertEqual(self.one(lambda m: threat(m, "T08").pop(key)), ["ACCEPTED_WITHOUT_OWNER_OR_DATE"])

    def test_accepted_risk_expires(self):
        self.assertEqual(self.one(lambda m: None, as_of="2027-01-14T09:00:00+01:00"), [])
        self.assertEqual(self.one(lambda m: None, as_of="2027-01-15T09:00:00+01:00"), ["ACCEPTED_RISK_REVIEW_OVERDUE"])

    def test_threat_without_disposition(self):
        self.assertEqual(self.one(lambda m: threat(m, "T02").pop("disposition")), ["THREAT_WITHOUT_DISPOSITION"])
        self.assertEqual(self.one(lambda m: threat(m, "T02").update(disposition="ignored")), ["THREAT_WITHOUT_DISPOSITION"])

    def test_model_date(self):
        self.assertEqual(self.one(lambda m: m.pop("as_of")), ["MODEL_WITHOUT_DATE"])
        self.assertEqual(self.one(lambda m: m.update(as_of="2026-10-22")), ["MODEL_DATED_IN_THE_FUTURE"])

    def test_an_empty_model_fails_on_the_real_topology(self):
        out = tm.check({"as_of": MODEL["as_of"]}, TARGET, u.AS_OF)
        self.assertEqual((out["verdict"], codes(out)), ("FAILED", ["ENTRY_POINT_NOT_IN_MODEL"]))
        self.assertEqual(len(out["failures"]), len(MODEL["entry_points"]))


class CommandLine(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(u.run(["threatmodel/check.py", "--as-of", u.AS_OF]).returncode, 0)
        self.assertEqual(u.run(["threatmodel/check.py"]).returncode, 64)
        self.assertEqual(u.run(["threatmodel/check.py", "--as-of", "2027-06-01T00:00:00+02:00"]).returncode, 1)
        rendered = u.run(["threatmodel/check.py", "--render"])
        self.assertEqual(rendered.stdout.decode("utf-8").replace("\r\n", "\n"), tm.render(MODEL))


if __name__ == "__main__":
    unittest.main()
