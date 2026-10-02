"""The generated corpus: reproducible, synthetic, and with a gold that holds no planted value."""
import ast
import contextlib
import hashlib
import io
import json
import os
import random
import re
import unittest

from tests import _util as u
from corpus import fakes, generate, gold, patches, reference_plan, repos, tabletops
from corpus.world import COMPANIES

SIZES = (12, 8, 6)
HOLDOUT = json.loads((u.ROOT / "eval" / "seeds.json").read_text(encoding="utf-8"))["author_seeds"]["holdout"]

# Approximations of well-known public credential formats, written from general knowledge and built
# from parts. They are here to show that the inert values of this pack do not take those shapes; they
# are not a statement about what any hosting platform's push protection does.
_B = "BEGIN "
REAL_FORMATS = {
    "cloud access key id": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "code-hosting token": r"\bgh[pousr]_[A-Za-z0-9]{36,}",
    "code-hosting fine-grained token": r"\bgithub_pat_[A-Za-z0-9_]{22,}",
    "code-hosting token (other)": r"\bglpat-[A-Za-z0-9_-]{20,}",
    "chat token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    "payment key": r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
    "web api key": r"\bAIza[0-9A-Za-z_-]{35}",
    "mail api key": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "package registry token": r"\b(?:npm_[A-Za-z0-9]{36}|pypi-AgE[A-Za-z0-9_-]{50,})",
    "model api key": r"\bsk-[A-Za-z0-9_-]{20,}",
    "signed web token": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.",
    "private key armour": "-{5}" + _B + r"(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY",
    "telephony key": r"\bSK[0-9a-f]{32}\b",
    "hosting token": r"\bdop_v1_[a-f0-9]{64}\b",
    "shop token": r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
    "vault token": r"\bhvs\.[A-Za-z0-9_-]{24,}",
    "database uri with password": r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:@/]+:[^\s@/]+@",
}
REAL = {name: re.compile(rx) for name, rx in REAL_FORMATS.items()}


def real_shapes(text: str) -> list[str]:
    return sorted(name for name, rx in REAL.items() if rx.search(text))


def tree_digest(root) -> str:
    h = hashlib.sha256()
    items = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            full = os.path.join(dirpath, name)
            items.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    for rel, full in sorted(items):
        with open(u.ext(full), "rb") as fh:
            h.update(f"{rel}\0{hashlib.sha256(fh.read()).hexdigest()}\n".encode("utf-8"))
    return h.hexdigest()


def make(name: str, seed: int = u.DEV_SEED, perturb: bool = False):
    out = u.tmp(name) / "c"
    lines = generate.generate(seed, out, out / "gold", u.AS_OF, *SIZES, perturb=perturb)
    return out, lines


class Determinism(unittest.TestCase):
    def test_two_folders_hold_the_same_bytes(self):
        a, la = make("corpus-a")
        b, lb = make("corpus-b/a-deeper/folder-with-a-longer-name")
        self.assertEqual(la, lb)
        self.assertEqual(tree_digest(a), tree_digest(b))
        self.assertEqual(len(la), sum(SIZES) + 4)

    def test_another_seed_is_another_corpus_with_the_same_shape(self):
        _, dev = make("corpus-dev")
        _, other = make("corpus-holdout", seed=HOLDOUT)
        self.assertEqual(len(dev), len(other))
        self.assertEqual(set(dev) & set(other), set())

    def test_nothing_is_read_from_the_clock_or_the_machine(self):
        forbidden = {"time", "secrets", "uuid", "getpass", "socket", "platform", "tempfile"}
        for path in sorted((u.ROOT / "corpus").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
            self.assertEqual(sorted(imported & forbidden), [], path.name)
            attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            self.assertEqual(sorted(attrs & {"urandom", "environ", "gethostname", "getlogin", "now", "today", "utcnow"}), [], path.name)

    def test_every_random_draw_comes_from_a_seeded_generator(self):
        for path in u.pack_sources():
            text = path.read_text(encoding="utf-8")
            self.assertEqual(re.findall(r"random\.Random\(\s*\)", text), [], path.name)
            self.assertEqual(re.findall(r"\brandom\.(?:choice|randint|shuffle|sample|randrange)\(", text), [], path.name)


class CommittedCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            cls.rc = generate.main(["--check"])
        cls.line = out.getvalue()
        cls.dir = u.ROOT / "build" / "corpus" / "_check"

    def test_manifest_and_gold_are_what_the_generator_writes(self):
        self.assertEqual(self.rc, 0, self.line)
        cfg = generate.CONFIG
        self.assertIn(f"entries: {cfg['repos'] + cfg['transcripts'] + cfg['patch_pairs'] + 4}; mismatches vs MANIFEST.sha256: 0", self.line)

    def test_every_label_is_confirmed_against_the_generated_bytes(self):
        checked, n_repos, problems = reference_plan.verify(u.DEV_SEED, self.dir, u.ROOT / "corpus" / "gold", False)
        self.assertEqual(problems, [])
        self.assertEqual(n_repos, generate.CONFIG["repos"])
        self.assertGreater(checked, n_repos)

    def test_a_wrong_label_is_not_confirmed(self):
        work = u.tmp("corpus-badgold")
        records = gold.read_jsonl(u.ROOT / "corpus" / "gold" / "labels.jsonl")
        victim = next(i for i, r in enumerate(records) if r["kind"] == "secret" and r["in_head"] and r["technique"] == "plain")
        records[victim] = dict(records[victim], line=records[victim]["line"] + 1)
        gold.write_jsonl(work / "labels.jsonl", records)
        (work / "repos.jsonl").write_bytes((u.ROOT / "corpus" / "gold" / "repos.jsonl").read_bytes())
        _, _, problems = reference_plan.verify(u.DEV_SEED, self.dir, work, False)
        self.assertEqual(len(problems), 1)

    def test_the_gold_holds_no_planted_value(self):
        text = "".join((u.ROOT / "corpus" / "gold" / n).read_text(encoding="utf-8")
                       for n in ("repos.jsonl", "labels.jsonl", "tabletops.jsonl", "patches.jsonl"))
        planted = 0
        for idx in range(1, generate.CONFIG["repos"] + 1):
            for plant in repos.plan_repo(u.DEV_SEED, idx).plants:
                if plant.kind != "secret":
                    continue
                planted += 1
                for line in plant.value.split("\n"):
                    if line and not line.startswith("-----"):
                        self.assertNotIn(line, text)
        self.assertGreater(planted, 200)
        labels = gold.read_jsonl(u.ROOT / "corpus" / "gold" / "labels.jsonl")
        self.assertEqual([r for r in labels if "value" in r or "secret" in r], [])
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{16}", r["fingerprint"]) for r in labels if r["kind"] == "secret"))

    def test_the_mix_of_the_corpus_is_what_the_readme_says(self):
        records = gold.read_jsonl(u.ROOT / "corpus" / "gold" / "repos.jsonl")
        archetypes = {r["archetype"] for r in records}
        self.assertEqual(archetypes, {name for name, _ in repos.ARCHETYPES})
        self.assertTrue(any(r["expected_verdict"] == "CLEAN" for r in records))
        self.assertTrue(any(r["has_boundary_file"] for r in records))
        carriers = {r["carrier"] for r in gold.read_jsonl(u.ROOT / "corpus" / "gold" / "labels.jsonl") if r["kind"] == "secret"}
        self.assertLessEqual({"head", "history_only", "branch_only", "tag_only", "dangling_blob", "unreachable_commit"}, carriers)


class Synthetic(unittest.TestCase):
    def test_inert_values_carry_the_marker_of_their_class(self):
        rng = random.Random("noa-tests/v1/formats/markers")
        for _ in range(200):
            self.assertRegex(fakes.vendor_api_token(rng), r"^nbxsyn_tk_[a-z2-7]{32}$")
            self.assertRegex(fakes.vendor_test_key(rng), r"^nbxsyn_test_[a-z2-7]{24}$")
            self.assertRegex(fakes.vendor_payment_key(rng), r"^QPSYN(?:-[A-Z0-9]{6}){4}$")
            self.assertRegex(fakes.vendor_webhook_secret(rng), r"^hvnsyn_[0-9A-Za-z]{36}$")
            block = fakes.armored_key_block(rng).split("\n")
            self.assertEqual((block[0], block[-1]), (fakes.BLOCK_BEGIN, fakes.BLOCK_END))
            self.assertIn("SYNTHETIC", block[0])
            uri, pw = fakes.connection_uri(rng, u.DOMAIN)
            self.assertRegex(uri, r"^nbxdb://[a-z_]+:[^@]+@db\.officina-brennero\.example:5432/[a-z_]+$")
            self.assertIn(pw, uri)

    def test_no_inert_value_takes_the_shape_of_a_well_known_real_credential(self):
        for cls in fakes.SECRET_CLASSES:
            rng = random.Random(f"noa-tests/v1/formats/{cls}")
            for _ in range(300):
                value = fakes.make(cls, rng, u.DOMAIN)
                self.assertEqual(real_shapes(value), [], cls)
        rng = random.Random("noa-tests/v1/formats/decoys")
        for _ in range(300):
            for fn in (fakes.sha256_hex, fakes.sha1_hex, fakes.uuid4, fakes.public_id, fakes.data_uri, fakes.integrity_hash):
                self.assertEqual(real_shapes(fn(rng)), [], fn.__name__)

    def test_the_detector_of_real_shapes_is_not_blind(self):
        # strings assembled at run time, in the documented shape of each family, with a filler body
        samples = [("cloud access key id", "AKIA" + "Q" * 16), ("code-hosting token", "ghp_" + "a" * 36),
                   ("payment key", "sk_" + "live_" + "a" * 24), ("model api key", "sk-" + "a" * 24),
                   ("private key armour", "-" * 5 + _B + "RSA PRIVATE KEY" + "-" * 5),
                   ("database uri with password", "postgres" + "://user:" + "pw" + "@host/db")]
        for name, text in samples:
            self.assertIn(name, real_shapes(text))

    def test_no_committed_fixture_and_no_generated_file_takes_a_real_shape(self):
        seen = 0
        for base in ("scenarios", "corpus/gold", "rules", "playbooks", "threatmodel"):
            for path in sorted((u.ROOT / base).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    seen += 1
                    self.assertEqual(real_shapes(path.read_bytes().decode("latin-1")), [], path.relative_to(u.ROOT).as_posix())
        for idx in range(1, 61):
            for perturb in (False, True):
                plan = repos.plan_repo(u.DEV_SEED, idx, perturb)
                for commit in plan.commits:
                    for rel, data in commit.snapshot.items():
                        seen += 1
                        self.assertEqual(real_shapes(data.decode("latin-1")), [], f"{plan.name}:{rel}")
        self.assertGreater(seen, 1000)

    def test_every_host_and_mail_address_is_on_a_reserved_example_domain(self):
        self.assertTrue(all(c["domain"].endswith(".example") for c in COMPANIES))
        mail = re.compile(r"[A-Za-z0-9._+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
        url = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^\s/@\"']*@)?([A-Za-z0-9.-]+)")
        allowed_hosts = {"git-lfs.github.com"}        # the constant first line of an LFS pointer file (a format, not a system)
        hosts: set[str] = set()

        def collect(text: str) -> None:
            hosts.update(m.group(1).lower() for m in mail.finditer(text))
            hosts.update(m.group(1).lower().rstrip(".") for m in url.finditer(text))

        for idx in range(1, 61):
            plan = repos.plan_repo(u.DEV_SEED, idx)
            for commit in plan.commits:
                for data in commit.snapshot.values():
                    collect(data.decode("latin-1"))
        for idx in range(1, 31):
            events, _ = tabletops.build(u.DEV_SEED, idx, u.AS_OF)
            collect(json.dumps(events))
            before, after, _ = patches.build(u.DEV_SEED, idx)
            for data in list(before.values()) + list(after.values()):
                collect(data.decode("latin-1"))
        for path in sorted((u.ROOT / "scenarios").rglob("*")):
            if path.is_file() and "input" in path.parts:
                collect(path.read_bytes().decode("latin-1"))
        bad = sorted(h for h in hosts if "." in h and not h.endswith(".example") and h not in allowed_hosts
                     and not re.fullmatch(r"(?:10|127)\.\d+\.\d+\.\d+|0\.0\.0\.0", h))
        self.assertEqual(bad, [])
        self.assertGreater(len(hosts), 5)

    def test_authors_are_role_accounts_of_fictitious_companies(self):
        for company in COMPANIES:
            for name, local in company["team"]:
                self.assertRegex(name, r"^[A-Z][a-z]+ (?:Dev [A-Z]|Ops)$")
                self.assertRegex(local, r"^(?:dev-[a-z]|ops)$")


if __name__ == "__main__":
    unittest.main()
