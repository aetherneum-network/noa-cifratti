"""The documents: present, consistent with the code, and honest about what they are."""
import hashlib
import json
import os
import re
import unittest
from pathlib import Path

from tests import _util as u

DOCS = ("SYNTHETIC.md", "CLAIMS.md", "COVERAGE.md", "MODEL.md", "SECURITY.md", "DEPENDENCIES.md", "CHANGELOG.md")
REQUIRED = DOCS + ("README.md", "LICENSE", ".github/workflows/ci.yml", "eval/seeds.json", "reports/scan.json", "reports/scenarios.json")
POST_FREEZE = ("eval/BLIND_PROTOCOL.md", "MANIFEST.sha256", "eval/history.json")     # written after the freeze tag

# The profile as it was before this pack (line endings normalised to LF): its length and its SHA-256.
# Since 2.0.3 "before this pack" is README.md of commit 7ae2d66: the repository's main profile plus its week-1
# review (pronouns aligned to he/him, thesis title, faculty-advisor line), pull request #1 of this repository.
# That review was made outside this pack and merged into the pack branch in commit 54c3250. Pins up to 2.0.2,
# for the profile of commit 7dca178: 8743 bytes, original 19b543c8239f5ee6908247c4388b12f7692a3d99175a2f0a2c0a849e0854e28d,
# with the token 9babecb68e822dfc23c5109ad698bd900d97a3c6fef487d18d6fb5e8521d4a5c.
PROFILE_BYTES = 8805
PROFILE_SHA256_ORIGINAL = "e301775aadf6e737ee93a06ce418dafe52b06524951c7d0a37c75e65c5b5c679"
# One token of it was changed by this pack after the first freeze (CLAIMS.md, "Changed after the first freeze"):
# in one line the underscore between two words became a space. Same length; this is the hash of the text as it
# is now (week-1 review plus that token).
PROFILE_SHA256 = "546f749d7ca146a40859e775c8a2ff1ba9a8b50d9786c4fc29a91701e9cffbed"
CHANGED_NOW = b"the veto rule on synthetic transparency he applies in reverse"      # "she" before the week-1 review
CHANGED_WAS = CHANGED_NOW.replace(b"synthetic transparency", b"_".join([b"synthetic", b"transparency"]))

PRONOUN = re.compile(r"\b(?:he|she|him|his|her|hers|himself|herself)\b", re.I)
QUOTED = re.compile(r'"[^"\n]*"')
TOP = ("noascan", "rules", "corpus", "threatmodel", "playbooks", "tabletop", "scenarios", "eval", "tools", "tests", "reports", ".github")
SKIP_DIRS = {".git", "build", "__pycache__"}
TEXT_SUFFIXES = {".md", ".py", ".json", ".jsonl", ".yml", ".yaml", ".txt", ".env", ".sha256", ".sh", ".ini", ".toml", ".cfg", ""}


def read(name):
    return (u.ROOT / name).read_bytes().replace(b"\r\n", b"\n").decode("utf-8")


def readme_parts():
    data = (u.ROOT / "README.md").read_bytes().replace(b"\r\n", b"\n")
    return data[:-PROFILE_BYTES], data[-PROFILE_BYTES:]


def own_texts():
    """The texts written by this pack: the documents and the new section of the README (not the old profile)."""
    out = {name: read(name) for name in DOCS}
    out["README.md (proof-pack section)"] = readme_parts()[0].decode("utf-8")
    for name in POST_FREEZE[:1]:
        if (u.ROOT / name).is_file():
            out[name] = read(name)
    return out


def text_files():
    for folder, dirs, names in os.walk(u.ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            path = Path(folder) / name
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                yield path.relative_to(u.ROOT).as_posix(), path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                continue                                    # fixtures that are not UTF-8 on purpose


class Present(unittest.TestCase):
    def test_required_files_exist(self):
        for name in REQUIRED:
            with self.subTest(file=name):
                self.assertTrue((u.ROOT / name).is_file())

    def test_every_path_a_document_names_exists(self):
        for name, text in own_texts().items():
            for ref in sorted(set(re.findall(r"`([A-Za-z0-9_.][A-Za-z0-9_./-]*)`", text))):
                first = ref.split("/")[0]
                is_path = ("/" in ref and first in TOP) or (ref.endswith((".md", ".sha256")) and "/" not in ref)
                if not is_path or ref in POST_FREEZE or ref == "run.md":          # run.md: one per scenario folder
                    continue
                with self.subTest(doc=name, ref=ref):
                    self.assertTrue((u.ROOT / ref.rstrip("/")).exists(), f"{name} names {ref}, which does not exist")

    def test_every_scenario_a_document_names_exists(self):
        for name, text in own_texts().items():
            for sid in sorted(set(re.findall(r"`(S\d\d)`", text))):
                with self.subTest(doc=name, scenario=sid):
                    self.assertTrue((u.ROOT / "scenarios" / sid / "scenario.json").is_file())

    def test_every_threat_a_document_names_is_in_the_model(self):
        ids = {t["id"] for t in json.loads(read("threatmodel/model.json"))["threats"]}
        for name, text in own_texts().items():
            for tid in set(re.findall(r"`(T\d\d)`", text)):
                self.assertIn(tid, ids, name)


class Readme(unittest.TestCase):
    def test_the_profile_below_the_new_section_is_the_old_one_except_for_one_token(self):
        head, profile = readme_parts()
        self.assertEqual(hashlib.sha256(profile).hexdigest(), PROFILE_SHA256)
        self.assertTrue(profile.startswith(b"# Noa Cifratti\n"))
        self.assertTrue(head.endswith(b"\n---\n\n"))
        self.assertEqual(profile.count(CHANGED_NOW), 1)
        original = profile.replace(CHANGED_NOW, CHANGED_WAS)           # put the underscore back: the text before this pack
        self.assertEqual(len(original), PROFILE_BYTES)
        self.assertEqual(hashlib.sha256(original).hexdigest(), PROFILE_SHA256_ORIGINAL)

    def test_the_identifier_the_intake_lint_refused_is_in_no_text_of_the_repository(self):
        identifier = CHANGED_WAS.split(b" on ", 1)[1].split(b" ", 1)[0].decode("ascii")
        self.assertEqual((len(identifier), identifier.count("_")), (22, 1))
        for rel, text in text_files():
            with self.subTest(file=rel):
                self.assertNotIn(identifier, text)
        for name in ("CLAIMS.md", "CHANGELOG.md"):                     # the change is recorded, in plain words
            self.assertIn("Changed after the first freeze", read(name))

    def test_it_opens_with_the_synthetic_banner(self):
        head = readme_parts()[0].decode("utf-8")
        first = head.split("\n", 1)[0]
        self.assertTrue(first.startswith("> **SYNTHETIC - Noa Cifratti is a synthetic alumni member (an AI agent)"))
        for phrase in ("not a person", "not a certified auditor", "not a penetration tester", "fictitious",
                       "not a security certification", "nothing here is an assessment of any real system"):
            self.assertIn(phrase, first)

    def test_the_new_section_says_what_how_how_much_and_what_not(self):
        head = readme_parts()[0].decode("utf-8")
        for title in ("## What is demonstrated", "## Re-run it", "## The numbers", "## Reproducibility", "## What is NOT demonstrated"):
            self.assertIn(title, head)
        block = head.split("## Re-run it", 1)[1].split("```")[1]
        commands = [ln for ln in block.strip().splitlines() if ln.startswith("python ")]
        self.assertTrue(1 <= len(commands) < 5)
        self.assertIn("internal consistency on synthetic data", head)
        self.assertIn("not yet run", head)

    def test_the_numbers_are_the_recorded_ones_with_seed_and_date(self):
        head = readme_parts()[0].decode("utf-8")
        seeds = json.loads(read("eval/seeds.json"))["author_seeds"]
        for suite, seed in seeds.items():
            res = json.loads(read(f"eval/results-{suite}.json"))
            s = res["secrets_by_class"]["ALL"]
            row = next(ln for ln in head.splitlines() if ln.startswith(f"| {seed} |"))
            cells = [c.strip() for c in row.strip("|").split("|")]
            self.assertEqual(cells[2], f"{s['tp']} of {s['tp'] + s['fn']}")
            self.assertEqual(cells[3], str(s["fp"]))
            self.assertEqual(cells[4], str(res["never_event_clean_with_covered_secret"]["count"]))
            self.assertEqual(cells[5], f"{res['surface']['items_exact']} of {res['surface']['pairs']}")
            self.assertEqual(cells[6], f"{res['tabletop']['violations_exact']} of {res['tabletop']['transcripts']}")
            self.assertIn(row, read("CLAIMS.md").replace("dev: the rules were written against it", "dev")
                          .replace("holdout: second look, not independent", "holdout (second look)")
                          .replace("stress: perturbed, used for diagnosis", "stress (perturbed; used for diagnosis)"))
        self.assertIn(json.loads(read("corpus/config.json"))["as_of"], head)
        dev = json.loads(read("eval/results-dev.json"))
        conf = dev["verdict_confusion_expected_to_got"]["CLEAN"]
        self.assertIn(f"{dev['clean_repos_not_called_clean']['count']} of {sum(conf.values())} secret-free", head)
        stress = json.loads(read("eval/results-stress.json"))
        self.assertIn(f"and {stress['clean_with_only_out_of_coverage_secret']['count']} perturbed repositories", head)


class Wording(unittest.TestCase):
    def test_no_gendered_pronoun_in_what_this_pack_wrote(self):
        for name, text in own_texts().items():
            if name == "CLAIMS.md":
                text = QUOTED.sub('""', text)             # sentences quoted from the old profile are not ours
            with self.subTest(doc=name):
                self.assertEqual(PRONOUN.findall(text), [])

    def test_the_author_is_declared_as_an_agent_and_never_as_a_professional(self):
        for name in ("SYNTHETIC.md", "SECURITY.md", "MODEL.md"):
            self.assertRegex(read(name), r"AI agent")
        for name, text in own_texts().items():
            flat = " ".join(text.split())
            for claim in ("is an auditor", "is a penetration tester", "certified by", "is a licensed", "audited by Noa"):
                self.assertNotIn(claim, flat, name)

    def test_the_model_file_names_the_author_model_and_the_only_two_admitted(self):
        text = read("MODEL.md")
        for phrase in ("synthetic AI agent", "Claude Opus 5.5", "No model is called", "disabled by default",
                       "`claude-opus-5-5`", "`claude-fable-5-1`"):
            self.assertIn(phrase, text)
        self.assertEqual(sorted(set(re.findall(r"claude-[a-z]+-\d[\d-]*\d", text))), ["claude-fable-5-1", "claude-opus-5-5"])
        from tabletop import model_roles
        self.assertEqual(sorted(model_roles.ALLOWED_MODELS), ["claude-fable-5-1", "claude-opus-5-5"])

    def test_a_standard_is_never_named_without_the_legal_mark(self):
        for name, text in own_texts().items():
            for para in re.split(r"\n\s*\n|\n(?=\|)", text):
                if re.search(r"OWASP|STRIDE|\bCWE\b|\bNIST\b|\bISO 27", para):
                    with self.subTest(doc=name, paragraph=para[:60]):
                        self.assertIn("[TO CONFIRM with legal]", para)
        for rule_file in ("config", "pycode"):
            self.assertIn("[TO CONFIRM with legal]", json.loads(read(f"rules/{rule_file}.json"))["reference"])

    def test_claims_uses_the_three_states_and_lists_its_limits(self):
        text = read("CLAIMS.md")
        for phrase in ("## Demonstrated", "## Not demonstrated: out of v2.0", "## Awaiting legal review — not touched",
                       "## Known limits", "not demonstrated: out of v2.0", "awaiting legal review — not touched",
                       "internal consistency"):
            self.assertIn(phrase, text)
        for claim in ("A1", "A2", "A3", "A4", "A5", "A6"):
            self.assertRegex(text, rf"\| {claim} \|.*`S\d\d`")
        legal = text.split("## Awaiting legal review — not touched", 1)[1].split("\n## ", 1)[0]
        profile = readme_parts()[1].decode("utf-8")
        rows = [ln for ln in legal.splitlines() if ln.startswith('| "')]
        self.assertGreaterEqual(len(rows), 5)
        for row in rows:
            self.assertTrue(row.rstrip().endswith("| awaiting legal review — not touched |"))
        for sentence in ("Applied case studies: platform auth surface, contracts pre-audit, API key isolation.",
                         "Noa pre-audits Davide Ferri's contracts", "Contracts he pre-audited",
                         "running industry-standard fuzzing and static analysis before external audit firm"):
            self.assertIn(sentence, profile)                # still there, not touched by this pack (week-1 review: pronoun only)

    def test_the_stdlib_only_statement_and_the_offline_workflow(self):
        self.assertIn("standard library only", read("DEPENDENCIES.md"))
        ci = read(".github/workflows/ci.yml")
        for needed in ("contents: read", "python -m unittest discover -s tests -t .", "python scenarios/run_all.py",
                       "python tools/rebuild.py", 'python-version: "3.12"'):
            self.assertIn(needed, ci)
        for forbidden in ("pip install", "secrets.", "npm ", "curl ", "docker "):
            self.assertNotIn(forbidden, ci)


class NothingInternal(unittest.TestCase):
    PATTERNS = [r"\b[A-Za-z]:\\\\?[A-Za-z]", r"\b[A-Z]:/[A-Za-z]", r"/Users/", r"/home/[a-z]", r"/opt/", r"AppData", r"\\\\\?\\\\"]

    def test_no_path_of_a_machine_in_the_repository(self):
        rx = re.compile("|".join(self.PATTERNS))
        long_path_code = {"tests/_util.py", "noascan/scan.py", "corpus/generate.py", "corpus/gitwrite.py", "tools/rebuild.py",
                          "scenarios/_common.py"}                    # the long-path prefix of Windows, as code
        for rel, text in text_files():
            if rel == "tests/test_docs.py":
                continue                                             # the patterns themselves
            hits = [m.group(0) for m in rx.finditer(text)]
            if rel in long_path_code:
                hits = [h for h in hits if "?" not in h]
            with self.subTest(file=rel):
                self.assertEqual(hits, [])

    def test_every_host_in_the_documents_is_on_a_reserved_domain(self):
        for name, text in own_texts().items():
            for host in set(re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|org|net|io|app|dev|example)\b", text)):
                with self.subTest(doc=name, host=host):
                    self.assertTrue(host.endswith(".example") or host == "lunaria-carto.example", host)

    def test_reports_are_about_this_repository_by_name_only(self):
        for name in ("reports/scan.json", "reports/scenarios.json"):
            text = read(name)
            self.assertNotIn(str(u.ROOT), text)
            self.assertNotIn(u.ROOT.as_posix(), text)


if __name__ == "__main__":
    unittest.main()
