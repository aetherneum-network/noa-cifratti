# CHANGELOG

All dates are those of the work. Published on 2026-10-02 as pull request #2 of this repository; the workflow runs on GitHub-hosted runners and its results are on the pull request.

## 2.0.3 — 2026-10-02 (tag `v2.0.3-freeze`)

Documentation and documentation tests only. No file that decides a result changed: `noascan/`,
`rules/`, `playbooks/`, `tabletop/`, `threatmodel/`, `corpus/`, `eval/score.py`, `eval/manual.py`
and `eval/seeds.json` are identical to `v2.0.2-freeze`, which stays the tag the blind harness checks
(`eval/BLIND_PROTOCOL.md` is unchanged). The version string of the scanner stays 2.0.2, because it
lives in a frozen file. `eval/history.json` and the result files are unchanged. In the workflow file
only a comment changed.

Why: the week-1 review of the profile (pull request #1 of this repository, made outside this pack)
was merged into the pack branch after 2.0.2. It changed the profile below the proof-pack section
(pronouns aligned, thesis title, advisor line of the diploma), so three documentation tests failed:
the hash pins of the profile, one quotation in `CLAIMS.md`, and the manifest check. The first run of
the workflow on pull request #2, published on 2026-10-02 after that merge, failed on these three
documentation and freeze tests; this release is the fix. Separately, the
proof-pack section of the README still said that the blind run on 2.0.2 had not been run, while
`eval/history.json` records steps 1 and 3 of it (runs 15 and 16).

### Changed

- `tests/test_docs.py`: "the text before this pack" is now the profile after the week-1 review; new
  length and hashes, with a comment that keeps the pins up to 2.0.2 and gives the reason. One quoted
  sentence follows the new pronoun of the profile.
- `README.md`, proof-pack section only: names the week-1 review; states what runs 15 and 16 record
  (tag, seed, dates, sizes, abstentions, never-events) and what is still not done: step 2 of the
  blind protocol, twenty values hidden by a human hand, is not yet run; no one is certified; the
  status is `evidence-pending` (product rule P3).
- `CLAIMS.md`: quotations follow the profile as it is now; the line on pronouns in "Left as
  written" records that they are consistent since the review; the row on the blind evaluation and
  known limits 1 and 3 record runs 15 and 16.
- Statements written before the publication, that nothing was pushed or that the workflow had never
  run remotely: the top line of this file, `CLAIMS.md` (known limits 6 to 8), `DEPENDENCIES.md`,
  `SYNTHETIC.md`, the proof-pack section of `README.md` and a comment in `.github/workflows/ci.yml`.
  They now say that the pack was published on 2026-10-02 as pull request #2, that the workflow runs on
  GitHub-hosted runners and that its results are on the pull request; no result is copied here.
- `MANIFEST.sha256`: regenerated with `tools/manifest.py` for the tag `v2.0.3-freeze`.

## 2.0.2 — 2026-09-30 (tag `v2.0.2-freeze`)

A code change: the scanner, the harness and the seeds differ from `v2.0.1-freeze`, so this is a
new code freeze and the blind harness now checks `v2.0.2-freeze` itself.

Source: finding T19 of the evaluation of 2026-09-30, from the blind run of that day on
`v2.0.1-freeze` (seed 20261011, runner "evaluator (Claude Opus 5.5)", `eval/history.json` runs 9
to 11). In the hand-planted step the evaluator hid one value only in the message of the last
commit (value M20, form "other"). The scanner did not read commit or tag messages, and neither
`COVERAGE.md` nor any report said so.

### Fixed

- **Commit and annotated-tag texts are read (T19).** Up to 2.0.1, `noascan/history.py` kept, of a
  commit object, its tree, parents, author and date, and, of a tag object, the line naming its
  target; the rest of the object (the message, the committer and tagger lines, an embedded tag) was
  dropped, and `noascan/scan.py` scanned only blobs and paths. Now `history.read()` keeps the
  header and the message of every commit and tag object in the database, reachable or not, and
  `scan()` reads each part with the same classes, forms and coverage decision as a file with no
  path. A finding there carries `object`, `object_type` and `part` (`header` or `message`) and no
  value; a part that is not UTF-8 is `NOT_COVERED`. The scope of every scan report gains
  `tags_read` and `object_texts`.
- **`COVERAGE.md` declares the rest of git's metadata** one by one: notes, author fields, stashes,
  unreachable objects, reflog and the other files under `.git`, the index, objects not in the local
  database, and what lies outside the repository. Known limits name the three values of the blind
  run that are outside the covered forms (M13, M14, M20). M20 itself is still missed in 2.0.2: it is
  a bare word with no key, which is not a covered form in a file either.

### Measured

- `tests/test_object_texts.py`, 15 new tests: every covered class only in a commit message, only in
  a tag message; unreachable commit and tag; author, committer and tagger fields; a tag embedded in
  a merge commit; a stash; a note; the reflog; a non-UTF-8 message; the environment-file form of
  the assignment rule in a message; an encoded value in a message; and three negative controls
  (messages, tags and identities with no value; a signed commit and a signed tag; a tree-only scan,
  which says it did not read them). Every test also checks that no value is printed. On the code of
  `v2.0.1-freeze` 13 of the 15 fail: 10 because the value is not found or not located, the 3
  controls only because the new scope keys are missing. The two that pass there (a note, the
  reflog) were already read, as a blob and as a file.
- `tests/test_report_safety.py`: the token its test writes in a commit subject and author name is
  now also found there (two findings located by object, no value in the report).
- Suite: 242 tests at `v2.0.1-freeze`, 259 now. Scenarios: 10 of 10; the expected outputs changed in
  the tool version and the two new scope keys only, no finding changed. The three author seeds,
  re-run with 2.0.2 (runs 12 to 14): result files byte-identical to runs 6 to 8. Rebuild outputs
  sha256 unchanged (`README.md`, "Reproducibility").

### Changed with it

- `eval/score.py`: `FREEZE_TAG` is `v2.0.2-freeze`; `eval/manual.py` defines "plain" to include a
  commit or tag message or header.
- `eval/seeds.json`: new list `seen_seeds` with 20261011, the seed of the blind run whose results were
  read to make this fix; `eval/score.py` and `eval/manual.py` refuse it like an author seed.
- `tools/manifest.py`: when the tag written is the harness's own tag, the header says so instead of
  naming a commit (the manifest travels inside that commit). `tests/test_freeze.py` follows, and
  accepts that at the tagged commit the blind protocol still names the previous tag, as long as the
  protocol says it is not yet valid.
- `noascan/__init__.py`: version 2.0.2 (it had stayed 2.0.0 in 2.0.1).
- `CLAIMS.md`, `README.md` (proof-pack section), `COVERAGE.md`, `eval/BLIND_PROTOCOL.md`.

### Superseded, not removed

- "Documentation only", the first words of 2.0.1 below, was wrong. The same entry lists changes to
  `tools/manifest.py`, `tests/test_freeze.py` and `tests/test_docs.py`, which are code, and
  `git diff --stat v2.0.0-freeze v2.0.1-freeze` shows them. What was true, and checked, is
  narrower: no frozen path changed. The blind protocol written for `v2.0.1-freeze` repeated the
  error; its version for 2.0.2 records it.

## 2.0.1 — 2026-09-30 (tag `v2.0.1-freeze`)

Documentation only. No file of the scanner, the rules, the playbooks, the tabletop, the threat
model, the corpus generator, the scorers or the seeds differs from `v2.0.0-freeze`; the blind
harness still compares those paths with `v2.0.0-freeze`, which stays where it was.

### Changed after the first freeze

- `README.md`, profile text: **one token**. In the section "Verifiable Artifacts", the line that
  names the Charter and the Rubric wrote the name of a rubric criterion as an identifier, with an
  underscore between the words "synthetic" and "transparency"; the underscore is now a space.
  Reason: the intake lint of the Council refuses a candidate document that names a rubric
  criterion by its identifier. No change of meaning, same length. Nothing else in the profile text
  changed, and the sentences awaiting legal review are untouched (see `CLAIMS.md`).
- `README.md`, proof-pack section: the sentence that called the profile unchanged "byte for byte"
  now names the exception.
- `CLAIMS.md`: the change is recorded in a section of its own.
- `tests/test_docs.py`: expects the hash of the profile text as it is now, and checks that putting
  the underscore back gives the hash of the original text; checks that the identifier is in no
  text of the repository.
- `MANIFEST.sha256`: regenerated. It now travels inside the tagged commit, so it names the tag
  and not the commit (a commit cannot contain its own id) and lists every file of that commit
  except itself, the blind protocol and the measurement history. `tools/manifest.py` writes it from
  a tree, refuses to write it if a frozen path differs from `v2.0.0-freeze`, and `--check` also
  compares the list with the tagged commit when the tag is in the clone. `tests/test_freeze.py`
  follows.

### Superseded, not removed

- "kept byte for byte", under "Not changed" of 2.0.0 below: true at `v2.0.0-freeze`; since this
  version the exception above applies.
- The manifest of 2.0.0 (195 files of the commit tagged `v2.0.0-freeze`) is in the history of
  this repository, in the commit that follows that tag.

## 2.0.0 — 2026-09-30 (tag `v2.0.0-freeze`)

First proof pack. Before it, this repository held a profile (`README.md`), a picture and a licence.

### Added

- `noascan/`: secret scanner on working tree and git object database (read-only), configuration
  and Python review, surface gate for patches, reports with fingerprints only, gate with five
  verdicts (`BLOCKED`, `NEEDS_REVIEW`, `NOT_COVERED`, `EXCEPTIONS_ONLY`, `CLEAN`).
- `rules/`: every decision lives in an ordered rule file, first match wins, exceptions on top;
  each rule carries its own examples, run by `python -m noascan rules-test`.
- `corpus/`: generator of synthetic repositories, transcripts and patch pairs from a seed, with a
  pure-Python git object writer; labels from the seeding plan, re-read by `reference_plan.py`.
- `threatmodel/`: a threat model of one synthetic target and the program that checks it.
- `playbooks/`, `tabletop/`: three incident playbooks, a scripted runner with an append-only
  hash-chained log, and a judge.
- `scenarios/`: ten scenarios `S01`-`S10`, each with `scenario.json`, `input/`, `expected/`,
  a checker and `run.md`; `scenarios/run_all.py`.
- `eval/`: scoring harness, author seeds, history of every measurement, blind protocol.
- `tools/`: double rebuild, scan of this repository, freeze manifest.
- `tests/`: offline test suite (sockets blocked).
- Documents: `SYNTHETIC.md`, `CLAIMS.md`, `COVERAGE.md`, `MODEL.md`, `SECURITY.md`,
  `DEPENDENCIES.md`, this file; a proof-pack section at the top of `README.md`; an offline CI
  workflow.

### Not changed

- The profile text of `README.md`: kept byte for byte below the new section (see `CLAIMS.md`).
- `avatar.jpg`, `LICENSE`.

### Defects found while building, and what was done

Kept here because a proof pack that only shows its final state hides how it got there.

| Found by | Defect | Fix |
|---|---|---|
| first dev measurement (run 1) | 45 false reports: labels under secret-looking keys reported as passwords (precision 0.8438) | two ordered suspect rules placed above the assignment rules: a word-like value goes to review, neither blocked nor cleared |
| first stress measurement (run 4) | 6 reports counted as false and 7 repositories called `CLEAN` with a secret outside coverage; percent-encoded and reversed values were invisible | two decode rules (percent-encoding, reversed text) as suspects; in the harness, a finding at the path of an out-of-coverage plant of the same class is now counted as "found in other form" and no longer as a false report. After both changes (run 5): 0 false reports, 4 such repositories |
| scenario `S03` (negative), at its first run | a planted value used as a file name produced no finding, and the path was shown unmasked in the report | paths are scanned like content; a label derived from content (a path, a commit message, an author name) is shown as `[masked:<fingerprint>]` |
| writing the command-line tests | `scan` on a directory that does not exist, or on a file, answered `CLEAN` with exit code 0; the surface gate passed when the "after" tree was missing; any text was accepted as reference date | a target that is not a directory is an error (exit 64); the reference date must be ISO 8601 |
| hardening the never-event, after run 2 | a scan limited to the working tree of a repository with history could be `CLEAN` | a history that exists and was not read is a gap (`history_not_read`): the verdict is `NOT_COVERED` |
| scan of this repository | a test source and a sentence of `COVERAGE.md` looked like an assigned password and a URI with a password | the texts were reworded; no exception was added for them |

Each fix changed a rule or the code that applies it; no expected output was edited by hand.

### Known limits

See `CLAIMS.md` ("Known limits") and `COVERAGE.md`.
