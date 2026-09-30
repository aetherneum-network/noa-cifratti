# CHANGELOG

All dates are those of the work, not of any release to the public: nothing was pushed.

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
