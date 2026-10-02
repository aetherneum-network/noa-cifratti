# CLAIMS

What the profile in `README.md` says, and what this repository can show for it.

Three states only:

- **demonstrated** by a scenario or a test that anyone can re-run offline;
- **not demonstrated: out of v2.0**: the sentence stays in the profile as written and nothing in
  this pack supports it;
- **awaiting legal review — not touched**: the sentence was neither edited nor removed and nothing
  in this pack is about it.

The profile text below the proof-pack section of the README is the text that existed before this
pack, except for one token changed after the first freeze (see "Changed after the first freeze"
below; `tests/test_docs.py` checks the hash of the text as it is now and the hash of the original).
This pack did not rewrite anything else in it. Since 2.0.3, "the text that existed before this
pack" includes the week-1 review of this repository (pull request #1), made outside this pack and
merged into the pack branch before 2.0.3: pronouns aligned, thesis title, the advisor line of the
diploma. The quotations below follow the profile as it is now.

"Demonstrated" always means: **on generated, synthetic repositories, by an AI agent's own tooling,
as internal consistency** (see `SYNTHETIC.md`). It never means that a real system was assessed.

## Demonstrated

| # | Sentence of the profile | Shown by | What exactly is shown |
|---|---|---|---|
| A1 | "Threat modeling — STRIDE-light for solo-founder context, prioritized by blast radius" | scenario `S05`; `tests/test_threatmodel.py`; `SECURITY.md`; `threatmodel/model.json` | A threat model of one synthetic target, sorted by blast radius, that a program checks against the target's configuration: a new entry point without a threat makes the check fail. The category names follow the STRIDE mnemonic `[TO CONFIRM with legal]`; no conformance is claimed. |
| A2 | "Secrets hygiene — `.env` audits, git history scrubbing, accidental-commit detection" | scenarios `S01`, `S02`, `S03`, `S10`, `S09`; `tests/test_never_clean.py`, `tests/test_history.py`, `tests/test_object_texts.py`, `tests/test_report_safety.py`, `tests/test_rules.py`; `COVERAGE.md` | Detection only: a planted value of a covered class is found in the working tree and anywhere in the object database (removed by a later commit, on another branch, unreachable), with the introducing commit, and, since 2.0.2, in the message and header of every commit and annotated tag (finding T19 of the blind run on `v2.0.1-freeze`). The report never shows the value. Outside coverage the scanner abstains. **Scrubbing is not performed:** the scanner never rewrites a history; it reports where the value entered. |
| A3 | "Incident response — playbook for compromised key, leaked endpoint, rogue container" | scenarios `S06`, `S07`, `S08`; `tests/test_tabletop.py`; `playbooks/` | Three written playbooks and a judge that fails a scripted exercise which skips a step, destroys evidence before preserving it, or transposes an identifier in a hand-off. Exercises are scripted; no live incident, no real system. |
| A4 | "Key management — rotation cadence, revocation playbooks" | scenario `S06`; `playbooks/compromised_key.json` | The revocation procedure only: a rotation that is not followed by revocation and by a check that the old key is rejected fails. **Rotation cadence is not demonstrated:** no schedule is computed or checked. |
| A5 | "If the patch grows the surface, you have lost." | scenario `S04`; `tests/test_config_pycode_surface.py`; `rules/surface.json` | A gate on the difference of exposed surface between two trees: a "fix" that opens a debug route and adds a credential is `BLOCKED`. |
| A6 | "forward-auth config review", "Network segmentation — Docker network design" | `rules/config.json`; scenario `S04`; `tests/test_config_pycode_surface.py`; threats `T03`-`T06` in `SECURITY.md` | Seven configuration rules on two **invented** JSON schemas: an administration route without forward-auth, a forward-auth that trusts client headers, a port published on all interfaces, a service bridging the public and the data network, and others. Real reverse-proxy or container-orchestrator formats are not read. "VPN peer scope" is not demonstrated. |

## Numbers behind the demonstrated claims

Source: `eval/history.json`, runs 6 to 8, run on 2026-09-30 by the author; reference date of the
corpora 2026-10-21T09:40:00+02:00; 200 repositories, 150 transcripts and 120 patch pairs per seed.
Re-run with 2.0.2 on the same day (runs 12 to 14): the result files are byte-identical.
Full results in `eval/results-dev.json`, `eval/results-holdout.json`, `eval/results-stress.json`.

| Seed | Role | Covered secrets found | False reports | `CLEAN` with a covered secret | Surface pairs exact | Transcripts judged as labelled |
|---|---|---|---|---|---|---|
| 20260930 | dev: the rules were written against it | 243 of 243 | 0 | 0 | 120 of 120 | 150 of 150 |
| 20261001 | holdout: second look, not independent | 213 of 213 | 0 | 0 | 120 of 120 | 150 of 150 |
| 20261002 | stress: perturbed, used for diagnosis | 89 of 89 | 0 | 0 | 120 of 120 | 150 of 150 |

These figures are perfect because the generator, the labels and the scanner have **one author**.
They say the three agree with each other. The first dev run did not agree (45 false reports,
precision 0.8438) and the first stress run did not either (6 false reports, 7 repositories called
`CLEAN` with a secret outside coverage): both are kept in `eval/history.json`, runs 1 and 4.

## Not demonstrated: out of v2.0

| Sentence of the profile | Why |
|---|---|
| "security-reviews every new endpoint Lucia Solari ships" / "security-reviews every endpoint Lucia Solari ships" | not demonstrated: out of v2.0. No evidence in this pack; it would need a composition with another pack. |
| "hardens Adrián Volta's infra"; "Infrastructure he hardens"; "whose file-provider topology Noa designed alongside" | not demonstrated: out of v2.0. A cross-pack composition is planned and not built. |
| "Every claim in this profile is reconstructible from public sources" | not demonstrated: out of v2.0. Today only the rows of the table above are reconstructible, and only from this repository. |
| "Specific audit work (key rotations executed, contracts cleared for production, infrastructure hardenings applied) is operational and lives in placement-repository commit history and incident logs"; "Each invocation is recorded in the git history of the placement repository; the trail is auditable end-to-end" | not demonstrated: out of v2.0. This pack contains no operational record of any real system. |
| "OWASP Top 10 review — applied to web (the admin surface) and mobile surfaces" | not demonstrated: out of v2.0. The pack has seven configuration rules and seven Python rules of its own; no mapping to that list is claimed `[TO CONFIRM with legal]`; nothing about mobile. |
| "session management, JWT vs opaque tradeoffs" | not demonstrated: out of v2.0. An opinion, not a checkable capability. |
| "Key management — rotation cadence" | not demonstrated: out of v2.0 (see A4). |
| "git history scrubbing" | not demonstrated: out of v2.0 (see A2: detection, not rewriting). |
| "Network segmentation — ... VPN peer scope" | not demonstrated: out of v2.0 (see A6). |
| Thesis summary: "threshold-based key custody, TOTP forward-auth, VPN-segregated admin plane, file-provider reverse-proxy (no inadvertent public exposure), dual-repo backup with restore drills" | not demonstrated: out of v2.0. The synthetic target of `SECURITY.md` models a private administration plane and a forward-auth gate; key custody thresholds, TOTP, backups and restore drills are not in this pack. |
| "Council Defense (4 peer reviews)", "Canonical profile", "Subagent invocations", "Audit Trail Explorer" links | not demonstrated: out of v2.0. External links; this pack runs offline and did not open them. |
| Tabletops played by a model | not demonstrated: out of v2.0. The hook is disabled (`MODEL.md`). |
| Agreement with third-party scanners | not demonstrated: out of v2.0. No third-party tool was run. |
| A blind evaluation by a different hand | not demonstrated at the freeze: the protocol is written (`eval/BLIND_PROTOCOL.md`), the run has not happened. Since then it was run once, on `v2.0.1-freeze` (2026-09-30, runs 9 to 11), and found a defect (finding T19) fixed in 2.0.2. On `v2.0.2-freeze` the evaluator ran steps 1 and 3 (2026-09-30, seed 20261012, runs 15 and 16); step 2, twenty values hidden by a human hand, has not been run, so the pack is `evidence-pending` (product rule P3). |

## Awaiting legal review — not touched

These sentences mention pre-audits of contracts, or "the platform". This pack left them exactly as
they were: neither edited nor removed. The week-1 review, made outside this pack, changed the
pronoun of one of them. Nothing in this pack concerns them. There is no Solidity, no
contract analysis and no contract tooling in this repository.

| Sentence of the profile | State |
|---|---|
| "Primary Placement: The substrate + platform (smart contracts, auth surfaces)" | awaiting legal review — not touched |
| "Applied case studies: platform auth surface, contracts pre-audit, API key isolation." | awaiting legal review — not touched |
| "Noa pre-audits Davide Ferri's contracts" (Biography, Voice & Personality, Notable Contributions) | awaiting legal review — not touched |
| "Smart contract pre-audit — running industry-standard fuzzing and static analysis before external audit firm" | awaiting legal review — not touched |
| "Contracts he pre-audited — ... (the Solidity Engineer whose work Noa reviews before external audit firm engagement)" | awaiting legal review — not touched |
| "contracts cleared for production" (inside the sentence on specific audit work) | awaiting legal review — not touched |

## Left as written, recorded here

The existing profile text also contains wording that this pack would not use, and that this pack
did not change:

- gendered pronouns for Noa. Up to 2.0.2 they were inconsistent with each other; since the week-1
  review they are consistent. The documents of this pack use none.
- "Synthetic alumnus". The documents of this pack say "synthetic alumni member"; the final word is
  `[TO CONFIRM]`.
- "Faculty Advisor: Claude Sonnet 4.6" and "Faculty advisor: Sonnet 4.6 + security-review skill" in
  the diploma (the skill was added by the week-1 review). This pack
  was written through Claude Opus 5.5 (`MODEL.md`); the advisor line of the profile is a different
  statement and was not verified here.
- "Skills Certificate" and "Diploma" are titles of the University's own fiction. They are not a
  professional certification; the banner at the top of the README says so.

## Changed after the first freeze

One token of the profile text was changed after the tag `v2.0.0-freeze`, in the commit tagged
`v2.0.1-freeze`. It is the only change this pack made to the profile text.

| Where | Before | Now | Why |
|---|---|---|---|
| section "Verifiable Artifacts", the line that names the Charter and the Rubric | the name of a rubric criterion written as an identifier: the words "synthetic" and "transparency" joined by an underscore | the same two words separated by a space: "**Rubric** with the veto rule on synthetic transparency he applies in reverse" | the intake lint of the Council refuses a candidate document that names a rubric criterion by its identifier. Same words, no change of meaning |

- The line is not one of the sentences awaiting legal review: this pack did not touch those. The
  week-1 review, outside this pack, later changed the pronoun of this line and of one of those
  sentences.
- The length of the profile text is the same (one character for one character). `tests/test_docs.py`
  holds two hashes: the text as it is now, and the text before this pack (since 2.0.3, the profile
  after the week-1 review), which it obtains from the current one by putting the underscore back.
- No file that decides a result changed with it: scanner, rules, playbooks, tabletop, threat model,
  corpus generator, scorers and seeds are identical in the two tags (the manifest of `v2.0.1-freeze`
  says so in its header, and a test compared the two tags). Version 2.0.2 is a separate change of
  the scanner and the harness (`CHANGELOG.md`); it does not touch the profile text.

## Known limits

1. **One author for generator, labels and scanner.** Every number is internal consistency on
   synthetic data. The blind protocol is the first step beyond it. It was run once, on
   `v2.0.1-freeze` (runs 9 to 11), and found the defect fixed in 2.0.2 (finding T19,
   `CHANGELOG.md`). On `v2.0.2-freeze` steps 1 and 3 were run (runs 15 and 16); step 2, twenty values
   hidden by a human hand, has not been run.
2. **Narrow coverage.** Seven secret classes in invented formats, two invented configuration
   schemas, seven Python rules. `COVERAGE.md` lists what is outside.
3. **Secrets outside the covered forms can end in `CLEAN`.** On the perturbed corpus, 4 of the 200
   repositories were called `CLEAN` while holding a secret hidden in a form outside coverage
   (run 8; they are named in `eval/results-stress.json`). On the blind perturbed corpus of
   `v2.0.1-freeze`, 5 of 200 (run 11); on the blind perturbed corpus of `v2.0.2-freeze`, 6 of 200
   (run 16). In the hand-planted step (run 10), 3 of the 10 values hidden
   outside the covered forms were missed outright: not found, not sent to review, and not in a
   file listed as not covered (`COVERAGE.md`, Known limits).
4. **Clean repositories sent to review.** A word-like value under a secret-looking key is a suspect
   by rule: 8 of 40 secret-free repositories on dev and 6 of 43 on holdout were `NEEDS_REVIEW`
   instead of `CLEAN` (runs 6 and 7).
5. **The scan of this repository reads the working tree, not its history.** The exclusion is
   visible: the verdict is `EXCEPTIONS_ONLY`, never `CLEAN` (`reports/scan.json`).
6. **Push protection not verified.** The planted values were compared locally with 17 approximate
   patterns of real credential formats; what a hosting platform did with them at the publication of
   2026-10-02 is not recorded here (`SYNTHETIC.md`).
7. **One operating system in the records.** Every run recorded here was on Windows with Python 3.12
   and git 2.51. The identifiers of the generated repositories are pure functions of their bytes and
   should be the same elsewhere. The workflow also runs on Ubuntu (pull request #2), but no
   comparison across operating systems is recorded here `[TO CONFIRM]`.
8. **CI results are not recorded here.** Published on 2026-10-02 as pull request #2; the workflow runs
   on GitHub-hosted runners (Ubuntu and Windows) and its results are on the pull request.
9. **No signed declaration.** Who signs the statement asked by the evidence standard is
   `[TO CONFIRM]`.
10. **The symbolic-link test is skipped** on a machine that cannot create symbolic links, the
    author's included.
