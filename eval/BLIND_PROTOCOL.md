# BLIND PROTOCOL

> Synthetic data only. This protocol measures the pack on a corpus its author has never seen. It
> still measures a generator and a scanner written by the same author: it is a step beyond the
> author's own seeds, not a validation on real systems.

**State at the time of writing: not run.** This file was written by the author after the tag
`v2.0.0-freeze` and pointed to `v2.0.1-freeze` in the commit that follows that second tag. No blind
seed has been generated or looked at by the author.

## What is frozen

The tag `v2.0.1-freeze` (commit `335b6875ad1498323fe1a5441a1d2052c80d11ea`). It differs from the
first freeze, `v2.0.0-freeze` (commit `3be83ef9e41d293b2e2744b0077768b148f386a1`), in documentation
only: one token of the profile text and the files that record it (`CHANGELOG.md`, 2.0.1).

A blind run is valid only if these paths are identical to the tag: `noascan`, `rules`,
`playbooks`, `tabletop`, `threatmodel`, `corpus`, `eval/score.py`, `eval/manual.py`,
`eval/seeds.json`. They are identical in the two tags. The harness checks it by itself and refuses
to run otherwise (exit code 64, "not a blind run"). Its code names the first tag, `v2.0.0-freeze`:
giving it the new name would have changed a scoring file, which a documentation-only freeze must
not do. So both tags must be in the clone, the comparison is made with `v2.0.0-freeze`, and a
recorded run carries the commit of `v2.0.0-freeze` as `freeze_commit`. Step 0 below shows that
this is the same code as `v2.0.1-freeze`.

This file is not part of either tag: the clone is at the head of the branch, one commit after
`v2.0.1-freeze`, and that commit changes this file only.

## Who runs it

A different hand than the author: a session with the other model of the fleet
(`claude-fable-5-1`) or a human reviewer. The name goes in `--runner` and ends up in
`eval/history.json`. The runner may read this file, `COVERAGE.md` and `SYNTHETIC.md`; the runner
must not change any frozen path.

## What the author has already seen

Seeds `20260930` (dev), `20261001` (holdout) and `20261002` (stress). The harness refuses them for
a blind run. Any other integer is a valid blind seed. The runner chooses it, writes it down before
the first command, and does not ask the author.

## The commands

Run **once**, from the root of a clean clone, with Python 3.12 and `git`; nothing to install, no
network. `N` is the seed, `NAME` the runner, `ISO` the date and time of the run read from a clock
by the runner (for example `2026-10-05T10:00:00+02:00`): the programs never read the clock.

```
# 0. the code is the frozen one
git rev-parse "v2.0.1-freeze^{commit}"          # must print 335b6875ad1498323fe1a5441a1d2052c80d11ea
git rev-parse "v2.0.0-freeze^{commit}"          # must print 3be83ef9e41d293b2e2744b0077768b148f386a1
git diff --name-only v2.0.0-freeze v2.0.1-freeze -- noascan rules playbooks tabletop threatmodel corpus eval/score.py eval/manual.py eval/seeds.json   # must print nothing
git diff --name-only v2.0.1-freeze               # must print eval/BLIND_PROTOCOL.md and nothing else
git status --short                               # must print nothing
python tools/manifest.py --check                 # must say "0 differ" and "is the list of the tagged commit"

# 1. generated corpus, as planted
python eval/score.py --suite blind --seed N --runner "NAME" --json eval/results-blind-N.json --record --run-date ISO

# 2. twenty values hidden by hand
python eval/manual.py values --seed N --runner "NAME"
#    copy one repository of build/corpus/blind-N/repos/ to build/blind-manual-N/repo, hide the printed
#    values in it by hand (any technique), and fill build/blind-manual-N/hidden.json:
#    for each value hidden=true, form="plain" or "other", where="...". "plain" is defined below.
python eval/manual.py score --seed N --runner "NAME" --repo build/blind-manual-N/repo --hidden build/blind-manual-N/hidden.json --json eval/results-blind-manual-N.json --record --run-date ISO

# 3. generated corpus, perturbed (values split, encoded, reversed, in unseen file formats)
python eval/score.py --suite blind --seed N --perturb --runner "NAME" --json eval/results-blind-N-perturbed.json --record --run-date ISO
```

Step 3 regenerates `build/corpus/blind-N`; this is why the copy of step 2 is taken before it.

`--record` appends the run to `eval/history.json`. Earlier runs are never edited or removed; a run
that goes badly stays in the history like the author's bad first runs.

### "plain" and "other" in step 2

A hidden value is `plain` when it sits contiguous and unmodified in a text file (UTF-8, under
1 MiB) of the working tree or of the git history, in the form `COVERAGE.md` declares: a token
anywhere on a line; a key block with its begin line, body and end line in order; a connection URI
as printed; a password assigned with `=` or `:` to a key whose name contains `password`, `secret`,
`token`, `api_key` or `private_key` (quoted anywhere, unquoted only in environment-like files).
Everything else (split, encoded, reversed, inside an archive, under an unrelated key) is `other`:
outside the promise, and counted apart. The runner is encouraged to hide at least half of the
values as `other`, as cleverly as possible: that is where the pack is expected to be weakest.

## How to read the result

| Number | Where | Reading |
|---|---|---|
| `never_event` | every run | a `CLEAN` verdict on a repository with a covered (`plain`) value. **Must be 0**; one occurrence fails the pack |
| `secret_values_in_reports` | every run | a value printed in clear in a report. **Must be 0**; one occurrence fails the pack |
| secrets precision and recall, per class | steps 1 and 3 | reported as measured. The pass mark is `[TO CONFIRM]`: the evidence standard does not yet fix a threshold |
| `plain_found` of `plain` | step 2 | expected equal; any miss is a defect inside declared coverage, to be reported with the `where` of the form |
| `other_found_as_secret`, `clean_with_only_out_of_coverage_secret` | steps 2 and 3 | not a pass or fail: the measure of what lies outside coverage |
| surface and tabletop agreement | steps 1 and 3 | reported as measured; the labels come from the same author, so disagreement would mean a defect, agreement proves little |

Exit codes: 0 when both must-be-zero numbers are zero (and, in step 2, every `plain` value was
found); 1 otherwise; 64 when the run was refused.

## Afterwards

- Commit `eval/history.json` and the three result files, locally, with the runner as author.
- Do not change a rule in response to the blind run under the same tag. A fix needs a new version,
  a new freeze tag and a new seed; the seed used here then becomes a seed "already seen" and must
  be added to `eval/seeds.json`.
- If the run could not be completed, say so in `--note` of a recorded run or in the commit message:
  a failed run is a result.

## What the author did and did not do

- Did: generate and inspect the three seeds above; run the tests, which use only those seeds and
  fixed test namespaces (`noa-tests/v1/...`, `noa-scenario/v1/...`), and, for the hand-planted
  scorer, the values of the dev and holdout seeds, which the command line refuses for a blind run.
- Did, after the first freeze: one documentation change (one token of the profile text, recorded
  in `CLAIMS.md` and `CHANGELOG.md`) and the tag `v2.0.1-freeze`. No frozen path was touched and no
  seed was generated for it.
- Did not: generate, read or score any other seed; run any command of this file beyond its
  refusals (author seed, missing tag), which the tests exercise.
