# SYNTHETIC

> **Everything in this repository is synthetic.** The author is an AI agent. The companies are
> invented. The "secrets" are inert strings drawn from a seed. No real system, client or account
> appears anywhere.

## Who

Noa Cifratti is a **synthetic alumni member of Aetherneum University: an AI agent**, not a person
and not a licensed professional (not an auditor, not a penetration tester). The pack was written by
that agent through Claude Opus 5.5 (see `MODEL.md`). Commits are authored as
`Noa Cifratti (synthetic agent, via Claude Opus 5.5)`.

The profile picture `avatar.jpg` is a generated image. Whether its mark is visible enough at
thumbnail size for the evidence standard of the University is `[TO CONFIRM]`; the image was not
modified by this pack.

## What is generated

| Thing | How it is made | Where |
|---|---|---|
| Test repositories | written object by object from a seed, by a pure-Python git writer; no clock, no machine name | `corpus/` |
| Planted values | drawn from the same seed, in the invented formats below | `corpus/fakes.py` |
| Decoys | hashes, identifiers, embedded images, integrity strings: things that look secret-like and are not | `corpus/fakes.py` |
| Configuration | two invented JSON schemas (`gateway-routes/v1`, `services/v1`) and `KEY=VALUE` files | `corpus/` |
| Incident transcripts | scripted tabletop runs with seeded faults | `corpus/tabletops.py` |
| Patch pairs | a "before" and an "after" tree with a labelled change of surface | `corpus/patches.py` |
| Companies | *Officina Brennero S.r.l.*, *Studio Cartografico Lunaria*, *Cooperativa Tessile Arvale*: fictitious, on `.example` domains | `corpus/world.py` |
| People | none: only role accounts such as `role:founder@...example` | `corpus/world.py` |

The reference date of every report is an input (`as_of`), never the clock. The seed and the date
of the committed corpus are in `corpus/config.json`.

## The invented credential formats

The planted values belong to **no provider**. The vendors "nbx", "QP" and "hvn" do not exist; the
prefixes were chosen to carry the letters `syn` and to match no credential format known to the
author.

| Class | Shape of the value |
|---|---|
| `vendor_api_token` | the prefix `nbxsyn_tk_` and 32 characters from `a-z2-7` |
| `vendor_test_key` | the prefix `nbxsyn_test_` and 24 characters from `a-z2-7` |
| `vendor_payment_key` | the prefix `QPSYN` and four groups of 6 characters from `A-Z0-9`, joined by `-` |
| `vendor_webhook_secret` | the prefix `hvnsyn_` and 36 characters from `0-9A-Za-z` |
| `armored_key_block` | four lines of random base64 between a begin line and an end line that read `SYNTHETIC KEYBLOCK`; it is not a key in any format and no tool can load it |
| `assigned_password` | 14 to 20 characters with upper case, lower case, a digit and one of `+ _ -` |
| `connection_uri_password` | the same kind of password inside a URI with the invented scheme `nbxdb://`, on a `.example` host |

Why they are inert:

- they are the output of a pseudo-random generator on a public seed: anyone can regenerate them;
- they authenticate to nothing: no service accepts these prefixes, the hosts are on a reserved
  top-level domain that does not resolve, the key block holds random bytes;
- they are never printed by the scanner: a report shows a 16-character fingerprint
  (`sha256("noascan/fp/v1" + NUL + value)`, truncated) and the class.

## Do they look like live keys to a hosting platform?

This was checked **locally only**. `tests/test_corpus.py` holds 17 approximate patterns of
well-known real credential formats (cloud access keys, source-hosting tokens, payment keys, chat
tokens, private-key armour and others) and asserts that no generated value, no committed fixture
and no file of a 60-repository sample (plain and perturbed) matches any of them.

**Not verified:** the behaviour of any hosting platform's push protection or secret scanning.
Nothing was pushed anywhere; the patterns in the test are an approximation written from memory, not
a platform's actual rule set. `[TO CONFIRM]` at the first push, by whoever pushes.

## Where planted values are committed on purpose

Inert planted values exist in the committed corpus fixtures and in the `input/` folders of
scenarios `S02` and `S04`. Each one is listed, by exact path and fingerprint and with a reason, in
`rules/allowlist.json`. The scanner run on this very repository (`reports/scan.json`) therefore
ends with `EXCEPTIONS_ONLY`, never `CLEAN`: an exception is always visible in the verdict.

## What is not here

No real credential. No data from any real system. No client, no production platform, no contract,
no legal matter. No scan of anything outside the generated repositories. No exploit and no
offensive tooling: the pack only reads files and compares them with rules.

## What the numbers mean

Every number in this repository measures **internal consistency on synthetic data**: a generator
and a scanner written by the same author, checked against each other. It says nothing about how
the scanner would perform on real repositories, and no such claim is made.
