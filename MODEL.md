# MODEL

## Who wrote this pack

A synthetic AI agent, **Noa Cifratti**, operating through **Claude Opus 5.5** (`claude-opus-5-5`),
wrote the code, the rules, the tests, the scenarios and the documents of version 2.0. No human
professional reviewed or signed them `[TO CONFIRM]` (the evidence standard of the University asks
for a signed declaration; who signs it is not decided in this pack).

## What runs at run time

**No model is called.** The scanner, the surface gate, the threat-model check, the tabletop judge,
the evaluation harness, the scenarios and the tests are deterministic Python on the standard
library. There is no network code in the pack; the tests run with sockets blocked
(`tests/test_offline.py`).

## The optional model hook

`tabletop/model_roles.py` reserves a place for a later experiment in which a model plays the roles
of a tabletop exercise. In version 2.0:

- it is **disabled by default** (`ENABLED = False`) and there is no switch to enable it from the
  command line or the environment;
- it contains no client code and imports no module (only the `__future__` annotations);
- nothing in the pack imports it;
- if it is ever enabled, the only models it admits are `claude-opus-5-5` and `claude-fable-5-1`.

A test (`tests/test_tabletop.py`) checks each of these points on the source itself.
Tabletops played by a model are therefore **not demonstrated** in version 2.0 (see `CLAIMS.md`).

## The blind evaluation

The author generated and inspected three seeds only (`eval/seeds.json`). The blind run is meant
for a different hand: a session with the other model of the fleet (`claude-fable-5-1`) or a human
reviewer, whose name goes into `eval/history.json` as `runner`. The commands are in
`eval/BLIND_PROTOCOL.md`. The blind run calls no model either: the different hand only chooses the
seed, hides the values and starts the program.

One blind run was made, on `v2.0.1-freeze` (seed 20261011, `eval/history.json` runs 9 to 11). To fix
what it found (version 2.0.2, `CHANGELOG.md`), the author read its results and the repository in
which the values were hidden, and did not generate that seed. The seed is now listed in
`eval/seeds.json` as seen, and the harness refuses it for a later blind run.

## Third-party tools

| Tool | Version used here | Role |
|---|---|---|
| Python | 3.12 | the only interpreter; standard library only |
| git | 2.51 (the version on the author's machine) | read-only queries on generated repositories |
| other secret scanners or static analysers | none | not run, not required; a comparison with third-party tools is not part of version 2.0 |
