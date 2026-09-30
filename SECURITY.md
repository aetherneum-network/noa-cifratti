# Security

> **SYNTHETIC.** Everything described here is a generated, fictitious target. Noa Cifratti is a
> synthetic alumni member (an AI agent) of Aetherneum University: not a person, not an auditor and
> not a penetration tester. Nothing in this file is an audit, a certification or a statement about
> any real system.

This file holds two things:

1. the **threat model of the synthetic target** used by this pack, in a form that a program checks
   against the target's own configuration files;
2. the **security notes of the pack itself** (what the scanner does with the repositories it reads).

## 1. Threat model of the synthetic target

**Target.** The tile-server of *Studio Cartografico Lunaria*, a fictitious company on the reserved
domain `lunaria-carto.example`. Its topology lives in `threatmodel/target/` as three files in the
invented schemas of this pack: gateway routes, services, and a production environment file.

**Context.** Solo-founder context: one person holds every role. For that reason each accepted risk
names a role account, a date and a review date instead of relying on a team to remember it.

**Method.** A short list of threat categories (spoofing, tampering, repudiation, information
disclosure, denial of service, elevation of privilege) applied per entry point and sorted by blast
radius, largest first. The category names follow the published STRIDE mnemonic
`[TO CONFIRM with legal]`; no conformance to any standard is claimed. The radius scale (1 to 5) is
this pack's own working convention, written in `rules/blast_radius.json`.

**Trust boundaries.** Internet to gateway (`B-INTERNET`); private plane to administration
(`B-PRIVATE`); host interfaces to containers (`B-HOST`).

**Entry points.** Five, each one an item that the surface extractor reads from the topology:
the public application route, the public API route, the administration route on the private
entrypoint, the gateway port on all interfaces, the administration port on the private bind.

**Assets.** Deploy and custody keys; the container runtime of the host; the administration plane;
the identity gate (forward-auth); the survey and tile database; the application handlers; the
availability of the public site.

### The table

The table below is not written by hand: it is the output of `python threatmodel/check.py --render`
and a test (`tests/test_threatmodel.py`) fails if this file and the model ever differ.

| # | Radius | Asset | Entry point | Category | Threat | Answer |
|---|---|---|---|---|---|---|
| T01 | 5 | deploy and custody keys | `route:public:api.lunaria-carto.example/v1` | information_disclosure | A key committed to the repository is read by anyone who can clone it. | mitigated: No covered secret in the tree; if one leaks, the compromised-key playbook rotates and revokes it. |
| T02 | 5 | container runtime of the host | `route:public:app.lunaria-carto.example/` | elevation_of_privilege | A compromised handler reaches the container runtime and takes the host. | mitigated: No service mounts the runtime socket. |
| T03 | 4 | administration plane | `route:admin:admin.lunaria-carto.example/` | spoofing | A request reaches the administration interface without an authenticated identity. | mitigated: The admin router sits behind forward-auth. |
| T04 | 4 | identity gate (forward-auth) | `route:admin:admin.lunaria-carto.example/` | spoofing | A client forges the identity headers that the gate is supposed to set. | mitigated: The forward-auth middleware does not trust forwarded headers from the client. |
| T05 | 4 | administration plane | `port:admin:10.77.0.1:8443` | elevation_of_privilege | The administration port is published on a public interface. | mitigated: The admin service publishes its port on the private bind only. |
| T06 | 4 | survey and tile database | `route:public:api.lunaria-carto.example/v1` | tampering | The public network reaches the database directly, bypassing the API. | mitigated: Segmentation: the database is on the data network only and publishes no port; the API is not on the public network. |
| T07 | 3 | application handlers | `route:public:app.lunaria-carto.example/` | information_disclosure | Debug output exposes internals through the public application. | mitigated: DEBUG is off in the production environment file and no debug route is public. |
| T08 | 3 | application handlers | `route:public:api.lunaria-carto.example/v1` | repudiation | An API call cannot be attributed afterwards because request logs are kept for a short time only. | accepted by role:founder@lunaria-carto.example on 2026-10-14, review by 2027-01-14: Low value of the data served by the public API; revisit when write endpoints are added. |
| T09 | 2 | public site availability | `port:gateway:0.0.0.0:443` | denial_of_service | A volumetric flood on the single gateway takes the public site down. | accepted by role:founder@lunaria-carto.example on 2026-10-14, review by 2027-01-14: One gateway, no upstream scrubbing: accepted for a public map viewer; rate limiting covers only the application layer. |
| T10 | 2 | public site availability | `route:public:app.lunaria-carto.example/` | denial_of_service | A single client exhausts the application handlers. | mitigated: Rate limiting on the public application router. |

### How it is verified

```
python threatmodel/check.py --as-of 2026-10-21T09:40:00+02:00
```

Exit code 0 means `PASSED`. The check fails, naming the item, when:

| Code | Meaning |
|---|---|
| `ENTRY_POINT_NOT_IN_MODEL` | the topology exposes a route, a port or a socket that the model does not list |
| `STALE_ENTRY_POINT` | the model lists an entry point that the topology no longer has |
| `ENTRY_POINT_WITHOUT_THREAT`, `ASSET_WITHOUT_THREAT` | something is listed and nobody asked what can go wrong with it |
| `THREAT_WITHOUT_DISPOSITION` | a threat is neither mitigated nor accepted |
| `MITIGATION_NOT_IN_TOPOLOGY` | the model says "mitigated" and the configuration does not show it |
| `MITIGATION_NOT_VERIFIABLE` | the mitigation names a check this pack does not know how to run |
| `ACCEPTED_WITHOUT_OWNER_OR_DATE` | an accepted risk has no owner, no date or no review date |
| `ACCEPTED_RISK_REVIEW_OVERDUE` | the review date of an accepted risk is before the reference date |
| `MODEL_WITHOUT_DATE`, `MODEL_DATED_IN_THE_FUTURE` | the model is undated, or dated after the reference date |
| `THREAT_WITH_UNKNOWN_CATEGORY`, `THREAT_WITH_UNKNOWN_REFERENCE` | a threat points to something that does not exist |
| `TOPOLOGY_NOT_READABLE` | a configuration file cannot be parsed: the check abstains and fails |

Scenario `S05` reproduces the first failure: a new public route is added to the topology without a
threat, and the check names it.

### Accepted risks

`T08` (short retention of request logs) and `T09` (a volumetric flood on the single gateway) are
accepted, not mitigated. Both were accepted by the role account `role:founder@lunaria-carto.example`
on 2026-10-14 with review by 2027-01-14 (fictitious dates inside the synthetic scenario, whose
reference date is 2026-10-21). At any reference date after the review date the check fails with
`ACCEPTED_RISK_REVIEW_OVERDUE`.

### What the model does not say

It covers only what the three configuration files express. It says nothing about the operating
system of the host, the supply chain of the images, physical access, people, or any behaviour at
run time. A `PASSED` means "the document and the topology agree", not "the target is secure".

## 2. Security notes of the pack itself

The scanner reads repositories it did not write. These are the properties it keeps, each with the
test that checks it:

| Property | Where it is checked |
|---|---|
| Source code under review is parsed, never imported or executed | `tests/test_config_pycode_surface.py` |
| `git` is called with read-only sub-commands only (`rev-parse`, `diff`, `show-ref`, `cat-file`, `ls-tree`), never through a shell, with a neutralised environment | `tests/test_offline.py`, `tests/test_history.py` |
| The scan never walks up into an enclosing repository | `tests/test_history.py` |
| A symbolic link is never followed: it is reported as a gap | `tests/test_never_clean.py` (this one test is skipped on a machine that cannot create symbolic links, the author's included) |
| No network: no module of the pack imports a network library, and the tests run with sockets blocked | `tests/test_offline.py` |
| A report holds a fingerprint of a finding, never its value, also when the value sits in a file name, a commit message or an author name | `tests/test_report_safety.py`, scenario `S03` |
| A target that cannot be read is an error (exit 64), never an empty and therefore "clean" scan | `tests/test_cli.py` |
| The tabletop log is append-only and hash-chained; a rewritten line is detected | `tests/test_tabletop.py` |
| No model is called; the optional hook is disabled and nothing imports it | `tests/test_tabletop.py`, `MODEL.md` |

Known weaknesses, stated rather than hidden:

- **Fingerprints are not salted.** A fingerprint is the first 16 hexadecimal characters of a SHA-256
  over a fixed prefix and the value. For a value with little entropy, someone who holds the report
  can test guesses against it. With the inert values of this pack that does not matter; a report
  about real material would have to be handled as internal.
- **The scanner trusts the `git` program on the machine.** A malicious repository is a known way to
  attack git itself; the pack reduces the exposure (read-only plumbing sub-commands, the object
  database named explicitly, no checkout, `GIT_*` variables removed from the environment, system
  configuration not read, no prompt) and does not claim to remove it.
- **Coverage is narrow by design.** See `COVERAGE.md`: outside the declared classes and file forms
  the scanner abstains (`NOT_COVERED`); it does not guess.

## 3. Reporting a problem

Open an issue on the repository that hosts this pack. There is no bounty, no response time and no
monitored security mailbox for a synthetic profile `[TO CONFIRM]`. Do not send real credentials:
nothing in this repository needs one.
