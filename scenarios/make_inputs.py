"""Author tool: (re)write the committed scenario inputs and the allowlist from fixed seeds.

    python scenarios/make_inputs.py            # rewrite scenarios/*/input and rules/allowlist.json
    python scenarios/make_inputs.py --check    # regenerate in memory and compare with what is committed

Everything written here is a pure function of ``SEED`` and ``AS_OF``: the planted values in the
two materialised trees (S02, S04) are the inert strings of ``corpus/fakes.py``, and ``--check``
(run by the tests) proves that the committed files are exactly what the generator produces - no
hand-typed credential-looking string can hide in a scenario input.

The allowlist is written from what was *planted* (the plan), never from what the scanner found.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus import fakes, gold, tabletops  # noqa: E402
from corpus.repos import ROUTES, SERVICES, base_config  # noqa: E402
from corpus.world import BY_KEY  # noqa: E402
from scenarios._common import fake, fake_uri, rng  # noqa: E402

SEED = 20260930
AS_OF = "2026-10-21T09:40:00+02:00"
WORDLIKE = "first-pet-name"      # decoy 12: a label under a secret-looking key


def j(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=True) + "\n"


def line_of(text: str, needle: str) -> int:
    return next(i + 1 for i, ln in enumerate(text.split("\n")) if needle in ln)


# ---- S02: five real plants, twelve decoys (Studio Cartografico Lunaria) ---------------------------------------------

def s02() -> tuple[dict[str, str], list[dict]]:
    domain = BY_KEY["lunaria"]["domain"]
    r = rng("S02", SEED, "decoys")
    token = fake("S02", SEED, "vendor_api_token")
    hook = fake("S02", SEED, "vendor_webhook_secret")
    admin_pw = fake("S02", SEED, "assigned_password")
    uri, uri_pw = fake_uri("S02", SEED, domain)
    block = fake("S02", SEED, "armored_key_block")
    banner = base64.b64encode(f"Welcome to the staging environment of {domain}".encode("ascii")).decode("ascii")
    files = {
        "README.md": "# tile-server\n\nInternal service of Studio Cartografico Lunaria (a fictitious company).\n"
                     "Scenario S02 fixture: five planted inert secrets and twelve decoys.\n",
        "deploy/prod.env": f"# production settings\nLOG_LEVEL=warn\nDEBUG=false\nNBX_API_TOKEN={token}\n",
        "config/integrations.json": "{\n" + ",\n".join([
            '  "schema": "integrations/v1"', '  "region": "eu-synthetic-1"', f'  "webhookSecret": {json.dumps(hook)}']) + "\n}\n",
        "src/settings.py": "\n".join([
            '"""Settings (synthetic; never executed)."""', "import os", "", f'PUBLIC_HOST = "app.{domain}"',
            "ADMIN_PASSWORD = " + json.dumps(admin_pw), 'DB_PASSWORD = os.environ["DB_PASSWORD"]',
            f'NBX_PUBLISHABLE_ID = "{fakes.public_id(r)}"', "SECRET_QUESTION = " + json.dumps(WORDLIKE)]) + "\n",
        "deploy/values.yml": "\n".join(["app:", f"  host: app.{domain}", "  replicas: 2", f"  tenantId: {fakes.uuid4(r)}",
                                        f'  databaseUrl: "{uri}"']) + "\n",
        "keys/deploy_key.txt": block + "\n",
        "requirements.lock": "\n".join(["# pinned (synthetic)", f"gateway-client==2.4.7 --hash=sha256:{fakes.sha256_hex(r)}",
                                        f"# integrity {fakes.integrity_hash(r)}"]) + "\n",
        "docs/runbook.md": "\n".join(["# Runbook - tile-server", "", "1. Check the gateway routes.", "2. Deploy.",
                                      f"Last good build: commit {fakes.sha1_hex(r)} on the staging branch.",
                                      f"Encoded banner: {banner}"]) + "\n",
        ".env.example": "\n".join(["# copy to .env and fill in", "LOG_LEVEL=info", "DB_PASSWORD=changeme", "TOKEN_TTL=3600",
                                   "DATABASE_URL=nbxdb://app_rw:${DB_PASSWORD}@db." + domain + ":5432/app"]) + "\n",
        "assets/logo.txt": fakes.data_uri(r) + "\n",
    }
    plants = [("deploy/prod.env", token, "vendor_api_token", gold.fingerprint(token)),
              ("config/integrations.json", hook, "vendor_webhook_secret", gold.fingerprint(hook)),
              ("src/settings.py", admin_pw, "assigned_password", gold.fingerprint(admin_pw)),
              ("deploy/values.yml", uri_pw, "connection_uri_password", gold.fingerprint(uri_pw)),
              ("keys/deploy_key.txt", block.split("\n")[0], "armored_key_block", gold.block_fingerprint(block))]
    secrets = [{"path": p, "line": line_of(files[p], needle), "class": cls, "fingerprint": fp}
               for p, needle, cls, fp in plants]
    decoy_lines = [("src/settings.py", "os.environ", "reference_py"), ("src/settings.py", "NBX_PUBLISHABLE_ID", "public_id"),
                   ("src/settings.py", "SECRET_QUESTION", "wordlike"), ("deploy/values.yml", "tenantId", "uuid_config"),
                   ("requirements.lock", "--hash=sha256", "sha256_lock"), ("requirements.lock", "# integrity", "integrity_hash"),
                   ("docs/runbook.md", "Last good build", "sha1_doc"), ("docs/runbook.md", "Encoded banner", "base64_text"),
                   (".env.example", "DB_PASSWORD=changeme", "placeholder_env"), (".env.example", "TOKEN_TTL", "nonsecret_key"),
                   (".env.example", "DATABASE_URL", "uri_placeholder"), ("assets/logo.txt", "data:image", "data_uri")]
    decoys = [{"path": p, "line": line_of(files[p], needle), "kind": kind} for p, needle, kind in decoy_lines]
    out = {f"S02/input/tree/{p}": text for p, text in files.items()}
    out["S02/input/labels.json"] = j({"as_of": AS_OF, "seed": SEED, "secrets": secrets, "decoys": decoys,
                                      "max_false_positives": 1})
    allow = [{"id": f"AL-S02-{i}", "type": "finding", "path": f"scenarios/S02/input/tree/{s['path']}", "class": s["class"],
              "fingerprint": s["fingerprint"],
              "reason": "scenario S02 fixture: inert synthetic value generated from the scenario seed (see SYNTHETIC.md)"}
             for i, s in enumerate(secrets, 1)]
    allow.append({"id": "AL-S02-6", "type": "finding", "path": "scenarios/S02/input/tree/src/settings.py",
                  "class": "wordlike_value_under_secret_key", "fingerprint": gold.fingerprint(WORDLIKE),
                  "reason": "scenario S02 fixture: decoy 12, a label under a secret-looking key; kept to show the review verdict"})
    return out, allow


# ---- S04: a "fix" that grows the surface, and a patch that shrinks it (Officina Brennero) --------------------------

def s04() -> tuple[dict[str, str], list[dict]]:
    domain = BY_KEY["brennero"]["domain"]
    host = f"app.{domain}"
    routes, services = base_config(domain)
    routes["routers"].append({"name": "legacy", "entrypoint": "public", "host": host, "path_prefix": "/legacy",
                              "middlewares": ["rate-limit"], "service": "app"})
    routes["routers"].append({"name": "portal", "entrypoint": "public", "host": host, "path_prefix": "/portal",
                              "middlewares": ["forward-auth"], "service": "app"})
    env = "# production settings\nLOG_LEVEL=warn\nDEBUG=false\n"
    readme = "# workshop-orders\n\nOfficina Brennero S.r.l. (a fictitious company). Scenario S04 fixture: {what}.\n"
    before = {ROUTES: j(routes), SERVICES: j(services), "deploy/prod.env": env, "README.md": readme.format(what="before the patch")}

    pw = fake("S04", SEED, "assigned_password")
    fix_routes = json.loads(json.dumps(routes))
    fix_routes["routers"].append({"name": "debug", "entrypoint": "public", "host": host, "path_prefix": "/debug",
                                  "middlewares": ["rate-limit"], "service": "app"})
    after_fix = {ROUTES: j(fix_routes), SERVICES: j(services), "deploy/prod.env": env + f"SMTP_PASSWORD={pw}\n",
                 "README.md": readme.format(what="after a 'fix' that opens a debug route and adds a credential")}
    red_routes = json.loads(json.dumps(routes))
    red_routes["routers"] = [r for r in red_routes["routers"] if r["name"] != "legacy"]
    after_reduce = {ROUTES: j(red_routes), SERVICES: j(services), "deploy/prod.env": env,
                    "README.md": readme.format(what="after a patch that removes the legacy route")}
    out = {}
    for name, tree in (("before", before), ("after_fix", after_fix), ("after_reduce", after_reduce)):
        out.update({f"S04/input/{name}/{p}": text for p, text in tree.items()})
    out["S04/input/params.json"] = j({"as_of": AS_OF, "seed": SEED, "expected_added": [
        f"route:{host}/debug", f"secret:deploy/prod.env#{gold.fingerprint(pw)}"]})
    allow = [{"id": "AL-S04-1", "type": "finding", "path": "scenarios/S04/input/after_fix/deploy/prod.env",
              "class": "assigned_password", "fingerprint": gold.fingerprint(pw),
              "reason": "scenario S04 fixture: inert synthetic value, the credential the 'fix' adds"},
             {"id": "AL-S04-2", "type": "finding", "path": f"scenarios/S04/input/after_fix/{ROUTES}",
              "class": "debug_route_public", "subject": "debug",
              "reason": "scenario S04 fixture: the debug route the 'fix' opens, in an invented configuration schema"}]
    return out, allow


# ---- S05: a new entry point the threat model does not know (Studio Cartografico Lunaria) ---------------------------

def s05() -> dict[str, str]:
    target = ROOT / "threatmodel" / "target"
    out = {}
    for path in sorted(p for p in target.rglob("*") if p.is_file()):
        rel = path.relative_to(target).as_posix()
        text = path.read_text(encoding="utf-8")
        if rel == ROUTES:
            doc = json.loads(text)
            doc["routers"].append({"name": "uploads", "entrypoint": "public", "host": "tiles.lunaria-carto.example",
                                   "path_prefix": "/upload", "middlewares": ["rate-limit"], "service": "app"})
            text = j(doc)
        out[f"S05/input/target/{rel}"] = text
    out["S05/input/params.json"] = j({"as_of": AS_OF, "new_entry_point": "route:public:tiles.lunaria-carto.example/upload"})
    return out


# ---- S06, S07, S08: tabletop transcripts ----------------------------------------------------------------------------

def events_for(playbook: str, company: str, subject: str, days_before: int) -> tuple[dict, list[dict]]:
    pb = json.loads((ROOT / "playbooks" / f"{playbook}.json").read_text(encoding="utf-8"))
    domain = BY_KEY[company]["domain"]
    events = []
    for step in pb["steps"]:
        ev = {"actor": f"{step['role']}@{domain}", "step": step["id"], "subject": {pb["subject_field"]: subject},
              "evidence": list(step["evidence"])}
        if "quorum" in step:
            ev["approvals"] = [f"custodian-{k}@{domain}" for k in (1, 3, 4)]
        if step.get("destructive"):
            ev["consent"] = {"by": f"human:approver@{domain}", "for": step["id"]}
        events.append(ev)
    return pb, events


def stamp(events: list[dict], days_before: int) -> list[dict]:
    start = datetime.fromisoformat(AS_OF) - timedelta(days=days_before, minutes=95)
    for i, ev in enumerate(events):
        ev["at"] = (start + timedelta(minutes=7 * i)).isoformat()
        if "consent" in ev:
            ev["consent"]["at"] = (start + timedelta(minutes=7 * i - 2)).isoformat()
    return events


def jsonl(events: list[dict]) -> str:
    return "".join(json.dumps(ev, sort_keys=True, ensure_ascii=True) + "\n" for ev in tabletops.chain(events))


def s06() -> dict[str, str]:
    _, clean = events_for("compromised_key", "arvale", "K-4172", 6)
    _, faulty = events_for("compromised_key", "arvale", "K-4172", 6)
    faulty = [e for e in faulty if e["step"] != "revoke_old_key"]      # rotated, never revoked
    return {"S06/input/clean.jsonl": jsonl(stamp(clean, 6)), "S06/input/faulty.jsonl": jsonl(stamp(faulty, 6)),
            "S06/input/params.json": j({"as_of": AS_OF, "playbook": "compromised_key"})}


def s07() -> dict[str, str]:
    domain = BY_KEY["brennero"]["domain"]
    pb, faulty = events_for("rogue_container", "brennero", "CT-3906", 4)
    restart = next(e for e in faulty if e["step"] == "restart_container")
    faulty.remove(restart)
    faulty.insert(next(i for i, e in enumerate(faulty) if e["step"] == "preserve_evidence"), restart)   # restart first
    _, ordered = events_for("rogue_container", "brennero", "CT-3906", 4)
    stamp(ordered, 4)

    def script(with_consent: bool) -> dict:
        actions = []
        for e in ordered:
            a = {"actor": e["actor"], "step": e["step"], "at": e["at"], "evidence": e["evidence"]}
            if "consent" in e and with_consent:
                a["consent"] = e["consent"]
            actions.append(a)
        return {"playbook": "rogue_container", "subject": "CT-3906", "company_domain": domain, "actions": actions}

    return {"S07/input/faulty.jsonl": jsonl(stamp(faulty, 4)), "S07/input/script_clean.json": j(script(True)),
            "S07/input/script_no_consent.json": j(script(False)),
            "S07/input/params.json": j({"as_of": AS_OF, "playbook": "rogue_container"})}


def s08() -> dict[str, str]:
    domain = BY_KEY["lunaria"]["domain"]
    right, wrong = "EP-4172", tabletops.transpose("EP-4172")
    _, events = events_for("leaked_endpoint", "lunaria", right, 2)
    by_step = {e["step"]: e for e in events}
    by_step["receive_alert"]["artifacts"] = [{"evidence": "alert_reference", "file": "alert.json"}]
    by_step["handoff_to_owner"]["artifacts"] = [{"evidence": "handoff_file", "file": "handoff.json"},
                                                {"evidence": "receipt_file", "file": "receipt.json"}]
    return {
        "S08/input/transcript.jsonl": jsonl(stamp(events, 2)),
        "S08/input/artifacts/alert.json": j({"author": f"monitoring@{domain}", "endpoint_id": right,
                                             "note": "public endpoint answering without authentication"}),
        "S08/input/artifacts/handoff.json": j({"author": f"operator@{domain}", "endpoint_id": wrong,
                                               "note": "closed on the gateway; please confirm on your side"}),
        "S08/input/artifacts/receipt.json": j({"author": f"owner-tiles@{domain}", "endpoint_id": wrong,
                                               "note": "received; confirmed closed"}),
        "S08/input/params.json": j({"as_of": AS_OF, "playbook": "leaked_endpoint", "alerted": right, "handed_off": wrong}),
    }


def params() -> dict[str, str]:
    narrow = [".env", ".env.*", "*/.env", "*/.env.*", "*.env"]
    return {
        "S01/input/params.json": j({"as_of": AS_OF, "seed": SEED, "company": "brennero"}),
        "S03/input/params.json": j({"as_of": AS_OF, "seed": SEED, "company": "arvale"}),
        "S09/input/params.json": j({"as_of": AS_OF, "seed": SEED, "company": "arvale"}),
        "S09/input/patch.json": j({"file": "secrets", "rule": "SEC-ASSIGN-BARE", "set": {"path_globs": narrow},
                                   "why": "narrow the unquoted KEY=value rule to environment files only"}),
        "S10/input/params.json": j({"as_of": AS_OF, "seed": SEED, "company": "brennero"}),
    }


def allowlist(entries: list[dict]) -> str:
    avatar = hashlib.sha256((ROOT / "avatar.jpg").read_bytes()).hexdigest()
    rules = [{"id": "AL-AVATAR", "type": "not_covered", "path": "avatar.jpg", "sha256": avatar,
              "reason": "profile picture: a binary image, pinned by content hash; the scanner abstains on it"}] + entries
    return j({
        "file": "allowlist", "version": "2.0.0", "as_of": "2026-09-30",
        "policy": "Exceptions for the scan of this repository itself, first match wins. Each entry pins one exact path and one "
                  "exact fingerprint (or subject, or content hash) and gives a reason. Findings may be excepted only under "
                  "corpus/ and scenarios/*/input/ (a test enforces it). An exception never yields CLEAN: the best verdict of a "
                  "scan that used one is EXCEPTIONS_ONLY.",
        "rules": rules})


def build() -> dict[str, str]:
    """Every generated file: {path relative to the repository root: text}."""
    out: dict[str, str] = {}
    s02_files, s02_allow = s02()
    s04_files, s04_allow = s04()
    for part in (s02_files, s04_files, s05(), s06(), s07(), s08(), params()):
        out.update({f"scenarios/{p}": text for p, text in part.items()})
    out["rules/allowlist.json"] = allowlist(s02_allow + s04_allow)
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    files = build()
    if "--check" in argv:
        bad = [p for p, text in sorted(files.items())
               if not (ROOT / p).is_file() or (ROOT / p).read_bytes().replace(b"\r\n", b"\n") != text.encode("utf-8")]
        print(f"scenario inputs: {len(files)} generated files, {len(bad)} differ from the committed ones")
        for p in bad[:10]:
            print("  " + p)
        return 1 if bad else 0
    for p, text in files.items():
        target = ROOT / p
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    print(f"scenario inputs: {len(files)} files written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
