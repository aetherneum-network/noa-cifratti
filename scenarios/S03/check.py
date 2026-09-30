"""S03 (negative) - Cooperativa Tessile Arvale: no planted value may appear in any report, terminal line or log."""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from corpus import gold  # noqa: E402
from corpus.world import BY_KEY  # noqa: E402
from noascan import report as nreport, surface  # noqa: E402
from noascan.__main__ import rules_diff  # noqa: E402
from noascan.scan import scan  # noqa: E402
from scenarios import _common as c  # noqa: E402
from tabletop import judge as tjudge  # noqa: E402
from tabletop.log import Log, read  # noqa: E402

SID = "S03"


def needles(values: dict[str, str]) -> dict[str, list[str]]:
    """Every form in which a planted value could leak: itself, its long lines, and common encodings."""
    out: dict[str, list[str]] = {}
    for name, value in values.items():
        forms = [ln for ln in value.split("\n") if len(ln) >= 12 and not ln.startswith("-----")] if "\n" in value else [value]
        more = []
        for v in forms:
            raw = v.encode("ascii")
            more += [base64.b64encode(raw).decode("ascii"), raw.hex(), v[::-1], json.dumps(v)[1:-1]]
        out[name] = sorted(set(forms + more))
    return out


def check():
    p = c.load(HERE / "input" / "params.json")
    as_of, seed = p["as_of"], p["seed"]
    domain = BY_KEY[p["company"]]["domain"]
    token = c.fake(SID, seed, "vendor_api_token")
    named = c.fake(SID, seed, "vendor_api_token", 1)
    pay = c.fake(SID, seed, "vendor_payment_key")
    hook = c.fake(SID, seed, "vendor_webhook_secret")
    pw = c.fake(SID, seed, "assigned_password")
    old_pw = c.fake(SID, seed, "assigned_password", 1)
    uri, uri_pw = c.fake_uri(SID, seed, domain)
    block = c.fake(SID, seed, "armored_key_block")
    subject_token = c.fake(SID, seed, "vendor_test_key")
    values = {"token": token, "token_in_file_name": named, "payment_key": pay, "webhook_secret": hook, "password": pw,
              "old_password": old_pw, "uri_password": uri_pw, "key_block": block, "token_as_identifier": subject_token}

    first = {"README.md": "# yarn-inventory\n\nCooperativa Tessile Arvale (a fictitious company).\n",
             "deploy/prod.env": f"LOG_LEVEL=warn\nSMTP_PASSWORD={old_pw}\n"}
    head = {"README.md": first["README.md"],
            "deploy/prod.env": f"LOG_LEVEL=warn\nNBX_API_TOKEN={token}\nSMTP_PASSWORD={pw}\n",
            "deploy/values.yml": f'app:\n  databaseUrl: "{uri}"\n  paymentKey: {pay}\n',
            "config/hooks.json": json.dumps({"schema": "hooks/v1", "webhookSecret": hook}, indent=2) + "\n",
            "keys/signing.txt": block + "\n",
            f"backup/{named}.txt": "exported on a Friday\n",
            "docs/notes.md": "Encoded for the vendor form: " + base64.b64encode(token.encode("ascii")).decode("ascii") + "\n"}
    work = c.workdir(SID)
    root = work / "yarn-inventory"
    c.build_repo(root, p["company"], [("initial import", first), ("wire the integrations", head)])
    before = work / "before"
    for rel, text in first.items():
        (before / rel).parent.mkdir(parents=True, exist_ok=True)
        (before / rel).write_bytes(text.encode("utf-8"))

    out = scan(root, as_of)
    texts = {"scan report": nreport.dumps(out), "scan summary": nreport.summary(out)}
    env = {k: v for k, v in os.environ.items() if k.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "PYTHONPATH",
                                                                "USERPROFILE", "LANG")}
    env.update(PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    cli_json = work / "cli.json"
    cp = subprocess.run([sys.executable, "-m", "noascan", "scan", str(root), "--as-of", as_of, "--json", str(cli_json)],
                        cwd=str(c.ROOT), env=env, capture_output=True, stdin=subprocess.DEVNULL, timeout=90)
    texts["command line stdout"] = cp.stdout.decode("utf-8", "replace")
    texts["command line stderr"] = cp.stderr.decode("utf-8", "replace")
    texts["command line report file"] = cli_json.read_text(encoding="ascii") if cli_json.is_file() else ""
    texts["surface report"] = nreport.dumps(surface.delta(before, root, as_of))
    patch = {"file": "secrets", "rule": "SEC-ASSIGN-BARE", "set": {"path_globs": ["*.ini"]}}
    texts["rules-diff report"] = nreport.dumps(rules_diff(root, as_of, patch))
    log = Log(work / "transcript.jsonl")     # someone pasted the key itself where the key identifier goes
    log.append({"actor": f"incident_lead@{domain}", "step": "declare_incident", "at": "2026-10-20T10:00:00+02:00",
                "subject": {"key_id": subject_token}, "evidence": ["alert_reference"]})
    log.append({"actor": f"operator@{domain}", "step": subject_token, "at": "2026-10-20T10:07:00+02:00",
                "subject": {"key_id": "K-4172"}, "evidence": []})
    judged = tjudge.judge(read(work / "transcript.jsonl"), tjudge.load_playbook("compromised_key"), as_of)
    texts["tabletop judgement"] = nreport.dumps(judged)

    failures: list[str] = []
    c.expect(HERE / "expected" / "scan.json", out, failures)
    forms = needles(values)
    leaks = sorted({f"{name} in {where}" for where, text in texts.items() for name, fs in forms.items()
                    for f in fs if f in text})
    if leaks:
        failures.append("planted values written in clear: " + ", ".join(leaks))
    on_disk = "".join(text for text in head.values()) + "".join(head) + (work / "transcript.jsonl").read_text(encoding="utf-8")
    if not all(v in on_disk for v in values.values() if v != old_pw):
        failures.append("fixture error: a planted value is not in the repository, the check would be vacuous")
    found = {f["fingerprint"] for f in out["findings"] if f.get("fingerprint")}
    expected_fps = {gold.fingerprint(v) for k, v in values.items() if k not in ("key_block", "token_as_identifier")}
    expected_fps.add(gold.block_fingerprint(block))
    if expected_fps - found:
        failures.append(f"{len(expected_fps - found)} planted values have no fingerprint in the report")
    if cp.returncode != 3:
        failures.append(f"command line exit code {cp.returncode}, not 3")
    if not any(f["path"].startswith("[masked:") for f in out["findings"]):
        failures.append("the file named after a token is not masked in the report")
    if gold.fingerprint(subject_token) not in texts["tabletop judgement"]:
        failures.append("the token pasted as an identifier is not replaced by its fingerprint in the judgement")
    line = (f"{len(values)} planted values, {sum(len(f) for f in forms.values())} forms searched in {len(texts)} outputs: "
            f"{len(leaks)} in clear; {len(expected_fps & found)}/{len(expected_fps)} present as fingerprints; "
            f"file named after a token masked")
    return c.result(SID, failures, line, {"outputs": len(texts), "leaks": len(leaks)})


if __name__ == "__main__":
    c.main(check)
