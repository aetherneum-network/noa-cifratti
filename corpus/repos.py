"""Plan and materialise the synthetic mini-repositories.

A repository is first *planned* as data (snapshots per commit, refs, and a list of plants: secrets,
decoys, configuration defects, dangerous calls, boundary files) and only then written to disk.
Gold labels come from the plan, never from the scanner: positions are resolved by looking up each
planted value in the planned snapshots, and ``corpus/reference_plan.py`` re-reads them from disk.
"""
from __future__ import annotations

import base64
import copy
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from corpus import fakes, perturb
from corpus.gitwrite import RepoWriter
from corpus.world import COMPANIES, EPOCH_BASE, TZ, author

SEVERITY = {"armored_key_block": "critical", "vendor_payment_key": "critical", "vendor_api_token": "high",
            "vendor_webhook_secret": "high", "assigned_password": "high", "connection_uri_password": "high",
            "vendor_test_key": "low"}

ARCHETYPES = [("clean", 24), ("head_secret", 26), ("history_only", 20), ("branch_only", 8), ("tag_only", 4),
              ("dangling", 4), ("boundary_clean", 6), ("boundary_secret", 4), ("multi", 4)]

MAX_FILE_BYTES = 1048576  # mirrors rules/secrets.json limits.max_file_bytes (checked by a test)


@dataclass
class Plant:
    kind: str                 # secret | decoy | config | pycode | boundary
    cls: str
    path: str
    value: str = ""           # secret value / decoy token - never written to gold
    marker: str = ""          # a line (stripped) that locates the plant when the value is not contiguous
    subject: str = ""         # config subject (router, service, middleware or env key)
    severity: str = ""
    covered: bool = True
    technique: str = "plain"
    carrier: str = "head"     # head | history_only | branch_only | tag_only | dangling_blob | unreachable_commit
    line: int = 0             # line in the HEAD snapshot (0 = not in HEAD / not line-addressable)
    first_commit: str = ""    # commit that introduced it ("" for a dangling blob)
    first_line: int = 0       # line in the introducing blob
    blob: str = ""            # blob id of the introducing version
    in_head: bool = False


@dataclass
class CommitPlan:
    message: str
    author: int
    snapshot: dict[str, bytes]
    parent: int | None
    line: str = "main"        # main | branch | tag | unreachable


@dataclass
class RepoPlan:
    name: str
    index: int
    company: str
    archetype: str
    commits: list[CommitPlan] = field(default_factory=list)
    plants: list[Plant] = field(default_factory=list)
    dangling_blobs: list[bytes] = field(default_factory=list)
    branch: str = ""
    tag: str = ""
    # filled by materialise()
    commit_ids: list[str] = field(default_factory=list)
    refs: dict[str, str] = field(default_factory=dict)
    head: str = ""
    object_ids: list[str] = field(default_factory=list)


class Tree:
    """Mutable working state: text files as line lists, flat JSON objects, structured JSON, raw bytes."""

    def __init__(self) -> None:
        self.text: dict[str, list[str]] = {}
        self.flat: dict[str, list[tuple[str, str]]] = {}
        self.objs: dict[str, dict] = {}
        self.raw: dict[str, bytes] = {}

    def add(self, path: str, *lines: str) -> None:
        self.text.setdefault(path, []).extend(lines)

    def remove(self, path: str, *lines: str) -> None:
        for line in lines:
            self.text[path].remove(line)
        if not self.text[path]:
            del self.text[path]

    def snapshot(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for path, lines in self.text.items():
            out[path] = ("\n".join(lines) + "\n").encode("utf-8")
        for path, entries in self.flat.items():
            body = ",\n".join(f"  {json.dumps(k)}: {json.dumps(v)}" for k, v in entries)
            out[path] = ("{\n" + body + "\n}\n").encode("utf-8")
        for path, obj in self.objs.items():
            out[path] = (json.dumps(obj, indent=2, sort_keys=False) + "\n").encode("utf-8")
        out.update(self.raw)
        return out


# ---- base content -------------------------------------------------------------------------------------------------

PY_DEFECTS = {
    "dynamic_code_execution": ("high", ["def compute(expr):", "    return eval(expr)"]),
    "shell_true": ("high", ["def archive(name):", "    return subprocess.run(\"tar czf \" + name, shell=True)"]),
    "unsafe_deserialization": ("high", ["def restore(blob):", "    return pickle.loads(blob)"]),
    "tls_verification_disabled": ("high", ["def fetch(url):", "    return client.get(url, verify=False)"]),
    "shell_command": ("high", ["def rotate_logs(name):", "    return os.system(\"gzip \" + name)"]),
    "debug_server": ("medium", ["def main():", "    app.run(debug=True)"]),
    "bind_all_interfaces": ("medium", ["def serve():", "    server.serve(host=\"0.0.0.0\", port=8080)"]),
}
PY_DECOYS = [
    ["def parse_literal(expr):", "    return ast.literal_eval(expr)"],
    ["def archive_safe(name):", "    return subprocess.run([\"tar\", \"czf\", name], check=True)"],
    ["def notes():", "    # never call eval(expr) or os.system(cmd) here", "    return None"],
    ["def decode(blob):", "    return json.loads(blob)"],
    ["def fetch_safe(url):", "    return client.get(url, verify=True)"],
    ["def main_safe():", "    app.run(debug=False)"],
    ["def serve_local():", "    server.serve(host=\"127.0.0.1\", port=8080)"],
    ["def doc():", "    \"\"\"Example only: eval(expr) and pickle.loads(blob) are forbidden here.\"\"\"", "    return 1"],
]
CONFIG_DEFECTS = {"admin_route_without_forward_auth": "high", "debug_route_public": "high",
                  "forward_auth_trusts_client_headers": "high", "internal_port_published_on_all_interfaces": "high",
                  "runtime_socket_mounted": "critical", "service_bridges_public_and_data_networks": "medium",
                  "debug_flag_enabled": "medium"}
PRIVATE_BIND = "10.77.0.1"


def base_config(domain: str) -> tuple[dict, dict]:
    routes = {
        "schema": "gateway-routes/v1",
        "entrypoints": {"public": {"bind": "0.0.0.0:443"}, "admin": {"bind": f"{PRIVATE_BIND}:8443"}},
        "middlewares": {
            "forward-auth": {"type": "forward-auth", "address": "http://authgate:9091/verify",
                             "trust_forward_header": False},
            "rate-limit": {"type": "rate-limit", "average": 50}},
        "routers": [
            {"name": "app", "entrypoint": "public", "host": f"app.{domain}", "path_prefix": "/",
             "middlewares": ["rate-limit"], "service": "app"},
            {"name": "api", "entrypoint": "public", "host": f"api.{domain}", "path_prefix": "/v1",
             "middlewares": ["rate-limit"], "service": "api"},
            {"name": "admin-ui", "entrypoint": "admin", "host": f"admin.{domain}", "path_prefix": "/",
             "middlewares": ["forward-auth"], "service": "admin"}]}
    services = {
        "schema": "services/v1",
        "networks": ["public", "app", "data", "admin"],
        "services": [
            {"name": "gateway", "plane": "public", "networks": ["public", "app"], "published": ["0.0.0.0:443:443"],
             "mounts": ["./config/gateway:/etc/gateway:ro"]},
            {"name": "app", "plane": "app", "networks": ["app"], "published": [], "mounts": []},
            {"name": "api", "plane": "app", "networks": ["app", "data"], "published": [], "mounts": []},
            {"name": "db", "plane": "data", "networks": ["data"], "published": [], "mounts": ["dbdata:/var/lib/db"]},
            {"name": "admin", "plane": "admin", "networks": ["admin", "data"],
             "published": [f"{PRIVATE_BIND}:8443:8443"], "mounts": []},
            {"name": "authgate", "plane": "admin", "networks": ["app", "admin"], "published": [], "mounts": []}]}
    return routes, services


ROUTES, SERVICES = "config/gateway/routes.json", "config/services.json"


def base_files(t: Tree, company: dict, project: str) -> None:
    domain = company["domain"]
    t.add("README.md", f"# {project}", "", f"Internal service of {company['name']} (a fictitious company).", "",
          "Deployment notes live in docs/runbook.md.")
    t.add("src/app.py", '"""Request handlers (synthetic; parsed by the corpus, never executed)."""', "import ast",
          "import json", "import os", "import pickle", "import subprocess", "",
          "from gateway_client import app, client, server", "", "", "def health():",
          "    return {\"status\": \"ok\"}")
    t.add("src/settings.py", '"""Settings are read from the environment."""', "import os", "",
          f"PUBLIC_HOST = \"app.{domain}\"", "LOG_LEVEL = os.environ.get(\"LOG_LEVEL\", \"info\")")
    t.add(".env.example", "# copy to .env and fill in", "LOG_LEVEL=info", f"PUBLIC_HOST=app.{domain}")
    t.add("deploy/values.yml", "app:", f"  host: app.{domain}", "  replicas: 2")
    t.add("deploy/prod.env", "# production settings (non-secret)", "LOG_LEVEL=warn", "DEBUG=false")
    t.add("scripts/deploy.sh", "#!/bin/sh", "set -eu", f"echo \"deploying {project}\"")
    t.add("docs/runbook.md", f"# Runbook - {project}", "", "1. Check the gateway routes.", "2. Deploy.", "")
    t.add("requirements.lock", "# pinned (synthetic)")
    t.flat["config/integrations.json"] = [("schema", "integrations/v1"), ("region", "eu-synthetic-1")]
    t.objs[ROUTES], t.objs[SERVICES] = base_config(domain)


# ---- decoys -------------------------------------------------------------------------------------------------------

DECOY_KINDS = ["sha256_lock", "sha1_doc", "uuid_config", "placeholder_env", "reference_py", "data_uri", "public_id",
               "nonsecret_key", "uri_placeholder", "integrity_hash", "base64_text", "checksum_json", "wordlike"]


def add_decoy(t: Tree, rng: random.Random, kind: str, domain: str) -> Plant | None:
    token = ""
    if kind == "sha256_lock":
        token = fakes.sha256_hex(rng)
        path, line = "requirements.lock", f"gateway-client==2.4.{rng.randrange(30)} --hash=sha256:{token}"
    elif kind == "sha1_doc":
        token = fakes.sha1_hex(rng)
        path, line = "docs/runbook.md", f"Last good build: commit {token} on the staging branch."
    elif kind == "uuid_config":
        token = fakes.uuid4(rng)
        path, line = "deploy/values.yml", f"  tenantId: {token}"
    elif kind == "placeholder_env":
        key = rng.choice(["DB_PASSWORD", "SMTP_PASSWORD", "NBX_API_TOKEN", "SESSION_SECRET"])
        ph = rng.choice(["changeme", "<your-value-here>", "${" + key + "}", "xxxxxxxxxxxx", "REPLACE_ME"])
        path, line = ".env.example", f"{key}={ph}"
    elif kind == "reference_py":
        key = rng.choice(["DB_PASSWORD", "API_TOKEN", "SESSION_SECRET"])
        path, line = "src/settings.py", f"{key} = os.environ[\"{key}\"]"
    elif kind == "data_uri":
        token = fakes.data_uri(rng)
        path, line = "assets/logo.txt", token
    elif kind == "public_id":
        token = fakes.public_id(rng)
        path, line = "src/settings.py", f"NBX_PUBLISHABLE_ID = \"{token}\""
    elif kind == "nonsecret_key":
        path = ".env.example"
        line = rng.choice(["PASSWORD_MIN_LENGTH=12", "TOKEN_TTL=3600", f"PASSWORD_HASH={fakes.sha256_hex(rng)}",
                           "SECRET_NAME=prod/db/main-credentials", "API_KEY_HEADER=X-Api-Key-Name",
                           "SESSION_SECRET_ROTATION=monthly-2026"])
    elif kind == "uri_placeholder":
        path, line = ".env.example", "DATABASE_URL=nbxdb://app_rw:${DB_PASSWORD}@db." + domain + ":5432/app"
    elif kind == "integrity_hash":
        token = fakes.integrity_hash(rng)
        path, line = "requirements.lock", f"# integrity {token}"
    elif kind == "base64_text":
        token = base64.b64encode(f"Welcome to the staging environment of {domain}".encode("ascii")).decode("ascii")
        path, line = "docs/runbook.md", f"Encoded banner: {token}"
    elif kind == "checksum_json":
        token = fakes.sha256_hex(rng)
        if any(k == "artifactChecksum" for k, _ in t.flat["config/integrations.json"]):
            return None
        t.flat["config/integrations.json"].append(("artifactChecksum", token))
        return Plant("decoy", kind, "config/integrations.json", value=token)
    else:  # wordlike
        path = "src/settings.py"
        line = rng.choice(["TOKEN_TYPE = \"bearer_token\"", "PASSWORD_FIELD = \"user_password_input\"",
                           "SECRET_QUESTION = \"first-pet-name\""])
    if line in t.text.get(path, []):
        return None
    t.add(path, line)
    return Plant("decoy", kind, path, value=token, marker=line.strip())


# ---- secrets ------------------------------------------------------------------------------------------------------

def _templates(cls: str, domain: str) -> list[tuple[str, str]]:
    """(path, line template) per class. ``{v}`` is the value; JSON targets use ``json:<key>``."""
    return {
        "vendor_api_token": [(".env", "NBX_API_TOKEN={v}"), ("config/integrations.json", "json:nimbuxToken"),
                             ("src/client.py", "NBX_TOKEN = \"{v}\""),
                             ("scripts/deploy.sh", "curl -sS -H \"X-Nbx-Token: {v}\" https://api.nimbux.example/v1/deploy"),
                             ("docs/runbook.md", "Use token `{v}` for the staging deploy.")],
        "vendor_test_key": [("tests/test_client.py", "TEST_KEY = \"{v}\""), ("tests/fixtures.json", "json:nimbuxTestKey"),
                            (".env.test", "NBX_TEST_KEY={v}")],
        "vendor_payment_key": [(".env", "QUILLPAY_SECRET_KEY={v}"), ("src/billing.py", "QP_KEY = \"{v}\""),
                               ("deploy/values.yml", "  quillpayKey: {v}")],
        "vendor_webhook_secret": [(".env", "HARBORVANE_SIGNING_SECRET={v}"),
                                  ("config/integrations.json", "json:webhookSecret"),
                                  ("src/hooks.py", "SIGNING = \"{v}\"")],
        "assigned_password": [(".env", "DB_PASSWORD={v}"), ("deploy/prod.env", "SMTP_PASSWORD={v}"),
                              ("deploy/values.yml", "  adminPassword: \"{v}\""),
                              ("config/integrations.json", "json:ldapBindPassword"),
                              ("src/settings.py", "ADMIN_PASSWORD = \"{v}\""),
                              ("scripts/backup.sh", "export BACKUP_PASSWORD={v}"),
                              ("deploy/values.yml", "  smtp_password: {v}")],
        "connection_uri_password": [(".env", "DATABASE_URL={uri}"), ("deploy/values.yml", "  databaseUrl: \"{uri}\""),
                                    ("src/settings.py", "DSN = \"{uri}\"")],
        "armored_key_block": [("keys/deploy_key.txt", "block"), ("docs/runbook.md", "block:fenced"),
                              ("deploy/values.yml", "block:yaml")],
    }[cls]


def add_secret(t: Tree, rng: random.Random, domain: str, carrier: str, do_perturb: bool,
               cls: str | None = None) -> tuple[Plant, list[tuple[str, str]]]:
    """Plant one secret in the tree. Returns the plant and the undo list [(path, line | 'json:key')]."""
    cls = cls or rng.choice(fakes.SECRET_CLASSES)
    uri = ""
    if cls == "connection_uri_password":
        uri, value = fakes.connection_uri(rng, domain)
    else:
        value = fakes.make(cls, rng, domain)
    plant = Plant("secret", cls, "", value=value, severity=SEVERITY[cls], carrier=carrier)
    if do_perturb and rng.random() < 0.75:
        path, lines, technique, covered = perturb.render(rng, cls, value, uri, domain)
        plant.path, plant.technique, plant.covered, plant.marker = path, technique, covered, lines[0].strip()
        t.add(path, *lines)
        return plant, [(path, ln) for ln in lines]
    path, tpl = rng.choice(_templates(cls, domain))
    plant.path = path
    if tpl.startswith("json:"):
        key = tpl[5:]
        n = 2
        while any(k == key for k, _ in t.flat.get(path, [])):
            key, n = f"{tpl[5:]}{n}", n + 1
        t.flat.setdefault(path, [("schema", "fixtures/v1")] if path.startswith("tests/") else []).append((key, value))
        return plant, [(path, "json:" + key)]
    if tpl.startswith("block"):
        body = value.split("\n")
        if tpl == "block:fenced":
            lines = ["Deploy key (rotate me):", "```", *body, "```"]
        elif tpl == "block:yaml":
            lines = ["  deployKey: |", *["    " + b for b in body]]
        else:
            lines = body
    else:
        lines = [tpl.format(v=value, uri=uri)]
    if path.endswith(".py") and path not in t.text:
        t.add(path, '"""Synthetic module."""')
    t.add(path, *lines)
    return plant, [(path, ln) for ln in lines]


def undo(t: Tree, undo_list: list[tuple[str, str]]) -> None:
    for path, ln in undo_list:
        if ln.startswith("json:") and path in t.flat:
            t.flat[path] = [(k, v) for k, v in t.flat[path] if k != ln[5:]]
        else:
            t.remove(path, ln)


BOUNDARY_KINDS = ["not_utf8", "binary_nul", "encrypted_archive", "zip_archive", "oversized", "utf16"]


def add_boundary(t: Tree, rng: random.Random, with_secret: bool, domain: str) -> list[Plant]:
    """A file the scanner must abstain on. With ``with_secret`` a token is hidden inside it (not covered)."""
    kind = rng.choice(BOUNDARY_KINDS)
    token = fakes.vendor_api_token(rng)
    noise = bytes(rng.randrange(256) for _ in range(rng.randrange(200, 400)))
    if kind == "not_utf8":
        path = "legacy/notes_latin1.txt"
        text = "Caffè e officina: note di migrazione\nvecchio sistema, codifica latin-1\n"
        data = (text + (f"token {token}\n" if with_secret else "")).encode("latin-1")
    elif kind == "binary_nul":
        path = "assets/firmware.bin"
        data = b"\x7fFWSYN\x00\x01" + noise.replace(b"\n", b"\x00") + b"\x00" + (token.encode() if with_secret else b"") + b"\x00"
    elif kind == "encrypted_archive":
        path = "backup/archive.tar.enc"
        data = b"Salted__" + noise  # the secret, if any, is inside the ciphertext: nothing to see
    elif kind == "zip_archive":
        path = "backup/export.zip"
        data = b"PK\x03\x04" + noise
    elif kind == "oversized":
        path = "data/dump.sql"
        row = "INSERT INTO parts VALUES (%d, 'gasket', 12.50);\n"
        body = "".join(row % i for i in range(MAX_FILE_BYTES // 40 + 2000))
        data = (body + (f"-- token {token}\n" if with_secret else "")).encode("ascii")
    else:
        path = "notes/windows_export.txt"
        text = "exported settings\r\n" + (f"NBX_API_TOKEN={token}\r\n" if with_secret else "")
        data = b"\xff\xfe" + text.encode("utf-16-le")
    t.raw[path] = data
    out = [Plant("boundary", kind, path, covered=False, technique="carrier_" + kind)]
    if with_secret:
        out.append(Plant("secret", "vendor_api_token", path, value=token, severity=SEVERITY["vendor_api_token"],
                         covered=False, technique="carrier_" + kind, carrier="head"))
    return out


# ---- config and code defects ------------------------------------------------------------------------------------

def add_config_defect(t: Tree, rng: random.Random, cls: str, domain: str) -> Plant:
    routes, services = t.objs[ROUTES], t.objs[SERVICES]
    sev = CONFIG_DEFECTS[cls]
    by_name = {s["name"]: s for s in services["services"]}
    if cls == "admin_route_without_forward_auth":
        prefix = rng.choice(["/admin", "/internal", "/metrics"])
        name = "admin-public" + prefix.replace("/", "-")
        routes["routers"].append({"name": name, "entrypoint": "public", "host": f"app.{domain}", "path_prefix": prefix,
                                  "middlewares": ["rate-limit"], "service": "admin"})
        return Plant("config", cls, ROUTES, subject=name, severity=sev)
    if cls == "debug_route_public":
        routes["routers"].append({"name": "debug", "entrypoint": "public", "host": f"api.{domain}",
                                  "path_prefix": rng.choice(["/debug", "/_debug"]), "middlewares": ["forward-auth"],
                                  "service": "api"})
        return Plant("config", cls, ROUTES, subject="debug", severity=sev)
    if cls == "forward_auth_trusts_client_headers":
        routes["middlewares"]["forward-auth"]["trust_forward_header"] = True
        return Plant("config", cls, ROUTES, subject="forward-auth", severity=sev)
    if cls == "internal_port_published_on_all_interfaces":
        name = rng.choice(["db", "admin"])
        by_name[name]["published"] = ["0.0.0.0:5432:5432"] if name == "db" else ["0.0.0.0:8443:8443"]
        return Plant("config", cls, SERVICES, subject=name, severity=sev)
    if cls == "runtime_socket_mounted":
        by_name["app"]["mounts"] = ["/var/run/container.sock:/var/run/container.sock"]
        return Plant("config", cls, SERVICES, subject="app", severity=sev)
    if cls == "service_bridges_public_and_data_networks":
        by_name["api"]["networks"] = ["public", "app", "data"]
        return Plant("config", cls, SERVICES, subject="api", severity=sev)
    t.remove("deploy/prod.env", "DEBUG=false")
    t.add("deploy/prod.env", "DEBUG=true")
    return Plant("config", cls, "deploy/prod.env", subject="DEBUG", severity=sev, marker="DEBUG=true")


def add_py_defect(t: Tree, cls: str) -> Plant:
    sev, lines = PY_DEFECTS[cls]
    t.add("src/app.py", "", "", *lines)
    return Plant("pycode", cls, "src/app.py", severity=sev, marker=lines[-1].strip())


# ---- planning -----------------------------------------------------------------------------------------------------

def _weighted(rng: random.Random, table: list[tuple[str, int]]) -> str:
    roll = rng.randrange(sum(w for _, w in table))
    for name, w in table:
        roll -= w
        if roll < 0:
            return name
    raise AssertionError("unreachable")


def plan_repo(seed: int, idx: int, do_perturb: bool = False) -> RepoPlan:
    rng = random.Random(f"noa-corpus/v1/{seed}/repo/{idx}")
    company = COMPANIES[idx % len(COMPANIES)]
    domain = company["domain"]
    project = rng.choice(company["projects"])
    arche = _weighted(rng, ARCHETYPES)
    plan = RepoPlan(f"R{idx:04d}-{company['key']}-{project}", idx, company["key"], arche)
    t = Tree()

    def commit(message: str, parent: int | None = -1, line: str = "main") -> int:
        if parent == -1:
            parent = next((i for i in range(len(plan.commits) - 1, -1, -1) if plan.commits[i].line == "main"), None)
        plan.commits.append(CommitPlan(message, rng.randrange(3), t.snapshot(), parent, line))
        return len(plan.commits) - 1

    base_files(t, company, project)
    kinds = rng.sample(DECOY_KINDS, rng.randrange(3, 8))
    for kind in kinds[:2]:
        plan.plants.append(add_decoy(t, rng, kind, domain))
    commit("Initial import")

    for snippet in rng.sample(PY_DECOYS, rng.randrange(1, 4)):
        t.add("src/app.py", "", "", *snippet)
    for kind in kinds[2:]:
        plan.plants.append(add_decoy(t, rng, kind, domain))
    if arche != "clean":
        if rng.random() < 0.35:
            for cls in rng.sample(sorted(CONFIG_DEFECTS), rng.choice([1, 1, 2])):
                plan.plants.append(add_config_defect(t, rng, cls, domain))
        if rng.random() < 0.35:
            for cls in rng.sample(sorted(PY_DEFECTS), rng.choice([1, 1, 2])):
                plan.plants.append(add_py_defect(t, cls))
    fork = commit("Add deployment configuration and handlers")

    if arche in ("head_secret", "multi"):
        for _ in range(rng.choice([1, 1, 2, 3])):
            plan.plants.append(add_secret(t, rng, domain, "head", do_perturb)[0])
        commit("Wire integrations")
    if arche in ("history_only", "multi"):
        added = [add_secret(t, rng, domain, "history_only", do_perturb) for _ in range(rng.choice([1, 1, 2]))]
        commit("Add credentials for the staging run")
        for plant, undo_list in added:
            plan.plants.append(plant)
            undo(t, undo_list)
        commit("Remove credentials from the tree")
    if arche in ("branch_only", "tag_only"):
        main_state = copy.deepcopy(t)
        plant, _ = add_secret(t, rng, domain, arche, do_perturb)
        plan.plants.append(plant)
        commit("Experiment with a hard-coded credential", parent=fork, line="branch" if arche == "branch_only" else "tag")
        if arche == "branch_only":
            plan.branch = "feature/" + rng.choice(["import-job", "legacy-sync", "quick-fix"])
        else:
            plan.tag = "rc-0." + str(rng.randrange(1, 9))
        t = main_state
    if arche == "dangling":
        main_state = copy.deepcopy(t)
        carrier = rng.choice(["dangling_blob", "unreachable_commit"])
        plant, _ = add_secret(t, rng, domain, carrier, do_perturb)
        plan.plants.append(plant)
        if carrier == "dangling_blob":
            plan.dangling_blobs.append(t.snapshot()[plant.path])  # staged once, never committed
        else:
            commit("Amended away: commit with a credential", parent=fork, line="unreachable")
        t = main_state
    if arche in ("boundary_clean", "boundary_secret"):
        plan.plants.extend(add_boundary(t, rng, arche == "boundary_secret", domain))
        commit("Add legacy material")

    t.add("docs/runbook.md", "3. Verify the health endpoint.")
    commit("Update the runbook")
    plan.plants = [p for p in plan.plants if p is not None]
    return plan


# ---- materialisation and gold -------------------------------------------------------------------------------------

def _locate(data: bytes, plant: Plant) -> int:
    """1-based line of the plant inside ``data`` (0 = not present or not line-addressable)."""
    if plant.technique.startswith("carrier_"):
        return 0
    try:
        lines = data.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        return 0
    if plant.cls == "armored_key_block" and plant.technique in ("plain", "unseen_format"):
        body = plant.value.split("\n")
        for i in range(len(lines) - len(body) + 1):
            if all(body[j] in lines[i + j] for j in range(len(body))):
                return i + 1
        return 0
    if plant.kind == "config" and plant.path.endswith(".json"):
        needle = f'"{plant.subject}": {{' if plant.subject == "forward-auth" else f'"name": "{plant.subject}"'
        return next((i + 1 for i, ln in enumerate(lines) if needle in ln), 0)
    if plant.value and plant.technique in ("plain", "unseen_format"):
        return next((i + 1 for i, ln in enumerate(lines) if plant.value in ln), 0)
    return next((i + 1 for i, ln in enumerate(lines) if ln.strip() == plant.marker), 0)


def _present(data: bytes, plant: Plant) -> bool:
    if plant.technique.startswith("carrier_"):
        return True
    return _locate(data, plant) > 0


def materialise(plan: RepoPlan, out_root: Path) -> Path:
    root = out_root / plan.name
    w = RepoWriter(root)
    base_ts = EPOCH_BASE + plan.index * 3600
    company = next(c for c in COMPANIES if c["key"] == plan.company)
    for i, c in enumerate(plan.commits):
        name, email = author(company, c.author)
        parents = [plan.commit_ids[c.parent]] if c.parent is not None else []
        plan.commit_ids.append(w.commit(w.tree(c.snapshot), parents, name, email, base_ts + i * 5400, TZ, c.message))
    main = [i for i, c in enumerate(plan.commits) if c.line == "main"]
    plan.head = plan.commit_ids[main[-1]]
    plan.refs["refs/heads/main"] = plan.head
    for i, c in enumerate(plan.commits):
        if c.line == "branch":
            plan.refs["refs/heads/" + plan.branch] = plan.commit_ids[i]
        elif c.line == "tag":
            name, email = author(company, c.author)
            plan.refs["refs/tags/" + plan.tag] = w.tag_object(plan.commit_ids[i], plan.tag, name, email,
                                                              base_ts + i * 5400 + 60, TZ, "release candidate")
    for ref, oid in plan.refs.items():
        w.ref(ref, oid)
    for data in plan.dangling_blobs:
        w.blob(data)
    head_snapshot = plan.commits[main[-1]].snapshot
    w.checkout(head_snapshot)

    for p in plan.plants:
        data = head_snapshot.get(p.path)
        p.in_head = data is not None and _present(data, p)
        p.line = _locate(data, p) if p.in_head else 0
        if p.kind not in ("secret", "boundary"):
            continue
        for i, c in enumerate(plan.commits):
            blob = c.snapshot.get(p.path)
            if blob is not None and _present(blob, p):
                p.first_commit, p.first_line, p.blob = plan.commit_ids[i], _locate(blob, p), w.blob(blob)
                break
        else:
            for blob in plan.dangling_blobs:
                if _present(blob, p):
                    p.first_line, p.blob = _locate(blob, p), w.blob(blob)
    plan.object_ids = sorted(w.objects)
    return root
