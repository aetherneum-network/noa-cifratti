"""Before/after pairs of a patch, with the expected change of the exposed surface.

Surface item identifiers (the same convention is documented in ``rules/surface.json``):

    route:<host><path_prefix>        a router on the public entrypoint
    port:<service>:<bind>:<port>     a published port on a non-private bind
    socket:<service>                 a container-runtime socket mounted into a service
    debugflag:<path>                 DEBUG enabled in an environment file
    secret:<path>#<fingerprint>      a covered secret in the tree

A route that loses its forward-auth middleware is *weakened*; one that gains it is *strengthened*.
``delta = added + weakened - removed - strengthened``.
"""
from __future__ import annotations

import copy
import json
import random
from pathlib import Path

from corpus import fakes
from corpus.gold import fingerprint
from corpus.repos import ROUTES, SERVICES, Tree, base_config
from corpus.world import COMPANIES

GROW = ["add_public_route", "add_debug_route", "publish_port", "mount_socket", "add_secret", "enable_debug_flag",
        "remove_auth"]
SHRINK = ["remove_route", "add_auth", "unpublish_port", "remove_secret"]
NEUTRAL = ["edit_readme", "change_replicas", "reorder_routers", "rename_middleware_setting"]


def _router(name: str, host: str, prefix: str, auth: bool, service: str = "app") -> dict:
    return {"name": name, "entrypoint": "public", "host": host, "path_prefix": prefix,
            "middlewares": ["forward-auth"] if auth else ["rate-limit"], "service": service}


def build(seed: int, idx: int) -> tuple[dict[str, bytes], dict[str, bytes], dict]:
    rng = random.Random(f"noa-corpus/v1/{seed}/patch/{idx}")
    company = COMPANIES[idx % len(COMPANIES)]
    domain = company["domain"]
    host = f"app.{domain}"
    t = Tree()
    t.add("README.md", f"# patch fixture {idx:03d}", "", f"{company['name']} (fictitious).")
    t.add("deploy/values.yml", "app:", "  replicas: 2")
    t.add("deploy/prod.env", "LOG_LEVEL=warn", "DEBUG=false")
    routes, services = base_config(domain)
    t.objs[ROUTES], t.objs[SERVICES] = routes, services
    by_name = {s["name"]: s for s in services["services"]}

    # pre-existing items, so that a patch has something to remove or strengthen
    routes["routers"].append(_router("legacy", host, "/legacy", False))
    routes["routers"].append(_router("portal", host, "/portal", True))
    routes["routers"].append(_router("reports-old", host, "/reports-old", False))
    pre_secret = ""
    if rng.random() < 0.5:
        by_name["db"]["published"] = ["0.0.0.0:5432:5432"]
    if rng.random() < 0.5:
        pre_secret = fakes.vendor_api_token(rng)
        t.add("deploy/prod.env", f"NBX_API_TOKEN={pre_secret}")
    before = t.snapshot()

    kind = rng.choice(["grow", "grow", "shrink", "neutral", "mixed", "mixed"])
    n = rng.choice([1, 1, 2])
    pool = {"grow": GROW, "shrink": SHRINK, "neutral": NEUTRAL, "mixed": GROW + SHRINK + NEUTRAL}[kind]
    ops = rng.sample(pool, min(n if kind != "mixed" else n + 1, len(pool)))
    added, removed, weakened, strengthened, done = [], [], [], [], []
    t = copy.deepcopy(t)
    routes, services = t.objs[ROUTES], t.objs[SERVICES]
    by_name = {s["name"]: s for s in services["services"]}
    for op in ops:
        if op == "add_public_route":
            routes["routers"].append(_router("reports", host, "/reports", rng.random() < 0.5))
            added.append(f"route:{host}/reports")
        elif op == "add_debug_route":
            routes["routers"].append(_router("debug", host, "/debug", False))
            added.append(f"route:{host}/debug")
        elif op == "publish_port":
            by_name["admin"]["published"] = ["0.0.0.0:8443:8443"]
            added.append("port:admin:0.0.0.0:8443")  # the previous publication on the private bind was no item
        elif op == "mount_socket":
            by_name["app"]["mounts"] = ["/var/run/container.sock:/var/run/container.sock"]
            added.append("socket:app")
        elif op == "add_secret":
            value = fakes.password(rng)
            t.add("deploy/prod.env", f"SMTP_PASSWORD={value}")
            added.append(f"secret:deploy/prod.env#{fingerprint(value)}")
        elif op == "enable_debug_flag":
            t.remove("deploy/prod.env", "DEBUG=false")
            t.add("deploy/prod.env", "DEBUG=true")
            added.append("debugflag:deploy/prod.env")
        elif op == "remove_auth":
            next(r for r in routes["routers"] if r["name"] == "portal")["middlewares"] = ["rate-limit"]
            weakened.append(f"route:{host}/portal")
        elif op == "remove_route":
            routes["routers"] = [r for r in routes["routers"] if r["name"] != "legacy"]
            removed.append(f"route:{host}/legacy")
        elif op == "add_auth":
            next(r for r in routes["routers"] if r["name"] == "reports-old")["middlewares"] = ["forward-auth"]
            strengthened.append(f"route:{host}/reports-old")
        elif op == "unpublish_port":
            if by_name["db"]["published"]:
                by_name["db"]["published"] = []
                removed.append("port:db:0.0.0.0:5432")
            else:
                continue
        elif op == "remove_secret":
            if pre_secret:
                t.remove("deploy/prod.env", f"NBX_API_TOKEN={pre_secret}")
                removed.append(f"secret:deploy/prod.env#{fingerprint(pre_secret)}")
            else:
                continue
        elif op == "edit_readme":
            t.add("README.md", "", "Reviewed on 2026-09-30.")
        elif op == "change_replicas":
            t.remove("deploy/values.yml", "  replicas: 2")
            t.add("deploy/values.yml", "  replicas: 3")
        elif op == "reorder_routers":
            routes["routers"] = list(reversed(routes["routers"]))
        elif op == "rename_middleware_setting":
            routes["middlewares"]["rate-limit"]["average"] = 80
        done.append(op)
    after = t.snapshot()
    delta = len(added) + len(weakened) - len(removed) - len(strengthened)
    gate = "BLOCKED" if delta > 0 else "NEEDS_REVIEW" if (added or weakened) else "PASS"
    gold = {"pair": f"P{idx:03d}", "company": company["key"], "ops": done, "added": sorted(added),
            "removed": sorted(removed), "weakened": sorted(weakened), "strengthened": sorted(strengthened),
            "delta": delta, "expected_gate": gate}
    return before, after, gold


def write_tree(files: dict[str, bytes], root: Path) -> None:
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)


def dumps(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)
