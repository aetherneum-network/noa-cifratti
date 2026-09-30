"""Configuration review on the two synthetic schemas of this pack, driven by ``rules/config.json``.

Understood: ``gateway-routes/v1`` (entrypoints, middlewares, routers), ``services/v1`` (services,
networks, published ports, mounts) and KEY=VALUE environment files. A file that declares one of
the two schemas and cannot be read as such is returned as an error: the caller reports it as
NOT_COVERED, it is never silently skipped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from noascan.rules_engine import RuleError


@dataclass
class Model:
    routers: list[tuple[str, dict]] = field(default_factory=list)            # (path, router)
    middlewares: list[tuple[str, dict]] = field(default_factory=list)        # (path, middleware with "name")
    services: list[tuple[str, dict]] = field(default_factory=list)           # (path, service)
    env: list[tuple[str, int, str, str]] = field(default_factory=list)       # (path, line, key, value)
    errors: list[tuple[str, str]] = field(default_factory=list)              # (path, reason)
    text: dict[str, list[str]] = field(default_factory=dict)                 # path -> lines, to locate subjects


@dataclass(frozen=True)
class ConfigFinding:
    rule: str
    cls: str
    path: str
    line: int
    subject: str


def _is_env(path: str, globs: list[str]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatchcase(name, g) for g in globs)


def parse(files: dict[str, str], rules: dict[str, Any]) -> Model:
    """``files`` maps posix paths to decoded text (only files inside coverage are passed in)."""
    m = Model()
    schemas = rules["schemas"]
    for path in sorted(files):
        text = files[path]
        if _is_env(path, rules["env_globs"]):
            for n, line in enumerate(text.split("\n"), 1):
                s = line.strip()
                if s.startswith("export "):
                    s = s[7:].lstrip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                key, _, value = s.partition("=")
                m.env.append((path, n, key.strip(), value.strip().strip("\"'")))
            continue
        if not path.endswith(".json"):
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            if any(f'"{s}"' in text for s in schemas.values()):
                m.errors.append((path, "config_not_parseable"))
            continue
        if not isinstance(doc, dict) or doc.get("schema") not in schemas.values():
            continue
        m.text[path] = text.split("\n")
        try:
            if doc["schema"] == schemas["routes"]:
                for name, mw in doc.get("middlewares", {}).items():
                    m.middlewares.append((path, dict(mw, name=name)))
                for router in doc.get("routers", []):
                    m.routers.append((path, {"name": str(router["name"]), "entrypoint": str(router["entrypoint"]),
                                             "host": str(router.get("host", "")),
                                             "path_prefix": str(router.get("path_prefix", "/")),
                                             "middlewares": [str(x) for x in router.get("middlewares", [])]}))
            else:
                for svc in doc.get("services", []):
                    m.services.append((path, {"name": str(svc["name"]), "plane": str(svc.get("plane", "")),
                                              "networks": [str(x) for x in svc.get("networks", [])],
                                              "published": [str(x) for x in svc.get("published", [])],
                                              "mounts": [str(x) for x in svc.get("mounts", [])]}))
        except (KeyError, TypeError, AttributeError):
            m.errors.append((path, "config_not_parseable"))
    return m


def published(entry: str) -> tuple[str, str]:
    """``bind:host_port:container_port`` or ``host_port:container_port`` -> (bind, host_port).

    A publication without an explicit bind listens on every interface.
    """
    parts = entry.rsplit(":", 2)
    if len(parts) == 3:
        return parts[0].strip("[]"), parts[1]
    return "0.0.0.0", parts[0]


def _prefix_hit(value: str, prefixes: list[str]) -> bool:
    return any(value == p or value.startswith(p + "/") for p in prefixes)


def matches(rule: dict[str, Any], subject: dict[str, Any]) -> bool:
    when = rule.get("when", {})
    for key, want in when.items():
        if key == "entrypoint":
            ok = subject.get("entrypoint") == want
        elif key == "path_prefix_any":
            ok = _prefix_hit(subject.get("path_prefix", ""), want)
        elif key == "lacks_middleware":
            ok = want not in subject.get("middlewares", [])
        elif key == "type":
            ok = subject.get("type") == want
        elif key == "setting":
            ok = all(subject.get(k) == v and type(subject.get(k)) is type(v) for k, v in want.items())
        elif key == "mount_source_regex":
            ok = any(re.search(want, mount.split(":", 1)[0]) for mount in subject.get("mounts", []))
        elif key == "plane_any":
            ok = subject.get("plane") in want
        elif key == "published_bind_any":
            ok = any(published(p)[0] in want for p in subject.get("published", []))
        elif key == "networks_all":
            ok = all(n in subject.get("networks", []) for n in want)
        elif key == "key":
            ok = subject.get("name") == want
        elif key == "value_in":
            ok = str(subject.get("value", "")).lower() in want
        else:
            raise RuleError(f"config: rule {rule['id']} uses an unknown condition {key!r}")
        if not ok:
            return False
    return True


def decide(target: str, subject: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    """The rules that decide ``subject``: for each aspect, the first rule that matches."""
    decided: dict[str, dict[str, Any]] = {}
    for rule in rules["rules"]:
        if rule.get("target") != target or rule.get("aspect", target) in decided:
            continue
        if matches(rule, subject):
            decided[rule.get("aspect", target)] = rule
    return list(decided.values())


def _line(lines: list[str], needle: str) -> int:
    return next((i + 1 for i, ln in enumerate(lines) if needle in ln), 0)


def review(model: Model, rules: dict[str, Any]) -> list[ConfigFinding]:
    out: list[ConfigFinding] = []

    def emit(target: str, path: str, subject: dict[str, Any], line: int) -> None:
        for rule in decide(target, subject, rules):
            if rule["action"] == "report":
                out.append(ConfigFinding(rule["id"], rule["class"], path, line, subject["name"]))

    for path, router in model.routers:
        emit("route", path, router, _line(model.text[path], f'"name": {json.dumps(router["name"])}'))
    for path, mw in model.middlewares:
        emit("middleware", path, mw, _line(model.text[path], f'{json.dumps(mw["name"])}: {{'))
    for path, svc in model.services:
        emit("service", path, svc, _line(model.text[path], f'"name": {json.dumps(svc["name"])}'))
    for path, line, key, value in model.env:
        emit("env", path, {"name": key, "value": value}, line)
    out.sort(key=lambda f: (f.path, f.line, f.rule, f.subject))
    return out
