"""Stress perturbations: the same planted secrets, hidden the way a hurried hand would hide them.

Used only with ``corpus/generate.py --perturb`` (the stress suite). Each technique states whether the
result is still inside the coverage declared in COVERAGE.md:

* ``unseen_format``  - the value is contiguous plain text in a file type the dev corpus never uses.
  Self-identifying classes (vendor formats, key blocks, connection URIs) stay COVERED; an
  ``assigned_password`` is covered only in the three assignment forms COVERAGE.md lists.
* everything else (split over lines, concatenated, base64, hex, reversed, percent-encoded) is NOT
  covered: the scanner may raise a suspect, but it promises nothing.
"""
from __future__ import annotations

import base64
import random

TECHNIQUES = ["unseen_format", "unseen_format", "split_lines", "concat_same_line", "base64", "hex", "reversed",
              "percent_encoded"]


def _unseen(rng: random.Random, cls: str, value: str, uri: str) -> tuple[str, list[str], bool]:
    shown = uri or value
    if cls == "armored_key_block":
        body = value.split("\n")
        return "deploy/settings.xml", ["<settings>", "  <deployKey><![CDATA[", *body, "  ]]></deployKey>", "</settings>"], True
    fmt = rng.choice(["xml", "csv", "tfvars", "notebook", "containerfile"])
    if fmt == "xml":
        # key="value": one of the listed assignment forms, so a password is still covered here
        return "deploy/settings.xml", [f"<credential name=\"deploy\" password=\"{shown}\"/>"], True
    if fmt == "csv":
        return "ops/inventory.csv", [f"deploy,{shown},2026-09-30"], cls != "assigned_password"
    if fmt == "tfvars":
        return "infra/main.tfvars", [f"admin_password = \"{shown}\""], True
    if fmt == "notebook":
        # a JSON string holding code: the quotes around the value are escaped
        return "notebooks/explore.ipynb", [f"   \"source\": [\"PASSWORD = \\\"{shown}\\\"\\n\"]"], cls != "assigned_password"
    return "Containerfile", [f"ENV DB_PASSWORD {shown}"], cls != "assigned_password"


def render(rng: random.Random, cls: str, value: str, uri: str, domain: str) -> tuple[str, list[str], str, bool]:
    """Return (path, lines, technique, covered)."""
    technique = rng.choice(TECHNIQUES)
    n = rng.randrange(1000, 10000)  # keeps the first line of each rendering unique inside a file
    flat = (uri or value).replace("\n", "\\n")
    if technique == "unseen_format":
        path, lines, covered = _unseen(rng, cls, value, uri)
        return path, lines, technique, covered
    if technique == "split_lines":
        half = len(flat) // 2
        return "src/obfuscated.py", [f"PART_{n} = (", f"    \"{flat[:half]}\"", f"    \"{flat[half:]}\"", ")"], technique, False
    if technique == "concat_same_line":
        cut = rng.randrange(4, max(5, len(flat) - 4))
        return "src/obfuscated.py", [f"JOINED_{n} = \"{flat[:cut]}\" + \"{flat[cut:]}\""], technique, False
    if technique == "base64":
        enc = base64.b64encode((uri or value).encode("utf-8")).decode("ascii")
        return "deploy/cache.env", [f"CACHE_SEED_{n}={enc}"], technique, False
    if technique == "hex":
        return "deploy/cache.env", [f"CACHE_SALT_{n}={(uri or value).encode('utf-8').hex()}"], technique, False
    if technique == "reversed":
        return "deploy/cache.env", [f"PAYLOAD_{n}={flat[::-1]}"], technique, False
    enc = "".join(f"%{b:02X}" for b in (uri or value).encode("utf-8"))
    return "docs/runbook.md", [f"Callback: https://hooks.{domain}/in?k={enc}"], technique, False
