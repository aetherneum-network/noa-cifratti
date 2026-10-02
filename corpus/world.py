"""The fictitious world of the corpus: three invented companies on ``.example`` domains.

Authors are role accounts, not persons. No name, address or host here refers to anything real.
"""
from __future__ import annotations

COMPANIES = [
    {"key": "brennero", "name": "Officina Brennero S.r.l.", "domain": "officina-brennero.example",
     "projects": ["workshop-orders", "parts-catalog", "bench-scheduler", "invoice-gateway"],
     "team": [("Brennero Dev A", "dev-a"), ("Brennero Dev B", "dev-b"), ("Brennero Ops", "ops")]},
    {"key": "lunaria", "name": "Studio Cartografico Lunaria", "domain": "lunaria-carto.example",
     "projects": ["tile-server", "survey-intake", "atlas-export", "layer-registry"],
     "team": [("Lunaria Dev A", "dev-a"), ("Lunaria Dev B", "dev-b"), ("Lunaria Ops", "ops")]},
    {"key": "arvale", "name": "Cooperativa Tessile Arvale", "domain": "arvale-tessile.example",
     "projects": ["loom-telemetry", "yarn-inventory", "members-portal", "dye-batches"],
     "team": [("Arvale Dev A", "dev-a"), ("Arvale Dev B", "dev-b"), ("Arvale Ops", "ops")]},
]

BY_KEY = {c["key"]: c for c in COMPANIES}

# 2026-09-01T09:00:00+02:00 - every generated commit and transcript is dated from here, never from the clock.
EPOCH_BASE = 1788246000
TZ = "+0200"


def author(company: dict, i: int) -> tuple[str, str]:
    name, local = company["team"][i % len(company["team"])]
    return name, f"{local}@{company['domain']}"
