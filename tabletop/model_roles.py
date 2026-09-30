"""Optional hook: tabletop roles played by a language model. DISABLED, and empty.

No model is called anywhere in this pack: not at run time, not in the tests, not in the scenarios.
This module only records the boundary decided for a possible later version:

* the hook is off by default and there is no environment variable or flag that turns it on;
* if it is ever implemented, only the two models below may be named;
* v2.0 ships no client and no network code, so even an explicit call fails.
"""
from __future__ import annotations

ENABLED = False
ALLOWED_MODELS = ("claude-opus-5-5", "claude-fable-5-1")


def role_player(model: str, role: str) -> None:
    if model not in ALLOWED_MODELS:
        raise ValueError("model not allowed for tabletop roles")
    if not ENABLED:
        raise RuntimeError("model-played roles are disabled in this pack: use the scripted runner")
    raise NotImplementedError("v2.0 ships no model client")
