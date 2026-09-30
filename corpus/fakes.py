"""Inert synthetic credentials and decoys, generated from a seeded ``random.Random``.

Nothing produced here belongs to a real provider account. The vendor formats are invented for this
pack (see SYNTHETIC.md) and carry the letters ``syn`` in their fixed prefix so that a reader - and a
hosting platform's secret scanner - can tell on sight that they are test strings:

    vendor_api_token        nbxsyn_tk_   + 32 chars [a-z2-7]        ("Nimbux", invented)
    vendor_test_key         nbxsyn_test_ + 24 chars [a-z2-7]        ("Nimbux", invented)
    vendor_payment_key      QPSYN + four groups of 6 [A-Z2-9], dashes   ("Quillpay", invented)
    vendor_webhook_secret   hvnsyn_      + 36 chars [A-Za-z0-9]     ("Harborvane", invented)
    armored_key_block       BEGIN/END "SYNTHETIC KEYBLOCK" armour lines around four lines of Base64
    assigned_password       14-20 chars, mixed case, digit and one of + _ -
    connection_uri_password nbxdb://user:<password>@db.<company>.example:5432/<db>   (invented scheme)

The values are never stored in this repository: they exist only inside generated corpora under
``build/`` and inside the two scenario inputs listed in ``rules/allowlist.json``.
"""
from __future__ import annotations

import base64
import random
import string

B32 = "abcdefghijklmnopqrstuvwxyz234567"
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
B62 = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
PW_BODY = string.ascii_letters + string.digits + "+_-"

_DASHES = "-" * 5          # built from parts so that this source file does not itself hold an armour line
BLOCK_BEGIN = _DASHES + "BEGIN SYNTHETIC KEYBLOCK" + _DASHES
BLOCK_END = _DASHES + "END SYNTHETIC KEYBLOCK" + _DASHES

SECRET_CLASSES = ("vendor_api_token", "vendor_test_key", "vendor_payment_key", "vendor_webhook_secret",
                  "armored_key_block", "assigned_password", "connection_uri_password")


def _pick(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def vendor_api_token(rng: random.Random) -> str:
    return "nbxsyn_tk_" + _pick(rng, B32, 32)


def vendor_test_key(rng: random.Random) -> str:
    return "nbxsyn_test_" + _pick(rng, B32, 24)


def vendor_payment_key(rng: random.Random) -> str:
    return "QPSYN" + "".join("-" + _pick(rng, UPPER, 6) for _ in range(4))


def vendor_webhook_secret(rng: random.Random) -> str:
    return "hvnsyn_" + _pick(rng, B62, 36)


def password(rng: random.Random) -> str:
    """14-20 characters, first and last alphanumeric, at least one upper, lower, digit and symbol."""
    n = rng.randrange(14, 21)
    inner = [rng.choice(string.ascii_uppercase), rng.choice(string.ascii_lowercase), rng.choice(string.digits),
             rng.choice("+_-")] + [rng.choice(PW_BODY) for _ in range(n - 6)]
    rng.shuffle(inner)
    return rng.choice(string.ascii_letters) + "".join(inner) + rng.choice(string.digits)


def armored_key_block(rng: random.Random) -> str:
    body = [base64.b64encode(bytes(rng.randrange(256) for _ in range(36))).decode("ascii") for _ in range(4)]
    return "\n".join([BLOCK_BEGIN, *body, BLOCK_END])


def connection_uri(rng: random.Random, domain: str) -> tuple[str, str]:
    """Return (uri, password). Only the password is the secret; the scheme is invented."""
    pw = password(rng)
    user = rng.choice(["app_rw", "svc_orders", "report_ro", "migrator"])
    db = rng.choice(["app", "orders", "ledger", "maps"])
    return f"nbxdb://{user}:{pw}@db.{domain}:5432/{db}", pw


def make(cls: str, rng: random.Random, domain: str = "corp.example") -> str:
    """The secret VALUE of a class (for connection_uri_password: the password, not the whole URI)."""
    if cls == "connection_uri_password":
        return connection_uri(rng, domain)[1]
    return {"vendor_api_token": vendor_api_token, "vendor_test_key": vendor_test_key,
            "vendor_payment_key": vendor_payment_key, "vendor_webhook_secret": vendor_webhook_secret,
            "armored_key_block": armored_key_block, "assigned_password": password}[cls](rng)


# ---- decoys: strings that look secret-like and are not credentials -------------------------------------------

def sha256_hex(rng: random.Random) -> str:
    return _pick(rng, HEX, 64)


def sha1_hex(rng: random.Random) -> str:
    return _pick(rng, HEX, 40)


def uuid4(rng: random.Random) -> str:
    h = _pick(rng, HEX, 32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{rng.choice('89ab')}{h[17:20]}-{h[20:]}"


def public_id(rng: random.Random) -> str:
    """Publishable identifier of the invented vendor: meant to be public, not a secret."""
    return "nbxsyn_pub_" + _pick(rng, B32, 24)


def data_uri(rng: random.Random) -> str:
    raw = bytes(rng.randrange(256) for _ in range(rng.randrange(240, 420)))
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


def integrity_hash(rng: random.Random) -> str:
    return "sha512-" + base64.b64encode(bytes(rng.randrange(256) for _ in range(64))).decode("ascii")
