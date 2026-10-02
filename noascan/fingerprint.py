"""The only form in which a finding's value may leave the scanner.

A fingerprint is a domain-separated, truncated SHA-256. It lets two reports be compared and a gold
label be matched without the value ever being written. Limit, stated plainly: it is unsalted, so a
*guessable* value (a dictionary password) can be confirmed by someone who already suspects it. For
the inert synthetic values of this pack that is irrelevant; for real use a keyed hash would be needed.
"""
from __future__ import annotations

import hashlib


def fingerprint(value: str) -> str:
    return hashlib.sha256(b"noascan/fp/v1\x00" + value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def block_fingerprint(lines: list[str]) -> str:
    """Key blocks are fingerprinted on their stripped lines, so indentation does not change identity."""
    return fingerprint("\n".join(line.strip() for line in lines))
