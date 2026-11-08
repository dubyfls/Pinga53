# SPDX-License-Identifier: AGPL-3.0-only
"""Recovery codes (Order 13 item 5).

Ten one-time codes minted at MFA enrollment or via /account/recovery-codes.
Each code is 16 URL-safe base64 chars from a CSPRNG (~96 bits of entropy).
Stored as argon2 hashes — the same hasher as passwords, per the order.

Verification: on login, iterate the caller's unused codes and argon2-verify.
On a match the row is marked `used_at = now` inside the login transaction so
concurrent reuse is impossible.
"""
from __future__ import annotations
import datetime as dt
import secrets
from typing import Iterable

from backend.db.models import RecoveryCode
from backend.security import auth as _auth


CODES_PER_ENROLLMENT = 10
CODE_LEN = 16
# Alphabet excludes '-' and '_' so format_for_display's hyphen separators
# are the ONLY hyphens in the string. verify_and_consume normalizes on the
# way in by stripping '-'/' '; if a raw code carried its own hyphens, that
# normalization would corrupt it and the verify would always fail.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # skip I,O,0,1 for readability


def _one_code() -> str:
    """CODE_LEN characters from a hyphen-free alphabet with ~80 bits of
    entropy. Grouped 4-4-4-4 for display."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(CODE_LEN))


def format_for_display(code: str) -> str:
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def mint_codes(session, user_id: int) -> list[str]:
    """Delete any existing codes for the user and mint a fresh set. Returns
    the plaintext list — caller must show it exactly once."""
    session.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).delete()
    codes = [_one_code() for _ in range(CODES_PER_ENROLLMENT)]
    for c in codes:
        session.add(RecoveryCode(user_id=user_id, code_hash=_auth.hash_password(c)))
    session.commit()
    return [format_for_display(c) for c in codes]


def verify_and_consume(session, user_id: int, code: str) -> bool:
    """True if `code` matches an unused recovery code; marks it used
    atomically. Accepts either raw or 4-4-4-4 formatted input."""
    normalized = code.replace("-", "").replace(" ", "")
    if not normalized:
        return False
    rows = (
        session.query(RecoveryCode)
        .filter(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        .all()
    )
    for row in rows:
        if _auth.verify_password(normalized, row.code_hash):
            row.used_at = dt.datetime.utcnow()
            session.commit()
            return True
    return False


def remaining(session, user_id: int) -> int:
    return (
        session.query(RecoveryCode)
        .filter(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        .count()
    )
