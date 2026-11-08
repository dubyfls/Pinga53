# SPDX-License-Identifier: AGPL-3.0-only
"""First-run bootstrap for the `administrator` account.

Creates a single admin with a CSPRNG one-time password. Refuses to run if the
account already exists. Returns the plaintext password exactly once — the
caller is responsible for showing it and never storing it. Nothing is logged
except the event name and username; the audit record carries no secret.
"""
from __future__ import annotations
import secrets

from backend import db
from backend.db.models import User
from backend.security.auth import hash_password


MIN_PASSWORD_LEN = 16  # Order 13 rule


class BootstrapError(RuntimeError):
    pass


def _one_time_password(length: int = 20) -> str:
    """URL-safe base64 (CSPRNG) trimmed to the requested length. Avoids
    ambiguous punctuation so the operator can transcribe it if needed."""
    # secrets.token_urlsafe(n) returns ~1.3*n chars; pick n so we clear the min.
    raw = secrets.token_urlsafe(max(length, MIN_PASSWORD_LEN))
    return raw[:max(length, MIN_PASSWORD_LEN)]


def create_bootstrap_admin(audit, username: str = "administrator") -> str:
    """Create the bootstrap admin. Returns the plaintext password."""
    s = db.session()
    try:
        if s.query(User).filter(User.username == username).first():
            raise BootstrapError(f"user '{username}' already exists — bootstrap refused")
        pw = _one_time_password()
        u = User(username=username, pw_hash=hash_password(pw), must_change_password=1)
        s.add(u); s.commit()
    finally:
        s.close()
    audit.record("admin.bootstrap", actor="cli", data={"username": username})
    return pw
