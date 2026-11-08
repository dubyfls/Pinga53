# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 auth core — Argon2 passwords, JWT sessions, TOTP with replay guard.

No plaintext ever stored. Tokens are signed with PINGA53_SECRET_KEY. The
get_current_user dependency gates every protected route; missing/invalid token
=> 401 (fail closed).
"""
from __future__ import annotations
import datetime as dt
import hmac
import time
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import jwt, JWTError
import pyotp

_pw = CryptContext(schemes=["argon2"], deprecated="auto")
_bearer = HTTPBearer(auto_error=False)
_ALGO = "HS256"
TOTP_STEP_SECONDS = 30
TOTP_WINDOW = 1  # ±1 step tolerance (Order 13 item 6)


def hash_password(pw: str) -> str:
    return _pw.hash(pw)


def verify_password(pw: str, pw_hash: str) -> bool:
    try:
        return _pw.verify(pw, pw_hash)
    except Exception:
        return False


def verify_totp(secret: str, code: str) -> bool:
    """Legacy path used by tests / MFA enrollment. Enforces the ±1 window and
    a constant-time comparison but does NOT do replay protection. Use
    verify_totp_no_replay for login."""
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=TOTP_WINDOW)
    except Exception:
        return False


def verify_totp_no_replay(secret: str, code: str, last_step: int | None,
                          now_ts: float | None = None) -> tuple[bool, int | None]:
    """Return (ok, matched_step). ok=True only if the code verifies AND its
    step is strictly greater than last_step. Uses hmac.compare_digest for
    the equality check so timing does not leak the step."""
    if not secret or not code:
        return False, None
    now = now_ts if now_ts is not None else time.time()
    current = int(now // TOTP_STEP_SECONDS)
    try:
        totp = pyotp.TOTP(secret)
        for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            step = current + offset
            expected = totp.at(for_time=step * TOTP_STEP_SECONDS)
            if hmac.compare_digest(expected, code.strip()):
                if last_step is not None and step <= last_step:
                    return False, step  # replay
                return True, step
    except Exception:
        return False, None
    return False, None


def new_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=f"Pinga53 ({username})", issuer_name="Pinga53")


def issue_token(username: str, secret_key: str, ttl_min: int) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {"sub": username, "iat": now, "exp": now + dt.timedelta(minutes=ttl_min)}
    return jwt.encode(claims, secret_key, algorithm=_ALGO)


def decode_token(token: str, secret_key: str) -> dict:
    return jwt.decode(token, secret_key, algorithms=[_ALGO])


def make_current_user_dep(secret_key: str):
    """Build the dependency bound to this app's secret key."""
    async def current_user(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> str:
        if creds is None:
            raise HTTPException(status_code=401, detail="auth required")
        try:
            payload = decode_token(creds.credentials, secret_key)
            return payload["sub"]
        except (JWTError, KeyError):
            raise HTTPException(status_code=401, detail="invalid or expired token")
    return current_user
