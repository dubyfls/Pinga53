# SPDX-License-Identifier: AGPL-3.0-only
"""MFA enrollment endpoints (Order 13 item 4).

GET /api/setup/mfa   - start (or resume, if the pending secret is still valid)
                       enrollment. Returns the secret in 4-character blocks for
                       manual entry, a server-rendered SVG QR code, and the
                       expiry of the pending secret. The pending secret is
                       kept in `users.mfa_pending_secret` for 10 minutes.
POST /api/setup/mfa  - confirm enrollment by submitting a current 6-digit code.
                       On success we promote `mfa_pending_secret` → `totp_secret`,
                       stamp `mfa_enrolled_at`, and clear the pending fields.
                       (Recovery codes are added by Item 5.)

The routes are reachable during the forced-enrollment flow (they're on the
gate's allow-list). Everything is scoped to the caller's own account.
"""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import pyotp

from backend import db
from backend.db.models import User, is_mfa_enrolled
from backend.security import auth as _auth


PENDING_TTL = dt.timedelta(minutes=10)
ISSUER = "Pinga53"


class MfaConfirmReq(BaseModel):
    code: str = Field(min_length=6, max_length=8)


def _fmt_secret(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def _qr_svg(uri: str) -> str:
    """Render the provisioning URI as an inline SVG. Raises ImportError if
    segno is not installed; the caller turns that into a 500."""
    import segno
    from io import BytesIO
    qr = segno.make(uri, error="m")
    buf = BytesIO()
    qr.save(buf, kind="svg", xmldecl=False, svgns=True, scale=6, border=4, omitsize=True)
    return buf.getvalue().decode("utf-8")


def _provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=f"{ISSUER} ({username})", issuer_name=ISSUER)


def build_router(cfg, audit, current_user) -> APIRouter:
    r = APIRouter(prefix="/api/setup", tags=["setup"])

    @r.get("/mfa")
    def start(who: str = Depends(current_user)):
        now = dt.datetime.utcnow()
        s = db.session()
        try:
            u = s.query(User).filter(User.username == who).first()
            if not u:
                raise HTTPException(status_code=401, detail="unknown user")
            if u.disabled_at is not None:
                raise HTTPException(status_code=403, detail="account disabled")
            if is_mfa_enrolled(u):
                raise HTTPException(status_code=400, detail="MFA already enrolled")
            if (not u.mfa_pending_secret) or (
                u.mfa_pending_expires is not None and u.mfa_pending_expires <= now
            ):
                u.mfa_pending_secret = _auth.new_totp_secret()
                u.mfa_pending_expires = now + PENDING_TTL
                s.commit()
            secret = u.mfa_pending_secret
            expires = u.mfa_pending_expires
        finally:
            s.close()

        uri = _provisioning_uri(secret, who)
        try:
            svg = _qr_svg(uri)
        except ImportError:
            raise HTTPException(status_code=500, detail="QR renderer missing on server (install segno)")

        return {
            "secret_blocks": _fmt_secret(secret),
            "qr_svg": svg,
            "expires_at": expires.isoformat(),
            "otpauth_uri": uri,
        }

    @r.post("/mfa")
    def confirm(body: MfaConfirmReq, request: Request, who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        now = dt.datetime.utcnow()
        s = db.session()
        try:
            u = s.query(User).filter(User.username == who).first()
            if not u:
                raise HTTPException(status_code=401, detail="unknown user")
            if u.disabled_at is not None:
                raise HTTPException(status_code=403, detail="account disabled")
            if is_mfa_enrolled(u):
                raise HTTPException(status_code=400, detail="MFA already enrolled")
            if (not u.mfa_pending_secret) or (
                u.mfa_pending_expires is not None and u.mfa_pending_expires <= now
            ):
                raise HTTPException(status_code=400, detail="no active enrollment — restart /setup/mfa")
            if not _auth.verify_totp(u.mfa_pending_secret, body.code):
                audit.record("mfa.enroll.fail", actor=who, ip=ip, reason="bad_code")
                raise HTTPException(status_code=401, detail="invalid code")
            u.totp_secret = u.mfa_pending_secret
            u.mfa_enrolled_at = now
            u.mfa_pending_secret = None
            u.mfa_pending_expires = None
            # anchor replay-protection floor at the current step (item 6 uses it)
            u.last_totp_step = int(now.timestamp() // 30)
            s.commit()
        finally:
            s.close()
        from backend.security import recovery
        s2 = db.session()
        try:
            u2 = s2.query(User).filter(User.username == who).first()
            codes = recovery.mint_codes(s2, u2.id)
        finally:
            s2.close()
        audit.record("mfa.enroll.ok", actor=who, ip=ip, data={"recovery_codes_issued": len(codes)})
        return {"ok": True, "recovery_codes": codes}

    return r
