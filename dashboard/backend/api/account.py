# SPDX-License-Identifier: AGPL-3.0-only
"""Account routes — password change and MFA setup completion.

The /account/password route is reachable during the forced-first-login flow;
it's how the user clears `must_change_password`. Item 7 extends this router
with self-service MFA reset and recovery-code regeneration.
"""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend import db
from backend.db.models import User, RecoveryCode, is_mfa_enrolled
from backend.security import auth, recovery


class PasswordChangeReq(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=12, max_length=1024)
    totp: str | None = None  # required once the user is MFA-enrolled


class RecoveryRegenReq(BaseModel):
    totp: str = Field(min_length=6, max_length=8)


class MfaResetReq(BaseModel):
    current_password: str = Field(min_length=1)
    totp: str = Field(min_length=6, max_length=8)


def build_router(cfg, audit, current_user) -> APIRouter:
    r = APIRouter(prefix="/api/account", tags=["account"])

    @r.post("/password")
    def change_password(body: PasswordChangeReq, request: Request, who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            u = s.query(User).filter(User.username == who).first()
            if not u:
                raise HTTPException(status_code=401, detail="unknown user")
            if u.disabled_at is not None:
                raise HTTPException(status_code=403, detail="account disabled")
            if not auth.verify_password(body.current_password, u.pw_hash):
                audit.record("account.password.fail", actor=who, ip=ip, reason="bad_current")
                raise HTTPException(status_code=401, detail="current password incorrect")
            # Once the user is enrolled, a live TOTP code is required. During the
            # forced-first-login flow (not yet enrolled) we only ask for the
            # current password — MFA enrollment is the next forced step.
            if is_mfa_enrolled(u):
                if not body.totp or not auth.verify_totp(u.totp_secret, body.totp):
                    audit.record("account.password.fail", actor=who, ip=ip, reason="bad_totp")
                    raise HTTPException(status_code=401, detail="invalid MFA code")
            if body.new_password == body.current_password:
                raise HTTPException(status_code=400, detail="new password must differ from current")
            u.pw_hash = auth.hash_password(body.new_password)
            u.must_change_password = 0
            s.commit()
        finally:
            s.close()
        audit.record("account.password.change", actor=who, ip=ip)
        return {"ok": True}

    @r.get("")
    def account_summary(who: str = Depends(current_user)):
        s = db.session()
        try:
            u = s.query(User).filter(User.username == who).first()
            if not u:
                raise HTTPException(status_code=401)
            return {
                "username": u.username,
                "last_login": u.last_login.isoformat() if u.last_login else None,
                "mfa_enrolled": is_mfa_enrolled(u),
                "disabled": u.disabled_at is not None,
                "recovery_codes_remaining": recovery.remaining(s, u.id),
                "must_change_password": bool(u.must_change_password),
            }
        finally:
            s.close()

    @r.post("/mfa/reset")
    def reset_own_mfa(body: MfaResetReq, request: Request, who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            u = s.query(User).filter(User.username == who).first()
            if not u:
                raise HTTPException(status_code=401)
            if u.disabled_at is not None:
                raise HTTPException(status_code=403, detail="account disabled")
            if not auth.verify_password(body.current_password, u.pw_hash):
                audit.record("account.mfa_reset.fail", actor=who, ip=ip, reason="bad_password")
                raise HTTPException(status_code=401, detail="password incorrect")
            if not u.totp_secret or not auth.verify_totp(u.totp_secret, body.totp):
                audit.record("account.mfa_reset.fail", actor=who, ip=ip, reason="bad_totp")
                raise HTTPException(status_code=401, detail="invalid MFA code")
            u.totp_secret = None
            u.mfa_enrolled_at = None
            u.mfa_pending_secret = None
            u.mfa_pending_expires = None
            u.last_totp_step = None
            s.query(RecoveryCode).filter(RecoveryCode.user_id == u.id).delete()
            s.commit()
        finally:
            s.close()
        audit.record("account.mfa_reset", actor=who, ip=ip)
        return {"ok": True, "next": "/setup/mfa"}

    @r.post("/recovery-codes")
    def regen_recovery_codes(body: RecoveryRegenReq, request: Request, who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            u = s.query(User).filter(User.username == who).first()
            if not u:
                raise HTTPException(status_code=401)
            if u.disabled_at is not None:
                raise HTTPException(status_code=403, detail="account disabled")
            if not u.totp_secret:
                raise HTTPException(status_code=400, detail="MFA not enrolled")
            if not auth.verify_totp(u.totp_secret, body.totp):
                audit.record("account.recovery.regen.fail", actor=who, ip=ip, reason="bad_totp")
                raise HTTPException(status_code=401, detail="invalid MFA code")
            codes = recovery.mint_codes(s, u.id)
        finally:
            s.close()
        audit.record("account.recovery.regen", actor=who, ip=ip, data={"issued": len(codes)})
        return {"recovery_codes": codes}

    return r
