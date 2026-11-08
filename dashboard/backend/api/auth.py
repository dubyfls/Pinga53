# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 auth API — login / logout / me.

Login verifies Argon2 password, then TOTP if the user has a secret (or if MFA is
required). Every attempt is audited (success and failure). No account creation
here — admins are provisioned via `pinga53d create-admin` only.
"""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel

from backend import db
from backend.db.models import User
from backend.security import auth
from backend.security import totp_ratelimit


class LoginReq(BaseModel):
    username: str
    password: str
    totp: str | None = None
    recovery_code: str | None = None


def build_router(cfg, audit, current_user) -> APIRouter:
    r = APIRouter(prefix="/api/auth", tags=["auth"])

    @r.post("/login")
    def login(body: LoginReq, request: Request):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            user = s.query(User).filter(User.username == body.username).first()
            # constant-ish work even if user missing (avoid trivial enumeration)
            ok_pw = auth.verify_password(body.password, user.pw_hash) if user else auth.verify_password(body.password, auth.hash_password("x"))
            if not user or not ok_pw:
                audit.record("auth.login.fail", actor=body.username, ip=ip, reason="bad_credentials")
                raise HTTPException(status_code=401, detail="invalid credentials")
            if user.disabled_at is not None:
                audit.record("auth.login.fail", actor=user.username, ip=ip, reason="disabled")
                raise HTTPException(status_code=403, detail="account disabled")

            # Users mid-first-login (must_change_password, or MFA required but not
            # yet enrolled) get a token so they can drive the forced-flow routes;
            # the ForcedFlowGate blocks everything else server-side.
            in_forced_flow = bool(user.must_change_password) or (
                cfg.require_mfa and user.totp_secret is None and user.mfa_enrolled_at is None
            )

            needs_totp = bool(user.totp_secret)
            if needs_totp:
                from backend.security import recovery
                lock = totp_ratelimit.remaining_lockout_seconds(user.username)
                if lock > 0:
                    audit.record("auth.login.fail", actor=user.username, ip=ip,
                                 reason="totp_locked", data={"retry_in_s": lock})
                    raise HTTPException(
                        status_code=429,
                        detail=f"too many MFA failures, try again in {lock} seconds",
                    )
                if body.recovery_code:
                    if not recovery.verify_and_consume(s, user.id, body.recovery_code):
                        totp_ratelimit.record_failure(user.username)
                        audit.record("auth.login.fail", actor=user.username, ip=ip, reason="bad_recovery")
                        raise HTTPException(status_code=401, detail="invalid recovery code")
                    audit.record("auth.recovery_used", actor=user.username, ip=ip,
                                 data={"remaining": recovery.remaining(s, user.id)})
                    totp_ratelimit.reset(user.username)
                elif not body.totp:
                    totp_ratelimit.record_failure(user.username)
                    audit.record("auth.login.fail", actor=user.username, ip=ip, reason="bad_totp")
                    raise HTTPException(status_code=401, detail="invalid MFA code")
                else:
                    ok, step = auth.verify_totp_no_replay(
                        user.totp_secret, body.totp, user.last_totp_step
                    )
                    if not ok:
                        totp_ratelimit.record_failure(user.username)
                        audit.record("auth.login.fail", actor=user.username, ip=ip, reason="bad_totp")
                        raise HTTPException(status_code=401, detail="invalid MFA code")
                    user.last_totp_step = step
                    totp_ratelimit.reset(user.username)
            elif cfg.require_mfa and not in_forced_flow:
                # Old path: MFA required, enrolled state unknown; block.
                audit.record("auth.login.fail", actor=user.username, ip=ip, reason="mfa_required_not_enrolled")
                raise HTTPException(status_code=403, detail="MFA required — contact administrator to enable enrollment")

            user.last_login = dt.datetime.now(dt.timezone.utc)
            s.commit()
            token = auth.issue_token(user.username, cfg.secret_key, cfg.jwt_ttl_min)
            audit.record("auth.login.ok", actor=user.username, ip=ip)
            return {"token": token, "user": user.username, "ttl_min": cfg.jwt_ttl_min}
        finally:
            s.close()

    @r.post("/logout")
    def logout(request: Request, who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        audit.record("auth.logout", actor=who, ip=ip)
        return {"ok": True}  # stateless JWT: client discards token

    @r.get("/me")
    def me(who: str = Depends(current_user)):
        return {"user": who}

    return r
