# SPDX-License-Identifier: AGPL-3.0-only
"""Admin dashboard routes (Order 13 item 10).

Admins-only. Every action requires the caller's own live TOTP code in the
request body so a stolen session cookie still can't be used to reset MFA
or lock accounts. Create-admin stays CLI-only for now.

TOTP replay guard: the same guard used at login (verify_totp_no_replay
against `users.last_totp_step`) also applies to every mutation route.
A code that logged you in cannot be replayed to authorize an admin
mutation; the caller must present a code from a later 30 s step.

Admin resolution: the seeded `administrator` account is the sole admin
today. `_is_admin` is a helper so a future schema change (an `is_admin`
column) can drop in without touching the route logic.
"""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend import db
from backend.db.models import User, RecoveryCode, is_mfa_enrolled
from backend.security import auth as _auth
from backend.security.bootstrap import _one_time_password


ADMIN_USERNAMES = {"administrator"}


def _is_admin(username: str) -> bool:
    return username in ADMIN_USERNAMES


class AdminActionReq(BaseModel):
    totp: str = Field(min_length=6, max_length=8)


def build_router(cfg, audit, current_user) -> APIRouter:
    r = APIRouter(prefix="/api/admin", tags=["admin"])

    def _require_admin_with_totp(session, who: str, totp: str) -> User:
        if not _is_admin(who):
            raise HTTPException(status_code=403, detail="admin only")
        me = session.query(User).filter(User.username == who).first()
        if not me or me.disabled_at is not None:
            raise HTTPException(status_code=403, detail="admin unavailable")
        if not me.totp_secret:
            raise HTTPException(status_code=401, detail="invalid MFA code")
        ok, step = _auth.verify_totp_no_replay(
            me.totp_secret, totp, me.last_totp_step
        )
        if not ok:
            raise HTTPException(status_code=401, detail="invalid MFA code")
        # Persist the step *before* the mutation runs so the replay guard
        # advances even if the mutation itself later raises (target not
        # found, cannot-disable-self, etc).
        me.last_totp_step = step
        session.commit()
        return me

    @r.get("/users")
    def list_users(who: str = Depends(current_user)):
        s = db.session()
        try:
            if not _is_admin(who):
                raise HTTPException(status_code=403, detail="admin only")
            rows = []
            for u in s.query(User).order_by(User.username).all():
                rows.append({
                    "username": u.username,
                    "mfa_enrolled": is_mfa_enrolled(u),
                    "disabled": u.disabled_at is not None,
                    "last_login": u.last_login.isoformat() if u.last_login else None,
                    "must_change_password": bool(u.must_change_password),
                })
            return {"users": rows}
        finally:
            s.close()

    @r.post("/users/{username}/password")
    def set_temp_password(username: str, body: AdminActionReq, request: Request,
                           who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            _require_admin_with_totp(s, who, body.totp)
            target = s.query(User).filter(User.username == username).first()
            if not target:
                raise HTTPException(status_code=404, detail="user not found")
            pw = _one_time_password()
            target.pw_hash = _auth.hash_password(pw)
            target.must_change_password = 1
            s.commit()
        finally:
            s.close()
        audit.record("admin.set_password.temp", actor=who, ip=ip,
                     data={"target": username, "must_change_password": True})
        # The one-time password is returned to the admin's browser exactly once.
        return {"username": username, "temp_password": pw}

    @r.post("/users/{username}/mfa/reset")
    def reset_target_mfa(username: str, body: AdminActionReq, request: Request,
                          who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            _require_admin_with_totp(s, who, body.totp)
            target = s.query(User).filter(User.username == username).first()
            if not target:
                raise HTTPException(status_code=404, detail="user not found")
            target.totp_secret = None
            target.mfa_enrolled_at = None
            target.mfa_pending_secret = None
            target.mfa_pending_expires = None
            target.last_totp_step = None
            s.query(RecoveryCode).filter(RecoveryCode.user_id == target.id).delete()
            s.commit()
        finally:
            s.close()
        audit.record("admin.reset_mfa", actor=who, ip=ip, data={"target": username})
        return {"ok": True}

    @r.post("/users/{username}/disable")
    def disable(username: str, body: AdminActionReq, request: Request,
                who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            _require_admin_with_totp(s, who, body.totp)
            if username == who:
                raise HTTPException(status_code=400, detail="cannot disable self")
            target = s.query(User).filter(User.username == username).first()
            if not target:
                raise HTTPException(status_code=404, detail="user not found")
            target.disabled_at = dt.datetime.utcnow()
            s.commit()
        finally:
            s.close()
        audit.record("admin.disable_user", actor=who, ip=ip, data={"target": username})
        return {"ok": True}

    @r.post("/users/{username}/enable")
    def enable(username: str, body: AdminActionReq, request: Request,
               who: str = Depends(current_user)):
        ip = request.client.host if request.client else "-"
        s = db.session()
        try:
            _require_admin_with_totp(s, who, body.totp)
            target = s.query(User).filter(User.username == username).first()
            if not target:
                raise HTTPException(status_code=404, detail="user not found")
            target.disabled_at = None
            s.commit()
        finally:
            s.close()
        audit.record("admin.enable_user", actor=who, ip=ip, data={"target": username})
        return {"ok": True}

    return r
