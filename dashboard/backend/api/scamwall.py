# SPDX-License-Identifier: AGPL-3.0-only
"""ScamWall read endpoints plus the four owner actions.

Read endpoints: mode (shadow/enforce), stop flag state, standing-hosts list,
feed source health, last decision run, last zone install, daily hits.

Owner actions (stop-on/off, mode-shadow/enforce, protect-add/remove, run-now):
require admin + a fresh TOTP step-up, and run via the root helper binary.
Every action is audited in the hash chain. Full detail lives in SECURITY.md.
"""
from __future__ import annotations
import asyncio
import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.modules.scamwall.reader import ScamWallReader
from backend.modules.scamwall.helper import run_helper, HelperError
from backend.security import auth as _auth
from backend import db as _db
from backend.db.models import User
from backend.api.admin import _is_admin


_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _validate_host(host: str) -> str:
    if not host or len(host) > 253:
        raise HTTPException(status_code=400, detail="host: length out of range")
    try:
        h = host.strip().lower().encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(status_code=400, detail="host: not valid punycode")
    if not _HOST_RE.match(h):
        raise HTTPException(status_code=400, detail="host: invalid characters or shape")
    return h


class ActionReq(BaseModel):
    totp: str = Field(min_length=6, max_length=8)
    host: str | None = None


def build_scamwall_router(cfg, current_user, audit) -> APIRouter:
    r = APIRouter(prefix="/api/scamwall", tags=["scamwall"])
    reader = ScamWallReader.from_config(cfg)

    def _require_admin_with_totp(who: str, totp: str) -> None:
        if not _is_admin(who):
            raise HTTPException(status_code=403, detail="admin only")
        s = _db.session()
        try:
            me = s.query(User).filter(User.username == who).first()
            if not me or me.disabled_at is not None or not me.totp_secret:
                raise HTTPException(status_code=401, detail="invalid MFA code")
            ok, step = _auth.verify_totp_no_replay(me.totp_secret, totp, me.last_totp_step)
            if not ok:
                raise HTTPException(status_code=401, detail="invalid MFA code")
            me.last_totp_step = step
            s.commit()
        finally:
            s.close()

    @r.get("/overview")
    async def overview(user: str = Depends(current_user)):
        return await asyncio.to_thread(reader.overview)

    @r.get("/hosts")
    async def hosts(user: str = Depends(current_user)):
        return await asyncio.to_thread(reader.hosts)

    @r.get("/health")
    async def health(user: str = Depends(current_user)):
        return await asyncio.to_thread(reader.feed_health)

    def _do(action: str, host: str | None, who: str):
        try:
            if host is not None:
                out = run_helper(cfg.helper_bin, action, host,
                                 use_sudo=cfg.use_sudo_helper)
            else:
                out = run_helper(cfg.helper_bin, action,
                                 use_sudo=cfg.use_sudo_helper)
        except HelperError as e:
            audit.record("scamwall.action.fail", actor=who,
                         data={"action": action, "host": host, "error": str(e)})
            raise HTTPException(status_code=502, detail=str(e))
        audit.record("scamwall.action.ok", actor=who,
                     data={"action": action, "host": host})
        return {"ok": True, "output": out}

    @r.post("/stop-on")
    async def stop_on(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        return await asyncio.to_thread(_do, "stop-on", None, user)

    @r.post("/stop-off")
    async def stop_off(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        return await asyncio.to_thread(_do, "stop-off", None, user)

    @r.post("/mode-shadow")
    async def mode_shadow(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        return await asyncio.to_thread(_do, "mode-shadow", None, user)

    @r.post("/mode-enforce")
    async def mode_enforce(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        return await asyncio.to_thread(_do, "mode-enforce", None, user)

    @r.post("/protect-add")
    async def protect_add(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        host = _validate_host(body.host or "")
        return await asyncio.to_thread(_do, "protect-add", host, user)

    @r.post("/protect-remove")
    async def protect_remove(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        host = _validate_host(body.host or "")
        return await asyncio.to_thread(_do, "protect-remove", host, user)

    @r.post("/run-now")
    async def run_now(body: ActionReq, user: str = Depends(current_user)):
        _require_admin_with_totp(user, body.totp)
        return await asyncio.to_thread(_do, "run-now", None, user)

    return r
