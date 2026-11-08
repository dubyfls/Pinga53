# SPDX-License-Identifier: AGPL-3.0-only
"""System endpoints: audit-log tail + hash-chain verify, plus basic status."""
from __future__ import annotations
import json
import os
from fastapi import APIRouter, Depends


def build_system_router(cfg, current_user, audit) -> APIRouter:
    r = APIRouter(prefix="/api/system", tags=["system"])

    @r.get("/audit")
    async def audit_tail(limit: int = 200, user: str = Depends(current_user)):
        path = cfg.audit_log
        rows = []
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    lines = f.readlines()[-limit:]
                for ln in lines:
                    try:
                        rows.append(json.loads(ln))
                    except Exception:
                        pass
        except Exception:
            pass
        ok, count = (True, len(rows))
        try:
            ok, count = audit.verify()
        except Exception:
            pass
        return {"entries": rows, "chain_ok": ok, "chain_count": count}

    @r.get("/status")
    async def status(user: str = Depends(current_user)):
        return {
            "bind": f"{getattr(cfg, 'bind_host', '0.0.0.0')}:{getattr(cfg, 'bind_port', 8053)}",
            "mfa_required": getattr(cfg, "require_mfa", False),
        }

    return r
