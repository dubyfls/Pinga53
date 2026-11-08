# SPDX-License-Identifier: AGPL-3.0-only
"""Pi-hole overview endpoints.

Read-only glance used by the dashboard's Pi-hole overview card:
status, queries today, blocked today.

The dashboard never asks the user for the Pi-hole app password in the browser.
The operator supplies it at install (`PINGA53_PIHOLE_APP_PASSWORD`), and the
dashboard uses it server-side via the PiholeClient to call the Pi-hole v6 API.
"""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Depends


def build_pihole_router(cfg, current_user, ftl, pi_client) -> APIRouter:
    r = APIRouter(prefix="/api/pihole", tags=["pihole"])

    @r.get("/overview")
    async def overview(_: str = Depends(current_user)):
        """Combined read: FTL metrics (queries/blocked/today) + API reachability."""
        out = {
            "connected": False,
            "admin_url": getattr(cfg, "pihole_admin_url", "/admin"),
            "ftl_available": False,
            "queries_today": 0,
            "blocked_today": 0,
            "blocked_pct": 0.0,
            "status": "unknown",
        }
        try:
            out["connected"] = await asyncio.to_thread(pi_client.available)
        except Exception as e:
            out["error"] = f"pihole api: {e}"
        try:
            if ftl.available():
                out["ftl_available"] = True
                m = await asyncio.to_thread(ftl.metrics)
                out["queries_today"] = int(m.get("queries", 0))
                out["blocked_today"] = int(m.get("blocked", 0))
                out["blocked_pct"] = float(m.get("blockedPct", 0.0))
        except Exception as e:
            out["ftl_error"] = str(e)
        if out["connected"] or out["ftl_available"]:
            out["status"] = "ok"
        else:
            out["status"] = "offline"
        return out

    return r
