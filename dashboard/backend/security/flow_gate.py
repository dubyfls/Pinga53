# SPDX-License-Identifier: AGPL-3.0-only
"""Forced-flow gate (Order 13 item 3).

Blocks a signed-in user from reaching any protected route while their account
still owes a step:

  * must_change_password → only /api/account/password
  * MFA required and not enrolled → only /api/setup/mfa

The gate runs before route handlers so it cannot be bypassed by a route
forgetting to add its own guard. Disabled accounts are 403'd on every
request. The gate is silent on the login/logout/me endpoints (they must stay
reachable so the client can drive the flow and unauthenticated calls simply
proceed to the route's own 401).
"""
from __future__ import annotations
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend import db
from backend.db.models import User, is_mfa_enrolled
from backend.security.auth import decode_token


ALLOWED_DURING_FORCED_FLOW = {
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/account/password",
    "/api/setup/mfa",
}


def _needs_password_change(u: User) -> bool:
    return bool(u.must_change_password)


def _needs_mfa_enrollment(u: User, require_mfa: bool) -> bool:
    return require_mfa and not is_mfa_enrolled(u)


class ForcedFlowGate(BaseHTTPMiddleware):
    def __init__(self, app, secret_key: str, require_mfa: bool):
        super().__init__(app)
        self.secret_key = secret_key
        self.require_mfa = require_mfa

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)
        if path in ALLOWED_DURING_FORCED_FLOW:
            return await call_next(request)

        auth_hdr = request.headers.get("authorization", "")
        if not auth_hdr.lower().startswith("bearer "):
            return await call_next(request)  # route dep will 401
        token = auth_hdr.split(" ", 1)[1]
        try:
            payload = decode_token(token, self.secret_key)
            username = payload.get("sub")
        except Exception:
            return await call_next(request)  # route dep will 401
        if not username:
            return await call_next(request)

        s = db.session()
        try:
            u = s.query(User).filter(User.username == username).first()
        finally:
            s.close()
        if not u:
            return await call_next(request)  # route dep will 401
        if u.disabled_at is not None:
            return JSONResponse(
                {"detail": "account disabled", "code": "disabled"},
                status_code=403,
            )
        if _needs_password_change(u):
            return JSONResponse(
                {"detail": "password change required", "code": "must_change_password", "next": "/account/password"},
                status_code=409,
            )
        if _needs_mfa_enrollment(u, self.require_mfa):
            return JSONResponse(
                {"detail": "MFA enrollment required", "code": "must_enroll_mfa", "next": "/setup/mfa"},
                status_code=409,
            )
        return await call_next(request)
