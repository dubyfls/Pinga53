# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 security middleware — headers + login rate limiting.

Headers: CSP, HSTS, frame-deny, nosniff, referrer policy. Rate limiter is a
per-IP sliding window guarding the login route against brute force (fail-closed:
over the limit => 429).
"""
from __future__ import annotations
import time
import threading
from collections import defaultdict, deque
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

_CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = _CSP
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # HSTS only meaningful over TLS; harmless otherwise, set for when TLS lands
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp


class _Window:
    def __init__(self, limit: int, window_s: int):
        self.limit, self.window = limit, window_s
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


# 6 login attempts / 5 min per IP
_login_limiter = _Window(limit=6, window_s=300)


def _reset_login_limiter():
    """Test hook: forget accumulated per-IP hits. Not called at runtime."""
    with _login_limiter.lock:
        _login_limiter.hits.clear()


class LoginRateLimit(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/api/auth/login" and request.method == "POST":
            ip = request.client.host if request.client else "-"
            if not _login_limiter.allow(ip):
                return JSONResponse({"detail": "too many attempts, slow down"}, status_code=429)
        return await call_next(request)
