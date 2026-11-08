# SPDX-License-Identifier: AGPL-3.0-only
"""Forced-flow gate + password-change tests for Order 13 item 3."""
from __future__ import annotations
import datetime as dt
import os
import tempfile
import unittest

from backend import db
from backend.db.models import User
from backend.security.auth import hash_password, new_totp_secret
from backend.security.bootstrap import create_bootstrap_admin
from backend.tests._asgi import serve


def _tmp_env():
    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False); tmp_db.close()
    tmp_audit = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tmp_audit.close()
    env = {
        "PINGA53_SECRET_KEY": "x" * 40,
        "PINGA53_DB_URL": f"sqlite:///{tmp_db.name}",
        "PINGA53_AUDIT_LOG": tmp_audit.name,
        "PINGA53_CONFIG_DIR": os.path.dirname(tmp_db.name),
        "PINGA53_REQUIRE_MFA": "true",
        "PINGA53_BIND_PORT": "0",
    }
    return env, tmp_db.name, tmp_audit.name


class _Base(unittest.TestCase):
    def setUp(self):
        self.env_patch, self.db_path, self.audit_path = _tmp_env()
        self._orig_env = {k: os.environ.get(k) for k in self.env_patch}
        os.environ.update(self.env_patch)
        from backend.security.headers import _reset_login_limiter
        _reset_login_limiter()
        from backend.main import create_app
        from backend.config import load
        self.cfg = load()
        db.init(self.cfg.db_url)
        self.app = create_app(self.cfg)
        self._serve_cm = serve(self.app)
        self.client = self._serve_cm.__enter__()

    def tearDown(self):
        self._serve_cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        os.unlink(self.db_path)
        os.unlink(self.audit_path)

    def _login(self, username, password, totp=None):
        body = {"username": username, "password": password}
        if totp:
            body["totp"] = totp
        return self.client.post("/api/auth/login", json=body)

    def _seed(self, **kwargs):
        s = db.session()
        try:
            u = User(pw_hash=hash_password("initial-password-1234"), **kwargs)
            s.add(u); s.commit(); s.refresh(u)
            return u.id
        finally:
            s.close()


class ForcedFlowMustChangePassword(_Base):
    def test_bootstrap_user_cannot_access_dashboard(self):
        # Fake audit for bootstrap (uses live audit path here, but content is safe)
        from backend.audit.hash_chain import AuditLog
        pw = create_bootstrap_admin(AuditLog(self.audit_path))
        r = self._login("administrator", pw)
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        h = {"Authorization": f"Bearer {token}"}

        # Login endpoint is reachable
        # Protected route must be blocked with 409 + code
        r2 = self.client.get("/api/health", headers=h)
        # health has no auth; use a real protected endpoint via system
        # fallback: use any /api/ path that's not whitelisted — use a made-up route
        r3 = self.client.get("/api/auth/me", headers=h)
        self.assertEqual(r3.status_code, 200)  # whitelisted
        # a definitely-not-whitelisted route
        r4 = self.client.get("/api/manage/blocking", headers=h)
        self.assertEqual(r4.status_code, 409, r4.text)
        self.assertEqual(r4.json().get("code"), "must_change_password")

    def test_can_change_password_and_then_hit_mfa_gate(self):
        from backend.audit.hash_chain import AuditLog
        pw = create_bootstrap_admin(AuditLog(self.audit_path))
        token = self._login("administrator", pw).json()["token"]
        h = {"Authorization": f"Bearer {token}"}
        r = self.client.post("/api/account/password", headers=h, json={
            "current_password": pw, "new_password": "brand-new-strong-pw-1234"
        })
        self.assertEqual(r.status_code, 200, r.text)
        # now must enroll MFA — password gate cleared, MFA gate raised
        r2 = self.client.get("/api/manage/blocking", headers=h)
        self.assertEqual(r2.status_code, 409)
        self.assertEqual(r2.json().get("code"), "must_enroll_mfa")


class DisabledUserBlocked(_Base):
    def test_disabled_login_refused(self):
        self._seed(username="dee", disabled_at=dt.datetime.utcnow(),
                   totp_secret=new_totp_secret())
        r = self._login("dee", "initial-password-1234")
        self.assertEqual(r.status_code, 403)


class NoTokenPassesThrough(_Base):
    def test_no_token_leaves_401_to_route(self):
        r = self.client.get("/api/system/status")
        # No token => route's own dep raises 401
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
