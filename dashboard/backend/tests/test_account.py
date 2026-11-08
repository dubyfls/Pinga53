# SPDX-License-Identifier: AGPL-3.0-only
"""/account page tests for Order 13 item 7."""
from __future__ import annotations
import datetime as dt
import os
import tempfile
import unittest

import pyotp

from backend import db
from backend.db.models import User, RecoveryCode
from backend.security import auth as _auth, totp_ratelimit
from backend.security.auth import hash_password, new_totp_secret
from backend.tests._asgi import serve


def _env():
    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False); tmp_db.close()
    tmp_audit = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tmp_audit.close()
    return {
        "PINGA53_SECRET_KEY": "x" * 40,
        "PINGA53_DB_URL": f"sqlite:///{tmp_db.name}",
        "PINGA53_AUDIT_LOG": tmp_audit.name,
        "PINGA53_CONFIG_DIR": os.path.dirname(tmp_db.name),
        "PINGA53_REQUIRE_MFA": "true",
    }, tmp_db.name, tmp_audit.name


class AccountRoutes(unittest.TestCase):
    def setUp(self):
        self.env_patch, self.db_path, self.audit_path = _env()
        self._orig_env = {k: os.environ.get(k) for k in self.env_patch}
        os.environ.update(self.env_patch)
        from backend.security.headers import _reset_login_limiter
        _reset_login_limiter()
        totp_ratelimit.reset_all()
        from backend.main import create_app
        from backend.config import load
        self.cfg = load()
        db.init(self.cfg.db_url)
        self.secret = new_totp_secret()
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     totp_secret=self.secret, mfa_enrolled_at=dt.datetime.utcnow())
            s.add(u); s.commit()
        finally:
            s.close()
        self.app = create_app(self.cfg)
        self._cm = serve(self.app)
        self.client = self._cm.__enter__()
        r = self.client.post("/api/auth/login", json={
            "username": "dee", "password": "pw-1234567890", "totp": pyotp.TOTP(self.secret).now()
        })
        self.assertEqual(r.status_code, 200, r.text)
        self.h = {"Authorization": f"Bearer {r.json()['token']}"}

    def tearDown(self):
        self._cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
        os.unlink(self.db_path); os.unlink(self.audit_path)

    def _fresh_totp(self):
        # Different step from the login one — advance server-side clock.
        # Simplest: read secret, compute code for step+1.
        import time
        step = int(time.time() // 30) + 1
        return pyotp.TOTP(self.secret).at(step * 30)

    def test_summary_endpoint(self):
        r = self.client.get("/api/account", headers=self.h)
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual(j["username"], "dee")
        self.assertTrue(j["mfa_enrolled"])
        self.assertFalse(j["disabled"])
        self.assertFalse(j["must_change_password"])

    def test_password_change_requires_totp_when_enrolled(self):
        r = self.client.post("/api/account/password", headers=self.h, json={
            "current_password": "pw-1234567890", "new_password": "new-strong-pw-98765"
        })
        self.assertEqual(r.status_code, 401)  # missing totp
        r2 = self.client.post("/api/account/password", headers=self.h, json={
            "current_password": "pw-1234567890", "new_password": "new-strong-pw-98765",
            "totp": self._fresh_totp(),
        })
        self.assertEqual(r2.status_code, 200, r2.text)

    def test_password_change_rejects_same_password(self):
        r = self.client.post("/api/account/password", headers=self.h, json={
            "current_password": "pw-1234567890", "new_password": "pw-1234567890",
            "totp": self._fresh_totp(),
        })
        self.assertEqual(r.status_code, 400)

    def test_mfa_reset_clears_secret_and_codes(self):
        # seed a recovery code
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            s.add(RecoveryCode(user_id=u.id, code_hash="unused-hash"))
            s.commit()
        finally:
            s.close()
        r = self.client.post("/api/account/mfa/reset", headers=self.h, json={
            "current_password": "pw-1234567890", "totp": self._fresh_totp(),
        })
        self.assertEqual(r.status_code, 200, r.text)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertIsNone(u.totp_secret)
            self.assertIsNone(u.mfa_enrolled_at)
            self.assertEqual(s.query(RecoveryCode).filter(RecoveryCode.user_id == u.id).count(), 0)
        finally:
            s.close()

    def test_mfa_reset_rejects_bad_password(self):
        r = self.client.post("/api/account/mfa/reset", headers=self.h, json={
            "current_password": "WRONG", "totp": self._fresh_totp(),
        })
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
