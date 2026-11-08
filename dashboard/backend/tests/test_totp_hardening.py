# SPDX-License-Identifier: AGPL-3.0-only
"""TOTP hardening tests for Order 13 item 6 — replay, rate-limit, issuer."""
from __future__ import annotations
import os
import tempfile
import time
import unittest

import pyotp

from backend import db
from backend.db.models import User
from backend.security import auth, totp_ratelimit
from backend.security.auth import hash_password
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


class Unit(unittest.TestCase):
    def test_issuer_is_pinga53(self):
        secret = auth.new_totp_secret()
        uri = auth.provisioning_uri(secret, "dee")
        self.assertIn("issuer=Pinga53", uri)
        self.assertIn("Pinga53%20%28dee%29", uri)

    def test_replay_rejected(self):
        secret = auth.new_totp_secret()
        totp = pyotp.TOTP(secret)
        now = int(time.time())
        step = now // 30
        code = totp.at(step * 30)
        ok, matched = auth.verify_totp_no_replay(secret, code, last_step=None, now_ts=step * 30)
        self.assertTrue(ok)
        self.assertEqual(matched, step)
        ok2, _ = auth.verify_totp_no_replay(secret, code, last_step=step, now_ts=step * 30)
        self.assertFalse(ok2, "same-step reuse must fail")

    def test_window_plus_minus_one(self):
        secret = auth.new_totp_secret()
        totp = pyotp.TOTP(secret)
        now = time.time()
        step = int(now // 30)
        # code from step-1 must still verify inside ±1 window
        code_prev = totp.at((step - 1) * 30)
        ok, matched = auth.verify_totp_no_replay(secret, code_prev, None, now_ts=step * 30)
        self.assertTrue(ok)
        self.assertEqual(matched, step - 1)
        # code from step-2 must NOT verify
        code_far = totp.at((step - 2) * 30)
        ok2, _ = auth.verify_totp_no_replay(secret, code_far, None, now_ts=step * 30)
        self.assertFalse(ok2)


class RateLimit(unittest.TestCase):
    def setUp(self):
        totp_ratelimit.reset_all()

    def test_locks_after_five_failures(self):
        for i in range(5):
            self.assertEqual(totp_ratelimit.remaining_lockout_seconds("dee"), 0)
            totp_ratelimit.record_failure("dee")
        self.assertGreater(totp_ratelimit.remaining_lockout_seconds("dee"), 0)

    def test_reset_clears_lock(self):
        for _ in range(5):
            totp_ratelimit.record_failure("dee")
        self.assertGreater(totp_ratelimit.remaining_lockout_seconds("dee"), 0)
        totp_ratelimit.reset("dee")
        self.assertEqual(totp_ratelimit.remaining_lockout_seconds("dee"), 0)


class LoginIntegration(unittest.TestCase):
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
        self.secret = auth.new_totp_secret()
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     totp_secret=self.secret, mfa_enrolled_at=__import__("datetime").datetime.utcnow(),
                     last_totp_step=None)
            s.add(u); s.commit()
        finally:
            s.close()
        self.app = create_app(self.cfg)
        self._cm = serve(self.app)
        self.client = self._cm.__enter__()

    def tearDown(self):
        self._cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
        os.unlink(self.db_path); os.unlink(self.audit_path)

    def _login(self, totp):
        return self.client.post("/api/auth/login", json={
            "username": "dee", "password": "pw-1234567890", "totp": totp,
        })

    def test_replay_same_totp_twice_fails(self):
        code = pyotp.TOTP(self.secret).now()
        r1 = self._login(code)
        self.assertEqual(r1.status_code, 200, r1.text)
        r2 = self._login(code)
        self.assertEqual(r2.status_code, 401)

    def test_rate_limit_after_five_bad_totps(self):
        from backend.security.headers import _reset_login_limiter
        for _ in range(5):
            _reset_login_limiter()
            r = self._login("000000")
            self.assertEqual(r.status_code, 401)
        _reset_login_limiter()
        r6 = self._login("000000")
        self.assertEqual(r6.status_code, 429)
        self.assertIn("seconds", r6.json().get("detail", ""))


if __name__ == "__main__":
    unittest.main()
