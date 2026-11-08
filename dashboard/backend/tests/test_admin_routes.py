# SPDX-License-Identifier: AGPL-3.0-only
"""Admin dashboard routes tests for Order 13 item 10.

Every admin mutation runs through the same TOTP replay guard as /api/auth/login
(verify_totp_no_replay against users.last_totp_step). Tests advance the auth
module's `time` reference between mutations so each request presents a code
from a strictly later 30-second step — matching what a real operator would do
by waiting a few seconds between clicks.
"""
from __future__ import annotations
import datetime as dt
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import pyotp

from backend import db
from backend.db.models import User, RecoveryCode
from backend.security import totp_ratelimit
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


class AdminRoutes(unittest.TestCase):
    def setUp(self):
        self.env_patch, self.db_path, self.audit_path = _env()
        self._orig_env = {k: os.environ.get(k) for k in self.env_patch}
        os.environ.update(self.env_patch)
        from backend.security.headers import _reset_login_limiter
        _reset_login_limiter(); totp_ratelimit.reset_all()
        from backend.main import create_app
        from backend.config import load
        self.cfg = load()
        db.init(self.cfg.db_url)
        self.admin_secret = new_totp_secret()
        self.dee_secret = new_totp_secret()
        self.loki_secret = new_totp_secret()
        s = db.session()
        try:
            s.add(User(username="administrator", pw_hash=hash_password("admin-pw-12345"),
                       totp_secret=self.admin_secret, mfa_enrolled_at=dt.datetime.utcnow()))
            s.add(User(username="dee", pw_hash=hash_password("dee-pw-12345"),
                       totp_secret=self.dee_secret, mfa_enrolled_at=dt.datetime.utcnow()))
            s.add(User(username="loki", pw_hash=hash_password("loki-pw-12345"),
                       totp_secret=self.loki_secret, mfa_enrolled_at=dt.datetime.utcnow()))
            s.commit()
        finally:
            s.close()
        self.app = create_app(self.cfg)
        self._cm = serve(self.app)
        self.client = self._cm.__enter__()
        # Successive admin mutations need increasing TOTP steps (replay guard).
        # This counter is bumped in _admin_post so no two actions in one test
        # collide on the same step.
        self._admin_step_offset = 0
        self._headers = None
        self._as_admin()

    def tearDown(self):
        self._cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
        os.unlink(self.db_path); os.unlink(self.audit_path)

    def _as_admin(self):
        from backend.security.headers import _reset_login_limiter
        _reset_login_limiter(); totp_ratelimit.reset_all()
        r = self.client.post("/api/auth/login", json={
            "username": "administrator", "password": "admin-pw-12345",
            "totp": pyotp.TOTP(self.admin_secret).now(),
        })
        self.assertEqual(r.status_code, 200, r.text)
        self._headers = {"Authorization": f"Bearer {r.json()['token']}"}

    def _admin_post(self, path, extra=None, headers=None):
        """POST to an admin endpoint with a live TOTP code from a step
        strictly later than any code used earlier in this test. Patches the
        auth module's `time` reference for the duration of the request so
        the server verifies against the same shifted clock."""
        from backend.security import auth as _auth_mod
        self._admin_step_offset += 90  # skip past ±1 window comfortably
        future = time.time() + self._admin_step_offset
        with patch.object(_auth_mod, "time") as mock_time:
            mock_time.time.return_value = future
            code = pyotp.TOTP(self.admin_secret).at(future)
            payload = {"totp": code}
            if extra:
                payload.update(extra)
            return self.client.post(path, json=payload, headers=headers or self._headers)

    def _as_dee(self):
        from backend.security.headers import _reset_login_limiter
        _reset_login_limiter(); totp_ratelimit.reset_all()
        r = self.client.post("/api/auth/login", json={
            "username": "dee", "password": "dee-pw-12345",
            "totp": pyotp.TOTP(self.dee_secret).now(),
        })
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": f"Bearer {r.json()['token']}"}

    def test_list_users_admin_only(self):
        r = self.client.get("/api/admin/users", headers=self._headers)
        self.assertEqual(r.status_code, 200)
        names = {u["username"] for u in r.json()["users"]}
        self.assertEqual(names, {"administrator", "dee", "loki"})
        # non-admin blocked
        h = self._as_dee()
        r2 = self.client.get("/api/admin/users", headers=h)
        self.assertEqual(r2.status_code, 403)

    def test_set_temp_password_requires_admin_totp(self):
        r = self.client.post("/api/admin/users/dee/password", headers=self._headers,
                             json={"totp": "000000"})
        self.assertEqual(r.status_code, 401)
        r2 = self._admin_post("/api/admin/users/dee/password")
        self.assertEqual(r2.status_code, 200, r2.text)
        j = r2.json()
        self.assertGreaterEqual(len(j["temp_password"]), 16)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertTrue(u.must_change_password)
        finally:
            s.close()

    def test_reset_target_mfa(self):
        r = self._admin_post("/api/admin/users/dee/mfa/reset")
        self.assertEqual(r.status_code, 200, r.text)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertIsNone(u.totp_secret)
            self.assertIsNone(u.mfa_enrolled_at)
        finally:
            s.close()

    def test_disable_and_enable(self):
        r = self._admin_post("/api/admin/users/dee/disable")
        self.assertEqual(r.status_code, 200, r.text)
        s = db.session()
        try:
            self.assertIsNotNone(s.query(User).filter(User.username == "dee").first().disabled_at)
        finally:
            s.close()
        r2 = self._admin_post("/api/admin/users/dee/enable")
        self.assertEqual(r2.status_code, 200, r2.text)

    def test_cannot_disable_self(self):
        r = self._admin_post("/api/admin/users/administrator/disable")
        self.assertEqual(r.status_code, 400)

    def test_login_totp_cannot_authorize_admin_mutation(self):
        """The very code that authenticated the caller must NOT be replayable
        against an admin mutation route: verify_totp_no_replay rejects any
        step <= last_totp_step, and login records the step it consumed."""
        from backend.security.headers import _reset_login_limiter
        from backend.security import auth as _auth_mod
        # setUp already burned the current step via _as_admin; advance the
        # auth-module clock so this fresh login lands on a strictly later
        # step and we can capture the exact code that consumed it.
        self._admin_step_offset += 90
        future = time.time() + self._admin_step_offset
        _reset_login_limiter(); totp_ratelimit.reset_all()
        with patch.object(_auth_mod, "time") as mock_time:
            mock_time.time.return_value = future
            login_code = pyotp.TOTP(self.admin_secret).at(future)
            r = self.client.post("/api/auth/login", json={
                "username": "administrator", "password": "admin-pw-12345",
                "totp": login_code,
            })
            self.assertEqual(r.status_code, 200, r.text)
            headers = {"Authorization": f"Bearer {r.json()['token']}"}

            # Same clock, same code — must be rejected as replay by the
            # admin route's guard.
            r2 = self.client.post("/api/admin/users/dee/disable",
                                  headers=headers, json={"totp": login_code})
        self.assertEqual(r2.status_code, 401, r2.text)

        # DB state unchanged.
        s = db.session()
        try:
            self.assertIsNone(s.query(User).filter(User.username == "dee").first().disabled_at)
        finally:
            s.close()

        # A code from a strictly later step in the same session works.
        r3 = self._admin_post("/api/admin/users/dee/disable", headers=headers)
        self.assertEqual(r3.status_code, 200, r3.text)

        # And that fresh code, replayed against the next admin mutation on
        # the same clock, is rejected — proving the guard covers every
        # admin mutation, not just login.
        prior_ts = time.time() + self._admin_step_offset
        prior_code = pyotp.TOTP(self.admin_secret).at(prior_ts)
        with patch.object(_auth_mod, "time") as mock_time:
            mock_time.time.return_value = prior_ts
            r4 = self.client.post("/api/admin/users/dee/enable",
                                  headers=headers, json={"totp": prior_code})
        self.assertEqual(r4.status_code, 401, r4.text)


if __name__ == "__main__":
    unittest.main()
