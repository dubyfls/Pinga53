# SPDX-License-Identifier: AGPL-3.0-only
"""MFA enrollment tests for Order 13 item 4."""
from __future__ import annotations
import datetime as dt
import os
import tempfile
import unittest

import pyotp

from backend import db
from backend.db.models import User
from backend.security.auth import hash_password
from backend.tests._asgi import serve

try:
    import segno  # noqa: F401
    HAS_SEGNO = True
except Exception:
    HAS_SEGNO = False


def _tmp_env():
    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False); tmp_db.close()
    tmp_audit = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tmp_audit.close()
    return {
        "PINGA53_SECRET_KEY": "x" * 40,
        "PINGA53_DB_URL": f"sqlite:///{tmp_db.name}",
        "PINGA53_AUDIT_LOG": tmp_audit.name,
        "PINGA53_CONFIG_DIR": os.path.dirname(tmp_db.name),
        "PINGA53_REQUIRE_MFA": "true",
    }, tmp_db.name, tmp_audit.name


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
        # seed a user in forced-MFA-flow state: password already changed
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("strong-password-12345"))
            s.add(u); s.commit()
        finally:
            s.close()
        self.app = create_app(self.cfg)
        self._cm = serve(self.app)
        self.client = self._cm.__enter__()
        # authenticate
        r = self.client.post("/api/auth/login", json={"username": "dee", "password": "strong-password-12345"})
        self.assertEqual(r.status_code, 200, r.text)
        self.headers = {"Authorization": f"Bearer {r.json()['token']}"}

    def tearDown(self):
        self._cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
        os.unlink(self.db_path); os.unlink(self.audit_path)


@unittest.skipUnless(HAS_SEGNO, "segno not importable — install for full test")
class Enrollment(_Base):
    def test_start_returns_qr_and_blocks(self):
        r = self.client.get("/api/setup/mfa", headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertIn("qr_svg", j)
        self.assertIn("<svg", j["qr_svg"])
        # 4-character blocks separated by single spaces
        parts = j["secret_blocks"].split(" ")
        self.assertTrue(all(len(p) == 4 for p in parts[:-1]), j["secret_blocks"])
        self.assertIn("expires_at", j)
        # label uses Pinga53 (username)
        self.assertIn("Pinga53%20%28dee%29", j["qr_svg"] + j.get("otpauth_uri", ""))

    def test_confirm_with_valid_code_enrolls(self):
        j = self.client.get("/api/setup/mfa", headers=self.headers).json()
        # pull secret from DB — the endpoint only returns blocks; we know the raw
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            secret = u.mfa_pending_secret
        finally:
            s.close()
        code = pyotp.TOTP(secret).now()
        r = self.client.post("/api/setup/mfa", headers=self.headers, json={"code": code})
        self.assertEqual(r.status_code, 200, r.text)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertEqual(u.totp_secret, secret)
            self.assertIsNotNone(u.mfa_enrolled_at)
            self.assertIsNone(u.mfa_pending_secret)
        finally:
            s.close()

    def test_confirm_with_bad_code_rejected(self):
        self.client.get("/api/setup/mfa", headers=self.headers)
        r = self.client.post("/api/setup/mfa", headers=self.headers, json={"code": "000000"})
        self.assertEqual(r.status_code, 401)

    def test_pending_expires_after_10min(self):
        self.client.get("/api/setup/mfa", headers=self.headers)
        # tick expiry into the past
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            u.mfa_pending_expires = dt.datetime.utcnow() - dt.timedelta(seconds=1)
            secret = u.mfa_pending_secret
            s.commit()
        finally:
            s.close()
        code = pyotp.TOTP(secret).now()
        r = self.client.post("/api/setup/mfa", headers=self.headers, json={"code": code})
        self.assertEqual(r.status_code, 400)

    def test_second_start_rotates_expired_secret(self):
        r1 = self.client.get("/api/setup/mfa", headers=self.headers).json()
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            first = u.mfa_pending_secret
            u.mfa_pending_expires = dt.datetime.utcnow() - dt.timedelta(seconds=1)
            s.commit()
        finally:
            s.close()
        r2 = self.client.get("/api/setup/mfa", headers=self.headers).json()
        self.assertNotEqual(r1["secret_blocks"], r2["secret_blocks"])


if __name__ == "__main__":
    unittest.main()
