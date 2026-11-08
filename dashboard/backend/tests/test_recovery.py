# SPDX-License-Identifier: AGPL-3.0-only
"""Recovery-code tests for Order 13 item 5."""
from __future__ import annotations
import os
import tempfile
import unittest

import pyotp

from backend import db
from backend.db.models import User, RecoveryCode
from backend.security.auth import hash_password, new_totp_secret
from backend.security import recovery
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


class UnitLevel(unittest.TestCase):
    def setUp(self):
        self.dbf = tempfile.NamedTemporaryFile(suffix=".db", delete=False); self.dbf.close()
        db.init(f"sqlite:///{self.dbf.name}")
        s = db.session()
        try:
            u = User(username="x", pw_hash=hash_password("p"))
            s.add(u); s.commit(); s.refresh(u)
            self.uid = u.id
        finally:
            s.close()

    def tearDown(self):
        os.unlink(self.dbf.name)

    def test_mint_returns_10_and_persists(self):
        s = db.session()
        try:
            codes = recovery.mint_codes(s, self.uid)
            self.assertEqual(len(codes), 10)
            self.assertEqual(len(set(codes)), 10)  # unique
            self.assertEqual(recovery.remaining(s, self.uid), 10)
        finally:
            s.close()

    def test_consume_marks_used_and_rejects_reuse(self):
        s = db.session()
        try:
            codes = recovery.mint_codes(s, self.uid)
            picked = codes[0]
            self.assertTrue(recovery.verify_and_consume(s, self.uid, picked))
            self.assertFalse(recovery.verify_and_consume(s, self.uid, picked), "reuse must fail")
            self.assertEqual(recovery.remaining(s, self.uid), 9)
        finally:
            s.close()

    def test_regen_wipes_old_and_mints_new(self):
        s = db.session()
        try:
            first = recovery.mint_codes(s, self.uid)
            second = recovery.mint_codes(s, self.uid)
            self.assertEqual(set(first).intersection(set(second)), set())
            self.assertEqual(recovery.remaining(s, self.uid), 10)
        finally:
            s.close()


@unittest.skipUnless(HAS_SEGNO, "segno needed to run full setup flow")
class EndToEnd(unittest.TestCase):
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
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("strong-password-12345"))
            s.add(u); s.commit()
        finally:
            s.close()
        self.app = create_app(self.cfg)
        self._cm = serve(self.app)
        self.client = self._cm.__enter__()
        r = self.client.post("/api/auth/login", json={"username": "dee", "password": "strong-password-12345"})
        self.token = r.json()["token"]
        self.h = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        self._cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
        os.unlink(self.db_path); os.unlink(self.audit_path)

    def _enroll_mfa(self):
        self.client.get("/api/setup/mfa", headers=self.h)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            secret = u.mfa_pending_secret
        finally:
            s.close()
        code = pyotp.TOTP(secret).now()
        r = self.client.post("/api/setup/mfa", headers=self.h, json={"code": code})
        self.assertEqual(r.status_code, 200)
        return secret, r.json()["recovery_codes"]

    def test_enrollment_returns_10_codes(self):
        secret, codes = self._enroll_mfa()
        self.assertEqual(len(codes), 10)

    def test_login_with_recovery_code(self):
        from backend.security.headers import _reset_login_limiter
        secret, codes = self._enroll_mfa()
        _reset_login_limiter()
        # log out, log in with a recovery code
        r = self.client.post("/api/auth/login", json={
            "username": "dee",
            "password": "strong-password-12345",
            "recovery_code": codes[0],
        })
        self.assertEqual(r.status_code, 200, r.text)
        # reuse must fail
        _reset_login_limiter()
        r2 = self.client.post("/api/auth/login", json={
            "username": "dee",
            "password": "strong-password-12345",
            "recovery_code": codes[0],
        })
        self.assertEqual(r2.status_code, 401)

    def test_regen_requires_current_totp(self):
        from backend.security.headers import _reset_login_limiter
        secret, codes = self._enroll_mfa()
        _reset_login_limiter()
        # bad TOTP
        r = self.client.post("/api/account/recovery-codes", headers=self.h, json={"totp": "000000"})
        self.assertEqual(r.status_code, 401)
        # good TOTP
        code = pyotp.TOTP(secret).now()
        r2 = self.client.post("/api/account/recovery-codes", headers=self.h, json={"totp": code})
        self.assertEqual(r2.status_code, 200, r2.text)
        self.assertEqual(len(r2.json()["recovery_codes"]), 10)


if __name__ == "__main__":
    unittest.main()
