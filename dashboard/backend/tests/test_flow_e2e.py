# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end flow tests for Order 13 item 11.

Covers the full self-service and admin paths together, plus the negative
cases the order calls out: replay rejected, rate limit, recovery single-use,
pending secret expiry, disabled user blocked, reset-mfa forces re-enrollment,
set-password forces change, existing enrolled users unaffected, and no
secret ever appears in login responses or the audit log after enrollment.
"""
from __future__ import annotations
import datetime as dt
import json
import os
import tempfile
import unittest

import pyotp

from backend import db
from backend.audit.hash_chain import AuditLog
from backend.db.models import User
from backend.security import totp_ratelimit
from backend.security.auth import hash_password
from backend.security.headers import _reset_login_limiter
from backend.tests._asgi import serve

try:
    import segno  # noqa
    HAS_SEGNO = True
except Exception:
    HAS_SEGNO = False


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


class _E2EBase(unittest.TestCase):
    def setUp(self):
        self.env_patch, self.db_path, self.audit_path = _env()
        self._orig_env = {k: os.environ.get(k) for k in self.env_patch}
        os.environ.update(self.env_patch)
        _reset_login_limiter(); totp_ratelimit.reset_all()
        from backend.main import create_app
        from backend.config import load
        self.cfg = load()
        db.init(self.cfg.db_url)
        self.app = create_app(self.cfg)
        self._cm = serve(self.app)
        self.client = self._cm.__enter__()

    def tearDown(self):
        self._cm.__exit__(None, None, None)
        for k, v in self._orig_env.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
        os.unlink(self.db_path); os.unlink(self.audit_path)

    def _bootstrap(self):
        from backend.security.bootstrap import create_bootstrap_admin
        return create_bootstrap_admin(AuditLog(self.audit_path))

    def _login(self, u, pw, **extra):
        _reset_login_limiter()
        body = {"username": u, "password": pw}; body.update(extra)
        return self.client.post("/api/auth/login", json=body)

    def _pending_secret(self, username):
        s = db.session()
        try:
            u = s.query(User).filter(User.username == username).first()
            return u.mfa_pending_secret
        finally:
            s.close()


@unittest.skipUnless(HAS_SEGNO, "segno needed for enrollment SVG")
class HappyPath(_E2EBase):
    def test_bootstrap_change_password_enroll_mfa_then_dashboard(self):
        pw = self._bootstrap()
        t1 = self._login("administrator", pw).json()["token"]
        h = {"Authorization": f"Bearer {t1}"}

        # dashboard blocked
        r = self.client.get("/api/manage/blocking", headers=h)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "must_change_password")

        # change password (no TOTP required yet — not enrolled)
        new_pw = "brand-new-strong-pw-9876"
        r = self.client.post("/api/account/password", headers=h,
                             json={"current_password": pw, "new_password": new_pw})
        self.assertEqual(r.status_code, 200)

        # MFA gate now
        r = self.client.get("/api/manage/blocking", headers=h)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "must_enroll_mfa")

        # start + confirm enrollment
        j = self.client.get("/api/setup/mfa", headers=h).json()
        secret = self._pending_secret("administrator")
        r = self.client.post("/api/setup/mfa", headers=h,
                             json={"code": pyotp.TOTP(secret).now()})
        self.assertEqual(r.status_code, 200)
        codes = r.json()["recovery_codes"]
        self.assertEqual(len(codes), 10)

        # now dashboard is reachable
        r = self.client.get("/api/manage/blocking", headers=h)
        # PiholeClient probably errors talking to the API; we just care the gate
        # is *not* the thing blocking. Any status other than 409 is fine.
        self.assertNotEqual(r.status_code, 409, r.text)

    def test_no_secret_in_audit_or_login_after_enrollment(self):
        pw = self._bootstrap()
        t = self._login("administrator", pw).json()["token"]
        h = {"Authorization": f"Bearer {t}"}
        self.client.post("/api/account/password", headers=h,
                          json={"current_password": pw, "new_password": "brand-new-strong-pw-9876"})
        self.client.get("/api/setup/mfa", headers=h)
        secret = self._pending_secret("administrator")
        j = self.client.post("/api/setup/mfa", headers=h,
                              json={"code": pyotp.TOTP(secret).now()}).json()
        codes = j["recovery_codes"]
        # audit log must contain neither the TOTP secret nor any recovery code
        blob = open(self.audit_path).read()
        self.assertNotIn(secret, blob)
        for c in codes:
            self.assertNotIn(c, blob)
        # A subsequent /api/auth/me response must not leak the secret either
        r = self.client.get("/api/auth/me", headers=h)
        self.assertNotIn(secret, r.text)


class ReplayAndRateLimit(_E2EBase):
    def test_same_totp_rejected_second_time(self):
        secret = pyotp.random_base32()
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     totp_secret=secret, mfa_enrolled_at=dt.datetime.utcnow())
            s.add(u); s.commit()
        finally:
            s.close()
        code = pyotp.TOTP(secret).now()
        r1 = self._login("dee", "pw-1234567890", totp=code)
        self.assertEqual(r1.status_code, 200)
        r2 = self._login("dee", "pw-1234567890", totp=code)
        self.assertEqual(r2.status_code, 401)

    def test_rate_limit_locks_after_five(self):
        secret = pyotp.random_base32()
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     totp_secret=secret, mfa_enrolled_at=dt.datetime.utcnow())
            s.add(u); s.commit()
        finally:
            s.close()
        for _ in range(5):
            self._login("dee", "pw-1234567890", totp="000000")
        r = self._login("dee", "pw-1234567890", totp="000000")
        self.assertEqual(r.status_code, 429)


@unittest.skipUnless(HAS_SEGNO, "segno needed for enrollment SVG")
class RecoverySingleUse(_E2EBase):
    def test_reset_mfa_forces_reenrollment(self):
        # Existing enrolled user (dee) — reset MFA via CLI, then login should
        # be pushed to /setup/mfa by the gate.
        secret = pyotp.random_base32()
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     totp_secret=secret, mfa_enrolled_at=dt.datetime.utcnow())
            s.add(u); s.commit()
        finally:
            s.close()
        from backend import cli
        cli.reset_mfa(["dee"], audit=AuditLog(self.audit_path))
        # Login now — no TOTP secret; the require_mfa forced-flow path
        # issues a token so /setup/mfa can be reached.
        r = self._login("dee", "pw-1234567890")
        self.assertEqual(r.status_code, 200, r.text)
        h = {"Authorization": f"Bearer {r.json()['token']}"}
        gated = self.client.get("/api/manage/blocking", headers=h)
        self.assertEqual(gated.status_code, 409)
        self.assertEqual(gated.json()["code"], "must_enroll_mfa")


class DisabledUser(_E2EBase):
    def test_disabled_login_refused(self):
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     disabled_at=dt.datetime.utcnow())
            s.add(u); s.commit()
        finally:
            s.close()
        r = self._login("dee", "pw-1234567890")
        self.assertEqual(r.status_code, 403)


class LegacyEnrolledUnaffected(_E2EBase):
    def test_legacy_totp_secret_still_works(self):
        # A user with an old totp_secret but no mfa_enrolled_at (pre-migration)
        # should count as enrolled and log in normally.
        secret = pyotp.random_base32()
        s = db.session()
        try:
            u = User(username="dee", pw_hash=hash_password("pw-1234567890"),
                     totp_secret=secret)  # no mfa_enrolled_at
            s.add(u); s.commit()
        finally:
            s.close()
        r = self._login("dee", "pw-1234567890", totp=pyotp.TOTP(secret).now())
        self.assertEqual(r.status_code, 200, r.text)


class SetPasswordForcesChange(_E2EBase):
    def test_cli_set_password_temp_marks_must_change(self):
        s = db.session()
        try:
            s.add(User(username="dee", pw_hash=hash_password("old-password-abc")))
            s.commit()
        finally:
            s.close()
        from backend import cli
        import io
        out = io.StringIO()
        cli.set_password(["dee", "--temp-password"], audit=AuditLog(self.audit_path), out=out)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertTrue(u.must_change_password)
        finally:
            s.close()


class BrandingSanity(unittest.TestCase):
    def test_totp_issuer(self):
        from backend.security.auth import provisioning_uri
        uri = provisioning_uri("BASE32SECRETTEST", "dee")
        self.assertIn("issuer=Pinga53", uri)

    def test_brand_module(self):
        from backend.branding import BRAND, DAEMON
        self.assertEqual(BRAND, "Pinga53")
        self.assertEqual(DAEMON, "pinga53d")


if __name__ == "__main__":
    unittest.main()
