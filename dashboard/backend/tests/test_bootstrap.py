# SPDX-License-Identifier: AGPL-3.0-only
"""Bootstrap tests for Order 13 item 2.

Verifies that `create_bootstrap_admin` produces a strong random password,
provisions `administrator` with `must_change_password` set and no MFA
enrolled, refuses if the account exists, and returns the plaintext password
exactly once (never persists or logs it).
"""
from __future__ import annotations
import io
import os
import re
import string
import tempfile
import unittest

from backend import db
from backend.db.models import User, is_mfa_enrolled
from backend.security.bootstrap import (
    BootstrapError,
    create_bootstrap_admin,
    MIN_PASSWORD_LEN,
)
from backend.security.auth import verify_password


class _FakeAudit:
    def __init__(self):
        self.records = []

    def record(self, event, **kw):
        self.records.append((event, kw))


def _fresh_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db.init(f"sqlite:///{tmp.name}")
    return tmp.name


class BootstrapAdmin(unittest.TestCase):
    def setUp(self):
        self.db_path = _fresh_db()
        self.audit = _FakeAudit()

    def tearDown(self):
        os.unlink(self.db_path)

    def test_creates_administrator_with_random_password(self):
        pw = create_bootstrap_admin(self.audit)
        self.assertGreaterEqual(len(pw), MIN_PASSWORD_LEN)
        # printable, no ambiguous whitespace
        self.assertTrue(all(c in string.ascii_letters + string.digits + "-_" for c in pw),
                        f"password contains unexpected chars: {pw!r}")
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "administrator").first()
            self.assertIsNotNone(u)
            self.assertTrue(bool(u.must_change_password))
            self.assertIsNone(u.totp_secret)
            self.assertIsNone(u.mfa_enrolled_at)
            self.assertFalse(is_mfa_enrolled(u))
            self.assertTrue(verify_password(pw, u.pw_hash))
        finally:
            s.close()

    def test_password_is_random_across_calls(self):
        pw1 = create_bootstrap_admin(self.audit)
        # remove first admin manually to allow a second call — proves entropy
        s = db.session()
        try:
            s.query(User).filter(User.username == "administrator").delete()
            s.commit()
        finally:
            s.close()
        pw2 = create_bootstrap_admin(self.audit)
        self.assertNotEqual(pw1, pw2)

    def test_refuses_when_administrator_exists(self):
        create_bootstrap_admin(self.audit)
        with self.assertRaises(BootstrapError):
            create_bootstrap_admin(self.audit)

    def test_audit_records_no_secret(self):
        pw = create_bootstrap_admin(self.audit)
        self.assertTrue(self.audit.records, "bootstrap should audit")
        blob = repr(self.audit.records)
        self.assertNotIn(pw, blob, "password must never enter the audit log")
        # any password-looking token should be absent — we log only the event + username
        for ev, kw in self.audit.records:
            self.assertEqual(ev, "admin.bootstrap")
            self.assertEqual(kw.get("data", {}).get("username"), "administrator")
            self.assertNotIn("password", kw.get("data", {}))
            self.assertNotIn("pw_hash", kw.get("data", {}))


class DaemonRefusesIfNoUsers(unittest.TestCase):
    def setUp(self):
        self.db_path = _fresh_db()

    def tearDown(self):
        os.unlink(self.db_path)

    def test_refuses_empty(self):
        from backend.main import _refuse_if_no_users
        from backend.config import Config
        cfg = Config(
            bind_host="127.0.0.1", bind_port=8053, config_dir="/tmp",
            state_dir="/tmp", db_url=f"sqlite:///{self.db_path}",
            audit_log="/tmp/a.jsonl", secret_key="x" * 32, cors_origins=[],
            pihole_ftl_db="/tmp/x", pihole_api="https://127.0.0.1/api",
            pihole_app_password="", pihole_admin_url="/admin", require_mfa=True,
        )
        with self.assertRaises(SystemExit) as cm:
            _refuse_if_no_users(cfg)
        self.assertIn("bootstrap", str(cm.exception))

    def test_allows_when_admin_exists(self):
        from backend.main import _refuse_if_no_users
        from backend.config import Config
        from backend.security.bootstrap import create_bootstrap_admin
        cfg = Config(
            bind_host="127.0.0.1", bind_port=8053, config_dir="/tmp",
            state_dir="/tmp", db_url=f"sqlite:///{self.db_path}",
            audit_log="/tmp/a.jsonl", secret_key="x" * 32, cors_origins=[],
            pihole_ftl_db="/tmp/x", pihole_api="https://127.0.0.1/api",
            pihole_app_password="", pihole_admin_url="/admin", require_mfa=True,
        )
        create_bootstrap_admin(_FakeAudit())
        _refuse_if_no_users(cfg)  # must not raise


if __name__ == "__main__":
    unittest.main()
