# SPDX-License-Identifier: AGPL-3.0-only
"""Admin CLI tests for Order 13 item 8.

CLI functions accept an audit mock and a stdout buffer so we can assert on
both without spawning a subprocess. Password prompts are patched via
`getpass.getpass` for the non-`--temp-password` paths.
"""
from __future__ import annotations
import datetime as dt
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from backend import db
from backend.db.models import User, RecoveryCode
from backend.security.auth import hash_password, new_totp_secret
from backend import cli


class _Audit:
    def __init__(self):
        self.records = []

    def record(self, event, **kw):
        self.records.append((event, kw))


class _BaseCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False); self.tmp.close()
        db.init(f"sqlite:///{self.tmp.name}")
        self.audit = _Audit()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _seed(self, username, **kw):
        s = db.session()
        try:
            u = User(username=username, pw_hash=hash_password("initial-pw-1234"), **kw)
            s.add(u); s.commit(); s.refresh(u)
            return u.id
        finally:
            s.close()


class CreateAdmin(_BaseCli):
    def test_create_with_temp_password(self):
        out = io.StringIO()
        cli.create_admin(["dee", "--temp-password"], audit=self.audit, out=out)
        first, pw, *_ = out.getvalue().splitlines()
        self.assertEqual(first, "dee")
        self.assertGreaterEqual(len(pw), 16)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertTrue(u.must_change_password)
            self.assertIsNone(u.totp_secret)
        finally:
            s.close()
        self.assertEqual(self.audit.records[0][0], "admin.create")
        self.assertNotIn(pw, str(self.audit.records))

    def test_create_interactive(self):
        out = io.StringIO()
        with patch("backend.cli.getpass.getpass", side_effect=["strong-password-x", "strong-password-x"]):
            cli.create_admin(["dee"], audit=self.audit, out=out)
        self.assertIn("dee", out.getvalue())
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertTrue(u.must_change_password)
        finally:
            s.close()

    def test_final_skips_must_change(self):
        out = io.StringIO()
        with patch("backend.cli.getpass.getpass", side_effect=["strong-password-x", "strong-password-x"]):
            cli.create_admin(["dee", "--final"], audit=self.audit, out=out)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertFalse(u.must_change_password)
        finally:
            s.close()

    def test_refuses_duplicate(self):
        self._seed("dee")
        with self.assertRaises(cli.CliError):
            cli.create_admin(["dee", "--temp-password"], audit=self.audit, out=io.StringIO())


class SetPassword(_BaseCli):
    def test_temp_sets_must_change(self):
        self._seed("dee")
        out = io.StringIO()
        cli.set_password(["dee", "--temp-password"], audit=self.audit, out=out)
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertTrue(u.must_change_password)
        finally:
            s.close()
        pw = out.getvalue().splitlines()[1]
        self.assertNotIn(pw, str(self.audit.records))

    def test_final_skips_must_change(self):
        self._seed("dee")
        with patch("backend.cli.getpass.getpass", side_effect=["another-strong-pw", "another-strong-pw"]):
            cli.set_password(["dee", "--final"], audit=self.audit, out=io.StringIO())
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertFalse(u.must_change_password)
        finally:
            s.close()


class ResetMfa(_BaseCli):
    def test_clears_secret_and_codes(self):
        uid = self._seed("dee", totp_secret=new_totp_secret(), mfa_enrolled_at=dt.datetime.utcnow())
        s = db.session()
        try:
            s.add(RecoveryCode(user_id=uid, code_hash="h1"))
            s.add(RecoveryCode(user_id=uid, code_hash="h2"))
            s.commit()
        finally:
            s.close()
        cli.reset_mfa(["dee"], audit=self.audit, out=io.StringIO())
        s = db.session()
        try:
            u = s.query(User).filter(User.username == "dee").first()
            self.assertIsNone(u.totp_secret)
            self.assertIsNone(u.mfa_enrolled_at)
            self.assertEqual(s.query(RecoveryCode).count(), 0)
        finally:
            s.close()


class DisableEnable(_BaseCli):
    def test_disable_then_enable(self):
        self._seed("dee")
        cli.disable_user(["dee"], audit=self.audit, out=io.StringIO())
        s = db.session()
        try:
            self.assertIsNotNone(s.query(User).filter(User.username == "dee").first().disabled_at)
        finally:
            s.close()
        cli.enable_user(["dee"], audit=self.audit, out=io.StringIO())
        s = db.session()
        try:
            self.assertIsNone(s.query(User).filter(User.username == "dee").first().disabled_at)
        finally:
            s.close()


class ListUsers(_BaseCli):
    def test_prints_columns_and_no_secrets(self):
        self._seed("dee", totp_secret=new_totp_secret(), mfa_enrolled_at=dt.datetime.utcnow())
        self._seed("loki")
        out = io.StringIO()
        cli.list_users([], audit=self.audit, out=out)
        text = out.getvalue()
        self.assertIn("USERNAME", text)
        self.assertIn("MFA", text)
        self.assertIn("dee", text)
        self.assertIn("enrolled", text)
        self.assertIn("loki", text)
        self.assertIn("not-enrolled", text)
        self.assertNotIn("SECRETSECRET", text)
        self.assertNotIn("initial-pw", text)


if __name__ == "__main__":
    unittest.main()
