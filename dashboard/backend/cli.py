# SPDX-License-Identifier: AGPL-3.0-only
"""Admin CLI subcommands (Order 13 item 8).

Every action audits. No subcommand ever prints or returns a totp_secret,
pw_hash, or recovery code. `create-admin` and `set-password` accept
`--temp-password` to generate a one-time random string (printed to stdout,
never to the audit log) and set `must_change_password`; without the flag
the caller supplies the password interactively via getpass.
"""
from __future__ import annotations
import datetime as dt
import getpass
import sys

from backend import db
from backend.audit.hash_chain import AuditLog
from backend.config import load
from backend.db.models import User, RecoveryCode, is_mfa_enrolled
from backend.security import auth as _auth
from backend.security.bootstrap import _one_time_password


class CliError(RuntimeError):
    pass


def _load():
    cfg = load()
    db.init(cfg.db_url)
    return cfg, AuditLog(cfg.audit_log)


def _find(session, username: str) -> User:
    u = session.query(User).filter(User.username == username).first()
    if not u:
        raise CliError(f"user '{username}' not found")
    return u


def _read_password(prompt: str = "New password: ") -> str:
    pw1 = getpass.getpass(prompt)
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        raise CliError("passwords do not match")
    if len(pw1) < 12:
        raise CliError("password must be at least 12 characters")
    return pw1


def create_admin(argv: list[str], *, audit=None, out=sys.stdout) -> int:
    """create-admin <user> [--temp-password] [--final]

    Default: prompt for a password twice, set it, mark must_change_password
    unless --final is given.
    With --temp-password: generate a one-time random password, print it to
    stdout, always mark must_change_password (--final is ignored)."""
    cfg, _audit = (None, audit) if audit is not None else _load()
    a = audit or _audit
    args = [x for x in argv if not x.startswith("--")]
    if not args:
        raise CliError("usage: pinga53d create-admin <user> [--temp-password] [--final]")
    username = args[0]
    temp = "--temp-password" in argv
    final = "--final" in argv
    s = db.session()
    try:
        if s.query(User).filter(User.username == username).first():
            raise CliError(f"user '{username}' already exists")
        if temp:
            pw = _one_time_password()
            must_change = 1
        else:
            pw = _read_password()
            must_change = 0 if final else 1
        u = User(username=username, pw_hash=_auth.hash_password(pw),
                 must_change_password=must_change)
        s.add(u); s.commit()
    finally:
        s.close()
    a.record("admin.create", actor="cli", data={"username": username, "must_change_password": bool(must_change)})
    if temp:
        print(username, file=out)
        print(pw, file=out)
        print("Temporary password. Change on first login. Not stored anywhere.", file=sys.stderr)
    else:
        print(f"user '{username}' created (must_change_password={bool(must_change)})", file=out)
    return 0


def set_password(argv: list[str], *, audit=None, out=sys.stdout) -> int:
    """set-password <user> [--final] [--temp-password]

    Prompts for a new password by default, or generates one with
    --temp-password. Sets must_change_password unless --final."""
    cfg, _audit = (None, audit) if audit is not None else _load()
    a = audit or _audit
    args = [x for x in argv if not x.startswith("--")]
    if not args:
        raise CliError("usage: pinga53d set-password <user> [--final] [--temp-password]")
    username = args[0]
    temp = "--temp-password" in argv
    final = "--final" in argv
    s = db.session()
    try:
        u = _find(s, username)
        if temp:
            pw = _one_time_password()
            u.must_change_password = 1
        else:
            pw = _read_password()
            u.must_change_password = 0 if final else 1
        u.pw_hash = _auth.hash_password(pw)
        s.commit()
    finally:
        s.close()
    a.record("admin.set_password", actor="cli", data={"username": username, "temp": temp, "final": final})
    if temp:
        print(username, file=out)
        print(pw, file=out)
        print("Temporary password. User must change on next login.", file=sys.stderr)
    else:
        print(f"password updated for '{username}'", file=out)
    return 0


def reset_mfa(argv: list[str], *, audit=None, out=sys.stdout) -> int:
    """reset-mfa <user>: clear TOTP secret and recovery codes."""
    cfg, _audit = (None, audit) if audit is not None else _load()
    a = audit or _audit
    if not argv:
        raise CliError("usage: pinga53d reset-mfa <user>")
    username = argv[0]
    s = db.session()
    try:
        u = _find(s, username)
        u.totp_secret = None
        u.mfa_enrolled_at = None
        u.mfa_pending_secret = None
        u.mfa_pending_expires = None
        u.last_totp_step = None
        s.query(RecoveryCode).filter(RecoveryCode.user_id == u.id).delete()
        s.commit()
    finally:
        s.close()
    a.record("admin.reset_mfa", actor="cli", data={"username": username})
    print(f"MFA cleared for '{username}' — user will re-enroll on next login", file=out)
    return 0


def disable_user(argv: list[str], *, audit=None, out=sys.stdout) -> int:
    cfg, _audit = (None, audit) if audit is not None else _load()
    a = audit or _audit
    if not argv:
        raise CliError("usage: pinga53d disable-user <user>")
    username = argv[0]
    s = db.session()
    try:
        u = _find(s, username)
        u.disabled_at = dt.datetime.utcnow()
        s.commit()
    finally:
        s.close()
    a.record("admin.disable_user", actor="cli", data={"username": username})
    print(f"user '{username}' disabled", file=out)
    return 0


def enable_user(argv: list[str], *, audit=None, out=sys.stdout) -> int:
    cfg, _audit = (None, audit) if audit is not None else _load()
    a = audit or _audit
    if not argv:
        raise CliError("usage: pinga53d enable-user <user>")
    username = argv[0]
    s = db.session()
    try:
        u = _find(s, username)
        u.disabled_at = None
        s.commit()
    finally:
        s.close()
    a.record("admin.enable_user", actor="cli", data={"username": username})
    print(f"user '{username}' enabled", file=out)
    return 0


def list_users(argv: list[str], *, audit=None, out=sys.stdout) -> int:
    if audit is None:
        _load()
    s = db.session()
    try:
        rows = s.query(User).order_by(User.username).all()
        header = f"{'USERNAME':<20} {'MFA':<12} {'LAST LOGIN':<26} STATUS"
        print(header, file=out)
        for u in rows:
            mfa = "enrolled" if is_mfa_enrolled(u) else "not-enrolled"
            last = u.last_login.isoformat() if u.last_login else "-"
            status = "disabled" if u.disabled_at is not None else "active"
            if u.must_change_password:
                status += " (must_change_pw)"
            print(f"{u.username:<20} {mfa:<12} {last:<26} {status}", file=out)
    finally:
        s.close()
    return 0


DISPATCH = {
    "create-admin": create_admin,
    "set-password": set_password,
    "reset-mfa": reset_mfa,
    "disable-user": disable_user,
    "enable-user": enable_user,
    "list-users": list_users,
}
