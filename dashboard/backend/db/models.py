# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 DB layer — SQLAlchemy models + idempotent startup migration.

Stores Argon2 password hashes, optional TOTP secrets, and one-shot recovery
codes as hashes. Never stores plaintext.

Migration policy: on every `init()`, we ensure the schema matches the current
model. Missing columns on `users` are added via `ALTER TABLE ADD COLUMN`
(SQLite supports this for nullable columns without a default) and any new
tables are created via `Base.metadata.create_all`. Safe to re-run.
"""
from __future__ import annotations
import datetime as dt

from sqlalchemy import create_engine, String, DateTime, Integer, ForeignKey, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    pw_hash: Mapped[str] = mapped_column(String(255))
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=lambda: dt.datetime.now(dt.timezone.utc))
    last_login: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    # Order 13 additions — self-service auth + MFA.
    mfa_pending_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_pending_expires: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    mfa_enrolled_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    last_totp_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    must_change_password: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disabled_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(255))
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


def is_mfa_enrolled(user: User) -> bool:
    """A user is enrolled if the migration marked them (mfa_enrolled_at) OR they
    still carry a `totp_secret` from before the migration existed."""
    return user.mfa_enrolled_at is not None or bool(user.totp_secret)


# ADD COLUMN specs for the migration. SQLite requires simple defaults; we use
# NULL for datetime/int/text and 0 for the must_change_password flag.
_USERS_MIGRATIONS: list[tuple[str, str]] = [
    ("mfa_pending_secret",    "VARCHAR(64)"),
    ("mfa_pending_expires",   "DATETIME"),
    ("mfa_enrolled_at",       "DATETIME"),
    ("last_totp_step",        "INTEGER"),
    ("must_change_password",  "INTEGER NOT NULL DEFAULT 0"),
    ("disabled_at",           "DATETIME"),
]


def _migrate_users(engine) -> None:
    insp = inspect(engine)
    if "users" not in insp.get_table_names():
        return  # create_all will build it fresh with the current model
    existing = {c["name"] for c in insp.get_columns("users")}
    with engine.begin() as conn:
        for col, decl in _USERS_MIGRATIONS:
            if col in existing:
                continue
            conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {decl}"))


_engine = None
_Session = None


def init(db_url: str):
    global _engine, _Session
    if db_url.startswith("sqlite:///"):
        import os
        path = db_url.replace("sqlite:///", "", 1)
        if path and path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    _engine = create_engine(db_url, connect_args=connect_args, future=True)
    _migrate_users(_engine)
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def session():
    if _Session is None:
        raise RuntimeError("db.init() not called")
    return _Session()
