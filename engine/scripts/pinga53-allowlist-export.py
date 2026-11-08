#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""pinga53-allowlist-export.py — export the household's Pi-hole allow entries.

Runs as the `scamwall` system user via
`pinga53-allowlist-export.timer`. Opens the Pi-hole gravity.db strictly
read-only (SQLite URI `?mode=ro&immutable=1`), reads only the tables
this exporter names, and writes the result atomically to
`/var/lib/scamwall/allowlist.json` in the shape
`internal/rpz/snapshot_pinga53.go::LoadPinga53Snapshot` reads.

WHY READ-ONLY EVEN THOUGH THIS ACCOUNT HAS NO WRITE PERMISSION.

The `scamwall` unit runs with `ProtectSystem=strict` and
`ReadWritePaths` scoped to `/var/lib/scamwall` alone, so it CANNOT write
to `/etc/pihole` regardless. `?mode=ro&immutable=1` on top of that:

  1. Tells SQLite it will not journal, checkpoint, or lock the file — a
     concurrent `pihole -g` run on the household's schedule cannot be
     slowed down by this exporter as an accident.
  2. Makes an accidental `PRAGMA writable_schema=ON` at some future edit
     of this script a hard failure rather than a silent power to change
     the schema.

WHY NOT EXPORT EVERYTHING THE DB HOLDS.

The order names three tables' worth of data explicitly. Anything else —
deny entries, client rows, group membership, the query journal — either
would be misinterpreted downstream (deny entries in the allow-only
snapshot) or is intelligence about the household this exporter has no
reason to send anywhere.

The queries below therefore SELECT only what the order names. A future
edit that adds a new SELECT must add its column names to the queries
here, so the audit surface is one grep.

WHY FAIL CLOSED ON UNKNOWN SCHEMA OR MISSING TABLE.

An unknown schema means we cannot say whether the semantics of `type`,
`enabled` or the join columns still mean what this exporter believes
they mean. The safe default is to refuse: the writer freezes on an
absent snapshot, so nothing gets blocked that shouldn't. A partial
export against a schema this build no longer understands is worse than
none: it is a machine-generated statement of confidence that this build
knows what it does not.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile


# The output shape's schema version. Bumped only when
# `internal/rpz/snapshot_pinga53.go::Pinga53SnapshotSchemaVersion` is
# bumped in the same commit — the reader refuses anything else.
OUTPUT_SCHEMA = 1

# domainlist.type values, per Pi-hole's `sql/gravity.db.sql`:
#   0 = exact allow (whitelist)
#   1 = exact deny (blacklist)      — NEVER exported
#   2 = regex allow (whitelist regex)
#   3 = regex deny (blacklist regex) — NEVER exported
DOMAINLIST_EXACT_ALLOW = 0
DOMAINLIST_REGEX_ALLOW = 2

# adlist.type values:
#   0 = block subscription (gravity feed)   — NEVER exported
#   1 = allow subscription (antigravity feed)
ADLIST_ALLOW_TYPE = 1

# Every gravity.db schema version this exporter has been read against.
# See owner question O-3 in scamwall/docs/orders/ORDER_12_PROGRESS.md for
# the household's currently-installed version and the range's rationale.
SUPPORTED_SCHEMA_VERSIONS = frozenset({18, 19, 20, 21})

# Required tables — a missing one is a fail-closed condition. The four
# names below are exactly what the SELECTs in this file reach for.
REQUIRED_TABLES = frozenset({"domainlist", "adlist", "antigravity", "info"})


class ExportError(Exception):
    """Fatal — the exporter exits non-zero with this message on stderr.

    Distinct from sqlite3.Error so a bad-schema condition and a genuine
    disk failure produce different exit paths and different log lines.
    """


def _sha256_file(path: str, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of the whole file. Chunked so a large gravity.db does not
    load into memory. The digest identifies WHICH DB this snapshot came
    from — it is not a per-entry integrity check."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_ro(gravity_path: str) -> sqlite3.Connection:
    """Open gravity.db in the most read-only mode SQLite supports.

    `mode=ro` — SQLite will refuse any write attempt.
    `immutable=1` — SQLite treats the file as never-changing for the
    duration of this connection: no journaling, no checkpointing, no
    file locks. Correct here because we hold the connection open only
    for the few short SELECTs below, and a concurrent Pi-hole update
    would land in a NEW file (Pi-hole rebuilds gravity by writing to a
    temp path and renaming, so an in-flight read sees a consistent
    snapshot at the inode level anyway).
    """
    if not os.path.isfile(gravity_path):
        raise ExportError(f"gravity.db not found: {gravity_path}")
    uri = f"file:{gravity_path}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _check_schema(conn: sqlite3.Connection, allowed_versions: frozenset[int]) -> int:
    """Refuse to read anything this build does not understand.

    Order matters: check tables FIRST so a missing `info` table returns
    a table-level error, not a "version unreadable" one — the two mean
    different things and the operator needs to be able to tell them apart.
    """
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ("
        + ",".join("?" for _ in REQUIRED_TABLES)
        + ")",
        tuple(sorted(REQUIRED_TABLES)),
    ).fetchall()
    present = {row["name"] for row in rows}
    missing = REQUIRED_TABLES - present
    if missing:
        raise ExportError(
            "gravity.db is missing required table(s): "
            + ", ".join(sorted(missing))
        )

    row = conn.execute(
        "SELECT value FROM info WHERE property='version'"
    ).fetchone()
    if row is None:
        raise ExportError("gravity.db info.version property is missing")
    raw = row["value"]
    try:
        version = int(raw)
    except (TypeError, ValueError) as e:
        raise ExportError(
            f"gravity.db info.version is not an integer: {raw!r}"
        ) from e
    if version not in allowed_versions:
        raise ExportError(
            f"gravity.db schema version {version} is not in the "
            f"supported set {sorted(allowed_versions)} — refusing to "
            f"export against a schema this build has not been read against"
        )
    return version


def _export_exact_allow(conn: sqlite3.Connection) -> list[str]:
    return [
        row["domain"]
        for row in conn.execute(
            "SELECT DISTINCT domain FROM domainlist "
            "WHERE type=? AND enabled=1 ORDER BY domain",
            (DOMAINLIST_EXACT_ALLOW,),
        )
    ]


def _export_regex_allow(conn: sqlite3.Connection) -> list[str]:
    return [
        row["domain"]
        for row in conn.execute(
            "SELECT DISTINCT domain FROM domainlist "
            "WHERE type=? AND enabled=1 ORDER BY domain",
            (DOMAINLIST_REGEX_ALLOW,),
        )
    ]


def _export_subscribed_allow(conn: sqlite3.Connection) -> list[str]:
    """Domains contributed by ENABLED allow-type subscriptions.

    A subscription's domains are the rows the adlist materialised into
    `antigravity` at its last update. Deny-type subscriptions land in
    `gravity` and are not read here. A disabled subscription is a
    subscription the household turned off — its domains do not belong
    in the snapshot."""
    return [
        row["domain"]
        for row in conn.execute(
            "SELECT DISTINCT antigravity.domain "
            "FROM antigravity "
            "JOIN adlist ON adlist.id = antigravity.adlist_id "
            "WHERE adlist.enabled=1 AND adlist.type=? "
            "ORDER BY antigravity.domain",
            (ADLIST_ALLOW_TYPE,),
        )
    ]


def _atomic_write(path: str, payload: bytes, mode: int = 0o644) -> None:
    """Write `payload` to `path` atomically.

    Writing is: create a temp file in the SAME DIRECTORY as `path`, write,
    fsync, chmod, rename. Same-directory is what makes `rename` atomic on
    POSIX (a rename across filesystems degrades to copy-then-unlink, which
    is not atomic). If any step raises, the temp file is removed so a
    failed run does not leave a partial `.allowlist-*.json` behind."""
    dst_dir = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".allowlist-", suffix=".json", dir=dst_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)  # atomic on POSIX
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def export(
    gravity_path: str,
    output_path: str,
    *,
    now: dt.datetime | None = None,
    allowed_versions: frozenset[int] = SUPPORTED_SCHEMA_VERSIONS,
) -> dict:
    """Read the three allow-list slices from `gravity_path` and write the
    Pinga53 snapshot to `output_path`. Returns the document that was
    written, so callers (main, tests) can log counts without re-reading
    the file."""
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    # Open first so the "gravity.db not found" ExportError takes precedence
    # over an OSError from _sha256_file trying to read a missing file. The
    # two look the same to the OS but only the former is a documented
    # refusal path an operator can act on.
    conn = _open_ro(gravity_path)
    try:
        source_sha256 = _sha256_file(gravity_path)
        _check_schema(conn, allowed_versions)
        exact = _export_exact_allow(conn)
        regex = _export_regex_allow(conn)
        subscribed = _export_subscribed_allow(conn)
    finally:
        conn.close()
    doc = {
        "schema": OUTPUT_SCHEMA,
        # RFC 3339 UTC ("Z" suffix) so the reader's time.Time.UnmarshalJSON
        # parses it without ambiguity.
        "generated_at": now.astimezone(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "source_sha256": source_sha256,
        "exact_allow": exact,
        "regex_allow": regex,
        "subscribed_allow": subscribed,
    }
    payload = (json.dumps(doc, indent=2, sort_keys=False) + "\n").encode("utf-8")
    _atomic_write(output_path, payload)
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Export Pi-hole allow entries into Pinga53's snapshot format.",
    )
    p.add_argument("--gravity", default="/etc/pihole/gravity.db",
                   help="path to gravity.db (default %(default)s)")
    p.add_argument("--output", default="/var/lib/scamwall/allowlist.json",
                   help="output snapshot path (default %(default)s)")
    p.add_argument("--allowed-versions", default=None,
                   help="comma-separated integers to override the built-in "
                        "supported set; use with care")
    args = p.parse_args(argv)

    versions = SUPPORTED_SCHEMA_VERSIONS
    if args.allowed_versions is not None:
        try:
            versions = frozenset(int(v) for v in args.allowed_versions.split(","))
        except ValueError:
            print(
                "pinga53-allowlist-export: --allowed-versions must be "
                "comma-separated integers",
                file=sys.stderr,
            )
            return 2

    try:
        doc = export(args.gravity, args.output, allowed_versions=versions)
    except ExportError as e:
        # Named category — the schema or table check refused the DB.
        print(f"pinga53-allowlist-export: {e}", file=sys.stderr)
        return 2
    except sqlite3.Error as e:
        # SQLite-level failure — corrupt file, permission denied on a
        # temp journal, etc. Kept distinct from ExportError so log
        # readers can tell "we refused this DB" from "we could not open
        # this DB".
        print(
            f"pinga53-allowlist-export: sqlite error: {e}",
            file=sys.stderr,
        )
        return 2
    except OSError as e:
        # A failure to write the output — permission denied on
        # /var/lib/scamwall, disk full, etc.
        print(
            f"pinga53-allowlist-export: could not write output: {e}",
            file=sys.stderr,
        )
        return 2

    print(
        f"pinga53-allowlist-export: wrote {args.output} "
        f"(exact={len(doc['exact_allow'])} "
        f"regex={len(doc['regex_allow'])} "
        f"subscribed={len(doc['subscribed_allow'])} "
        f"source_sha256={doc['source_sha256'][:12]})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
