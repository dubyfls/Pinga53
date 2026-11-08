# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 audit log — append-only, hash-chained, tamper-evident.

Each record carries the SHA-256 of the previous record. Any edit/deletion in
the middle breaks the chain and is detectable via verify(). This is the spine
of the "every config change is audited" guarantee.
"""
from __future__ import annotations
import json
import os
import hashlib
import datetime as dt
import threading

_lock = threading.Lock()
_GENESIS = "0" * 64


def _digest(prev_hash: str, payload: dict) -> str:
    body = prev_hash + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def _last_hash(path: str) -> str:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return _GENESIS
    with open(path, "rb") as f:
        # read last non-empty line
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = min(size, 4096)
        f.seek(size - block)
        last = f.read().splitlines()[-1]
    try:
        return json.loads(last)["hash"]
    except Exception:
        return _GENESIS


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def record(self, event: str, *, actor: str = "system", ip: str = "-", **fields) -> dict:
        with _lock:
            prev = _last_hash(self.path)
            payload = {
                "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                "event": event,
                "actor": actor,
                "ip": ip,
                "data": fields,
                "prev": prev,
            }
            rec = {**payload, "hash": _digest(prev, payload)}
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            return rec

    def verify(self) -> tuple[bool, int]:
        """Returns (intact, records_checked). False if the chain is broken."""
        if not os.path.exists(self.path):
            return True, 0
        prev = _GENESIS
        n = 0
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                payload = {k: rec[k] for k in ("ts", "event", "actor", "ip", "data", "prev")}
                if rec["prev"] != prev or rec["hash"] != _digest(prev, payload):
                    return False, n
                prev = rec["hash"]
                n += 1
        return True, n
