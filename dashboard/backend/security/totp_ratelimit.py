# SPDX-License-Identifier: AGPL-3.0-only
"""Per-user TOTP failure rate limit (Order 13 item 6).

5 failed codes per user per 5 minutes → lockout for the remainder of the
window. Login callers query `remaining_lockout_seconds(user)` before checking
the code and `record_failure(user)` when the code is wrong. Successful
verifications call `reset(user)` so a legitimate user isn't stuck.
"""
from __future__ import annotations
import threading
import time
from collections import defaultdict, deque


FAIL_LIMIT = 5
WINDOW_SECONDS = 300


class _State:
    def __init__(self):
        self.failures: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()


_state = _State()


def _prune(q: deque, now: float) -> None:
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()


def remaining_lockout_seconds(user: str, now: float | None = None) -> int:
    """0 if the user may attempt now, else the seconds until they can retry."""
    ts = now if now is not None else time.time()
    with _state.lock:
        q = _state.failures[user]
        _prune(q, ts)
        if len(q) < FAIL_LIMIT:
            return 0
        oldest = q[0]
        return max(0, int(WINDOW_SECONDS - (ts - oldest)) + 1)


def record_failure(user: str, now: float | None = None) -> int:
    """Register a failed attempt. Returns the count of failures still in the
    window after this one (useful for logging)."""
    ts = now if now is not None else time.time()
    with _state.lock:
        q = _state.failures[user]
        _prune(q, ts)
        q.append(ts)
        return len(q)


def reset(user: str) -> None:
    with _state.lock:
        _state.failures.pop(user, None)


def reset_all() -> None:
    """Test hook."""
    with _state.lock:
        _state.failures.clear()
