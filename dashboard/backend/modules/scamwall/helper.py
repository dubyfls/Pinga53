# SPDX-License-Identifier: AGPL-3.0-only
"""Thin wrapper around /usr/local/sbin/pinga53-helper.

The dashboard runs as a non-root `pinga53` user. All state-changing ScamWall
actions therefore go through the helper, which is called via a sudoers
drop-in that whitelists exactly this one binary for this one user. The helper
itself validates its subcommand against a fixed allowlist and refuses anything
else; see SECURITY.md.

This module is deliberately minimal: argv composition, an exec via sudo, and
an error type. Argument validation lives at the API layer; the helper repeats
it, and this layer does not try to second-guess either.
"""
from __future__ import annotations
import os
import subprocess


class HelperError(RuntimeError):
    pass


_ALLOWED = (
    "stop-on", "stop-off",
    "mode-shadow", "mode-enforce",
    "protect-add", "protect-remove",
    "run-now",
)


def run_helper(binary: str, action: str, *args: str,
               use_sudo: bool = True, timeout: float = 15.0) -> str:
    if action not in _ALLOWED:
        raise HelperError(f"helper: refusing unknown action: {action!r}")
    for a in args:
        if not isinstance(a, str) or any(ch in a for ch in ("\x00", "\n", "\r")):
            raise HelperError("helper: refusing argument with control character")
    argv: list[str] = []
    if use_sudo:
        argv += ["/usr/bin/sudo", "-n", "--"]
    argv += [binary, action, *args]
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            env=env, check=False,
        )
    except FileNotFoundError as e:
        raise HelperError(f"helper not found: {e}")
    except subprocess.TimeoutExpired:
        raise HelperError("helper timed out")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout or "").strip()
        raise HelperError(f"helper exit {p.returncode}: {msg[:400]}")
    return (p.stdout or "").strip()
