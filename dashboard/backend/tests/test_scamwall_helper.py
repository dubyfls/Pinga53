# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the pinga53-helper bash binary.

The helper's job is strict argv validation and safe file edits. Running it
as root requires a running sudo + a sudoers drop-in, so these tests shell
the helper directly WITHOUT sudo and WITHOUT being root — the goal is to
exercise:

  1. argument validation refusals (bad subcommand, extra args, invalid hosts),
  2. root-only refusal (we are not root),
  3. stop-on/off behavior against a tempdir state tree (the subcommand
     is allowed to succeed as the current user because we override the
     STATE_DIR to our tempdir).

What we don't test here: `set_mode` (needs a real unbound.conf + systemctl)
and `run_now` (needs `/usr/local/bin/scamwall`). Those live in integration
tests for the installed system.
"""
from __future__ import annotations
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


HELPER = Path(__file__).resolve().parents[2] / "deploy" / "pinga53-helper"


class HelperShape(unittest.TestCase):
    def test_exists_and_executable(self):
        self.assertTrue(HELPER.exists(), HELPER)
        self.assertTrue(os.access(HELPER, os.X_OK))

    def test_bash_strict_mode(self):
        body = HELPER.read_text()
        self.assertEqual(body.splitlines()[0], "#!/usr/bin/env bash")
        self.assertIn("set -Eeuo pipefail", body)


class NonRootIsRefused(unittest.TestCase):
    def test_refuses_without_root(self):
        if os.geteuid() == 0:
            self.skipTest("test must run as non-root")
        r = subprocess.run([str(HELPER), "stop-on"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must run as root", r.stderr)


class _FakeRootBase(unittest.TestCase):
    """Fake EUID=0 by exporting EUID=0 in the environment. The helper uses
    ${EUID:-$(id -u)} so an explicit EUID=0 short-circuits the root check.
    This DOES NOT give us real root; it merely lets us exercise the argv
    paths that do not touch root-only files. We point the helper at a
    tempdir for state and keep operations within it.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pinga53-helper-"))
        self.env = {
            **os.environ,
            "EUID": "0",
            "PINGA53_SCAMWALL_STATE": str(self.tmp / "state"),
            "PINGA53_SCAMWALL_STOP_FLAG": str(self.tmp / "state" / "STOP-AUTOMATIC"),
            "PINGA53_PROTECTED": str(self.tmp / "protected.txt"),
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args, env_extra=None):
        env = self.env
        if env_extra:
            env = {**env, **env_extra}
        return subprocess.run([str(HELPER), *args], capture_output=True, text=True, env=env)


class UsageAndRefusals(_FakeRootBase):
    def test_no_args_prints_usage_and_exits_2(self):
        r = self._run()
        self.assertEqual(r.returncode, 2)
        self.assertIn("subcommands", r.stderr)

    def test_unknown_subcommand(self):
        r = self._run("delete-everything")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown subcommand", r.stderr)

    def test_stop_on_takes_no_arguments(self):
        r = self._run("stop-on", "oops")
        self.assertEqual(r.returncode, 1)
        self.assertIn("takes no arguments", r.stderr)

    def test_protect_add_requires_host(self):
        r = self._run("protect-add")
        self.assertEqual(r.returncode, 1)
        self.assertIn("protect-add HOST", r.stderr)


class StopFlagToggles(_FakeRootBase):
    def test_on_then_off(self):
        flag = Path(self.env["PINGA53_SCAMWALL_STOP_FLAG"])
        r = self._run("stop-on")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(flag.exists())
        r = self._run("stop-off")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(flag.exists())


class HostValidation(_FakeRootBase):
    def _bad(self, host: str):
        r = self._run("protect-add", host)
        self.assertEqual(r.returncode, 1, (host, r.stderr))
        self.assertIn("invalid argument", r.stderr)

    def test_rejects_empty(self):
        self._bad("")

    def test_rejects_too_long(self):
        self._bad("a" * 254 + ".com")

    def test_rejects_no_dot(self):
        self._bad("localhost")

    def test_rejects_uppercase(self):
        self._bad("Evil.Example")

    def test_rejects_leading_hyphen(self):
        self._bad("-bad.example")

    def test_rejects_trailing_hyphen(self):
        self._bad("bad-.example")

    def test_rejects_whitespace(self):
        self._bad("bad example.com")

    def test_rejects_shell_metacharacters(self):
        self._bad("evil.example;rm -rf /")
        self._bad("evil.example$(whoami)")
        self._bad("evil`id`.example")

    def test_rejects_newline(self):
        self._bad("evil.example\nanother.example")


class ProtectAddRemove(_FakeRootBase):
    def test_add_then_remove(self):
        p = Path(self.env["PINGA53_PROTECTED"])
        r = self._run("protect-add", "safe.example")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("safe.example", p.read_text())
        r = self._run("protect-add", "safe.example")
        self.assertEqual(r.returncode, 0)
        self.assertIn("already present", r.stdout)
        r = self._run("protect-remove", "safe.example")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("safe.example", p.read_text())


class SubcommandAllowlist(_FakeRootBase):
    """Every subcommand must be one of the fixed allowlist entries."""

    ALLOWED = (
        "stop-on", "stop-off", "mode-shadow", "mode-enforce",
        "protect-add", "protect-remove", "run-now",
    )

    def test_rejects_anything_outside_allowlist(self):
        for bogus in ("exec", "shutdown", "install-pihole", "mode-off",
                      "protect-wipe", "..", "stop-on ; rm -rf"):
            r = self._run(bogus)
            self.assertEqual(r.returncode, 2, bogus)
            self.assertIn("unknown subcommand", r.stderr)


if __name__ == "__main__":
    unittest.main()


class ModeSwitch(_FakeRootBase):
    """mode-shadow / mode-enforce edit the rpz stanza install.sh writes."""

    STANZA = ('rpz:\n    name: "scamwall.rpz"\n    zonefile: "/etc/unbound/rpz/scamwall.zone"\n'
              '    rpz-action-override: passthru\n    rpz-log: yes\n')

    def _env(self, checkconf_ok=True):
        conf = self.tmp / "pinga53.conf"
        if not conf.exists():
            conf.write_text(self.STANZA)
        stub = self.tmp / "bin"; stub.mkdir(exist_ok=True)
        (stub / "checkconf").write_text("#!/bin/sh\nexit %d\n" % (0 if checkconf_ok else 1))
        (stub / "systemctl").write_text("#!/bin/sh\nexit 0\n")
        for f in ("checkconf", "systemctl"):
            os.chmod(stub / f, 0o755)
        return conf, {"PINGA53_UNBOUND_CONF": str(conf),
                      "PINGA53_UNBOUND_CHECKCONF": str(stub / "checkconf"),
                      "PINGA53_SYSTEMCTL": str(stub / "systemctl")}

    def _can_install(self):
        return os.geteuid() == 0

    def test_enforce_then_shadow_round_trip(self):
        if not self._can_install():
            self.skipTest("install -o root needs real root")
        conf, extra = self._env()
        self.assertEqual(self._run("mode-enforce", env_extra=extra).returncode, 0)
        self.assertNotIn("rpz-action-override", conf.read_text())
        self.assertEqual(self._run("mode-shadow", env_extra=extra).returncode, 0)
        self.assertEqual(conf.read_text().count("rpz-action-override: passthru"), 1)

    def test_rejected_config_is_restored(self):
        if not self._can_install():
            self.skipTest("install -o root needs real root")
        conf, extra = self._env(checkconf_ok=False)
        before = conf.read_text()
        r = self._run("mode-enforce", env_extra=extra)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(conf.read_text(), before)

    def test_mode_requires_rpz_stanza(self):
        conf, extra = self._env()
        conf.write_text("server:\n    port: 5335\n")
        r = self._run("mode-enforce", env_extra=extra)
        self.assertEqual(r.returncode, 3)
        self.assertIn("no rpz stanza", r.stderr)
