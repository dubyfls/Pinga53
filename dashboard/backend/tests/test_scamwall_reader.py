# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for backend/modules/scamwall/reader.py.

Each test writes fixture files under a tempdir and asserts the reader's
view. No live services are touched. The reader is designed to never raise
on a missing or malformed file; the tests exercise that contract alongside
the happy paths.
"""
from __future__ import annotations
import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from backend.modules.scamwall.reader import ScamWallReader


@dataclass
class _FakeCfg:
    unbound_conf: str
    scamwall_zone: str
    scamwall_state: str
    scamwall_stop_flag: str
    scamwall_install_log: str


class _ReaderBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pinga53-sw-"))
        self.state = self.tmp / "state"
        for sub in ("metrics", "journal", "records", "out"):
            (self.state / sub).mkdir(parents=True, exist_ok=True)
        self.zone = self.tmp / "scamwall.zone"
        self.conf = self.tmp / "pinga53.conf"
        self.stop = self.state / "STOP-AUTOMATIC"
        self.log = self.tmp / "scamwall-install.log"
        self.cfg = _FakeCfg(
            unbound_conf=str(self.conf),
            scamwall_zone=str(self.zone),
            scamwall_state=str(self.state),
            scamwall_stop_flag=str(self.stop),
            scamwall_install_log=str(self.log),
        )
        self.r = ScamWallReader.from_config(self.cfg)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class MissingFiles(_ReaderBase):
    def test_everything_missing_returns_defaults(self):
        self.assertEqual(self.r.mode(), "unknown")
        self.assertFalse(self.r.stop_automatic())
        self.assertEqual(self.r.hosts(), {"count": 0, "hosts": []})
        self.assertEqual(self.r.hits_today()["total"], 0)
        self.assertEqual(self.r.feed_health()["sources"], [])
        self.assertFalse(self.r.last_decision()["available"])
        self.assertFalse(self.r.last_install()["available"])
        # overview should return something coherent
        ov = self.r.overview()
        self.assertEqual(ov["mode"], "unknown")
        self.assertEqual(ov["hosts"]["count"], 0)


class ModeShadow(_ReaderBase):
    def test_passthru_means_shadow(self):
        self.conf.write_text(
            "rpz:\n"
            "    name: scamwall.\n"
            "    zonefile: /etc/unbound/rpz/scamwall.zone\n"
            "    action-override: passthru\n"
        )
        self.assertEqual(self.r.mode(), "shadow")


class ModeEnforce(_ReaderBase):
    def test_nxdomain_means_enforce(self):
        self.conf.write_text(
            "rpz:\n"
            "    name: scamwall.\n"
            "    action-override: nxdomain\n"
        )
        self.assertEqual(self.r.mode(), "enforce")


class StopFlag(_ReaderBase):
    def test_file_presence_toggles_flag(self):
        self.assertFalse(self.r.stop_automatic())
        self.stop.write_text("")
        self.assertTrue(self.r.stop_automatic())


class ZoneHostsParsed(_ReaderBase):
    def test_hosts_are_extracted_from_zone(self):
        body = (
            "; comment\n"
            "$ORIGIN scamwall.\n"
            "@ 3600 IN SOA localhost. root.localhost. 1 3600 600 86400 3600\n"
            "evil.example. CNAME .\n"
            "bad.phish.test. CNAME .\n"
            "\n"
            "   \n"
        )
        self.zone.write_text(body)
        out = self.r.hosts()
        self.assertEqual(out["count"], 2)
        self.assertIn("evil.example", out["hosts"])
        self.assertIn("bad.phish.test", out["hosts"])


class SummaryHits(_ReaderBase):
    def test_hits_today_reads_summary(self):
        (self.state / "metrics" / "summary.json").write_text(
            json.dumps({"shadow_hits": 42, "generated_at": "2026-11-08T00:00:00Z"})
        )
        out = self.r.hits_today()
        self.assertEqual(out["total"], 42)
        self.assertEqual(out["generated_at"], "2026-11-08T00:00:00Z")


class FeedHealth(_ReaderBase):
    def test_feed_health_merges_health_file(self):
        rec = self.state / "records" / "cert-polska-warning-list.json"
        rec.write_text(json.dumps({
            "schema_version": 1,
            "source_id": "cert-polska-warning-list",
            "written_at": "2026-11-08T01:00:00Z",
            "cadence_hours": 4,
            "record_count": 1200,
            "records": [],
        }))
        (self.state / "records" / "_health.json").write_text(json.dumps({
            "cert-polska-warning-list": {
                "last_success": "2026-11-08T01:00:00Z",
                "last_error": None,
            }
        }))
        out = self.r.feed_health()
        self.assertEqual(len(out["sources"]), 1)
        s = out["sources"][0]
        self.assertEqual(s["source_id"], "cert-polska-warning-list")
        self.assertEqual(s["record_count"], 1200)
        self.assertEqual(s["last_success"], "2026-11-08T01:00:00Z")

    def test_malformed_json_is_skipped(self):
        (self.state / "records" / "garbage.json").write_text("{not json")
        self.assertEqual(self.r.feed_health()["sources"], [])


class LastDecision(_ReaderBase):
    def test_record_file_is_parsed(self):
        (self.state / "out" / "scamwall.zone.record.json").write_text(json.dumps({
            "generated_at": "2026-11-08T02:00:00Z",
            "added": 7, "removed": 1, "total": 320,
        }))
        out = self.r.last_decision()
        self.assertTrue(out["available"])
        self.assertEqual(out["added"], 7)
        self.assertEqual(out["removed"], 1)
        self.assertEqual(out["total"], 320)


class LastInstall(_ReaderBase):
    def test_tail_of_install_log(self):
        self.log.write_text("line 1\nline 2\nline 3\n")
        out = self.r.last_install()
        self.assertTrue(out["available"])
        self.assertEqual(out["last"], "line 3")
        self.assertEqual(out["tail"][-3:], ["line 1", "line 2", "line 3"])


if __name__ == "__main__":
    unittest.main()
