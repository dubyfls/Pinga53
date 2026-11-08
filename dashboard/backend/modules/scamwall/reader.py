# SPDX-License-Identifier: AGPL-3.0-only
"""ScamWall reader — READ-ONLY views over the engine's on-disk state.

Everything here is a plain file read with a short timeout and a safe fallback:
if a file is missing or malformed we return "unknown" rather than raising. The
dashboard renders empty cards in that case.

Sources read (defaults; all overridable in Config):

    /etc/unbound/unbound.conf.d/pinga53.conf   -> mode (shadow/enforce)
    /etc/pinga53/scamwall/STOP-AUTOMATIC       -> automatic-blocking flag
    /etc/unbound/rpz/scamwall.zone             -> standing-hosts list
    /var/lib/scamwall/metrics/summary.json     -> hits-per-day (counts only)
    /var/lib/scamwall/journal/*.log            -> daily hits (per-host, newest)
    /var/lib/scamwall/records/<id>.json        -> per-source health
    /var/lib/scamwall/out/scamwall.zone.record.json -> last decision run
    /var/log/pinga53/scamwall-install.log      -> last zone install
"""
from __future__ import annotations
import glob
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScamWallReader:
    unbound_conf: str
    zone: str
    state_dir: str
    stop_flag: str
    install_log: str

    @classmethod
    def from_config(cls, cfg) -> "ScamWallReader":
        return cls(
            unbound_conf=cfg.unbound_conf,
            zone=cfg.scamwall_zone,
            state_dir=cfg.scamwall_state,
            stop_flag=cfg.scamwall_stop_flag,
            install_log=cfg.scamwall_install_log,
        )

    # ---- primitives ----

    def _safe_read_text(self, path: str, max_bytes: int = 4 * 1024 * 1024) -> str | None:
        try:
            with open(path, "rb") as f:
                b = f.read(max_bytes)
            return b.decode("utf-8", errors="replace")
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def _safe_read_json(self, path: str) -> dict | None:
        raw = self._safe_read_text(path)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    # ---- facets ----

    def mode(self) -> str:
        """install.sh writes the scamwall rpz stanza with
        "rpz-action-override: passthru" in shadow mode and without it in
        enforce mode. No rpz stanza at all: unknown."""
        text = self._safe_read_text(self.unbound_conf)
        if text is None:
            return "unknown"
        if re.search(r"^\s*(rpz-)?action-override\s*:\s*passthru\s*$", text, re.MULTILINE):
            return "shadow"
        if re.search(r"^rpz:", text, re.MULTILINE):
            return "enforce"
        return "unknown"

    def stop_automatic(self) -> bool:
        return os.path.exists(self.stop_flag)

    def _parse_zone_hosts(self) -> list[str]:
        text = self._safe_read_text(self.zone)
        if text is None:
            return []
        hosts: list[str] = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith(";") or s.startswith("$"):
                continue
            parts = s.split()
            if not parts:
                continue
            name = parts[0].rstrip(".").lower()
            if not name or name in ("@", "scamwall", "localhost"):
                continue
            if "." not in name:
                continue
            hosts.append(name)
        return hosts

    def hosts(self) -> dict:
        h = self._parse_zone_hosts()
        return {"count": len(h), "hosts": h}

    def _summary(self) -> dict | None:
        return self._safe_read_json(os.path.join(self.state_dir, "metrics", "summary.json"))

    def hits_today(self) -> dict:
        s = self._summary() or {}
        total = int(s.get("shadow_hits") or s.get("hits_today") or 0)
        return {"total": total, "generated_at": s.get("generated_at")}

    _HDR_FIELDS = ("source_id", "written_at", "record_count", "cadence_hours")

    def _read_records_header(self, path: str) -> dict | None:
        """Read only the leading summary fields of a records file. The
        fetcher writes them before the (very large) records array, so the
        first 8 KiB are enough and the file is never loaded whole."""
        try:
            with open(path, "rb") as fh:
                head = fh.read(8192).decode("utf-8", "replace")
        except Exception:
            return None
        out: dict = {}
        for k in self._HDR_FIELDS:
            m = re.search(r'"%s"\s*:\s*("([^"\\]*)"|-?[0-9.eE+]+)' % k, head)
            if m:
                out[k] = m.group(2) if m.group(2) is not None else float(m.group(1))
        return out or None

    def feed_health(self) -> dict:
        """Per-source health from /var/lib/scamwall/records/<id>.json files.

        Shape per entry:
            {
              "source_id": str,
              "written_at": ISO 8601,
              "record_count": int,
              "cadence_hours": float,
              "last_error": str | None,
            }
        """
        rec_dir = os.path.join(self.state_dir, "records")
        out = []
        try:
            entries = sorted(os.listdir(rec_dir))
        except Exception:
            return {"sources": []}
        for name in entries:
            if not name.endswith(".json") or name.startswith("_"):
                continue
            body = self._read_records_header(os.path.join(rec_dir, name))
            if not body:
                continue
            out.append({
                "source_id": body.get("source_id", name.removesuffix(".json")),
                "written_at": body.get("written_at"),
                "record_count": int(body.get("record_count", 0)),
                "cadence_hours": float(body.get("cadence_hours") or 0),
            })
        health_path = os.path.join(self.state_dir, "records", "_health.json")
        hb = self._safe_read_json(health_path)
        if isinstance(hb, dict):
            by_src = {s["source_id"]: s for s in out}
            for k, v in hb.items():
                if k not in by_src or not isinstance(v, dict):
                    continue
                by_src[k]["last_success"] = v.get("last_success")
                by_src[k]["last_error"] = v.get("last_error")
        return {"sources": out}

    def last_decision(self) -> dict:
        body = self._safe_read_json(os.path.join(self.state_dir, "out", "scamwall.zone.record.json"))
        if not body:
            return {"available": False}
        return {
            "available": True,
            "generated_at": body.get("generated_at"),
            "added": int(body.get("added", 0)),
            "removed": int(body.get("removed", 0)),
            "total": int(body.get("total", 0)),
        }

    def last_install(self) -> dict:
        text = self._safe_read_text(self.install_log)
        if text is None:
            return {"available": False}
        lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
        tail = lines[-20:]
        last = tail[-1] if tail else ""
        return {"available": True, "tail": tail, "last": last}

    def overview(self) -> dict:
        return {
            "mode": self.mode(),
            "stop_automatic": self.stop_automatic(),
            "hosts": {"count": len(self._parse_zone_hosts())},
            "hits_today": self.hits_today(),
            "last_decision": self.last_decision(),
            "last_install": self.last_install(),
        }

    def probe(self) -> str:
        """Quick CLI probe — prints what the reader sees. No exceptions escape."""
        lines = []
        for label, val in [
            ("unbound_conf", self.unbound_conf),
            ("zone", self.zone),
            ("state_dir", self.state_dir),
            ("stop_flag", self.stop_flag),
            ("install_log", self.install_log),
        ]:
            exists = Path(val).exists()
            lines.append(f"{label}: {val}  [{'ok' if exists else 'missing'}]")
        lines.append(f"mode: {self.mode()}")
        lines.append(f"stop_automatic: {self.stop_automatic()}")
        lines.append(f"hosts: {self.hosts()['count']}")
        return "\n".join(lines)
