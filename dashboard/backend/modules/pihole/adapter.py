# SPDX-License-Identifier: AGPL-3.0-only
"""pihole-FTL adapter — read-only.

Reads the FTL database (never writes, never touches the engine) and returns
metrics for the dashboard's Pi-hole overview card. Uses the stable `queries`
view so it works across FTL v5/v6 storage changes.
"""
from __future__ import annotations
import sqlite3
import time

# FTL status codes
BLOCKED = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16)
CACHED = (3, 17)
FORWARDED = (2, 14)


TYPE_NAMES = {1:"A",2:"AAAA",3:"ANY",4:"SRV",5:"SOA",6:"PTR",7:"TXT",8:"NAPTR",
              9:"MX",10:"DS",11:"RRSIG",12:"DNSKEY",13:"NS",14:"OTHER",15:"SVCB",16:"HTTPS"}


def scalar_row(cur, q, args=()):
    cur.execute(q, args)
    return cur.fetchone() or ()


class FtlAdapter:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _conn(self):
        return sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=2.0)

    def available(self) -> bool:
        try:
            c = self._conn()
            c.execute("SELECT 1 FROM queries LIMIT 1")
            c.close()
            return True
        except Exception:
            return False

    def metrics(self, window_min: int = 1440, buckets: int = 40, bucket_s: int = 60) -> dict:
        now = int(time.time())
        since = now - window_min * 60
        c = self._conn()
        cur = c.cursor()

        def scalar(q, args=()):
            cur.execute(q, args)
            r = cur.fetchone()
            return r[0] if r and r[0] is not None else 0


        inb = ",".join(map(str, BLOCKED))
        inc = ",".join(map(str, CACHED))
        infw = ",".join(map(str, FORWARDED))
        recent = now - 3600  # top-lists window: 1h of recent activity (not 24h)

        # headline aggregates in ONE indexed scan over the base table (not the
        # `queries` view, whose per-row correlated subqueries are slow at scale).
        # SQLite treats `status IN (...)` as 1/0, so SUM() gives class counts.
        row = scalar_row(cur,
            f"SELECT COUNT(*), SUM(status IN ({inb})), SUM(status IN ({inc})), "
            f"SUM(status IN ({infw})), COUNT(DISTINCT client), "
            f"AVG(CASE WHEN reply_time>0 THEN reply_time END), "
            f"AVG(CASE WHEN reply_time>0 AND status IN ({infw}) THEN reply_time END) "
            f"FROM query_storage WHERE timestamp>=?", (since,))
        total = row[0] or 0
        blocked = row[1] or 0
        cached = row[2] or 0
        fwded = row[3] or 0
        clients = row[4] or 0
        avg_ms = (row[5] or 0) * 1000
        upstream_ms = (row[6] or 0) * 1000

        blocked_pct = round(blocked / total * 100, 1) if total else 0.0
        cache_hit = round(cached / (cached + fwded) * 100, 1) if (cached + fwded) else 0.0

        # time-series: per-bucket counts + per-bucket avg latency
        s_since = now - buckets * bucket_s
        cur.execute(
            f"SELECT (timestamp/{bucket_s})*{bucket_s} b, COUNT(*), "
            f"SUM(status IN ({inb})), "
            f"AVG(CASE WHEN reply_time>0 THEN reply_time END) "
            f"FROM query_storage WHERE timestamp>=? GROUP BY b", (s_since,))
        rows = {r[0]: (r[1], r[2] or 0, r[3]) for r in cur.fetchall()}
        qps, blockedRate, upstreamMs = [], [], []
        base = (s_since // bucket_s)
        for i in range(buckets):
            b = (base + i) * bucket_s
            tot, blk, lat = rows.get(b, (0, 0, None))
            ts = b * 1000
            qps.append({"t": ts, "v": tot})
            blockedRate.append({"t": ts, "v": blk})
            upstreamMs.append({"t": ts, "v": round((lat or 0) * 1000)})

        # top domains
        cur.execute(
            f"SELECT d.domain, COUNT(*) c, SUM(q.status IN ({inb})) "
            f"FROM query_storage q JOIN domain_by_id d ON d.id=q.domain "
            f"WHERE q.timestamp>=? GROUP BY q.domain ORDER BY c DESC LIMIT 7", (recent,))
        topDomains = [{"name": d or "?", "hits": c, "blocked": (b or 0) > 0} for d, c, b in cur.fetchall()]

        # client -> hostname map from FTL's network tables (best-effort)
        names = {}
        try:
            cur.execute(
                "SELECT na.ip, n.name FROM network_addresses na "
                "JOIN network n ON n.id = na.network_id "
                "WHERE n.name IS NOT NULL AND n.name != ''")
            names = {ip: nm for ip, nm in cur.fetchall() if nm}
        except Exception:
            pass

        # top clients (resolve friendly names where known)
        cur.execute(
            "SELECT cl.ip, COUNT(*) c FROM query_storage q JOIN client_by_id cl ON cl.id=q.client "
            "WHERE q.timestamp>=? GROUP BY q.client ORDER BY c DESC LIMIT 6", (recent,))
        topClients = []
        for ip, c2 in cur.fetchall():
            ip = ip or "?"
            topClients.append({"ip": ip, "name": names.get(ip, ip), "q": c2, "risk": 0})

        # query-type breakdown (last 24h) -> pie slices. One grouped scan.
        cur.execute("SELECT type, COUNT(*) c FROM query_storage WHERE timestamp>=? GROUP BY type ORDER BY c DESC", (since,))
        queryTypes = []
        for tcode, cnt in cur.fetchall():
            label = TYPE_NAMES.get(tcode, TYPE_NAMES.get(tcode - 100, f"T{tcode}"))
            queryTypes.append({"type": label, "count": cnt})
        # keep heat key present (empty) for back-compat with any consumer
        heat = []

        # real "vs 1h" deltas: this hour vs the hour before
        def hcount(a, b, extra=""):
            cur.execute(f"SELECT COUNT(*) FROM query_storage WHERE timestamp>=? AND timestamp<?{extra}", (a, b))
            r = cur.fetchone()
            return r[0] if r else 0
        h1, h2 = now - 3600, now - 7200
        q_now, q_prev = hcount(h1, now), hcount(h2, h1)
        b_now, b_prev = hcount(h1, now, f" AND status IN ({inb})"), hcount(h2, h1, f" AND status IN ({inb})")
        cur.execute("SELECT COUNT(DISTINCT client) FROM query_storage WHERE timestamp>=?", (h1,)); cl_now = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT client) FROM query_storage WHERE timestamp>=? AND timestamp<?", (h2, h1)); cl_prev = cur.fetchone()[0]

        def pct(cur_v, prev_v):
            return round((cur_v - prev_v) / prev_v * 100, 1) if prev_v else 0.0
        deltas = {
            "queries": pct(q_now, q_prev),
            "blocked": pct(b_now, b_prev),
            "blockedPct": pct(b_now / q_now * 100 if q_now else 0, b_prev / q_prev * 100 if q_prev else 0),
            "clients": pct(cl_now, cl_prev),
        }

        c.close()
        return {
            "queries": total, "blocked": blocked, "blockedPct": blocked_pct, "clients": clients,
            "cacheHitPct": cache_hit,
            "avgLatencyMs": round(avg_ms, 1),
            "upstreamLatencyMs": round(upstream_ms, 1),
            "qps": qps, "blockedRate": blockedRate, "upstreamMs": upstreamMs,
            "topDomains": topDomains, "topClients": topClients,
            "heat": heat,
            "queryTypes": queryTypes,
            "deltas": deltas,
            "_source": "pihole-FTL",
        }

    def probe(self) -> str:
        """Human-readable schema + sample check for validating against a real DB."""
        out = [f"db: {self.db_path}"]
        try:
            c = self._conn(); cur = c.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
            out.append("objects: " + ", ".join(r[0] for r in cur.fetchall()))
            cur.execute("PRAGMA table_info(queries)")
            cols = [r[1] for r in cur.fetchall()]
            out.append("queries columns: " + (", ".join(cols) or "(none — view missing?)"))
            cur.execute("SELECT COUNT(*) FROM query_storage")
            out.append(f"total rows: {cur.fetchone()[0]}")
            m = self.metrics(window_min=60)
            out.append(f"last 60min -> queries={m['queries']} blocked={m['blocked']} "
                       f"({m['blockedPct']}%) clients={m['clients']} cacheHit={m['cacheHitPct']}%")
            out.append(f"top domain: {m['topDomains'][0]['name'] if m['topDomains'] else '-'}")
            c.close()
        except Exception as e:
            out.append(f"ERROR: {e}")
        return "\n".join(out)
