// SPDX-License-Identifier: AGPL-3.0-only
// Overview — two side-by-side cards: Pi-hole status/queries and ScamWall summary.
import { useEffect, useState } from "react";
import { api } from "../security/api";
import { Shield, Activity, ExternalLink } from "lucide-react";

type Pi = {
  connected: boolean;
  admin_url: string;
  ftl_available: boolean;
  queries_today: number;
  blocked_today: number;
  blocked_pct: number;
  status: string;
};

type ScamWallSummary = {
  mode: string;
  stop_automatic: boolean;
  hosts: { count: number };
  hits_today: { total: number; generated_at?: string };
  last_decision: { available: boolean; generated_at?: string; added?: number; removed?: number; total?: number };
  last_install: { available: boolean; last?: string };
};

const fmt = (n: number) => (n ?? 0).toLocaleString();

export default function Overview() {
  const [pi, setPi] = useState<Pi | null>(null);
  const [sw, setSw] = useState<ScamWallSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setErr(null);
    try {
      const [p, s] = await Promise.all([
        api<Pi>("/api/pihole/overview"),
        api<ScamWallSummary>("/api/scamwall/overview"),
      ]);
      setPi(p); setSw(s);
    } catch (e: any) { setErr(String(e?.message || e)); }
  }
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {err && <div className="panel" style={{ padding: 10, color: "var(--danger)" }}>WARN {err}</div>}

      <div className="grid cols-2">
        {/* Pi-hole card */}
        <div className="panel" style={{ padding: 14 }}>
          <div className="panel-title">
            <Activity size={14} /> Pi-hole
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginTop: 10 }}>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Status</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700,
                   color: pi?.status === "ok" ? "var(--accent)" : "var(--danger)" }}>
                {pi?.status?.toUpperCase() ?? "..."}
              </div>
            </div>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Queries today</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{fmt(pi?.queries_today ?? 0)}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Blocked today</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>
                {fmt(pi?.blocked_today ?? 0)} <span style={{ color: "var(--text-dim)", fontWeight: 400 }}>({(pi?.blocked_pct ?? 0).toFixed(1)}%)</span>
              </div>
            </div>
          </div>
          <div style={{ marginTop: 14 }}>
            <a className="btn" href={pi?.admin_url ?? "/admin"} target="_blank" rel="noopener noreferrer">
              Open Pi-hole admin <ExternalLink size={12} style={{ marginLeft: 6 }}/>
            </a>
          </div>
        </div>

        {/* ScamWall card */}
        <div className="panel" style={{ padding: 14 }}>
          <div className="panel-title">
            <Shield size={14} /> ScamWall
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginTop: 10 }}>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Mode</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700,
                   color: sw?.mode === "enforce" ? "var(--accent)" : "var(--warn)" }}>
                {sw?.mode?.toUpperCase() ?? "..."}
              </div>
            </div>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Automatic blocking</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700,
                   color: sw?.stop_automatic ? "var(--danger)" : "var(--accent)" }}>
                {sw?.stop_automatic ? "STOPPED" : "ON"}
              </div>
            </div>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Standing hosts</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{fmt(sw?.hosts?.count ?? 0)}</div>
            </div>
            <div>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Hits today</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{fmt(sw?.hits_today?.total ?? 0)}</div>
            </div>
            <div style={{ gridColumn: "span 2" }}>
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>Last decision</div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
                {sw?.last_decision?.available
                  ? `${sw.last_decision.generated_at ?? "?"} · +${fmt(sw.last_decision.added ?? 0)} / -${fmt(sw.last_decision.removed ?? 0)}`
                  : "(none yet)"}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
