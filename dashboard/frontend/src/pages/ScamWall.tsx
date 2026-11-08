// SPDX-License-Identifier: AGPL-3.0-only
// ScamWall page: mode, STOP flag, standing hosts, feed health, and owner actions.
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../security/api";
import { Shield, RefreshCw, Lock, Unlock } from "lucide-react";

type Overview = {
  mode: string;
  stop_automatic: boolean;
  hosts: { count: number };
  hits_today: { total: number; generated_at?: string };
  last_decision: { available: boolean; generated_at?: string; added?: number; removed?: number; total?: number };
  last_install: { available: boolean; last?: string; tail?: string[] };
};

type HostsResp = { count: number; hosts: string[] };

type FeedHealth = {
  sources: {
    source_id: string;
    written_at?: string;
    record_count: number;
    cadence_hours: number;
    last_success?: string;
    last_error?: string;
  }[];
};

const fmt = (n: number) => (n ?? 0).toLocaleString();

export default function ScamWall() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [hosts, setHosts] = useState<HostsResp | null>(null);
  const [health, setHealth] = useState<FeedHealth | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [action, setAction] = useState<{ kind: string; host?: string } | null>(null);
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [newHost, setNewHost] = useState("");

  async function load() {
    setErr(null);
    try {
      const [o, h, f] = await Promise.all([
        api<Overview>("/api/scamwall/overview"),
        api<HostsResp>("/api/scamwall/hosts"),
        api<FeedHealth>("/api/scamwall/health"),
      ]);
      setOv(o); setHosts(h); setHealth(f);
    } catch (e: any) { setErr(String(e?.message || e)); }
  }
  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    if (!hosts) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return hosts.hosts.slice(0, 200);
    return hosts.hosts.filter(h => h.includes(q)).slice(0, 200);
  }, [hosts, filter]);

  async function perform() {
    if (!action) return;
    setBusy(true); setNote(null); setErr(null);
    try {
      const payload: any = { totp };
      if (action.host) payload.host = action.host;
      await api<any>(`/api/scamwall/${action.kind}`, {
        method: "POST", body: JSON.stringify(payload),
      });
      setNote(`${action.kind} ok`);
      setAction(null); setTotp("");
      await load();
    } catch (e: any) {
      const msg = e instanceof ApiError ? e.message : String(e?.message || e);
      setErr(msg);
    } finally { setBusy(false); }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {err && <div className="panel" style={{ padding: 10, color: "var(--danger)" }}>WARN {err}</div>}
      {note && <div className="panel" style={{ padding: 10, color: "var(--accent)" }}>{note}</div>}

      {/* Summary + actions */}
      <div className="panel" style={{ padding: 14 }}>
        <div className="panel-title"><Shield size={14} /> ScamWall state</div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 10 }}>
          <Stat label="Mode" value={ov?.mode?.toUpperCase() ?? "..."} color={ov?.mode === "enforce" ? "var(--accent)" : "var(--warn)"} />
          <Stat label="Automatic" value={ov?.stop_automatic ? "STOPPED" : "ON"} color={ov?.stop_automatic ? "var(--danger)" : "var(--accent)"} />
          <Stat label="Standing hosts" value={fmt(ov?.hosts?.count ?? 0)} />
          <Stat label="Hits today" value={fmt(ov?.hits_today?.total ?? 0)} />
        </div>

        <div style={{ marginTop: 14, display: "flex", flexWrap: "wrap", gap: 8 }}>
          <button className="btn" onClick={() => setAction({ kind: ov?.mode === "enforce" ? "mode-shadow" : "mode-enforce" })}>
            Switch to {ov?.mode === "enforce" ? "shadow" : "enforce"}
          </button>
          <button className="btn" onClick={() => setAction({ kind: ov?.stop_automatic ? "stop-off" : "stop-on" })}>
            {ov?.stop_automatic
              ? (<><Unlock size={12} style={{ marginRight: 6 }}/>Resume automatic</>)
              : (<><Lock size={12} style={{ marginRight: 6 }}/>Stop automatic</>)}
          </button>
          <button className="btn" onClick={() => setAction({ kind: "run-now" })}>
            <RefreshCw size={12} style={{ marginRight: 6 }}/>Run now
          </button>
        </div>
      </div>

      {/* Standing hosts */}
      <div className="panel" style={{ padding: 14 }}>
        <div className="panel-title">Standing hosts ({fmt(hosts?.count ?? 0)})</div>
        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          <input placeholder="filter…" value={filter} onChange={e => setFilter(e.target.value)}
                 style={{ flex: 1, background: "var(--panel-2)", border: "1px solid var(--border)",
                          color: "var(--text)", padding: "6px 8px", borderRadius: 6, fontFamily: "var(--mono)" }}/>
          <input placeholder="host to protect…" value={newHost} onChange={e => setNewHost(e.target.value)}
                 style={{ flex: 1, background: "var(--panel-2)", border: "1px solid var(--border)",
                          color: "var(--text)", padding: "6px 8px", borderRadius: 6, fontFamily: "var(--mono)" }}/>
          <button className="btn" disabled={!newHost.trim()}
                  onClick={() => setAction({ kind: "protect-add", host: newHost.trim() })}>protect</button>
          <button className="btn" disabled={!newHost.trim()}
                  onClick={() => setAction({ kind: "protect-remove", host: newHost.trim() })}>unprotect</button>
        </div>
        <div style={{ marginTop: 10, maxHeight: 320, overflow: "auto",
                      background: "var(--panel-2)", border: "1px solid var(--border)",
                      borderRadius: 6, fontFamily: "var(--mono)", fontSize: 12 }}>
          {filtered.length === 0
            ? <div style={{ padding: 12, color: "var(--text-mute)" }}>no hosts</div>
            : filtered.map(h => <div key={h} style={{ padding: "4px 10px", borderBottom: "1px solid var(--border)" }}>{h}</div>)}
        </div>
      </div>

      {/* Feed health */}
      <div className="panel" style={{ padding: 14 }}>
        <div className="panel-title">Feed sources</div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, marginTop: 8 }}>
          <thead><tr style={{ color: "var(--text-mute)", textAlign: "left" }}>
            <th style={{ padding: "6px 8px" }}>Source</th><th>Last success</th>
            <th>Records</th><th>Cadence (h)</th><th>Last error</th>
          </tr></thead>
          <tbody>
            {health?.sources?.length
              ? health.sources.map(s => (
                <tr key={s.source_id} style={{ borderTop: "1px solid var(--border)", fontFamily: "var(--mono)" }}>
                  <td style={{ padding: "6px 8px" }}>{s.source_id}</td>
                  <td style={{ color: "var(--text-dim)" }}>{s.last_success ?? s.written_at ?? "-"}</td>
                  <td>{fmt(s.record_count)}</td>
                  <td>{s.cadence_hours ?? "-"}</td>
                  <td style={{ color: s.last_error ? "var(--danger)" : "var(--text-dim)" }}>{s.last_error ?? "-"}</td>
                </tr>
              ))
              : <tr><td colSpan={5} style={{ padding: 12, color: "var(--text-mute)", textAlign: "center" }}>no sources reported</td></tr>}
          </tbody>
        </table>
      </div>

      {/* Last decision + install */}
      <div className="panel" style={{ padding: 14 }}>
        <div className="panel-title">Last run</div>
        <div style={{ marginTop: 10, fontFamily: "var(--mono)", fontSize: 12 }}>
          <div>Decision: {ov?.last_decision?.available
            ? `${ov.last_decision.generated_at ?? "?"} · +${fmt(ov.last_decision.added ?? 0)} / -${fmt(ov.last_decision.removed ?? 0)} (total ${fmt(ov.last_decision.total ?? 0)})`
            : "(none yet)"}</div>
          <div style={{ marginTop: 6 }}>Install: {ov?.last_install?.available
            ? ov.last_install.last
            : "(no log)"}</div>
        </div>
      </div>

      {/* TOTP step-up modal */}
      {action && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)",
                      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50 }}>
          <div className="panel" style={{ padding: 18, minWidth: 320, maxWidth: 420 }}>
            <div className="panel-title">Confirm: {action.kind}</div>
            {action.host && <div style={{ fontFamily: "var(--mono)", fontSize: 12, marginTop: 8 }}>host: {action.host}</div>}
            <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-dim)" }}>
              Enter your current TOTP code to confirm.
            </div>
            <input value={totp} onChange={e => setTotp(e.target.value.replace(/\D/g, "").slice(0, 8))}
                   inputMode="numeric" pattern="[0-9]*" placeholder="000000"
                   style={{ width: "100%", marginTop: 8, padding: "8px 10px",
                            background: "var(--panel-2)", border: "1px solid var(--border)",
                            color: "var(--text)", borderRadius: 6, fontFamily: "var(--mono)", letterSpacing: 2 }}/>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
              <button className="btn" onClick={() => { setAction(null); setTotp(""); }}>cancel</button>
              <button className="btn" onClick={perform} disabled={busy || totp.length < 6}>confirm</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <div style={{ color: "var(--text-mute)", fontSize: 11 }}>{label}</div>
      <div style={{ fontFamily: "var(--mono)", fontWeight: 700, color: color ?? "var(--text)" }}>{value}</div>
    </div>
  );
}
