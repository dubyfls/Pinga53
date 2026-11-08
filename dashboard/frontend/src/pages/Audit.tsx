// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useState } from "react";
import { authedFetch } from "../security/authStore";
import { ScrollText, ShieldCheck, ShieldAlert } from "lucide-react";

type Entry = { ts?: string; event?: string; actor?: string; ip?: string; hash?: string; [k: string]: any };

export default function Audit() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [chainOk, setChainOk] = useState<boolean | null>(null);
  const [count, setCount] = useState(0);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setErr(null);
    try {
      const r = await authedFetch("/api/system/audit?limit=200").then(r => r.json());
      setEntries((r.entries ?? []).slice().reverse());
      setChainOk(r.chain_ok); setCount(r.chain_count ?? 0);
    } catch (e: any) { setErr(String(e?.message ?? e)); }
  }
  useEffect(() => { load(); const i = setInterval(load, 10000); return () => clearInterval(i); }, []);

  const meta = (e: Entry) => {
    const skip = new Set(["ts", "event", "actor", "ip", "hash", "prev_hash", "seq"]);
    const extra = Object.entries(e).filter(([k]) => !skip.has(k));
    return extra.length ? extra.map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ") : "";
  };

  return (
    <div style={{ padding: 4 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}><ScrollText size={20} /><h1 style={{ margin: 0 }}>Audit Log</h1></div>
      <p style={{ color: "var(--text-mute,#7a8794)", marginTop: 4, fontSize: 13 }}>Hash-chained, tamper-evident event log. Each entry is cryptographically linked to the previous.</p>

      <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "12px 0", fontSize: 12, fontFamily: "var(--mono)" }}>
        {chainOk === null ? <span style={{ color: "var(--text-mute)" }}>verifying&hellip;</span>
          : chainOk ? <span style={{ color: "var(--accent,#39ff14)", display: "flex", alignItems: "center", gap: 6 }}><ShieldCheck size={14} /> CHAIN INTACT &middot; {count} entries</span>
          : <span style={{ color: "var(--danger,#ff3b3b)", display: "flex", alignItems: "center", gap: 6 }}><ShieldAlert size={14} /> CHAIN BROKEN &mdash; tampering detected</span>}
      </div>
      {err && <div style={{ color: "var(--danger,#ff3b3b)", fontSize: 12 }}>&#9888; {err}</div>}

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead><tr style={{ color: "var(--text-mute,#7a8794)", textAlign: "left", fontSize: 11, background: "var(--panel-2,#0d1117)" }}>
            <th style={{ padding: "8px 10px" }}>Time</th><th>Event</th><th>Actor</th><th>IP</th><th>Detail</th></tr></thead>
          <tbody>
            {entries.length === 0 && <tr><td colSpan={5} style={{ color: "var(--text-mute)", padding: 16, textAlign: "center" }}>No audit entries yet</td></tr>}
            {entries.map((e, i) => (
              <tr key={i} style={{ borderTop: "1px solid var(--border,#1a1f26)", fontFamily: "var(--mono)" }}>
                <td style={{ padding: "6px 10px", color: "var(--text-mute)", whiteSpace: "nowrap" }}>{(e.ts ?? "").slice(0, 19).replace("T", " ")}</td>
                <td style={{ color: e.event?.includes("fail") ? "var(--danger,#ff3b3b)" : "var(--text,#e6edf3)" }}>{e.event}</td>
                <td>{e.actor}</td>
                <td style={{ color: "var(--text-mute)" }}>{e.ip}</td>
                <td style={{ color: "var(--text-mute)", fontSize: 11 }}>{meta(e)}</td>
              </tr>))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
