// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — top header: title, UTC clock, operator + logout
import { useEffect, useState } from "react";
import { LogOut } from "lucide-react";

const TITLES: Record<string, string> = {
  overview: "Overview",
  scamwall: "ScamWall",
  audit: "Audit Log",
  account: "Account",
};

export default function Header({ view, connected, user, onLogout }: {
  view: string; connected: boolean; user?: string; onLogout?: () => void;
}) {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const i = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(i); }, []);
  return (
    <header className="hdr">
      <div>
        <div className="crumb">PINGA53 / {view.toUpperCase()}</div>
        <h1>{TITLES[view] ?? view}</h1>
      </div>
      <div className="hdr-right">
        <div className="live-pill">
          <span className="pulse" style={{ background: connected ? "var(--accent)" : "var(--danger)" }} />
          {connected ? "LIVE" : "OFFLINE"}
        </div>
        <div className="clock">{now.toISOString().slice(11, 19)} UTC</div>
        {user && (
          <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 11, color: "var(--text-dim)" }}>
            <span>{user}</span>
            <LogOut size={15} style={{ cursor: "pointer" }} onClick={onLogout} />
          </div>
        )}
      </div>
    </header>
  );
}
