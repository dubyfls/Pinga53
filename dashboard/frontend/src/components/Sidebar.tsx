// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — left side navigation
import { BRAND } from "../brand";
import { LayoutDashboard, ShieldAlert, ScrollText, UserRound } from "lucide-react";

export type View = "overview" | "scamwall" | "audit" | "account";

const NAV: { sec: string; items: { id: View; label: string; icon: any }[] }[] = [
  { sec: "Operations", items: [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
  ]},
  { sec: "Security", items: [
    { id: "scamwall", label: "ScamWall", icon: ShieldAlert },
  ]},
  { sec: "System", items: [
    { id: "audit",   label: "Audit Log", icon: ScrollText },
    { id: "account", label: "Account",   icon: UserRound },
  ]},
];

export default function Sidebar({ view, setView }: { view: View; setView: (v: View) => void }) {
  return (
    <aside className="side">
      <div className="brand">
        <div className="brand-name">PINGA<b>53</b></div>
        <div className="brand-sub">Pi-hole · ScamWall · Audit</div>
      </div>
      <nav className="nav">
        {NAV.map(group => (
          <div key={group.sec}>
            <div className="nav-sec">{group.sec}</div>
            {group.items.map(it => {
              const Icon = it.icon;
              return (
                <div key={it.id}
                     className={"nav-item" + (view === it.id ? " active" : "")}
                     onClick={() => setView(it.id)}>
                  <Icon size={16} strokeWidth={1.75} />
                  <span>{it.label}</span>
                </div>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="side-foot">
        {BRAND}<br />
        <span style={{ color: "var(--accent-dim)" }}>local-only</span>
      </div>
    </aside>
  );
}
