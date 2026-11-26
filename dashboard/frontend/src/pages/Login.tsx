// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — login gate, embedded in the dashboard chrome. Sidebar (logo +
// locked nav) and header frame the operator sign-in, which sits over the
// Citadelle scene (fortress + world-in-hands + the road up). Definition and
// mission at bottom-right. Keeps the real auth/MFA flow.
import { useEffect, useState } from "react";
import { authStore } from "../security/authStore";
import { BRAND } from "../brand";
import CitadelleBg from "../components/CitadelleBg";
import GlobeGlassBg from "../components/GlobeGlassBg";
import RoadBg from "../components/RoadBg";
import { LayoutDashboard, ShieldAlert, ScrollText, UserRound, Lock } from "lucide-react";

function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <circle cx="24" cy="22" r="13" stroke="var(--accent)" strokeWidth="1.6" />
      <ellipse cx="24" cy="22" rx="6.5" ry="13" stroke="rgba(165,205,235,0.5)" strokeWidth="1" />
      <line x1="11" y1="22" x2="37" y2="22" stroke="rgba(165,205,235,0.5)" strokeWidth="1" />
      <path d="M12 40 C14 30 20 30 24 34 C28 30 34 30 36 40" stroke="rgba(205,225,252,0.75)" strokeWidth="1.4" />
    </svg>
  );
}

const NAV = [
  { sec: "Operations", items: [{ label: "Overview", icon: LayoutDashboard }] },
  { sec: "Security",   items: [{ label: "ScamWall", icon: ShieldAlert }] },
  { sec: "System",     items: [{ label: "Audit Log", icon: ScrollText }, { label: "Account", icon: UserRound }] },
];

export default function Login({ onAuthed }: { onAuthed: () => void }) {
  const [username, setU] = useState("");
  const [password, setP] = useState("");
  const [totp, setT] = useState("");
  const [showMfa, setShowMfa] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(new Date());
  useEffect(() => { const i = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(i); }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      await authStore.login(username, password, showMfa ? totp : undefined);
      onAuthed();
    } catch (e: any) {
      const msg = String(e.message || e);
      if (/MFA/i.test(msg)) setShowMfa(true);
      setErr(msg);
    } finally { setBusy(false); }
  }

  return (
    <div className="app login-app">
      <aside className="side">
        <div className="brand">
          <BrandMark />
          <div>
            <div className="brand-name" role="img" aria-label="Pinga53">PINGA<b>53</b></div>
            <div className="brand-sub">Resolver · ScamWall · Audit</div>
          </div>
        </div>
        <nav className="nav login-nav" aria-hidden="true">
          {NAV.map(g => (
            <div key={g.sec}>
              <div className="nav-sec">{g.sec}</div>
              {g.items.map(it => {
                const Icon = it.icon;
                return (
                  <div key={it.label} className="nav-item">
                    <Icon size={16} strokeWidth={1.75} /><span>{it.label}</span>
                  </div>
                );
              })}
            </div>
          ))}
          <div className="nav-locked"><Lock size={12} /> sign in to continue</div>
        </nav>
        <div className="side-foot">{BRAND}<br /><span style={{ color: "var(--accent-dim)" }}>local-only</span></div>
      </aside>

      <div className="main">
        <header className="hdr">
          <div>
            <div className="crumb">PINGA53 / SIGN IN</div>
            <h1>Sign In</h1>
          </div>
          <div className="hdr-right">
            <div className="lock-pill"><span className="pulse" /> LOCKED</div>
            <div className="clock">{now.toISOString().slice(11, 19)} UTC</div>
          </div>
        </header>

        <div className="login-stage">
          <GlobeGlassBg />
          <RoadBg />
          <CitadelleBg />

          <form className="login-panel" onSubmit={submit}>
            <div className="login-pt"><b>▸</b> OPERATOR SIGN-IN</div>
            <label className="lf">
              <span>Operator</span>
              <input value={username} onChange={e => setU(e.target.value)} autoFocus autoComplete="username" />
            </label>
            <label className="lf">
              <span>Passphrase</span>
              <input type="password" value={password} onChange={e => setP(e.target.value)} autoComplete="current-password" />
            </label>
            {showMfa && (
              <label className="lf">
                <span>MFA Code</span>
                <input value={totp} onChange={e => setT(e.target.value)} inputMode="numeric" placeholder="000000" maxLength={6} />
              </label>
            )}
            {err && <div className="login-err">⚠ {err}</div>}
            <button className="login-btn" disabled={busy || !username || !password}>
              {busy ? "AUTHENTICATING…" : "ENTER PINGA53"}
            </button>
            <div className="login-foot">local resolver · session is local-only</div>
          </form>

          <div className="login-def">
            <p><b>PINGA53</b> — local-first protective-DNS control plane.</p>
            <p><b>SCAMWALL</b> — the scam-domain detection engine: RPZ firewall + anomaly scoring.</p>
            <p className="mission"><b>MISSION</b> — block the scam before the click, on hardware you own, with data you keep.</p>
            <p className="login-by">A solo project by <b>Duplan DeCelestin Fils-Aime</b></p>
            <p className="login-attrib">Built on Pi-hole FTL + Unbound</p>
          </div>
        </div>
      </div>
    </div>
  );
}
