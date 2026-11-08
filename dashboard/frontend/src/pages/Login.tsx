// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — login gate. Logo splash + credentials. Optional MFA field.
import { useState } from "react";
import { authStore } from "../security/authStore";
import CitadelleBg from "../components/CitadelleBg";

export default function Login({ onAuthed }: { onAuthed: () => void }) {
  const [username, setU] = useState("");
  const [password, setP] = useState("");
  const [totp, setT] = useState("");
  const [showMfa, setShowMfa] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

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
    <div className="login-wrap">
      <div className="login-bg" />
      <div className="citadelle-word" aria-hidden="true">CITADELLE</div>
      <CitadelleBg />
      <form className="login-card login-card--foot" onSubmit={submit}>
        <div className="login-wordmark" role="img" aria-label="Pinga53">PINGA<b>53</b></div>
        <div className="login-sub">SECURE ACCESS · LOCAL CONTROL PLANE</div>

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

        <div className="login-foot">engine: pihole-FTL · session is local-only</div>
      </form>
    </div>
  );
}
