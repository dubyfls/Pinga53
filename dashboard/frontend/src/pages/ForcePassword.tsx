// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — forced password change on first login (or after an admin reset).
import { useState } from "react";
import { api } from "../security/api";
import { authStore } from "../security/authStore";

export default function ForcePassword({ onDone }: { onDone: () => void }) {
  const [cur, setCur] = useState(""); const [n1, setN1] = useState(""); const [n2, setN2] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  // An admin password reset keeps MFA, so the server then also wants a code.
  const [totp, setTotp] = useState(""); const [needMfa, setNeedMfa] = useState(false);
  const mismatch = n2.length > 0 && n1 !== n2;

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr("");
    if (n1.length < 12) { setErr("New password must be at least 12 characters."); return; }
    if (n1 !== n2) { setErr("New passwords do not match."); return; }
    setBusy(true);
    try {
      await api("/api/account/password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: n1, ...(totp ? { totp } : {}) }) });
      onDone();
    } catch (e: any) {
      const msg = String(e.message || e);
      if (/MFA/i.test(msg)) { setNeedMfa(true); setErr(totp ? msg : "Enter the 6-digit code from your authenticator app."); }
      else setErr(msg);
    } finally { setBusy(false); }
  }

  return (
    <div className="login-wrap">
      <div className="login-bg" />
      <form className="login-card" onSubmit={submit}>
        <div className="login-wordmark" role="img" aria-label="Pinga53">PINGA<b>53</b></div>
        <div className="login-sub">STEP 1 OF 2 · SET YOUR PASSWORD</div>
        <p className="flow-note">Signed in as <b>{authStore.user()}</b>. Replace the temporary password before continuing.</p>
        <label className="lf"><span>Current password</span>
          <input type="password" value={cur} onChange={e => setCur(e.target.value)} autoFocus autoComplete="current-password" /></label>
        <label className="lf"><span>New password (12+ characters)</span>
          <input type="password" value={n1} onChange={e => setN1(e.target.value)} autoComplete="new-password" /></label>
        <label className="lf"><span>Confirm new password</span>
          <input type="password" value={n2} onChange={e => setN2(e.target.value)} autoComplete="new-password" /></label>
        {needMfa && (
          <label className="lf"><span>MFA code</span>
            <input value={totp} onChange={e => setTotp(e.target.value.replace(/\D/g, ""))} inputMode="numeric" placeholder="000000" maxLength={8} autoComplete="one-time-code" autoFocus /></label>
        )}
        {mismatch && <div className="login-err">⚠ Passwords do not match.</div>}
        {err && <div className="login-err">⚠ {err}</div>}
        <button className="login-btn" disabled={busy || !cur || !n1 || !n2 || (needMfa && totp.length < 6)}>{busy ? "SAVING…" : "SET PASSWORD"}</button>
        <button type="button" className="link-btn" onClick={() => { authStore.logout(); window.location.reload(); }}>Sign out</button>
      </form>
    </div>
  );
}
