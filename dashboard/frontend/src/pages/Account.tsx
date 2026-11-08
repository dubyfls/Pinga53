// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — the signed-in user's own account: password, two-factor, recovery codes.
import { useEffect, useState } from "react";
import { KeyRound, ShieldCheck, LifeBuoy, UserRound } from "lucide-react";
import { api, Account as Acct } from "../security/api";
import { MfaEnroll } from "./MfaSetup";
import RecoveryCodes from "../components/RecoveryCodes";

function Row({ k, v, ok }: { k: string; v: string; ok?: boolean }) {
  return (
    <div className="acct-row"><span>{k}</span>
      <b style={{ color: ok === undefined ? "var(--text)" : ok ? "var(--accent)" : "var(--warn, #ffb020)" }}>{v}</b></div>
  );
}

function Panel({ icon, title, children }: { icon: any; title: string; children: any }) {
  const I = icon;
  return (
    <section className="panel acct-panel">
      <h3><I size={15} /> {title}</h3>
      {children}
    </section>
  );
}

function ChangePassword({ mfa, onDone }: { mfa: boolean; onDone: () => void }) {
  const [cur, setCur] = useState(""); const [n1, setN1] = useState(""); const [n2, setN2] = useState(""); const [totp, setT] = useState("");
  const [msg, setMsg] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setMsg("");
    if (n1.length < 12) return setErr("New password must be at least 12 characters.");
    if (n1 !== n2) return setErr("New passwords do not match.");
    setBusy(true);
    try {
      await api("/api/account/password", { method: "POST",
        body: JSON.stringify({ current_password: cur, new_password: n1, totp: mfa ? totp : undefined }) });
      setCur(""); setN1(""); setN2(""); setT(""); setMsg("Password changed."); onDone();
    } catch (e: any) { setErr(String(e.message || e)); } finally { setBusy(false); }
  }
  return (
    <form className="acct-form" onSubmit={submit}>
      <label className="lf"><span>Current password</span><input type="password" value={cur} onChange={e => setCur(e.target.value)} autoComplete="current-password" /></label>
      <label className="lf"><span>New password (12+ characters)</span><input type="password" value={n1} onChange={e => setN1(e.target.value)} autoComplete="new-password" /></label>
      <label className="lf"><span>Confirm new password</span><input type="password" value={n2} onChange={e => setN2(e.target.value)} autoComplete="new-password" /></label>
      {mfa && <label className="lf"><span>Authenticator code</span><input value={totp} onChange={e => setT(e.target.value.replace(/\D/g, ""))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" /></label>}
      {err && <div className="login-err">⚠ {err}</div>}
      {msg && <div className="acct-ok">✓ {msg}</div>}
      <button className="login-btn" disabled={busy || !cur || !n1 || !n2 || (mfa && totp.length !== 6)}>{busy ? "SAVING…" : "CHANGE PASSWORD"}</button>
    </form>
  );
}

function RegenCodes({ onDone }: { onDone: () => void }) {
  const [totp, setT] = useState(""); const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  if (codes) return <RecoveryCodes codes={codes} onDone={() => { setCodes(null); setT(""); onDone(); }} />;
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try { setCodes((await api<{ recovery_codes: string[] }>("/api/account/recovery-codes", { method: "POST", body: JSON.stringify({ totp }) })).recovery_codes); }
    catch (e: any) { setErr(String(e.message || e)); } finally { setBusy(false); }
  }
  return (
    <form className="acct-form" onSubmit={submit}>
      <p className="flow-note">New codes replace every unused old code.</p>
      <label className="lf"><span>Authenticator code</span><input value={totp} onChange={e => setT(e.target.value.replace(/\D/g, ""))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" /></label>
      {err && <div className="login-err">⚠ {err}</div>}
      <button className="ghost-btn" disabled={busy || totp.length !== 6}>{busy ? "Issuing…" : "Issue new recovery codes"}</button>
    </form>
  );
}

function ResetMfa({ onDone }: { onDone: () => void }) {
  const [pw, setPw] = useState(""); const [totp, setT] = useState(""); const [sure, setSure] = useState(false);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await api("/api/account/mfa/reset", { method: "POST", body: JSON.stringify({ current_password: pw, totp }) }); onDone(); }
    catch (e: any) { setErr(String(e.message || e)); } finally { setBusy(false); }
  }
  return (
    <form className="acct-form" onSubmit={submit}>
      <p className="flow-note">Use this when moving to a new phone. Your current authenticator and recovery codes stop working, and you set up two-factor again right away.</p>
      <label className="lf"><span>Password</span><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoComplete="current-password" /></label>
      <label className="lf"><span>Current authenticator code</span><input value={totp} onChange={e => setT(e.target.value.replace(/\D/g, ""))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" /></label>
      <label className="check"><input type="checkbox" checked={sure} onChange={e => setSure(e.target.checked)} /> I have my new phone ready</label>
      {err && <div className="login-err">⚠ {err}</div>}
      <button className="danger-btn" disabled={busy || !sure || !pw || totp.length !== 6}>{busy ? "Resetting…" : "Reset two-factor"}</button>
    </form>
  );
}

export default function AccountPage() {
  const [acct, setAcct] = useState<Acct | null>(null); const [err, setErr] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  async function load() { setErr(""); try { setAcct(await api<Acct>("/api/account")); } catch (e: any) { setErr(String(e.message || e)); } }
  useEffect(() => { load(); }, []);

  return (
    <div className="acct">
      <div className="acct-head"><UserRound size={20} /><h1>Account</h1></div>
      {err && <div className="login-err">⚠ {err}</div>}
      {acct && (
        <div className="acct-grid">
          <Panel icon={UserRound} title="SIGNED IN">
            <Row k="User" v={acct.username} />
            <Row k="Last sign-in" v={acct.last_login ? new Date(acct.last_login + (acct.last_login.endsWith("Z") ? "" : "Z")).toLocaleString() : "—"} />
            <Row k="Two-factor" v={acct.mfa_enrolled ? "on" : "off"} ok={acct.mfa_enrolled} />
            <Row k="Recovery codes left" v={String(acct.recovery_codes_remaining)} ok={acct.recovery_codes_remaining >= 3} />
          </Panel>
          <Panel icon={KeyRound} title="PASSWORD">
            <ChangePassword mfa={acct.mfa_enrolled} onDone={load} />
          </Panel>
          <Panel icon={ShieldCheck} title="TWO-FACTOR SIGN-IN">
            {acct.mfa_enrolled
              ? <ResetMfa onDone={() => { setEnrolling(true); load(); }} />
              : enrolling
                ? <MfaEnroll onDone={() => { setEnrolling(false); load(); }} />
                : <><p className="flow-note">Two-factor is off for this account.</p>
                    <button className="login-btn" onClick={() => setEnrolling(true)}>SET UP TWO-FACTOR</button></>}
          </Panel>
          {acct.mfa_enrolled && (
            <Panel icon={LifeBuoy} title="RECOVERY CODES">
              <RegenCodes onDone={load} />
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}
