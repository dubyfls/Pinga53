// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — MFA enrollment: scan the QR (or type the key), confirm one code,
// then save the one-time recovery codes. Used for the forced first-login step
// and from the Account page.
import { useEffect, useState } from "react";
import { api } from "../security/api";
import RecoveryCodes from "../components/RecoveryCodes";

type Start = { secret_blocks: string; qr_svg: string; expires_at: string };

// The server renders the QR at a fixed pixel size with no viewBox, so CSS
// sizing clipped it (270px drawn into a 200px box: unscannable). Give it a
// viewBox so it scales whole.
function scalableSvg(svg: string): string {
  if (/viewBox=/.test(svg)) return svg;
  return svg.replace(/<svg([^>]*?)\swidth="(\d+(?:\.\d+)?)"\s+height="(\d+(?:\.\d+)?)"/,
    (_m, pre, w, h) => `<svg${pre} viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"`);
}

export function MfaEnroll({ onDone }: { onDone: () => void }) {
  const [start, setStart] = useState<Start | null>(null);
  const [code, setCode] = useState(""); const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);

  async function load() {
    setErr("");
    try { setStart(await api<Start>("/api/setup/mfa")); } catch (e: any) { setErr(String(e.message || e)); }
  }
  useEffect(() => { load(); }, []);

  async function confirm(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      const r = await api<{ recovery_codes: string[] }>("/api/setup/mfa", { method: "POST", body: JSON.stringify({ code: code.trim() }) });
      setCodes(r.recovery_codes);
    } catch (e: any) {
      const msg = String(e.message || e);
      setErr(/no active enrollment/i.test(msg) ? "The setup key expired. A new one is shown — scan it again." : msg);
      if (/no active enrollment/i.test(msg)) { setCode(""); load(); }
    } finally { setBusy(false); }
  }

  if (codes) return <RecoveryCodes codes={codes} onDone={onDone} />;

  return (
    <form className="mfa-enroll" onSubmit={confirm}>
      <ol className="mfa-steps">
        <li>Open an authenticator app (1Password, Google Authenticator, Authy, Microsoft Authenticator).</li>
        <li>Scan this code, or type the key below.</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      {start ? (
        <>
          {/* server-rendered SVG from segno (backend/api/setup.py), same origin */}
          <div className="mfa-qr" dangerouslySetInnerHTML={{ __html: scalableSvg(start.qr_svg) }} />
          <div className="mfa-key"><span>Key</span><code>{start.secret_blocks}</code></div>
          <div className="mfa-exp">Key valid until {new Date(start.expires_at + (start.expires_at.endsWith("Z") ? "" : "Z")).toLocaleTimeString()}</div>
        </>
      ) : !err && <div className="mfa-exp">Preparing key…</div>}
      <label className="lf"><span>6-digit code</span>
        <input value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))} inputMode="numeric"
               autoComplete="one-time-code" placeholder="000000" maxLength={6} /></label>
      {err && <div className="login-err">⚠ {err}</div>}
      <button className="login-btn" disabled={busy || code.length !== 6 || !start}>{busy ? "CHECKING…" : "CONFIRM CODE"}</button>
    </form>
  );
}

export default function MfaSetup({ onDone }: { onDone: () => void }) {
  return (
    <div className="login-wrap">
      <div className="login-bg" />
      <div className="login-card wide">
        <div className="login-wordmark" role="img" aria-label="Pinga53">PINGA<b>53</b></div>
        <div className="login-sub">SET UP TWO-FACTOR SIGN-IN</div>
        <MfaEnroll onDone={onDone} />
      </div>
    </div>
  );
}
