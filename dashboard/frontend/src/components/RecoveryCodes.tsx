// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — show freshly issued recovery codes exactly once.
import { useState } from "react";

export default function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const text = codes.join("\n");
  function copy() { navigator.clipboard?.writeText(text).then(() => setCopied(true)).catch(() => {}); }
  function download() {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([`Pinga53 recovery codes\n\n${text}\n`], { type: "text/plain" }));
    a.download = "pinga53-recovery-codes.txt"; a.click(); URL.revokeObjectURL(a.href);
  }
  return (
    <div className="recovery">
      <div className="recovery-title">Save your recovery codes</div>
      <p className="flow-note">Each code signs you in once if you lose your authenticator. They are shown only now.</p>
      <ul className="recovery-list">{codes.map(c => <li key={c}><code>{c}</code></li>)}</ul>
      <div className="recovery-actions">
        <button type="button" className="ghost-btn" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
        <button type="button" className="ghost-btn" onClick={download}>Download .txt</button>
      </div>
      <label className="check"><input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} /> I saved these codes somewhere safe</label>
      <button className="login-btn" disabled={!saved} onClick={onDone}>CONTINUE</button>
    </div>
  );
}
