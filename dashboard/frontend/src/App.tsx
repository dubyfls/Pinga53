// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — app shell. Gated: no token => Login; else the dashboard.
import { useEffect, useState } from "react";
import Sidebar, { View } from "./components/Sidebar";
import Header from "./components/Header";
import Overview from "./pages/Overview";
import ScamWall from "./pages/ScamWall";
import Audit from "./pages/Audit";
import Login from "./pages/Login";
import ForcePassword from "./pages/ForcePassword";
import MfaSetup from "./pages/MfaSetup";
import AccountPage from "./pages/Account";
import Placeholder from "./pages/Placeholder";
import { flowState } from "./security/api";
import { authStore } from "./security/authStore";

const LABEL: Record<string, string> = {
  overview: "Overview",
  scamwall: "ScamWall",
  audit: "Audit Log",
  account: "Account",
};

export default function App() {
  const [authed, setAuthed] = useState(authStore.isAuthed());
  const [view, setView] = useState<View>("overview");
  const [step, setStep] = useState<"checking" | "password" | "mfa" | "ok">("checking");
  const [flowErr, setFlowErr] = useState("");

  async function recheck() {
    setFlowErr("");
    try { setStep((await flowState()).step); }
    catch (e: any) { setFlowErr(String(e.message || e)); }
  }
  useEffect(() => { if (authed) recheck(); }, [authed]);

  if (!authed) return <Login onAuthed={() => { setStep("checking"); setAuthed(true); }} />;
  if (flowErr) return (
    <div className="login-wrap"><div className="login-bg" /><div className="login-card">
      <div className="login-err">WARN {flowErr}</div>
      <button className="login-btn" onClick={recheck}>RETRY</button>
      <button className="link-btn" onClick={() => { authStore.logout(); setAuthed(false); }}>Sign out</button>
    </div></div>);
  if (step === "checking") return <div className="login-wrap"><div className="login-bg" /></div>;
  if (step === "password") return <ForcePassword onDone={recheck} />;
  if (step === "mfa") return <MfaSetup onDone={recheck} />;

  return (
    <div className="app">
      <Sidebar view={view} setView={setView} />
      <div className="main">
        <Header view={view} connected={true}
                user={authStore.user() || undefined}
                onLogout={() => { authStore.logout(); setAuthed(false); }} />
        {view === "overview"
          ? <Overview />
          : view === "scamwall"
          ? <ScamWall />
          : view === "audit"
          ? <Audit />
          : view === "account"
          ? <AccountPage />
          : <Placeholder title={LABEL[view] ?? view} phase="v0.2" />}
      </div>
    </div>
  );
}
