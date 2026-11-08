// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — themed placeholder for modules not yet wired
import { Radio } from "lucide-react";

export default function Placeholder({ title, phase }: { title: string; phase: string }) {
  return (
    <div className="coming">
      <Radio size={40} strokeWidth={1.25} color="var(--accent-dim)" />
      <div className="big">{title.toUpperCase()}</div>
      <div className="meta">module scaffolded · {phase}</div>
      <div className="meta" style={{ color: "var(--text-mute)" }}>data feed not yet connected</div>
    </div>
  );
}
