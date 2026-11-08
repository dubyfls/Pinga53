// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMetricsProducesAllFields walks the §4 fields and proves every one is
// populated (or stated empty) from a fixture that touches every code path:
// standing set, free-stack baseline, allowlist, protected.txt, journal with
// a mix of allowed / unknown / protected hits, baseline-dir with a 7d-ago
// snapshot, records-dir with today's hosts.
func TestMetricsProducesAllFields(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	// 1. shadow zone: 4 hosts.
	shadowZone := filepath.Join(dir, "scamwall.zone")
	_ = os.WriteFile(shadowZone, []byte(`
$ORIGIN scamwall.rpz.
@ IN SOA x. x. 1 3600 600 86400 300
unique.example.com CNAME .
shared.example.com CNAME .
onallowlist.example.net CNAME .
onprotected.bank.example CNAME .
`), 0o644)

	// 2. unbound-rpz dir: one free zone with shared.example.com only.
	unboundDir := filepath.Join(dir, "rpz")
	_ = os.MkdirAll(unboundDir, 0o755)
	_ = os.WriteFile(filepath.Join(unboundDir, "urlhaus.rpz"), []byte(`
shared.example.com CNAME .
`), 0o644)

	// 3. allowlist (one host).
	allowlist := filepath.Join(dir, "allow.txt")
	_ = os.WriteFile(allowlist, []byte("onallowlist.example.net\n"), 0o644)

	// 4. protected.txt (one suffix).
	protected := filepath.Join(dir, "protected.txt")
	_ = os.WriteFile(protected, []byte("# protected\nbank.example\n"), 0o644)

	// 5. journal.
	journal := filepath.Join(dir, "journal.log")
	_ = os.WriteFile(journal, []byte(`
Nov 07 10:00:01 pinga53 unbound[1]: rpz: applied [scamwall] unique.example.com
Nov 07 10:00:02 pinga53 unbound[1]: rpz: applied [scamwall] shared.example.com
Nov 07 10:00:03 pinga53 unbound[1]: rpz: applied [scamwall] onallowlist.example.net
Nov 07 10:00:04 pinga53 unbound[1]: rpz: applied [scamwall] onprotected.bank.example
Nov 07 10:00:05 pinga53 unbound[1]: rpz: applied [scamwall] shared.example.com
Nov 07 10:00:06 pinga53 unbound[1]: some other log line
`), 0o644)

	// 6. baseline-dir with a 7d-ago snapshot.
	baselineDir := filepath.Join(dir, "baseline")
	_ = os.MkdirAll(baselineDir, 0o755)
	// 7d ago: contained unique.example.com → still present in a source
	// today, counts in precision.
	_ = os.WriteFile(filepath.Join(baselineDir, now.AddDate(0, 0, -7).Format("2006-01-02")+".json"),
		[]byte(`{"generated_at":"2026-10-31T12:00:00Z","hosts":["unique.example.com","ghost.example.net"]}`), 0o644)
	// A date between so lead-time sees shared.example.com.
	_ = os.WriteFile(filepath.Join(baselineDir, now.AddDate(0, 0, -2).Format("2006-01-02")+".json"),
		[]byte(`{"generated_at":"2026-11-05T12:00:00Z","hosts":["shared.example.com"]}`), 0o644)

	// 7. records-dir with today's sources.
	recordsDir := filepath.Join(dir, "records")
	_ = os.MkdirAll(recordsDir, 0o755)
	_ = os.WriteFile(filepath.Join(recordsDir, "src.json"), []byte(`
{"schema_version":1,"source_id":"src","written_at":"2026-11-07T12:00:00Z","cadence_hours":0.5,"record_count":2,"records":[{"type":"domain","value":"unique.example.com","source_id":"src","classification":"malicious","state":"active"},{"type":"domain","value":"shared.example.com","source_id":"src","classification":"malicious","state":"active"}]}
`), 0o644)

	outDir := filepath.Join(dir, "metrics")

	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdout.Close() })

	rc := cmdMetrics(stdout, []string{
		"--shadow-zone", shadowZone,
		"--unbound-rpz", unboundDir,
		"--journal", journal,
		"--allowlist", allowlist,
		"--protected", protected,
		"--baseline-dir", baselineDir,
		"--records-dir", recordsDir,
		"--out-dir", outDir,
		"--now", now.Format(time.RFC3339),
	})
	if rc != 0 {
		stdoutBytes, _ := os.ReadFile(stdout.Name())
		t.Fatalf("cmdMetrics rc=%d, stdout=%s", rc, stdoutBytes)
	}

	out, err := os.ReadFile(filepath.Join(outDir, "2026-11-07.json"))
	if err != nil {
		t.Fatalf("read metrics output: %v", err)
	}
	var doc metricsDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, out)
	}
	if doc.SchemaVersion != metricsSchemaVersion {
		t.Fatalf("schema: got %d", doc.SchemaVersion)
	}
	if doc.Standing != 4 {
		t.Fatalf("standing: got %d, want 4 (body=%s)", doc.Standing, out)
	}
	// unique_vs_free = hosts in standing not in free stack. Free stack
	// has shared.example.com only; three unique.
	if doc.UniqueVsFree != 3 {
		t.Fatalf("unique_vs_free: got %d, want 3", doc.UniqueVsFree)
	}
	if doc.ShadowHits != 5 {
		t.Fatalf("shadow_hits: got %d, want 5", doc.ShadowHits)
	}
	if doc.WouldBlockHousehold != 5 {
		t.Fatalf("would_block_household: got %d, want 5", doc.WouldBlockHousehold)
	}
	// False-block candidates: onallowlist.example.net (1), onprotected.bank.example (1).
	gotFB := map[string]int{}
	for _, f := range doc.FalseBlockCandidates {
		gotFB[f.Host] = f.Count
	}
	if gotFB["onallowlist.example.net"] != 1 {
		t.Fatalf("expected onallowlist host counted once: %+v", doc.FalseBlockCandidates)
	}
	if gotFB["onprotected.bank.example"] != 1 {
		t.Fatalf("expected onprotected host counted once: %+v", doc.FalseBlockCandidates)
	}
	// Precision 7d: 1/2 (unique.example.com still listed, ghost.example.net not).
	if doc.Precision7d <= 0 || doc.Precision7d > 1 {
		t.Fatalf("precision_7d: got %v", doc.Precision7d)
	}
	// Document must NOT carry any client IP or name.
	if strings.Contains(string(out), "pinga53 unbound[1]") {
		t.Fatalf("metrics output leaked a raw journal line: %s", out)
	}
}

func TestMetricsEmptyInputs(t *testing.T) {
	dir := t.TempDir()
	stdout, _ := os.CreateTemp(t.TempDir(), "out")
	t.Cleanup(func() { _ = stdout.Close() })
	outDir := filepath.Join(dir, "m")
	rc := cmdMetrics(stdout, []string{"--out-dir", outDir, "--now", "2026-11-07T12:00:00Z"})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if _, err := os.Stat(filepath.Join(outDir, "2026-11-07.json")); err != nil {
		t.Fatalf("output missing: %v", err)
	}
}
