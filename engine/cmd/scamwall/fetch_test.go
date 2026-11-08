// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/feedsources"
)

// callerFile returns runtime.Caller(1) for this file so the shipped
// registry path can be resolved relative to the test file's location.
func callerFile() (uintptr, string, int, bool) { return runtime.Caller(1) }

// TestMergeRecordsFreshAndStale writes two per-source records files — one
// fresh, one older than 2× its own cadence — to a temp dir and asserts the
// merge drops the stale one and keeps the fresh one.
func TestMergeRecordsFreshAndStale(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	fresh := []feed.EvidenceRecord{{
		Type: "domain", Value: "fresh.example.com", SourceID: "src-a",
		Classification: "malicious", State: "active",
	}}
	stale := []feed.EvidenceRecord{{
		Type: "domain", Value: "stale.example.com", SourceID: "src-b",
		Classification: "malicious", State: "active",
	}}
	// fresh: written 10 min ago, cadence 30 min → kept.
	if err := feedsources.WriteRecordsFile(filepath.Join(dir, "src-a.json"), "src-a", 30*time.Minute, now.Add(-10*time.Minute), fresh); err != nil {
		t.Fatal(err)
	}
	// stale: written 3 h ago, cadence 60 min (limit 2 h) → dropped.
	if err := feedsources.WriteRecordsFile(filepath.Join(dir, "src-b.json"), "src-b", 60*time.Minute, now.Add(-3*time.Hour), stale); err != nil {
		t.Fatal(err)
	}

	w, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	rc := cmdMergeRecords(w, []string{"--dir", dir, "--now", now.Format(time.RFC3339)})
	if rc != 0 {
		t.Fatalf("cmdMergeRecords: rc=%d", rc)
	}
	buf, err := os.ReadFile(w.Name())
	if err != nil {
		t.Fatal(err)
	}
	var out []feed.EvidenceRecord
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatalf("unmarshal merged records: %v\nbody=%s", err, buf)
	}
	gotValues := map[string]bool{}
	for _, r := range out {
		gotValues[r.Value] = true
	}
	if !gotValues["fresh.example.com"] {
		t.Fatalf("fresh.example.com missing from merge: %v", gotValues)
	}
	if gotValues["stale.example.com"] {
		t.Fatalf("stale.example.com survived the freshness filter: %v", gotValues)
	}
}

// TestMergeRecordsEmptyDirYieldsEmptyArray proves the shim's fallback case.
func TestMergeRecordsEmptyDirYieldsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	w, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	rc := cmdMergeRecords(w, []string{"--dir", dir, "--now", time.Now().UTC().Format(time.RFC3339)})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	buf, err := os.ReadFile(w.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(buf)) != "[]" {
		t.Fatalf("expected empty array, got %q", buf)
	}
}

// TestMergeRecordsMissingDirIsNotAnError covers the first-run shape where
// the records directory has not yet been created.
// TestFetchSkipsOnMissingCredentialFile covers ORDER 17B §1 Enable: an
// enabled abuse.ch source (URLhaus/ThreatFox) with no key file on disk
// must SKIP with a health message, not fail the service. The shipped
// deploy cannot place the operator's Auth-Key, so a fresh install has to
// run with those two sources skipping until the operator supplies it.
func TestFetchSkipsOnMissingCredentialFile(t *testing.T) {
	// Point at the shipped registry (urlhaus enabled).
	_, here, _, _ := callerFile()
	registryPath := filepath.Join(filepath.Dir(here), "..", "..", "config", "registry.json")

	outDir := t.TempDir()
	secretsDir := t.TempDir() // deliberately empty — no abusech.key
	cacheDir := t.TempDir()

	w, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	rc := cmdFetch(w, []string{
		"--registry", registryPath,
		"--out-dir", outDir,
		"--secrets-dir", secretsDir,
		"--cache-dir", cacheDir,
		"--only", "urlhaus",
		"--timeout", "5s",
	})
	if rc != exitOK {
		t.Fatalf("cmdFetch: rc=%d (expected 0 because the only source skips, nothing failed)", rc)
	}
	buf, err := os.ReadFile(w.Name())
	if err != nil {
		t.Fatal(err)
	}
	body := string(buf)
	if !strings.Contains(body, "fetch: urlhaus: skipped (credential file missing") {
		t.Errorf("expected the skip-on-missing-key message; got:\n%s", body)
	}
	// Nothing was written for urlhaus.
	if _, err := os.Stat(filepath.Join(outDir, "urlhaus.json")); err == nil {
		t.Errorf("urlhaus.json was written while the key was absent; expected a skip")
	}
}

func TestMergeRecordsMissingDirIsNotAnError(t *testing.T) {
	w, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	rc := cmdMergeRecords(w, []string{"--dir", "/tmp/nope-not-a-dir-xyz-" + t.Name()})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
}

func TestMergeRecordsMinSourcesAndCap(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	mk := func(src string, hosts ...string) {
		var rs []feed.EvidenceRecord
		for _, h := range hosts {
			rs = append(rs, feed.EvidenceRecord{Type: "domain", Value: h, SourceID: src, Classification: "malicious", State: "active"})
		}
		if err := feedsources.WriteRecordsFile(filepath.Join(dir, src+".json"), src, 30*time.Minute, now.Add(-time.Minute), rs); err != nil {
			t.Fatal(err)
		}
	}
	mk("src-a", "both.example", "only-a.example")
	mk("src-b", "both.example", "only-b.example")

	run := func(args ...string) (int, []feed.EvidenceRecord) {
		w, err := os.CreateTemp(t.TempDir(), "out")
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		rc := cmdMergeRecords(w, append([]string{"--dir", dir, "--now", now.Format(time.RFC3339)}, args...))
		buf, _ := os.ReadFile(w.Name())
		var out []feed.EvidenceRecord
		if rc == 0 {
			if err := json.Unmarshal(buf, &out); err != nil {
				t.Fatalf("stdout is not a JSON array: %v\n%s", err, buf)
			}
		}
		return rc, out
	}
	rc, out := run("--min-sources", "2")
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if len(out) != 2 {
		t.Fatalf("want both source records of both.example only, got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.Value != "both.example" {
			t.Errorf("single-source host %s survived --min-sources 2", r.Value)
		}
	}
	if rc, _ := run("--max-records", "3"); rc == 0 {
		t.Error("4 records under --max-records 3 was not refused")
	}
	if rc, out := run(); rc != 0 || len(out) != 4 {
		t.Errorf("default (no prefilter) should keep all 4, rc=%d n=%d", rc, len(out))
	}
}
