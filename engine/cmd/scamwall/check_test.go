// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A minimal source-registry document the loader accepts. Only the fields
// the check command touches are populated. See internal/sourceregistry
// for the field-by-field validation.
const minimalRegistry = `{
  "schema_version": 2,
  "note": "test fixture",
  "retired_source_ids": [],
  "sources": [
    {
      "source_id": "src-0001",
      "catalog_ref": "1",
      "requested_priority": "unknown",
      "official_name": "URLhaus",
      "official_documentation": "https://urlhaus.abuse.ch/api/",
      "verified_on": "2026-09-30",
      "kind": "bulk feed",
      "indicator_types": ["url"],
      "classification_meaning": "listed by URLhaus",
      "authentication": "key",
      "quotas": "unknown",
      "update_cadence": "unknown",
      "retention": "unknown",
      "withdrawal_behaviour": "unknown",
      "attribution_required": "unknown",
      "derived_data_restrictions": "unknown",
      "upstream_sources": [],
      "upstream_sources_completeness": "unknown",
      "aggregation_dependencies": [],
      "access_status": "public",
      "ownership_of_official_documentation": "unknown"
    },
    {
      "source_id": "src-0002",
      "catalog_ref": "2",
      "requested_priority": "unknown",
      "official_name": "PhishTank",
      "official_documentation": "https://phishtank.org/data.json",
      "verified_on": "2026-09-30",
      "kind": "bulk feed",
      "indicator_types": ["url"],
      "classification_meaning": "listed as phish",
      "authentication": "key",
      "quotas": "unknown",
      "update_cadence": "unknown",
      "retention": "unknown",
      "withdrawal_behaviour": "unknown",
      "attribution_required": "unknown",
      "derived_data_restrictions": "unknown",
      "upstream_sources": [],
      "upstream_sources_completeness": "unknown",
      "aggregation_dependencies": [],
      "access_status": "public",
      "ownership_of_official_documentation": "unknown"
    }
  ]
}`

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// runCheck invokes cmdCheck against a captured stdout. Returns exit code
// and captured output.
func runCheck(t *testing.T, args ...string) (int, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "check-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	code := cmdCheck(f, args)
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		t.Fatal(err)
	}
	return code, buf.String()
}

func TestCheck_AllCovered(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	prot := filepath.Join(dir, "protected.txt")
	writeFile(t, reg, minimalRegistry)
	writeFile(t, prot, "abuse.ch\nphishtank.org\n")

	code, out := runCheck(t, "--registry", reg, "--protected", prot)
	if code != 0 {
		t.Fatalf("want exit 0, got %d\nout:\n%s", code, out)
	}
	if !strings.Contains(out, "every registered feed host") {
		t.Errorf("summary line missing:\n%s", out)
	}
}

func TestCheck_UncoveredHostReported(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	prot := filepath.Join(dir, "protected.txt")
	writeFile(t, reg, minimalRegistry)
	// Only abuse.ch covered; phishtank.org NOT.
	writeFile(t, prot, "abuse.ch\n")

	code, out := runCheck(t, "--registry", reg, "--protected", prot)
	if code != 1 {
		t.Fatalf("want exit 1, got %d\nout:\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL  phishtank.org") {
		t.Errorf("failure line missing phishtank.org:\n%s", out)
	}
	if !strings.Contains(out, "[source src-0002]") {
		t.Errorf("failure line missing source id:\n%s", out)
	}
	if !strings.Contains(out, "1 of 2 feed host(s) uncovered") {
		t.Errorf("summary line missing count:\n%s", out)
	}
}

func TestCheck_CommentsAndBlanksInProtectedListAreIgnored(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	prot := filepath.Join(dir, "protected.txt")
	writeFile(t, reg, minimalRegistry)
	writeFile(t, prot, `# feeds
abuse.ch
   # indented comment (still a comment)

  phishtank.org
`)

	code, out := runCheck(t, "--registry", reg, "--protected", prot)
	if code != 0 {
		t.Fatalf("want exit 0, got %d\nout:\n%s", code, out)
	}
}

func TestCheck_MissingFlagsExit2(t *testing.T) {
	if code, _ := runCheck(t); code != exitUsage {
		t.Errorf("no args: want %d, got %d", exitUsage, code)
	}
	if code, _ := runCheck(t, "--registry", "x"); code != exitUsage {
		t.Errorf("missing --protected: want %d, got %d", exitUsage, code)
	}
	if code, _ := runCheck(t, "--protected", "x"); code != exitUsage {
		t.Errorf("missing --registry: want %d, got %d", exitUsage, code)
	}
}

func TestCheck_MissingRegistryFileExits3(t *testing.T) {
	dir := t.TempDir()
	prot := filepath.Join(dir, "protected.txt")
	writeFile(t, prot, "abuse.ch\n")
	code, out := runCheck(t, "--registry", "/no/such/file.json", "--protected", prot)
	if code != 3 {
		t.Errorf("want exit 3 (could-not-check), got %d\nout:\n%s", code, out)
	}
}

func TestCheck_MissingProtectedFileExits3(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	writeFile(t, reg, minimalRegistry)
	code, out := runCheck(t, "--registry", reg, "--protected", "/no/such/file.txt")
	if code != 3 {
		t.Errorf("want exit 3, got %d\nout:\n%s", code, out)
	}
}

func TestCheck_QuietPassPrintsOneLine(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	prot := filepath.Join(dir, "protected.txt")
	writeFile(t, reg, minimalRegistry)
	writeFile(t, prot, "abuse.ch\nphishtank.org\n")

	code, out := runCheck(t, "--quiet", "--registry", reg, "--protected", prot)
	if code != 0 {
		t.Fatalf("want exit 0, got %d\nout:\n%s", code, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("--quiet pass should print 1 line, got %d:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "ok  ") {
		t.Errorf("--quiet pass should start with 'ok', got %q", lines[0])
	}
}
