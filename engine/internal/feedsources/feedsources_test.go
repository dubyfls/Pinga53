// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

func TestNormaliseHost(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain host", "example.com", "example.com", false},
		{"with scheme", "https://evil.example.com/path?x=1", "evil.example.com", false},
		{"with port", "evil.example.com:8080", "evil.example.com", false},
		{"with userinfo", "https://u:p@evil.example.com/x", "evil.example.com", false},
		{"trailing dot", "evil.example.com.", "evil.example.com", false},
		{"uppercase", "EVIL.Example.COM", "evil.example.com", false},
		{"idna ace", "xn--mnich-kva.com", "xn--mnich-kva.com", false},
		{"idna unicode", "münchen.com", "xn--mnchen-3ya.com", false},
		{"ip literal", "192.0.2.1", "", true},
		{"single label", "localhost", "", true},
		{"empty", "", "", true},
		{"public suffix only", "co.uk", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormaliseHost(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NormaliseHost(%q): err=%v wantErr=%v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("NormaliseHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDropProtected(t *testing.T) {
	records := []feed.EvidenceRecord{
		{Type: "domain", Value: "abuse.ch"},
		{Type: "domain", Value: "subdomain.abuse.ch"},
		{Type: "domain", Value: "evilbuseabuse.ch"}, // not a suffix match
		{Type: "domain", Value: "evil.example.com"},
	}
	protected := []string{"# comment", "abuse.ch", "", "phishtank.org"}
	out := DropProtected(records, protected)
	got := map[string]bool{}
	for _, r := range out {
		got[r.Value] = true
	}
	if got["abuse.ch"] || got["subdomain.abuse.ch"] {
		t.Fatalf("DropProtected failed to drop protected host: %+v", out)
	}
	if !got["evilbuseabuse.ch"] {
		t.Fatalf("DropProtected dropped a non-suffix match: %+v", out)
	}
	if !got["evil.example.com"] {
		t.Fatalf("DropProtected dropped an unrelated host: %+v", out)
	}
}

func TestDedupe(t *testing.T) {
	records := []feed.EvidenceRecord{
		{Type: "domain", Value: "a.example", SourceID: "s1"},
		{Type: "domain", Value: "a.example", SourceID: "s1"},
		{Type: "domain", Value: "a.example", SourceID: "s2"},
		{Type: "domain", Value: "b.example", SourceID: "s1"},
	}
	out := Dedupe(records)
	if len(out) != 3 {
		t.Fatalf("Dedupe: want 3 records, got %d", len(out))
	}
}

func TestWriteAndReadRecordsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	records := []feed.EvidenceRecord{
		{Type: "domain", Value: "a.example", SourceID: "src-x", Classification: "malicious", State: "active"},
	}
	if err := WriteRecordsFile(path, "src-x", 30*time.Minute, now, records); err != nil {
		t.Fatalf("WriteRecordsFile: %v", err)
	}
	rf, err := ReadRecordsFile(path)
	if err != nil {
		t.Fatalf("ReadRecordsFile: %v", err)
	}
	if rf.SchemaVersion != RecordsFileSchema {
		t.Fatalf("schema: got %d want %d", rf.SchemaVersion, RecordsFileSchema)
	}
	if rf.SourceID != "src-x" {
		t.Fatalf("source id: got %q", rf.SourceID)
	}
	if rf.RecordCount != 1 || len(rf.Records) != 1 || rf.Records[0].Value != "a.example" {
		t.Fatalf("records round-trip failed: %+v", rf)
	}
}

func TestReadKeyFileRefusesWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "abusech.key")
	if err := os.WriteFile(path, []byte("my-secret-key\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadKeyFile(path); err == nil {
		t.Fatalf("ReadKeyFile should refuse a 0644 file")
	} else if !strings.Contains(err.Error(), "world-readable") {
		t.Fatalf("expected world-readable in error, got %v", err)
	}
}

func TestReadKeyFileMissing(t *testing.T) {
	_, err := ReadKeyFile("/tmp/nope-does-not-exist-xyz.key")
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
	if !strings.Contains(err.Error(), "credential file is missing") {
		t.Fatalf("expected ErrKeyFileMissing wrapping, got %v", err)
	}
}

func TestReadKeyFileHappy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "abusech.key")
	if err := os.WriteFile(path, []byte("my-secret-key\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadKeyFile(path)
	if err != nil {
		t.Fatalf("ReadKeyFile: %v", err)
	}
	if got != "my-secret-key" {
		t.Fatalf("got %q, want %q", got, "my-secret-key")
	}
}
