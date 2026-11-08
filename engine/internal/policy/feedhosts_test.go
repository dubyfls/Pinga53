// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/policy"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// mkReg builds a minimal sourceregistry.Registry that FeedHosts can walk.
// Only the fields FeedHosts reads are populated — the loader's own
// validation is exercised elsewhere.
func mkReg(urls ...string) *sourceregistry.Registry {
	reg := &sourceregistry.Registry{}
	for i, u := range urls {
		reg.Sources = append(reg.Sources, sourceregistry.Source{
			SourceID:              genSourceID(i),
			OfficialDocumentation: u,
		})
	}
	return reg
}

func genSourceID(i int) string {
	// src-0001, src-0002, …
	digits := [4]byte{'0', '0', '0', '0'}
	n := i + 1
	pos := 3
	for n > 0 && pos >= 0 {
		digits[pos] = byte('0' + n%10)
		n /= 10
		pos--
	}
	return "src-" + string(digits[:])
}

func TestFeedHosts_ExtractsAndLowercases(t *testing.T) {
	reg := mkReg(
		"https://URLhaus.abuse.ch/api/",
		"https://phishtank.org/data.json",
		"https://data.mozilla.org/",
	)
	got := policy.FeedHosts(reg)
	if len(got) != 3 {
		t.Fatalf("want 3 hosts, got %d: %+v", len(got), got)
	}
	hosts := []string{got[0].Host, got[1].Host, got[2].Host}
	want := []string{"urlhaus.abuse.ch", "phishtank.org", "data.mozilla.org"}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("host[%d]=%q, want %q", i, hosts[i], want[i])
		}
	}
	// Source citation is preserved.
	if got[0].SourceID != "src-0001" {
		t.Errorf("SourceID[0]=%q, want src-0001", got[0].SourceID)
	}
}

func TestFeedHosts_DeduplicatesFirstWins(t *testing.T) {
	reg := mkReg(
		"https://urlhaus.abuse.ch/api/",
		"https://urlhaus.abuse.ch/downloads/text/", // same host, second source
		"https://sslbl.abuse.ch/blacklist/",        // different subdomain, distinct host
	)
	got := policy.FeedHosts(reg)
	if len(got) != 2 {
		t.Fatalf("want 2 unique hosts, got %d: %+v", len(got), got)
	}
	if got[0].SourceID != "src-0001" {
		t.Errorf("first-wins broke: SourceID[0]=%q, want src-0001", got[0].SourceID)
	}
	if got[1].Host != "sslbl.abuse.ch" {
		t.Errorf("host[1]=%q, want sslbl.abuse.ch", got[1].Host)
	}
}

func TestFeedHosts_SkipsUnknownAndMalformed(t *testing.T) {
	reg := mkReg(
		"https://good.example/",
		"unknown",
		"",
		"::not::a::url",
		"https://another.example/x",
	)
	got := policy.FeedHosts(reg)
	if len(got) != 2 {
		t.Fatalf("want 2 valid hosts, got %d: %+v", len(got), got)
	}
	if got[0].Host != "good.example" || got[1].Host != "another.example" {
		t.Errorf("skipping malformed dropped the wrong entries: %+v", got)
	}
}

func TestCoverAllowSuffix_WholeLabelMatch(t *testing.T) {
	protected := []string{"abuse.ch", "  example.com  ", "# a comment (whitespace-only after trim ignored)", ""}
	// The blank/comment handling is done by the caller (readProtectedList);
	// but the matcher should not mistake a whitespace suffix for a real one.
	protected = []string{"abuse.ch", "example.com"}
	cases := []struct {
		host string
		want bool
	}{
		{"abuse.ch", true},             // exact
		{"urlhaus.abuse.ch", true},     // subdomain
		{"deep.nested.abuse.ch", true}, // deeper subdomain
		{"example.com", true},          // exact, second suffix
		{"badabuse.ch", false},         // tail-similar but different label boundary
		{"notabuse.ch", false},         // tail-similar
		{"abuse.chx", false},           // extra trailing chars
		{"unrelated.org", false},       // no match at all
		{"URLhaus.ABUSE.CH", true},     // case-insensitive
	}
	for _, tc := range cases {
		got := policy.CoverAllowSuffix(tc.host, protected)
		if got != tc.want {
			t.Errorf("CoverAllowSuffix(%q, protected)=%v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestCoverAllowSuffix_EmptyInputs(t *testing.T) {
	if policy.CoverAllowSuffix("", []string{"example.com"}) {
		t.Error("empty host must not match")
	}
	if policy.CoverAllowSuffix("example.com", nil) {
		t.Error("nil protected must not match anything")
	}
	if policy.CoverAllowSuffix("example.com", []string{"   "}) {
		t.Error("whitespace-only suffix must not match anything")
	}
}

func TestUncoveredFeedHosts_ReportsMissing(t *testing.T) {
	reg := mkReg(
		"https://urlhaus.abuse.ch/",
		"https://data.mozilla.org/",
		"https://phishtank.org/",
	)
	protected := []string{"abuse.ch"} // only one covered
	uncovered := policy.UncoveredFeedHosts(reg, protected)
	if len(uncovered) != 2 {
		t.Fatalf("want 2 uncovered, got %d: %+v", len(uncovered), uncovered)
	}
	names := []string{uncovered[0].Host, uncovered[1].Host}
	want := []string{"data.mozilla.org", "phishtank.org"}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("uncovered[%d]=%q, want %q", i, names[i], want[i])
		}
	}
}

func TestUncoveredFeedHosts_AllCovered(t *testing.T) {
	reg := mkReg(
		"https://urlhaus.abuse.ch/",
		"https://sslbl.abuse.ch/",
	)
	protected := []string{"abuse.ch"}
	if got := policy.UncoveredFeedHosts(reg, protected); len(got) != 0 {
		t.Fatalf("all-covered should return empty slice, got %+v", got)
	}
}

func TestUncoveredFeedHosts_NilRegistry(t *testing.T) {
	if got := policy.UncoveredFeedHosts(nil, []string{"anything"}); got != nil {
		t.Fatalf("nil registry should return nil slice, got %+v", got)
	}
}
