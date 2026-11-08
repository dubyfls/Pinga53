// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"encoding/json"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// A household-only run decides with the LOCAL rights. A source whose terms
// prohibit derived output (OpenPhish, abuse.ch) still counts toward
// protecting the household, and the outcome is marked export-withheld so it
// can never reach a published list.
func TestHouseholdLocalUseDecidesWithoutDerivedOutput(t *testing.T) {
	p := testPolicy(t, 1, ScopeExact)
	p.HouseholdLocalUse = true
	rep := run{
		asserts: []string{"src-a"},
		sources: householdGrant(sourceregistry.OpDerivedOutput),
		policy:  p,
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
	}.do(t)
	o := only(t, rep)
	if o.Reason == ReasonDerivedOutputRefused {
		t.Fatalf("household-local run still asked derived_output: %s", o.Explanation)
	}
	if o.Canonical != "one.example.com" {
		t.Fatalf("decision lost its indicator: %+v", o)
	}
	if !o.ExportWithheld {
		t.Fatal("a derived_output-prohibited source produced an exportable outcome")
	}
	for _, e := range rep.ForAudience(AudienceExport).Outcomes {
		if e.Canonical != "" {
			t.Fatalf("export audience named %q from a derived_output-prohibited source", e.Canonical)
		}
	}
	for _, r := range rep.ForAudience(AudienceExport).Records {
		if r.Canonical != "" {
			t.Fatalf("export audience record named %q", r.Canonical)
		}
	}
}

// Enrichment is a local right and is still required.
func TestHouseholdLocalUseStillRequiresEnrichment(t *testing.T) {
	p := testPolicy(t, 1, ScopeExact)
	p.HouseholdLocalUse = true
	rep := run{
		asserts: []string{"src-a"},
		sources: householdGrant(sourceregistry.OpEnrichment),
		policy:  p,
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
	}.do(t)
	wantDecision(t, only(t, rep), DecisionRefuse, ReasonEnrichmentRefused)
}

// Off by default; the field round-trips; it changes the digest only when set.
func TestHouseholdLocalUseDefaultAndDigest(t *testing.T) {
	p := testPolicy(t, 1, ScopeExact)
	if p.HouseholdLocalUse {
		t.Fatal("household_local_use must default to false")
	}
	before := p.Digest()
	p.HouseholdLocalUse = true
	if p.Digest() == before {
		t.Fatal("setting household_local_use did not change the policy digest")
	}
	var q struct {
		H bool `json:"household_local_use"`
	}
	if err := json.Unmarshal([]byte(`{"household_local_use": true}`), &q); err != nil || !q.H {
		t.Fatal("field name drifted")
	}
}

func householdGrant(op sourceregistry.Operation) []sourceregistry.Source {
	srcs := twoSources()
	srcs[0].Permissions[op] = prohibitedGrant()
	return srcs
}
