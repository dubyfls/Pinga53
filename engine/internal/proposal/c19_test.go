// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// C-19 — an explicit upstream retraction, by a source entitled to be counted,
// is a CONFLICT and not merely an absence.
//
// The gap this closes: a source that says "we were wrong about this" is today
// invisible while anyone else is still reporting. It drops out of the live
// set, `Corroboration.Withdrawn` records it, and then nothing reads that
// field unless EVERY source has withdrawn. So two sources asserting and one
// retracting proposes a block and says nothing about the retraction.
//
// A retraction is not an absence. An expired observation is a source going
// quiet; a withdrawal is a source speaking, and what it says contradicts the
// sources still asserting. `Conflicted` already refuses to take sides between
// `malicious` and `benign`; this is the same disagreement written a different
// way.

func retractionRun(t *testing.T, withdrawnGrants map[sourceregistry.Operation]sourceregistry.Grant) *Report {
	t.Helper()
	c := testSource("src-c", nil)
	for op, g := range withdrawnGrants {
		c.Permissions[op] = g
	}
	return run{
		asserts: []string{"src-a", "src-b", "src-c"},
		sources: []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil), c},
		policy:  testPolicy(t, 2, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "r1", "bad.example.com"),
			adverse("src-b", "r2", "bad.example.com"),
			withdrawnRecord("src-c", "r3", "bad.example.com"),
		},
	}.do(t)
}

// withdrawnRecord is a source retracting what it previously said.
func withdrawnRecord(sourceID, recordID, value string) feed.EvidenceRecord {
	r := adverse(sourceID, recordID, value)
	r.Status = string("withdrawn")
	return r
}

func TestARetractionByACountableSourceIsAConflict(t *testing.T) {
	rep := retractionRun(t, nil)
	o := rep.Outcomes[0]

	if o.Decision != DecisionAbstain {
		t.Fatalf("decision = %s/%s, want %s: two sources assert and a third has retracted; "+
			"this build does not take a side in a disagreement\n  %s", o.Decision, o.Reason, DecisionAbstain, o.Explanation)
	}
	if o.Reason != ReasonConflict {
		t.Errorf("reason = %s, want %s", o.Reason, ReasonConflict)
	}
	if !o.Conflicted {
		t.Errorf("Conflicted = false; the report does not carry the disagreement it decided on")
	}
	if !strings.Contains(o.Explanation, "src-c") {
		t.Errorf("the explanation does not name the retracting source: %q", o.Explanation)
	}
	if len(o.RetractedBy) != 1 || o.RetractedBy[0] != "src-c" {
		t.Errorf("RetractedBy = %v, want [src-c]", o.RetractedBy)
	}
}

// TestARetractionByASourceThatMayNotBeCountedIsNotAConflict — a source whose
// grant does not permit its records being combined with others cannot be used
// to justify a block, and must not be usable to veto one either. Rights cut
// both ways or they are not rights.
func TestARetractionByASourceThatMayNotBeCountedIsNotAConflict(t *testing.T) {
	rep := retractionRun(t, map[sourceregistry.Operation]sourceregistry.Grant{
		sourceregistry.OpEnrichment: prohibitedGrant(),
	})
	o := rep.Outcomes[0]
	if o.Decision != DecisionPropose {
		t.Fatalf("decision = %s/%s, want %s: src-c may not be combined with anything, so its "+
			"retraction counts for nothing in either direction\n  %s", o.Decision, o.Reason, DecisionPropose, o.Explanation)
	}
	if len(o.RetractedBy) != 0 {
		t.Errorf("RetractedBy = %v, want none", o.RetractedBy)
	}
}

// TestALapsedObservationIsNotARetraction — the discrimination the control is
// made of, and the same one C-11 draws between a failure and a quarantine.
// Going quiet is not the same as speaking.
func TestALapsedObservationIsNotARetraction(t *testing.T) {
	expired := adverse("src-c", "r3", "bad.example.com")
	past := testAt.Add(-time.Hour)
	expired.ExpiresAt = &past

	rep := run{
		asserts: []string{"src-a", "src-b", "src-c"},
		sources: []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil), testSource("src-c", nil)},
		policy:  testPolicy(t, 2, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "r1", "bad.example.com"),
			adverse("src-b", "r2", "bad.example.com"),
			expired,
		},
	}.do(t)

	o := rep.Outcomes[0]
	if o.Decision != DecisionPropose {
		t.Fatalf("decision = %s/%s, want %s: src-c's evidence lapsed, which is silence, not "+
			"contradiction\n  %s", o.Decision, o.Reason, DecisionPropose, o.Explanation)
	}
}

// TestEverySourceRetractingIsStillWithdrawnOnly — the existing reason must
// keep winning when it applies. "Every source retracted" and "the sources
// disagree" are different facts and an operator acts differently on them.
func TestEverySourceRetractingIsStillWithdrawnOnly(t *testing.T) {
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil)},
		policy:  testPolicy(t, 2, ScopeExact),
		records: []feed.EvidenceRecord{
			withdrawnRecord("src-a", "r1", "bad.example.com"),
			withdrawnRecord("src-b", "r2", "bad.example.com"),
		},
	}.do(t)

	o := rep.Outcomes[0]
	if o.Reason != ReasonWithdrawnOnly {
		t.Errorf("reason = %s, want %s", o.Reason, ReasonWithdrawnOnly)
	}
}
