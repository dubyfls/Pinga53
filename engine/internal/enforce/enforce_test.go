// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/shadow"
)

// subscribedRead is a gravity answer that WAS read and covers nothing.
//
// Needed because shadow.SubscribedNotRead makes C-25 hold every addition for
// review — correctly: "I could not check whether I would be overriding the
// household" is not a reason to go ahead. A fixture using it therefore
// produces no KindAdd at all, and a test asserting on additions against it
// would be asserting on the unread-gravity path while believing it was
// testing an ordinary add. That is how the first draft of this file failed.
type subscribedRead struct{}

func (subscribedRead) Membership(string) (shadow.Tristate, shadow.Tristate) {
	return shadow.No, shadow.No
}
func (subscribedRead) Read() bool     { return true }
func (subscribedRead) Source() string { return "synthetic: read, and covering nothing" }

// fixturePlan is a shadow comparison holding one of every kind that matters,
// built through the real shadow.Compare rather than by hand.
//
// Through Compare deliberately: a hand-built shadow.Plan would let this file
// assert against a shape internal/shadow never actually produces, which is
// how a vocabulary drifts from the thing it is supposed to describe.
func fixturePlan(t *testing.T) *shadow.Plan {
	t.Helper()
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	p, err := shadow.Compare(shadow.Input{
		// added.example.com is absent from the appliance and allowed by
		// nothing: an effective addition.
		// present.example.com is held by an entry ScamWall owns.
		// stale.example.net is owned and no longer qualifies: a removal.
		Qualifying: []string{"added.example.com", "present.example.com"},
		Observed: shadow.Observation{
			Entries: []shadow.Entry{
				{Domain: "present.example.com", Enabled: true, Comment: "placed by scamwall"},
				{Domain: "stale.example.net", Enabled: true, Comment: "placed by scamwall"},
			},
			ReadAt:        at,
			TargetHost:    "pihole.invalid",
			TargetAddress: "198.51.100.1:443",
			Complete:      true,
		},
		Owned: shadow.LedgerOwnership{Domains: map[string]bool{
			"present.example.com": true,
			"stale.example.net":   true,
		}},
		// Read, and covering nothing, so additions are not held for the
		// unread-allowlist reason and the review below is the subscribed one.
		Allow: shadow.ObservedAllowList{
			Covers:    func(string) bool { return false },
			CoverKind: func(string) (bool, bool) { return false, false },
		},
		Subscribed:        subscribedRead{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: at.Format(time.RFC3339),
		ComparedAt:        at,
		BuildIdentity:     "scamwall test",
	})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	return p
}

// TestTheShadowAdapterReportsAndCannotApply.
//
// OutcomeReported is the only outcome this adapter can return. The assertion
// is not decoration: an adapter interface is a place where the power to write
// tends to arrive by accident, and the shadow path's whole value is that it
// has never had that power.
func TestTheShadowAdapterReportsAndCannotApply(t *testing.T) {
	a := ShadowAdapter{Plan: fixturePlan(t)}

	r, err := a.Enforce(Plan{Adds: []string{"anything.example.com"}})
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if r.Outcome != OutcomeReported {
		t.Errorf("outcome is %q, want %q", r.Outcome, OutcomeReported)
	}
	if r.Outcome.Changed() {
		t.Error("the shadow adapter reported having changed something")
	}
	if r.Reason == "" {
		t.Error("a non-applying outcome carries no reason")
	}
	if r.Adapter != "shadow" {
		t.Errorf("adapter is %q", r.Adapter)
	}
}

// TestTheShadowAdapterReportsTheComparisonAndNotThePlan.
//
// The plan argument is ignored for the counts on purpose. A host the decider
// wanted to add and the appliance already blocks is not an addition, and
// reporting the decider's number would overstate the work. The fixture makes
// them differ: the plan claims three additions, the appliance says one.
func TestTheShadowAdapterReportsTheComparisonAndNotThePlan(t *testing.T) {
	a := ShadowAdapter{Plan: fixturePlan(t)}

	r, _ := a.Enforce(Plan{Adds: []string{"a.example.com", "b.example.com", "c.example.com"}})
	if r.Adds != 1 {
		t.Errorf("reported %d addition(s); the appliance holds one of the two qualifying "+
			"hosts already, so exactly one is an addition", r.Adds)
	}
	if r.Removals != 1 {
		t.Errorf("reported %d removal(s), want the one owned entry that stopped qualifying", r.Removals)
	}
	if r.Entries != 2 {
		t.Errorf("reported %d observed entries, want 2", r.Entries)
	}
}

// TestANilComparisonIsNotAnEmptyAppliance.
//
// The same refusal internal/shadow makes about a partial read and
// internal/ledger makes about a missing file. A run that produced no
// comparison and a household whose appliance holds nothing are different
// facts, and only one of them is a reason to act.
func TestANilComparisonIsNotAnEmptyAppliance(t *testing.T) {
	r, err := ShadowAdapter{}.Enforce(Plan{})
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if r.Adds != 0 || r.Removals != 0 || r.Entries != 0 {
		t.Errorf("a nil comparison produced counts: %+v", r)
	}
	if !strings.Contains(r.Reason, "not a statement that the appliance holds nothing") {
		t.Errorf("the reason does not distinguish absence from emptiness: %q", r.Reason)
	}
}

// TestEveryShadowKindIsSayableInThePlanVocabulary.
//
// If a shadow plan cannot be expressed in Plan's terms then Plan is missing a
// case a real appliance produces, and the adapter boundary would quietly drop
// it. Checked over the whole closed Kind vocabulary rather than over the
// fixture, so a kind added later fails here rather than going unnoticed.
func TestEveryShadowKindIsSayableInThePlanVocabulary(t *testing.T) {
	// The closed set from internal/shadow, restated so that adding a kind
	// there without deciding its enforcement meaning fails this test.
	all := []shadow.Kind{
		shadow.KindAdd, shadow.KindAlreadyPresent, shadow.KindConflict, shadow.KindRemove,
		shadow.KindHouseholdAllowed, shadow.KindAllowNotEvaluable, shadow.KindDisabledEntry,
		shadow.KindReview,
	}
	// Each kind is either acted on, held for review, or deliberately inert.
	// An inert kind changes nothing about enforcement: the appliance already
	// holds the entry, or the household has overridden it.
	inert := map[shadow.Kind]bool{
		shadow.KindAlreadyPresent:   true,
		shadow.KindConflict:         true,
		shadow.KindHouseholdAllowed: true,
		shadow.KindDisabledEntry:    true,
	}
	acted := map[shadow.Kind]bool{shadow.KindAdd: true, shadow.KindRemove: true}
	review := map[shadow.Kind]bool{shadow.KindReview: true, shadow.KindAllowNotEvaluable: true}

	for _, k := range all {
		if !inert[k] && !acted[k] && !review[k] {
			t.Errorf("shadow kind %q has no enforcement meaning; FromShadow would drop it "+
				"silently", k)
		}
	}
}

// TestFromShadowSortsAndSeparates.
func TestFromShadowSortsAndSeparates(t *testing.T) {
	p := FromShadow(fixturePlan(t))
	if len(p.Adds) != 1 || p.Adds[0] != "added.example.com" {
		t.Errorf("adds are %v", p.Adds)
	}
	if len(p.Removals) != 1 || p.Removals[0] != "stale.example.net" {
		t.Errorf("removals are %v", p.Removals)
	}
	if FromShadow(nil).Adds != nil {
		t.Error("a nil comparison produced additions")
	}
}

// TestDescribeSaysWhatHappenedAndWhy.
func TestDescribeSaysWhatHappenedAndWhy(t *testing.T) {
	s := Describe(Result{
		Adapter: "rpz", Outcome: OutcomeFrozen, Reason: "the supply is degraded",
		Adds: 0, Removals: 0,
	})
	for _, want := range []string{"rpz", "frozen", "0 addition(s)", "the supply is degraded"} {
		if !strings.Contains(s, want) {
			t.Errorf("the description omits %q: %s", want, s)
		}
	}
}

// TestNoChangeIsASuccessAndNotAChange.
//
// The distinction the exit status depends on. A run that found the state
// already correct succeeded; it did not move the resolver's view, and a
// caller counting changes must not include it.
func TestNoChangeIsASuccessAndNotAChange(t *testing.T) {
	if OutcomeNoChange.Changed() {
		t.Error("no_change reports itself as a change")
	}
	if !OutcomeApplied.Changed() {
		t.Error("applied does not report itself as a change")
	}
	for _, o := range []Outcome{OutcomeFrozen, OutcomeRefused, OutcomeReview, OutcomeReported} {
		if o.Changed() {
			t.Errorf("%q reports itself as a change", o)
		}
	}
}
