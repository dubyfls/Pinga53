// SPDX-License-Identifier: AGPL-3.0-only

package proposal_test

import (
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/proposal"
)

// C-21 — what keeps a ScamWall-owned block alive, and what ends it.
//
// Four rules, and the interesting part is which of them a FREEZE suspends.
// A freeze exists to protect against the ABSENCE of evidence: the supply is
// degraded, so "nobody is saying this is bad any more" stops meaning what it
// usually means. It is not a reason to ignore evidence that did arrive, and
// it is never a reason to override the household.

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func owned(name string, justifiedHoursAgo int) proposal.OwnedEntry {
	return proposal.OwnedEntry{
		Canonical:       name,
		AddedAt:         t0.Add(-time.Duration(justifiedHoursAgo+100) * time.Hour),
		LastJustifiedAt: t0.Add(-time.Duration(justifiedHoursAgo) * time.Hour),
	}
}

func retain(in proposal.RetentionInput) proposal.RetentionDecision {
	if in.Now.IsZero() {
		in.Now = t0
	}
	if in.Lifetime == 0 {
		in.Lifetime = 168 * time.Hour // a week
	}
	return proposal.AssessRetention(in)
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestAJustifiedBlockIsKept — the control on the control.
func TestAJustifiedBlockIsKept(t *testing.T) {
	d := retain(proposal.RetentionInput{
		Owned:          []proposal.OwnedEntry{owned("bad.example.com", 1)},
		StillJustified: map[string]bool{"bad.example.com": true},
	})
	if len(d.Removals) != 0 {
		t.Fatalf("removals = %v, want none", d.Removals)
	}
}

// TestAWithdrawnReportDoesNotKeepABlockAlive — ORDER 9 §1 harm 2, named
// exactly. A retraction is evidence that ARRIVED, so a freeze does not
// suspend it.
func TestAWithdrawnReportDoesNotKeepABlockAlive(t *testing.T) {
	for _, outage := range []bool{false, true} {
		d := retain(proposal.RetentionInput{
			Owned:        []proposal.OwnedEntry{owned("retracted.example.com", 1)},
			Withdrawn:    map[string]bool{"retracted.example.com": true},
			SourceOutage: outage,
			OnOutage:     proposal.OutageHold,
		})
		if !has(d.Removals, "retracted.example.com") {
			t.Errorf("source outage=%v: a withdrawn report left the block standing; removals = %v", outage, d.Removals)
		}
	}
}

// TestTheHouseholdsExceptionEndsABlockEvenUnderFreeze — the household's own
// statement outranks every source, which is this tree's existing rule for
// ReasonUserException, and a freeze is not a reason to stop honouring it.
func TestTheHouseholdsExceptionEndsABlockEvenUnderFreeze(t *testing.T) {
	d := retain(proposal.RetentionInput{
		Owned:          []proposal.OwnedEntry{owned("bank.example.com", 1)},
		StillJustified: map[string]bool{"bank.example.com": true},
		Excepted:       map[string]bool{"bank.example.com": true},
		SourceOutage:   true,
		OnOutage:       proposal.OutageHold,
	})
	if !has(d.Removals, "bank.example.com") {
		t.Fatalf("an excepted domain stayed blocked through a freeze; removals = %v", d.Removals)
	}
	if d.Outcomes[0].Reason != proposal.ReasonRetentionExcepted {
		t.Errorf("reason = %s, want %s", d.Outcomes[0].Reason, proposal.ReasonRetentionExcepted)
	}
}

// TestLifetimeExpiryIsWhatAFreezeSuspends — the discriminating pair. The same
// stale block, under the two outage behaviours the household can choose,
// must come to different answers, or `on_source_outage` is decorative.
func TestLifetimeExpiryIsWhatAFreezeSuspends(t *testing.T) {
	stale := []proposal.OwnedEntry{owned("stale.example.com", 400)} // well past a week

	held := retain(proposal.RetentionInput{
		Owned: stale, SourceOutage: true, OnOutage: proposal.OutageHold,
	})
	if has(held.Removals, "stale.example.com") {
		t.Errorf("hold_existing_blocks removed a block during an outage; removals = %v", held.Removals)
	}
	if !held.Frozen {
		t.Errorf("the decision does not report itself as frozen")
	}
	if held.Outcomes[0].Reason != proposal.ReasonRetentionFrozen {
		t.Errorf("reason = %s, want %s", held.Outcomes[0].Reason, proposal.ReasonRetentionFrozen)
	}

	expired := retain(proposal.RetentionInput{
		Owned: stale, SourceOutage: true, OnOutage: proposal.OutageExpire,
	})
	if !has(expired.Removals, "stale.example.com") {
		t.Fatalf("expire_existing_blocks kept a block past its lifetime through an outage; removals = %v", expired.Removals)
	}

	// And with no outage at all, lifetime simply applies.
	normal := retain(proposal.RetentionInput{Owned: stale})
	if !has(normal.Removals, "stale.example.com") {
		t.Errorf("a block past its lifetime was kept with no outage in sight; removals = %v", normal.Removals)
	}
}

// TestLifetimeRunsFromTheLastJustificationNotFromTheAdd — a block that keeps
// being re-justified never expires, which is the whole point of measuring
// from re-justification rather than from when it was added.
func TestLifetimeRunsFromTheLastJustificationNotFromTheAdd(t *testing.T) {
	e := proposal.OwnedEntry{
		Canonical:       "long.example.com",
		AddedAt:         t0.Add(-8760 * time.Hour), // a year ago
		LastJustifiedAt: t0.Add(-1 * time.Hour),    // still being reported
	}
	d := retain(proposal.RetentionInput{Owned: []proposal.OwnedEntry{e}})
	if has(d.Removals, "long.example.com") {
		t.Fatalf("a block re-justified an hour ago was expired on the strength of when it was added")
	}
}

// TestTheHouseholdsOwnEntriesAreNeverPlanItems — the rule that has to survive
// every other rule. An exception or a withdrawal naming a domain ScamWall does
// NOT own must not produce a removal: ScamWall would be deleting somebody
// else's entry on the strength of its own opinion.
func TestTheHouseholdsOwnEntriesAreNeverPlanItems(t *testing.T) {
	d := retain(proposal.RetentionInput{
		Owned:     []proposal.OwnedEntry{owned("ours.example.com", 1)},
		Excepted:  map[string]bool{"theirs.example.com": true},
		Withdrawn: map[string]bool{"alsotheirs.example.com": true},
	})
	for _, n := range []string{"theirs.example.com", "alsotheirs.example.com"} {
		if has(d.Removals, n) {
			t.Errorf("%s is not owned by ScamWall and was proposed for removal", n)
		}
	}
	for _, o := range d.Outcomes {
		if o.Canonical != "ours.example.com" {
			t.Errorf("an outcome was reported for %s, which is not in the ownership ledger", o.Canonical)
		}
	}
}

// TestAnExceptionOutranksAWithdrawalOutranksALifetime — the order is fixed so
// that the recorded reason is stable and an operator reading two runs sees
// the same reason for the same facts.
func TestAnExceptionOutranksAWithdrawalOutranksALifetime(t *testing.T) {
	d := retain(proposal.RetentionInput{
		Owned:     []proposal.OwnedEntry{owned("all.example.com", 400)},
		Excepted:  map[string]bool{"all.example.com": true},
		Withdrawn: map[string]bool{"all.example.com": true},
	})
	if d.Outcomes[0].Reason != proposal.ReasonRetentionExcepted {
		t.Errorf("reason = %s, want %s: the household's statement is the top of the order",
			d.Outcomes[0].Reason, proposal.ReasonRetentionExcepted)
	}
}

// TestZeroLifetimeIsRefusedNotTreatedAsImmediate — a lifetime nobody set must
// not mean "expire everything now". This is the same rule as C-10's
// limits_unset and it fails the same way if it is missed.
func TestZeroLifetimeIsRefusedNotTreatedAsImmediate(t *testing.T) {
	d := proposal.AssessRetention(proposal.RetentionInput{
		Owned: []proposal.OwnedEntry{owned("bad.example.com", 400)},
		Now:   t0,
		// Lifetime deliberately unset.
	})
	if len(d.Removals) != 0 {
		t.Fatalf("an unset block_lifetime expired %d block(s); an unset limit is not a zero one", len(d.Removals))
	}
	if d.Outcomes[0].Reason != proposal.ReasonRetentionLifetimeUnset {
		t.Errorf("reason = %s, want %s", d.Outcomes[0].Reason, proposal.ReasonRetentionLifetimeUnset)
	}
}
