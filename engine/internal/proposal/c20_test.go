// SPDX-License-Identifier: AGPL-3.0-only

package proposal_test

import (
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/proposal"
)

// C-20 — caps, deferral and the abnormal-removal rule.
//
// Three separate statements that a single "max additions" number is often
// mistaken for:
//
//   - PER-RUN is an abnormality signal. One batch far larger than usual means
//     something upstream changed, and applying the first N of it vets none of
//     it. This build already holds the whole run, and that is not weakened
//     here — what is added is that the held set is RECORDED as deferred
//     rather than silently forgotten.
//   - PER-DAY is a ration. Today's budget is spent; the excess waits for
//     tomorrow. Nothing is abnormal and nothing is dropped.
//   - ABNORMAL REMOVALS is the mass-unblocking guard, and it is measured
//     against what ScamWall owns, not against a fixed count.

var day = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func evidenceAt(h int) time.Time { return day.Add(time.Duration(h) * time.Hour) }

// TestTheDailyCapCountsWhatShadowRunsProposed is the clause ORDER 9 names
// explicitly. In this build the only path from a decision to the appliance is
// an operator applying a shadow plan, so a shadow addition IS an addition. A
// ledger that counts only what an enforcing run applied lets the daily cap be
// walked past by running shadow repeatedly.
func TestTheDailyCapCountsWhatShadowRunsProposed(t *testing.T) {
	l := proposal.DayLedger{Known: true, AutomaticAdditions: 0, ShadowAdditions: 8}
	if got := l.Additions(); got != 8 {
		t.Fatalf("Additions() = %d, want 8: a shadow run's proposed adds count toward the daily cap", got)
	}

	// Cap 10, 8 already proposed today, 5 more qualify: 2 fit, 3 are deferred.
	rep := reportOf(t, "a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com")
	pol := activePolicy(t, 100, 10) // generous per-run cap, daily cap of 10
	plan := proposal.Qualify(rep, pol, proposal.AutoInputs{
		Today: l,
		NewestEvidence: map[string]time.Time{
			"a.example.com": evidenceAt(1),
			"b.example.com": evidenceAt(5), // newest
			"c.example.com": evidenceAt(4),
			"d.example.com": evidenceAt(3),
			"e.example.com": evidenceAt(2),
		},
	})

	if len(plan.Blocks) != 2 {
		t.Fatalf("blocks = %v (%d), want 2 — the day had 8 of its 10 already spent", plan.Blocks, len(plan.Blocks))
	}
	// Newest evidence goes first.
	want := []string{"b.example.com", "c.example.com"}
	for i, w := range want {
		if plan.Blocks[i] != w {
			t.Errorf("blocks[%d] = %s, want %s — the cap must be spent newest evidence first", i, plan.Blocks[i], w)
		}
	}
	if len(plan.Deferred) != 3 {
		t.Fatalf("deferred = %v, want 3 entries; the excess must be deferred, not dropped", plan.Deferred)
	}
	// Deferred are newest-first too, so the next run takes them in the same
	// priority rather than in a second, different order.
	for i, w := range []string{"d.example.com", "e.example.com", "a.example.com"} {
		if plan.Deferred[i].Canonical != w {
			t.Errorf("deferred[%d] = %s, want %s", i, plan.Deferred[i].Canonical, w)
		}
	}
	for _, d := range plan.Deferred {
		if d.Reason != proposal.ReasonDeferredDailyCap {
			t.Errorf("%s deferred under %s, want %s", d.Canonical, d.Reason, proposal.ReasonDeferredDailyCap)
		}
	}
}

// TestNothingIsDropped — the property the whole control turns on. Every
// indicator that qualified is either planned or deferred, never neither.
func TestNothingIsDropped(t *testing.T) {
	rep := reportOf(t, "a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com")
	pol := activePolicy(t, 100, 3)
	plan := proposal.Qualify(rep, pol, proposal.AutoInputs{})

	accounted := map[string]bool{}
	for _, b := range plan.Blocks {
		accounted[b] = true
	}
	for _, d := range plan.Deferred {
		if accounted[d.Canonical] {
			t.Errorf("%s is both planned and deferred", d.Canonical)
		}
		accounted[d.Canonical] = true
	}
	for _, n := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"} {
		if !accounted[n] {
			t.Errorf("%s qualified and is neither planned nor deferred; it was dropped", n)
		}
	}
}

// TestAnUnknownEvidenceTimeSortsLast — a name whose recency nobody recorded
// must not win the cap by accident. Unknown is the back of the queue, and the
// order is still deterministic.
func TestAnUnknownEvidenceTimeSortsLast(t *testing.T) {
	rep := reportOf(t, "known.example.com", "unknown.example.com")
	pol := activePolicy(t, 100, 1)
	plan := proposal.Qualify(rep, pol, proposal.AutoInputs{
		NewestEvidence: map[string]time.Time{"known.example.com": evidenceAt(1)},
	})
	if len(plan.Blocks) != 1 || plan.Blocks[0] != "known.example.com" {
		t.Fatalf("blocks = %v, want [known.example.com]: an unrecorded evidence time must not outrank a recorded one", plan.Blocks)
	}
}

// TestThePerRunHoldIsRecordedAsDeferredNotForgotten — the existing whole-run
// hold is kept exactly as it was. What changes is that the held set now
// appears in Deferred, so a reader can see that the work is waiting rather
// than gone.
func TestThePerRunHoldIsRecordedAsDeferredNotForgotten(t *testing.T) {
	rep := reportOf(t, "a.example.com", "b.example.com", "c.example.com")
	pol := activePolicy(t, 2, 100) // per-run cap of 2, three would block
	plan := proposal.Qualify(rep, pol, proposal.AutoInputs{})

	if !plan.Held {
		t.Fatalf("the run was not held; the per-run hold must not be weakened into a truncation")
	}
	if len(plan.Blocks) != 0 {
		t.Errorf("blocks = %v, want none: an abnormal batch is held whole", plan.Blocks)
	}
	if len(plan.Deferred) != 3 {
		t.Fatalf("deferred = %v, want all three recorded as waiting", plan.Deferred)
	}
	for _, d := range plan.Deferred {
		if d.Reason != proposal.ReasonBulkChangeExceedsLimit {
			t.Errorf("%s deferred under %s, want %s", d.Canonical, d.Reason, proposal.ReasonBulkChangeExceedsLimit)
		}
	}
}

// TestADayAlreadySpentDefersEverything — the boundary. Zero remaining is not
// "unlimited".
func TestADayAlreadySpentDefersEverything(t *testing.T) {
	rep := reportOf(t, "a.example.com", "b.example.com")
	pol := activePolicy(t, 100, 10)
	plan := proposal.Qualify(rep, pol, proposal.AutoInputs{
		Today: proposal.DayLedger{Known: true, AutomaticAdditions: 10},
	})
	if len(plan.Blocks) != 0 {
		t.Fatalf("blocks = %v, want none: the day's budget was already spent", plan.Blocks)
	}
	if len(plan.Deferred) != 2 {
		t.Errorf("deferred = %v, want 2", plan.Deferred)
	}
}

// TestTheDailyCapNoticeTracksWhetherTheJournalWasRead.
//
// A plan must never say a limit is unenforced while it is enforcing it, and
// must never stop saying so while it is not. An unread journal makes every
// run look like the day's first, which is enforcement in name only — so the
// notice stands in that case, and names exactly what the run did do.
func TestTheDailyCapNoticeTracksWhetherTheJournalWasRead(t *testing.T) {
	rep := reportOf(t, "a.example.com")
	pol := activePolicy(t, 100, 10)

	unread := proposal.Qualify(rep, pol, proposal.AutoInputs{})
	if !anyContains(unread.NotEnforced, "max_additions_per_day") {
		t.Errorf("the journal was not read and the plan does not say the daily cap is unenforced: %v", unread.NotEnforced)
	}

	read := proposal.Qualify(rep, pol, proposal.AutoInputs{Today: proposal.DayLedger{Known: true}})
	if anyContains(read.NotEnforced, "max_additions_per_day") {
		t.Errorf("the journal was read and the cap was applied, yet the plan still calls it unenforced: %v", read.NotEnforced)
	}
}

// TestAnUnreadJournalIsNotMorePermissiveThanAReadOne — the trap this control
// invites. If "we did not read the journal" disabled the cap, the way to get
// unlimited additions would be to not keep a journal.
func TestAnUnreadJournalIsNotMorePermissiveThanAReadOne(t *testing.T) {
	rep := reportOf(t, "a.example.com", "b.example.com", "c.example.com")
	plan := proposal.Qualify(rep, activePolicy(t, 100, 2), proposal.AutoInputs{})
	if len(plan.Blocks) != 2 {
		t.Fatalf("blocks = %v, want 2: the daily cap must still bound a run whose journal was not read", plan.Blocks)
	}
	if len(plan.Deferred) != 1 {
		t.Errorf("deferred = %v, want 1", plan.Deferred)
	}
}

// ---- removals ----

// TestAnAbnormalRemovalRunIsHeldWhole — the mass-unblocking guard. It is
// measured against what ScamWall owns, because "twelve removals" is routine
// for a large ledger and catastrophic for a small one.
func TestAnAbnormalRemovalRunIsHeldWhole(t *testing.T) {
	d := proposal.AssessRemovals(proposal.RemovalInput{
		Proposed:   names(30),
		OwnedCount: 100,
		MaxPerRun:  100,
		MaxPerDay:  100,
		Today:      proposal.DayLedger{},
	})
	if !d.Held {
		t.Fatalf("30 removals against 100 owned entries (30%%) was not held; the abnormal-run threshold is %.0f%%",
			proposal.AbnormalRemovalFraction*100)
	}
	if len(d.Removals) != 0 {
		t.Errorf("removals = %v, want none", d.Removals)
	}
	if d.Reason != proposal.ReasonAbnormalRemovalRun {
		t.Errorf("reason = %s, want %s", d.Reason, proposal.ReasonAbnormalRemovalRun)
	}
	if len(d.Deferred) != 30 {
		t.Errorf("a held removal run recorded %d deferred, want 30", len(d.Deferred))
	}
}

func TestAnOrdinaryRemovalRunProceeds(t *testing.T) {
	d := proposal.AssessRemovals(proposal.RemovalInput{
		Proposed:   names(10),
		OwnedCount: 100,
		MaxPerRun:  100,
		MaxPerDay:  100,
	})
	if d.Held {
		t.Fatalf("10 removals against 100 owned (10%%) was held; the guard must not stop ordinary retention")
	}
	if len(d.Removals) != 10 {
		t.Errorf("removals = %d, want 10", len(d.Removals))
	}
}

// TestRemovingEverythingFromAnEmptyLedgerIsNotDivisionByZero — and a removal
// proposed against nothing owned is a bug in the caller, not a licence.
func TestRemovingEverythingFromAnEmptyLedgerIsNotDivisionByZero(t *testing.T) {
	d := proposal.AssessRemovals(proposal.RemovalInput{
		Proposed:   names(3),
		OwnedCount: 0,
		MaxPerRun:  100,
		MaxPerDay:  100,
	})
	if !d.Held {
		t.Fatalf("three removals were planned against an ownership ledger holding nothing")
	}
}

// TestRemovalsBeyondTheCapAreDeferredNotDropped mirrors the addition rule.
func TestRemovalsBeyondTheCapAreDeferredNotDropped(t *testing.T) {
	d := proposal.AssessRemovals(proposal.RemovalInput{
		Proposed:   names(10),
		OwnedCount: 1000,
		MaxPerRun:  100,
		MaxPerDay:  10,
		Today:      proposal.DayLedger{Known: true, Removals: 6},
	})
	if d.Held {
		t.Fatalf("a rationed run was held; a spent budget is not an abnormality")
	}
	if len(d.Removals) != 4 {
		t.Errorf("removals = %d, want 4 — six of today's ten were already used", len(d.Removals))
	}
	if len(d.Deferred) != 6 {
		t.Errorf("deferred = %d, want 6", len(d.Deferred))
	}
}
