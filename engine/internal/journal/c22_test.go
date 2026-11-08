// SPDX-License-Identifier: AGPL-3.0-only

package journal_test

import (
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/journal"
)

// C-22 — a journal records what CHANGED, and forgets nothing.
//
// Three rules, and the first two pull in opposite directions, which is why
// they have to be stated together:
//
//   - Journal only on SUBSTANTIVE change. A run that reaches the same
//     conclusion about a host as the last one has nothing new to say, and a
//     journal that appends a revision every run is a log file with a schema:
//     it grows without bound and the one line that matters is invisible in it.
//   - A previously journalled host STAYS journalled. "Nothing changed" must
//     never become "this host is gone" — the whole point of the journal is
//     that a host ScamWall has ever acted on can be found afterwards.
//   - The LAST-BLOCK TIME is kept, because C-21 measures a block's lifetime
//     from when it was last justified and there is nowhere else to read it.

var day0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func at(h int) time.Time { return day0.Add(time.Duration(h) * time.Hour) }

func observedRun(t time.Time, items ...journal.Item) journal.RunInput {
	return journal.RunInput{
		At:             t,
		Observed:       true,
		ObservedDigest: "sha256:whatever-the-appliance-looked-like",
		Items:          items,
	}
}

func item(canonical, substance string, blocked bool) journal.Item {
	return journal.Item{Canonical: canonical, Substance: substance, Blocked: blocked}
}

func mustRecord(tb *testing.T, j *journal.Journal, in journal.RunInput) journal.Result {
	tb.Helper()
	res, err := j.Record(in)
	if err != nil {
		tb.Fatalf("Record: %v", err)
	}
	return res
}

func TestARunThatChangesNothingWritesNothing(t *testing.T) {
	j := journal.New()
	first := mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated/src-a,src-b", true)))
	if first.Appended != 1 {
		t.Fatalf("the first run appended %d revision(s), want 1", first.Appended)
	}

	second := mustRecord(t, j, observedRun(at(1), item("bad.example.com", "propose/corroborated/src-a,src-b", true)))
	if second.Appended != 0 {
		t.Fatalf("an identical second run appended %d revision(s); a journal that appends every run "+
			"is a log file with a schema", second.Appended)
	}
	if n := j.Revisions("bad.example.com"); n != 1 {
		t.Errorf("the host has %d revision(s), want 1", n)
	}
}

func TestASubstantiveChangeIsWritten(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated/src-a,src-b", true)))
	res := mustRecord(t, j, observedRun(at(1), item("bad.example.com", "abstain/withdrawn_only/src-a", false)))
	if res.Appended != 1 {
		t.Fatalf("a run reaching a different conclusion appended %d revision(s), want 1", res.Appended)
	}
	if n := j.Revisions("bad.example.com"); n != 2 {
		t.Errorf("the host has %d revision(s), want 2", n)
	}
}

// TestAHostThatStopsAppearingStaysJournalled is the rule that pulls against
// the first one. A run that no longer mentions a host has said nothing about
// it, and "nothing" is not "gone".
func TestAHostThatStopsAppearingStaysJournalled(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated", true)))
	mustRecord(t, j, observedRun(at(1), item("other.example.com", "propose/corroborated", true)))

	e, ok := j.Entry("bad.example.com")
	if !ok {
		t.Fatalf("a host ScamWall acted on is not in the journal one run later")
	}
	if e.Revisions != 1 {
		t.Errorf("Revisions = %d, want 1; the absent run must not have written anything", e.Revisions)
	}
	if !e.FirstJournalledAt.Equal(at(0)) {
		t.Errorf("FirstJournalledAt = %s, want %s", e.FirstJournalledAt, at(0))
	}
}

func TestTheLastBlockTimeIsKept(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated", true)))
	// Same substance, so nothing is appended — and the block time must still
	// move, or a block re-justified every hour looks a week stale.
	mustRecord(t, j, observedRun(at(5), item("bad.example.com", "propose/corroborated", true)))

	e, _ := j.Entry("bad.example.com")
	if !e.LastBlockAt.Equal(at(5)) {
		t.Fatalf("LastBlockAt = %s, want %s: C-21 measures a lifetime from here", e.LastBlockAt, at(5))
	}
	if e.Revisions != 1 {
		t.Errorf("Revisions = %d, want 1: moving the block time is not a substantive change", e.Revisions)
	}

	// And a run that does NOT block must not move it backwards or forwards.
	mustRecord(t, j, observedRun(at(9), item("bad.example.com", "abstain/withdrawn_only", false)))
	e, _ = j.Entry("bad.example.com")
	if !e.LastBlockAt.Equal(at(5)) {
		t.Errorf("LastBlockAt = %s after a non-blocking run, want %s", e.LastBlockAt, at(5))
	}
}

// TestTheDayLedgerCountsWhatTheRunsDid — C-20 reads this, and C-20's whole
// daily cap is enforcement in name only without it.
func TestTheDayLedgerCountsWhatTheRunsDid(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("a.example.com", "s", true), item("b.example.com", "s", true)))
	mustRecord(t, j, observedRun(at(2), item("c.example.com", "s", true)))
	// The next day.
	mustRecord(t, j, observedRun(at(30), item("d.example.com", "s", true)))

	l := j.Day(at(3))
	if !l.Known {
		t.Fatalf("a ledger read from the journal reports itself unknown; C-20 would then treat the " +
			"day as empty, which is the trap that control names")
	}
	if l.Additions != 3 {
		t.Errorf("Additions() = %d, want 3", l.Additions)
	}
	if next := j.Day(at(30)); next.Additions != 1 {
		t.Errorf("the following day counted %d, want 1", next.Additions)
	}
}

func TestAnEmptyJournalStillKnowsTheDayIsEmpty(t *testing.T) {
	// "No journal" and "a journal that says nothing happened" are different
	// facts, and C-20 acts differently on them.
	l := journal.New().Day(at(0))
	if !l.Known {
		t.Fatalf("an empty journal reports the day as unknown")
	}
	if l.Additions != 0 {
		t.Errorf("Additions() = %d, want 0", l.Additions)
	}
}

func TestTheJournalRoundTripsThroughItsOwnFormat(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated", true)))
	mustRecord(t, j, observedRun(at(4), item("bad.example.com", "abstain/withdrawn_only", false)))

	b, err := j.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := journal.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	e, ok := back.Entry("bad.example.com")
	if !ok {
		t.Fatalf("the host did not survive the round trip")
	}
	if e.Revisions != 2 || !e.LastBlockAt.Equal(at(0)) || !e.FirstJournalledAt.Equal(at(0)) {
		t.Errorf("entry came back as %+v", e)
	}

	// Byte-identical, so a journal committed to a repository diffs as the
	// change it records rather than as a reordering.
	again, err := back.Marshal()
	if err != nil {
		t.Fatalf("Marshal (second): %v", err)
	}
	if string(again) != string(b) {
		t.Errorf("two marshals of one journal differ:\n%s\n%s", b, again)
	}
}
