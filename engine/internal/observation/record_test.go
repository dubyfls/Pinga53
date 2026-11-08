// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"testing"
	"time"
)

var recordAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// rec builds a valid observation for the record tests.
func rec(t *testing.T, value, source, record string) Observation {
	t.Helper()
	o, err := New(TypeDomain, value, source, recordAt)
	if err != nil {
		t.Fatalf("New(%q, %q): %v", value, source, err)
	}
	o.SourceRecordID = record
	o.Classification = ClassMalicious
	o.State = StateActive
	o.Status = StatusCurrent
	return o
}

// liveCount is how many entries are current across the whole store.
func liveCount(s *Store) int {
	n := 0
	for _, ind := range s.Indicators() {
		n += len(ind.Current(recordAt))
	}
	return n
}

// mustAdd adds and fails on error, returning the outcome.
func mustAdd(t *testing.T, s *Store, o Observation) Outcome {
	t.Helper()
	out, err := s.Add(o)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return out
}

// TestCorrectionWithinOneIndicator is the SAME-KEY regression.
//
// This is the behaviour the superseded implementation already had, and it must
// survive the change of scope. Recorded honestly: it does NOT discriminate
// between the two implementations.
func TestCorrectionWithinOneIndicator(t *testing.T) {
	s := NewStore()
	if got := mustAdd(t, s, rec(t, "same.example.com", "src-A", "rec-1")); got != OutcomeNew {
		t.Fatalf("first add: %v, want %v", got, OutcomeNew)
	}

	// Same record, same indicator, different content.
	corrected := rec(t, "same.example.com", "src-A", "rec-1")
	corrected.Classification = ClassBenign
	if got := mustAdd(t, s, corrected); got != OutcomeCorrection {
		t.Fatalf("correction: %v, want %v", got, OutcomeCorrection)
	}

	ind, ok := s.Lookup(Key{Type: TypeDomain, Canonical: "same.example.com"})
	if !ok {
		t.Fatal("the indicator is gone")
	}
	if len(ind.History()) != 2 {
		t.Errorf("history holds %d entries, want 2", len(ind.History()))
	}
	cur := ind.Current(recordAt)
	if len(cur) != 1 {
		t.Fatalf("%d current entries, want 1", len(cur))
	}
	if cur[0].Observation.Classification != ClassBenign {
		t.Errorf("current classification is %q, want the correction", cur[0].Observation.Classification)
	}
	if cur[0].Revision != 1 {
		t.Errorf("the correction is revision %d, want 1", cur[0].Revision)
	}

	// Re-adding the identical record must change nothing.
	if got := mustAdd(t, s, corrected); got != OutcomeDuplicate {
		t.Errorf("re-adding the same record: %v, want %v", got, OutcomeDuplicate)
	}
	if len(ind.History()) != 2 {
		t.Errorf("a duplicate grew the history to %d", len(ind.History()))
	}
}

// TestCorrectionAcrossIndicators is the CROSS-KEY regression, and the defect.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// The record index was scoped to the indicator, so a correction that changed
// the record's SUBJECT was not recognised as a correction at all:
//
//	add old.example.com rec-1 -> outcome=new
//	add new.example.com rec-1 -> outcome=new          (want: correction)
//	old.example.com  entries=1 current=1 [rev=0 superseded=false]
//	new.example.com  entries=1 current=1 [rev=0 superseded=false]
//
// The withdrawn subject stayed CURRENT for the rest of the store's life, and
// the provider's single revised statement was counted as two live assertions.
func TestCorrectionAcrossIndicators(t *testing.T) {
	s := NewStore()
	mustAdd(t, s, rec(t, "old.example.com", "src-A", "rec-1"))

	if got := mustAdd(t, s, rec(t, "new.example.com", "src-A", "rec-1")); got != OutcomeCorrection {
		t.Fatalf("a record whose subject changed reported %v, want %v", got, OutcomeCorrection)
	}

	old, ok := s.Lookup(Key{Type: TypeDomain, Canonical: "old.example.com"})
	if !ok {
		t.Fatal("the superseded indicator was deleted; history must be retained")
	}
	if n := len(old.Current(recordAt)); n != 0 {
		t.Errorf("the corrected subject still has %d current entry/entries", n)
	}
	if n := len(old.History()); n != 1 {
		t.Errorf("the corrected subject's history holds %d entries, want 1", n)
	}
	if !old.History()[0].Superseded {
		t.Error("the old entry is not marked superseded")
	}

	fresh, ok := s.Lookup(Key{Type: TypeDomain, Canonical: "new.example.com"})
	if !ok {
		t.Fatal("the corrected-to indicator is missing")
	}
	cur := fresh.Current(recordAt)
	if len(cur) != 1 {
		t.Fatalf("%d current entries on the new subject, want 1", len(cur))
	}
	// The revision continues the record's history rather than restarting it.
	if cur[0].Revision != 1 {
		t.Errorf("the correction is revision %d, want 1: a correction continues "+
			"the record's history rather than starting a new one", cur[0].Revision)
	}
	if got := liveCount(s); got != 1 {
		t.Errorf("%d live entries across the store, want 1: one provider record "+
			"making one revised statement is one live assertion", got)
	}
}

// TestCorrectionChainAcrossThreeIndicators. A record may be corrected more
// than once, and only the newest may be live.
func TestCorrectionChainAcrossThreeIndicators(t *testing.T) {
	s := NewStore()
	mustAdd(t, s, rec(t, "first.example.com", "src-A", "rec-1"))
	mustAdd(t, s, rec(t, "second.example.com", "src-A", "rec-1"))
	if got := mustAdd(t, s, rec(t, "third.example.com", "src-A", "rec-1")); got != OutcomeCorrection {
		t.Fatalf("third revision reported %v, want %v", got, OutcomeCorrection)
	}
	if got := liveCount(s); got != 1 {
		t.Errorf("%d live entries, want 1", got)
	}
	third, _ := s.Lookup(Key{Type: TypeDomain, Canonical: "third.example.com"})
	if cur := third.Current(recordAt); len(cur) != 1 || cur[0].Revision != 2 {
		t.Errorf("the newest revision is %v, want one entry at revision 2", cur)
	}
	// Every earlier subject is retained and superseded.
	for _, gone := range []string{"first.example.com", "second.example.com"} {
		ind, ok := s.Lookup(Key{Type: TypeDomain, Canonical: gone})
		if !ok {
			t.Errorf("%s was deleted rather than superseded", gone)
			continue
		}
		if len(ind.History()) != 1 || !ind.History()[0].Superseded {
			t.Errorf("%s: history=%d, superseded=%v", gone, len(ind.History()), ind.History()[0].Superseded)
		}
	}
}

// TestWithdrawalAcrossIndicators is the WITHDRAWAL regression.
//
// A provider that withdraws a record must take the live assertion with it, and
// the withdrawal must still be attributable afterwards.
func TestWithdrawalAcrossIndicators(t *testing.T) {
	s := NewStore()
	mustAdd(t, s, rec(t, "withdrawn.example.com", "src-A", "rec-1"))
	if got := liveCount(s); got != 1 {
		t.Fatalf("premise: %d live entries before the withdrawal, want 1", got)
	}

	gone := rec(t, "withdrawn.example.com", "src-A", "rec-1")
	gone.Status = StatusWithdrawn
	if got := mustAdd(t, s, gone); got != OutcomeCorrection {
		t.Fatalf("a withdrawal reported %v, want %v", got, OutcomeCorrection)
	}
	if got := liveCount(s); got != 0 {
		t.Errorf("%d live entries after the withdrawal, want 0", got)
	}

	ind, _ := s.Lookup(Key{Type: TypeDomain, Canonical: "withdrawn.example.com"})
	if len(ind.History()) != 2 {
		t.Errorf("the withdrawal did not retain history: %d entries", len(ind.History()))
	}

	// A withdrawal that also moves the subject retires the old subject too.
	s2 := NewStore()
	mustAdd(t, s2, rec(t, "a.example.com", "src-A", "rec-9"))
	moved := rec(t, "b.example.com", "src-A", "rec-9")
	moved.Status = StatusWithdrawn
	mustAdd(t, s2, moved)
	if got := liveCount(s2); got != 0 {
		t.Errorf("%d live entries after a moved withdrawal, want 0", got)
	}
	if a, ok := s2.Lookup(Key{Type: TypeDomain, Canonical: "a.example.com"}); !ok || len(a.History()) != 1 {
		t.Error("the original subject's history was not retained")
	}
}

// TestRecordIdentityIsPerSource. Two providers may use the same record id and
// must not collide.
func TestRecordIdentityIsPerSource(t *testing.T) {
	s := NewStore()
	mustAdd(t, s, rec(t, "shared.example.com", "src-A", "rec-1"))
	if got := mustAdd(t, s, rec(t, "shared.example.com", "src-B", "rec-1")); got != OutcomeNew {
		t.Fatalf("a second source reusing rec-1 reported %v, want %v", got, OutcomeNew)
	}
	if got := liveCount(s); got != 2 {
		t.Errorf("%d live entries, want 2: two sources are two assertions", got)
	}
}

// TestRecordKeyCannotBeForgedAcrossItsFieldBoundary is the COLLISION
// regression.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// The record key was the two fields joined with a NUL:
//
//	SourceID "src-A\x00rec" + SourceRecordID "1"        -> "src-A\x00rec\x001"
//	SourceID "src-A"        + SourceRecordID "rec\x001" -> "src-A\x00rec\x001"
//
// Two different provider records, one key. SourceID is validated only for
// emptiness, so this is reachable, and the effect was that one provider's
// record silently superseded another's.
//
// HONEST NOTE ON DISCRIMINATION. Only the FIRST forgery below actually
// collided under the superseded scheme; it is the one that fails against it,
// with "the second record was treated as a revision of the first
// (correction)". The other two do not discriminate: the superseded key
// appended a trailing NUL on the empty-record-id branch, which happened to
// keep those two pairs apart. They are kept as cover for a boundary the struct
// key removes by construction rather than by a lucky suffix.
func TestRecordKeyCannotBeForgedAcrossItsFieldBoundary(t *testing.T) {
	forgeries := []struct {
		name             string
		sourceA, recordA string
		sourceB, recordB string
	}{
		{"a NUL moved across the boundary", "src-A\x00rec", "1", "src-A", "rec\x001"},
		{"the whole key in one field", "src-A\x00rec-1", "", "src-A", "rec-1"},
		{"an empty record id against a NUL-suffixed source", "src-A\x00", "", "src-A", ""},
	}

	// Both records name the SAME indicator. That is what makes the collision
	// reachable: under the superseded indicator-scoped index, two records were
	// only ever compared with each other when they were filed under the same
	// canonical value, so a forgery across two indicators never met its
	// target. Within one indicator it did, and the second record was taken as
	// a revision of the first.
	const shared = "collide.example.com"

	for _, f := range forgeries {
		t.Run(f.name, func(t *testing.T) {
			s := NewStore()
			a := rec(t, shared, f.sourceA, f.recordA)
			b := rec(t, shared, f.sourceB, f.recordB)
			if a.SourceID == b.SourceID && a.SourceRecordID == b.SourceRecordID {
				t.Fatal("the two records are identical; there is nothing to forge")
			}

			if got := mustAdd(t, s, a); got != OutcomeNew {
				t.Fatalf("first add reported %v", got)
			}
			if got := mustAdd(t, s, b); got != OutcomeNew {
				t.Fatalf("the second record was treated as a revision of the "+
					"first (%v); the two keys collided across their field boundary", got)
			}
			if got := liveCount(s); got != 2 {
				t.Errorf("%d live entries, want 2: these are two distinct "+
					"provider records", got)
			}
		})
	}
}

// TestForgedRecordKeysAcrossIndicatorsAreAlsoDistinct.
//
// HONEST NOTE ON DISCRIMINATION: this case does NOT discriminate. Under the
// superseded indicator-scoped index the two records were never compared, so it
// passed there too. It is kept because the scope is now global, which is
// exactly what makes a forged field boundary reachable across indicators — the
// struct key is a precondition of that change, not a repair of a defect that
// was live before it.
func TestForgedRecordKeysAcrossIndicatorsAreAlsoDistinct(t *testing.T) {
	s := NewStore()
	mustAdd(t, s, rec(t, "alpha.example.com", "src-A\x00rec", "1"))
	if got := mustAdd(t, s, rec(t, "beta.example.com", "src-A", "rec\x001")); got != OutcomeNew {
		t.Fatalf("a forged boundary superseded an unrelated record: %v", got)
	}
	if got := liveCount(s); got != 2 {
		t.Errorf("%d live entries, want 2", got)
	}
}

// TestObservationsWithNoRecordIDStayIndicatorScoped is the guard on the other
// side of the scope decision.
//
// Without a record id there is no cross-indicator identity to follow. Indexing
// these globally would make a source that reports twenty domains supersede
// nineteen of its own reports.
func TestObservationsWithNoRecordIDStayIndicatorScoped(t *testing.T) {
	s := NewStore()
	for _, v := range []string{"n1.example.com", "n2.example.com", "n3.example.com"} {
		if got := mustAdd(t, s, rec(t, v, "src-A", "")); got != OutcomeNew {
			t.Fatalf("%s reported %v, want %v", v, got, OutcomeNew)
		}
	}
	if got := liveCount(s); got != 3 {
		t.Errorf("%d live entries, want 3: unidentified records are scoped to "+
			"their own indicator", got)
	}

	// Within ONE indicator, a second unidentified report from the same source
	// is still a correction, not a second opinion.
	again := rec(t, "n1.example.com", "src-A", "")
	again.Classification = ClassBenign
	if got := mustAdd(t, s, again); got != OutcomeCorrection {
		t.Errorf("a re-import from the same source reported %v, want %v", got, OutcomeCorrection)
	}
	if got := liveCount(s); got != 3 {
		t.Errorf("%d live entries after the re-import, want 3", got)
	}
}

// TestIngestionOrderDoesNotChangeTheResult. The correction machinery must not
// make the store order-dependent in what it holds live.
func TestIngestionOrderDoesNotChangeTheResult(t *testing.T) {
	build := func(order []Observation) int {
		s := NewStore()
		for _, o := range order {
			if _, err := s.Add(o); err != nil {
				t.Fatalf("Add: %v", err)
			}
		}
		return liveCount(s)
	}
	a := rec(t, "o1.example.com", "src-A", "rec-1")
	b := rec(t, "o2.example.com", "src-B", "rec-1")
	c := rec(t, "o3.example.com", "src-C", "rec-2")

	if x, y := build([]Observation{a, b, c}), build([]Observation{c, b, a}); x != y {
		t.Errorf("ingestion order changed the live count: %d and %d", x, y)
	}
}
