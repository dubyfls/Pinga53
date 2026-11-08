// SPDX-License-Identifier: AGPL-3.0-only

package journal_test

import (
	"errors"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/journal"
)

// C-23 — a run that did not read the appliance may not journal what it would
// have changed there.
//
// The principle is already this tree's: `shadow` refuses to state a plan it
// did not read the appliance for, and the crosswalk notes it. What was
// missing is the journal, and the journal is where the principle matters
// most — a plan is read once and thrown away, while a journal entry is what
// every later run compares against. One revision recorded without state
// behind it silently becomes the baseline that decides whether the NEXT run
// changed anything.

func unobservedRun(items ...journal.Item) journal.RunInput {
	return journal.RunInput{At: at(0), Observed: false, Items: items}
}

func TestARunWithNoObservedStateIsRefused(t *testing.T) {
	j := journal.New()
	res, err := j.Record(unobservedRun(item("bad.example.com", "propose/corroborated", true)))
	if err == nil {
		t.Fatalf("a run that read nothing was journalled anyway: %+v", res)
	}
	if !errors.Is(err, journal.ErrNoObservedState) {
		t.Errorf("err = %v, want %v", err, journal.ErrNoObservedState)
	}
	if _, ok := j.Entry("bad.example.com"); ok {
		t.Errorf("the refused run left an entry behind")
	}
}

// TestObservedWithoutADigestIsAlsoRefused — a revision that cannot say WHAT it
// was looking at is a revision about nothing, and it would pass a check that
// only read the boolean.
func TestObservedWithoutADigestIsAlsoRefused(t *testing.T) {
	j := journal.New()
	in := journal.RunInput{
		At: at(0), Observed: true, ObservedDigest: "",
		Items: []journal.Item{item("bad.example.com", "s", true)},
	}
	if _, err := j.Record(in); !errors.Is(err, journal.ErrNoObservedState) {
		t.Fatalf("err = %v, want %v", err, journal.ErrNoObservedState)
	}
}

// TestTheRefusalIsTotal.
//
// Not "the hosts that needed the appliance are skipped". A journal half
// written under a rule that says it should not have been written at all is
// worse than none: the half that landed becomes the baseline every later run
// compares against, and nothing records that it was never checked.
func TestTheRefusalIsTotal(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("known.example.com", "propose/corroborated", true)))
	before, _ := j.Entry("known.example.com")

	_, err := j.Record(unobservedRun(
		item("known.example.com", "abstain/withdrawn_only", false),
		item("new.example.com", "propose/corroborated", true),
	))
	if err == nil {
		t.Fatalf("the run was accepted")
	}
	after, _ := j.Entry("known.example.com")
	if after.Revisions != before.Revisions || !after.LastSeenAt.Equal(before.LastSeenAt) {
		t.Errorf("the refused run changed an existing entry:\n before %+v\n after  %+v", before, after)
	}
	if _, ok := j.Entry("new.example.com"); ok {
		t.Errorf("the refused run added a host")
	}
}

// TestEveryRevisionSaysWhatItWasLookingAt — the field is what makes the
// refusal checkable afterwards rather than only at the moment of writing.
func TestEveryRevisionSaysWhatItWasLookingAt(t *testing.T) {
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated", true)))
	e, _ := j.Entry("bad.example.com")
	for i, r := range e.History {
		if r.ObservedDigest == "" {
			t.Errorf("revision %d records no observed state", i)
		}
	}
}
