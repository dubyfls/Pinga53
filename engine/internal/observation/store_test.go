// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"math/rand"
	"testing"
	"time"
)

// TestReImportingTheSameRecordIsIdempotent is the first of the four ways a
// corroboration count gets inflated: one source, imported twice.
func TestReImportingTheSameRecordIsIdempotent(t *testing.T) {
	s := NewStore()
	o := mustNew(t, "example.com", "src-0001")
	o.SourceRecordID = "rec-1"

	if got, err := s.Add(o); err != nil || got != OutcomeNew {
		t.Fatalf("first add = %q, %v", got, err)
	}
	before := s.Digest()

	later := o
	later.IngestedAt = t2
	if got, err := s.Add(later); err != nil || got != OutcomeDuplicate {
		t.Fatalf("second add = %q, %v; re-importing an unchanged record must change nothing", got, err)
	}
	if s.Digest() != before {
		t.Error("the store changed on a duplicate import")
	}

	ind, _ := s.Lookup(o.Key())
	if n := len(ind.Current(t1)); n != 1 {
		t.Errorf("%d current observations after importing one record twice; one source said one thing", n)
	}
	if got := ind.Corroborate(nil, t1); got.SupportingCount() != 1 {
		t.Errorf("supporting count = %d, want 1", got.SupportingCount())
	}
}

// TestARecordWithNoProviderIDIsStillOneVoice covers the same inflation when
// the provider publishes no record id of its own.
func TestARecordWithNoProviderIDIsStillOneVoice(t *testing.T) {
	s := NewStore()
	o := mustNew(t, "example.com", "src-0001")
	o.Category = "delivery-scam"
	if _, err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	again := o
	again.Category = "invoice-scam" // a different claim from the same source
	if got, _ := s.Add(again); got != OutcomeCorrection {
		t.Errorf("second import = %q, want a correction; without a record id, one source has one record per indicator", got)
	}
	ind, _ := s.Lookup(o.Key())
	if n := len(ind.Current(t1)); n != 1 {
		t.Errorf("%d current observations; a re-import from one source is not a second opinion", n)
	}
}

// TestACorrectionSupersedesWithoutErasing is the withdrawal/correction rule.
func TestACorrectionSupersedesWithoutErasing(t *testing.T) {
	s := NewStore()
	first := mustNew(t, "example.com", "src-0001")
	first.SourceRecordID = "rec-1"
	first.ProviderClassification = "phishing"
	if _, err := s.Add(first); err != nil {
		t.Fatal(err)
	}

	corrected := first
	corrected.Classification = ClassBenign
	corrected.ProviderClassification = "false positive, withdrawn"
	corrected.IngestedAt = t2
	if got, err := s.Add(corrected); err != nil || got != OutcomeCorrection {
		t.Fatalf("correction = %q, %v", got, err)
	}

	ind, _ := s.Lookup(first.Key())
	current := ind.Current(t2)
	if len(current) != 1 || current[0].Observation.Classification != ClassBenign {
		t.Fatalf("current = %+v; the correction did not take effect", current)
	}
	sup := ind.Superseded()
	if len(sup) != 1 || sup[0].Observation.ProviderClassification != "phishing" {
		t.Errorf("superseded = %+v; the original claim was erased rather than retained", sup)
	}
	if len(ind.History()) != 2 {
		t.Errorf("history holds %d entries, want 2", len(ind.History()))
	}
}

// TestACorrectionDoesNotTouchAnotherSource pins the blast radius.
func TestACorrectionDoesNotTouchAnotherSource(t *testing.T) {
	s := NewStore()
	a := mustNew(t, "example.com", "src-0001")
	a.SourceRecordID = "rec-1"
	b := mustNew(t, "example.com", "src-0002")
	b.SourceRecordID = "rec-9"
	if _, err := s.Add(a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(b); err != nil {
		t.Fatal(err)
	}

	correction := a
	correction.Classification = ClassBenign
	if _, err := s.Add(correction); err != nil {
		t.Fatal(err)
	}

	ind, _ := s.Lookup(a.Key())
	for _, e := range ind.Current(t1) {
		if e.Observation.SourceID == "src-0002" && e.Observation.Classification != ClassMalicious {
			t.Error("correcting src-0001 rewrote src-0002's observation")
		}
	}
	if n := len(ind.Current(t1)); n != 2 {
		t.Errorf("%d current observations, want 2", n)
	}
}

// TestConflictingClassificationsAreRetained refuses to pick a winner.
func TestConflictingClassificationsAreRetained(t *testing.T) {
	s := NewStore()
	bad := mustNew(t, "example.com", "src-0001")
	good := mustNew(t, "example.com", "src-0002")
	good.Classification = ClassBenign
	for _, o := range []Observation{bad, good} {
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}

	ind, _ := s.Lookup(bad.Key())
	byClass := ind.Classifications(t1)
	if len(byClass[ClassMalicious]) != 1 || len(byClass[ClassBenign]) != 1 {
		t.Errorf("classifications = %+v; a disagreement was resolved instead of reported", byClass)
	}
	if !ind.Conflicted(t1) {
		t.Error("the disagreement was not reported as one")
	}
}

// TestUnknownDoesNotContradictAnAssertion keeps abstention from reading as
// disagreement.
func TestUnknownDoesNotContradictAnAssertion(t *testing.T) {
	s := NewStore()
	bad := mustNew(t, "example.com", "src-0001")
	silent := mustNew(t, "example.com", "src-0002")
	silent.Classification = ClassUnknown
	for _, o := range []Observation{bad, silent} {
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	ind, _ := s.Lookup(bad.Key())
	if ind.Conflicted(t1) {
		t.Error("a source that declined to classify was counted as disputing one that did")
	}
}

// TestExpiredEvidenceLeavesTheLiveSetAndStaysInHistory is the expiry rule in
// both directions at once.
func TestExpiredEvidenceLeavesTheLiveSetAndStaysInHistory(t *testing.T) {
	s := NewStore()
	o := mustNew(t, "example.com", "src-0001")
	o.ExpiresAt = ptr(t1)
	if _, err := s.Add(o); err != nil {
		t.Fatal(err)
	}

	ind, _ := s.Lookup(o.Key())
	if n := len(ind.Current(t0)); n != 1 {
		t.Errorf("before expiry: %d current, want 1", n)
	}
	if n := len(ind.Current(t2)); n != 0 {
		t.Errorf("after expiry: %d current, want 0; a lapsed source must not keep an indicator live", n)
	}
	if n := len(ind.History()); n != 1 {
		t.Errorf("after expiry: %d in history, want 1; lapsed evidence is still evidence that it was said", n)
	}
	if n := len(ind.Expired(t2)); n != 1 {
		t.Errorf("Expired reported %d, want 1", n)
	}
}

// TestOneStaleSourceDoesNotKeepAnIndicatorAlive is the specific case the order
// names: an indicator whose only support has lapsed.
func TestOneStaleSourceDoesNotKeepAnIndicatorAlive(t *testing.T) {
	s := NewStore()
	stale := mustNew(t, "example.com", "src-0001")
	stale.ExpiresAt = ptr(t1)
	if _, err := s.Add(stale); err != nil {
		t.Fatal(err)
	}
	ind, _ := s.Lookup(stale.Key())
	c := ind.Corroborate(nil, t2)
	if c.SupportingCount() != 0 {
		t.Errorf("supporting count = %d at a time when every observation has lapsed", c.SupportingCount())
	}
	if len(c.ExpiredOnly) != 1 {
		t.Errorf("expired-only = %v, want one entry naming the lapsed source", c.ExpiredOnly)
	}
}

// TestAWithdrawnObservationIsRetainedAndNotCounted separates withdrawal from
// expiry, which are different facts about the source.
func TestAWithdrawnObservationIsRetainedAndNotCounted(t *testing.T) {
	s := NewStore()
	o := mustNew(t, "example.com", "src-0001")
	o.SourceRecordID = "rec-1"
	if _, err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	w := o
	w.Status = StatusWithdrawn
	if got, _ := s.Add(w); got != OutcomeCorrection {
		t.Fatalf("withdrawal = %q, want a correction", got)
	}

	ind, _ := s.Lookup(o.Key())
	if n := len(ind.Current(t1)); n != 0 {
		t.Errorf("%d current observations after a withdrawal", n)
	}
	if n := len(ind.History()); n != 2 {
		t.Errorf("history holds %d, want 2; a withdrawal must not erase that the claim was made", n)
	}
	c := ind.Corroborate(nil, t1)
	if len(c.Withdrawn) != 1 {
		t.Errorf("withdrawn = %v", c.Withdrawn)
	}
	if c.SupportingCount() != 0 {
		t.Errorf("supporting count = %d after the only source withdrew", c.SupportingCount())
	}
}

// TestOrderingIsDeterministicUnderShuffledInput is the property the plan
// digest and every report depend on.
func TestOrderingIsDeterministicUnderShuffledInput(t *testing.T) {
	build := func(seed int64) string {
		obs := []Observation{}
		for _, spec := range []struct{ value, source, record string }{
			{"example.com", "src-0001", "a"},
			{"example.com", "src-0002", "b"},
			{"example.com", "src-0001", "c"},
			{"other.example.com", "src-0003", ""},
			{"third.example.com", "src-0002", "d"},
			{"other.example.com", "src-0001", "e"},
		} {
			o := mustNew(t, spec.value, spec.source)
			o.SourceRecordID = spec.record
			obs = append(obs, o)
		}
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(obs), func(i, j int) { obs[i], obs[j] = obs[j], obs[i] })

		s := NewStore()
		for _, o := range obs {
			if _, err := s.Add(o); err != nil {
				t.Fatal(err)
			}
		}
		return s.Digest()
	}

	want := build(1)
	for _, seed := range []int64{2, 3, 5, 8, 13, 21, 34, 55} {
		if got := build(seed); got != want {
			t.Fatalf("seed %d produced digest %s, want %s; ingestion order changed the result", seed, got, want)
		}
	}
}

// TestTheDigestChangesWithContent keeps the determinism test above from being
// satisfied by a constant.
func TestTheDigestChangesWithContent(t *testing.T) {
	a := NewStore()
	if _, err := a.Add(mustNew(t, "example.com", "src-0001")); err != nil {
		t.Fatal(err)
	}
	b := NewStore()
	if _, err := b.Add(mustNew(t, "example.com", "src-0002")); err != nil {
		t.Fatal(err)
	}
	if a.Digest() == b.Digest() {
		t.Error("two stores with different sources share a digest")
	}
}

// TestUnicodeAndPunycodeAreOneIndicator is the canonicalisation-collision case:
// two spellings of one name must not become two independent sources.
func TestUnicodeAndPunycodeAreOneIndicator(t *testing.T) {
	s := NewStore()
	unicodeForm := mustNew(t, "münchen.de", "src-0001")
	aceForm := mustNew(t, "xn--mnchen-3ya.de", "src-0002")
	for _, o := range []Observation{unicodeForm, aceForm} {
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	if s.Len() != 1 {
		t.Fatalf("%d indicators; the two spellings did not collapse", s.Len())
	}
	ind, _ := s.Lookup(unicodeForm.Key())
	if n := len(ind.Current(t1)); n != 2 {
		t.Errorf("%d observations; the collapse lost one source's attribution", n)
	}
	seen := map[string]bool{}
	for _, e := range ind.Current(t1) {
		seen[e.Observation.ObservedValue] = true
	}
	if !seen["münchen.de"] || !seen["xn--mnchen-3ya.de"] {
		t.Errorf("observed values = %v; the written forms did not survive deduplication", seen)
	}
}

// TestOneSourceSpellingItBothWaysIsStillOneVoice is the same collision from
// the inflation side.
func TestOneSourceSpellingItBothWaysIsStillOneVoice(t *testing.T) {
	s := NewStore()
	a := mustNew(t, "münchen.de", "src-0001")
	b := mustNew(t, "xn--mnchen-3ya.de", "src-0001")
	for _, o := range []Observation{a, b} {
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	ind, _ := s.Lookup(a.Key())
	if n := len(ind.Current(t1)); n != 1 {
		t.Errorf("%d current observations; one source writing a name two ways became two voices", n)
	}
	if c := ind.Corroborate(nil, t1); c.SupportingCount() != 1 {
		t.Errorf("supporting count = %d, want 1", c.SupportingCount())
	}
}

// TestAddingManyObservationsStaysBounded checks the store does not degrade or
// lose entries at the sizes a feed can reach.
func TestAddingManyObservationsStaysBounded(t *testing.T) {
	s := NewStore()
	const n = 2000
	for i := 0; i < n; i++ {
		o := mustNew(t, "d"+itoa(i)+".example.com", "src-0001")
		if _, err := s.Add(o); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if s.Len() != n {
		t.Errorf("%d indicators, want %d", s.Len(), n)
	}
	first := s.Digest()
	if second := s.Digest(); first != second {
		t.Error("the digest is not stable across two calls")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

var _ = time.Now
