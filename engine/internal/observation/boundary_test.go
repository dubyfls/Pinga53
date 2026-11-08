// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

var boundaryAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// sound builds an observation that Validate accepts, so that each test below
// changes exactly one thing.
func sound(t *testing.T, value string) Observation {
	t.Helper()
	o, err := New(TypeDomain, value, "src-A", boundaryAt)
	if err != nil {
		t.Fatalf("New(%q): %v", value, err)
	}
	o.Classification = ClassMalicious
	o.State = StateActive
	o.Status = StatusCurrent
	if err := o.Validate(); err != nil {
		t.Fatalf("the unmutated observation is already invalid: %v", err)
	}
	return o
}

// TestCanonicalMustBeDerivedFromWhatWasObserved is the trust boundary.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// Observation's fields are exported and Validate checked only that Canonical
// was non-empty, so "construct it with New" was advice rather than a boundary.
// Demonstrated against it, verbatim:
//
//	after New:        observed="innocent.example.com" canonical="innocent.example.com"
//	after tampering:  observed="innocent.example.com" canonical="bank.example.com"
//	Validate() = <nil>
//	Store.Add -> outcome=new   filed under: bank.example.com
//
// Canonical is the INDICATOR IDENTITY: what gets proposed for blocking, what
// corroboration counts against, what a report names. A caller could set it to
// any domain at all and the trusted store accepted it.
func TestCanonicalMustBeDerivedFromWhatWasObserved(t *testing.T) {
	o := sound(t, "innocent.example.com")
	o.Canonical = "bank.example.com"

	err := o.Validate()
	if err == nil {
		t.Fatal("an asserted canonical value was accepted")
	}
	if !errors.Is(err, ErrInvalidField) {
		t.Errorf("refused, but not as an invalid field: %v", err)
	}
	if !strings.Contains(err.Error(), "canonical does not match") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// And the store must not file it.
	s := NewStore()
	if _, addErr := s.Add(o); addErr == nil {
		t.Fatal("the store accepted an observation with an asserted canonical value")
	}
	if s.Len() != 0 {
		t.Errorf("the store holds %d indicator(s) after refusing the record", s.Len())
	}
	if _, ok := s.Lookup(Key{Type: TypeDomain, Canonical: "bank.example.com"}); ok {
		t.Error("the attacker's canonical value reached the store")
	}
}

// TestSignalsMustBeDerivedToo. Signals are the evidence for a risk decision.
// An asserted set can hide evidence or invent it.
func TestSignalsMustBeDerivedToo(t *testing.T) {
	// A value that genuinely carries a signal: a zero-width space that
	// canonicalisation deletes.
	o, err := New(TypeDomain, "ex\u200bample.com", "src-A", boundaryAt)
	if err != nil {
		t.Skipf("the signal-bearing fixture does not canonicalise here: %v", err)
	}
	o.Classification = ClassMalicious
	o.State = StateActive
	o.Status = StatusCurrent
	if len(o.Signals) == 0 {
		t.Skip("this build derives no signal from the fixture; nothing to suppress")
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("the unmutated signal-bearing observation is invalid: %v", err)
	}

	// Suppressing the evidence must be refused.
	suppressed := o.clone()
	suppressed.Signals = nil
	if err := suppressed.Validate(); err == nil {
		t.Error("an observation with its derived signals stripped was accepted")
	}

	// Inventing evidence must be refused too.
	invented := o.clone()
	invented.Signals = append(append([]domain.Signal(nil), o.Signals...), o.Signals[0])
	if err := invented.Validate(); err == nil {
		t.Error("an observation with an invented extra signal was accepted")
	}
}

// TestProviderConfidenceMustBeFinite.
//
// NaN compares false against everything including itself, so a threshold
// written either way silently excludes it, and both readings look deliberate.
func TestProviderConfidenceMustBeFinite(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		o := sound(t, "finite.example.com")
		o.ProviderConfidence = &ProviderConfidence{Scale: "s:0_100", Value: v}
		if err := o.Validate(); err == nil {
			t.Errorf("a confidence of %v was accepted", v)
		}
	}
	// A finite value on a named scale is still fine.
	o := sound(t, "finite.example.com")
	o.ProviderConfidence = &ProviderConfidence{Scale: "s:0_100", Value: 87.5}
	if err := o.Validate(); err != nil {
		t.Errorf("a finite confidence was refused: %v", err)
	}
}

// TestProviderControlledFieldsAreBounded.
//
// Before this pass only ObservedValue and ProviderClassification were bounded.
// Every case below was ACCEPTED by the superseded Validate.
func TestProviderControlledFieldsAreBounded(t *testing.T) {
	huge := strings.Repeat("Z", 200_000)

	tests := []struct {
		name string
		mut  func(*Observation)
	}{
		{"category", func(o *Observation) { o.Category = huge }},
		{"raw", func(o *Observation) { o.RawRetention = RetentionRetained; o.Raw = huge }},
		{"source_id", func(o *Observation) { o.SourceID = huge }},
		{"source_record_id", func(o *Observation) { o.SourceRecordID = huge }},
		{"confidence scale", func(o *Observation) {
			o.ProviderConfidence = &ProviderConfidence{Scale: huge, Value: 1}
		}},
		{"reference count", func(o *Observation) { o.References = make([]Reference, 100_000) }},
		{"reference url", func(o *Observation) { o.References = []Reference{{URL: huge}} }},
		{"reference note", func(o *Observation) { o.References = []Reference{{URL: "u", Note: huge}} }},
		{"signal count", func(o *Observation) { o.Signals = make([]domain.Signal, 1000) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := sound(t, "bounded.example.com")
			tc.mut(&o)
			if err := o.Validate(); err == nil {
				t.Error("an unbounded provider-controlled field was accepted")
			}
		})
	}
}

// TestImpossibleTimestampsAreRefused.
//
// Only relationships that cannot hold on ANY clock are here. Nothing compares
// a provider's timestamps with IngestedAt: that difference is ordinary skew
// between two machines, and refusing it would discard good evidence for a
// reason that has nothing to do with the evidence.
func TestImpossibleTimestampsAreRefused(t *testing.T) {
	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var zero time.Time

	tests := []struct {
		name string
		mut  func(*Observation)
	}{
		// Does NOT discriminate: the superseded Validate already refused this
		// one. Kept as cover that the existing check survived the rewrite.
		{"first_seen after last_seen", func(o *Observation) {
			o.SourceFirstSeen, o.SourceLastSeen = &late, &early
		}},
		{"expires before first_seen", func(o *Observation) {
			o.SourceFirstSeen, o.ExpiresAt = &late, &early
		}},
		{"first_seen present but zero", func(o *Observation) { o.SourceFirstSeen = &zero }},
		{"last_seen present but zero", func(o *Observation) { o.SourceLastSeen = &zero }},
		{"expires_at present but zero", func(o *Observation) { o.ExpiresAt = &zero }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := sound(t, "times.example.com")
			tc.mut(&o)
			err := o.Validate()
			if err == nil {
				t.Fatal("an impossible timestamp relationship was accepted")
			}
			if !errors.Is(err, ErrImpossibleTimes) {
				t.Errorf("refused, but not as impossible times: %v", err)
			}
		})
	}

	// NEGATIVE CONTROL: an ordinary, possible window must still be accepted,
	// including a provider window that straddles ingestion.
	t.Run("a possible window is accepted", func(t *testing.T) {
		o := sound(t, "times.example.com")
		o.SourceFirstSeen, o.SourceLastSeen = &early, &late
		exp := late.Add(24 * time.Hour)
		o.ExpiresAt = &exp
		if err := o.Validate(); err != nil {
			t.Errorf("a possible window was refused: %v", err)
		}
	})
}

// TestDigestCannotBeForgedAcrossAFieldBoundary is the ADVERSARIAL DELIMITER
// COLLISION test.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// observationDigest wrote key \x1f value \x1e, joined references with \x1d
// and \x1c, joined the confidence scale to its value with "=", and wrote the
// sentinel "\x00absent" into the same slot a real value uses. Every one of
// those delimiters appears inside a field the PROVIDER controls. Demonstrated:
//
//	A: References = [{URL: "u\x1dn", Note: ""}]
//	B: References = [{URL: "u",      Note: "n\x1d"}]
//	digest A == digest B: true
//
// Two different reference sets, one digest. A digest whose boundaries can be
// moved by its own input is not an identity.
//
// HONEST NOTE ON DISCRIMINATION. Only the FIRST case below actually collides
// under the superseded encoding, and it is the only one that fails against it.
// The others do not discriminate: rebalancing content across a key/value
// boundary changes the total length of the encoding, so the two forms differ
// anyway, and a collision needs two ADJACENT variable-length fields to trade
// bytes — which the url/note pair inside one reference is, and the rest are
// not. They are kept as cover for boundaries the length prefix removes by
// construction rather than by an accident of layout.
func TestDigestCannotBeForgedAcrossAFieldBoundary(t *testing.T) {
	scale := 1.0
	tests := []struct {
		name string
		a, b func(*Observation)
	}{
		{
			name: "a reference separator moved between url and note",
			a:    func(o *Observation) { o.References = []Reference{{URL: "u\x1dn", Note: ""}} },
			b:    func(o *Observation) { o.References = []Reference{{URL: "u", Note: "n\x1d"}} },
		},
		{
			name: "a reference list separator inside one url",
			a:    func(o *Observation) { o.References = []Reference{{URL: "a\x1cb"}} },
			b:    func(o *Observation) { o.References = []Reference{{URL: "a"}, {URL: "b"}} },
		},
		{
			name: "a unit separator inside a category",
			a:    func(o *Observation) { o.Category = "c\x1fstatus\x1ewithdrawn" },
			b:    func(o *Observation) { o.Category = "c" },
		},
		{
			name: "a record separator inside provider_classification",
			a:    func(o *Observation) { o.ProviderClassification = "p\x1eclassification\x1fbenign" },
			b:    func(o *Observation) { o.ProviderClassification = "p" },
		},
		{
			name: "an equals sign inside a confidence scale",
			a: func(o *Observation) {
				o.ProviderConfidence = &ProviderConfidence{Scale: "s=1", Value: scale}
			},
			b: func(o *Observation) {
				o.ProviderConfidence = &ProviderConfidence{Scale: "s", Value: scale}
			},
		},
		{
			name: "the absent sentinel written as a real value",
			a:    func(o *Observation) { o.ProviderConfidence = &ProviderConfidence{Scale: "\x00absent", Value: 0} },
			b:    func(o *Observation) { o.ProviderConfidence = nil },
		},
		{
			name: "a signal separator inside a category",
			a:    func(o *Observation) { o.Category = "x,y" },
			b:    func(o *Observation) { o.Category = "x" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := sound(t, "digest.example.com")
			b := sound(t, "digest.example.com")
			tc.a(&a)
			tc.b(&b)
			if observationDigest(a) == observationDigest(b) {
				t.Error("two observations with different contents share a digest; " +
					"a field boundary was forged from inside the input")
			}
		})
	}
}

// TestStoreDigestCannotBeForged applies the same question one level up.
//
// HONEST NOTE ON DISCRIMINATION. The forgery here does NOT collide under the
// superseded encoding either; what fails against it is the version assertion,
// because that encoding labelled itself v1. That is the honest finding: the
// store-level digest was not shown to be forgeable, and the label is what
// keeps a v1 value from being compared with a v2 one as though the data had
// changed.
func TestStoreDigestCannotBeForged(t *testing.T) {
	build := func(mut func(*Observation)) string {
		o := sound(t, "store-digest.example.com")
		mut(&o)
		s := NewStore()
		if _, err := s.Add(o); err != nil {
			t.Fatalf("Add: %v", err)
		}
		return s.Digest()
	}
	a := build(func(o *Observation) { o.Category = "c\x1fcanonical\x1fevil.example.com" })
	b := build(func(o *Observation) { o.Category = "c" })
	if a == b {
		t.Error("two stores with different contents share a digest")
	}
	if !strings.HasPrefix(a, "scamwall-observations-v2:") {
		t.Errorf("the store digest is not labelled with its encoding version: %.40s", a)
	}
}

// TestDigestIsStableForEqualContent is the NEGATIVE CONTROL.
//
// A digest function that returned a fresh value every call would pass every
// collision test above and be useless.
func TestDigestIsStableForEqualContent(t *testing.T) {
	a := sound(t, "stable.example.com")
	b := sound(t, "stable.example.com")
	a.References = []Reference{{URL: "u2", Note: "n"}, {URL: "u1", Note: "m"}}
	b.References = []Reference{{URL: "u1", Note: "m"}, {URL: "u2", Note: "n"}}
	if observationDigest(a) != observationDigest(b) {
		t.Error("the same references in a different order produced different digests")
	}
	// Repeatability across many calls, not two. The interesting failure is a
	// map iteration order leaking into the encoding, which shows up as an
	// occasional difference rather than a reliable one — so the check is a
	// run of calls compared against the first, and comparing two calls
	// directly would be both a tautology and a weaker test.
	first := observationDigest(a)
	for i := 0; i < 64; i++ {
		if got := observationDigest(a); got != first {
			t.Fatalf("the digest changed on call %d: %s then %s", i, first, got)
		}
	}
}
