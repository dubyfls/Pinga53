// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
)

func ptr[T any](v T) *T { return &v }

// mustNew builds a valid observation for tests that are about something else.
func mustNew(t *testing.T, value, sourceID string) Observation {
	t.Helper()
	o, err := New(TypeDomain, value, sourceID, t1)
	if err != nil {
		t.Fatalf("New(%q, %q): %v", value, sourceID, err)
	}
	o.Classification = ClassMalicious
	o.State = StateActive
	return o
}

func TestThreeFailuresAreKeptApart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   Type
		value string
		want  error
	}{
		{"a type nobody defined", Type("wombat"), "example.com", ErrUnknownType},
		{"a real type this build cannot canonicalise", TypeURL, "https://example.com/", ErrUnsupportedType},
		{"a supported type with a malformed value", TypeDomain, "not a domain", ErrInvalidValue},
		{"a supported type with an IP literal", TypeDomain, "192.0.2.1", ErrInvalidValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.typ, tc.value, "src-0001", t1)
			if !errors.Is(err, tc.want) {
				t.Errorf("New(%q, %q) = %v, want %v", tc.typ, tc.value, err, tc.want)
			}
		})
	}
}

// TestAnIPShapedStringIsADifferentFactForEachType is the type-collision case.
// The same characters are refused for two different reasons, and a caller that
// cannot tell the reasons apart will treat an unimplemented type as a
// malformed value.
func TestAnIPShapedStringIsADifferentFactForEachType(t *testing.T) {
	_, asDomain := New(TypeDomain, "192.0.2.1", "src-0001", t1)
	_, asUsername := New(TypeUsername, "192.0.2.1", "src-0001", t1)

	if !errors.Is(asDomain, ErrInvalidValue) {
		t.Errorf("as a domain: %v, want ErrInvalidValue", asDomain)
	}
	if !errors.Is(asUsername, ErrUnsupportedType) {
		t.Errorf("as a username: %v, want ErrUnsupportedType — the value may be a perfectly good username", asUsername)
	}
	if errors.Is(asUsername, ErrInvalidValue) {
		t.Error("an unsupported type was reported as an invalid value; nothing has assessed the value at all")
	}
}

// TestTypeIsPartOfIdentity keeps two claims about different things from
// corroborating each other.
func TestTypeIsPartOfIdentity(t *testing.T) {
	a := mustNew(t, "example.com", "src-0001")
	b := a
	b.Type = TypeUsername
	if a.Key() == b.Key() {
		t.Error("the same string under two types produced one key; a username report would corroborate a domain block")
	}
}

func TestAnObservationWithNoSourceIsRefused(t *testing.T) {
	for _, id := range []string{"", "   ", "\t"} {
		o := mustNew(t, "example.com", "src-0001")
		o.SourceID = id
		if err := o.Validate(); !errors.Is(err, ErrNoSource) {
			t.Errorf("source id %q: %v, want ErrNoSource", id, err)
		}
		s := NewStore()
		if _, err := s.Add(o); err == nil {
			t.Errorf("source id %q entered the store", id)
		}
	}
}

// TestUnknownIsNotZeroAndNotBenign pins the distinction the whole
// classification vocabulary exists for.
func TestUnknownIsNotZeroAndNotBenign(t *testing.T) {
	if ClassUnknown == ClassBenign {
		t.Fatal("unknown and benign are the same value")
	}
	o := mustNew(t, "example.com", "src-0001")
	o.Classification = ""
	if err := o.Validate(); err == nil {
		t.Error("an unset classification was accepted; silence from the author is not the provider saying `unknown`")
	}
	o.Classification = ClassUnknown
	if err := o.Validate(); err != nil {
		t.Errorf("an explicit `unknown` was refused: %v", err)
	}
}

// TestAMissingTimestampDoesNotBecomeTheEpoch is the reason the optional
// timestamps are pointers.
func TestAMissingTimestampDoesNotBecomeTheEpoch(t *testing.T) {
	o := mustNew(t, "example.com", "src-0001")
	if o.SourceFirstSeen != nil || o.SourceLastSeen != nil || o.ExpiresAt != nil {
		t.Fatal("New invented a timestamp nobody supplied")
	}
	dated := o
	dated.SourceFirstSeen = ptr(time.Unix(0, 0).UTC())
	if observationDigest(o) == observationDigest(dated) {
		t.Error("an absent first-seen digests identically to one at the Unix epoch")
	}
}

func TestImpossibleTimestampOrderIsRefused(t *testing.T) {
	o := mustNew(t, "example.com", "src-0001")
	o.SourceFirstSeen = ptr(t2)
	o.SourceLastSeen = ptr(t0)
	if err := o.Validate(); !errors.Is(err, ErrImpossibleTimes) {
		t.Errorf("%v, want ErrImpossibleTimes", err)
	}
}

func TestAReportCountOfNoneIsNotACountOfZero(t *testing.T) {
	absent := mustNew(t, "example.com", "src-0001")
	zero := absent
	zero.ReportCount = ptr(0)
	if observationDigest(absent) == observationDigest(zero) {
		t.Error("`the provider does not publish a count` and `the provider says zero` are the same record")
	}
	negative := absent
	negative.ReportCount = ptr(-1)
	if err := negative.Validate(); err == nil {
		t.Error("a negative report count was accepted")
	}
}

func TestConfidenceRequiresAScale(t *testing.T) {
	o := mustNew(t, "example.com", "src-0001")
	o.ProviderConfidence = &ProviderConfidence{Value: 80}
	if err := o.Validate(); err == nil {
		t.Error("a confidence of 80 on an unnamed scale was accepted; it is not comparable with anything")
	}
	o.ProviderConfidence.Scale = "example-provider:0_to_100"
	if err := o.Validate(); err != nil {
		t.Errorf("a scaled confidence was refused: %v", err)
	}
}

// TestRawContentNeedsARetentionDecision keeps a provider's response from being
// kept by default.
func TestRawContentNeedsARetentionDecision(t *testing.T) {
	o := mustNew(t, "example.com", "src-0001")
	if o.RawRetention != RetentionNone {
		t.Errorf("the default retention is %q; keeping a provider's response must be a decision, not a default", o.RawRetention)
	}
	o.Raw = `{"example":"synthetic provider response"}`
	if err := o.Validate(); !errors.Is(err, ErrRetentionRefused) {
		t.Errorf("%v, want ErrRetentionRefused", err)
	}
	o.RawRetention = RetentionRetained
	if err := o.Validate(); err != nil {
		t.Errorf("an explicitly retained response was refused: %v", err)
	}
}

// TestTheWrittenFormSurvivesCanonicalisation is the provenance half of
// FINDING-82: the signal says something was removed, and the observed value is
// what lets a reviewer see what.
func TestTheWrittenFormSurvivesCanonicalisation(t *testing.T) {
	o, err := New(TypeDomain, "ex\u200bample.com", "src-0001", t1)
	if err != nil {
		t.Fatal(err)
	}
	if o.Canonical != "example.com" {
		t.Fatalf("canonical = %q", o.Canonical)
	}
	if o.ObservedValue != "ex\u200bample.com" {
		t.Errorf("observed value = %q; the evidence for the signal did not survive", o.ObservedValue)
	}
	if len(o.Signals) == 0 {
		t.Error("the signals did not survive onto the observation")
	}
}

func TestTheObservedValueIsBounded(t *testing.T) {
	// A value domain.Assess refuses outright, so this only ever bounds
	// something already refused — but the bound is asserted rather than
	// assumed, because ObservedValue is stored and reported.
	o := mustNew(t, "example.com", "src-0001")
	o.ObservedValue = strings.Repeat("a", maxObservedValue+1)
	if err := o.Validate(); err == nil {
		t.Error("an oversized observed value was accepted")
	}
}

// TestTheDigestCoversEveryVisibleField is the guard that keeps correction
// detection honest. A field added to Observation and not added to
// observationDigest would be invisible to sameContent, so a correction
// changing only that field would be silently swallowed as a duplicate.
func TestTheDigestCoversEveryVisibleField(t *testing.T) {
	base := mustNew(t, "example.com", "src-0001")
	base.SourceRecordID = "rec-1"

	mutations := map[string]func(*Observation){
		"Type":                   func(o *Observation) { o.Type = TypeUsername },
		"Canonical":              func(o *Observation) { o.Canonical = "other.example.com" },
		"ObservedValue":          func(o *Observation) { o.ObservedValue = "EXAMPLE.COM" },
		"Signals":                func(o *Observation) { o.Signals = append(o.Signals, "non_ascii") },
		"SourceID":               func(o *Observation) { o.SourceID = "src-0002" },
		"SourceRecordID":         func(o *Observation) { o.SourceRecordID = "rec-2" },
		"SourceFirstSeen":        func(o *Observation) { o.SourceFirstSeen = ptr(t0) },
		"SourceLastSeen":         func(o *Observation) { o.SourceLastSeen = ptr(t2) },
		"ExpiresAt":              func(o *Observation) { o.ExpiresAt = ptr(t2) },
		"ProviderClassification": func(o *Observation) { o.ProviderClassification = "phish" },
		"Classification":         func(o *Observation) { o.Classification = ClassBenign },
		"ProviderConfidence":     func(o *Observation) { o.ProviderConfidence = &ProviderConfidence{Scale: "s", Value: 1} },
		"ReportCount":            func(o *Observation) { o.ReportCount = ptr(3) },
		"State":                  func(o *Observation) { o.State = StateInactive },
		"Category":               func(o *Observation) { o.Category = "delivery-scam" },
		"Status":                 func(o *Observation) { o.Status = StatusWithdrawn },
		"References":             func(o *Observation) { o.References = []Reference{{URL: "https://example.invalid/r", Note: "n"}} },
		"RawRetention":           func(o *Observation) { o.RawRetention = RetentionRetained },
		"Raw":                    func(o *Observation) { o.RawRetention = RetentionRetained; o.Raw = "{}" },
	}

	want := observationDigest(base)
	for field, mutate := range mutations {
		got := base
		mutate(&got)
		if observationDigest(got) == want {
			t.Errorf("changing %s does not change the digest; a correction to that field would be swallowed as a duplicate", field)
		}
	}

	// Ingestion time is deliberately excluded: it changes on every import and
	// including it would make idempotence impossible.
	later := base
	later.IngestedAt = t2
	if !base.sameContent(later) {
		t.Error("re-importing an unchanged record at a later time is not a duplicate")
	}
}
