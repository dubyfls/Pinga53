// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// TestTheStoreCannotBeRewrittenThroughARead is the regression for FINDING-85.
//
// Observation is a value type, so assigning it copies the scalars — but its
// slices and pointers are shared, and a caller holding the result of Lookup
// could change a stored source's signals, its evidence references or its
// expiry in place: no revision, no supersession, no trace.
func TestTheStoreCannotBeRewrittenThroughARead(t *testing.T) {
	s := NewStore()
	o := mustNew(t, "münchen.de", "src-0001")
	o.References = []Reference{{URL: "https://example.invalid/report", Note: "synthetic"}}
	o.ExpiresAt = ptr(t2)
	o.ReportCount = ptr(3)
	o.ProviderConfidence = &ProviderConfidence{Scale: "example:0_to_100", Value: 80}
	if _, err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	before := s.Digest()

	ind, _ := s.Lookup(o.Key())
	got := &ind.Entries[0].Observation
	if len(got.Signals) > 0 {
		got.Signals[0] = "tampered"
	}
	got.References[0].URL = "https://tampered.invalid/"
	*got.ExpiresAt = t0
	*got.ReportCount = 9999
	got.ProviderConfidence.Value = 100

	if after := s.Digest(); after != before {
		t.Errorf("a caller rewrote the store through a read\n  before %s\n  after  %s", before, after)
	}

	// And through History, which is the read a caller reaches for precisely
	// when it wants the superseded evidence.
	fresh, _ := s.Lookup(o.Key())
	for _, e := range fresh.History() {
		if len(e.Observation.Signals) > 0 {
			e.Observation.Signals[0] = "tampered-again"
		}
	}
	if after := s.Digest(); after != before {
		t.Error("a caller rewrote the store through History")
	}
}

// TestTheCallersOwnCopyCannotReachIntoTheStore is the same defect from the
// other side: a caller that keeps its slice after Add must not retain a
// handle to what the store now holds.
func TestTheCallersOwnCopyCannotReachIntoTheStore(t *testing.T) {
	s := NewStore()
	o := mustNew(t, "münchen.de", "src-0001")
	o.References = []Reference{{URL: "https://example.invalid/report", Note: "synthetic"}}
	if _, err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	before := s.Digest()

	if len(o.Signals) > 0 {
		o.Signals[0] = "tampered"
	}
	o.References[0].URL = "https://tampered.invalid/"

	if after := s.Digest(); after != before {
		t.Error("the caller's own copy still reached into the store after Add")
	}
}

// TestConcurrentReadsAreSafe checks the claim the Store's documentation makes.
//
// The comment says the store is not safe for concurrent use and that callers
// own the lock. That is a claim about WRITES. Reads under an external read
// lock must genuinely not mutate anything, and a read that cloned lazily or
// sorted in place would break that silently. Run with -race, this fails if it
// does.
func TestConcurrentReadsAreSafe(t *testing.T) {
	s := NewStore()
	for _, id := range []string{"src-0001", "src-0002", "src-0003"} {
		o := mustNew(t, "example.com", id)
		o.SourceRecordID = id + "-r1"
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	want := s.Digest()

	var wg sync.WaitGroup
	var mu sync.RWMutex
	errs := make(chan string, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.RLock()
			defer mu.RUnlock()
			for j := 0; j < 50; j++ {
				if got := s.Digest(); got != want {
					errs <- "digest changed under concurrent reads"
					return
				}
				for _, ind := range s.Indicators() {
					_ = ind.Corroborate(nil, t1)
					_ = ind.Classifications(t1)
					_ = ind.History()
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if s.Digest() != want {
		t.Error("the store changed after read-only concurrent access")
	}
}

// TestHostileValuesAreRefusedRatherThanCarried walks the input classes the
// order names, through the public constructor.
func TestHostileValuesAreRefusedRatherThanCarried(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"deeply nested labels", strings.Repeat("a.", 300) + "example.com"},
		{"one oversized label", strings.Repeat("a", 2000) + ".example.com"},
		{"oversized unicode", strings.Repeat("ü", 2000) + ".example.com"},
		{"invalid utf-8", "exa\xffmple.com"},
		{"a null byte", "exa\x00mple.com"},
		{"a newline", "example.com\nsecond.example.com"},
		{"only dots", strings.Repeat(".", 500)},
		{"empty", ""},
		{"whitespace", "   \t  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := New(TypeDomain, tc.value, "src-0001", t1)
			if err == nil {
				t.Fatalf("accepted %d bytes as %q", len(tc.value), o.Canonical)
			}
			if len(err.Error()) > 256 {
				t.Errorf("the error is %d bytes for a %d-byte input; the message size is chosen by the input", len(err.Error()), len(tc.value))
			}
		})
	}
}

// TestNumericExtremesAreRefusedOrExplicit covers the overflow and impossible
// ordering cases.
func TestNumericExtremesAreRefusedOrExplicit(t *testing.T) {
	maxInt := int(^uint(0) >> 1)

	o := mustNew(t, "example.com", "src-0001")
	o.ReportCount = ptr(maxInt)
	if err := o.Validate(); err != nil {
		t.Errorf("the maximum representable count was refused: %v", err)
	}
	s := NewStore()
	if _, err := s.Add(o); err != nil {
		t.Errorf("the maximum representable count did not enter the store: %v", err)
	}

	o.ReportCount = ptr(-1)
	if err := o.Validate(); err == nil {
		t.Error("a negative count was accepted")
	}

	far := mustNew(t, "example.com", "src-0002")
	far.SourceFirstSeen = ptr(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))
	far.SourceLastSeen = ptr(time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := far.Validate(); err == nil {
		t.Error("first-seen after last-seen was accepted")
	}
}

// TestCorroborationDoesNotPanicOnAMalformedRegistry covers the inputs the
// registry's own validator refuses but which this code must survive.
func TestCorroborationDoesNotPanicOnAMalformedRegistry(t *testing.T) {
	ind := indicatorOf(t, "src-0001", "src-0002")
	selfRef := src("src-0001", sourceregistry.UpstreamDocumentedComplete, []string{"src-0001"}, nil)
	dangling := src("src-0001", sourceregistry.UpstreamDocumentedComplete, []string{"src-nowhere"}, nil)
	unrecognised := src("src-0001", "sometimes", nil, nil)
	plain := src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, nil)

	for _, tc := range []struct {
		name string
		reg  *sourceregistry.Registry
	}{
		{"self-referential lineage", synthReg(t, selfRef, plain)},
		{"an edge to a source that does not exist", synthReg(t, dangling, plain)},
		{"an unrecognised completeness value", synthReg(t, unrecognised, plain)},
		{"a registry with no sources at all", synthReg(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan corroborationResult, 1)
			go func() {
				c := ind.Corroborate(tc.reg, t1)
				done <- corroborationResult{c}
			}()
			select {
			case got := <-done:
				// Whatever it decides, it must never claim more independence
				// than the registry supports, and every exclusion must carry
				// a reason.
				if got.c.IndependentCount() > 2 {
					t.Errorf("independent = %v", got.c.Independent)
				}
				if got.c.IndependentCount() < 2 && len(got.c.Notes) == 0 {
					t.Error("a source was excluded with no reason recorded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Corroborate did not terminate")
			}
		})
	}
}

// corroborationResult carries a Corroboration over a channel, so that a
// Corroborate that never returns is a test failure rather than a hung suite.
type corroborationResult struct{ c Corroboration }
