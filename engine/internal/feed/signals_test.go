// SPDX-License-Identifier: AGPL-3.0-only

package feed_test

import (
	"errors"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// TestOneSuspiciousEntryNoLongerDestroysTheFeed is the feed half of SW-P3-05.
//
// A mixed-script name is a syntactically valid domain. When Normalize returned
// an error for it, this validator could not distinguish "one entry looks
// suspicious" from "this file is corrupt", so a single such record rejected the
// whole signed feed — every unrelated indicator in it included. The blast
// radius was the defect, not the caution.
func TestOneSuspiciousEntryNoLongerDestroysTheFeed(t *testing.T) {
	s := newSigner(t)
	records := oneBlockRecord + `,` +
		`{"domain":"аpple.example.com","action":"block","confidence":"high","category":"phishing"},` +
		`{"domain":"other.example.com","action":"block","confidence":"high"}`

	v, err := feed.Validate(s.envelope(payload(records), testKeyID), s.opts())
	if err != nil {
		t.Fatalf("a feed containing a mixed-script name was rejected whole: %v", err)
	}
	if len(v.Indicators) != 3 {
		t.Fatalf("%d indicators survived, want 3", len(v.Indicators))
	}

	var flagged int
	for _, ind := range v.Indicators {
		for _, sig := range ind.Signals {
			if sig == domain.SignalMixedScript {
				flagged++
			}
		}
	}
	if flagged != 1 {
		t.Fatalf("%d indicators carry the mixed-script signal, want exactly 1", flagged)
	}
}

// TestStructuralFailuresStillRejectTheWholeFeed: the contract that a corrupt or
// unauthentic file is refused in its entirety is unchanged. Loosening the
// mixed-script rule must not have loosened this.
func TestStructuralFailuresStillRejectTheWholeFeed(t *testing.T) {
	s := newSigner(t)
	cases := map[string]struct {
		records string
		want    error
	}{
		"a syntactically invalid domain": {
			records: oneBlockRecord + `,{"domain":"not a domain","action":"block","confidence":"high"}`,
			want:    feed.ErrInvalidRecord,
		},
		"an IP literal": {
			records: oneBlockRecord + `,{"domain":"192.0.2.1","action":"block","confidence":"high"}`,
			want:    feed.ErrInvalidRecord,
		},
		"a wildcard": {
			records: oneBlockRecord + `,{"domain":"*.example.com","action":"block","confidence":"high"}`,
			want:    feed.ErrInvalidRecord,
		},
		"a public suffix": {
			records: oneBlockRecord + `,{"domain":"co.uk","action":"block","confidence":"high"}`,
			want:    feed.ErrInvalidRecord,
		},
		"an unknown action": {
			records: `{"domain":"bad.example.com","action":"nuke","confidence":"high"}`,
			want:    feed.ErrInvalidAction,
		},
		"an unknown confidence": {
			records: `{"domain":"bad.example.com","action":"block","confidence":"certain"}`,
			want:    feed.ErrInvalidConfidence,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := feed.Validate(s.envelope(payload(tc.records), testKeyID), s.opts())
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDuplicateDetectionSurvivesTheChange: mixed-script names now reach the
// deduplication step, so two spellings of one such name must collide there
// rather than producing two indicators for the same canonical domain.
func TestDuplicateDetectionSurvivesTheChange(t *testing.T) {
	s := newSigner(t)
	records := `{"domain":"аpple.example.com","action":"block","confidence":"high"},` +
		`{"domain":"АPPLE.example.com","action":"block","confidence":"high"}`
	_, err := feed.Validate(s.envelope(payload(records), testKeyID), s.opts())
	if !errors.Is(err, feed.ErrDuplicateRecord) {
		t.Fatalf("got %v, want ErrDuplicateRecord", err)
	}
}

// TestConflictDetectionSurvivesTheChange: the same, for records that disagree.
func TestConflictDetectionSurvivesTheChange(t *testing.T) {
	s := newSigner(t)
	records := `{"domain":"аpple.example.com","action":"block","confidence":"high"},` +
		`{"domain":"АPPLE.example.com","action":"allow","confidence":"high"}`
	_, err := feed.Validate(s.envelope(payload(records), testKeyID), s.opts())
	if !errors.Is(err, feed.ErrConflictingRecord) {
		t.Fatalf("got %v, want ErrConflictingRecord", err)
	}
}

// TestSignalsAreDeterministicAcrossRuns: the plan digest is computed from these,
// so an ordering that varied between runs would make operator review useless.
func TestSignalsAreDeterministicAcrossRuns(t *testing.T) {
	s := newSigner(t)
	records := `{"domain":"аpple.example.com","action":"block","confidence":"high"},` +
		`{"domain":"пример.example.com","action":"block","confidence":"high"},` +
		`{"domain":"例えテスト.example.com","action":"block","confidence":"high"}`
	env := s.envelope(payload(records), testKeyID)

	first, err := feed.Validate(env, s.opts())
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		again, err := feed.Validate(env, s.opts())
		if err != nil {
			t.Fatal(err)
		}
		for i := range first.Indicators {
			a, b := first.Indicators[i].Signals, again.Indicators[i].Signals
			if len(a) != len(b) {
				t.Fatalf("signal count varies between runs for %s", first.Indicators[i].Domain)
			}
			for j := range a {
				if a[j] != b[j] {
					t.Fatalf("signal order varies between runs for %s: %v vs %v", first.Indicators[i].Domain, a, b)
				}
			}
		}
	}
}

// TestOrdinaryRecordsCarryNoSignals: the common case must stay quiet.
func TestOrdinaryRecordsCarryNoSignals(t *testing.T) {
	s := newSigner(t)
	v, err := feed.Validate(s.envelope(payload(oneBlockRecord), testKeyID), s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Indicators[0].Signals) != 0 {
		t.Fatalf("an ordinary ASCII record carries signals: %v", v.Indicators[0].Signals)
	}
}
