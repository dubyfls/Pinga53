// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// TestAnInvisibleCharacterDoesNotReachAProposal is the policy half of the
// FINDING-82 regression, and it is deliberately written against the real path:
// domain.Assess produces the signals, and Decide consumes them, exactly as
// internal/feed wires them together.
//
// Each input canonicalises to "example.com" — a legitimate domain — and every
// one of them previously reached DispositionPropose with ReasonEligible.
func TestAnInvisibleCharacterDoesNotReachAProposal(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"soft hyphen", "ex\u00adample.com"},
		{"zero width space", "ex\u200bample.com"},
		{"word joiner", "ex\u2060ample.com"},
		{"variation selector", "ex\ufe0fample.com"},
		{"byte order mark", "ex\ufeffample.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := domain.Assess(tc.raw)
			if err != nil {
				t.Fatalf("Assess(%q) = %v; the input is valid and the premise of this test is that it is", tc.raw, err)
			}
			if a.Domain != "example.com" {
				t.Fatalf("canonical form is %q, want example.com; this fixture no longer collapses onto the legitimate name", a.Domain)
			}
			d, reason := Decide(feed.Indicator{
				Domain:     a.Domain,
				Action:     feed.ActionBlock,
				Confidence: feed.ConfidenceHigh,
				Signals:    a.Signals(),
			})
			if d != DispositionReview {
				t.Errorf("%q canonicalised to %s and got %s (%s); a name whose written form was silently altered must be seen by a human before it is proposed",
					tc.raw, a.Domain, d, reason)
			}
			if reason != ReasonInvisibleCharacter {
				t.Errorf("reason = %q, want %q", reason, ReasonInvisibleCharacter)
			}
		})
	}
}

// TestAnInvisibleCharacterIsReviewedAndNotExcluded keeps the correction from
// overshooting in the other direction. Excluding on a signal silently
// withdraws protection from an entry the publisher was confident about, which
// is the same mistake as proposing on one.
func TestAnInvisibleCharacterIsReviewedAndNotExcluded(t *testing.T) {
	a, err := domain.Assess("ex\u200bample.com")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := Decide(feed.Indicator{
		Domain: a.Domain, Action: feed.ActionBlock,
		Confidence: feed.ConfidenceHigh, Signals: a.Signals(),
	})
	if d == DispositionExclude {
		t.Error("an invisible character excluded the entry; a signal is not evidence in either direction")
	}
}

// TestTheFeedsOwnTermsStillComeFirst pins the documented precedence. An allow
// record or a low-confidence record is excluded on the feed's own say-so,
// before any property of the name is consulted.
func TestTheFeedsOwnTermsStillComeFirst(t *testing.T) {
	a, err := domain.Assess("ex\u200bample.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ind  feed.Indicator
		want Reason
	}{
		{feed.Indicator{Domain: a.Domain, Action: feed.ActionAllow, Confidence: feed.ConfidenceHigh, Signals: a.Signals()}, ReasonNotBlockAction},
		{feed.Indicator{Domain: a.Domain, Action: feed.ActionBlock, Confidence: feed.ConfidenceLow, Signals: a.Signals()}, ReasonBelowConfidence},
	} {
		d, reason := Decide(tc.ind)
		if d != DispositionExclude || reason != tc.want {
			t.Errorf("got %s (%s), want exclude (%s)", d, reason, tc.want)
		}
	}
}

// TestBothNameSignalsReportADeterministicReason fixes the precedence between
// the two review signals, so a plan digest does not depend on slice order.
func TestBothNameSignalsReportADeterministicReason(t *testing.T) {
	ind := feed.Indicator{
		Domain: "xn--pple-43d.com", Action: feed.ActionBlock, Confidence: feed.ConfidenceHigh,
		Signals: []domain.Signal{domain.SignalMixedScript, domain.SignalInvisibleCharacter},
	}
	reversed := ind
	reversed.Signals = []domain.Signal{domain.SignalInvisibleCharacter, domain.SignalMixedScript}

	d1, r1 := Decide(ind)
	d2, r2 := Decide(reversed)
	if d1 != d2 || r1 != r2 {
		t.Errorf("the outcome depends on signal order: %s/%s vs %s/%s", d1, r1, d2, r2)
	}
	if r1 != ReasonInvisibleCharacter {
		t.Errorf("reason = %q, want %q by the documented precedence", r1, ReasonInvisibleCharacter)
	}
}
