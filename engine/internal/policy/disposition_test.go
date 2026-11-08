// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/policy"
)

func ind(name string, action feed.Action, conf feed.Confidence, signals ...domain.Signal) feed.Indicator {
	d, err := domain.Normalize(name)
	if err != nil {
		panic("test fixture is not a valid domain: " + name + ": " + err.Error())
	}
	return feed.Indicator{Domain: d, Action: action, Confidence: conf, Signals: signals}
}

// TestDecideSeparatesTheFourQuestions is the acceptance test for SW-P3-05.
//
// Validity, risk signal, evidence and eligibility are four different things.
// The table below asserts each combination lands where the documented policy
// says it does — and, just as importantly, that no combination of Unicode
// signals alone moves an entry anywhere.
func TestDecideSeparatesTheFourQuestions(t *testing.T) {
	cases := []struct {
		name       string
		indicator  feed.Indicator
		wantDisp   policy.Disposition
		wantReason policy.Reason
	}{
		{
			"an ordinary high-confidence block is proposed",
			ind("example.com", feed.ActionBlock, feed.ConfidenceHigh),
			policy.DispositionPropose, policy.ReasonEligible,
		},
		{
			"an allow record is excluded regardless of the name",
			ind("example.com", feed.ActionAllow, feed.ConfidenceHigh),
			policy.DispositionExclude, policy.ReasonNotBlockAction,
		},
		{
			"a low-confidence block is excluded",
			ind("example.com", feed.ActionBlock, feed.ConfidenceLow),
			policy.DispositionExclude, policy.ReasonBelowConfidence,
		},
		{
			"a mixed-script name the feed is confident about goes to review, not to the plan",
			ind("аpple.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalMixedScript),
			policy.DispositionReview, policy.ReasonMixedScript,
		},
		{
			"non-ASCII alone changes nothing",
			ind("пример.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalNonASCII),
			policy.DispositionPropose, policy.ReasonEligible,
		},
		{
			"a single non-Latin script alone changes nothing",
			ind("пример.example.com", feed.ActionBlock, feed.ConfidenceHigh,
				domain.SignalNonASCII, domain.SignalSingleNonLatinScript),
			policy.DispositionPropose, policy.ReasonEligible,
		},
		{
			"punycode input alone changes nothing",
			ind("xn--e1afmkfd.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalPunycodeInput),
			policy.DispositionPropose, policy.ReasonEligible,
		},
		{
			"the feed's own exclusion outranks a name signal",
			ind("аpple.example.com", feed.ActionBlock, feed.ConfidenceMedium, domain.SignalMixedScript),
			policy.DispositionExclude, policy.ReasonBelowConfidence,
		},
		{
			"an allow record with a mixed-script name is still just an allow record",
			ind("аpple.example.com", feed.ActionAllow, feed.ConfidenceHigh, domain.SignalMixedScript),
			policy.DispositionExclude, policy.ReasonNotBlockAction,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disp, reason := policy.Decide(tc.indicator)
			if disp != tc.wantDisp || reason != tc.wantReason {
				t.Fatalf("got (%s, %s), want (%s, %s)", disp, reason, tc.wantDisp, tc.wantReason)
			}
		})
	}
}

// TestUnicodeAloneIsNeverEvidence is the negative half stated on its own,
// because it is the failure mode most likely to be introduced by a later
// well-meaning change.
func TestUnicodeAloneIsNeverEvidence(t *testing.T) {
	for _, s := range []domain.Signal{
		domain.SignalNonASCII,
		domain.SignalPunycodeInput,
		domain.SignalSingleNonLatinScript,
	} {
		i := ind("example.com", feed.ActionBlock, feed.ConfidenceHigh, s)
		if disp, _ := policy.Decide(i); disp != policy.DispositionPropose {
			t.Errorf("signal %q alone changed the disposition to %s", s, disp)
		}
	}
}

func validatedWith(t *testing.T, inds ...feed.Indicator) *feed.Validated {
	t.Helper()
	return &feed.Validated{
		FeedID:          "test-feed",
		ManifestVersion: "1.0",
		ExpiresAt:       time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Indicators:      inds,
	}
}

// TestReviewEntriesAreWithheldWithoutBeingHidden: a plan must not propose them,
// must not count them as exclusions, and must still show them.
func TestReviewEntriesAreWithheldWithoutBeingHidden(t *testing.T) {
	p := policy.Compute(validatedWith(t,
		ind("example.com", feed.ActionBlock, feed.ConfidenceHigh),
		ind("аpple.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalMixedScript),
	))

	if p.Count() != 1 {
		t.Fatalf("%d entries proposed, want 1", p.Count())
	}
	if p.ReviewCount() != 1 {
		t.Fatalf("%d entries held for review, want 1", p.ReviewCount())
	}
	if p.Exclusions.Total() != 0 {
		t.Fatalf("a review entry was counted as an exclusion: %+v", p.Exclusions)
	}
	if p.Review[0].Reason != policy.ReasonMixedScript {
		t.Fatalf("review reason = %q", p.Review[0].Reason)
	}
	for _, e := range p.Entries {
		if e.Domain == p.Review[0].Domain {
			t.Fatal("an entry appears in both the plan and the review section")
		}
	}
}

// TestReviewSectionIsCoveredByTheDigest: two plans that differ only in whether
// an entry was withheld must not share an identity, or operator approval of one
// would authorise the other.
func TestReviewSectionIsCoveredByTheDigest(t *testing.T) {
	withReview := policy.Compute(validatedWith(t,
		ind("example.com", feed.ActionBlock, feed.ConfidenceHigh),
		ind("аpple.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalMixedScript),
	))
	withoutReview := policy.Compute(validatedWith(t,
		ind("example.com", feed.ActionBlock, feed.ConfidenceHigh),
	))
	if withReview.Digest == withoutReview.Digest {
		t.Fatal("a plan holding an entry for review has the same digest as one that never saw it")
	}
	if !strings.Contains(policy.Canonical(withReview), "review:1") {
		t.Fatalf("the review count is not in the digest input:\n%s", policy.Canonical(withReview))
	}
}

// TestPlanIsDeterministicWithReviewEntries: the digest is the basis of operator
// review, so it must not depend on map iteration or input order.
func TestPlanIsDeterministicWithReviewEntries(t *testing.T) {
	build := func() *policy.Plan {
		return policy.Compute(validatedWith(t,
			ind("zeta.example.com", feed.ActionBlock, feed.ConfidenceHigh),
			ind("gоogle.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalMixedScript),
			ind("alpha.example.com", feed.ActionBlock, feed.ConfidenceHigh),
			ind("аpple.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalMixedScript),
			ind("пример.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalNonASCII),
		))
	}
	first := build()
	for range 100 {
		again := build()
		if again.Digest != first.Digest {
			t.Fatalf("digest is not deterministic: %s vs %s", again.Digest, first.Digest)
		}
		if policy.Canonical(again) != policy.Canonical(first) {
			t.Fatal("the canonical serialisation is not deterministic")
		}
	}
	// And the review section must be sorted, like the entries.
	for i := 1; i < len(first.Review); i++ {
		if first.Review[i-1].Domain >= first.Review[i].Domain {
			t.Fatalf("the review section is not sorted: %q then %q", first.Review[i-1].Domain, first.Review[i].Domain)
		}
	}
}

// TestReasonCodesAreStable pins the wire form of every reason. These appear in
// plans and are covered by the digest, so a rename is a format change.
func TestReasonCodesAreStable(t *testing.T) {
	want := map[policy.Reason]string{
		policy.ReasonEligible:        "eligible",
		policy.ReasonNotBlockAction:  "not_block_action",
		policy.ReasonBelowConfidence: "below_confidence",
		policy.ReasonMixedScript:     "mixed_script_requires_review",
	}
	for r, s := range want {
		if string(r) != s {
			t.Errorf("reason code changed: %q, want %q", string(r), s)
		}
	}
	dispositions := map[policy.Disposition]string{
		policy.DispositionPropose: "propose",
		policy.DispositionReview:  "review",
		policy.DispositionExclude: "exclude",
	}
	for d, s := range dispositions {
		if string(d) != s {
			t.Errorf("disposition changed: %q, want %q", string(d), s)
		}
	}
}

// TestPlanSerialisesTheReviewSection: a captured plan document has to carry the
// withheld entries, or the reviewer reading the file sees a different plan from
// the one the terminal printed.
func TestPlanSerialisesTheReviewSection(t *testing.T) {
	p := policy.Compute(validatedWith(t,
		ind("аpple.example.com", feed.ActionBlock, feed.ConfidenceHigh, domain.SignalMixedScript),
	))
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var round policy.Plan
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.ReviewCount() != 1 {
		t.Fatalf("the review section did not survive serialisation: %s", b)
	}
	if round.Review[0].Reason != policy.ReasonMixedScript {
		t.Fatalf("the reason did not survive serialisation: %s", b)
	}
	if !strings.Contains(string(b), "mixed_script") {
		t.Fatalf("the signals did not survive serialisation: %s", b)
	}
}
