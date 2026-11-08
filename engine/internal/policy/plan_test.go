// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/policy"
)

func indicator(d string, a feed.Action, c feed.Confidence) feed.Indicator {
	return feed.Indicator{Domain: domain.Domain(d), Action: a, Confidence: c, Category: "phishing"}
}

func validated(inds ...feed.Indicator) *feed.Validated {
	return &feed.Validated{
		FeedID:          "test-feed",
		ManifestVersion: "1.0",
		ExpiresAt:       time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Indicators:      inds,
	}
}

func TestComputeSelectsOnlyHighConfidenceBlocks(t *testing.T) {
	v := validated(
		indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh),
		indicator("b.example.com", feed.ActionBlock, feed.ConfidenceMedium),
		indicator("c.example.com", feed.ActionBlock, feed.ConfidenceLow),
		indicator("d.example.com", feed.ActionAllow, feed.ConfidenceHigh),
	)
	p := policy.Compute(v)

	if p.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", p.Count())
	}
	if p.Entries[0].Domain != "a.example.com" {
		t.Errorf("wrong entry selected: %q", p.Entries[0].Domain)
	}
	if p.Exclusions.BelowConfidence != 2 {
		t.Errorf("BelowConfidence = %d, want 2", p.Exclusions.BelowConfidence)
	}
	if p.Exclusions.NotBlockAction != 1 {
		t.Errorf("NotBlockAction = %d, want 1", p.Exclusions.NotBlockAction)
	}
}

// TestComputeIsDeterministic is a security property, not a convenience: an
// operator reviewing a plan must be able to rely on the reviewed plan being
// the plan in hand.
func TestComputeIsDeterministic(t *testing.T) {
	inds := []feed.Indicator{
		indicator("zebra.example.com", feed.ActionBlock, feed.ConfidenceHigh),
		indicator("alpha.example.com", feed.ActionBlock, feed.ConfidenceHigh),
		indicator("middle.example.com", feed.ActionBlock, feed.ConfidenceHigh),
	}
	first := policy.Compute(validated(inds...))

	// Same set, different input order.
	shuffled := []feed.Indicator{inds[2], inds[0], inds[1]}
	second := policy.Compute(validated(shuffled...))

	if first.Digest != second.Digest {
		t.Fatalf("digest depends on input order: %s vs %s", first.Digest, second.Digest)
	}
	if policy.Canonical(first) != policy.Canonical(second) {
		t.Fatal("canonical form depends on input order")
	}
	for i := range first.Entries {
		if first.Entries[i].Domain != second.Entries[i].Domain {
			t.Fatalf("entry %d differs: %q vs %q", i, first.Entries[i].Domain, second.Entries[i].Domain)
		}
	}
}

func TestComputeSortsEntries(t *testing.T) {
	p := policy.Compute(validated(
		indicator("zebra.example.com", feed.ActionBlock, feed.ConfidenceHigh),
		indicator("alpha.example.com", feed.ActionBlock, feed.ConfidenceHigh),
	))
	if p.Entries[0].Domain != "alpha.example.com" || p.Entries[1].Domain != "zebra.example.com" {
		t.Fatalf("entries not sorted: %v", p.Entries)
	}
}

func TestComputeRepeatedRunsAreIdentical(t *testing.T) {
	v := validated(
		indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh),
		indicator("b.example.com", feed.ActionBlock, feed.ConfidenceHigh),
	)
	want := policy.Compute(v).Digest
	for range 20 {
		if got := policy.Compute(v).Digest; got != want {
			t.Fatalf("digest is unstable across runs: %s != %s", got, want)
		}
	}
}

func TestDigestChangesWithContent(t *testing.T) {
	a := policy.Compute(validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh)))
	b := policy.Compute(validated(indicator("b.example.com", feed.ActionBlock, feed.ConfidenceHigh)))
	if a.Digest == b.Digest {
		t.Fatal("different plans must have different digests")
	}
}

func TestDigestChangesWithFeedIdentity(t *testing.T) {
	v1 := validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh))
	v2 := validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh))
	v2.FeedID = "other-feed"
	if policy.Compute(v1).Digest == policy.Compute(v2).Digest {
		t.Fatal("feed identity must contribute to the digest")
	}
}

func TestDigestFormatIsPrefixed(t *testing.T) {
	p := policy.Compute(validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh)))
	if !strings.HasPrefix(p.Digest, "sha256:") {
		t.Fatalf("digest should name its algorithm: %s", p.Digest)
	}
}

func TestEmptyPlan(t *testing.T) {
	p := policy.Compute(validated())
	if !p.IsEmpty() || p.Count() != 0 {
		t.Fatal("expected an empty plan")
	}
	if p.Digest == "" {
		t.Fatal("even an empty plan needs a digest")
	}
}

func TestPlanCarriesExpiredCountFromFeed(t *testing.T) {
	v := validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh))
	v.ExpiredCount = 3
	p := policy.Compute(v)
	if p.Exclusions.ExpiredInFeed != 3 {
		t.Errorf("ExpiredInFeed = %d, want 3", p.Exclusions.ExpiredInFeed)
	}
	if p.Exclusions.Total() != 3 {
		t.Errorf("Total() = %d, want 3", p.Exclusions.Total())
	}
}

func TestPlanIsAlwaysDryRun(t *testing.T) {
	p := policy.Compute(validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh)))
	if !p.DryRun {
		t.Fatal("a Phase 1 plan must record itself as dry-run")
	}
}

// TestEnforcementIsNotCompiledIn asserts the Phase 1 boundary directly.
func TestEnforcementIsNotCompiledIn(t *testing.T) {
	if policy.EnforcementCompiledIn {
		t.Fatal("enforcement must not be compiled into a Phase 1 build")
	}
}

func TestApplyAlwaysRefuses(t *testing.T) {
	p := policy.Compute(validated(indicator("a.example.com", feed.ActionBlock, feed.ConfidenceHigh)))
	err := policy.Apply(p)
	if !errors.Is(err, policy.ErrEnforcementUnavailable) {
		t.Fatalf("Apply must refuse in Phase 1, got %v", err)
	}
}
