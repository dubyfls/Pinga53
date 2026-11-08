// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// C-01 and C-02 — independence is a property of origins, and an aggregator
// that republishes X adds no vote beyond X.
//
// The tree already refused three of the four ways this number gets inflated:
// one source imported twice, an aggregator counted alongside an upstream that
// is ALSO reporting, and a source whose lineage nobody documented. The fourth
// was still open. Collapsing folds a source into an upstream present among the
// candidates; when the shared upstream reports nothing — because it is a
// corpus, a submission queue, or somebody else's aggregate that this registry
// holds no record for — there is nothing to fold into, and two republishers of
// one corpus counted as two independent voices.

// labelled is a source declaring machine-readable lineage.
func labelled(id string, labels []string) sourceregistry.Source {
	s := testSource(id, nil)
	s.UpstreamLabels = labels
	return s
}

func c01Registry(t *testing.T, origins []string, sources ...sourceregistry.Source) *sourceregistry.Registry {
	t.Helper()
	reg := &sourceregistry.Registry{
		SchemaVersion:   sourceregistry.SchemaVersion,
		ExternalOrigins: origins,
		Sources:         sources,
	}
	if problems := reg.Validate(testAt); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("fixture registry problem: %s", p)
		}
		t.FailNow()
	}
	return reg
}

func c01Run(t *testing.T, reg *sourceregistry.Registry, need int, ids ...string) Outcome {
	t.Helper()
	records := make([]feed.EvidenceRecord, 0, len(ids))
	for i, id := range ids {
		records = append(records, adverse(id, "r"+string(rune('1'+i)), "bad.example.com"))
	}
	rep := run{
		asserts:         ids,
		sources:         reg.Sources,
		externalOrigins: reg.ExternalOrigins,
		policy:          testPolicy(t, need, ScopeExact),
		records:         records,
	}.do(t)
	return rep.Outcomes[0]
}

// TestTwoFeedsRepublishingOneCorpusAreOneVoice is C-02's missing half.
func TestTwoFeedsRepublishingOneCorpusAreOneVoice(t *testing.T) {
	reg := c01Registry(t, []string{"a_public_phishing_corpus"},
		labelled("src-a", []string{"a_public_phishing_corpus"}),
		labelled("src-b", []string{"a_public_phishing_corpus"}))

	o := c01Run(t, reg, 2, "src-a", "src-b")
	if o.Decision != DecisionPropose && o.Reason != ReasonInsufficientSupport {
		// Recorded before asserting, because the failure message matters more
		// than the assertion here.
		t.Logf("decision %s/%s: %s", o.Decision, o.Reason, o.Explanation)
	}
	if o.Decision == DecisionPropose {
		t.Fatalf("two feeds republishing one corpus satisfied a two-independent-source policy; "+
			"independent sources reported as %v", o.IndependentSources)
	}
	if o.IndependentOriginGroups != 1 {
		t.Errorf("IndependentOriginGroups = %d, want 1", o.IndependentOriginGroups)
	}
	if !strings.Contains(o.Explanation, "a_public_phishing_corpus") {
		t.Errorf("the explanation does not name the origin they share: %q", o.Explanation)
	}
}

// TestTwoPrimariesAreTwoVoices is the control on the control. If origin
// grouping cannot be satisfied, the threshold can never be met and the product
// blocks nothing.
func TestTwoPrimariesAreTwoVoices(t *testing.T) {
	reg := c01Registry(t, nil, testSource("src-a", nil), testSource("src-b", nil))
	o := c01Run(t, reg, 2, "src-a", "src-b")
	if o.Decision != DecisionPropose {
		t.Fatalf("two primary observers did not satisfy a two-source policy: %s/%s\n  %s",
			o.Decision, o.Reason, o.Explanation)
	}
	if o.IndependentOriginGroups != 2 {
		t.Errorf("IndependentOriginGroups = %d, want 2", o.IndependentOriginGroups)
	}
}

// TestAPartialOverlapIsCountedAsTheMaximumDisjointFamily.
//
// A draws on x, B draws on y, C draws on both. The largest pairwise-disjoint
// family is {A, B} — two voices, not three and not one. A rule that counted
// "sources sharing nothing with anyone" would say one; a rule that counted
// connected components would say one; neither is what the evidence supports.
func TestAPartialOverlapIsCountedAsTheMaximumDisjointFamily(t *testing.T) {
	reg := c01Registry(t, []string{"x_corpus", "y_corpus"},
		labelled("src-a", []string{"x_corpus"}),
		labelled("src-b", []string{"y_corpus"}),
		labelled("src-c", []string{"x_corpus", "y_corpus"}))

	o := c01Run(t, reg, 2, "src-a", "src-b", "src-c")
	if o.Decision != DecisionPropose {
		t.Fatalf("a two-source policy was not met by two genuinely disjoint voices: %s/%s\n  %s",
			o.Decision, o.Reason, o.Explanation)
	}
	if o.IndependentOriginGroups != 2 {
		t.Errorf("IndependentOriginGroups = %d, want 2", o.IndependentOriginGroups)
	}

	o = c01Run(t, reg, 3, "src-a", "src-b", "src-c")
	if o.Decision == DecisionPropose {
		t.Fatalf("three sources drawing on two origins satisfied a three-source policy")
	}
}

// TestAChainOfRepublishersCollapsesOntoItsOrigin — C-02 transitively. A copy
// of a copy is still the original.
func TestAChainOfRepublishersCollapsesOntoItsOrigin(t *testing.T) {
	reg := c01Registry(t, []string{"origin_corpus"},
		labelled("src-a", []string{"origin_corpus"}),
		labelled("src-b", []string{"src-a"}),
		labelled("src-c", []string{"src-b"}))

	o := c01Run(t, reg, 2, "src-b", "src-c")
	if o.Decision == DecisionPropose {
		t.Fatalf("a republisher and a republisher of that republisher were two voices; "+
			"independent = %v, groups = %d", o.IndependentSources, o.IndependentOriginGroups)
	}
}

// TestAnUnresolvableUpstreamIsItsOwnOriginNotASharedOne.
//
// The safe direction, and it is the opposite of the obvious one. Two sources
// naming upstreams nobody can resolve must not be merged: an unresolvable
// upstream cannot be SHOWN to be shared, and inventing a shared origin would
// destroy independence that may be real. The claimability chain (FINDING-134)
// is what refuses those sources, and it refuses them for a stated reason;
// this computation must not quietly do it for a different one.
func TestAnUnresolvableUpstreamIsItsOwnOriginNotASharedOne(t *testing.T) {
	reg := c01Registry(t, []string{"p_corpus", "q_corpus"},
		labelled("src-a", []string{"p_corpus"}),
		labelled("src-b", []string{"q_corpus"}))
	g := reg.MaxDisjointOrigins([]string{"src-a", "src-b"})
	if g.Count != 2 {
		t.Fatalf("Count = %d, want 2: two distinct origins are two voices", g.Count)
	}
	if len(g.Shared) != 0 {
		t.Errorf("Shared = %v, want none", g.Shared)
	}
}

// adverseRecords builds one adverse record per source id, all naming the same
// indicator.
func adverseRecords(ids ...string) []feed.EvidenceRecord {
	out := make([]feed.EvidenceRecord, 0, len(ids))
	for i, id := range ids {
		out = append(out, adverse(id, "r"+string(rune('1'+i)), "bad.example.com"))
	}
	return out
}
