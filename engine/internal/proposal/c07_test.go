// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// C-07 — an `authoritative` source may satisfy the threshold alone, and only
// under two conditions that are both easy to leave out.
//
//  1. The household's policy must say so. A tier the registry author sets is
//     a claim about a provider; permission to act on one source is a decision
//     about the household's own risk, and the two must not be the same
//     statement.
//  2. Only PRIMARY lineage may hold the tier. An aggregator marked
//     authoritative would let one republished corpus block on its own, which
//     is exactly the inflation C-01 and C-02 exist to refuse, arriving through
//     a field instead of through a count.

func authoritative(id string) sourceregistry.Source {
	s := testSource(id, nil)
	s.TrustTier = sourceregistry.TierAuthoritative
	return s
}

func c07Policy(t *testing.T, need int, allow bool) *Policy {
	t.Helper()
	p := testPolicy(t, need, ScopeExact)
	p.AcceptAuthoritativeAlone = allow
	return p
}

func c07Run(t *testing.T, reg *sourceregistry.Registry, p *Policy, ids ...string) Outcome {
	t.Helper()
	rep := run{
		asserts:         ids,
		sources:         reg.Sources,
		externalOrigins: reg.ExternalOrigins,
		policy:          p,
		records:         adverseRecords(ids...),
	}.do(t)
	return rep.Outcomes[0]
}

func TestAnAuthoritativeSourceAloneSatisfiesTheThresholdWhenThePolicyAllowsIt(t *testing.T) {
	reg := c01Registry(t, nil, authoritative("src-a"))
	o := c07Run(t, reg, c07Policy(t, 2, true), "src-a")

	if o.Decision != DecisionPropose {
		t.Fatalf("decision = %s/%s, want %s\n  %s", o.Decision, o.Reason, DecisionPropose, o.Explanation)
	}
	if o.Reason != ReasonAuthoritativeSource {
		t.Errorf("reason = %s, want %s: a one-source proposal must not be reported as ordinary corroboration",
			o.Reason, ReasonAuthoritativeSource)
	}
	if len(o.AuthoritativeSources) != 1 || o.AuthoritativeSources[0] != "src-a" {
		t.Errorf("AuthoritativeSources = %v, want [src-a]", o.AuthoritativeSources)
	}
	if !strings.Contains(o.Explanation, "accept_authoritative_alone") {
		t.Errorf("the explanation does not name the policy switch that permitted it: %q", o.Explanation)
	}
}

func TestTheSameSourceAloneIsNotEnoughWhenThePolicyDoesNotAllowIt(t *testing.T) {
	reg := c01Registry(t, nil, authoritative("src-a"))
	o := c07Run(t, reg, c07Policy(t, 2, false), "src-a")

	if o.Decision != DecisionAbstain {
		t.Fatalf("an authoritative source blocked on its own with accept_authoritative_alone false: %s/%s\n  %s",
			o.Decision, o.Reason, o.Explanation)
	}
	// ...and the tier is still reported, because an operator deciding whether
	// to turn the switch on needs to see that it would have made a difference.
	if len(o.AuthoritativeSources) != 1 {
		t.Errorf("AuthoritativeSources = %v; the tier is a fact about the evidence whether or not it was acted on",
			o.AuthoritativeSources)
	}
}

func TestAnOrdinarySourceAloneIsNeverEnough(t *testing.T) {
	reg := c01Registry(t, nil, testSource("src-a", nil))
	o := c07Run(t, reg, c07Policy(t, 2, true), "src-a")
	if o.Decision != DecisionAbstain {
		t.Fatalf("an ordinary source satisfied a two-source policy alone: %s/%s", o.Decision, o.Reason)
	}
}

// TestTheTierNeverLowersTheAnswer — the switch may only ever turn an
// abstention into a proposal. A refusal is not a policy question, and a
// conflict is not answered by one source being trusted more.
func TestTheTierNeverLowersTheAnswer(t *testing.T) {
	reg := c01Registry(t, nil, authoritative("src-a"))
	p := c07Policy(t, 1, true)
	p.Exceptions = []Exception{}
	o := c07Run(t, reg, p, "src-a")
	if o.Decision != DecisionPropose {
		t.Fatalf("a one-source policy met by an authoritative source did not propose: %s/%s", o.Decision, o.Reason)
	}
	// With the threshold already met, the ordinary reason must win: the tier
	// is a fallback, not a relabelling of every proposal.
	if o.Reason != ReasonCorroborated {
		t.Errorf("reason = %s, want %s: the threshold was met without needing the tier", o.Reason, ReasonCorroborated)
	}
}

// --- the registry half --------------------------------------------------

func TestOnlyPrimaryLineageMayBeAuthoritative(t *testing.T) {
	for name, s := range map[string]sourceregistry.Source{
		"an aggregator": func() sourceregistry.Source {
			s := authoritative("src-b")
			s.UpstreamLabels = []string{"src-a"}
			return s
		}(),
		"a source drawing on an external corpus": func() sourceregistry.Source {
			s := authoritative("src-b")
			s.UpstreamLabels = []string{"a_corpus"}
			return s
		}(),
		"a source with undocumented lineage": func() sourceregistry.Source {
			s := authoritative("src-b")
			s.UpstreamSourcesCompleteness = sourceregistry.UpstreamUnknown
			return s
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			reg := &sourceregistry.Registry{
				SchemaVersion:   sourceregistry.SchemaVersion,
				ExternalOrigins: []string{"a_corpus"},
				Sources:         []sourceregistry.Source{testSource("src-a", nil), s},
			}
			var got strings.Builder
			for _, p := range reg.Validate(testAt) {
				got.WriteString(p.String() + "\n")
			}
			if !strings.Contains(got.String(), "trust_tier") {
				t.Fatalf("%s was accepted as authoritative:\n%s", name, got.String())
			}
		})
	}
}

func TestAPrimaryMayBeAuthoritative(t *testing.T) {
	reg := &sourceregistry.Registry{
		SchemaVersion: sourceregistry.SchemaVersion,
		Sources:       []sourceregistry.Source{authoritative("src-a")},
	}
	for _, p := range reg.Validate(testAt) {
		t.Errorf("a primary observer was refused the authoritative tier: %s", p)
	}
}

func TestAnUnrecognisedTierIsRefused(t *testing.T) {
	s := testSource("src-a", nil)
	s.TrustTier = "very_trustworthy"
	reg := &sourceregistry.Registry{SchemaVersion: sourceregistry.SchemaVersion, Sources: []sourceregistry.Source{s}}
	var got strings.Builder
	for _, p := range reg.Validate(testAt) {
		got.WriteString(p.String() + "\n")
	}
	if !strings.Contains(got.String(), "trust_tier") {
		t.Fatalf("an unrecognised tier was accepted:\n%s", got.String())
	}
}
