// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// ProposalRule measures internal/proposal's decision semantics.
//
// # WHY IT CALLS THE SHIPPED RULE INSTEAD OF RESTATING IT
//
// PolicyDetector already makes this argument for the v1 plan path: a detector
// that reimplemented the decision would be scoring its own copy, and the copy
// is the thing that drifts. proposal.DecideIndicator is exported for exactly
// this, and what is measured here is therefore the rule the command runs.
//
// # HOW THREE OUTCOMES BECOME THIS HARNESS'S FIVE
//
// internal/proposal answers propose, abstain or refuse. This harness scores
// propose, pass, abstain, unsupported and parse_failure, and the mapping is
// driven by the REASON rather than by the decision, because two of
// proposal's abstentions are answers and two are declinations.
//
// The question each mapping asks is: did the rule DECIDE to leave this name
// alone, or did it fail to decide?
//
//   - DECIDED, so PASS: the household excepted it; the threshold was not met;
//     the only sources that met it arrived by republication; nothing live
//     supports it; the only evidence has expired or been withdrawn. In every one of those the rule read what there was and
//     concluded "leave it alone", which is an answer and usually the right
//     one. Scoring them as abstentions would give the rule no measurable
//     false-positive rate at all, because it would almost never be counted as
//     having decided anything.
//   - DID NOT DECIDE, so ABSTAIN: sources conflict; the name carries a signal
//     that wants a human; a rights position forbade the operation. The first
//     two are the harness's own definition of waiting for a person —
//     PolicyDetector maps DispositionReview the same way — and the third is a
//     case where the rule was not permitted to look. Scoring a licensing
//     problem as "correctly left alone" would award it a perfect
//     false-positive rate, which is the exact fault DecisionAbstain exists to
//     prevent.
//
// proposalOutcomeToDecision is the table, so the mapping is auditable rather
// than buried in a switch.
type ProposalRule struct {
	// Policy is the operator policy under test. Part of the identity.
	Policy *proposal.Policy
	// Registry is what independence and rights are assessed against.
	Registry *sourceregistry.Registry
	// Label names the configuration in a report.
	Label string
}

// Name identifies the configuration, including the policy's own digest, so a
// number belongs to a configuration somebody can reproduce.
func (r ProposalRule) Name() string {
	return fmt.Sprintf("%s (proposal semantics v%d, policy %s)",
		r.Label, proposal.SemanticsVersion, shortDigest(r.Policy.Digest()))
}

// ConfigDigest binds the policy and the scoring semantics. The registry is
// NOT in it: Binding.RegistryDigest carries the registry for the whole run,
// and digesting it twice would refuse a comparison for one difference counted
// in two places.
func (r ProposalRule) ConfigDigest() string {
	return digestValue("proposal-rule", struct {
		Policy    string `json:"policy_digest"`
		Semantics int    `json:"proposal_semantics_version"`
	}{r.Policy.Digest(), proposal.SemanticsVersion})
}

// Decide runs the shipped rule.
func (r ProposalRule) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	if len(e.Case.Observations) == 0 {
		return DecisionAbstain, "no observations; this rule decides from provenance and there is none"
	}

	// The ZERO Attribution: this harness models no signer at all. A fixture
	// observation carries a source id and no channel, so treating each as
	// spoken in its own right is a property of THESE FIXTURES and not a
	// claim about the world. A fixture set that wanted to exercise the
	// aggregator rule would have to carry the channel, which schema v1 does
	// not, and inventing one here would be inventing provenance.
	out := proposal.DecideIndicator(e.Indicator, r.Registry, r.Policy, evaluationTime, proposal.Attribution{})
	if out.Decision == proposal.DecisionPropose {
		return DecisionPropose, out.Explanation
	}
	d, mapped := proposalOutcomeToDecision[out.Reason]
	if !mapped {
		// A reason this table does not cover is not silently rounded into
		// either column. Abstaining is the honest answer and the harness
		// counts it, so a reason added to internal/proposal without a decision
		// being taken here is visible in the numbers rather than invisible in
		// them. TestEveryProposalReasonIsMapped fails on it too.
		return DecisionAbstain, "this harness has no scoring rule for reason " + string(out.Reason)
	}
	return d, out.Explanation
}

// proposalOutcomeToDecision is the auditable form of the mapping above.
//
// Every reason internal/proposal can attach to a non-proposal appears exactly
// once, and TestEveryProposalReasonIsMapped fails when one does not.
var proposalOutcomeToDecision = map[proposal.Reason]Decision{
	// Decided to leave it alone.
	proposal.ReasonUserException:       DecisionPass,
	proposal.ReasonInsufficientSupport: DecisionPass,
	// DECIDED, so PASS, for the same reason as the line above: the rule read
	// what there was and concluded the independent threshold was not met. The
	// SHORTFALL has a different cause and a different fix, which is why it is
	// a separate reason code, but the answer it produces is the same answer.
	proposal.ReasonAggregatedNotIndependent: DecisionPass,
	proposal.ReasonNoLiveEvidence:           DecisionPass,
	proposal.ReasonExpiredOnly:              DecisionPass,
	proposal.ReasonWithdrawnOnly:            DecisionPass,

	// Did not decide.
	proposal.ReasonConflict:             DecisionAbstain,
	proposal.ReasonNameRequiresReview:   DecisionAbstain,
	proposal.ReasonDerivedOutputRefused: DecisionAbstain,
	proposal.ReasonEnrichmentRefused:    DecisionAbstain,
}

// NaiveSuffixRule is DELIBERATELY WRONG, and it is here so the harness can be
// shown to catch it.
//
// It matches by string suffix instead of by label, which is the mistake the
// whole of internal/proposal's matching exists to avoid:
//
//	strings.HasSuffix("notbad.example.com", "bad.example.com") == true
//
// and notbad.example.com is somebody else's domain. A harness that scored this
// the same as the correct rule would not be measuring anything, and a control
// that nobody can fail is not a control.
type NaiveSuffixRule struct {
	// Members are the canonical names the list holds.
	Members []string
	// Label names the configuration in a report.
	Label string
}

// Name identifies the configuration, and says what it is.
func (r NaiveSuffixRule) Name() string {
	return fmt.Sprintf("%s (%d entries, DELIBERATELY DEFECTIVE suffix matching, %s)",
		r.Label, len(r.Members), shortDigest(r.ConfigDigest()))
}

// ConfigDigest binds the membership, in a canonical order.
func (r NaiveSuffixRule) ConfigDigest() string {
	ms := append([]string(nil), r.Members...)
	sortStrings(ms)
	return digestValue("naive-suffix-rule", ms)
}

// Decide proposes anything whose canonical form ENDS WITH a member.
func (r NaiveSuffixRule) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	for _, m := range r.Members {
		if strings.HasSuffix(e.Canonical, m) {
			return DecisionPropose, "ends with " + m
		}
	}
	return DecisionPass, "no member is a suffix of it"
}

// ExactLabelRule is the correct counterpart: the same membership, compared by
// label. It is the control that makes NaiveSuffixRule's failures attributable
// to the matching and to nothing else — same list, same cases, one difference.
type ExactLabelRule struct {
	Members []string
	Label   string
}

// Name identifies the configuration.
func (r ExactLabelRule) Name() string {
	return fmt.Sprintf("%s (%d entries, exact label matching, %s)",
		r.Label, len(r.Members), shortDigest(r.ConfigDigest()))
}

// ConfigDigest binds the membership.
func (r ExactLabelRule) ConfigDigest() string {
	ms := append([]string(nil), r.Members...)
	sortStrings(ms)
	return digestValue("exact-label-rule", ms)
}

// Decide proposes exactly the canonical names it holds.
func (r ExactLabelRule) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	for _, m := range r.Members {
		if proposal.Covers(m, proposal.ScopeExact, e.Canonical) {
			return DecisionPropose, "on the list"
		}
	}
	return DecisionPass, "not on the list"
}

// sortStrings is sort.Strings, named locally so the three digests above read
// the same way.
func sortStrings(s []string) { sort.Strings(s) }

// compile-time check that the three rules are detectors whose configuration
// can be bound. A rule that could not state its own configuration would make
// every comparison involving it unrepeatable, and Improved would say so rather
// than assume — but a rule in THIS package has no excuse.
var (
	_ Detector         = ProposalRule{}
	_ ConfigIdentified = ProposalRule{}
	_ Detector         = NaiveSuffixRule{}
	_ ConfigIdentified = NaiveSuffixRule{}
	_ Detector         = ExactLabelRule{}
	_ ConfigIdentified = ExactLabelRule{}
)
