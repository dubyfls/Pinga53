// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Operation is one thing ScamWall might do with a source's data.
//
// # WHY AUTHORIZATION IS PER-OPERATION
//
// The first version of this registry carried three rights fields —
// commercial_use, caching, redistribution — and a single `enabled` boolean.
// That model cannot express the thing that actually matters, and it fails in
// both directions:
//
//   - It over-refuses. A source whose terms permit querying and forbid
//     republishing would be refused outright, even though a purely local
//     lookup is exactly what it permits. Requiring redistribution rights to
//     perform a permitted local lookup is a category error.
//   - It under-refuses. `permitted` in three fields said nothing about whether
//     ScamWall could keep a copy, use the data to annotate other records, or
//     train on it — so those operations were authorised by silence.
//
// Permission to query does not imply permission to publish, and the reverse is
// not implied either. Each operation carries its own grant, and each is checked
// on its own.
type Operation string

// The operations a source's terms are assessed against.
const (
	// OpRetrieval — fetch the data at all.
	OpRetrieval Operation = "retrieval"
	// OpLocalStorage — keep a local copy beyond the life of one request.
	OpLocalStorage Operation = "local_storage"
	// OpEnrichment — use it to annotate or score records from elsewhere.
	OpEnrichment Operation = "enrichment"
	// OpModelTraining — use it as training data. Frequently prohibited even
	// where every other use is permitted, which is why it is not folded into
	// enrichment.
	OpModelTraining Operation = "model_training"
	// OpCommercialUse — use it in a commercial context.
	OpCommercialUse Operation = "commercial_use"
	// OpRedistribution — pass the provider's records on to anyone else.
	OpRedistribution Operation = "redistribution"
	// OpDerivedOutput — publish something computed FROM it. Distinct from
	// redistribution: a blocklist derived from a feed is not the feed, and a
	// licence may treat the two differently in either direction.
	OpDerivedOutput Operation = "derived_output"
)

// AllOperations is the closed set. A record must carry a grant for every one of
// them: an operation a record does not mention is an operation nobody
// considered, and silence is not a permission.
var AllOperations = []Operation{
	OpRetrieval, OpLocalStorage, OpEnrichment, OpModelTraining,
	OpCommercialUse, OpRedistribution, OpDerivedOutput,
}

// Grant statuses.
const (
	// GrantPermitted — the terms permit it, unconditionally.
	GrantPermitted = "permitted"
	// GrantProhibited — the terms forbid it.
	GrantProhibited = "prohibited"
	// GrantConditional — the terms permit it subject to conditions, which are
	// enumerated and individually assessed. Conditional is NEVER sufficient on
	// its own: see Authorizes.
	GrantConditional = "conditional"
	// GrantUnknown — not established. Refused for every operation, because an
	// unestablished right is indistinguishable from an absent one at the moment
	// it matters.
	GrantUnknown = "unknown"
	// GrantNotApplicable — the operation is not meaningful for this source.
	// It is still refused; it is a statement about relevance, not a permission.
	GrantNotApplicable = "not_applicable"
)

// ValidGrantStatuses is the closed vocabulary for a grant.
var ValidGrantStatuses = []string{
	GrantPermitted, GrantProhibited, GrantConditional, GrantUnknown, GrantNotApplicable,
}

// Condition satisfaction.
const (
	ConditionSatisfied   = "yes"
	ConditionUnsatisfied = "no"
	ConditionUnknown     = "unknown"
)

// ValidConditionSatisfaction is the closed vocabulary for a condition.
var ValidConditionSatisfaction = []string{ConditionSatisfied, ConditionUnsatisfied, ConditionUnknown}

// Citation is one reference to something a provider actually published, and the
// day it was read.
//
// A rights assertion with no citation is an opinion. The registry's whole claim
// to be evidence rests on every assertion being traceable to a document and a
// date, so a citation carries both or it is refused.
type Citation struct {
	// URL of the page the assertion was read from. https only — see the note
	// in Validate.
	URL string `json:"url"`
	// CheckedOn is the day it was read, in DateLayout form.
	CheckedOn string `json:"checked_on"`
	// Quote is the provider's own words, or a close paraphrase, so that a later
	// reader can tell whether the page still says what the record claims
	// without re-deriving the reasoning.
	Quote string `json:"quote"`
}

// Evidence separates four things that a single free-text field would blur, and
// whose blurring is the usual way a provenance record becomes untrustworthy.
//
//   - ProviderTerms — what the provider's own terms SAY. Quoted.
//   - TechnicalCapability — what the documentation says the thing CAN DO.
//     A marketing page describing a capability is not a term of licence, and a
//     licence permitting a use is not evidence the API exposes the field.
//   - ResearcherInterpretation — this project's READING. Not the provider's
//     words, and labelled so it can never be mistaken for them.
//   - UnresolvedQuestions — what is still not known. Recorded rather than
//     rounded to a conclusion in either direction.
type Evidence struct {
	ProviderTerms            []Citation `json:"provider_terms"`
	TechnicalCapability      []Citation `json:"technical_capability"`
	ResearcherInterpretation string     `json:"researcher_interpretation"`
	UnresolvedQuestions      []string   `json:"unresolved_questions"`
}

// Condition is one thing the provider requires before a conditional grant
// applies.
type Condition struct {
	// ID is stable within the record, so a decision can name the condition it
	// turned on.
	ID string `json:"id"`
	// Text is the condition as the provider states it.
	Text string `json:"text"`
	// Satisfied: yes, no, or unknown. `unknown` denies, exactly as `no` does —
	// an unmet condition and an unassessed one are the same thing at the moment
	// the operation would happen.
	Satisfied string `json:"satisfied"`
	// Basis is why this project says it is satisfied or not. Required, because
	// "yes" with no reason is the assertion this whole structure exists to
	// prevent.
	Basis string `json:"basis"`
}

// Grant is the assessed permission for one operation.
type Grant struct {
	Status     string      `json:"status"`
	Conditions []Condition `json:"conditions"`
	Evidence   Evidence    `json:"evidence"`
}

// Authorizes reports whether one operation is permitted, and why not when it is
// not.
//
// This is the function docs/SOURCE_REGISTRY.md's acceptance criterion is about:
// the registry cannot authorise an operation whose required access or usage
// conditions are unknown or unmet.
//
// `conditional` on its own authorises NOTHING. It authorises only when every
// enumerated condition is recorded as satisfied, with a basis. A conditional
// grant carrying no conditions is refused rather than treated as permitted —
// otherwise "conditional" would be a synonym for "permitted" written by an
// author who had not finished reading.
func (s *Source) Authorizes(op Operation) (bool, string) {
	g, ok := s.Permissions[op]
	if !ok {
		return false, fmt.Sprintf("no grant is recorded for %q; an operation nobody assessed is not permitted by silence", op)
	}
	switch g.Status {
	case GrantPermitted:
		return true, ""
	case GrantProhibited:
		return false, fmt.Sprintf("%s is prohibited by the recorded terms", op)
	case GrantUnknown:
		return false, fmt.Sprintf("%s is recorded as unknown; an unestablished right is refused, not assumed", op)
	case GrantNotApplicable:
		return false, fmt.Sprintf("%s is recorded as not applicable to this source", op)
	case GrantConditional:
		if len(g.Conditions) == 0 {
			return false, fmt.Sprintf("%s is conditional but no condition is recorded; `conditional` with nothing to satisfy is refused", op)
		}
		var unmet []string
		for _, c := range g.Conditions {
			switch c.Satisfied {
			case ConditionSatisfied:
			case ConditionUnsatisfied:
				unmet = append(unmet, fmt.Sprintf("%s (not satisfied)", c.ID))
			default:
				unmet = append(unmet, fmt.Sprintf("%s (satisfaction unknown)", c.ID))
			}
		}
		if len(unmet) > 0 {
			sort.Strings(unmet)
			return false, fmt.Sprintf("%s is conditional and these conditions are not met: %s", op, strings.Join(unmet, ", "))
		}
		return true, ""
	default:
		return false, fmt.Sprintf("%s carries an unrecognised grant status %q", op, g.Status)
	}
}

// UnauthorizedIntendedOperations returns the operations this record says
// ScamWall intends to perform but which its own recorded terms do not
// authorise.
//
// This is what `enabled` is checked against. A source is enabled for the uses
// it declares, and only when every one of them is authorised — not because
// three legacy fields happened to read `permitted`.
func (s *Source) UnauthorizedIntendedOperations() []string {
	var refused []string
	for _, op := range s.IntendedOperations {
		if ok, why := s.Authorizes(Operation(op)); !ok {
			refused = append(refused, why)
		}
	}
	sort.Strings(refused)
	return refused
}

// validateGrants checks the shape of every grant, and the evidence behind it.
func (s *Source) validateGrants(idx int, asOf time.Time, problems *[]Problem) {
	at := func(f string) string { return fmt.Sprintf("sources[%d].%s", idx, f) }

	for _, op := range AllOperations {
		g, ok := s.Permissions[op]
		if !ok {
			*problems = append(*problems, Problem{
				at("permissions." + string(op)),
				"required and absent — every operation carries a grant, because an operation nobody assessed must not be authorised by silence",
			})
			continue
		}
		p := "permissions." + string(op)
		if !contains(ValidGrantStatuses, g.Status) {
			*problems = append(*problems, Problem{
				at(p + ".status"),
				fmt.Sprintf("is %q; permitted values are %s", g.Status, strings.Join(ValidGrantStatuses, ", ")),
			})
			continue
		}

		// Conditions belong to `conditional` and nowhere else. Conditions
		// attached to a `permitted` grant would be either ignored or silently
		// load-bearing, and neither is acceptable in a record like this.
		if g.Status == GrantConditional && len(g.Conditions) == 0 {
			*problems = append(*problems, Problem{
				at(p + ".conditions"),
				"is empty while the status is `conditional`; enumerate what must hold, or record the status the terms actually support",
			})
		}
		if g.Status != GrantConditional && len(g.Conditions) > 0 {
			*problems = append(*problems, Problem{
				at(p + ".conditions"),
				fmt.Sprintf("lists conditions while the status is %q; conditions apply to `conditional` grants only", g.Status),
			})
		}
		for j, c := range g.Conditions {
			cp := fmt.Sprintf("%s.conditions[%d]", p, j)
			if strings.TrimSpace(c.ID) == "" {
				*problems = append(*problems, Problem{at(cp + ".id"), "is empty; a condition needs a stable name so a decision can cite it"})
			}
			if strings.TrimSpace(c.Text) == "" {
				*problems = append(*problems, Problem{at(cp + ".text"), "is empty; record the condition as the provider states it"})
			}
			if !contains(ValidConditionSatisfaction, c.Satisfied) {
				*problems = append(*problems, Problem{
					at(cp + ".satisfied"),
					fmt.Sprintf("is %q; permitted values are %s", c.Satisfied, strings.Join(ValidConditionSatisfaction, ", ")),
				})
			}
			if strings.TrimSpace(c.Basis) == "" {
				*problems = append(*problems, Problem{
					at(cp + ".basis"),
					"is empty; a condition recorded as satisfied without a stated basis is the assertion this structure exists to prevent",
				})
			}
		}

		// Evidence. A grant that makes a claim must cite the terms it read it
		// from; `unknown` and `not_applicable` claim nothing and need none.
		asserts := g.Status == GrantPermitted || g.Status == GrantProhibited || g.Status == GrantConditional
		if asserts && len(g.Evidence.ProviderTerms) == 0 {
			*problems = append(*problems, Problem{
				at(p + ".evidence.provider_terms"),
				fmt.Sprintf("is empty while the status is %q; a rights assertion with no citation is an opinion", g.Status),
			})
		}
		validateCitations(at(p+".evidence.provider_terms"), g.Evidence.ProviderTerms, asOf, problems)
		validateCitations(at(p+".evidence.technical_capability"), g.Evidence.TechnicalCapability, asOf, problems)
	}

	// Intended operations must be real operations, and must not repeat.
	seen := map[string]bool{}
	for j, op := range s.IntendedOperations {
		ip := at(fmt.Sprintf("intended_operations[%d]", j))
		if !containsOp(AllOperations, Operation(op)) {
			*problems = append(*problems, Problem{ip, fmt.Sprintf("is %q, which is not an operation this registry assesses", op)})
			continue
		}
		if seen[op] {
			*problems = append(*problems, Problem{ip, fmt.Sprintf("%q is listed twice", op)})
		}
		seen[op] = true
	}
}

func validateCitations(path string, cites []Citation, asOf time.Time, problems *[]Problem) {
	for i, c := range cites {
		p := fmt.Sprintf("%s[%d]", path, i)
		if problem := checkDocumentationURL(c.URL); problem != "" {
			*problems = append(*problems, Problem{p + ".url", problem})
		}
		if problem := checkReadDate(c.CheckedOn, asOf); problem != "" {
			*problems = append(*problems, Problem{p + ".checked_on", problem})
		}
		if strings.TrimSpace(c.Quote) == "" {
			*problems = append(*problems, Problem{
				p + ".quote",
				"is empty; record what the page actually said, so a later reader can tell whether it still says it",
			})
		}
	}
}

func containsOp(hay []Operation, needle Operation) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
