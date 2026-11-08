// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"fmt"
	"math"
	"sort"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// MinReportableDenominator is the smallest denominator this package will
// compute a rate for.
//
// docs/EVALUATION_PROTOCOL.md §5.1: "A stratum with fewer than 10 labelled
// observations is reported as a count with an interval and no rate at all; a
// percentage over single digits invites a comparison the data cannot support."
// Enforcing it in code rather than in review is what stops "caught 40% more"
// over eleven observations from reaching a report.
const MinReportableDenominator = 10

// Rate is a proportion, its denominator, and its uncertainty.
//
// The denominator is not optional and is not a footnote. A rate reported
// without one cannot be checked, cannot be compared with another rate, and is
// the single most common way an evaluation result misleads.
type Rate struct {
	Numerator   int `json:"numerator"`
	Denominator int `json:"denominator"`
	// Reportable is false when the denominator is zero or below
	// MinReportableDenominator. When it is false, Value, Lower and Upper are
	// meaningless and Note says why.
	Reportable bool    `json:"reportable"`
	Value      float64 `json:"value,omitempty"`
	// Lower and Upper are the Wilson score interval at 95%. Reported as an
	// interval, never as a plus-or-minus: the interval is asymmetric near 0
	// and 1, which is exactly where these proportions live.
	Lower float64 `json:"lower,omitempty"`
	Upper float64 `json:"upper,omitempty"`
	Note  string  `json:"note,omitempty"`
}

// String renders the rate so that it cannot be read without its denominator.
func (r Rate) String() string {
	if !r.Reportable {
		return fmt.Sprintf("%d/%d — no rate (%s)", r.Numerator, r.Denominator, r.Note)
	}
	return fmt.Sprintf("%.3f [%.3f, %.3f] (%d/%d)", r.Value, r.Lower, r.Upper, r.Numerator, r.Denominator)
}

// newRate computes a proportion with its Wilson interval, refusing to report
// one the denominator cannot support.
func newRate(numerator, denominator int, what string) Rate {
	r := Rate{Numerator: numerator, Denominator: denominator}
	switch {
	case denominator == 0:
		r.Note = fmt.Sprintf("no %s, so the ratio has no denominator", what)
		return r
	case denominator < MinReportableDenominator:
		r.Note = fmt.Sprintf("only %d %s; below the %d needed for a rate to be worth stating",
			denominator, what, MinReportableDenominator)
		return r
	}
	r.Reportable = true
	r.Value = float64(numerator) / float64(denominator)
	r.Lower, r.Upper = wilson(numerator, denominator)
	return r
}

// wilson returns the Wilson score interval at 95%.
//
// Wilson rather than the normal approximation because these proportions sit
// near 0 and 1 — a good rule has a false-positive rate near zero — where the
// normal approximation produces intervals that extend below zero and above
// one, and an interval containing impossible values is not an interval.
func wilson(successes, trials int) (lower, upper float64) {
	if trials == 0 {
		return 0, 0
	}
	const z = 1.959963984540054 // 97.5th percentile of the standard normal
	n := float64(trials)
	p := float64(successes) / n
	z2 := z * z
	denom := 1 + z2/n
	centre := (p + z2/(2*n)) / denom
	spread := (z / denom) * math.Sqrt(p*(1-p)/n+z2/(4*n*n))
	lower = math.Max(0, centre-spread)
	upper = math.Min(1, centre+spread)

	// The Wilson interval always contains the point estimate. In floating
	// point it does not quite: at p = 1 the algebra cancels to exactly 1, but
	// the arithmetic returns 0.9999999999999999, and the reported interval
	// then excludes the number it is an interval for. Clamping to p restores
	// the property a reader relies on and moves nothing by more than one unit
	// in the last place.
	lower = math.Min(lower, p)
	upper = math.Max(upper, p)
	return lower, upper
}

// Counts are the raw tallies a stratum produced. Every rate below is derived
// from these, and they are reported alongside so that any rate can be checked.
type Counts struct {
	// Cases is every case in the stratum.
	Cases int `json:"cases"`
	// Labelled is the cases a qualifying label was available for.
	Labelled int `json:"labelled"`
	// LabelledMalicious and LabelledLegitimate partition Labelled.
	LabelledMalicious  int `json:"labelled_malicious"`
	LabelledLegitimate int `json:"labelled_legitimate"`
	// Unlabelled is reported as its own number and is never folded into
	// either of the two above.
	Unlabelled int `json:"unlabelled"`

	// AdditionalProposals are cases the candidate proposes and the baseline
	// does not. Everything the protocol calls "additional" is measured here.
	AdditionalProposals int `json:"additional_proposals"`
	// TruePositives, FalsePositives: additional proposals with a label.
	TruePositives  int `json:"true_positives"`
	FalsePositives int `json:"false_positives"`
	// UnlabelledProposals are additional proposals no label was available
	// for. Excluded from precision and reported beside it, because a
	// precision computed over the fraction that got labelled is a statement
	// about the labeller.
	UnlabelledProposals int `json:"unlabelled_proposals"`

	// CandidateProposes counts every proposal, additional or not. Recall is
	// against this, per §5.1, not against the additional ones.
	CandidateProposes          int `json:"candidate_proposes"`
	CandidateProposesMalicious int `json:"candidate_proposes_malicious"`
	// TrueNegatives are labelled-legitimate cases the candidate does not
	// propose.
	TrueNegatives int `json:"true_negatives"`
	// FalseNegatives are labelled-malicious cases the candidate does not
	// propose. Abstentions are included here — declining to act on something
	// harmful is a miss, whatever the rule calls it.
	FalseNegatives int `json:"false_negatives"`

	// InvalidObservationCases is how many cases carried a fixture
	// observation that could not be resolved. Those cases are counted HERE
	// and nowhere else: they are not in Cases, and so contribute to no rate.
	// A decision taken on evidence the harness silently discarded is not a
	// measurement of the rule, and averaging it in would report one.
	InvalidObservationCases int `json:"invalid_observation_cases"`

	// Abstentions, Unsupported and ParseFailures are each their own number.
	// None of them is silently merged into pass: a harness that did would
	// report a rule as having correctly left something alone when it never
	// looked at it.
	Abstentions   int `json:"abstentions"`
	Unsupported   int `json:"unsupported"`
	ParseFailures int `json:"parse_failures"`

	// BaselineProposes is what the baseline did, so that "additional" can be
	// checked rather than trusted.
	BaselineProposes int `json:"baseline_proposes"`
}

// Metrics are the derived rates for one stratum.
type Metrics struct {
	Counts Counts `json:"counts"`
	// Precision: of additional proposals that received a label, the fraction
	// labelled malicious. §5.1.
	Precision Rate `json:"precision"`
	// Recall: of labelled-malicious cases seen, the fraction the candidate
	// proposes. §5.1. Never "of all scams", which is not a set.
	Recall Rate `json:"recall"`
	// Coverage: the fraction of cases any label could be obtained for. It
	// BOUNDS the other two, and the report says so in the same breath.
	Coverage Rate `json:"coverage"`
	// FalsePositiveRate: of labelled-legitimate cases, the fraction the
	// candidate additionally proposes.
	FalsePositiveRate Rate `json:"false_positive_rate"`
	// FalseNegativeRate: of labelled-malicious cases, the fraction missed.
	FalseNegativeRate Rate `json:"false_negative_rate"`
	// AbstentionRate: of all cases, the fraction declined.
	AbstentionRate Rate `json:"abstention_rate"`
}

// Stratum is one slice of the results.
type Stratum struct {
	// Kind is what the slice is by: "overall", "family", "type", "category".
	Kind    string  `json:"kind"`
	Name    string  `json:"name"`
	Metrics Metrics `json:"metrics"`
}

// CaseResult is what happened to one case, kept so that every disagreement
// can be explained rather than merely counted.
type CaseResult struct {
	CaseID            string   `json:"case_id"`
	Value             string   `json:"value"`
	Canonical         string   `json:"canonical,omitempty"`
	Family            string   `json:"family"`
	Label             Label    `json:"label"`
	BaselineDecision  Decision `json:"baseline_decision"`
	BaselineReason    string   `json:"baseline_reason"`
	CandidateDecision Decision `json:"candidate_decision"`
	CandidateReason   string   `json:"candidate_reason"`
	// Additional is true when the candidate proposes and the baseline does not.
	Additional bool `json:"additional"`
	// Outcome names the cell this case landed in, so a reader can find the
	// cases behind any number without recomputing the classification.
	Outcome string `json:"outcome"`

	// InvalidObservations is how many of the case's fixture observations
	// could not be resolved. Any value above zero means the decision above
	// was taken on INCOMPLETE evidence, and the case is excluded from every
	// rate rather than scored as though the evidence had been whole.
	InvalidObservations int `json:"invalid_observations"`
	// ObservationFailures is why each one failed, preserved so that a reader
	// can see what was lost rather than being told a number went down.
	ObservationFailures []ObservationFailure `json:"observation_failures,omitempty"`
	// ObservationsAccepted is how many did resolve.
	ObservationsAccepted int `json:"observations_accepted"`
}

// Result is a complete run.
type Result struct {
	// Binding is the identity of the inputs, by digest rather than by name.
	// It is first because everything after it is only meaningful relative to
	// it. See binding.go.
	Binding Binding `json:"binding"`

	// --- identity as the inputs describe THEMSELVES ---
	//
	// These are names and self-declarations, kept because a report has to be
	// readable. They are never used to decide comparability; Binding is.
	FixtureSetID      string     `json:"fixture_set_id"`
	FixtureSetVersion string     `json:"fixture_set_version"`
	Partition         Partition  `json:"partition"`
	Provenance        Provenance `json:"fixture_provenance"`
	BaselineName      string     `json:"baseline_name"`
	CandidateName     string     `json:"candidate_name"`
	EvaluatedAt       string     `json:"evaluated_at"`

	// --- honesty flags, carried with the numbers rather than beside them ---
	// NotProtocolConformant lists every reason this run does not satisfy
	// docs/EVALUATION_PROTOCOL.md. It is part of the result, so a number
	// cannot be lifted out of the report without its caveats.
	NotProtocolConformant []string `json:"not_protocol_conformant"`

	Overall    Metrics   `json:"overall"`
	ByFamily   []Stratum `json:"by_family"`
	ByType     []Stratum `json:"by_type"`
	ByCategory []Stratum `json:"by_category"`

	// Disagreements are the cases where baseline and candidate differ, with
	// both reasons. This is what a reviewer reads before believing a number.
	Disagreements []CaseResult `json:"disagreements"`
	// Cases is every case result, so that any number can be traced to the
	// cases behind it.
	//
	// This is NOT a claim that the run is reproducible from its own output.
	// Whether it is depends on the bindings actually present, and
	// Result.Reproducible answers that rather than asserting it.
	Cases []CaseResult `json:"cases"`

	// InvalidObservationCases and InvalidObservations are the run-level
	// totals for evidence the harness could not resolve. They sit at the top
	// of the result, not buried in a stratum, because they bound what every
	// number below is worth.
	InvalidObservationCases int `json:"invalid_observation_cases"`
	InvalidObservations     int `json:"invalid_observations"`
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Run evaluates a candidate against a baseline over a fixture set.
//
// The registry is used only to assess corroboration. A nil registry is
// permitted and makes every independence claim unestablished, which is the
// honest answer when nothing is available to check lineage against.
func Run(set *FixtureSet, baseline, candidate Detector, reg *sourceregistry.Registry, opts ...RunOption) *Result {
	var cfg runConfig
	for _, o := range opts {
		o(&cfg)
	}
	r := &Result{
		Binding:           bindingFor(set, baseline, candidate, reg, cfg),
		FixtureSetID:      set.ID,
		FixtureSetVersion: set.Version,
		Partition:         set.Partition,
		Provenance:        set.Provenance,
		BaselineName:      baseline.Name(),
		CandidateName:     candidate.Name(),
		EvaluatedAt:       evaluationTime.UTC().Format(evaluationTimeLayout),
	}

	r.NotProtocolConformant = conformanceProblems(set, baseline, reg)

	for _, c := range set.Cases {
		e := resolve(c, reg)
		bd, br := baseline.Decide(e)
		cd, cr := candidate.Decide(e)

		res := CaseResult{
			CaseID:            c.ID,
			Value:             c.Value,
			Canonical:         e.Canonical,
			Family:            c.Family,
			Label:             c.Label,
			BaselineDecision:  bd,
			BaselineReason:    br,
			CandidateDecision: cd,
			CandidateReason:   cr,
			Additional:        cd == DecisionPropose && bd != DecisionPropose,

			InvalidObservations:  len(e.ObservationFailures),
			ObservationFailures:  e.ObservationFailures,
			ObservationsAccepted: e.ObservationsAccepted,
		}
		res.Outcome = outcomeOf(res)
		r.InvalidObservationCases += boolToInt(len(e.ObservationFailures) > 0)
		r.InvalidObservations += len(e.ObservationFailures)
		r.Cases = append(r.Cases, res)
		if bd != cd {
			r.Disagreements = append(r.Disagreements, res)
		}
	}

	// Appended AFTER the loop, because only the loop knows. This travels
	// inside the Result so that quoting a rate without it takes effort.
	if r.InvalidObservationCases > 0 {
		r.NotProtocolConformant = append(r.NotProtocolConformant, fmt.Sprintf(
			"%d case(s) declared %d observation(s) this harness could not resolve; "+
				"those cases are excluded from every rate below, so the denominators "+
				"are smaller than the fixture set and the result does not describe them",
			r.InvalidObservationCases, r.InvalidObservations))
		sort.Strings(r.NotProtocolConformant)
	}

	// The binding was captured before the first case. Everything it names is
	// still reachable by the caller while the loop runs, so it is re-captured
	// here and anything that moved is marked rather than reported as though
	// one configuration had been measured. See digestUnstable.
	reconfirm(&r.Binding, set, baseline, candidate, reg)

	r.Overall = metricsOver(r.Cases)
	r.ByFamily = stratify("family", r.Cases, set.Cases, func(c Case) string { return c.Family })
	r.ByType = stratify("type", r.Cases, set.Cases, func(c Case) string { return string(c.Type) })
	r.ByCategory = stratify("category", r.Cases, set.Cases, func(c Case) string {
		if c.Category == "" {
			return "(none)"
		}
		return c.Category
	})
	return r
}

// conformanceProblems lists every way a run falls short of the protocol.
//
// These are not warnings to be silenced. Each one is a reason a number from
// this run cannot be quoted as evidence of effectiveness, and they travel
// inside the Result so that quoting the number without them takes effort.
func conformanceProblems(set *FixtureSet, baseline Detector, reg *sourceregistry.Registry) []string {
	var out []string

	if set.Provenance == ProvenanceSynthetic {
		out = append(out, "the fixtures are synthetic and were written by this project, so agreement between them and this project's rule is not evidence about the world (EVALUATION_PROTOCOL.md §3)")
	}
	if _, isNull := baseline.(NullBaseline); isNull {
		out = append(out, "the baseline proposes nothing, so `additional` means `proposed at all` rather than `added on top of what the household runs` (EVALUATION_PROTOCOL.md §2.1)")
	}
	out = append(out, "labels were written alongside the rule under test rather than obtained from an independent labeller, which is the tautology §3 forbids")
	out = append(out, "no traffic was observed; recall here is against the fixtures present, never against scams in the world (EVALUATION_PROTOCOL.md §5.1)")
	if reg == nil {
		out = append(out, "no source registry was supplied, so every independence claim is unestablished")
	}
	if set.Partition == PartitionDevelopment {
		out = append(out, "this is the development partition; a result from it must not be quoted as a held-out result (EVALUATION_PROTOCOL.md §4)")
	}
	sort.Strings(out)
	return out
}

func outcomeOf(r CaseResult) string {
	switch r.CandidateDecision {
	case DecisionParseFailure:
		return "parse_failure"
	case DecisionUnsupported:
		return "unsupported"
	}
	// Checked after the two above, which are already distinct outcomes and
	// are the REASON observation resolution was never attempted. Checked
	// before everything else, so that a malformed observation can never
	// present as an ordinary pass, abstention or zero-support miss.
	if r.InvalidObservations > 0 {
		return "invalid_observation"
	}
	switch r.CandidateDecision {
	case DecisionAbstain:
		if r.Label == LabelMalicious {
			return "abstained_on_malicious"
		}
		return "abstained"
	case DecisionPropose:
		switch r.Label {
		case LabelMalicious:
			if r.Additional {
				return "true_positive_additional"
			}
			return "true_positive_already_covered"
		case LabelLegitimate:
			if r.Additional {
				return "false_positive_additional"
			}
			return "false_positive_already_covered"
		default:
			return "proposed_unlabelled"
		}
	default:
		switch r.Label {
		case LabelMalicious:
			return "false_negative"
		case LabelLegitimate:
			return "true_negative"
		default:
			return "passed_unlabelled"
		}
	}
}

func metricsOver(cases []CaseResult) Metrics {
	var c Counts
	for _, r := range cases {
		// A case whose evidence could not be fully resolved is counted here
		// and excluded from everything below. It is NOT a pass, NOT an
		// abstention and NOT a zero-support result: the harness does not know
		// what the rule would have decided on the evidence the fixture
		// actually declared, and a rate computed as though it did would be a
		// statement about the harness rather than about the rule.
		if r.InvalidObservations > 0 {
			c.InvalidObservationCases++
			continue
		}
		c.Cases++
		switch r.Label {
		case LabelMalicious:
			c.Labelled++
			c.LabelledMalicious++
		case LabelLegitimate:
			c.Labelled++
			c.LabelledLegitimate++
		default:
			c.Unlabelled++
		}

		if r.BaselineDecision == DecisionPropose {
			c.BaselineProposes++
		}

		switch r.CandidateDecision {
		case DecisionAbstain:
			c.Abstentions++
		case DecisionUnsupported:
			c.Unsupported++
		case DecisionParseFailure:
			c.ParseFailures++
		}

		if r.CandidateDecision == DecisionPropose {
			c.CandidateProposes++
			if r.Label == LabelMalicious {
				c.CandidateProposesMalicious++
			}
		}

		if r.Additional {
			c.AdditionalProposals++
			switch r.Label {
			case LabelMalicious:
				c.TruePositives++
			case LabelLegitimate:
				c.FalsePositives++
			default:
				c.UnlabelledProposals++
			}
		}

		// The two are deliberately asymmetric. A miss is any failure to
		// propose something harmful — abstaining on a scam is still not
		// catching it — whereas a true negative requires the rule to have
		// actually said `pass`. Crediting an abstention as a correct
		// negative would award a rule that decides nothing a perfect
		// false-positive rate and a clean sheet.
		switch {
		case r.Label == LabelMalicious && r.CandidateDecision != DecisionPropose:
			c.FalseNegatives++
		case r.Label == LabelLegitimate && r.CandidateDecision == DecisionPass:
			c.TrueNegatives++
		}
	}

	labelledProposals := c.TruePositives + c.FalsePositives
	return Metrics{
		Counts:            c,
		Precision:         newRate(c.TruePositives, labelledProposals, "labelled additional proposals"),
		Recall:            newRate(c.CandidateProposesMalicious, c.LabelledMalicious, "labelled-malicious cases"),
		Coverage:          newRate(c.Labelled, c.Cases, "cases"),
		FalsePositiveRate: newRate(c.FalsePositives, c.LabelledLegitimate, "labelled-legitimate cases"),
		FalseNegativeRate: newRate(c.FalseNegatives, c.LabelledMalicious, "labelled-malicious cases"),
		AbstentionRate:    newRate(c.Abstentions, c.Cases, "cases"),
	}
}

func stratify(kind string, results []CaseResult, cases []Case, key func(Case) string) []Stratum {
	byKey := map[string][]CaseResult{}
	index := map[string]Case{}
	for _, c := range cases {
		index[c.ID] = c
	}
	for _, r := range results {
		k := key(index[r.CaseID])
		byKey[k] = append(byKey[k], r)
	}

	names := make([]string, 0, len(byKey))
	for k := range byKey {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make([]Stratum, 0, len(names))
	for _, n := range names {
		out = append(out, Stratum{Kind: kind, Name: n, Metrics: metricsOver(byKey[n])})
	}
	return out
}

// Improved compares two runs over the same fixture set and says whether the
// second is better, worse, or not distinguishable.
//
// "Better" is a PAIR, per §5.2: more caught AND not more wrongly proposed.
// Being merely more aggressive is not an improvement, it is a setting, and a
// comparison that reported only the first half could be satisfied by one.
func Improved(before, after *Result) (better bool, why string) {
	// Comparability first, and by BINDING rather than by name. The superseded
	// implementation compared only the self-declared fixture id and version —
	// two strings the fixture file asserts about itself. Two different fixture
	// CONTENTS claiming the same id, two different baselines, two different
	// registries, two different partitions and two incompatible scoring
	// versions all compared as though they were the same measurement, and the
	// comparison would report an improvement. See comparableWith.
	if why, ok := comparableWith(before, after); !ok {
		return false, why
	}
	bt, at := before.Overall.Counts.TruePositives, after.Overall.Counts.TruePositives
	bf, af := before.Overall.Counts.FalsePositives, after.Overall.Counts.FalsePositives

	switch {
	case at > bt && af <= bf:
		return true, fmt.Sprintf("catches %d more (%d -> %d) at no additional cost in false proposals (%d -> %d)", at-bt, bt, at, bf, af)
	case at >= bt && af < bf:
		return true, fmt.Sprintf("proposes %d fewer legitimate cases (%d -> %d) without catching less (%d -> %d)", bf-af, bf, af, bt, at)
	case at < bt || af > bf:
		return false, fmt.Sprintf("catches %d (was %d) and wrongly proposes %d (was %d)", at, bt, af, bf)
	default:
		return false, fmt.Sprintf("no difference: %d caught, %d wrongly proposed in both", at, af)
	}
}
