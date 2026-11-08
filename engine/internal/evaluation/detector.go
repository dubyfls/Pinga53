// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/observation"
	"github.com/dubyfls/Pinga53/engine/internal/policy"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// Decision is what a configuration would do about a case.
type Decision string

// The decision vocabulary.
const (
	// DecisionPropose — the configuration would propose acting on it.
	DecisionPropose Decision = "propose"
	// DecisionPass — the configuration would leave it alone. An answer, and
	// the right one for most of the internet.
	DecisionPass Decision = "pass"
	// DecisionAbstain — the configuration declines to answer. Counted, never
	// folded into pass: a rule that abstains everywhere has zero recall and no
	// reportable precision, and a harness that scored abstention as "correctly
	// left alone" would award it a perfect false-positive rate.
	DecisionAbstain Decision = "abstain"
	// DecisionUnsupported — the configuration cannot assess this case at all,
	// because the indicator type is not implemented. Distinct from abstention:
	// abstaining is a choice about a case that was understood.
	DecisionUnsupported Decision = "unsupported"
	// DecisionParseFailure — the case value could not be canonicalised.
	// Reported as its own number, because a harness that swallowed parse
	// failures would report a rule as having passed on input it never saw.
	DecisionParseFailure Decision = "parse_failure"
)

// Assessed reports whether the decision is one the metrics can use.
func (d Decision) Assessed() bool { return d == DecisionPropose || d == DecisionPass }

// Evidence is everything the harness resolved about a case before handing it
// to a detector.
//
// Detectors receive this rather than the raw Case so that each of them sees
// exactly the same resolved inputs. A detector that canonicalised the value
// itself could differ from the one next to it for reasons that have nothing to
// do with the rule being compared.
type Evidence struct {
	Case Case
	// Canonical is the canonicalised value, empty when canonicalisation failed.
	Canonical string
	// CanonicalErr is why it failed, nil when it did not.
	CanonicalErr error
	// Unsupported is true when the indicator type is not implemented. Kept
	// apart from CanonicalErr because they are different facts: an
	// unsupported type means nothing assessed the value at all, and a value
	// nobody assessed has not been found malformed.
	Unsupported bool
	// Signals are what internal/domain observed about the written form.
	Signals []domain.Signal
	// Indicator holds the case's observations, when it carries any.
	Indicator observation.Indicator
	// Corroboration is what those observations support, assessed against the
	// registry supplied to the run.
	Corroboration observation.Corroboration
	// ObservationFailures is every fixture observation that could NOT be
	// resolved into the store, with the reason.
	//
	// It exists because the superseded implementation discarded them with a
	// bare `continue`. See resolve.
	ObservationFailures []ObservationFailure
	// ObservationsAccepted is how many did resolve, so that "some were lost"
	// can be told from "there were none".
	ObservationsAccepted int
}

// ObservationFailure is one fixture observation that could not be resolved.
//
// The fixture is caller-controlled, so Reason is built only from this
// project's own error vocabulary and is bounded; Index locates the
// observation without reproducing anything the fixture chose.
type ObservationFailure struct {
	// Index is the position in the case's observations array.
	Index int `json:"index"`
	// Stage is where it failed: "construct" or "store".
	Stage string `json:"stage"`
	// Reason is the bounded failure text.
	Reason string `json:"reason"`
}

// Detector is one configuration under comparison.
//
// Both the baseline and the candidate are detectors. Making them the same type
// is deliberate: a baseline that were a different kind of thing could not be
// held to the same definitions, and §2.1 of the protocol is largely about
// baselines that are not held to anything.
type Detector interface {
	// Name is how the configuration appears in a report. It must identify a
	// configuration somebody could reproduce, not describe one.
	Name() string
	// Decide answers for one case.
	Decide(Evidence) (Decision, string)
}

// --- baselines -----------------------------------------------------------

// NullBaseline proposes nothing at all.
//
// # This is not a protocol-conformant baseline and the harness says so
//
// docs/EVALUATION_PROTOCOL.md §2.1 requires the baseline to be the household's
// real configuration, named list by named list, because the question is
// whether ScamWall adds value ON TOP OF what is already running. Comparing
// against a configuration that blocks nothing answers "does this do anything",
// which has a known answer and is not the question.
//
// It exists because ScamWall has no deployed configuration to compare against
// yet, and a harness with no baseline at all could not be tested. Every report
// computed against it carries NotProtocolConformant, and the reason travels
// with the number rather than sitting in a document beside it.
type NullBaseline struct{}

// Name identifies the configuration.
func (NullBaseline) Name() string { return "null-baseline (proposes nothing)" }

// Decide always passes.
func (NullBaseline) Decide(Evidence) (Decision, string) {
	return DecisionPass, "the null baseline proposes nothing"
}

// ListDetector proposes exactly the canonical values it was given.
//
// This is the shape a real baseline has: a named list, pinned, whose contents
// are written down. It is also a perfectly good candidate, which is why it is
// one type rather than two.
// Member is one entry in a list: an indicator TYPE and a canonical value.
//
// The type is part of the key because a canonical string means nothing on its
// own. "192.0.2.1" as a domain and as an IPv4 address are different claims,
// and a list keyed by the string alone would answer for one when asked about
// the other.
type Member struct {
	Type      observation.Type `json:"type"`
	Canonical string           `json:"canonical"`
}

type ListDetector struct {
	Label   string
	Members map[Member]bool
}

// NewListDetector builds a detector from canonical DOMAIN values.
//
// It is the convenience form for the common case. Anything mixing indicator
// types must use NewTypedListDetector, so that the type is stated rather than
// assumed.
func NewListDetector(name string, values []string) *ListDetector {
	ms := make([]Member, 0, len(values))
	for _, v := range values {
		ms = append(ms, Member{Type: observation.TypeDomain, Canonical: v})
	}
	return NewTypedListDetector(name, ms)
}

// NewTypedListDetector builds a detector from typed members.
func NewTypedListDetector(name string, members []Member) *ListDetector {
	m := make(map[Member]bool, len(members))
	for _, v := range members {
		m[v] = true
	}
	return &ListDetector{Label: name, Members: m}
}

// Name identifies the configuration.
//
// # WHY THE DIGEST IS IN THE NAME
//
// The superseded Name was "label (N entries)". Two lists with the same label
// and the same COUNT but entirely different contents were indistinguishable
// in every report and in every stored result — so a result could be compared
// against another run of a "same" baseline that shared nothing with it. The
// digest is over the canonical typed membership, so the name changes when the
// list changes.
func (d *ListDetector) Name() string {
	return fmt.Sprintf("%s (%d entries, %s)", d.Label, len(d.proposing()), shortDigest(d.ConfigDigest()))
}

// proposing is the membership that actually decides anything: the keys whose
// value is true.
//
// # WHY THE VALUE IS NOT IGNORED
//
// Members is a map[Member]bool and Decide reads the VALUE — `if
// d.Members[...]`. The superseded ConfigDigest ranged over the map and
// digested the KEYS, so two detectors that decide differently digested
// identically:
//
//	A = {m: true}   digest over [m]   Decide(m) = propose
//	B = {m: false}  digest over [m]   Decide(m) = pass
//
// Same digest, same Name, opposite answer, and a stored result naming either
// one was indistinguishable from a result naming the other. A digest
// documented as covering "everything that changes what the detector decides"
// covered a set the detector does not decide from (FINDING-115).
//
// A false entry is excluded rather than encoded, because a false entry is
// exactly as decisive as an absent one: {m: false} and {} propose the same
// things and must therefore be the same configuration. Digesting the pairs
// would instead refuse a comparison between two lists that decide identically.
func (d *ListDetector) proposing() []Member {
	ms := make([]Member, 0, len(d.Members))
	for m, on := range d.Members {
		if on {
			ms = append(ms, m)
		}
	}
	return ms
}

// ConfigDigest is the list's identity: every member it would propose, typed,
// in a canonical order, and nothing else. The label is deliberately excluded —
// renaming a list does not change what it proposes.
func (d *ListDetector) ConfigDigest() string {
	ms := d.proposing()
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Type != ms[j].Type {
			return ms[i].Type < ms[j].Type
		}
		return ms[i].Canonical < ms[j].Canonical
	})
	return digestValue("list-detector", ms)
}

// Decide proposes membership.
func (d *ListDetector) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	if d.Members[Member{Type: e.Case.Type, Canonical: e.Canonical}] {
		return DecisionPropose, "on the list"
	}
	return DecisionPass, "not on the list"
}

// --- candidates ----------------------------------------------------------

// PolicyDetector is ScamWall's decision rule as it actually exists.
//
// It runs internal/policy.Decide over the case's feed claim and the signals
// internal/domain produced, so that what is measured here is the shipped rule
// rather than a restatement of it. A review disposition maps to abstention,
// which is what it is: the rule declines to propose and waits for a human.
type PolicyDetector struct{}

// Name identifies the configuration.
func (PolicyDetector) Name() string { return "scamwall-policy (internal/policy.Decide)" }

// Decide runs the shipped rule.
func (PolicyDetector) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	if e.Case.FeedClaim == nil {
		return DecisionAbstain, "no feed claim; this rule decides from what a feed asserts and there is nothing to decide from"
	}

	d, reason := policy.Decide(feed.Indicator{
		Domain:     domain.Domain(e.Canonical),
		Action:     e.Case.FeedClaim.Action,
		Confidence: e.Case.FeedClaim.Confidence,
		Category:   e.Case.FeedClaim.Category,
		Signals:    e.Signals,
	})
	switch d {
	case policy.DispositionPropose:
		return DecisionPropose, string(reason)
	case policy.DispositionReview:
		return DecisionAbstain, string(reason)
	default:
		return DecisionPass, string(reason)
	}
}

// CorroborationDetector proposes only what independent sources support.
//
// It exists so that the provenance model has something to be measured by. It
// is not proposed as a policy: the threshold below is a parameter of an
// experiment, not a tuned value, and nothing in ScamWall consumes it.
type CorroborationDetector struct {
	// MinIndependent is how many established-independent sources must assert
	// the indicator adversely.
	MinIndependent int
	// AcceptUnestablished counts sources whose independence is not
	// established. Setting it true is the inflation the registry exists to
	// prevent, and it is settable so that the harness can DEMONSTRATE the
	// inflation rather than merely assert it.
	AcceptUnestablished bool
}

// Name identifies the configuration, including its parameters, so that a
// number belongs to a configuration somebody can reproduce.
func (d CorroborationDetector) Name() string {
	return fmt.Sprintf("corroboration (min_independent=%d, accept_unestablished=%t)",
		d.MinIndependent, d.AcceptUnestablished)
}

// Decide counts adverse support.
func (d CorroborationDetector) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	if len(e.Case.Observations) == 0 {
		return DecisionAbstain, "no observations; this rule decides from provenance and there is none"
	}

	n := e.Corroboration.IndependentCount()
	if d.AcceptUnestablished {
		n += len(e.Corroboration.Unestablished)
	}
	// Only adverse classifications count towards a proposal. A source that
	// says benign, or that declines to say, is not support for acting.
	//
	// Counting is per SOURCE, not per record. Walking the entries and counting
	// each adverse one was the first version of this, and the harness's own
	// repeated-one-source fixture caught it: one noisy provider publishing the
	// same indicator under three record ids scored three, which is the exact
	// inflation the whole provenance model exists to prevent, reintroduced one
	// layer above it.
	eligible := map[string]bool{}
	for _, id := range append(append([]string(nil), e.Corroboration.Independent...), unestablishedIf(d.AcceptUnestablished, e.Corroboration)...) {
		eligible[id] = true
	}
	adverseSources := map[string]bool{}
	for _, entry := range e.Indicator.Current(evaluationTime) {
		o := entry.Observation
		if !eligible[o.SourceID] {
			continue
		}
		if o.Classification == observation.ClassMalicious || o.Classification == observation.ClassSuspicious {
			adverseSources[o.SourceID] = true
		}
	}
	adverse := len(adverseSources)
	if adverse < d.MinIndependent {
		return DecisionPass, fmt.Sprintf("%d adverse supporting source(s) of %d required (independent=%d, unestablished=%d)",
			adverse, d.MinIndependent, e.Corroboration.IndependentCount(), len(e.Corroboration.Unestablished))
	}
	return DecisionPropose, fmt.Sprintf("%d adverse supporting source(s) (independent=%d)", adverse, e.Corroboration.IndependentCount())
}

func unestablishedIf(on bool, c observation.Corroboration) []string {
	if !on {
		return nil
	}
	return c.Unestablished
}

// AlwaysPropose is a control. It exists so that the harness can be shown to
// FAIL a rule that marks everything malicious; a harness that cannot do that
// is not measuring anything.
type AlwaysPropose struct{}

// Name identifies the configuration.
func (AlwaysPropose) Name() string { return "control-always-propose" }

// Decide proposes everything it can parse.
func (AlwaysPropose) Decide(e Evidence) (Decision, string) {
	if e.Unsupported {
		return DecisionUnsupported, fmt.Sprintf("indicator type %q is not implemented", e.Case.Type)
	}
	if e.CanonicalErr != nil {
		return DecisionParseFailure, e.CanonicalErr.Error()
	}
	return DecisionPropose, "proposes everything"
}

// AlwaysAbstain is the other control: a rule that never commits. It must not
// receive a good score.
type AlwaysAbstain struct{}

// Name identifies the configuration.
func (AlwaysAbstain) Name() string { return "control-always-abstain" }

// Decide abstains on everything.
func (AlwaysAbstain) Decide(Evidence) (Decision, string) {
	return DecisionAbstain, "abstains on everything"
}

// evaluationTime is the instant every run is evaluated at.
//
// It is fixed rather than time.Now so that a fixture carrying an expiry
// produces the same result today and in a year. A run that moved with the
// clock would be a different measurement every time it was repeated, which is
// the opposite of what a regression harness is for.
var evaluationTime = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// EvaluationTime returns the instant runs are evaluated at.
func EvaluationTime() time.Time { return evaluationTime }

// resolve builds the Evidence for one case.
func resolve(c Case, reg *sourceregistry.Registry) Evidence {
	e := Evidence{Case: c}

	if c.Type.Supported() {
		a, err := domain.Assess(c.Value)
		if err != nil {
			e.CanonicalErr = err
		} else {
			e.Canonical = a.Domain.String()
			e.Signals = a.Signals()
		}
	} else {
		e.Unsupported = true
	}

	if len(c.Observations) == 0 || e.Canonical == "" {
		return e
	}

	store := observation.NewStore()
	for i, co := range c.Observations {
		o, err := observation.New(c.Type, c.Value, co.SourceID, evaluationTime)
		if err != nil {
			e.ObservationFailures = append(e.ObservationFailures,
				newObservationFailure(i, "construct", err))
			continue
		}
		o.SourceRecordID = co.SourceRecordID
		o.Classification = co.Classification
		o.State = co.State
		o.Status = co.Status
		if o.Status == "" {
			o.Status = observation.StatusCurrent
		}
		o.ExpiresAt = co.ExpiresAt
		if _, err := store.Add(o); err != nil {
			e.ObservationFailures = append(e.ObservationFailures,
				newObservationFailure(i, "store", err))
			continue
		}
		e.ObservationsAccepted++
	}
	if ind, ok := store.Lookup(observation.Key{Type: c.Type, Canonical: e.Canonical}); ok {
		e.Indicator = ind
		e.Corroboration = ind.Corroborate(reg, evaluationTime)
	}
	return e
}

// sortedFamilies returns the families present, in a stable order.
func sortedFamilies(cases []Case) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cases {
		if !seen[c.Family] {
			seen[c.Family] = true
			out = append(out, c.Family)
		}
	}
	sort.Strings(out)
	return out
}

// maxFailureReason bounds the failure text kept for one observation.
//
// The reason is built from this project's own error vocabulary, but those
// errors quote the offending field — and that field came from the fixture,
// which is caller-controlled. A bound here means one malformed observation
// cannot inflate a result document, and the report layer escapes what
// survives.
const maxFailureReason = 200

// newObservationFailure records one unresolvable observation.
//
// # WHY THIS EXISTS RATHER THAN A BARE continue
//
// The superseded resolve() discarded both failure paths with `continue`, and
// the consequences were not theoretical. Demonstrated against it:
//
//	a case labelled malicious, whose only two observations were both
//	invalid, resolved to zero entries, and the candidate returned
//	`pass` — scored as an ordinary FALSE NEGATIVE, indistinguishable
//	from a rule that simply missed it;
//
//	a case with one valid and one invalid observation was scored
//	`true_positive_additional` — the rule was CREDITED with a correct
//	answer computed from evidence the harness had silently thrown half
//	of away.
//
// Neither appeared in any count: parse_failures was 0. A measurement taken
// over evidence that was quietly discarded is not a measurement of the rule.
func newObservationFailure(index int, stage string, err error) ObservationFailure {
	reason := clipRunes(err.Error(), maxFailureReason)
	return ObservationFailure{Index: index, Stage: stage, Reason: reason}
}

// clipRunes truncates s to at most n bytes, never inside a rune.
//
// A byte slice would cut a multi-byte character in half and emit the fragment,
// which is how a bounded field becomes invalid UTF-8. See FINDING-89 for what
// invalid text costs this repository once it reaches a document.
func clipRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// ConfigDigest identifies the null baseline.
//
// It has no configuration, which is itself the fact worth binding: a result
// measured against it is measured against nothing.
func (NullBaseline) ConfigDigest() string { return digestValue("null-baseline", struct{}{}) }

// ConfigDigest identifies the policy detector.
//
// PolicyDetector has no parameters of its own — it defers to internal/policy.
// The digest therefore binds WHICH detector was used, not how it was tuned,
// and that is all there is to bind.
func (PolicyDetector) ConfigDigest() string { return digestValue("policy-detector", struct{}{}) }

// ConfigDigest identifies the corroboration detector by its parameters.
//
// Both fields change what it decides, so both are in the digest.
func (d CorroborationDetector) ConfigDigest() string {
	return digestValue("corroboration-detector", struct {
		MinIndependent      int  `json:"min_independent"`
		AcceptUnestablished bool `json:"accept_unestablished"`
	}{d.MinIndependent, d.AcceptUnestablished})
}
