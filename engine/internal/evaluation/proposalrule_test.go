// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # ORDER 6 STAGE G — THE REGRESSION EVALUATION
//
// The candidate is measured against the current policy baseline and four
// controls, over synthetic fixtures, at a bound instant, under a bound
// registry and a bound policy.
//
// WHAT THESE NUMBERS ARE. Regression evidence: a change to the rule either
// moves them or does not. Nothing more. The fixtures were written by the same
// project that wrote the rule, which is the tautology
// docs/EVALUATION_PROTOCOL.md §3 exists to forbid, and every report this
// package emits says so in its own output.
//
// WHAT THEY ARE NOT. Held-out validity, real-world effectiveness, or evidence
// of production readiness. No claim of any of those is made here or anywhere
// this file's output is quoted.

const suffixFixturePath = "testdata/suffix-confusion-v1.json"

// proposalEvalRegistry is a registry whose grants PERMIT the operations the
// proposal rule performs.
//
// evalRegistry above grants everything `unknown`, which is correct for what it
// was written for — the detectors there consult independence and never rights
// — and would refuse every indicator here on rights grounds. Two registries
// rather than one loosened registry: relaxing evalRegistry would change what
// the existing detectors are measured against, and this file has no business
// doing that.
func proposalEvalRegistry() *sourceregistry.Registry {
	grant := sourceregistry.Grant{
		Status: sourceregistry.GrantPermitted,
		Evidence: sourceregistry.Evidence{
			ProviderTerms: []sourceregistry.Citation{{
				URL:       "https://example.com/terms",
				CheckedOn: "2026-01-01",
				Quote:     "synthetic terms written for this test suite",
			}},
		},
	}
	mk := func(id, completeness string, deps []string) sourceregistry.Source {
		perms := map[sourceregistry.Operation]sourceregistry.Grant{}
		for _, op := range sourceregistry.AllOperations {
			perms[op] = grant
		}
		return sourceregistry.Source{
			SourceID:                    id,
			UpstreamSourcesCompleteness: completeness,
			AggregationDependencies:     deps,
			Permissions:                 perms,
		}
	}
	return &sourceregistry.Registry{SchemaVersion: 2, Sources: []sourceregistry.Source{
		mk("eval-src-A", sourceregistry.UpstreamDocumentedComplete, nil),
		mk("eval-src-B", sourceregistry.UpstreamDocumentedComplete, nil),
		mk("eval-src-AGG", sourceregistry.UpstreamDocumentedComplete, []string{"eval-src-A"}),
		mk("eval-src-U1", sourceregistry.UpstreamUnknown, nil),
		mk("eval-src-U2", sourceregistry.UpstreamUnknown, nil),
	}}
}

func evalPolicy(t *testing.T) *proposal.Policy {
	t.Helper()
	p, err := proposal.ParsePolicy([]byte(`{
		"schema_version": 1,
		"note": "ORDER 6 Stage G evaluation policy; synthetic",
		"min_independent_sources": 2,
		"proposal_scope": "exact",
		"accept_unestablished_independence": false
	}`))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

// listedNames are the names a list-shaped rule holds: the twelve malicious
// apexes of the suffix fixture and nothing else.
func listedNames() []string {
	out := make([]string, 0, 12)
	for i := 1; i <= 12; i++ {
		out = append(out, fmt.Sprintf("bad-%02d.example.com", i))
	}
	return out
}

// TestEveryProposalReasonIsMapped fails when a reason is added to
// internal/proposal without a decision being taken about how it scores.
//
// The alternative is a reason silently falling into one column, which is how a
// rule acquires a measurement nobody chose.
func TestEveryProposalReasonIsMapped(t *testing.T) {
	// Reasons that belong to RECORD admission never reach an outcome, so they
	// are not in the table and must not be.
	recordOnly := map[proposal.Reason]bool{
		proposal.ReasonValueInvalid: true, proposal.ReasonTypeUnknown: true,
		proposal.ReasonTypeUnsupported: true, proposal.ReasonSignerNotAuthorised: true,
		proposal.ReasonSourceUnknown: true, proposal.ReasonSourceRetired: true,
		proposal.ReasonStorageRefused: true, proposal.ReasonRawRefused: true,
		proposal.ReasonRecordInvalid: true,
	}
	for _, r := range proposal.AllReasons {
		switch {
		// Both PROPOSAL reasons. They are handled before the table — a
		// proposal is scored as a proposal whatever justified it — so being
		// IN the table would be the defect, not being absent from it.
		case r == proposal.ReasonCorroborated, r == proposal.ReasonAuthoritativeSource:
			if _, ok := proposalOutcomeToDecision[r]; ok {
				t.Errorf("%s is a PROPOSAL and must not be in the non-proposal table", r)
			}
		case recordOnly[r]:
			if _, ok := proposalOutcomeToDecision[r]; ok {
				t.Errorf("%s is a record-admission reason and never reaches an outcome", r)
			}
		default:
			if _, ok := proposalOutcomeToDecision[r]; !ok {
				t.Errorf("%s has no scoring rule; decide whether it is an answer or a "+
					"declination before it can be measured", r)
			}
		}
	}
}

// TestTheSuffixFixtureLoadsAndSaysWhatItIs.
func TestTheSuffixFixtureLoadsAndSaysWhatItIs(t *testing.T) {
	set, err := LoadSet(suffixFixturePath)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if set.Provenance != ProvenanceSynthetic {
		t.Errorf("provenance = %q; this set was written by this project and must say so", set.Provenance)
	}
	if set.Partition != PartitionDevelopment {
		t.Errorf("partition = %q; nothing here has been held out", set.Partition)
	}
	if len(set.Cases) != 36 {
		t.Errorf("cases = %d, want 36", len(set.Cases))
	}
}

// TestTheDefectiveMatchingRuleIsCaught is the point of the whole stage.
//
// NaiveSuffixRule and ExactLabelRule hold THE SAME twelve names and differ in
// one thing: whether the match is required to end at a label boundary. If the
// harness cannot separate them, it is not measuring matching.
func TestTheDefectiveMatchingRuleIsCaught(t *testing.T) {
	set, err := LoadSet(suffixFixturePath)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	reg := proposalEvalRegistry()

	exact := ExactLabelRule{Members: listedNames(), Label: "exact-only"}
	naive := NaiveSuffixRule{Members: listedNames(), Label: "defective-suffix"}

	good := Run(set, NullBaseline{}, exact, reg, WithSourceCommit(canonicalCommit))
	bad := Run(set, NullBaseline{}, naive, reg, WithSourceCommit(canonicalCommit))

	gf, bf := good.Overall.Counts.FalsePositives, bad.Overall.Counts.FalsePositives
	if gf != 0 {
		t.Errorf("the exact rule wrongly proposed %d legitimate case(s); the fixture's "+
			"siblings are not on its list", gf)
	}
	if bf != 12 {
		t.Errorf("the defective rule wrongly proposed %d legitimate case(s), want 12 — "+
			"one per sibling. The harness is not separating the two rules", bf)
	}

	// And Improved must say so, in the direction that matters: more aggression
	// bought with false proposals is not an improvement.
	better, why := Improved(good, bad)
	if better {
		t.Errorf("replacing label matching with suffix matching was reported as an "+
			"improvement: %s", why)
	}
	t.Logf("exact -> defective: %s", why)
}

// TestTheControlsBehaveLikeControls.
//
// always-propose must be punished for proposing everything, always-abstain
// must be given nothing for deciding nothing, and neither may come out ahead
// of a rule that answers.
func TestTheControlsBehaveLikeControls(t *testing.T) {
	set, err := LoadSet(suffixFixturePath)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	reg := proposalEvalRegistry()
	candidate := ProposalRule{Policy: evalPolicy(t), Registry: reg, Label: "provenance-aware"}

	cand := Run(set, NullBaseline{}, candidate, reg, WithSourceCommit(canonicalCommit))
	propose := Run(set, NullBaseline{}, AlwaysPropose{}, reg, WithSourceCommit(canonicalCommit))
	abstain := Run(set, NullBaseline{}, AlwaysAbstain{}, reg, WithSourceCommit(canonicalCommit))

	if propose.Overall.Counts.FalsePositives != 12 {
		t.Errorf("always-propose wrongly proposed %d of the 12 legitimate cases",
			propose.Overall.Counts.FalsePositives)
	}
	if abstain.Overall.Counts.TruePositives != 0 {
		t.Errorf("always-abstain was credited with %d catches", abstain.Overall.Counts.TruePositives)
	}
	if abstain.Overall.Counts.FalsePositives != 0 {
		t.Errorf("always-abstain was charged %d false proposals", abstain.Overall.Counts.FalsePositives)
	}

	if better, why := Improved(cand, propose); better {
		t.Errorf("always-propose was reported as an improvement on the candidate: %s", why)
	}
	if better, why := Improved(cand, abstain); better {
		t.Errorf("always-abstain was reported as an improvement on the candidate: %s", why)
	}

	// The candidate must actually catch something, or every assertion above
	// holds vacuously.
	if cand.Overall.Counts.TruePositives == 0 {
		t.Error("the candidate caught nothing; the comparisons above are vacuous")
	}
	if cand.Overall.Counts.FalsePositives != 0 {
		t.Errorf("the candidate wrongly proposed %d legitimate case(s)",
			cand.Overall.Counts.FalsePositives)
	}
	t.Logf("candidate: %d caught, %d wrongly proposed, %d abstained",
		cand.Overall.Counts.TruePositives, cand.Overall.Counts.FalsePositives,
		cand.Overall.Counts.Abstentions)
}

// TestTheProvenanceAwareCandidateOnTheMainFixtureSet runs the candidate over
// the fixture set the earlier orders built, which carries the families this
// rule is about — corroboration, aggregation, expiry, withdrawal, conflict,
// invisible characters, mixed script, unresolvable sources.
func TestTheProvenanceAwareCandidateOnTheMainFixtureSet(t *testing.T) {
	set := loadFixtures(t)
	reg := proposalEvalRegistry()
	candidate := ProposalRule{Policy: evalPolicy(t), Registry: reg, Label: "provenance-aware"}

	r := Run(set, NullBaseline{}, candidate, reg, WithSourceCommit(canonicalCommit))

	if ok, missing := r.Reproducible(); !ok {
		t.Errorf("the run does not carry every binding needed to reproduce it: %v", missing)
	}
	if len(r.NotProtocolConformant) == 0 {
		t.Error("a run over synthetic fixtures against a null baseline reported no " +
			"conformance problems; the caveats must travel with the numbers")
	}
	if r.Overall.Counts.TruePositives == 0 {
		t.Error("the candidate caught nothing on the main fixture set")
	}
	if r.Overall.Counts.FalsePositives != 0 {
		t.Errorf("the candidate wrongly proposed %d legitimate case(s) on the main set",
			r.Overall.Counts.FalsePositives)
	}

	var b strings.Builder
	r.Text(&b)
	// The text report wraps, so the comparison is over collapsed whitespace:
	// asserting on the exact line breaks would be asserting on the wrap width.
	out := strings.Join(strings.Fields(b.String()), " ")
	for _, want := range []string{
		"the fixtures are synthetic and were written by this project",
		"not evidence about the world",
		"which is the tautology",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not carry the caveat %q", want)
		}
	}
	t.Logf("main set: %d caught, %d wrongly proposed, %d abstained, %d unsupported",
		r.Overall.Counts.TruePositives, r.Overall.Counts.FalsePositives,
		r.Overall.Counts.Abstentions, r.Overall.Counts.Unsupported)
}

// TestIncomparableMeasurementsAreStillRefusedOnTheNewRule.
//
// The binding machinery Stage A corrected has to hold for the new detectors
// too, or a comparison between two policies over two fixture sets would report
// an improvement.
func TestIncomparableMeasurementsAreStillRefusedOnTheNewRule(t *testing.T) {
	main := loadFixtures(t)
	suffix, err := LoadSet(suffixFixturePath)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	reg := proposalEvalRegistry()
	candidate := ProposalRule{Policy: evalPolicy(t), Registry: reg, Label: "provenance-aware"}

	a := Run(main, NullBaseline{}, candidate, reg, WithSourceCommit(canonicalCommit))
	b := Run(suffix, NullBaseline{}, candidate, reg, WithSourceCommit(canonicalCommit))

	if better, why := Improved(a, b); better {
		t.Errorf("two runs over DIFFERENT fixture sets were compared: %s", why)
	} else if !strings.Contains(why, "fixture") {
		t.Errorf("the refusal does not name the fixture difference: %s", why)
	}

	// A different registry is the other half.
	other := proposalEvalRegistry()
	other.Sources = other.Sources[:2]
	c := Run(main, NullBaseline{}, candidate, other, WithSourceCommit(canonicalCommit))
	if better, why := Improved(a, c); better {
		t.Errorf("two runs under different registries were compared: %s", why)
	}
}

// TestTwoPoliciesOverOneFixtureSetAreComparable is the positive control for
// the above: a tightening that refused every comparison would satisfy it, and
// comparing two policies is the operation this stage exists to perform.
func TestTwoPoliciesOverOneFixtureSetAreComparable(t *testing.T) {
	set, err := LoadSet(suffixFixturePath)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	reg := proposalEvalRegistry()

	strict, err := proposal.ParsePolicy([]byte(
		`{"schema_version":1,"min_independent_sources":2,"proposal_scope":"exact"}`))
	if err != nil {
		t.Fatal(err)
	}
	loose, err := proposal.ParsePolicy([]byte(
		`{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact"}`))
	if err != nil {
		t.Fatal(err)
	}

	a := Run(set, NullBaseline{},
		ProposalRule{Policy: strict, Registry: reg, Label: "min-2"}, reg,
		WithSourceCommit(canonicalCommit))
	b := Run(set, NullBaseline{},
		ProposalRule{Policy: loose, Registry: reg, Label: "min-1"}, reg,
		WithSourceCommit(canonicalCommit))

	if a.Binding.CandidateDigest == b.Binding.CandidateDigest {
		t.Fatal("two different policies produced the same candidate digest; the policy " +
			"is not bound and the comparison below would be between two identical things")
	}
	if why, ok := comparableWith(a, b); !ok {
		t.Fatalf("two policies over one fixture set were refused: %s", why)
	}
	better, why := Improved(a, b)
	t.Logf("min_independent_sources 2 -> 1: better=%v, %s", better, why)
}

// TestTheEvaluationReportsCanBeWritten emits the Stage G reports when
// SCAMWALL_EVAL_OUT names a directory, so the review package can carry them
// without a second harness being written to produce them.
//
// Off by default: a test that wrote files on every run would be a test with a
// side effect nobody asked for.
func TestTheEvaluationReportsCanBeWritten(t *testing.T) {
	dir := os.Getenv("SCAMWALL_EVAL_OUT")
	if dir == "" {
		t.Skip("SCAMWALL_EVAL_OUT is not set; nothing is written")
	}
	reg := proposalEvalRegistry()
	policy := evalPolicy(t)

	main := loadFixtures(t)
	suffix, err := LoadSet(suffixFixturePath)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}

	runs := []struct {
		name      string
		set       *FixtureSet
		candidate Detector
	}{
		{"main-provenance-aware", main, ProposalRule{Policy: policy, Registry: reg, Label: "provenance-aware"}},
		{"main-always-propose", main, AlwaysPropose{}},
		{"main-always-abstain", main, AlwaysAbstain{}},
		{"suffix-provenance-aware", suffix, ProposalRule{Policy: policy, Registry: reg, Label: "provenance-aware"}},
		{"suffix-exact-only", suffix, ExactLabelRule{Members: listedNames(), Label: "exact-only"}},
		{"suffix-defective-matching", suffix, NaiveSuffixRule{Members: listedNames(), Label: "defective-suffix"}},
		{"suffix-always-propose", suffix, AlwaysPropose{}},
		{"suffix-always-abstain", suffix, AlwaysAbstain{}},
	}
	for _, r := range runs {
		res := Run(r.set, NullBaseline{}, r.candidate, reg, WithSourceCommit(canonicalCommit))
		writeEval(t, dir, r.name+".txt", func(f *os.File) { res.Text(f) })
		writeEval(t, dir, r.name+".json", func(f *os.File) {
			if err := res.JSON(f); err != nil {
				t.Errorf("JSON: %v", err)
			}
		})
	}
}

func writeEval(t *testing.T, dir, name string, write func(*os.File)) {
	t.Helper()
	f, err := os.Create(dir + "/" + name) //nolint:gosec // an explicit directory from the environment
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close %s: %v", name, err)
		}
	}()
	write(f)
}
