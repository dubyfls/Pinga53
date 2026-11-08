// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

const fixturePath = "testdata/synthetic-v1.json"

// evalRegistry is the synthetic registry the fixture set's source ids resolve
// against. It is built here rather than read from docs/source-registry.json
// on purpose: binding the harness's own tests to the shipped research record
// would make them fail whenever a real disposition changed, which is a change
// to evidence and not to this code.
func evalRegistry() *sourceregistry.Registry {
	mk := func(id, completeness string, deps []string) sourceregistry.Source {
		perms := map[sourceregistry.Operation]sourceregistry.Grant{}
		for _, op := range sourceregistry.AllOperations {
			perms[op] = sourceregistry.Grant{Status: sourceregistry.GrantUnknown}
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

func loadFixtures(t *testing.T) *FixtureSet {
	t.Helper()
	set, err := LoadSet(filepath.FromSlash(fixturePath))
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	return set
}

func TestTheShippedFixtureSetLoadsAndValidates(t *testing.T) {
	set := loadFixtures(t)
	if len(set.Cases) == 0 {
		t.Fatal("the fixture set is empty")
	}
	if set.Provenance != ProvenanceSynthetic {
		t.Errorf("provenance = %q; this set is written by this project and must say so", set.Provenance)
	}
	if set.Partition != PartitionDevelopment {
		t.Errorf("partition = %q; nothing here has been held out", set.Partition)
	}
	t.Logf("%s v%s: %d cases across %d families", set.ID, set.Version, len(set.Cases), len(sortedFamilies(set.Cases)))
}

// TestEveryRequiredFixtureFamilyIsPresent keeps the set from quietly losing
// coverage of a case the normalisation and provenance work exists to handle.
func TestEveryRequiredFixtureFamilyIsPresent(t *testing.T) {
	set := loadFixtures(t)
	present := map[string]bool{}
	for _, f := range sortedFamilies(set.Cases) {
		present[f] = true
	}
	for _, want := range []string{
		"ordinary-legitimate",
		"asserted-malicious",
		"syntactically-invalid",
		"internationalised-legitimate",
		"invisible-character",
		"mixed-script",
		"suspicious-looking-legitimate",
		"local-and-appliance",
		"repeated-one-source",
		"corroborated-independent",
		"aggregator-and-upstream",
		"unknown-lineage",
		"conflicting-classification",
		"expired-evidence",
		"withdrawn-evidence",
		"unsupported-type",
	} {
		if !present[want] {
			t.Errorf("fixture family %q is missing", want)
		}
	}
}

// TestAFixtureSetWithoutProvenanceIsRefused is the honesty gate on the input
// side. A set whose origin is unstated cannot be assessed for leakage or
// rights, and "we wrote it ourselves" is a fine answer that has to be given.
func TestAFixtureSetWithoutProvenanceIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, json string }{
		{"no provenance", `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance_note":"n","partition":"development","baseline_id":"b","cases":[{"id":"a","type":"domain","value":"www.example.com","family":"f","label":"legitimate","label_basis":"b"}]}`},
		{"no provenance note", `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","partition":"development","baseline_id":"b","cases":[{"id":"a","type":"domain","value":"www.example.com","family":"f","label":"legitimate","label_basis":"b"}]}`},
		{"no version", `{"schema_version":1,"fixture_set_id":"x","provenance":"synthetic","provenance_note":"n","partition":"development","baseline_id":"b","cases":[{"id":"a","type":"domain","value":"www.example.com","family":"f","label":"legitimate","label_basis":"b"}]}`},
		{"no baseline id", `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","provenance_note":"n","partition":"development","cases":[{"id":"a","type":"domain","value":"www.example.com","family":"f","label":"legitimate","label_basis":"b"}]}`},
		{"no label basis", `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","provenance_note":"n","partition":"development","baseline_id":"b","cases":[{"id":"a","type":"domain","value":"www.example.com","family":"f","label":"legitimate"}]}`},
		{"no family", `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","provenance_note":"n","partition":"development","baseline_id":"b","cases":[{"id":"a","type":"domain","value":"www.example.com","label":"legitimate","label_basis":"b"}]}`},
		{"an unknown field", `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","provenance_note":"n","partition":"development","baseline_id":"b","accuracy":0.99,"cases":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSet([]byte(tc.json)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// --- the controls the harness must be able to fail -----------------------

// TestARuleThatProposesEverythingFailsVisibly is the harness's own acceptance
// criterion. A harness that cannot fail this rule is not measuring anything.
func TestARuleThatProposesEverythingFailsVisibly(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, AlwaysPropose{}, evalRegistry())

	if !r.Overall.Precision.Reportable {
		t.Fatalf("precision was not reportable: %s", r.Overall.Precision)
	}
	if r.Overall.Precision.Value >= 0.6 {
		t.Errorf("a rule that proposes everything scored precision %s", r.Overall.Precision)
	}
	if r.Overall.Counts.FalsePositives < r.Overall.Counts.TruePositives {
		t.Errorf("proposing everything produced %d false positives against %d true; the harness is not seeing the cost",
			r.Overall.Counts.FalsePositives, r.Overall.Counts.TruePositives)
	}
	// The rule proposes every legitimate case it can parse. The ones it
	// cannot are the local and appliance names, and the gap between the two
	// counts must be exactly those rather than an unexplained shortfall.
	wantFP, unparseable := 0, 0
	for _, c := range r.Cases {
		if c.Label != LabelLegitimate {
			continue
		}
		if c.CandidateDecision == DecisionPropose {
			wantFP++
		} else {
			unparseable++
			if c.CandidateDecision != DecisionParseFailure && c.CandidateDecision != DecisionUnsupported {
				t.Errorf("case %s was neither proposed nor unparseable: %s", c.CaseID, c.CandidateDecision)
			}
		}
	}
	if r.Overall.Counts.FalsePositives != wantFP {
		t.Errorf("%d false positives recorded, %d legitimate cases were proposed", r.Overall.Counts.FalsePositives, wantFP)
	}
	if !r.Overall.FalsePositiveRate.Reportable {
		t.Errorf("false-positive rate %s was not reportable", r.Overall.FalsePositiveRate)
	}
	if r.Overall.FalsePositiveRate.Denominator != r.Overall.Counts.LabelledLegitimate {
		t.Errorf("FPR denominator is %d, want %d (all labelled-legitimate cases, including the ones the rule could not parse)",
			r.Overall.FalsePositiveRate.Denominator, r.Overall.Counts.LabelledLegitimate)
	}
	t.Logf("always-propose wrongly proposed %d of %d legitimate cases; %d it could not parse or does not support",
		wantFP, r.Overall.Counts.LabelledLegitimate, unparseable)
}

// TestARuleThatAbstainsOnEverythingGetsNoGoodScore is the other control. The
// failure mode it guards is a harness that scores abstention as "correctly
// left alone", which would award a do-nothing rule a perfect false-positive
// rate and a clean sheet.
func TestARuleThatAbstainsOnEverythingGetsNoGoodScore(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, AlwaysAbstain{}, evalRegistry())

	if r.Overall.Counts.Abstentions != r.Overall.Counts.Cases {
		t.Fatalf("%d abstentions over %d cases", r.Overall.Counts.Abstentions, r.Overall.Counts.Cases)
	}
	if r.Overall.Recall.Reportable && r.Overall.Recall.Value != 0 {
		t.Errorf("recall %s for a rule that decided nothing", r.Overall.Recall)
	}
	if r.Overall.Precision.Reportable {
		t.Errorf("precision %s was reported for a rule that made no proposals; there is no denominator", r.Overall.Precision)
	}
	if r.Overall.Counts.FalseNegatives != r.Overall.Counts.LabelledMalicious {
		t.Errorf("%d false negatives against %d labelled-malicious cases; declining to act on something harmful is a miss",
			r.Overall.Counts.FalseNegatives, r.Overall.Counts.LabelledMalicious)
	}
	if r.Overall.Counts.TrueNegatives != 0 {
		t.Errorf("%d true negatives were credited to a rule that never said `pass`", r.Overall.Counts.TrueNegatives)
	}
	t.Logf("always-abstain: recall %s, precision %s, FN %d",
		r.Overall.Recall, r.Overall.Precision, r.Overall.Counts.FalseNegatives)
}

// TestUnlabelledCasesAreNeverCountedAsNegative is the §5 rule that most
// directly manufactures a good number when broken.
func TestUnlabelledCasesAreNeverCountedAsNegative(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, AlwaysPropose{}, evalRegistry())
	c := r.Overall.Counts

	if c.Labelled+c.Unlabelled != c.Cases {
		t.Errorf("%d labelled + %d unlabelled != %d cases", c.Labelled, c.Unlabelled, c.Cases)
	}
	if c.LabelledMalicious+c.LabelledLegitimate != c.Labelled {
		t.Error("the labelled cases do not partition into malicious and legitimate")
	}
	if c.Unlabelled == 0 {
		t.Fatal("the fixture set has no unlabelled cases and cannot exercise this rule")
	}

	// Count the additional proposals by label directly from the case results,
	// and check the harness's own tallies against them. The rule proposes
	// everything it can parse, which is not everything, so the expectation is
	// derived rather than assumed.
	var proposedLabelled, proposedUnlabelled int
	for _, r := range r.Cases {
		if !r.Additional {
			continue
		}
		if r.Label == LabelUnknown {
			proposedUnlabelled++
		} else {
			proposedLabelled++
		}
	}
	if proposedUnlabelled == 0 {
		t.Fatal("no unlabelled case was proposed; this test cannot show that unlabelled proposals are excluded")
	}
	if got := c.TruePositives + c.FalsePositives; got != proposedLabelled {
		t.Errorf("precision denominator is %d, want %d; %d unlabelled proposals leaked into it",
			got, proposedLabelled, got-proposedLabelled)
	}
	if c.UnlabelledProposals != proposedUnlabelled {
		t.Errorf("%d unlabelled proposals recorded, %d were made", c.UnlabelledProposals, proposedUnlabelled)
	}
	if c.AdditionalProposals != proposedLabelled+proposedUnlabelled {
		t.Errorf("%d additional proposals recorded, %d were made", c.AdditionalProposals, proposedLabelled+proposedUnlabelled)
	}
	t.Logf("%d additional proposals: %d labelled (the precision denominator), %d unlabelled (excluded and reported)",
		c.AdditionalProposals, proposedLabelled, proposedUnlabelled)
}

// TestParseFailuresAndUnsupportedTypesAreReported keeps the harness from
// reporting a rule as having passed on input it never saw.
func TestParseFailuresAndUnsupportedTypesAreReported(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, PolicyDetector{}, evalRegistry())
	c := r.Overall.Counts

	if c.ParseFailures == 0 {
		t.Error("no parse failures were reported, but the set contains syntactically invalid cases")
	}
	if c.Unsupported == 0 {
		t.Error("no unsupported types were reported, but the set contains url, username and phone-number cases")
	}
	for _, s := range r.ByFamily {
		switch s.Name {
		case "syntactically-invalid":
			if s.Metrics.Counts.ParseFailures != s.Metrics.Counts.Cases {
				t.Errorf("syntactically-invalid: %d of %d cases reported as parse failures",
					s.Metrics.Counts.ParseFailures, s.Metrics.Counts.Cases)
			}
		case "unsupported-type":
			if s.Metrics.Counts.Unsupported != s.Metrics.Counts.Cases {
				t.Errorf("unsupported-type: %d of %d cases reported as unsupported",
					s.Metrics.Counts.Unsupported, s.Metrics.Counts.Cases)
			}
		}
	}
	t.Logf("policy detector: %d parse failures, %d unsupported", c.ParseFailures, c.Unsupported)
}

// --- metric definitions --------------------------------------------------

func TestWilsonIntervalsAreCorrectAndBounded(t *testing.T) {
	for _, tc := range []struct {
		successes, trials    int
		wantLower, wantUpper float64
	}{
		// Reference values for the Wilson score interval at 95%.
		{0, 100, 0.0000, 0.0370},
		{50, 100, 0.4038, 0.5962},
		{100, 100, 0.9630, 1.0000},
		{1, 10, 0.0179, 0.4041},
	} {
		lo, hi := wilson(tc.successes, tc.trials)
		if math.Abs(lo-tc.wantLower) > 0.001 || math.Abs(hi-tc.wantUpper) > 0.001 {
			t.Errorf("wilson(%d, %d) = [%.4f, %.4f], want [%.4f, %.4f]",
				tc.successes, tc.trials, lo, hi, tc.wantLower, tc.wantUpper)
		}
		if lo < 0 || hi > 1 || lo > hi {
			t.Errorf("wilson(%d, %d) = [%.4f, %.4f] is not a proportion interval", tc.successes, tc.trials, lo, hi)
		}
	}
}

// TestASmallStratumGetsCountsAndNoRate is §5.1's "no percentage over single
// digits" rule, enforced in code rather than in review.
func TestASmallStratumGetsCountsAndNoRate(t *testing.T) {
	small := newRate(3, 9, "labelled cases")
	if small.Reportable {
		t.Errorf("a rate was reported over 9 observations: %s", small)
	}
	if small.Numerator != 3 || small.Denominator != 9 {
		t.Error("the counts were lost along with the rate")
	}
	if !strings.Contains(small.String(), "3/9") {
		t.Errorf("the rendered form does not carry the counts: %q", small.String())
	}

	atThreshold := newRate(3, MinReportableDenominator, "labelled cases")
	if !atThreshold.Reportable {
		t.Errorf("a rate at the threshold was refused: %s", atThreshold)
	}

	none := newRate(0, 0, "labelled cases")
	if none.Reportable {
		t.Error("a rate was reported with no denominator")
	}
}

// TestARateNeverRendersWithoutItsDenominator is the rule that stops a number
// being quoted on its own.
func TestARateNeverRendersWithoutItsDenominator(t *testing.T) {
	for _, r := range []Rate{
		newRate(7, 10, "x"),
		newRate(0, 50, "x"),
		newRate(2, 3, "x"),
		newRate(0, 0, "x"),
	} {
		if !strings.Contains(r.String(), "/") {
			t.Errorf("%q does not show its denominator", r.String())
		}
	}
}

// TestCoverageBoundsTheOtherRates checks the relationship §5.1 insists on is
// actually true of what this package computes.
func TestCoverageBoundsTheOtherRates(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, PolicyDetector{}, evalRegistry())
	c := r.Overall.Counts

	if c.Labelled > c.Cases {
		t.Fatal("more labelled cases than cases")
	}
	if r.Overall.Coverage.Denominator != c.Cases {
		t.Errorf("coverage denominator is %d, want %d (all cases)", r.Overall.Coverage.Denominator, c.Cases)
	}
	if r.Overall.Recall.Denominator != c.LabelledMalicious {
		t.Errorf("recall denominator is %d, want %d (labelled-malicious cases, never `all scams`)",
			r.Overall.Recall.Denominator, c.LabelledMalicious)
	}
	if r.Overall.Precision.Denominator != c.TruePositives+c.FalsePositives {
		t.Errorf("precision denominator is %d, want %d (labelled ADDITIONAL proposals)",
			r.Overall.Precision.Denominator, c.TruePositives+c.FalsePositives)
	}
	t.Logf("coverage %s bounds precision %s and recall %s",
		r.Overall.Coverage, r.Overall.Precision, r.Overall.Recall)
}

// TestAdditionalMeansAdditional checks the set-difference semantics: a case
// the baseline already proposes cannot be an additional catch.
func TestAdditionalMeansAdditional(t *testing.T) {
	set := loadFixtures(t)
	var malicious []string
	for _, c := range set.Cases {
		if c.Label == LabelMalicious {
			malicious = append(malicious, c.Value)
		}
	}
	// A baseline that already covers every malicious case leaves the candidate
	// nothing to add, however good the candidate is.
	baseline := NewListDetector("covers-everything", malicious)
	r := Run(set, baseline, AlwaysPropose{}, evalRegistry())

	if r.Overall.Counts.TruePositives != 0 {
		t.Errorf("%d additional true positives against a baseline that already covers them all", r.Overall.Counts.TruePositives)
	}
	if r.Overall.Counts.CandidateProposesMalicious == 0 {
		t.Fatal("the candidate proposed none of them, so this test shows nothing")
	}
	if !r.Overall.Recall.Reportable || r.Overall.Recall.Value == 0 {
		t.Errorf("recall %s; recall is over all proposals, not only additional ones", r.Overall.Recall)
	}
}

// --- improvement and regression ------------------------------------------

// TestTheHarnessDetectsImprovementAndRegression is the harness's reason to
// exist. If it cannot tell a better rule from a worse one, it is decoration.
func TestTheHarnessDetectsImprovementAndRegression(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	var malicious, some []string
	for _, c := range set.Cases {
		if c.Label == LabelMalicious {
			malicious = append(malicious, c.Value)
		}
	}
	some = malicious[:len(malicious)/2]

	weak := Run(set, NullBaseline{}, NewListDetector("catches-half", some), reg)
	strong := Run(set, NullBaseline{}, NewListDetector("catches-all", malicious), reg)
	reckless := Run(set, NullBaseline{}, AlwaysPropose{}, reg)

	if better, why := Improved(weak, strong); !better {
		t.Errorf("catching more at no extra cost was not reported as an improvement: %s", why)
	}
	if better, why := Improved(strong, weak); better {
		t.Errorf("catching less was reported as an improvement: %s", why)
	}
	if better, why := Improved(strong, reckless); better {
		t.Errorf("proposing everything was reported as an improvement: %s", why)
	}
	if better, why := Improved(strong, strong); better {
		t.Errorf("a rule compared with itself was reported as an improvement: %s", why)
	}
}

// TestBeingMoreAggressiveIsNotAnImprovement is §5.2: the result is a pair, and
// a comparison satisfied by aggression alone would be worthless.
func TestBeingMoreAggressiveIsNotAnImprovement(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	var malicious, legitimate []string
	for _, c := range set.Cases {
		switch c.Label {
		case LabelMalicious:
			malicious = append(malicious, c.Value)
		case LabelLegitimate:
			legitimate = append(legitimate, c.Value)
		}
	}
	careful := Run(set, NullBaseline{}, NewListDetector("careful", malicious[:2]), reg)
	// Catches more AND wrongly proposes more.
	aggressive := Run(set, NullBaseline{}, NewListDetector("aggressive", append(append([]string(nil), malicious...), legitimate...)), reg)

	if aggressive.Overall.Counts.TruePositives <= careful.Overall.Counts.TruePositives {
		t.Fatal("the aggressive rule did not catch more; this test shows nothing")
	}
	if better, why := Improved(careful, aggressive); better {
		t.Errorf("catching more at a higher false-proposal cost was reported as an improvement: %s", why)
	}
}

// TestRunsAreDeterministic is what makes a regression harness a regression
// harness rather than a random number generator.
func TestRunsAreDeterministic(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	render := func() string {
		var b bytes.Buffer
		r := Run(set, NullBaseline{}, PolicyDetector{}, reg)
		if err := r.JSON(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	want := render()
	for i := 0; i < 10; i++ {
		if got := render(); got != want {
			t.Fatalf("run %d differs from run 0", i)
		}
	}
}

// TestTheResultCarriesItsOwnCaveats keeps a number from being liftable out of
// its context.
func TestTheResultCarriesItsOwnCaveats(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, PolicyDetector{}, evalRegistry())

	if len(r.NotProtocolConformant) == 0 {
		t.Fatal("a synthetic run against a null baseline reported no conformance problems")
	}
	joined := strings.Join(r.NotProtocolConformant, " ")
	for _, want := range []string{"synthetic", "baseline proposes nothing", "independent labeller", "development partition"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the caveats do not mention %q: %v", want, r.NotProtocolConformant)
		}
	}

	var b bytes.Buffer
	r.Text(&b)
	out := b.String()
	if !strings.Contains(out, "WHAT THIS RESULT IS NOT") {
		t.Error("the operator report does not lead with its caveats")
	}
	if strings.Index(out, "WHAT THIS RESULT IS NOT") > strings.Index(out, "RATES") {
		t.Error("the caveats appear after the numbers")
	}
}

func TestTheResultIsReproducibleFromItsOwnOutput(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, PolicyDetector{}, evalRegistry())

	if r.FixtureSetID == "" || r.FixtureSetVersion == "" {
		t.Error("the result does not name the fixture set it was computed from")
	}
	if r.BaselineName == "" || r.CandidateName == "" {
		t.Error("the result does not name the configurations it compared")
	}
	if len(r.Cases) != len(set.Cases) {
		t.Errorf("the result carries %d case results for %d cases", len(r.Cases), len(set.Cases))
	}
	for _, c := range r.Cases {
		if c.Outcome == "" {
			t.Errorf("case %s has no recorded outcome", c.CaseID)
		}
		if c.CandidateReason == "" {
			t.Errorf("case %s records a decision with no reason", c.CaseID)
		}
	}
}

// TestProvenanceCatchesWhatTheFeedClaimAlone DoesNot is the demonstration the
// provenance model was built for, measured rather than asserted.
//
// The shipped rule decides from what a feed asserts. Every case in the
// provenance families below carries a high-confidence block claim, and every
// one of them is stipulated legitimate, because the support behind the claim
// is not what it appears: one noisy source reporting three times, an
// aggregator counted alongside the feed it copies, two sources whose lineage
// nobody has documented, evidence that has lapsed, evidence that was
// withdrawn, and ids that resolve to nothing. A rule that reads only the claim
// proposes all of them.
func TestProvenanceCatchesWhatTheFeedClaimAloneDoesNot(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	claimOnly := Run(set, NullBaseline{}, PolicyDetector{}, reg)
	withProvenance := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, reg)

	provenanceFamilies := map[string]bool{
		"repeated-one-source": true, "aggregator-and-upstream": true,
		"unknown-lineage": true, "expired-evidence": true,
		"withdrawn-evidence": true, "unresolvable-source": true,
	}
	countFP := func(r *Result) int {
		n := 0
		for _, c := range r.Cases {
			if provenanceFamilies[c.Family] && c.Label == LabelLegitimate && c.CandidateDecision == DecisionPropose {
				n++
			}
		}
		return n
	}

	before, after := countFP(claimOnly), countFP(withProvenance)
	if before == 0 {
		t.Fatal("the claim-only rule proposed none of the provenance cases; this test shows nothing")
	}
	if after >= before {
		t.Errorf("reading provenance did not reduce false proposals on these families: %d -> %d", before, after)
	}
	t.Logf("false proposals on the provenance families: claim-only %d, corroboration-aware %d", before, after)

	// And it must not have bought that by catching less.
	if withProvenance.Overall.Counts.TruePositives == 0 {
		t.Error("the corroboration rule caught nothing; a rule that proposes nothing is not an improvement")
	}
}

// TestAcceptingUndocumentedLineageReintroducesTheFalsePositive measures the
// inflation the registry exists to prevent, rather than asserting it.
//
// The only difference between the two configurations is whether sources with
// undocumented upstreams are counted towards independence. Everything else is
// identical, so any difference in the numbers is that decision and nothing
// else.
func TestAcceptingUndocumentedLineageReintroducesTheFalsePositive(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	strict := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, reg)
	loose := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2, AcceptUnestablished: true}, reg)

	find := func(r *Result, id string) CaseResult {
		for _, c := range r.Cases {
			if c.CaseID == id {
				return c
			}
		}
		t.Fatalf("case %s is missing from the result", id)
		return CaseResult{}
	}

	if got := find(strict, "corr-006").CandidateDecision; got != DecisionPass {
		t.Errorf("strict: two undocumented-lineage sources produced %s, want pass", got)
	}
	if got := find(loose, "corr-006").CandidateDecision; got != DecisionPropose {
		t.Errorf("loose: counting undocumented lineage as independence did not produce the inflated proposal (%s); this test cannot show the cost", got)
	}
	if loose.Overall.Counts.FalsePositives <= strict.Overall.Counts.FalsePositives {
		t.Errorf("counting unknown upstreams as independence cost nothing: %d -> %d false positives",
			strict.Overall.Counts.FalsePositives, loose.Overall.Counts.FalsePositives)
	}
	if better, why := Improved(strict, loose); better {
		t.Errorf("the inflated configuration was reported as an improvement: %s", why)
	}
	t.Logf("false positives: strict %d, counting-unknown-lineage %d",
		strict.Overall.Counts.FalsePositives, loose.Overall.Counts.FalsePositives)
}

// TestTheNullBaselineIsFlaggedAndANamedListIsNot keeps the honesty flag from
// being permanently on, which would make it decoration.
func TestTheNullBaselineIsFlaggedAndANamedListIsNot(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	withNull := Run(set, NullBaseline{}, PolicyDetector{}, reg)
	withList := Run(set, NewListDetector("household-lists-v1", []string{"www.example.com"}), PolicyDetector{}, reg)

	hasNullWarning := func(r *Result) bool {
		for _, w := range r.NotProtocolConformant {
			if strings.Contains(w, "baseline proposes nothing") {
				return true
			}
		}
		return false
	}
	if !hasNullWarning(withNull) {
		t.Error("the null baseline was not flagged")
	}
	if hasNullWarning(withList) {
		t.Error("a named list baseline was flagged as proposing nothing")
	}
	// The synthetic and independent-labeller warnings are properties of the
	// fixtures and must survive either baseline.
	if len(withList.NotProtocolConformant) == 0 {
		t.Error("a named baseline silenced every caveat, including the ones about the fixtures")
	}
}

// TestOneNoisySourceIsNotThreeVoices is the regression for FINDING-84, which
// the harness found in its own corroboration detector.
//
// corr-004 is one source publishing the same indicator under three record ids.
// The store holds three entries, correctly — they are three records — but
// corroboration is a count of SOURCES, and the first version of this detector
// walked the entries. One noisy provider scored three, which is the inflation
// the provenance model exists to prevent, reintroduced one layer above it.
func TestOneNoisySourceIsNotThreeVoices(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, reg)

	var got CaseResult
	for _, c := range r.Cases {
		if c.CaseID == "corr-004" {
			got = c
		}
	}
	if got.CaseID == "" {
		t.Fatal("corr-004 is missing from the fixture set")
	}
	if got.CandidateDecision == DecisionPropose {
		t.Errorf("one source reporting three times reached %s (%s); repeats from one provider are one voice",
			got.CandidateDecision, got.CandidateReason)
	}

	// The three records are still all held. The fix is to the counting, not to
	// the store, and losing two of them would be a different defect.
	e := resolve(set.Cases[indexOfCase(t, set, "corr-004")], reg)
	if n := len(e.Indicator.Current(EvaluationTime())); n != 3 {
		t.Errorf("%d records held for corr-004, want 3; the fix must not discard records", n)
	}
	if n := e.Corroboration.SupportingCount(); n != 1 {
		t.Errorf("supporting count = %d, want 1", n)
	}
}

func indexOfCase(t *testing.T, set *FixtureSet, id string) int {
	t.Helper()
	for i, c := range set.Cases {
		if c.ID == id {
			return i
		}
	}
	t.Fatalf("case %s not found", id)
	return -1
}
