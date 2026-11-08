// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestAFixtureFileIsBounded checks the loader does not read whatever it is
// pointed at.
func TestAFixtureFileIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	// A syntactically plausible file just over the bound.
	var b bytes.Buffer
	b.WriteString(`{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","provenance_note":"`)
	b.WriteString(strings.Repeat("a", MaxSetBytes))
	b.WriteString(`","partition":"development","baseline_id":"b","cases":[]}`)
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSet(path)
	if !errors.Is(err, ErrSetTooLarge) {
		t.Errorf("a %d-byte fixture file gave %v, want ErrSetTooLarge", b.Len(), err)
	}
}

// TestMalformedFixtureInputIsRefusedRatherThanPartiallyAccepted walks the
// parser's edges. Each of these must produce an error and no fixture set, so
// that a caller ignoring the error cannot act on a half-parsed one.
func TestMalformedFixtureInputIsRefusedRatherThanPartiallyAccepted(t *testing.T) {
	valid := `{"schema_version":1,"fixture_set_id":"x","version":"1","provenance":"synthetic","provenance_note":"n","partition":"development","baseline_id":"b","cases":[{"id":"a","type":"domain","value":"www.example.com","family":"f","label":"legitimate","label_basis":"b"}]}`
	if _, err := ParseSet([]byte(valid)); err != nil {
		t.Fatalf("the control fixture does not parse: %v", err)
	}

	for _, tc := range []struct{ name, input string }{
		{"empty", ""},
		{"not json", "this is not json"},
		{"a bare array", "[]"},
		{"truncated", valid[:len(valid)/2]},
		{"a second document appended", valid + valid},
		{"trailing junk", valid + " oops"},
		{"the wrong schema version", strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1)},
		{"a duplicated case id", strings.Replace(valid, `"cases":[`, `"cases":[{"id":"a","type":"domain","value":"other.example.com","family":"f","label":"legitimate","label_basis":"b"},`, 1)},
		{"an unrecognised label", strings.Replace(valid, `"label":"legitimate"`, `"label":"probably-bad"`, 1)},
		{"an unrecognised type", strings.Replace(valid, `"type":"domain"`, `"type":"wombat"`, 1)},
		{"a deeply nested value", `{"schema_version":1,"cases":` + strings.Repeat("[", 2000) + strings.Repeat("]", 2000) + `}`},
		{"an observation with no source", strings.Replace(valid, `"label_basis":"b"`, `"label_basis":"b","observations":[{"source_id":"","classification":"malicious","state":"active"}]`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := ParseSet([]byte(tc.input))
			if err == nil {
				t.Fatalf("accepted; parsed %d cases", len(set.Cases))
			}
			if set != nil {
				t.Error("an error was returned alongside a fixture set")
			}
		})
	}
}

// TestNumbersAreNeverReportedWithoutTheirDenominator is the property the whole
// report format rests on, checked over every rate in every stratum of a real
// run rather than over one hand-picked value.
func TestNumbersAreNeverReportedWithoutTheirDenominator(t *testing.T) {
	set := loadFixtures(t)
	for _, candidate := range []Detector{
		PolicyDetector{}, AlwaysPropose{}, AlwaysAbstain{},
		CorroborationDetector{MinIndependent: 2},
		NewListDetector("empty", nil),
	} {
		r := Run(set, NullBaseline{}, candidate, evalRegistry())
		all := []Stratum{{Kind: "overall", Name: "overall", Metrics: r.Overall}}
		all = append(all, r.ByFamily...)
		all = append(all, r.ByType...)
		all = append(all, r.ByCategory...)

		for _, s := range all {
			for name, rate := range map[string]Rate{
				"precision": s.Metrics.Precision, "recall": s.Metrics.Recall,
				"coverage": s.Metrics.Coverage, "fpr": s.Metrics.FalsePositiveRate,
				"fnr": s.Metrics.FalseNegativeRate, "abstention": s.Metrics.AbstentionRate,
			} {
				if !strings.Contains(rate.String(), "/") {
					t.Errorf("%s %s/%s renders as %q with no denominator", candidate.Name(), s.Name, name, rate.String())
				}
				if rate.Reportable {
					if rate.Denominator < MinReportableDenominator {
						t.Errorf("%s %s/%s reported a rate over %d observations", candidate.Name(), s.Name, name, rate.Denominator)
					}
					if rate.Value < rate.Lower || rate.Value > rate.Upper {
						t.Errorf("%s %s/%s: %.4f is outside [%.4f, %.4f]", candidate.Name(), s.Name, name, rate.Value, rate.Lower, rate.Upper)
					}
				}
				if rate.Numerator > rate.Denominator {
					t.Errorf("%s %s/%s: numerator %d exceeds denominator %d", candidate.Name(), s.Name, name, rate.Numerator, rate.Denominator)
				}
			}
		}
	}
}

// TestTheCountsAreInternallyConsistent checks the tallies against each other,
// for every detector, so that a change to one branch of the counting cannot
// quietly contradict another.
func TestTheCountsAreInternallyConsistent(t *testing.T) {
	set := loadFixtures(t)
	for _, candidate := range []Detector{
		PolicyDetector{}, AlwaysPropose{}, AlwaysAbstain{},
		CorroborationDetector{MinIndependent: 1},
		CorroborationDetector{MinIndependent: 2, AcceptUnestablished: true},
	} {
		r := Run(set, NullBaseline{}, candidate, evalRegistry())
		c := r.Overall.Counts
		name := candidate.Name()

		if c.Cases != len(set.Cases) {
			t.Errorf("%s: %d cases counted, %d present", name, c.Cases, len(set.Cases))
		}
		if c.Labelled+c.Unlabelled != c.Cases {
			t.Errorf("%s: labelled %d + unlabelled %d != cases %d", name, c.Labelled, c.Unlabelled, c.Cases)
		}
		if c.LabelledMalicious+c.LabelledLegitimate != c.Labelled {
			t.Errorf("%s: the labelled cases do not partition", name)
		}
		if c.TruePositives+c.FalsePositives+c.UnlabelledProposals != c.AdditionalProposals {
			t.Errorf("%s: TP %d + FP %d + unlabelled %d != additional %d",
				name, c.TruePositives, c.FalsePositives, c.UnlabelledProposals, c.AdditionalProposals)
		}
		if c.AdditionalProposals > c.CandidateProposes {
			t.Errorf("%s: %d additional proposals out of %d proposals", name, c.AdditionalProposals, c.CandidateProposes)
		}
		if c.CandidateProposesMalicious+c.FalseNegatives != c.LabelledMalicious {
			t.Errorf("%s: caught %d + missed %d != %d labelled-malicious",
				name, c.CandidateProposesMalicious, c.FalseNegatives, c.LabelledMalicious)
		}
		if c.TrueNegatives > c.LabelledLegitimate {
			t.Errorf("%s: %d true negatives over %d labelled-legitimate cases", name, c.TrueNegatives, c.LabelledLegitimate)
		}
		if c.Abstentions+c.Unsupported+c.ParseFailures > c.Cases {
			t.Errorf("%s: more non-decisions than cases", name)
		}
	}
}

// TestEveryCaseLandsInExactlyOneOutcome keeps a case from being counted twice
// or from vanishing between the cells.
func TestEveryCaseLandsInExactlyOneOutcome(t *testing.T) {
	set := loadFixtures(t)
	r := Run(set, NullBaseline{}, PolicyDetector{}, evalRegistry())

	seen := map[string]int{}
	byOutcome := map[string]int{}
	for _, c := range r.Cases {
		seen[c.CaseID]++
		byOutcome[c.Outcome]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("case %s appears %d times in the results", id, n)
		}
	}
	total := 0
	for _, n := range byOutcome {
		total += n
	}
	if total != len(set.Cases) {
		t.Errorf("%d outcomes recorded for %d cases", total, len(set.Cases))
	}
	t.Logf("outcomes: %v", byOutcome)
}

// TestTheReportSurvivesHostileFixtureContent checks the renderer cannot be
// broken, or used to break a terminal, by what a fixture says.
func TestTheReportSurvivesHostileFixtureContent(t *testing.T) {
	hostile := &FixtureSet{
		SchemaVersion: 1, ID: "hostile", Version: "1",
		Provenance: ProvenanceSynthetic, ProvenanceNote: "synthetic, written for this test",
		Partition: PartitionDevelopment, BaselineID: "none",
		Cases: []Case{
			{ID: "h1", Type: "domain", Value: strings.Repeat("a", 5000) + ".example.com", Family: "hostile", Label: LabelUnknown, LabelBasis: "n/a"},
			{ID: "h2", Type: "domain", Value: "\x1b[31mred\x1b[0m.example.com", Family: "hostile", Label: LabelUnknown, LabelBasis: "n/a"},
			{ID: "h3", Type: "domain", Value: "a\nb.example.com", Family: strings.Repeat("f", 400), Label: LabelUnknown, LabelBasis: "n/a"},
			{ID: "h4", Type: "domain", Value: "ex\u200bample.com", Family: "hostile", Label: LabelUnknown, LabelBasis: "n/a"},
		},
	}
	if problems := hostile.Validate(); len(problems) != 0 {
		t.Fatalf("the hostile set does not validate: %v", problems)
	}

	r := Run(hostile, NullBaseline{}, PolicyDetector{}, nil)

	var text bytes.Buffer
	r.Text(&text)
	if text.Len() == 0 {
		t.Fatal("the report is empty")
	}
	// A 5 KB value must not put 5 KB into the report.
	if strings.Contains(text.String(), strings.Repeat("a", 200)) {
		t.Error("the report echoed an unbounded value")
	}

	var j bytes.Buffer
	if err := r.JSON(&j); err != nil {
		t.Fatalf("the result does not encode: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(j.Bytes(), &round); err != nil {
		t.Errorf("the emitted JSON does not parse back: %v", err)
	}
}

// TestConcurrentRunsAreIndependent checks a run holds no shared state, so that
// two comparisons in flight cannot contaminate each other.
func TestConcurrentRunsAreIndependent(t *testing.T) {
	set := loadFixtures(t)
	reg := evalRegistry()

	want := func(d Detector) string {
		var b bytes.Buffer
		if err := Run(set, NullBaseline{}, d, reg).JSON(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	policyWant := want(PolicyDetector{})
	proposeWant := want(AlwaysPropose{})

	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := 0; i < 8; i++ {
		for _, tc := range []struct {
			d    Detector
			want string
		}{{PolicyDetector{}, policyWant}, {AlwaysPropose{}, proposeWant}} {
			wg.Add(1)
			go func(d Detector, want string) {
				defer wg.Done()
				var b bytes.Buffer
				if err := Run(set, NullBaseline{}, d, reg).JSON(&b); err != nil {
					errs <- err.Error()
					return
				}
				if b.String() != want {
					errs <- fmt.Sprintf("%s produced a different result under concurrency", d.Name())
				}
			}(tc.d, tc.want)
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestAnIntervalAlwaysContainsItsPointEstimate is the regression for
// FINDING-86.
//
// The Wilson interval contains the point estimate by construction. In floating
// point at p = 1 it did not: the algebra cancels to exactly 1 and the
// arithmetic returns 0.9999999999999999, so a recall of 1.000 was reported
// with an upper bound below it.
func TestAnIntervalAlwaysContainsItsPointEstimate(t *testing.T) {
	for n := 1; n <= 200; n++ {
		for _, k := range []int{0, 1, n / 2, n - 1, n} {
			if k < 0 || k > n {
				continue
			}
			lo, hi := wilson(k, n)
			p := float64(k) / float64(n)
			if p < lo || p > hi {
				t.Errorf("wilson(%d, %d) = [%.17f, %.17f] excludes %.17f", k, n, lo, hi, p)
			}
			if lo < 0 || hi > 1 {
				t.Errorf("wilson(%d, %d) = [%.17f, %.17f] leaves [0, 1]", k, n, lo, hi)
			}
			if lo > hi {
				t.Errorf("wilson(%d, %d) = [%.17f, %.17f] is inverted", k, n, lo, hi)
			}
		}
	}
}
