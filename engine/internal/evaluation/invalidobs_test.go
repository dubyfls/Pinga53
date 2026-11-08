// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"strings"
	"testing"
)

// dropSet is the fixture the pre-fix control was demonstrated against.
//
// Every observation below is syntactically well-formed JSON carrying a value
// outside its field's closed vocabulary. FixtureSet.Validate does not check
// those vocabularies — only observation.Validate does, inside Store.Add — so
// the set PARSES and the damage happens during resolution, which is exactly
// where the superseded implementation was silent.
const dropSet = `{
  "schema_version": 1,
  "fixture_set_id": "drop-regression",
  "version": "v1",
  "description": "d",
  "provenance": "synthetic",
  "provenance_note": "written for this test",
  "partition": "held-out",
  "baseline_id": "b",
  "baseline_covers": [],
  "baseline_note": "n",
  "cases": [
    {"id":"all-invalid","type":"domain","value":"evil-drop.example.com","family":"f",
     "label":"malicious","label_basis":"adjudicated",
     "observations":[
       {"source_id":"s1","classification":"not-a-classification","state":"active"},
       {"source_id":"s2","classification":"malicious","state":"not-a-state"}
     ]},
    {"id":"partly-invalid","type":"domain","value":"mixed-drop.example.org","family":"f",
     "label":"malicious","label_basis":"adjudicated",
     "observations":[
       {"source_id":"s1","classification":"malicious","state":"active"},
       {"source_id":"s2","classification":"malicious","state":"WRONG"}
     ]},
    {"id":"clean-none","type":"domain","value":"good-drop.example.net","family":"f",
     "label":"legitimate","label_basis":"adjudicated"},
    {"id":"clean-observed","type":"domain","value":"seen-drop.example.com","family":"f",
     "label":"malicious","label_basis":"adjudicated",
     "observations":[
       {"source_id":"s1","classification":"malicious","state":"active"}
     ]}
  ]
}`

func runDropSet(t *testing.T) *Result {
	t.Helper()
	set, err := ParseSet([]byte(dropSet))
	if err != nil {
		t.Fatalf("the fixture set was refused at parse time: %v", err)
	}
	return Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1, AcceptUnestablished: true}, nil)
}

func resultCase(t *testing.T, r *Result, id string) CaseResult {
	t.Helper()
	for _, c := range r.Cases {
		if c.CaseID == id {
			return c
		}
	}
	t.Fatalf("no case %q in the result", id)
	return CaseResult{}
}

// TestUnresolvableObservationsArePreserved is the substance of the fix.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// resolve() discarded both failure paths with a bare `continue`. Run against
// it, this exact fixture produced:
//
//	all-invalid      outcome=false_negative            decision=pass
//	partly-invalid   outcome=true_positive_additional  decision=propose
//	counts: cases=3 falseNegatives=1 parseFailures=0
//
// The first is a labelled-malicious case whose only two observations were both
// thrown away, scored as an ordinary miss — indistinguishable from a rule that
// looked at the evidence and declined. The second is worse: the rule was
// CREDITED with a true positive computed from evidence the harness had
// silently discarded half of. Neither appeared in any count.
func TestUnresolvableObservationsArePreserved(t *testing.T) {
	r := runDropSet(t)

	t.Run("every failure is preserved on the case", func(t *testing.T) {
		all := resultCase(t, r, "all-invalid")
		if all.InvalidObservations != 2 {
			t.Errorf("all-invalid: InvalidObservations = %d, want 2", all.InvalidObservations)
		}
		if all.ObservationsAccepted != 0 {
			t.Errorf("all-invalid: ObservationsAccepted = %d, want 0", all.ObservationsAccepted)
		}
		if len(all.ObservationFailures) != 2 {
			t.Fatalf("all-invalid: %d failure record(s), want 2", len(all.ObservationFailures))
		}
		// The records must locate the observation and say what went wrong.
		for i, f := range all.ObservationFailures {
			if f.Index != i {
				t.Errorf("failure %d: Index = %d, want %d", i, f.Index, i)
			}
			if f.Stage == "" {
				t.Errorf("failure %d: no stage recorded", i)
			}
			if strings.TrimSpace(f.Reason) == "" {
				t.Errorf("failure %d: no reason recorded", i)
			}
		}

		part := resultCase(t, r, "partly-invalid")
		if part.InvalidObservations != 1 || part.ObservationsAccepted != 1 {
			t.Errorf("partly-invalid: %d invalid / %d accepted, want 1 / 1",
				part.InvalidObservations, part.ObservationsAccepted)
		}
	})

	t.Run("a malformed observation is never an ordinary outcome", func(t *testing.T) {
		for _, id := range []string{"all-invalid", "partly-invalid"} {
			got := resultCase(t, r, id).Outcome
			if got != "invalid_observation" {
				t.Errorf("%s: outcome = %q, want %q", id, got, "invalid_observation")
			}
			// The three the order names explicitly.
			for _, forbidden := range []string{
				"false_negative", "true_negative", "passed_unlabelled",
				"abstained", "abstained_on_malicious",
				"true_positive_additional", "true_positive_already_covered",
			} {
				if got == forbidden {
					t.Errorf("%s: scored as an ordinary %q", id, forbidden)
				}
			}
		}
	})

	t.Run("excluded cases contribute to no rate", func(t *testing.T) {
		c := r.Overall.Counts
		if c.InvalidObservationCases != 2 {
			t.Errorf("InvalidObservationCases = %d, want 2", c.InvalidObservationCases)
		}
		// Two of the four cases resolved; only those may be in Cases.
		if c.Cases != 2 {
			t.Errorf("Counts.Cases = %d, want 2 (the two that resolved)", c.Cases)
		}
		// The superseded implementation reported falseNegatives=1 here, from
		// all-invalid. That case is now excluded, so the count is 0.
		if c.FalseNegatives != 0 {
			t.Errorf("FalseNegatives = %d, want 0; an unresolvable case must not "+
				"be scored as a miss", c.FalseNegatives)
		}
		// clean-observed is a genuine true positive and must still count.
		// partly-invalid must not: the superseded implementation credited it,
		// reporting 2 here from an answer computed on half the evidence.
		if c.TruePositives != 1 {
			t.Errorf("TruePositives = %d, want 1 (clean-observed only); the rule "+
				"must not be credited for an answer computed from discarded evidence",
				c.TruePositives)
		}
	})

	t.Run("the run carries explicit totals", func(t *testing.T) {
		if r.InvalidObservationCases != 2 {
			t.Errorf("Result.InvalidObservationCases = %d, want 2", r.InvalidObservationCases)
		}
		if r.InvalidObservations != 3 {
			t.Errorf("Result.InvalidObservations = %d, want 3", r.InvalidObservations)
		}
	})

	t.Run("the caveat travels with the numbers", func(t *testing.T) {
		joined := strings.Join(r.NotProtocolConformant, "\n")
		if !strings.Contains(joined, "could not resolve") {
			t.Errorf("NotProtocolConformant does not mention the unresolved evidence:\n%s", joined)
		}
	})
}

// TestUnresolvableObservationsAppearInTheReport. A count nobody prints is not
// materially better than a silent continue.
func TestUnresolvableObservationsAppearInTheReport(t *testing.T) {
	r := runDropSet(t)
	var buf bytes.Buffer
	r.Text(&buf)
	out := buf.String()

	for _, want := range []string{
		"EVIDENCE THE HARNESS COULD NOT RESOLVE",
		"EXCLUDED from every count and rate",
		"all-invalid",
		"partly-invalid",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not contain %q", want)
		}
	}
	// The section must precede the rates it bounds.
	if i, j := strings.Index(out, "COULD NOT RESOLVE"), strings.Index(out, "RATES"); i < 0 || j < 0 || i > j {
		t.Errorf("the unresolved-evidence section does not precede RATES (at %d and %d)", i, j)
	}
}

// TestACleanSetReportsNoLostEvidence is the NEGATIVE CONTROL.
//
// Without it, an implementation that marked every case invalid would pass all
// the assertions above.
func TestACleanSetReportsNoLostEvidence(t *testing.T) {
	set, err := LoadSet("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatalf("the repository fixture no longer loads: %v", err)
	}
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)
	if r.InvalidObservationCases != 0 || r.InvalidObservations != 0 {
		t.Errorf("the repository's own fixture reports %d lost observation(s) in %d case(s); "+
			"it is expected to resolve completely", r.InvalidObservations, r.InvalidObservationCases)
	}
	if r.Overall.Counts.Cases != len(set.Cases) {
		t.Errorf("Counts.Cases = %d, want %d: a clean set must not lose cases",
			r.Overall.Counts.Cases, len(set.Cases))
	}
	var buf bytes.Buffer
	r.Text(&buf)
	if !strings.Contains(buf.String(), "none: every observation the fixture declared was resolved") {
		t.Error("the report does not state that nothing was lost")
	}
}

// TestFailureReasonsAreBounded. The reason comes from an error that quotes the
// offending field, and that field came from the fixture.
func TestFailureReasonsAreBounded(t *testing.T) {
	long := strings.Repeat("z", 50_000)
	doc := `{
  "schema_version": 1, "fixture_set_id": "bound", "version": "v1",
  "description": "d", "provenance": "synthetic", "provenance_note": "n",
  "partition": "held-out", "baseline_id": "b", "baseline_covers": [],
  "baseline_note": "n",
  "cases": [
    {"id":"c1","type":"domain","value":"bound.example.com","family":"f",
     "label":"malicious","label_basis":"b",
     "observations":[{"source_id":"s1","classification":"` + long + `","state":"active"}]}
  ]
}`
	set, err := ParseSet([]byte(doc))
	if err != nil {
		t.Fatalf("the fixture set was refused at parse time: %v", err)
	}
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	c := resultCase(t, r, "c1")
	if c.InvalidObservations != 1 {
		t.Fatalf("InvalidObservations = %d, want 1", c.InvalidObservations)
	}
	reason := c.ObservationFailures[0].Reason
	if len(reason) > maxFailureReason+8 {
		t.Errorf("the failure reason is %d bytes; it is meant to be bounded at %d",
			len(reason), maxFailureReason)
	}
	if strings.Contains(reason, strings.Repeat("z", 1000)) {
		t.Errorf("the failure reason carries a caller-controlled run of %d bytes", len(reason))
	}
}
