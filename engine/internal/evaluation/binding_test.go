// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/observation"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// bindSet builds a fixture set whose SELF-DECLARED identity is fixed but whose
// contents vary, which is exactly the confusion the superseded Improved could
// not see through.
func bindSet(t *testing.T, partition, extraCaseValue string) *FixtureSet {
	t.Helper()
	extra := ""
	if extraCaseValue != "" {
		extra = `,{"id":"extra","type":"domain","value":"` + extraCaseValue +
			`","family":"f","label":"malicious","label_basis":"adjudicated"}`
	}
	doc := `{
  "schema_version": 1,
  "fixture_set_id": "bind-set",
  "version": "v1",
  "description": "d",
  "provenance": "synthetic",
  "provenance_note": "written for this test",
  "partition": "` + partition + `",
  "baseline_id": "b",
  "baseline_covers": [],
  "baseline_note": "n",
  "cases": [
    {"id":"c1","type":"domain","value":"one.example.com","family":"f",
     "label":"malicious","label_basis":"adjudicated"}` + extra + `
  ]
}`
	s, err := ParseSet([]byte(doc))
	if err != nil {
		t.Fatalf("fixture refused: %v", err)
	}
	return s
}

// TestTwoFixturesCanShareAnIdentityAndDifferInContent is the premise of the
// whole finding. If this failed, the rest would be theoretical.
func TestTwoFixturesCanShareAnIdentityAndDifferInContent(t *testing.T) {
	a := bindSet(t, "held-out", "")
	b := bindSet(t, "held-out", "two.example.com")

	if a.ID != b.ID || a.Version != b.Version {
		t.Fatal("the two sets were built with different declared identities")
	}
	if len(a.Cases) == len(b.Cases) {
		t.Fatal("the two sets have the same contents; they are meant to differ")
	}
	if a.BytesDigest() == b.BytesDigest() {
		t.Error("two different fixture files produced the same bytes digest")
	}
	if a.BytesDigest() == "" {
		t.Error("a parsed fixture set carries no bytes digest")
	}
}

// TestImprovedRefusesIncomparableRuns.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// It compared before.FixtureSetID and before.FixtureSetVersion, and nothing
// else. Both are strings the fixture file asserts about ITSELF. Every case
// below passed that check and was compared as though the two runs had measured
// the same thing.
func TestImprovedRefusesIncomparableRuns(t *testing.T) {
	reg := &sourceregistry.Registry{SchemaVersion: 1, Note: "a"}
	other := &sourceregistry.Registry{SchemaVersion: 1, Note: "b"}
	setA := bindSet(t, "held-out", "")
	setB := bindSet(t, "held-out", "two.example.com")
	setDev := bindSet(t, "development", "")

	base := func(s *FixtureSet, b, c Detector, r *sourceregistry.Registry) *Result {
		return Run(s, b, c, r)
	}
	nullB := NullBaseline{}
	listB := NewListDetector("household-v1", []string{"one.example.com"})
	cand1 := CorroborationDetector{MinIndependent: 1}
	cand2 := CorroborationDetector{MinIndependent: 2}

	tests := []struct {
		name   string
		before *Result
		after  *Result
		want   string // substring the refusal must contain
	}{
		{
			name:   "different fixture contents under the same declared identity",
			before: base(setA, nullB, cand1, reg),
			after:  base(setB, nullB, cand2, reg),
			want:   "different fixture CONTENTS",
		},
		{
			name:   "different partitions",
			before: base(setA, nullB, cand1, reg),
			after:  base(setDev, nullB, cand2, reg),
			want:   "different fixture CONTENTS", // the partition is in the bytes
		},
		{
			name:   "different baselines",
			before: base(setA, nullB, cand1, reg),
			after:  base(setA, listB, cand2, reg),
			want:   "different baselines",
		},
		{
			name:   "a registry in one run and not the other",
			before: base(setA, nullB, cand1, reg),
			after:  base(setA, nullB, cand2, nil),
			want:   "one run had a source registry and the other did not",
		},
		{
			name:   "different registries",
			before: base(setA, nullB, cand1, reg),
			after:  base(setA, nullB, cand2, other),
			want:   "different source registries",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			better, why := Improved(tc.before, tc.after)
			if better {
				t.Fatalf("reported an IMPROVEMENT across incomparable runs: %s", why)
			}
			if !strings.Contains(why, tc.want) {
				t.Errorf("refused for the wrong reason:\n got  %s\n want containing %q", why, tc.want)
			}
		})
	}
}

// TestImprovedRefusesIncompatibleSemantics. A stored result from before a
// scoring change looks exactly like one from after it.
func TestImprovedRefusesIncompatibleSemantics(t *testing.T) {
	set := bindSet(t, "held-out", "")
	before := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	after := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)

	// Simulate a result stored under the previous scoring rules.
	before.Binding.SemanticsVersion = SemanticsVersion - 1

	better, why := Improved(before, after)
	if better {
		t.Fatalf("compared results scored under different rules: %s", why)
	}
	if !strings.Contains(why, "different rules") {
		t.Errorf("refused for the wrong reason: %s", why)
	}
}

// TestImprovedRefusesAnUnboundBaseline. A detector from outside this package
// is still a legitimate detector; it simply cannot be compared across runs.
func TestImprovedRefusesAnUnboundBaseline(t *testing.T) {
	set := bindSet(t, "held-out", "")
	before := Run(set, opaqueDetector{}, CorroborationDetector{MinIndependent: 1}, nil)
	after := Run(set, opaqueDetector{}, CorroborationDetector{MinIndependent: 2}, nil)

	if before.Binding.BaselineDigest != digestUnavailable {
		t.Fatalf("the opaque baseline reported a digest: %q", before.Binding.BaselineDigest)
	}
	better, why := Improved(before, after)
	if better {
		t.Fatalf("compared against a baseline that cannot identify itself: %s", why)
	}
	if !strings.Contains(why, "cannot state its own configuration") {
		t.Errorf("refused for the wrong reason: %s", why)
	}
}

// opaqueDetector implements Detector but not ConfigIdentified.
type opaqueDetector struct{}

func (opaqueDetector) Name() string { return "opaque" }
func (opaqueDetector) Decide(Evidence) (Decision, string) {
	return DecisionPass, "opaque"
}

// TestImprovedStillWorksWhenTheRunsAreComparable is the POSITIVE CONTROL.
//
// Without it, an Improved that refused everything would pass every test above.
func TestImprovedStillWorksWhenTheRunsAreComparable(t *testing.T) {
	set, err := LoadSet("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatalf("the repository fixture no longer loads: %v", err)
	}
	strict := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)
	loose := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)

	if why, ok := comparableWith(strict, loose); !ok {
		t.Fatalf("two runs over identical inputs were held incomparable: %s", why)
	}
	// Whichever way the verdict falls, it must be a verdict about the NUMBERS
	// and not a refusal to compare.
	_, why := Improved(strict, loose)
	for _, refusal := range []string{"not comparable", "cannot state", "different rules"} {
		if strings.Contains(why, refusal) {
			t.Errorf("comparable runs were refused: %s", why)
		}
	}
}

// TestListDetectorIdentityIsItsMembership.
//
// The superseded Name was "label (N entries)". These two lists share a label
// and a count and have no member in common.
func TestListDetectorIdentityIsItsMembership(t *testing.T) {
	a := NewListDetector("household-v1", []string{"a.example.com", "b.example.com"})
	b := NewListDetector("household-v1", []string{"c.example.com", "d.example.com"})

	if len(a.Members) != len(b.Members) {
		t.Fatal("the two lists differ in size; they are meant to differ only in content")
	}
	if a.ConfigDigest() == b.ConfigDigest() {
		t.Error("two lists with no member in common share a configuration digest")
	}
	if a.Name() == b.Name() {
		t.Errorf("two lists with no member in common share a name: %q", a.Name())
	}

	// The digest is over membership, so order must not matter...
	reordered := NewListDetector("household-v1", []string{"b.example.com", "a.example.com"})
	if a.ConfigDigest() != reordered.ConfigDigest() {
		t.Error("the same members in a different order produced a different digest")
	}
	// ...and the label must not, either: renaming a list does not change what
	// it proposes.
	renamed := NewListDetector("household-v2", []string{"a.example.com", "b.example.com"})
	if a.ConfigDigest() != renamed.ConfigDigest() {
		t.Error("renaming a list changed its configuration digest")
	}
}

// TestListMembershipIsTyped. A canonical string means nothing without the
// indicator type it is a value of.
func TestListMembershipIsTyped(t *testing.T) {
	asDomain := NewTypedListDetector("x", []Member{{Type: observation.TypeDomain, Canonical: "a.example.com"}})
	asURL := NewTypedListDetector("x", []Member{{Type: observation.TypeURL, Canonical: "a.example.com"}})
	if asDomain.ConfigDigest() == asURL.ConfigDigest() {
		t.Error("the same canonical value under two indicator types digests identically")
	}

	// A domain case must not be answered by a URL entry.
	e := Evidence{Case: Case{Type: observation.TypeDomain}, Canonical: "a.example.com"}
	if d, _ := asURL.Decide(e); d == DecisionPropose {
		t.Error("a URL list proposed a domain case with the same canonical string")
	}
	if d, _ := asDomain.Decide(e); d != DecisionPropose {
		t.Error("a domain list did not propose its own member")
	}
}

// TestReproducibleReportsWhatIsMissing.
//
// The superseded Result documented itself as "fully reproducible from its own
// output" while binding none of its inputs. This replaces the claim with an
// answer.
func TestReproducibleReportsWhatIsMissing(t *testing.T) {
	set := bindSet(t, "held-out", "")

	// No registry, no source commit: not reproducible, and it says why.
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	ok, missing := r.Reproducible()
	if ok {
		t.Error("a result with no source commit claimed to be reproducible")
	}
	if !strings.Contains(strings.Join(missing, "\n"), "no source commit") {
		t.Errorf("the missing bindings do not mention the source commit: %v", missing)
	}

	// With a registry and a supplied commit, every binding is present.
	reg := &sourceregistry.Registry{SchemaVersion: 1}
	full := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, reg,
		WithSourceCommit("3152485b96cc669bca1f73b8fefa7fd171f7df6f"))
	if ok, missing := full.Reproducible(); !ok {
		t.Errorf("a fully bound result reports missing bindings: %v", missing)
	}
	if full.Binding.SourceCommit == "" {
		t.Error("the supplied source commit was not recorded")
	}
	if full.Binding.RegistryState != "present" || full.Binding.RegistryDigest == "" {
		t.Errorf("the registry was not bound: state=%q digest=%q",
			full.Binding.RegistryState, full.Binding.RegistryDigest)
	}
}

// TestAbsentRegistryIsDistinctFromAnEmptyOne. "No registry" and "a registry
// that happens to be empty" are different claims about independence.
func TestAbsentRegistryIsDistinctFromAnEmptyOne(t *testing.T) {
	set := bindSet(t, "held-out", "")
	none := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	empty := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, &sourceregistry.Registry{})

	if none.Binding.RegistryState != "absent" {
		t.Errorf("no registry recorded as %q", none.Binding.RegistryState)
	}
	if empty.Binding.RegistryState != "present" {
		t.Errorf("an empty registry recorded as %q", empty.Binding.RegistryState)
	}
	if why, ok := comparableWith(none, empty); ok {
		t.Error("a run with no registry was held comparable with one that had an empty registry")
	} else if !strings.Contains(why, "did not") {
		t.Errorf("refused for the wrong reason: %s", why)
	}
}

// TestTheReportStatesItsBindings. A binding nobody prints cannot be checked.
func TestTheReportStatesItsBindings(t *testing.T) {
	set := bindSet(t, "held-out", "")

	unbound := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	var buf bytes.Buffer
	unbound.Text(&buf)
	out := buf.String()
	for _, want := range []string{
		"INPUTS THIS RESULT IS BOUND TO",
		"fixture bytes   sha256:",
		"NOT SUPPLIED",
		"NOT REPRODUCIBLE FROM THIS OUTPUT ALONE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not contain %q", want)
		}
	}

	// A CANONICAL commit, not an abbreviation. This test supplied "deadbeef"
	// and asserted that the report claimed full reproducibility — so the test
	// itself certified the defect FINDING-108 records. An abbreviation names
	// no object: it may match one today, several tomorrow, and none in another
	// clone, and a binding that exists to say which code was measured cannot
	// be satisfied by it.
	full := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1},
		&sourceregistry.Registry{SchemaVersion: 1},
		WithSourceCommit("80e470710aee5d7ba20016ca3ade8abc299f0986"))
	buf.Reset()
	full.Text(&buf)
	out = buf.String()
	if !strings.Contains(out, "carries every binding needed to reproduce it") {
		t.Error("a fully bound report does not say so")
	}
	if strings.Contains(out, "NOT REPRODUCIBLE") {
		t.Error("a fully bound report still claims to be unreproducible")
	}
}

// TestDigestsAreStableAcrossRuns. A digest that changed between two runs over
// identical inputs would make every comparison refuse.
func TestDigestsAreStableAcrossRuns(t *testing.T) {
	reg := &sourceregistry.Registry{SchemaVersion: 1, Note: "x",
		Sources: []sourceregistry.Source{{SourceID: "s1", Permissions: map[sourceregistry.Operation]sourceregistry.Grant{}}}}
	for i := 0; i < 20; i++ {
		set := bindSet(t, "held-out", "")
		r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, reg)
		first := bindSet(t, "held-out", "")
		want := Run(first, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, reg)
		if r.Binding != want.Binding {
			t.Fatalf("iteration %d produced a different binding:\n %+v\n %+v", i, r.Binding, want.Binding)
		}
	}
}

// TestPartitionGuardIsExercisedDirectly.
//
// HONEST NOTE. The partition is part of the fixture document, so two runs over
// different partitions already differ in their fixture digest and are refused
// by that check first — the partition clause in comparableWith is never the
// reason a real pair is rejected. It is kept as defence in depth, for a
// Binding assembled by some future caller rather than by ParseSet, and it is
// exercised here directly so that it is not untested code pretending to be a
// control.
func TestPartitionGuardIsExercisedDirectly(t *testing.T) {
	set := bindSet(t, "held-out", "")
	a := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	b := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)

	if why, ok := comparableWith(a, b); !ok {
		t.Fatalf("the two runs should be comparable before the mutation: %s", why)
	}
	b.Binding.Partition = PartitionDevelopment

	why, ok := comparableWith(a, b)
	if ok {
		t.Fatal("a held-out run was held comparable with a development one")
	}
	if !strings.Contains(why, "different partitions") {
		t.Errorf("refused for the wrong reason: %s", why)
	}
}

// TestImprovedNoLongerReportsAFabricatedImprovement is the sharpest form of
// the finding: not "it refused for the wrong reason", but "it said yes".
//
// Both fixture files declare fixture_set_id "bind-set" version "v1". They have
// different cases. The superseded comparability check compared only those two
// self-declared strings, so it passed, and the counts then differed for the
// obvious reason that the two runs were over different data:
//
//	before: over setA, a list that proposes nothing   -> 0 true positives
//	after:  over setB, a list that proposes both      -> 2 true positives
//
// and it reported: IMPROVEMENT, "catches 2 more (0 -> 2) at no additional cost".
// That sentence is about two different measurements.
func TestImprovedNoLongerReportsAFabricatedImprovement(t *testing.T) {
	setA := bindSet(t, "held-out", "")
	setB := bindSet(t, "held-out", "two.example.com")

	before := Run(setA, NullBaseline{}, NewListDetector("cand", nil), nil)
	after := Run(setB, NullBaseline{},
		NewListDetector("cand", []string{"one.example.com", "two.example.com"}), nil)

	// The premise: the counts really do differ, so a comparison that got as
	// far as looking at them would find an "improvement".
	if before.Overall.Counts.TruePositives != 0 {
		t.Fatalf("premise broken: before has %d true positives, want 0",
			before.Overall.Counts.TruePositives)
	}
	if after.Overall.Counts.TruePositives == 0 {
		t.Fatal("premise broken: after has no true positives to be tempted by")
	}

	better, why := Improved(before, after)
	if better {
		t.Fatalf("FABRICATED IMPROVEMENT across two different fixture files "+
			"sharing a declared identity: %s", why)
	}
	if !strings.Contains(why, "different fixture CONTENTS") {
		t.Errorf("refused, but not because the contents differ: %s", why)
	}
}
