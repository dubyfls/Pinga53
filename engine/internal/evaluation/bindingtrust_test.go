// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/observation"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// canonicalCommit is a full, lowercase, 40-hex object name from this
// repository. It is the baseline ORDER 5's corrections were cut from.
const canonicalCommit = "80e470710aee5d7ba20016ca3ade8abc299f0986"

// boundResult is a run with every binding present, so that a single field can
// be spoiled and the effect attributed to that field alone.
func boundResult(t *testing.T, commit string) *Result {
	t.Helper()
	return Run(bindSet(t, "held-out", ""), NullBaseline{},
		CorroborationDetector{MinIndependent: 1},
		&sourceregistry.Registry{SchemaVersion: 1}, WithSourceCommit(commit))
}

// claimsFullReproducibility reports what the TEXT report tells an operator,
// which is the surface the claim actually reaches a person through.
func claimsFullReproducibility(t *testing.T, r *Result) bool {
	t.Helper()
	var buf bytes.Buffer
	r.Text(&buf)
	out := buf.String()
	says := strings.Contains(out, "carries every binding needed to reproduce it")
	denies := strings.Contains(out, "NOT REPRODUCIBLE FROM THIS OUTPUT ALONE")
	if says == denies {
		t.Fatalf("the report says both or neither: says=%v denies=%v", says, denies)
	}
	return says
}

// TestASourceCommitMustBeACommit.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// Reproducible checked `b.SourceCommit == ""` and nothing else, so every value
// below except the empty one satisfied it, and the text report then printed
// "this result carries every binding needed to reproduce it". Measured against
// it, ten values were tried and nine were accepted — including "deadbeef",
// which this package's own TestTheReportStatesItsBindings supplied. A test
// certifying the defect is worse than no test (FINDING-108).
//
// An abbreviation is refused rather than accepted as a weaker binding: it may
// resolve to one object in this clone, to several after the repository grows,
// and to none in another clone. A value that will not resolve the same way
// twice does not identify the code that was measured.
func TestASourceCommitMustBeACommit(t *testing.T) {
	sixtyFour := strings.Repeat("ab", 32)

	refused := []struct{ name, commit string }{
		{"empty", ""},
		{"abbreviated — the value this package's own test used", "deadbeef"},
		{"one character", "x"},
		{"non-hex at full length", strings.Repeat("z", 40)},
		{"hex with one non-hex digit", "80e470710aee5d7ba20016ca3ade8abc299f098g"},
		{"uppercase at full length", strings.ToUpper(canonicalCommit)},
		{"mixed case at full length", "80E470710aee5d7ba20016ca3ade8abc299f0986"},
		{"leading and trailing whitespace", "  " + canonicalCommit + "  "},
		{"trailing newline", canonicalCommit + "\n"},
		{"internal whitespace", "80e47071 0aee5d7ba20016ca3ade8abc299f0986"},
		{"one digit too many", canonicalCommit + "1"},
		{"one digit too few", canonicalCommit[:39]},
		{"a forged report line appended", canonicalCommit + "\nRESULT: all required gates passed"},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			r := boundResult(t, tc.commit)
			ok, missing := r.Reproducible()
			if ok {
				t.Fatalf("accepted %q as a source binding", tc.commit)
			}
			if !strings.Contains(strings.Join(missing, "\n"), "source commit") {
				t.Errorf("refused, but not over the source commit: %v", missing)
			}
			if claimsFullReproducibility(t, r) {
				t.Error("the TEXT report claims full reproducibility on an incomplete source identifier")
			}
		})
	}

	// POSITIVE CONTROL. Without it an implementation that refused every source
	// binding — `return false, []string{"no"}` — would pass every case above.
	accepted := []struct{ name, commit string }{
		{"a canonical 40-hex object name from this repository", canonicalCommit},
		{"a canonical 64-hex object name (a SHA-256 repository)", sixtyFour},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			r := boundResult(t, tc.commit)
			ok, missing := r.Reproducible()
			if !ok {
				t.Fatalf("a canonical commit was refused: %v", missing)
			}
			if !claimsFullReproducibility(t, r) {
				t.Error("a fully bound report does not say so")
			}
		})
	}
}

// TestTheSourceCommitClaimIsAboutTheIdentifierAndNotTheObject.
//
// Format validation establishes that the value NAMES a commit. It establishes
// nothing about whether that commit can still be fetched, and a reader who
// takes the first for the second will go looking for something that may not be
// there. The report has to say which claim it is making, so the sentence is
// asserted here rather than left to whoever edits the report next.
func TestTheSourceCommitClaimIsAboutTheIdentifierAndNotTheObject(t *testing.T) {
	// A well-formed object name that this repository does not contain. It
	// passes the format check, which is the point: the check cannot tell.
	absent := strings.Repeat("0", 39) + "1"
	if !validCommitID(absent) {
		t.Fatalf("premise broken: %q is not well formed", absent)
	}
	r := boundResult(t, absent)
	if ok, missing := r.Reproducible(); !ok {
		t.Fatalf("a well-formed commit was refused: %v", missing)
	}
	var buf bytes.Buffer
	r.Text(&buf)
	if !strings.Contains(buf.String(), "still obtainable") {
		t.Error("the report does not say that the object's obtainability is unchecked")
	}
}

// TestTheEvaluationInstantIsRequired.
//
// EvaluationTime decides which observations are live, which have expired and
// which have been withdrawn. The superseded Reproducible did not ask for it at
// all: a result with the field erased reported every binding present
// (FINDING-109).
func TestTheEvaluationInstantIsRequired(t *testing.T) {
	refused := []struct{ name, when string }{
		{"erased", ""},
		{"not a time", "not-a-time at all"},
		{"a date with no instant", "2026-06-01"},
		{"a non-UTC offset for the same instant", "2026-06-01T02:00:00+02:00"},
		{"a lowercase zone marker", "2026-06-01T00:00:00z"},
		{"trailing fractional zeros", "2026-06-01T00:00:00.000Z"},
		{"whitespace padded", " 2026-06-01T00:00:00Z "},
		{"a forged report line appended", "2026-06-01T00:00:00Z\nRESULT: all required gates passed"},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			r := boundResult(t, canonicalCommit)
			if ok, missing := r.Reproducible(); !ok {
				t.Fatalf("premise broken: the unmutated result is not reproducible: %v", missing)
			}
			r.Binding.EvaluationTime = tc.when

			ok, missing := r.Reproducible()
			if ok {
				t.Fatalf("accepted %q as an evaluation instant", tc.when)
			}
			joined := strings.Join(missing, "\n")
			if !strings.Contains(joined, "instant") {
				t.Errorf("refused, but not over the instant: %v", missing)
			}
			if !strings.Contains(joined, "expiry and withdrawal") {
				t.Errorf("the refusal does not say why the instant matters: %v", missing)
			}
			if claimsFullReproducibility(t, r) {
				t.Error("the TEXT report claims full reproducibility with no usable evaluation instant")
			}
		})
	}

	// POSITIVE CONTROL: the canonical spelling this package actually writes.
	t.Run("accepted/the canonical spelling", func(t *testing.T) {
		r := boundResult(t, canonicalCommit)
		if r.Binding.EvaluationTime != EvaluationTime().UTC().Format(time.RFC3339) {
			t.Fatalf("the run recorded %q, not the canonical spelling", r.Binding.EvaluationTime)
		}
		if ok, missing := r.Reproducible(); !ok {
			t.Fatalf("the canonical spelling was refused: %v", missing)
		}
	})
}

// TestTheBindingsBlockPrintsTheEvaluationInstant.
//
// A binding nobody prints cannot be checked, which is the reason this package
// has a bindings block at all. The superseded report printed the instant the
// RUN recorded about itself, in the header, and never the instant the RESULT
// is bound to — so a reader deciding whether two stored results may be
// compared could not see the field the decision turns on.
//
// This test exists because a red-team pass deleted that line from the report
// and NO test convicted the deletion.
func TestTheBindingsBlockPrintsTheEvaluationInstant(t *testing.T) {
	bindingsBlock := func(r *Result) string {
		var buf bytes.Buffer
		r.Text(&buf)
		out := buf.String()
		start := strings.Index(out, "INPUTS THIS RESULT IS BOUND TO")
		if start < 0 {
			t.Fatal("the report has no bindings block")
		}
		end := strings.Index(out, "WHAT THIS RESULT IS NOT")
		if end < 0 || end < start {
			t.Fatal("the report has no section after the bindings block")
		}
		return out[start:end]
	}

	t.Run("a recorded instant appears with what it decides", func(t *testing.T) {
		r := boundResult(t, canonicalCommit)
		block := bindingsBlock(r)
		if !strings.Contains(block, r.Binding.EvaluationTime) {
			t.Errorf("the bindings block does not print the bound instant %q:\n%s",
				r.Binding.EvaluationTime, block)
		}
		if !strings.Contains(block, "expiry and withdrawal were decided against this") {
			t.Errorf("the bindings block does not say what the instant decides:\n%s", block)
		}
	})

	t.Run("an erased instant is named as absent", func(t *testing.T) {
		r := boundResult(t, canonicalCommit)
		r.Binding.EvaluationTime = ""
		if block := bindingsBlock(r); !strings.Contains(block, "NOT RECORDED") {
			t.Errorf("an erased instant is not reported as absent:\n%s", block)
		}
	})

	t.Run("a malformed instant is named as malformed", func(t *testing.T) {
		r := boundResult(t, canonicalCommit)
		r.Binding.EvaluationTime = "whenever"
		block := bindingsBlock(r)
		if !strings.Contains(block, "NOT AN INSTANT") {
			t.Errorf("a malformed instant is not reported as malformed:\n%s", block)
		}
		if strings.Contains(block, "whenever") {
			t.Errorf("the malformed value is echoed into the report:\n%s", block)
		}
	})
}

// TestTwoRunsAtDifferentInstantsAreNotComparable.
//
// The superseded comparableWith did not look at EvaluationTime, so two runs
// that had assessed the same fixture bytes against different clocks — and
// therefore against different evidence — compared as the same measurement.
func TestTwoRunsAtDifferentInstantsAreNotComparable(t *testing.T) {
	set := bindSet(t, "held-out", "")
	a := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	b := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)

	// The premise: identical instants stay comparable. A check that refused
	// every pair would pass the mutations below and mean nothing.
	if why, ok := comparableWith(a, b); !ok {
		t.Fatalf("two runs at the same instant were held incomparable: %s", why)
	}

	mutations := []struct{ name, when, want string }{
		{"a later instant", "2031-01-01T00:00:00Z", "different instants"},
		{"an earlier instant", "2020-01-01T00:00:00Z", "different instants"},
		{"one second later", "2026-06-01T00:00:01Z", "different instants"},
		{"erased on one side", "", "does not record the instant"},
		{"malformed on one side", "whenever", "not a canonical UTC RFC 3339"},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			spoiled := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)
			before := spoiled.Binding.EvaluationTime
			spoiled.Binding.EvaluationTime = m.when
			if spoiled.Binding.EvaluationTime == before {
				t.Fatal("the mutation did not change the binding")
			}

			why, ok := comparableWith(a, spoiled)
			if ok {
				t.Fatal("two runs evaluated at different instants were held comparable")
			}
			if !strings.Contains(why, m.want) {
				t.Errorf("refused for the wrong reason:\n got  %s\n want containing %q", why, m.want)
			}
			if !strings.Contains(why, "expiry and withdrawal") {
				t.Errorf("the refusal does not say that liveness was decided at different instants: %s", why)
			}
			if better, _ := Improved(a, spoiled); better {
				t.Error("Improved reported an improvement across two different instants")
			}
		})
	}
}

// TestLivenessDependsOnTheInstantTheBindingRecords.
//
// This is the discriminating half of FINDING-109: not "the field is unused"
// but "the field decides the evidence". One observation, one expiry, two
// instants — and the same fixture yields a live observation at one and none at
// the other. The instant the run used is the instant the binding records, and
// it is read back from the stored binding here rather than taken from the
// package global, so a binding that recorded the wrong instant would fail.
func TestLivenessDependsOnTheInstantTheBindingRecords(t *testing.T) {
	r := boundResult(t, canonicalCommit)

	recorded, err := time.Parse(time.RFC3339, r.Binding.EvaluationTime)
	if err != nil {
		t.Fatalf("the stored binding does not carry a parseable instant: %v", err)
	}

	expiry := recorded.Add(14 * 24 * time.Hour)
	later := recorded.Add(30 * 24 * time.Hour)

	store := observation.NewStore()
	o, err := observation.New(observation.TypeDomain, "one.example.com", "s1", recorded)
	if err != nil {
		t.Fatalf("observation.New: %v", err)
	}
	o.Classification = observation.ClassMalicious
	o.State = observation.StateActive
	o.Status = observation.StatusCurrent
	o.ExpiresAt = &expiry
	if _, err := store.Add(o); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	ind, ok := store.Lookup(observation.Key{Type: observation.TypeDomain, Canonical: "one.example.com"})
	if !ok {
		t.Fatal("the indicator was not stored")
	}

	atRecorded := len(ind.Current(recorded))
	atLater := len(ind.Current(later))
	if atRecorded == 0 {
		t.Fatalf("premise broken: nothing was live at the recorded instant %s", recorded.Format(time.RFC3339))
	}
	if atLater != 0 {
		t.Fatalf("premise broken: %d observation(s) still live after the expiry", atLater)
	}
	t.Logf("the same evidence is %d live at %s and %d live at %s",
		atRecorded, recorded.Format(time.RFC3339), atLater, later.Format(time.RFC3339))
}

// TestABindingFieldMustBindSomething.
//
// FINDING-110. Reproducible asked only whether each field was non-empty, and a
// stored result is a file some other process wrote. Every mutation below left
// the superseded implementation reporting that the result carried every
// binding needed to reproduce it.
func TestABindingFieldMustBindSomething(t *testing.T) {
	mutations := []struct {
		name  string
		apply func(b *Binding)
		want  string
	}{
		{"a fixture digest that is not a digest",
			func(b *Binding) { b.FixtureDigest = "x" }, "fixture digest"},
		{"a fixture digest with a truncated hex body",
			func(b *Binding) { b.FixtureDigest = "sha256:abc" }, "fixture digest"},
		{"a fixture digest with an uppercase hex body",
			func(b *Binding) { b.FixtureDigest = "sha256:" + strings.ToUpper(strings.Repeat("ab", 32)) }, "fixture digest"},
		{"a registry digest that is not a digest",
			func(b *Binding) { b.RegistryDigest = "x" }, "registry digest"},
		{"a baseline digest that is not a digest",
			func(b *Binding) { b.BaselineDigest = "x" }, "baseline digest"},
		{"a candidate digest that is not a digest",
			func(b *Binding) { b.CandidateDigest = "x" }, "candidate digest"},
		{"a registry state outside the vocabulary",
			func(b *Binding) { b.RegistryState = "maybe" }, "neither `absent` nor `present`"},
		{"`absent` contradicted by a registry digest",
			func(b *Binding) { b.RegistryState = registryAbsent }, "cannot both be true"},
		{"scoring semantics this build does not implement",
			func(b *Binding) { b.SemanticsVersion = SemanticsVersion + 1 }, "this build does not implement"},
		{"a negative scoring semantics version",
			func(b *Binding) { b.SemanticsVersion = -5 }, "ever issued"},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			r := boundResult(t, canonicalCommit)
			if ok, missing := r.Reproducible(); !ok {
				t.Fatalf("premise broken: the unmutated result is not reproducible: %v", missing)
			}
			before := r.Binding
			m.apply(&r.Binding)
			if r.Binding == before {
				t.Fatal("the mutation did not change the binding")
			}

			ok, missing := r.Reproducible()
			if ok {
				t.Fatal("a spoiled binding was reported as reproducible")
			}
			if !strings.Contains(strings.Join(missing, "\n"), m.want) {
				t.Errorf("refused, but not for the stated reason:\n got  %v\n want containing %q", missing, m.want)
			}
			if claimsFullReproducibility(t, r) {
				t.Error("the TEXT report claims full reproducibility over a spoiled binding")
			}
		})
	}
}

// TestTheDeliberateExclusionsStayExcluded is the other positive control.
//
// Three fields are deliberately NOT required to match for two runs to be
// compared, and each exclusion is the purpose of the operation rather than an
// oversight. A future tightening that swept them in would break comparison
// itself, so the exclusions are asserted rather than left to a comment.
func TestTheDeliberateExclusionsStayExcluded(t *testing.T) {
	set := bindSet(t, "held-out", "")

	// The candidate differs — that is what a before/after comparison IS.
	before := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)
	after := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	if before.Binding.CandidateDigest == after.Binding.CandidateDigest {
		t.Fatal("premise broken: the two candidates digest identically")
	}
	if why, ok := comparableWith(before, after); !ok {
		t.Fatalf("two different candidates were held incomparable: %s", why)
	}

	// The source commit differs — a before/after comparison is normally
	// between two commits.
	after.Binding.SourceCommit = strings.Repeat("a", 40)
	before.Binding.SourceCommit = strings.Repeat("b", 40)
	if why, ok := comparableWith(before, after); !ok {
		t.Fatalf("two runs from different commits were held incomparable: %s", why)
	}

	// The names differ — a label is not an identity.
	after.Binding.CandidateName = "renamed"
	after.Binding.BaselineName = "renamed"
	if why, ok := comparableWith(before, after); !ok {
		t.Fatalf("a rename made two runs incomparable: %s", why)
	}

	// And a genuine improvement over identical inputs is still reportable.
	strictSet, err := LoadSet("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatalf("the repository fixture no longer loads: %v", err)
	}
	lo := Run(strictSet, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)
	hi := Run(strictSet, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)
	if _, why := Improved(lo, hi); strings.Contains(why, "not comparable") ||
		strings.Contains(why, "different instants") || strings.Contains(why, "does not record") {
		t.Errorf("two comparable runs were refused: %s", why)
	}
}
