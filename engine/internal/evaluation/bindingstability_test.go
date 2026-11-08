// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/observation"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT THIS FILE IS ABOUT
//
// bindingaudit_test.go established that every Binding field is required and
// compared as the design says. It asked that question one field at a time and
// on one side at a time, which left four ways a binding can still fail to
// bind:
//
//	FINDING-115  ListDetector.ConfigDigest digested the KEYS of a
//	             map[Member]bool while Decide reads the VALUE, so two lists
//	             that decide oppositely had the same identity.
//	FINDING-116  every FixtureSet field a run reads is exported, so a set
//	             could be edited after the parse-time digest was taken and the
//	             binding would still name the original bytes.
//	FINDING-117  the binding is captured before the first case; a detector or
//	             a registry that changed during the run was reported as though
//	             one configuration had been measured.
//	FINDING-118  comparableWith asked "do these two values DIFFER", so two
//	             results that were both silent about the baseline, the
//	             registry state or the scoring version passed every check on
//	             the strength of neither of them having said anything.
//
// Each has a positive control beside it, because every one of these could be
// "fixed" by refusing everything.

// TestAListDetectorsIdentityIsWhatItProposes.
//
// Members is a map[Member]bool. Decide reads the value; the superseded
// ConfigDigest ranged over the map and used only the key.
func TestAListDetectorsIdentityIsWhatItProposes(t *testing.T) {
	m := Member{Type: observation.TypeDomain, Canonical: "one.example.com"}

	on := &ListDetector{Label: "list", Members: map[Member]bool{m: true}}
	off := &ListDetector{Label: "list", Members: map[Member]bool{m: false}}
	empty := &ListDetector{Label: "list", Members: map[Member]bool{}}

	e := Evidence{Case: Case{Type: observation.TypeDomain}, Canonical: m.Canonical}

	// The premise: they really do decide differently.
	if d, _ := on.Decide(e); d != DecisionPropose {
		t.Fatalf("premise broken: the true member does not propose, got %s", d)
	}
	if d, _ := off.Decide(e); d != DecisionPass {
		t.Fatalf("premise broken: the false member proposes, got %s", d)
	}

	if on.ConfigDigest() == off.ConfigDigest() {
		t.Errorf("two lists that decide oppositely share one identity:\n"+
			"  {member: true}  -> %s\n  {member: false} -> %s",
			on.ConfigDigest(), off.ConfigDigest())
	}
	if on.Name() == off.Name() {
		t.Errorf("two lists that decide oppositely share one name: %q", on.Name())
	}

	// And the other direction, which is the positive control: a false entry is
	// exactly as decisive as an absent one, so digesting the PAIRS rather than
	// the effective membership would be over-binding and would refuse a
	// comparison between two lists that decide identically.
	if off.ConfigDigest() != empty.ConfigDigest() {
		t.Errorf("a false member and no member decide identically but digest "+
			"differently:\n  {member: false} -> %s\n  {}              -> %s",
			off.ConfigDigest(), empty.ConfigDigest())
	}
	if got, want := off.Name(), empty.Name(); got != want {
		t.Errorf("the entry count includes members that decide nothing: %q vs %q", got, want)
	}
}

// TestAFixtureSetCannotKeepAnIdentityItNoLongerHas.
//
// The digest is over the bytes and is taken once. Every field a run reads is
// exported, so a caller can replace the cases after parsing and the digest
// would still name the file the cases came out of.
func TestAFixtureSetCannotKeepAnIdentityItNoLongerHas(t *testing.T) {
	set := bindSet(t, "held-out", "")
	original := set.BytesDigest()
	if !validDigest(original) {
		t.Fatalf("premise broken: a parsed set has no usable digest: %q", original)
	}

	// Mutating an exported field is all it takes.
	set.Cases[0].Label = LabelLegitimate

	if got := set.BytesDigest(); got == original {
		t.Errorf("a set whose cases were replaced still claims the identity of "+
			"the bytes it was parsed from: %s", got)
	} else if got != digestMutated {
		t.Errorf("a modified set reports %q, which is neither the original "+
			"digest nor the marker", got)
	}

	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1},
		&sourceregistry.Registry{SchemaVersion: 1}, WithSourceCommit(canonicalCommit))
	ok, missing := r.Reproducible()
	if ok {
		t.Error("a run over a modified set claims to carry every binding needed " +
			"to reproduce it")
	}
	if !strings.Contains(strings.Join(missing, " "), "modified after it was parsed") {
		t.Errorf("the reason does not say what happened: %v", missing)
	}
	if claimsFullReproducibility(t, r) {
		t.Error("the TEXT report claims full reproducibility for a modified set")
	}

	// Two runs over two DIFFERENTLY modified sets must not be comparable on
	// the strength of both carrying the same marker.
	other := bindSet(t, "held-out", "")
	other.Cases[0].Value = "two.example.com"
	r2 := Run(other, NullBaseline{}, CorroborationDetector{MinIndependent: 1},
		&sourceregistry.Registry{SchemaVersion: 1}, WithSourceCommit(canonicalCommit))
	if why, ok := comparableWith(r, r2); ok {
		t.Error("two runs over two different modified sets were reported comparable")
	} else if !strings.Contains(why, "fixture") {
		t.Errorf("the refusal does not name the fixture binding: %s", why)
	}
}

// TestAnUnmodifiedSetKeepsItsIdentity is the positive control for the above.
// Without it, a BytesDigest that returned the marker unconditionally would
// satisfy every assertion in it.
func TestAnUnmodifiedSetKeepsItsIdentity(t *testing.T) {
	set := bindSet(t, "held-out", "")
	first := set.BytesDigest()
	for i := 0; i < 3; i++ {
		if got := set.BytesDigest(); got != first {
			t.Fatalf("the digest of an untouched set is not stable: %q then %q", first, got)
		}
	}
	if !validDigest(first) {
		t.Errorf("an untouched parsed set does not carry a usable digest: %q", first)
	}
	// Reading a case must not count as changing one.
	_ = set.Cases[0].Label
	if got := set.BytesDigest(); got != first {
		t.Errorf("reading a case changed the digest: %q", got)
	}

	r := boundResult(t, canonicalCommit)
	if ok, missing := r.Reproducible(); !ok {
		t.Errorf("an ordinary run is no longer reproducible: %v", missing)
	}
}

// movingDetector changes its own configuration as it decides.
//
// It is not a hypothetical: Detector is an exported interface, an
// implementation may keep state, and nothing in the package prevented one from
// being measured under a binding taken before it moved.
type movingDetector struct {
	decisions int
}

func (d *movingDetector) Name() string { return "moving" }

func (d *movingDetector) Decide(Evidence) (Decision, string) {
	d.decisions++
	return DecisionPass, "moving"
}

func (d *movingDetector) ConfigDigest() string {
	return digestValue("moving-detector", struct {
		Decisions int `json:"decisions"`
	}{d.decisions})
}

// steadyDetector is the same shape with a configuration that does not move. It
// is the positive control for the run-stability check.
type steadyDetector struct{}

func (steadyDetector) Name() string                       { return "steady" }
func (steadyDetector) Decide(Evidence) (Decision, string) { return DecisionPass, "steady" }
func (steadyDetector) ConfigDigest() string {
	return digestValue("steady-detector", struct{}{})
}

// TestAnInputThatMovedDuringTheRunIsNotReportedAsOne.
func TestAnInputThatMovedDuringTheRunIsNotReportedAsOne(t *testing.T) {
	set := bindSet(t, "held-out", "two.example.com")

	t.Run("a candidate that reconfigures itself", func(t *testing.T) {
		cand := &movingDetector{}
		r := Run(set, NullBaseline{}, cand, &sourceregistry.Registry{SchemaVersion: 1},
			WithSourceCommit(canonicalCommit))
		if cand.decisions == 0 {
			t.Fatal("premise broken: the detector never decided, so it never moved")
		}
		if validDigest(r.Binding.CandidateDigest) {
			t.Errorf("a candidate that changed configuration mid-run is bound to "+
				"one configuration: %s", r.Binding.CandidateDigest)
		}
		ok, missing := r.Reproducible()
		if ok {
			t.Error("a run under a moving candidate claims full reproducibility")
		}
		if !strings.Contains(strings.Join(missing, " "), "while the run was in progress") {
			t.Errorf("the reason does not say what happened: %v", missing)
		}
	})

	t.Run("a baseline that reconfigures itself", func(t *testing.T) {
		r := Run(set, &movingDetector{}, steadyDetector{},
			&sourceregistry.Registry{SchemaVersion: 1}, WithSourceCommit(canonicalCommit))
		if validDigest(r.Binding.BaselineDigest) {
			t.Errorf("a baseline that changed mid-run is bound to one "+
				"configuration: %s", r.Binding.BaselineDigest)
		}
		// Two such runs must not become comparable by both being marked.
		r2 := Run(set, &movingDetector{}, steadyDetector{},
			&sourceregistry.Registry{SchemaVersion: 1}, WithSourceCommit(canonicalCommit))
		if _, ok := comparableWith(r, r2); ok {
			t.Error("two runs whose baselines both moved were reported comparable")
		}
	})

	t.Run("a steady run is unaffected", func(t *testing.T) {
		r := Run(set, NullBaseline{}, steadyDetector{},
			&sourceregistry.Registry{SchemaVersion: 1}, WithSourceCommit(canonicalCommit))
		if !validDigest(r.Binding.CandidateDigest) {
			t.Errorf("a detector that did not move was marked unstable: %s",
				r.Binding.CandidateDigest)
		}
		if ok, missing := r.Reproducible(); !ok {
			t.Errorf("a steady run is no longer reproducible: %v", missing)
		}
	})
}

// TestTwoSilentResultsAreNotAgreed.
//
// A stored result is a file some other process wrote. comparableWith asked
// only whether two values DIFFER, so two files that were both silent about a
// field agreed about it trivially, and Improved then reported an improvement
// between two things not established to be the same measurement.
func TestTwoSilentResultsAreNotAgreed(t *testing.T) {
	spoil := []struct {
		field string
		apply func(*Binding)
		want  string
	}{
		{"BaselineDigest", func(b *Binding) { b.BaselineDigest = "" }, "baseline"},
		{"BaselineDigest (unavailable)",
			func(b *Binding) { b.BaselineDigest = digestUnavailable }, "baseline"},
		{"BaselineDigest (not a digest)",
			func(b *Binding) { b.BaselineDigest = "x" }, "baseline"},
		{"RegistryState", func(b *Binding) { b.RegistryState = "" }, "registry"},
		{"RegistryDigest", func(b *Binding) {
			b.RegistryState = registryPresent
			b.RegistryDigest = ""
		}, "registry"},
		{"SemanticsVersion", func(b *Binding) { b.SemanticsVersion = 0 }, "scoring rules"},
		{"FixtureDigest (not a digest)",
			func(b *Binding) { b.FixtureDigest = "x" }, "fixture"},
		{"FixtureDigest (mutation marker)",
			func(b *Binding) { b.FixtureDigest = digestMutated }, "fixture"},
	}

	for _, sp := range spoil {
		t.Run(sp.field, func(t *testing.T) {
			before := boundResult(t, canonicalCommit)
			after := boundResult(t, canonicalCommit)
			if why, ok := comparableWith(before, after); !ok {
				t.Fatalf("premise broken: two identical runs are incomparable: %s", why)
			}

			// BOTH sides, identically. This is the case the field-by-field
			// audit does not reach: it spoils one side only, so the values
			// differ and the existing inequality check fires.
			sp.apply(&before.Binding)
			sp.apply(&after.Binding)

			why, ok := comparableWith(before, after)
			if ok {
				t.Fatalf("two runs that are both silent about %s were reported "+
					"comparable", sp.field)
			}
			if !strings.Contains(why, sp.want) {
				t.Errorf("the refusal does not name %s: %s", sp.want, why)
			}

			better, reason := Improved(before, after)
			if better {
				t.Errorf("Improved reported an improvement between two runs not "+
					"established to measure the same thing: %s", reason)
			}
		})
	}
}

// TestAnHonestPairIsStillComparable is the positive control for the above: a
// tightening that refused every comparison would pass every assertion in it.
func TestAnHonestPairIsStillComparable(t *testing.T) {
	before := boundResult(t, canonicalCommit)
	after := boundResult(t, canonicalCommit)
	if why, ok := comparableWith(before, after); !ok {
		t.Fatalf("two ordinary runs are no longer comparable: %s", why)
	}

	// The absent-registry case must stay comparable too: two runs that BOTH
	// say "no registry was supplied" have made the same statement, which is
	// not the same as two runs that said nothing.
	noRegBefore := Run(bindSet(t, "held-out", ""), NullBaseline{},
		CorroborationDetector{MinIndependent: 1}, nil, WithSourceCommit(canonicalCommit))
	noRegAfter := Run(bindSet(t, "held-out", ""), NullBaseline{},
		CorroborationDetector{MinIndependent: 2}, nil, WithSourceCommit(canonicalCommit))
	if why, ok := comparableWith(noRegBefore, noRegAfter); !ok {
		t.Errorf("two runs that both state `absent` were refused: %s", why)
	}
}
