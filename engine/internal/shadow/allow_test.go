// SPDX-License-Identifier: AGPL-3.0-only

package shadow

import (
	"strings"
	"testing"
)

// ORDER 8 control C-18, FINDING-132, at this package's surface.
//
// The question this file answers is not "does a regex match" — that is
// internal/policy's, and is tested there. It is: does a plan tell the truth
// about what it checked?

// allowing is an AllowList that covers exactly the names given.
type allowing struct {
	names       map[string]bool
	unevaluable int
}

func (a allowing) Allowed(d string) bool { return a.names[d] }

// Cover reports these fixtures' entries as EXACT, which is what they are.
func (a allowing) Cover(d string) (bool, bool) { return a.names[d], false }
func (a allowing) Unevaluable() int            { return a.unevaluable }
func (a allowing) Counts() (int, int)          { return len(a.names), a.unevaluable }
func (a allowing) Read() bool                  { return true }
func (a allowing) Source() string              { return "synthetic" }

// TestAHouseholdAllowedNameIsNotProposedAsAnAddition.
//
// The addition would be inert: Pi-hole resolves allow against deny in the
// allow's favour. A plan that listed it as an addition would be claiming work
// that will not happen.
func TestAHouseholdAllowedNameIsNotProposedAsAnAddition(t *testing.T) {
	in := input([]string{"wanted.example.com", "scam.example.com"}, observation(), NoOwnership{})
	in.Allow = allowing{names: map[string]bool{"wanted.example.com": true}}

	p := mustCompare(t, in)
	if got := kindOf(t, p, "wanted.example.com"); got != KindHouseholdAllowed {
		t.Errorf("kind = %q, want %q; the household already said it wants this name",
			got, KindHouseholdAllowed)
	}
	if got := kindOf(t, p, "scam.example.com"); got != KindAdd {
		t.Errorf("kind = %q, want %q; one allowed name must not suppress the others", got, KindAdd)
	}
}

// TestAnUnreadablePatternWithholdsTheAdditionRatherThanGuessing.
//
// "No pattern I could read matched" is a weaker statement than "no pattern
// matched", and only the second licenses a block.
func TestAnUnreadablePatternWithholdsTheAdditionRatherThanGuessing(t *testing.T) {
	in := input([]string{"scam.example.com"}, observation(), NoOwnership{})
	in.Allow = allowing{names: map[string]bool{}, unevaluable: 1}

	p := mustCompare(t, in)
	if got := kindOf(t, p, "scam.example.com"); got != KindAllowNotEvaluable {
		t.Errorf("kind = %q, want %q", got, KindAllowNotEvaluable)
	}
}

// TestAKnownAllowBeatsAnUnreadableOne. A host the readable patterns DO cover
// is reported as allowed, not as undecidable: the ordering of the two cases is
// itself a claim and is asserted rather than left to the reader of the switch.
func TestAKnownAllowBeatsAnUnreadableOne(t *testing.T) {
	in := input([]string{"wanted.example.com"}, observation(), NoOwnership{})
	in.Allow = allowing{names: map[string]bool{"wanted.example.com": true}, unevaluable: 3}

	p := mustCompare(t, in)
	if got := kindOf(t, p, "wanted.example.com"); got != KindHouseholdAllowed {
		t.Errorf("kind = %q, want %q", got, KindHouseholdAllowed)
	}
}

// TestAnUnreadAllowListIsStatedOnEveryAddition.
//
// This is the property that makes the whole change worth having. Every build
// before ORDER 8 behaved like this run and said nothing about it.
func TestAnUnreadAllowListIsStatedOnEveryAddition(t *testing.T) {
	in := input([]string{"scam.example.com"}, observation(), NoOwnership{})
	in.Allow = AllowNotRead{}

	p := mustCompare(t, in)
	if got := kindOf(t, p, "scam.example.com"); got != KindAdd {
		t.Fatalf("kind = %q, want %q; not reading the allow lists must not suppress "+
			"the addition, only qualify it", got, KindAdd)
	}
	for _, c := range p.Changes {
		if c.Domain != "scam.example.com" {
			continue
		}
		if !strings.Contains(c.Explanation, "NOT checked") {
			t.Errorf("an addition from a run that never read the allow lists does not "+
				"say so: %q", c.Explanation)
		}
	}
}

// TestANilAllowListIsRefused. A nil and an empty AllowList answer every domain
// the same way and mean opposite things, exactly as for Ownership.
func TestANilAllowListIsRefused(t *testing.T) {
	in := input([]string{"scam.example.com"}, observation(), NoOwnership{})
	in.Allow = nil

	if _, err := Compare(in); err == nil {
		t.Fatal("a comparison with no allow-list answer was accepted")
	} else if !strings.Contains(err.Error(), "allow-list answer") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// TestADisabledAllowEntryIsNotPermission is the mirror of
// TestADisabledEntryIsNotProtection: a switched-off allow entry permits
// nothing, and counting it would report the household as having allowed
// something it turned off. Enforced where the rows are read, in cmd's
// newAllowList; asserted here as the property the plan depends on.
func TestADisabledAllowEntryIsNotPermission(t *testing.T) {
	// An AllowList built from only the ENABLED rows does not cover the name.
	in := input([]string{"switched-off.example.com"}, observation(), NoOwnership{})
	in.Allow = allowing{names: map[string]bool{}}

	p := mustCompare(t, in)
	if got := kindOf(t, p, "switched-off.example.com"); got != KindAdd {
		t.Errorf("kind = %q, want %q; a disabled allow entry is not permission", got, KindAdd)
	}
}
