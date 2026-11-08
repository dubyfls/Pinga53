// SPDX-License-Identifier: AGPL-3.0-only

package shadow

import (
	"strings"
	"testing"
	"time"
)

// C-25 — Pi-hole's precedence is modelled, not assumed.
//
// ORDER 8 left "does the appliance resolve allow over deny?" as its first
// owner question, and FINDING-132's severity was lowered on the assumption
// that it does. The appliance documents the answer, and it is longer than one
// bit: six levels, and ScamWall's exact deny sits in the MIDDLE of them.
// Two of the four things below it are the household's own choices.

func hostState(exactAllow, regexAllow bool, sub Tristate) HostState {
	return HostState{ExactAllow: exactAllow, RegexAllow: regexAllow, SubscribedAllow: sub}
}

func TestTheDocumentedOrderIsEncodedOnce(t *testing.T) {
	for name, tc := range map[string]struct {
		state HostState
		want  AddLabel
	}{
		"nothing above it": {hostState(false, false, No), LabelEffective},
		"an exact allow":   {hostState(true, false, No), LabelOverriddenByExactAllow},
		"a regex allow":    {hostState(false, true, No), LabelOverriddenByRegexAllow},
		"both allows, exact reported": {
			// The order is an order. A host covered by both reports the
			// higher one, so two runs over the same appliance say the same
			// thing and an operator fixing it knows which entry to look at.
			hostState(true, true, No), LabelOverriddenByExactAllow,
		},
		"a subscribed allowlist": {hostState(false, false, Yes), LabelOverridesSubscribedAllowlist},
		"subscribed membership unknown": {
			hostState(false, false, Unknown), LabelUnknownSubscribedAllowlist,
		},
		"an exact allow outranks a subscribed allowlist": {
			// Both would stop the add mattering, and they are different
			// facts: one says the add is inert, the other says the add WINS
			// and overrides something the household chose.
			hostState(true, false, Yes), LabelOverriddenByExactAllow,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := LabelAdd(tc.state); got != tc.want {
				t.Errorf("LabelAdd(%+v) = %s, want %s", tc.state, got, tc.want)
			}
		})
	}
}

// TestAnAddThatWouldOverrideASubscribedAllowlistGoesToReview is the clause
// the control exists for. ScamWall's exact deny BEATS a list the household
// subscribed to, and beating the household is not something an unattended
// system may do quietly.
func TestAnAddThatWouldOverrideASubscribedAllowlistGoesToReview(t *testing.T) {
	p := planWith(t, Input{
		Qualifying:        []string{"bad.example.com"},
		Observed:          observationOf(),
		Owned:             NoOwnership{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: "2026-03-01T12:00:00Z",
		ComparedAt:        time.Date(2026, 3, 1, 12, 5, 0, 0, time.UTC),
		BuildIdentity:     "scamwall test (synthetic)",
		Allow:             allowNothing{},
		Subscribed:        fixedSubscription{allow: Yes},
	})
	c := changeFor(t, p, "bad.example.com")
	if c.Kind != KindReview {
		t.Fatalf("kind = %s, want %s\n  %s", c.Kind, KindReview, c.Explanation)
	}
	if c.Precedence != LabelOverridesSubscribedAllowlist {
		t.Errorf("precedence = %s, want %s", c.Precedence, LabelOverridesSubscribedAllowlist)
	}
	if p.Requests() {
		t.Errorf("a plan whose only item is a review item reports that it would request something")
	}
	if !strings.Contains(c.Explanation, "subscribed") {
		t.Errorf("the explanation does not say what would be overridden: %q", c.Explanation)
	}
}

// TestUnknownSubscribedMembershipAlsoGoesToReview — the PARTIAL fallback
// ORDER 9 §C-25 names. This build cannot read gravity, so this is the branch
// every addition takes today.
func TestUnknownSubscribedMembershipAlsoGoesToReview(t *testing.T) {
	p := planWith(t, Input{
		Qualifying:        []string{"bad.example.com"},
		Observed:          observationOf(),
		Owned:             NoOwnership{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: "2026-03-01T12:00:00Z",
		ComparedAt:        time.Date(2026, 3, 1, 12, 5, 0, 0, time.UTC),
		BuildIdentity:     "scamwall test (synthetic)",
		Allow:             allowNothing{},
		Subscribed:        SubscribedNotRead{},
	})
	c := changeFor(t, p, "bad.example.com")
	if c.Kind != KindReview {
		t.Fatalf("kind = %s, want %s\n  %s", c.Kind, KindReview, c.Explanation)
	}
	if c.Precedence != LabelUnknownSubscribedAllowlist {
		t.Errorf("precedence = %s, want %s", c.Precedence, LabelUnknownSubscribedAllowlist)
	}
}

// TestAnEffectiveAddIsStillAnAdd — the control on the control. A build that
// COULD read the subscribed lists and found the host in none of them must
// still be able to say "this would take effect", or the label is an off
// switch.
func TestAnEffectiveAddIsStillAnAdd(t *testing.T) {
	p := planWith(t, Input{
		Qualifying:        []string{"bad.example.com"},
		Observed:          observationOf(),
		Owned:             NoOwnership{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: "2026-03-01T12:00:00Z",
		ComparedAt:        time.Date(2026, 3, 1, 12, 5, 0, 0, time.UTC),
		BuildIdentity:     "scamwall test (synthetic)",
		Allow:             allowNothing{},
		Subscribed:        fixedSubscription{allow: No},
	})
	c := changeFor(t, p, "bad.example.com")
	if c.Kind != KindAdd {
		t.Fatalf("kind = %s, want %s\n  %s", c.Kind, KindAdd, c.Explanation)
	}
	if c.Precedence != LabelEffective {
		t.Errorf("precedence = %s, want %s", c.Precedence, LabelEffective)
	}
	if !p.Requests() {
		t.Errorf("an effective addition does not report itself as a request")
	}
}

// TestAHouseholdAllowStillOutranksEverything — C-18's answer is unchanged by
// C-25 and must stay unchanged: the precedence table says so in its top two
// rows.
func TestAHouseholdAllowStillOutranksEverything(t *testing.T) {
	p := planWith(t, Input{
		Qualifying:        []string{"bad.example.com"},
		Observed:          observationOf(),
		Owned:             NoOwnership{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: "2026-03-01T12:00:00Z",
		ComparedAt:        time.Date(2026, 3, 1, 12, 5, 0, 0, time.UTC),
		BuildIdentity:     "scamwall test (synthetic)",
		Allow:             allowExactly{name: "bad.example.com"},
		Subscribed:        fixedSubscription{allow: Yes},
	})
	c := changeFor(t, p, "bad.example.com")
	if c.Kind != KindHouseholdAllowed {
		t.Fatalf("kind = %s, want %s\n  %s", c.Kind, KindHouseholdAllowed, c.Explanation)
	}
	if c.Precedence != LabelOverriddenByExactAllow {
		t.Errorf("precedence = %s, want %s", c.Precedence, LabelOverriddenByExactAllow)
	}
}

// TestANilSubscriptionIsRefused — nil and "read nothing" answer every domain
// identically and mean opposite things, which is the rule this package
// already applies to Ownership and to AllowList.
func TestANilSubscriptionIsRefused(t *testing.T) {
	_, err := Compare(Input{
		Qualifying:        []string{"bad.example.com"},
		Observed:          observationOf(),
		Owned:             NoOwnership{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: "2026-03-01T12:00:00Z",
		ComparedAt:        time.Date(2026, 3, 1, 12, 5, 0, 0, time.UTC),
		BuildIdentity:     "scamwall test (synthetic)",
		Allow:             allowNothing{},
		Subscribed:        nil,
	})
	if err == nil {
		t.Fatalf("a nil subscription answer was accepted")
	}
}

// TestThePrecedenceOrderIsStatedInOnePlace — the control says "encode this
// order once, in one function". A second copy is a second behaviour the first
// time one of them is corrected.
func TestThePrecedenceOrderIsStatedInOnePlace(t *testing.T) {
	// The levels are declared in ascending order and nothing skips or
	// repeats: a table whose numbers drifted would let two labels claim the
	// same level and the comparison below would silently pick one.
	levels := []Precedence{
		PrecExactAllow, PrecRegexAllow, PrecExactDeny,
		PrecSubscribedAllow, PrecSubscribedDeny, PrecRegexDeny,
	}
	for i := 1; i < len(levels); i++ {
		if levels[i] != levels[i-1]+1 {
			t.Fatalf("level %d is %d and the one before it is %d", i, levels[i], levels[i-1])
		}
	}
	if PrecExactDeny <= PrecRegexAllow || PrecExactDeny >= PrecSubscribedAllow {
		t.Fatalf("ScamWall's exact deny is not between the regex allow and the subscribed allowlists, " +
			"which is the whole shape of this control")
	}
}

// TestEveryKindTheComparisonProducesIsRendered.
//
// A count line that names a category the body never prints sends its reader
// looking for lines that are not there — and with C-25 the kind this build
// produces most of the time is the one that was missing from the renderer.
func TestEveryKindTheComparisonProducesIsRendered(t *testing.T) {
	for _, k := range []Kind{
		KindAdd, KindReview, KindRemove, KindConflict, KindDisabledEntry,
		KindAlreadyPresent, KindHouseholdAllowed, KindAllowNotEvaluable,
	} {
		p := &Plan{Changes: []Change{{Kind: k, Domain: "x.example.com", Explanation: "synthetic"}}}
		var b strings.Builder
		p.Text(&b)
		if !strings.Contains(b.String(), "x.example.com") {
			t.Errorf("a change of kind %s does not appear in the text plan:\n%s", k, b.String())
		}
	}
}

// TestThePrecedenceLabelIsPrinted — the label is the whole content of C-25's
// output, and a field nobody prints is a field nobody acts on.
func TestThePrecedenceLabelIsPrinted(t *testing.T) {
	p := planWith(t, Input{
		Qualifying:        []string{"bad.example.com"},
		Observed:          observationOf(),
		Owned:             NoOwnership{},
		Allow:             allowNothing{},
		Subscribed:        SubscribedNotRead{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: "2026-03-01T12:00:00Z",
		ComparedAt:        time.Date(2026, 3, 1, 12, 5, 0, 0, time.UTC),
		BuildIdentity:     "scamwall test (synthetic)",
	})
	var b strings.Builder
	p.Text(&b)
	if !strings.Contains(b.String(), string(LabelUnknownSubscribedAllowlist)) {
		t.Errorf("the plan does not print the precedence label:\n%s", b.String())
	}
}
