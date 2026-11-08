// SPDX-License-Identifier: AGPL-3.0-only

package policy

import "testing"

// ORDER 8, control C-18. The household's allow entries win, and an allow
// pattern ScamWall cannot evaluate faithfully makes the decision ABSTAIN
// rather than block.
//
// # WHY ABSTAIN AND NOT "IGNORE THE PATTERN"
//
// Pi-hole's regexes are POSIX ERE evaluated by the appliance. Go's regexp is
// RE2. The two overlap but are not the same language, and where they differ
// the difference is silent: a pattern that means one thing on the appliance
// and another here does not announce itself. Guessing in the household's
// disfavour is the one outcome this project will not ship, so a pattern that
// cannot be evaluated faithfully removes ScamWall's opinion rather than the
// household's.
//
// The cost is real and is the point of the counts: enough unevaluable
// patterns and the product says nothing at all. That is visible rather than
// silent — DESIGN_LEDGER GAP-004 describes the same fail-safe on the other
// tree and worries it can turn the product off unnoticed. It is reported.

func TestPlainPatternsAreEvaluated(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{`(^|\.)bank\.example\.com$`, "bank.example.com", true},
		{`(^|\.)bank\.example\.com$`, "login.bank.example.com", true},
		{`(^|\.)bank\.example\.com$`, "bank.example.com.evil.org", false},
		{`^ads\.`, "ads.example.com", true},
		{`^ads\.`, "noads.example.com", false},
	} {
		a := ParseAllowRegex(tc.pattern)
		if !a.Evaluable {
			t.Errorf("ParseAllowRegex(%q) is not evaluable: %s", tc.pattern, a.Why)
			continue
		}
		if got := a.Matches(tc.host); got != tc.want {
			t.Errorf("%q matches %q = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

// TestUnevaluableConstructsAreRefusedNotGuessed names each construct C-18
// lists, so a future change that starts accepting one has to say so here.
func TestUnevaluableConstructsAreRefusedNotGuessed(t *testing.T) {
	for _, pattern := range []string{
		`[[:alnum:]]+\.example\.com`, // POSIX class
		`\<word\>`,                   // GNU word boundaries
		`(a)\1`,                      // back-reference
		`(?i)example\.com`,           // inline group flags
		`(?=lookahead)`,              // lookaround
		`example\.com;invert`,        // the invert option
	} {
		a := ParseAllowRegex(pattern)
		if a.Evaluable {
			t.Errorf("ParseAllowRegex(%q) claims to be evaluable; the appliance "+
				"and this process do not agree on what it means", pattern)
		}
		if a.Why == "" {
			t.Errorf("ParseAllowRegex(%q) refused without saying why", pattern)
		}
		if a.Matches("anything.example.com") {
			t.Errorf("ParseAllowRegex(%q) matched despite being unevaluable; an "+
				"unevaluable pattern must never answer yes or no", pattern)
		}
	}
}

// TestQuerytypeOptionIsStrippedAndTheRestEvaluated. C-18 names this one
// specifically: `;querytype=` narrows which query types a rule applies to and
// does not change what the pattern matches, so it is removed and the pattern
// is evaluated.
func TestQuerytypeOptionIsStrippedAndTheRestEvaluated(t *testing.T) {
	a := ParseAllowRegex(`(^|\.)bank\.example\.com$;querytype=A`)
	if !a.Evaluable {
		t.Fatalf("a querytype option made the pattern unevaluable: %s", a.Why)
	}
	if !a.Matches("bank.example.com") {
		t.Error("the pattern stopped matching once its option was stripped")
	}
}

// TestCoverageReportsUnevaluablePatterns is what makes the fail-safe visible.
func TestCoverageReportsUnevaluablePatterns(t *testing.T) {
	exact := []string{"allowed.example.com"}
	regexes := []string{`(^|\.)ok\.example\.com$`, `[[:alnum:]]x`}

	c := CoverAllow("allowed.example.com", exact, regexes)
	if !c.ExactMatch {
		t.Error("an exact allow entry did not register")
	}
	if c.Unevaluable != 1 {
		t.Errorf("unevaluable = %d, want 1", c.Unevaluable)
	}

	c = CoverAllow("ok.example.com", exact, regexes)
	if !c.RegexMatch {
		t.Error("an evaluable allow regex did not register")
	}

	c = CoverAllow("unrelated.example.org", exact, regexes)
	if c.ExactMatch || c.RegexMatch {
		t.Error("a host no allow entry names was reported as allowed")
	}
	if !c.MustAbstain() {
		t.Error("a host is not covered, but one allow pattern could not be " +
			"evaluated; ScamWall cannot know whether it is allowed and must abstain")
	}
}

// TestAnExactAllowIsCaseAndDotInsensitiveTheWayTheApplianceIs.
func TestAnExactAllowMatchesCanonically(t *testing.T) {
	c := CoverAllow("bank.example.com", []string{"BANK.Example.COM."}, nil)
	if !c.ExactMatch {
		t.Error("an allow entry written with different case and a trailing dot " +
			"did not match; the appliance treats them as one name")
	}
}
