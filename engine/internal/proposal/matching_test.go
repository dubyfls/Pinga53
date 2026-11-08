// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"errors"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// canon is the canonical form of a name, or a fatal error. Every argument to
// Covers is a canonical form in the real code path, so a test that passed it
// anything else would be measuring a function that is never called that way.
func canon(t *testing.T, raw string) string {
	t.Helper()
	d, err := domain.Normalize(raw)
	if err != nil {
		t.Fatalf("%q is not a valid domain: %v", raw, err)
	}
	return d.String()
}

// TestMatchingIsOverLabelsAndNotOverCharacters.
//
// The table is the requirement: exact hit and miss, children and siblings, the
// bad/notbad pair, trailing dots and case, Unicode and punycode.
func TestMatchingIsOverLabelsAndNotOverCharacters(t *testing.T) {
	cases := []struct {
		name  string
		base  string
		scope Scope
		query string
		want  bool
	}{
		// exact
		{"exact hit", "bad.example.com", ScopeExact, "bad.example.com", true},
		{"exact miss", "bad.example.com", ScopeExact, "other.example.com", false},
		{"exact does not reach a child", "example.com", ScopeExact, "a.example.com", false},
		{"exact does not reach a parent", "a.example.com", ScopeExact, "example.com", false},

		// children and siblings
		{"a child", "example.com", ScopeSubdomains, "a.example.com", true},
		{"a grandchild", "example.com", ScopeSubdomains, "a.b.example.com", true},
		{"a sibling", "a.example.com", ScopeSubdomains, "b.example.com", false},
		{"the apex, under subdomains", "example.com", ScopeSubdomains, "example.com", false},
		{"a parent, under subdomains", "a.example.com", ScopeSubdomains, "example.com", false},

		// THE pair. A naive strings.HasSuffix answers true for the second.
		{"bad.example.com matches itself", "bad.example.com", ScopeExact, "bad.example.com", true},
		{"notbad.example.com is somebody else", "bad.example.com", ScopeExact, "notbad.example.com", false},
		{"notbad.example.com is not beneath bad.example.com", "bad.example.com", ScopeSubdomains, "notbad.example.com", false},
		{"a suffix that is not a label boundary", "ample.com", ScopeSubdomains, "ex.ample.com", true},
		{"a substring in the middle", "example.com", ScopeSubdomains, "example.com.attacker.example.net", false},
		{"a substring in the middle, exact", "example.com", ScopeExact, "example.com.attacker.example.net", false},

		// punycode: both sides canonicalise to the same ACE form
		{"an internationalised child", "例え.example.com", ScopeSubdomains, "a.例え.example.com", true},
		{"punycode input matches its Unicode spelling", "xn--r8jz45g.example.com", ScopeExact, "例え.example.com", true},
		{"a different internationalised name", "例え.example.com", ScopeExact, "テスト.example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Covers(canon(t, tc.base), tc.scope, canon(t, tc.query))
			if got != tc.want {
				t.Errorf("Covers(%q, %s, %q) = %v, want %v", tc.base, tc.scope, tc.query, got, tc.want)
			}
		})
	}
}

// TestTrailingDotsAndCaseAreCanonicalisedBeforeAnythingIsCompared.
//
// Matching never sees these spellings: internal/domain removes one trailing
// root dot and lowercases. The test is here because the property is what makes
// a string comparison legitimate at all.
func TestTrailingDotsAndCaseAreCanonicalisedBeforeAnythingIsCompared(t *testing.T) {
	want := canon(t, "bad.example.com")
	for _, spelling := range []string{
		"bad.example.com", "BAD.EXAMPLE.COM", "Bad.Example.Com",
		"bad.example.com.", "BAD.example.COM.", "  bad.example.com  ",
	} {
		if got := canon(t, spelling); got != want {
			t.Errorf("%q canonicalises to %q, want %q", spelling, got, want)
		}
		if !Covers(want, ScopeExact, canon(t, spelling)) {
			t.Errorf("%q does not match its own canonical form", spelling)
		}
	}
	// Two trailing dots is malformed, not a spelling.
	if _, err := domain.Normalize("bad.example.com.."); err == nil {
		t.Error("a repeated trailing dot was accepted as a name")
	}
}

// TestAnUnknownScopeReachesNothing.
//
// A scope this build does not understand must not be read as the more
// permissive of the two it does. ParsePolicy refuses one, so this is defence
// in depth for a Policy assembled in memory.
func TestAnUnknownScopeReachesNothing(t *testing.T) {
	for _, q := range []string{"example.com", "a.example.com", ""} {
		if Covers("example.com", Scope("everything"), q) {
			t.Errorf("an unrecognised scope reached %q", q)
		}
	}
}

// TestExceptionPrecedenceIsBySpecificity.
//
// The property that matters: adding a NARROWER exception must not change the
// decision about any name the narrower one does not itself reach.
func TestExceptionPrecedenceIsBySpecificity(t *testing.T) {
	broad := Exception{Value: "example.com", Scope: ScopeSubdomains, Note: "everything under it"}
	narrow := Exception{Value: "pay.example.com", Scope: ScopeExact, Note: "the payments host"}
	apex := Exception{Value: "example.com", Scope: ScopeExact, Note: "the apex itself"}

	t.Run("the most specific exception wins", func(t *testing.T) {
		p := testPolicy(t, 1, ScopeExact, broad, narrow)
		m, ok := p.MatchException(canon(t, "pay.example.com"))
		if !ok {
			t.Fatal("no exception matched a name two of them reach")
		}
		if m.Exception.Canonical() != canon(t, "pay.example.com") {
			t.Errorf("the broader exception won: %q", m.Exception.Canonical())
		}
	})

	t.Run("the order in the file changes nothing", func(t *testing.T) {
		a := testPolicy(t, 1, ScopeExact, broad, narrow)
		b := testPolicy(t, 1, ScopeExact, narrow, broad)
		ma, _ := a.MatchException(canon(t, "pay.example.com"))
		mb, _ := b.MatchException(canon(t, "pay.example.com"))
		if ma.Exception.Canonical() != mb.Exception.Canonical() {
			t.Errorf("file order decided the winner: %q then %q",
				ma.Exception.Canonical(), mb.Exception.Canonical())
		}
		if a.Digest() != b.Digest() {
			t.Error("reordering the exceptions changed the policy digest")
		}
	})

	t.Run("exact beats subdomains at equal specificity", func(t *testing.T) {
		p := testPolicy(t, 1, ScopeExact, broad, apex)
		m, ok := p.MatchException(canon(t, "example.com"))
		if !ok {
			t.Fatal("the apex matched no exception")
		}
		if m.Exception.Scope != ScopeExact {
			t.Errorf("the subdomain rule won at the apex, which it does not even reach: %s", m.Exception.Scope)
		}
	})

	t.Run("a name no exception reaches matches none", func(t *testing.T) {
		p := testPolicy(t, 1, ScopeExact, broad, narrow)
		for _, q := range []string{"example.net", "notexample.com", "example.com.attacker.example.net"} {
			if m, ok := p.MatchException(canon(t, q)); ok {
				t.Errorf("%q was excepted by %q at %s", q, m.Exception.Canonical(), m.Exception.Scope)
			}
		}
	})

	t.Run("the apex is not reached by a subdomain exception", func(t *testing.T) {
		p := testPolicy(t, 1, ScopeExact, broad)
		if _, ok := p.MatchException(canon(t, "example.com")); ok {
			t.Error("a `subdomains` exception reached the apex; see ScopeSubdomains")
		}
		if _, ok := p.MatchException(canon(t, "a.example.com")); !ok {
			t.Error("a `subdomains` exception did not reach a child")
		}
	})
}

// TestAPolicyIsRefusedRatherThanDefaulted.
func TestAPolicyIsRefusedRatherThanDefaulted(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"the wrong schema version", `{"schema_version":99,"min_independent_sources":1,"proposal_scope":"exact"}`, ErrPolicySchema},
		{"no threshold", `{"schema_version":1,"proposal_scope":"exact"}`, ErrPolicyInvalid},
		{"a threshold of zero", `{"schema_version":1,"min_independent_sources":0,"proposal_scope":"exact"}`, ErrPolicyInvalid},
		{"a negative threshold", `{"schema_version":1,"min_independent_sources":-1,"proposal_scope":"exact"}`, ErrPolicyInvalid},
		{"no proposal scope", `{"schema_version":1,"min_independent_sources":1}`, ErrPolicyInvalid},
		{"an invented scope", `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"everything"}`, ErrPolicyInvalid},
		{"an exception with no scope", `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			"exceptions":[{"value":"example.com"}]}`, ErrPolicyInvalid},
		{"an exception that is not a domain", `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			"exceptions":[{"value":"not a domain","scope":"exact"}]}`, ErrPolicyInvalid},
		{"the same exception twice", `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			"exceptions":[{"value":"example.com","scope":"exact"},{"value":"EXAMPLE.COM.","scope":"exact"}]}`, ErrPolicyInvalid},
		{"an unknown field", `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact","enforce":true}`, nil},
		{"a second document", `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact"}{"x":1}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tc.doc))
			if err == nil {
				t.Fatal("an unusable policy was accepted")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("an ordinary policy is accepted", func(t *testing.T) {
		p, err := ParsePolicy([]byte(`{"schema_version":1,"min_independent_sources":2,
			"proposal_scope":"subdomains","accept_unestablished_independence":false,
			"exceptions":[{"value":"BANK.example.com.","scope":"exact","note":"the household's bank"}]}`))
		if err != nil {
			t.Fatalf("a well-formed policy was refused: %v", err)
		}
		if *p.MinIndependentSources != 2 || p.ProposalScope != ScopeSubdomains {
			t.Errorf("the policy did not decode as written: %+v", p)
		}
		if got := p.Exceptions[0].Canonical(); got != "bank.example.com" {
			t.Errorf("the exception was not canonicalised: %q", got)
		}
	})
}

// TestASubdomainRuleOnAPublicSuffixIsRefused.
//
// One line of an operator's file must not be able to reach every name
// registered under a suffix. The fact needed to refuse it is looked up in the
// compiled public-suffix list, never inferred from the shape of the name:
// co.uk is a suffix and co.com is not, and no amount of label counting
// distinguishes them.
func TestASubdomainRuleOnAPublicSuffixIsRefused(t *testing.T) {
	refused := []string{"com", "co.uk", "org.uk", "github.io"}
	for _, base := range refused {
		t.Run("refused: "+base, func(t *testing.T) {
			doc := `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
				"exceptions":[{"value":"` + base + `","scope":"subdomains"}]}`
			_, err := ParsePolicy([]byte(doc))
			if err == nil {
				t.Fatalf("a `subdomains` rule on the public suffix %q was accepted", base)
			}
			if !errors.Is(err, ErrPolicyInvalid) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			if !strings.Contains(err.Error(), "public suffix") && !strings.Contains(err.Error(), "single label") {
				t.Errorf("the refusal does not say what is wrong with the name: %v", err)
			}
		})
	}

	// The positive control, and it is required: refusing EVERY subdomain rule
	// would satisfy all of the above and make the scope useless.
	allowed := []string{"example.com", "example.co.uk", "sub.example.com", "someone.github.io"}
	for _, base := range allowed {
		t.Run("allowed: "+base, func(t *testing.T) {
			doc := `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
				"exceptions":[{"value":"` + base + `","scope":"subdomains"}]}`
			if _, err := ParsePolicy([]byte(doc)); err != nil {
				t.Fatalf("a registrable name was refused a `subdomains` rule: %v", err)
			}
		})
	}

	t.Run("an exact rule on a suffix is refused too, one layer down", func(t *testing.T) {
		// Not this package's doing: internal/domain refuses the NAME, so no
		// scope of any kind can be written against a public suffix. Asserted so
		// that the boundary is recorded where a reader of this package looks.
		doc := `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			"exceptions":[{"value":"com","scope":"exact"}]}`
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Fatal("a rule on a bare public suffix was accepted")
		}
	})
}
