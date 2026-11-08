// SPDX-License-Identifier: AGPL-3.0-only

package domain

import (
	"errors"
	"strings"
	"testing"
)

// ORDER 8, control C-16, and FINDING-133.
//
// # WHY UNDERSCORE
//
// The profile excluded underscore via idna.StrictDomainName(true), on the
// reasoning that resolvers treat it inconsistently. That reasoning is about
// names one might *create*. ScamWall does not create names; it decides about
// names that already exist and are already resolving. Hosted phishing tenants
// use underscore, and `_dmarc`-style labels are ordinary. A host ScamWall
// cannot normalise is a host it can never block — the refusal was not a
// conservative choice, it was a hole with a conservative-sounding reason.
//
// The widening is by exactly one character. Everything a relaxed IDNA profile
// would otherwise admit — space, slash, at, percent, quote, backslash, bang,
// dollar, semicolon — must still be refused, and TestUnderscoreWideningAdmits
// NothingElse is what says so. Those are not merely invalid: a slash or a
// space in a name handed to a Pi-hole API, a log line or a blocklist file is
// its own hazard.

func TestUnderscoreLabelsAreBlockable(t *testing.T) {
	for _, in := range []string{
		"my_tenant.phish.co.uk",
		"under_score.example.org",
		"_dmarc.example.org",
		"a_b.c_d.example.org",
	} {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q) refused a name that exists and resolves: %v", in, err)
			continue
		}
		if !strings.Contains(got.String(), "_") {
			t.Errorf("Normalize(%q) = %q; the underscore was rewritten rather than kept", in, got)
		}
	}
}

// TestUnderscoreWideningAdmitsNothingElse is the control that bounds the fix.
//
// Each of these is admitted by idna.StrictDomainName(false), which is why the
// fix is not simply to turn that flag off.
func TestUnderscoreWideningAdmitsNothingElse(t *testing.T) {
	for _, in := range []string{
		"bad!char.example.org",
		"dollar$.example.org",
		"sp ace.example.org",
		"semi;colon.example.org",
		"slash/x.example.org",
		"at@sign.example.org",
		"per%cent.example.org",
		"quote\"x.example.org",
		"back\\slash.example.org",
		"tab\tchar.example.org",
	} {
		got, err := Normalize(in)
		if err == nil {
			t.Errorf("Normalize(%q) = %q; a name carrying that character reaches "+
				"a Pi-hole API call, a log line and a blocklist file", in, got)
		}
	}
}

// TestSharpSIsPreservedNotTransitioned. UTS #46 non-transitional: the ß must
// not become `ss`, or straße-bank.de and strasse-bank.de become one name and
// a block on either hits the other.
func TestSharpSIsPreservedNotTransitioned(t *testing.T) {
	got, err := Normalize("straße-bank.de")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got.String() == "strasse-bank.de" {
		t.Fatal("ß was mapped to ss; that is transitional processing, and it " +
			"merges two distinct registrable names")
	}
	if got.String() != "xn--strae-bank-83a.de" {
		t.Errorf("Normalize(straße-bank.de) = %q, want the non-transitional A-label", got)
	}
}

// TestStableReasonCodes. C-16 requires IP literals, single labels and
// wildcards to be refused with a stable reason, not a free-text message.
func TestStableReasonCodes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want error
	}{
		{"1.2.3.4", ErrIPLiteral},
		{"2001:db8::1", ErrIPLiteral},
		{"singlelabel", ErrSingleLabel},
		{"*.evil.example.org", ErrWildcard},
		{"localhost", ErrLocalhost},
	} {
		_, err := Normalize(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("Normalize(%q) error = %v, want %v", tc.in, err, tc.want)
		}
	}
}

// TestCanonicalFormIsIdempotentWithUnderscores. The whole plan-digest and
// deduplication model depends on one name having one spelling.
func TestCanonicalFormIsIdempotentWithUnderscores(t *testing.T) {
	for _, in := range []string{"MY_Tenant.Phish.CO.UK", "_DMARC.example.ORG"} {
		once, err := Normalize(in)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}
		twice, err := Normalize(once.String())
		if err != nil {
			t.Fatalf("Normalize(%q): %v", once, err)
		}
		if once != twice {
			t.Errorf("%q normalises to %q then to %q; the canonical form is not canonical", in, once, twice)
		}
	}
}
