// SPDX-License-Identifier: AGPL-3.0-only

package domain_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// TestConfusableLookalikesAreSignalled covers the homograph constructions the
// old rejection existed to catch. Each must now be VALID and SIGNALLED, which
// is a strictly more informative outcome than an error: the caller learns both
// that the name parses and that it is worth a look.
func TestConfusableLookalikesAreSignalled(t *testing.T) {
	cases := map[string]string{
		"cyrillic a leading a latin word": "аpple.example.com",
		"cyrillic o inside a latin word":  "gоogle.example.com",
		"greek omicron inside latin":      "gοogle.example.com",
		"cyrillic a inside paypal":        "paypаl.example.com",
		"cyrillic in the second label":    "example.gооgle-mail.com",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := domain.Assess(in)
			if err != nil {
				t.Fatalf("Assess(%q) should succeed: %v", in, err)
			}
			if !a.Has(domain.SignalMixedScript) {
				t.Fatalf("no mixed-script signal for %q; got %v", in, a.Signals())
			}
		})
	}
}

// TestLegitimateJapaneseIsNotAMixture: Japanese routinely combines Han with
// both kana scripts inside a single word. Treating that as a confusable
// construction would flag ordinary names.
func TestLegitimateJapaneseIsNotAMixture(t *testing.T) {
	for _, in := range []string{
		"日本語例え.example.com", // Han + Hiragana
		"テスト例.example.com",  // Katakana + Han
		"例えテスト.example.com", // Han + Hiragana + Katakana
	} {
		t.Run(in, func(t *testing.T) {
			a, err := domain.Assess(in)
			if err != nil {
				t.Fatalf("Assess(%q): %v", in, err)
			}
			if a.Has(domain.SignalMixedScript) {
				t.Fatalf("%q flagged as mixed-script: %+v", in, a.Observations)
			}
			if !a.Has(domain.SignalSingleNonLatinScript) {
				t.Fatalf("%q was not reported as an ordinary internationalised name: %v", in, a.Signals())
			}
		})
	}
}

// TestPunycodeInputIsADistinctSignal: a feed that writes the ACE form has told
// a reviewer nothing about what the name looks like. That is a fact about the
// publisher, not about the name, so it gets its own signal.
func TestPunycodeInputIsADistinctSignal(t *testing.T) {
	unicodeForm, err := domain.Assess("пример.example.com")
	if err != nil {
		t.Fatal(err)
	}
	aceForm, err := domain.Assess(unicodeForm.Domain.String())
	if err != nil {
		t.Fatal(err)
	}

	if aceForm.Domain != unicodeForm.Domain {
		t.Fatalf("the two spellings canonicalise differently: %q vs %q", aceForm.Domain, unicodeForm.Domain)
	}
	if !aceForm.Has(domain.SignalPunycodeInput) {
		t.Fatalf("punycode input was not signalled: %v", aceForm.Signals())
	}
	if unicodeForm.Has(domain.SignalPunycodeInput) {
		t.Fatal("the readable spelling was reported as punycode input")
	}
	if !unicodeForm.Has(domain.SignalNonASCII) {
		t.Fatal("the readable spelling was not reported as non-ASCII")
	}
	// The script observation is derived from the canonical form, so it must
	// survive the change of spelling.
	if aceForm.Has(domain.SignalSingleNonLatinScript) != unicodeForm.Has(domain.SignalSingleNonLatinScript) {
		t.Fatal("the script observation depends on how the name was spelled")
	}
}

// TestPlainASCIINamesCarryNoSignals: the overwhelmingly common case must not
// acquire noise, or a plan's review section becomes unreadable and gets ignored.
func TestPlainASCIINamesCarryNoSignals(t *testing.T) {
	for _, in := range []string{"example.com", "sub.example.co.uk", "web3.example.com", "a-b.example.org"} {
		a, err := domain.Assess(in)
		if err != nil {
			t.Fatalf("Assess(%q): %v", in, err)
		}
		if len(a.Observations) != 0 {
			t.Errorf("%q produced observations: %+v", in, a.Observations)
		}
	}
}

// TestInvalidInputIsStillRejected: separating risk from syntax must not have
// loosened syntax. Every one of these is a SYNTAX error and stays one.
func TestInvalidInputIsStillRejected(t *testing.T) {
	cases := map[string]error{
		"":                   domain.ErrEmpty,
		"   ":                domain.ErrEmpty,
		"example":            domain.ErrSingleLabel,
		"com":                domain.ErrSingleLabel,
		"192.0.2.1":          domain.ErrIPLiteral,
		"[::1]":              domain.ErrIPLiteral,
		"*.example.com":      domain.ErrWildcard,
		"exa mple.com":       domain.ErrInvalidCharacter,
		"http://example.com": domain.ErrInvalidCharacter,
		"user@example.com":   domain.ErrInvalidCharacter,
		"example..com":       domain.ErrEmptyLabel,
		".example.com":       domain.ErrEmptyLabel,
		"example.com..":      domain.ErrEmptyLabel,
		"localhost":          domain.ErrLocalhost,
		"printer.local":      domain.ErrLocalTLD,
		"secret.onion":       domain.ErrLocalTLD,
		"example.123":        domain.ErrNumericTLD,
		"co.uk":              domain.ErrPublicSuffix,
		// A leading or trailing hyphen is caught by the IDNA profile, before
		// this package's own label loop sees it. The distinction is recorded
		// rather than smoothed over: both are syntax failures either way.
		"-bad.example.com":      domain.ErrMalformedIDN,
		"bad-.example.com":      domain.ErrMalformedIDN,
		"xn--.example.com":      domain.ErrMalformedIDN,
		"xn--a-ecp.example.com": domain.ErrMalformedIDN,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := domain.Assess(in)
			if err == nil {
				t.Fatalf("Assess(%q) should fail with %v", in, want)
			}
			if !errors.Is(err, want) {
				t.Fatalf("Assess(%q) = %v, want %v", in, err, want)
			}
		})
	}
}

// TestAssessIsDeterministic: two runs over the same input must produce
// byte-identical observations, including their order. A plan digest depends on
// it, and a digest that varies between runs makes operator review meaningless.
func TestAssessIsDeterministic(t *testing.T) {
	inputs := []string{
		"аpple.example.com",
		"пример.example.com",
		"例えテスト.example.com",
		"example.com",
		"xn--80ak6aa92e.example.com",
	}
	for _, in := range inputs {
		first, err := domain.Assess(in)
		if err != nil {
			t.Fatalf("Assess(%q): %v", in, err)
		}
		for range 50 {
			again, err := domain.Assess(in)
			if err != nil {
				t.Fatalf("Assess(%q) failed on a repeat run: %v", in, err)
			}
			if !reflect.DeepEqual(first, again) {
				t.Fatalf("Assess(%q) is not deterministic:\n%+v\n%+v", in, first, again)
			}
		}
	}
}

// TestDuplicateSpellingsCanonicaliseTogether: the deduplication a feed
// validator performs is only correct if two spellings of one name produce one
// canonical form. Mixed-script names are included deliberately — they now
// survive normalisation, so they can now collide.
func TestDuplicateSpellingsCanonicaliseTogether(t *testing.T) {
	groups := [][]string{
		{"Example.COM", "example.com", "EXAMPLE.com."},
		{"пример.example.com", "ПРИМЕР.example.com"},
		{"аpple.example.com", "АPPLE.example.com"},
	}
	for _, g := range groups {
		want, err := domain.Normalize(g[0])
		if err != nil {
			t.Fatalf("Normalize(%q): %v", g[0], err)
		}
		for _, in := range g[1:] {
			got, err := domain.Normalize(in)
			if err != nil {
				t.Fatalf("Normalize(%q): %v", in, err)
			}
			if got != want {
				t.Errorf("%q and %q canonicalise differently: %q vs %q", g[0], in, got, want)
			}
		}
	}
}

// TestSignalValuesAreStable pins the wire form. These strings appear in plans
// and in operator reports; renaming one silently changes every stored plan's
// meaning, so the change has to be deliberate enough to edit this list.
func TestSignalValuesAreStable(t *testing.T) {
	want := map[domain.Signal]string{
		domain.SignalNonASCII:             "non_ascii",
		domain.SignalPunycodeInput:        "punycode_input",
		domain.SignalSingleNonLatinScript: "single_non_latin_script",
		domain.SignalMixedScript:          "mixed_script",
	}
	for sig, s := range want {
		if string(sig) != s {
			t.Errorf("signal value changed: %q, want %q", string(sig), s)
		}
	}
}

// TestObservationsNeverCarryUnicode: the label reported alongside an
// observation is what gets printed. Printing the Unicode form would render the
// confusable exactly as the person who chose it intended.
func TestObservationsNeverCarryUnicode(t *testing.T) {
	for _, in := range []string{
		"аpple.example.com",
		"пример.example.com",
		"例えテスト.example.com",
	} {
		a, err := domain.Assess(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range a.Observations {
			for _, r := range o.Label + o.Detail {
				if r >= 0x80 {
					t.Errorf("observation for %q carries non-ASCII: %+v", in, o)
					break
				}
			}
		}
	}
}

// TestNormalizeAndAssessAgree: Normalize is documented as a thin projection of
// Assess. If they ever disagree, one caller's canonical form is another's
// rejection.
func TestNormalizeAndAssessAgree(t *testing.T) {
	inputs := []string{
		"example.com", "аpple.example.com", "пример.example.com",
		"münchen.example.com", "localhost", "*.example.com", "co.uk", "", "192.0.2.1",
		"例え.example.com",
	}
	for _, in := range inputs {
		d, nerr := domain.Normalize(in)
		a, aerr := domain.Assess(in)
		if (nerr == nil) != (aerr == nil) {
			t.Fatalf("%q: Normalize err=%v, Assess err=%v", in, nerr, aerr)
		}
		if nerr == nil && d != a.Domain {
			t.Fatalf("%q: Normalize=%q, Assess=%q", in, d, a.Domain)
		}
	}
}

func TestAssessRejectsOverlongInputWithoutPanicking(t *testing.T) {
	long := strings.Repeat("a", 5000) + ".example.com"
	if _, err := domain.Assess(long); err == nil {
		t.Fatal("an over-long name should be rejected")
	}
}

// TestIgnorableCharactersAreMappedAwayNotRejected pins a behaviour that is
// easy to misread as a hole.
//
// A SOFT HYPHEN inside a label is mapped to nothing by the IDNA lookup
// profile, so the name canonicalises to the form without it. That is the
// standard behaviour and the same thing a resolver and a browser do, which is
// exactly why it is right: a canonical form that disagreed with what actually
// resolves would let two spellings of one name reach a plan as two entries.
func TestIgnorableCharactersAreMappedAwayNotRejected(t *testing.T) {
	const softHyphen = "\u00ad"
	got, err := domain.Normalize("exam" + softHyphen + "ple.example.com")
	if err != nil {
		t.Fatalf("a soft hyphen should be mapped away, not rejected: %v", err)
	}
	if got != "example.example.com" {
		t.Fatalf("canonical form = %q, want %q", got, "example.example.com")
	}
	// And it must therefore collide with the plain spelling, so a feed
	// containing both is caught as a duplicate rather than blocking twice.
	plain, err := domain.Normalize("example.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if plain != got {
		t.Fatalf("the two spellings did not converge: %q vs %q", plain, got)
	}
}
