// SPDX-License-Identifier: AGPL-3.0-only

package domain

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// invisibleRunes are the characters this package must report. Every one of
// them is DELETED by the IDNA lookup profile rather than rejected by it, which
// is exactly what makes them dangerous: the canonical form is a legitimate
// name and nothing about it records that the written form was different.
var invisibleRunes = []rune{
	0x00AD, // SOFT HYPHEN
	0x200B, // ZERO WIDTH SPACE
	0x2060, // WORD JOINER
	0xFE0F, // VARIATION SELECTOR-16
	0xFEFF, // ZERO WIDTH NO-BREAK SPACE
}

// TestAnInvisibleCharacterCollapsesOntoALegitimateNameAndSaysSo is the
// regression for FINDING-82.
//
// Each of these inputs canonicalises to "example.com" — the legitimate
// domain's canonical form, byte for byte. That collapse is correct IDNA
// behaviour and is not the defect. The defect was that nothing recorded it:
// the only signal raised was SignalNonASCII, which this package documents as
// meaning nothing at all and which internal/policy ignores by design, so the
// entry became an ordinary blocking proposal against the legitimate name.
func TestAnInvisibleCharacterCollapsesOntoALegitimateNameAndSaysSo(t *testing.T) {
	for _, r := range invisibleRunes {
		raw := "ex" + string(r) + "ample.com"
		a, err := Assess(raw)
		if err != nil {
			t.Fatalf("U+%04X: Assess(%q) = %v; the input is syntactically valid and must not be rejected", r, raw, err)
		}
		if a.Domain != "example.com" {
			t.Fatalf("U+%04X: canonical form is %q, want %q — the premise of this test has changed", r, a.Domain, "example.com")
		}
		if !a.Has(SignalInvisibleCharacter) {
			t.Errorf("U+%04X: %q canonicalised to the legitimate %q with signals %v and no %s; "+
				"the written form differs from the canonical form and nothing says so",
				r, raw, a.Domain, a.Signals(), SignalInvisibleCharacter)
		}
		want := fmt.Sprintf("U+%04X", r)
		for _, o := range a.Observations {
			if o.Signal == SignalInvisibleCharacter && o.Detail != want {
				t.Errorf("U+%04X: detail is %q, want %q", r, o.Detail, want)
			}
		}
	}
}

// TestAnInvisibleCharacterIsASignalAndNotAnInvalidity holds the two halves of
// SW-P3-05 apart in the direction this signal could break them.
func TestAnInvisibleCharacterIsASignalAndNotAnInvalidity(t *testing.T) {
	a, err := Assess("ex\u200bample.com")
	if err != nil {
		t.Fatalf("a removed character made a valid name invalid: %v", err)
	}
	if a.Domain == "" {
		t.Fatal("no canonical form was produced")
	}
	// And the reverse: an ordinary name must not acquire the signal.
	for _, ok := range []string{"example.com", "münchen.de", "xn--mnchen-3ya.de", "日本語.jp"} {
		b, err := Assess(ok)
		if err != nil {
			t.Fatalf("Assess(%q) = %v", ok, err)
		}
		if b.Has(SignalInvisibleCharacter) {
			t.Errorf("Assess(%q) raised %s; nothing was removed from it", ok, SignalInvisibleCharacter)
		}
	}
}

// TestSeveralInvisibleCharactersAreReportedOnceEachAndInOrder pins the
// deterministic rendering, and pins that the characters are named rather than
// printed: a report that reproduced them would recreate the problem in the
// reader's terminal.
func TestSeveralInvisibleCharactersAreReportedOnceEachAndInOrder(t *testing.T) {
	a, err := Assess("e\ufeffx\u200ba\u200bm\u00adple.com")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var detail string
	for _, o := range a.Observations {
		if o.Signal == SignalInvisibleCharacter {
			detail = o.Detail
		}
	}
	if want := "U+00AD+U+200B+U+FEFF"; detail != want {
		t.Errorf("detail = %q, want %q (sorted, deduplicated)", detail, want)
	}
	for _, r := range invisibleRunes {
		if strings.ContainsRune(detail, r) {
			t.Errorf("detail contains U+%04X as a character rather than as a name", r)
		}
	}
}

// TestASurvivingInvisibleCharacterIsNotReportedAsRemoved guards the half of
// the check that keeps the claim true. The signal says the canonical form does
// not carry what was written; a character the profile kept must therefore not
// raise it.
func TestASurvivingInvisibleCharacterIsNotReportedAsRemoved(t *testing.T) {
	for _, r := range invisibleRunes {
		if !unicode.In(r, invisibleClasses...) {
			t.Errorf("U+%04X is not in any invisible class; the detector cannot see it", r)
		}
		a, err := Assess("ex" + string(r) + "ample.com")
		if err != nil {
			continue
		}
		if strings.ContainsRune(string(a.Domain), r) && a.Has(SignalInvisibleCharacter) {
			t.Errorf("U+%04X survived into %q and was still reported as removed", r, a.Domain)
		}
	}
}

// TestAnInvisibleCharacterCannotManufactureAnEmptyLabel checks the structural
// consequence of deletion: a label consisting only of removed characters would
// vanish, and an empty label must still be refused rather than silently closed
// up.
func TestAnInvisibleCharacterCannotManufactureAnEmptyLabel(t *testing.T) {
	for _, raw := range []string{"ex.\u200b.com", "\u00ad.example.com", "example.\ufeff.com"} {
		a, err := Assess(raw)
		if err == nil {
			t.Errorf("Assess(%q) = %q with no error; a label of nothing but removed characters must not become a valid name", raw, a.Domain)
		}
	}
}
