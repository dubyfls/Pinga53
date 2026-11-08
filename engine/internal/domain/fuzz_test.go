// SPDX-License-Identifier: AGPL-3.0-only

package domain_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// FuzzAssess drives the normaliser and the signal reporter with arbitrary
// input.
//
// The invariants below are what a caller is entitled to rely on. Each is
// stated as a property rather than as an expected output, because for
// arbitrary input there is no expected output — only rules that must hold
// whatever comes back.
//
// A fuzz run that finds nothing establishes that nothing was found in the
// inputs it reached. It is not a proof of absence, and this comment exists so
// that a green run is not read as one.
func FuzzAssess(f *testing.F) {
	seeds := []string{
		"", " ", ".", "..", "example.com", "EXAMPLE.COM.", "a.b.c.d.e.f",
		"xn--80ak6aa92e.com", "аpple.example.com", "пример.example.com",
		"192.0.2.1", "[::1]", "*.example.com", "localhost", "co.uk",
		"-a.example.com", "a-.example.com", "a..b.com", "\u00ad.example.com",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 130) + "com",
		"\x00example.com", "exa\tmple.com", "user@example.com", "http://x.com",
		"\u0640.example.com", "\u200b.example.com", "xn--.example.com",
		// FINDING-82: each of these canonicalises to "example.com".
		"ex\u00adample.com", "ex\u200bample.com", "ex\u2060ample.com",
		"ex\ufe0fample.com", "ex\ufeffample.com", "e\ufeffx\u200ba\u00adm.example.com",
		// FINDING-83: an input far above the canonical length limit.
		strings.Repeat("a", 2000) + ".example.com",
		strings.Repeat("\u00fc", 800) + ".example.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		// INVARIANT 1: no panic. Enforced by the fuzzer itself — reaching the
		// end of this function at all is the assertion.
		a, err := domain.Assess(raw)
		if err != nil {
			// INVARIANT 2: a rejection yields no domain and no observations,
			// so a caller that ignores the error cannot act on a half-result.
			if a.Domain != "" || len(a.Observations) != 0 {
				t.Fatalf("Assess(%q) failed but returned %+v", raw, a)
			}
			return
		}

		d := string(a.Domain)

		// INVARIANT 3: bounded acceptance. Nothing longer than the RFC limit,
		// and no label longer than the label limit, is ever accepted.
		if len(d) > domain.MaxLength {
			t.Fatalf("Assess(%q) accepted a %d-byte name", raw, len(d))
		}
		labels := strings.Split(d, ".")
		if len(labels) < domain.MinLabels {
			t.Fatalf("Assess(%q) accepted %q with %d labels", raw, d, len(labels))
		}
		for _, l := range labels {
			if l == "" {
				t.Fatalf("Assess(%q) accepted %q with an empty label", raw, d)
			}
			if len(l) > domain.MaxLabelLength {
				t.Fatalf("Assess(%q) accepted a %d-byte label in %q", raw, len(l), d)
			}
		}

		// INVARIANT 4: the canonical form is ASCII, lowercase, and free of the
		// syntax the parser is supposed to have rejected. A canonical form
		// that could carry a slash, an at-sign or an uppercase letter would
		// mean two spellings of one name could both reach a plan.
		if !utf8.ValidString(d) {
			t.Fatalf("Assess(%q) produced invalid UTF-8", raw)
		}
		for _, r := range d {
			if r >= 0x80 {
				t.Fatalf("Assess(%q) produced a non-ASCII canonical form %q", raw, d)
			}
			if r >= 'A' && r <= 'Z' {
				t.Fatalf("Assess(%q) produced an uppercase canonical form %q", raw, d)
			}
		}
		if strings.ContainsAny(d, " \t\r\n/\\@:?#%*") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
			t.Fatalf("Assess(%q) produced %q, which contains rejected syntax", raw, d)
		}

		// INVARIANT 5: normalisation is idempotent. Feeding a canonical form
		// back in must return it unchanged, or deduplication is unsound and
		// one name can reach a plan twice.
		again, err := domain.Assess(d)
		if err != nil {
			t.Fatalf("Assess(%q) produced %q, which Assess then rejected: %v", raw, d, err)
		}
		if again.Domain != a.Domain {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, d, again.Domain)
		}

		// INVARIANT 6: determinism. Same input, same observations, same order.
		repeat, err := domain.Assess(raw)
		if err != nil {
			t.Fatalf("Assess(%q) succeeded then failed: %v", raw, err)
		}
		if repeat.Domain != a.Domain || len(repeat.Observations) != len(a.Observations) {
			t.Fatalf("Assess(%q) is not deterministic", raw)
		}
		for i := range a.Observations {
			if repeat.Observations[i] != a.Observations[i] {
				t.Fatalf("Assess(%q) observation %d varies between runs", raw, i)
			}
		}

		// INVARIANT 7: an observation is safe to print. The whole point of
		// reporting the ASCII label is that it cannot render as a confusable.
		for _, o := range a.Observations {
			for _, r := range o.Label + o.Detail {
				if r >= 0x80 {
					t.Fatalf("Assess(%q) produced a non-ASCII observation %+v", raw, o)
				}
			}
		}

		// INVARIANT 8: script observations are attached to labels of the name
		// that was returned, never to something invented.
		for _, o := range a.Observations {
			if o.Label != d && !strings.Contains(d, o.Label) {
				t.Fatalf("Assess(%q) observation names %q, which is not part of %q", raw, o.Label, d)
			}
		}

		// INVARIANT 9: canonicalisation never silently discards an invisible
		// character. If the input carried one and the canonical form does not,
		// the assessment has to say so — otherwise the written form and the
		// accepted form differ with nothing anywhere recording it, which is
		// FINDING-82. Stated over the canonical form so that it holds for
		// characters this test does not enumerate.
		for _, r := range raw {
			if !unicode.In(r, invisibleProperties...) || strings.ContainsRune(d, r) {
				continue
			}
			if !a.Has(domain.SignalInvisibleCharacter) {
				t.Fatalf("Assess(%q) removed U+%04X on the way to %q and raised %v", raw, r, d, a.Signals())
			}
		}
	})
}

// invisibleProperties mirrors the Unicode classes the package treats as
// having no visible rendering. It is written out here rather than read from
// the package, so that INVARIANT 9 is an independent statement of the property
// rather than a restatement of the implementation's own table.
var invisibleProperties = []*unicode.RangeTable{
	unicode.Cf,
	unicode.Variation_Selector,
	unicode.Other_Default_Ignorable_Code_Point,
}
