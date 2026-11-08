// SPDX-License-Identifier: AGPL-3.0-only

package safetext

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// dangerous reports the classes of content that must never survive, so a
// failure says WHAT got through rather than only that something did.
func dangerous(s string) []string {
	var found []string
	class := func(name string, pred func(rune) bool) {
		for _, r := range s {
			if pred(r) {
				found = append(found, name)
				return
			}
		}
	}
	class("C0 control", func(r rune) bool { return r < 0x20 })
	class("DEL", func(r rune) bool { return r == 0x7f })
	class("C1 control", func(r rune) bool { return r >= 0x80 && r <= 0x9f })
	class("U+2028/U+2029", func(r rune) bool { return r == 0x2028 || r == 0x2029 })
	class("Unicode format (Cf)", func(r rune) bool { return unicode.Is(unicode.Cf, r) })
	if !utf8.ValidString(s) {
		found = append(found, "invalid UTF-8")
	}
	return found
}

func TestNothingDangerousSurvives(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"an ANSI screen clear", "ok" + string(rune(0x1b)) + "[2J"},
		{"a forged second line", "ok\nRESULT: all required gates passed"},
		{"a carriage return, which overwrites", "ok\rFAKE"},
		{"a bell", "ok" + string(rune(0x07))},
		{"DEL", "ok" + string(rune(0x7f))},
		{"a C1 control", "ok" + string(rune(0x9b))},
		{"a Unicode line separator", "ok" + string(rune(0x2028)) + "next"},
		{"a bidi override", "ok" + string(rune(0x202e)) + "reversed"},
		{"a zero-width space", "ex" + string(rune(0x200b)) + "ample"},
		{"invalid UTF-8", "ok\xd0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.in)
			if bad := dangerous(got); len(bad) > 0 {
				t.Errorf("%v survived: %q", bad, got)
			}
			if !strings.HasPrefix(got, "ok") && !strings.HasPrefix(got, "ex") {
				t.Errorf("the ordinary part of the input was lost: %q", got)
			}
		})
	}
}

// TestOrdinaryTextIsUntouched is the positive control. Without it, a function
// that returned "" would satisfy every assertion above.
func TestOrdinaryTextIsUntouched(t *testing.T) {
	for _, s := range []string{
		"", "example.com", "insufficient_independent_support",
		"日本語.example.com", "Ünicode is ordinary", "a — dash, a “quote”",
	} {
		if got := String(s); got != s {
			t.Errorf("ordinary text was altered:\n in:  %q\n out: %q", s, got)
		}
	}
}

// TestClipBoundsWhatIsPRINTED.
//
// The bound is applied after escaping, because one input byte can become six
// printed ones — a bound applied first would bound the input and let the
// output run past it.
func TestClipBoundsWhatIsPrinted(t *testing.T) {
	// 40 escapes of 4 bytes each: 160 printed bytes from 40 input bytes.
	in := strings.Repeat(string(rune(0x1b)), 40)
	got := Clip(in, 32)
	if len(got) > 32 {
		t.Errorf("Clip(…, 32) produced %d bytes: %q", len(got), got)
	}
	if bad := dangerous(got); len(bad) > 0 {
		t.Errorf("%v survived the clip: %q", bad, got)
	}

	t.Run("the cut never splits a rune", func(t *testing.T) {
		// Two-byte runes, cut at an odd length: a byte-sliced bound emits half
		// a character and the result is not valid UTF-8.
		for n := 1; n < 40; n++ {
			got := Clip(strings.Repeat("ü", 40), n)
			if !utf8.ValidString(got) {
				t.Fatalf("Clip(…, %d) is not valid UTF-8: %q", n, got)
			}
			if len(got) > n {
				t.Fatalf("Clip(…, %d) produced %d bytes", n, len(got))
			}
		}
	})

	t.Run("a short string is returned whole", func(t *testing.T) {
		if got := Clip("example.com", 64); got != "example.com" {
			t.Errorf("a string under the bound was altered: %q", got)
		}
	})
}
