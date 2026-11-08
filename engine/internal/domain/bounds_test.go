// SPDX-License-Identifier: AGPL-3.0-only

package domain

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTheRawInputIsBoundedBeforeAnythingExpensiveTouchesIt is the regression
// for FINDING-83.
//
// MaxLength bounds the canonical form and is checked AFTER IDNA conversion.
// That left the raw input unbounded through the conversion and, worse, through
// the error message: a 5 KB record produced a 5 KB error, and internal/feed
// then wrapped it with the same value again.
func TestTheRawInputIsBoundedBeforeAnythingExpensiveTouchesIt(t *testing.T) {
	raw := strings.Repeat("a", 5000) + ".example.com"
	_, err := Assess(raw)
	if err == nil {
		t.Fatal("a 5 KB input was accepted")
	}
	if !errors.Is(err, ErrInputTooLong) {
		t.Errorf("error is %v, want ErrInputTooLong", err)
	}
	if len(err.Error()) > 128 {
		t.Errorf("the error is %d bytes for a %d-byte input; an error message's size must not be chosen by the input", len(err.Error()), len(raw))
	}
}

// TestALongInputIsRefusedRatherThanConverted pins that the bound sits before
// the IDNA work rather than after it. A Unicode input expands during
// conversion, so a post-conversion bound does the expensive part first.
func TestALongInputIsRefusedRatherThanConverted(t *testing.T) {
	raw := strings.Repeat("ü", 5000) + ".example.com"
	_, err := Assess(raw)
	if !errors.Is(err, ErrInputTooLong) {
		t.Errorf("error is %v, want ErrInputTooLong", err)
	}
}

// TestNothingValidIsRefusedByTheInputBound checks the bound discards nothing a
// later check would have accepted. A maximal canonical name, written in its
// Unicode form, must still pass.
func TestNothingValidIsRefusedByTheInputBound(t *testing.T) {
	// Six Unicode labels plus a TLD: 377 raw bytes canonicalising to 233,
	// which is a valid name whose WRITTEN form is well above MaxLength. A
	// bound placed on the raw input has to clear this to be honest.
	label := strings.Repeat("ü", 30)
	raw := strings.Join([]string{label, label, label, label, label, label, "example", "com"}, ".")
	if len(raw) <= MaxLength {
		t.Fatalf("the fixture is %d bytes and does not exercise the gap between MaxInputLength and MaxLength", len(raw))
	}
	if len(raw) > MaxInputLength {
		t.Fatalf("the fixture is %d bytes, above MaxInputLength %d; it cannot show what this test claims", len(raw), MaxInputLength)
	}
	if _, err := Assess(raw); err != nil {
		t.Errorf("a valid %d-byte Unicode name was refused: %v", len(raw), err)
	}
}

// TestAnIDNAErrorDoesNotEchoTheWholeLabel bounds the one error in this package
// whose text came from a third-party library and carried the input verbatim.
func TestAnIDNAErrorDoesNotEchoTheWholeLabel(t *testing.T) {
	raw := strings.Repeat("a", 500) + ".example.com"
	_, err := Assess(raw)
	if err == nil {
		t.Fatal("a 500-byte label was accepted")
	}
	if errors.Is(err, ErrInputTooLong) {
		t.Fatalf("the fixture is %d bytes and hit the input bound instead of the IDNA path", len(raw))
	}
	if len(err.Error()) > 256 {
		t.Errorf("the IDNA error is %d bytes: %q", len(err.Error()), err)
	}
}

// TestClipTruncatesOnARuneBoundary keeps the helper from producing invalid
// UTF-8, which would break the JSON encoding of any report that carried it.
func TestClipTruncatesOnARuneBoundary(t *testing.T) {
	for _, s := range []string{
		strings.Repeat("ü", 200),
		strings.Repeat("日", 200),
		strings.Repeat("a", 200),
		strings.Repeat("a", 63) + strings.Repeat("ü", 10),
	} {
		got := Clip(s)
		// utf8.ValidString, not a hand-rolled check. The helper this replaced
		// could not fail: its only rejection was
		//
		//	if r == '�' && !strings.ContainsRune(s, '�')
		//
		// which is a contradiction — reaching r == U+FFFD proves s contains
		// U+FFFD, so the second half is always false. What it actually
		// returned was len([]rune(s)) > 0, i.e. "not empty". Worse, ranging
		// over invalid UTF-8 yields U+FFFD runes, so an invalid string was
		// non-empty and therefore "valid". This test asserted nothing about
		// encoding for as long as it existed.
		if !utf8.ValidString(got) {
			t.Errorf("Clip produced invalid UTF-8 for a %d-byte input", len(s))
		}
		if len(got) > maxEchoLength+40 {
			t.Errorf("Clip returned %d bytes, which is not a bound", len(got))
		}
	}
	if short := "example.com"; Clip(short) != short {
		t.Errorf("Clip altered a short value: %q", Clip(short))
	}
}
