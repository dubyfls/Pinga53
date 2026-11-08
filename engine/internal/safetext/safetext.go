// SPDX-License-Identifier: AGPL-3.0-only

// Package safetext renders caller-controlled text into a report.
//
// # WHY THIS IS A PACKAGE AND NOT A HELPER IN EACH REPORTER
//
// It was a helper in one reporter. `internal/evaluation/report.go` grew it
// because a fixture file is caller-controlled and its values reach a terminal,
// a log and a JSON document, and FINDING-89 and FINDING-111 are what happens
// when they reach any of those unescaped or unbounded.
//
// The second reporter — proposals built from a signed evidence document — has
// exactly the same problem with exactly the same inputs, and a security
// control with two copies has two behaviours as soon as one of them is
// corrected. So the two lines of implementation live here and both reporters
// call them.
//
// # WHAT IS ESCAPED, AND WHY EACH ONE
//
//   - C0 controls, DEL and C1 controls. An ESC in a terminal is a command:
//     `ESC [ 2J` clears the screen, and a report is read in a terminal. A
//     newline is worse than it looks — it lets a field forge a second line of
//     output, which is how a value becomes a fabricated verdict.
//   - U+2028 and U+2029. They are line terminators to a JavaScript parser and
//     invisible to a reader, so a field carrying one is one thing in a
//     terminal and another in anything that re-parses the output.
//   - Unicode format characters (Cf). Bidi overrides reorder what a reader
//     sees without changing what the program read — the Trojan Source class —
//     and zero-width characters hide text outright.
//   - Invalid UTF-8. Emitted as escaped bytes rather than passed through: a
//     report is also encoded as JSON elsewhere, and invalid UTF-8 does not
//     survive that.
package safetext

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// String renders s so that nothing in it can act on a terminal, forge a line
// of output, hide itself from a reader, or break a JSON encoder.
func String(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", s[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&b, "\\u%04x", r)
		case r == 0x2028 || r == 0x2029:
			fmt.Fprintf(&b, "\\u%04x", r)
		case unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Clip renders s safely and bounds it to n bytes.
//
// Escaping happens BEFORE the cut, so the bound applies to what is actually
// printed rather than to the input it came from — one escaped byte can become
// six printed ones.
//
// The cut is moved back to a rune boundary. A byte-sliced bound cuts a
// multi-byte character in half and emits the fragment, which is how a bounded
// field becomes invalid UTF-8.
func Clip(s string, n int) string {
	s = String(s)
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	if n <= len(ellipsis) {
		// No room for a marker; clip to a rune boundary and say nothing.
		cut := n
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut]
	}
	cut := n - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}
