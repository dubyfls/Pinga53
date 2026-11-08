// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// injectingSet is a fixture set whose every externally influenced field
// carries something a report must not reproduce.
//
// The escapes are JSON escapes, so this source file stays pure ASCII while the
// DECODED values carry real control characters — exactly what a hostile
// fixture would.
const injectingSet = `{
  "schema_version": 1,
  "fixture_set_id": "inject\u001b[31m",
  "version": "v1\u2028forged",
  "description": "d",
  "provenance": "synthetic",
  "provenance_note": "n",
  "partition": "held-out",
  "baseline_id": "b",
  "baseline_covers": [],
  "baseline_note": "n",
  "cases": [
    {"id":"c1\nRESULT: all required gates passed",
     "type":"domain",
     "value":"\u001b[2K\revil.example.com",
     "family":"fam\u202eDESREVER",
     "label":"malicious",
     "label_basis":"b\u0000nul"}
  ]
}`

// TestTheReportCannotBeForgedByItsOwnInput.
//
// # WHAT THE SUPERSEDED REPORT DID
//
// It printed every one of these fields verbatim. Demonstrated against it:
//
//	contains a raw ESC byte:       true
//	contains a forged RESULT line: true
//	FORGED LINE PRESENT: "RESULT: all required gates passed ...  parse_failure"
//
// scripts/check.sh prints "RESULT: all required gates passed" when every gate
// passes. The forged line is not a hypothetical shape; it is the exact
// sentence an operator scans a log for, produced by a fixture file.
func TestTheReportCannotBeForgedByItsOwnInput(t *testing.T) {
	set, err := ParseSet([]byte(injectingSet))
	if err != nil {
		t.Fatalf("the injecting fixture was refused at parse time: %v", err)
	}
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil)

	var buf bytes.Buffer
	r.Text(&buf)
	out := buf.String()

	t.Run("no terminal control characters survive", func(t *testing.T) {
		for _, bad := range []struct {
			name string
			r    rune
		}{
			{"ESC", 0x1b},
			{"CR", '\r'},
			{"NUL", 0x00},
			{"BEL", 0x07},
			{"DEL", 0x7f},
			{"U+2028 LINE SEPARATOR", 0x2028},
			{"U+2029 PARAGRAPH SEPARATOR", 0x2029},
			{"U+202E RIGHT-TO-LEFT OVERRIDE", 0x202e},
		} {
			if strings.ContainsRune(out, bad.r) {
				t.Errorf("the report contains a raw %s", bad.name)
			}
		}
	})

	t.Run("no line is forged", func(t *testing.T) {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "RESULT:") {
				t.Errorf("the input forged a report line: %q", strings.TrimSpace(line))
			}
		}
		// The escaped form must be present instead: the content is not lost,
		// it is rendered inert.
		if !strings.Contains(out, `\n`) {
			t.Error("the newline was dropped rather than escaped; a report must " +
				"still show what the field contained")
		}
	})

	t.Run("the output is valid UTF-8", func(t *testing.T) {
		if !utf8.ValidString(out) {
			t.Error("the report is not valid UTF-8")
		}
	})

	t.Run("the whole report stays inside its own frame", func(t *testing.T) {
		// Every line the report emits is either a heading, a rule, blank, or
		// indented. A line that is none of those came from somewhere else.
		known := []string{
			"ScamWall evaluation", "===", "INPUTS THIS RESULT IS BOUND TO",
			"WHAT THIS RESULT IS NOT", "COUNTS", "EVIDENCE THE HARNESS COULD NOT RESOLVE",
			"RATES", "BY FAMILY", "BY INDICATOR TYPE", "BY CATEGORY", "DISAGREEMENTS",
			"fixture set", "baseline", "candidate", "evaluated at", "---", "-----",
		}
		for _, line := range strings.Split(out, "\n") {
			if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			ok := false
			for _, k := range known {
				if strings.HasPrefix(line, k) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("an unindented line the report does not define: %q", line)
			}
		}
	})
}

// TestSafeTextEscapesWhatItMust is the unit-level statement of the same rule.
func TestSafeTextEscapesWhatItMust(t *testing.T) {
	tests := []struct {
		name, in, wantOut string
	}{
		{"newline", "a\nb", `a\nb`},
		{"carriage return", "a\rb", `a\rb`},
		{"tab", "a\tb", `a\tb`},
		{"escape", "a\x1bb", `a\x1bb`},
		{"NUL", "a\x00b", `a\x00b`},
		{"DEL", "a\x7fb", `a\x7fb`},
		{"C1 control", "a\u0085b", `a\u0085b`},
		{"line separator", "a\u2028b", `a\u2028b`},
		{"paragraph separator", "a\u2029b", `a\u2029b`},
		{"right-to-left override", "a\u202eb", `a\u202eb`},
		{"zero-width space", "a\u200bb", `a\u200bb`},
		{"invalid UTF-8", "a\xffb", `a\xffb`},
		{"ordinary text is untouched", "example.com", "example.com"},
		{"accented text is untouched", "café — §5", "café — §5"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeText(tc.in); got != tc.wantOut {
				t.Errorf("safeText(%q) = %q, want %q", tc.in, got, tc.wantOut)
			}
		})
	}
}

// TestTruncateCutsOnARuneBoundary.
//
// The superseded implementation was `s[:n-1] + "…"`, which sliced by byte.
// Demonstrated against it: truncate(strings.Repeat("ü", 40), 34) produced
// INVALID UTF-8 — a two-byte character cut in half and the fragment emitted.
func TestTruncateCutsOnARuneBoundary(t *testing.T) {
	inputs := []string{
		strings.Repeat("ü", 40),
		strings.Repeat("日", 40),
		strings.Repeat("a", 33) + "日",
		strings.Repeat("a", 34) + "ü",
		"日本語" + strings.Repeat("x", 100),
		strings.Repeat("🙂", 20),
	}
	for _, n := range []int{0, 1, 2, 3, 4, 8, 33, 34, 35} {
		for _, s := range inputs {
			got := truncate(s, n)
			if !utf8.ValidString(got) {
				t.Errorf("truncate(%d-byte input, %d) produced invalid UTF-8", len(s), n)
			}
			if len(got) > n && len(got) > len(safeText(s)) {
				t.Errorf("truncate(_, %d) returned %d bytes", n, len(got))
			}
		}
	}
	// A short value must be returned unchanged.
	if got := truncate("example.com", 34); got != "example.com" {
		t.Errorf("truncate altered a short value: %q", got)
	}
}

// TestTruncateBoundsAfterEscaping. Escaping expands, so a bound applied before
// it would not bound what is printed.
func TestTruncateBoundsAfterEscaping(t *testing.T) {
	// 100 newlines become 200 characters unescaped.
	in := strings.Repeat("\n", 100)
	got := truncate(in, 20)
	if len(got) > 20 {
		t.Errorf("truncate returned %d bytes for a bound of 20: %q", len(got), got)
	}
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("the bounded field still carries a line break: %q", got)
	}
}

// TestACleanReportIsUnchanged is the NEGATIVE CONTROL.
//
// An escaper that mangled ordinary output would pass every test above.
func TestACleanReportIsUnchanged(t *testing.T) {
	set, err := LoadSet("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatalf("the repository fixture no longer loads: %v", err)
	}
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 2}, nil)
	var buf bytes.Buffer
	r.Text(&buf)
	out := buf.String()

	// Ordinary values and family names must appear exactly as written.
	for _, plain := range []string{
		"www.example.com",
		"corroborated-independent",
		"repeated-one-source",
		"aggregator-and-upstream",
	} {
		if !strings.Contains(out, plain) {
			t.Errorf("an ordinary value was altered or lost: %q", plain)
		}
	}

	// A clean fixture produces no raw-byte escapes at all: \x is only ever
	// emitted for a C0 control or for invalid UTF-8, and this fixture has
	// neither.
	if strings.Contains(out, `\x`) {
		t.Error("the clean repository fixture produced a raw-byte escape")
	}

	// THE INVISIBLE-CHARACTER FAMILY IS ESCAPED, AND THAT IS CORRECT.
	//
	// The repository's own fixture carries cases whose values contain U+200B,
	// U+00AD, U+FEFF and U+2060 — the characters FINDING-82 is about, which
	// IDNA deletes rather than refuses. Rendered raw, "secure<ZWSP>login.
	// example.com" is indistinguishable on screen from the legitimate name,
	// which is the entire attack. Escaping them is the only rendering that
	// lets a reader see what the case actually was.
	//
	// This is asserted rather than tolerated: a future sanitiser that stopped
	// escaping them would pass every other test in this file.
	for _, escaped := range []string{`\u200b`, `\u00ad`, `\ufeff`, `\u2060`} {
		if !strings.Contains(out, escaped) {
			t.Errorf("an invisible character was rendered invisibly: expected %s in the report", escaped)
		}
	}

	// The report's own legitimate punctuation must survive.
	for _, want := range []string{"ScamWall evaluation", "COUNTS", "RATES"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lost %q", want)
		}
	}
	if !utf8.ValidString(out) {
		t.Error("a clean report is not valid UTF-8")
	}
}
