// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// # WHAT THIS FILE IS ABOUT
//
// diagnostictrust_test.go audits the VALIDATION diagnostics — the ones
// fixture.go builds out of caller-controlled values. It takes as its premise
// that the strict-decode path upstream of it "refuses a hostile KEY without
// being echoed", and tests that premise for the unknown-field branch and the
// duplicate-key branch at the top level.
//
// It does not test what the duplicate-key walk does with a key that contains
// the separators the schema PATH is built out of. That was the hole:
//
//	FINDING-112  a key containing "[" had everything from the bracket onwards
//	             emitted verbatim, because describeLocation cleaned the path at
//	             RENDER time by splitting on "[" and could not tell a suffix
//	             the walk wrote from one the document supplied.
//	FINDING-113  a key containing "." was split into segments that were each a
//	             schema name, rendering a path the parser never produced.
//	FINDING-114  the walk collected duplicate-key problems without any bound.
//	             Each one was short and safe; there could be twenty thousand.
//
// The correction moves the sanitising to appendSegment, where the key arrives,
// and applies fixture.go's two existing bounds to the walk.

// unrecognisedLiteral is the placeholder the walk substitutes for a key that
// is not one of this schema's names.
//
// Spelled out rather than referenced as unrecognisedSegment so that this file
// compiles against the SUPERSEDED implementation too — which used the same
// literal, in describeLocation. A pre-fix control that will not build is not a
// control.
const unrecognisedLiteral = "<unrecognised>"

// duplicateUnder wraps a hostile key around an object that names one key
// twice, which is the only way the walk reaches describeLocation with a
// non-empty path.
func duplicateUnder(key string) []byte {
	return []byte(`{` + jsonString(key) + `:{"a":1,"a":2}}`)
}

// TestAHostileKeyCannotReachTheDiagnosticThroughThePath.
//
// The `[` case is the discriminating one: measured against the superseded
// implementation the error string carried a raw ESC (0x1b) and a raw BEL
// (0x07) straight out of the document.
func TestAHostileKeyCannotReachTheDiagnosticThroughThePath(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"a bracket carrying terminal controls",
			withCodePoint("cases[", 0x1b, "[2J") + string(rune(0x07)) + "forged"},
		{"a bracket carrying a bidi override",
			withCodePoint("cases[", 0x202e, "]")},
		{"a bracket carrying a Unicode line separator",
			withCodePoint("cases[", 0x2028, "RESULT: all required gates passed")},
		{"a dot forging a schema path", "cases.label"},
		{"a dot and a bracket together", "cases.label[0]"},
		{"a schema name with a bracket suffix", "cases[999]"},
		{"a long bracket suffix", "cases[" + strings.Repeat("A", 4096) + "]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSet(duplicateUnder(tc.key))
			if err == nil {
				t.Fatal("a document naming a key twice was ACCEPTED")
			}
			msg := err.Error()

			if got := controlFree(msg); len(got) > 0 {
				t.Errorf("the diagnostic carries raw controls from the key: %v\n%q", got, msg)
			}
			if !utf8.ValidString(msg) {
				t.Errorf("the diagnostic is not valid UTF-8: %q", msg)
			}
			// The key's own bytes must not appear at all. The check is on the
			// part after "cases", because "cases" is one of OUR names and may
			// legitimately be printed — what must not survive is anything the
			// document chose to put after it.
			if tail := strings.TrimPrefix(tc.key, "cases"); tail != "" && strings.Contains(msg, tail) {
				t.Errorf("the diagnostic echoes the key: %q\nin: %q", tail, msg)
			}
			// A path the parser did not produce is as misleading as an
			// unescaped one: it names an object that is not in the document.
			if strings.Contains(msg, "cases.label") {
				t.Errorf("the diagnostic renders a forged schema path: %q", msg)
			}
			if !strings.Contains(msg, unrecognisedLiteral) {
				t.Errorf("an unrecognised segment is not reported as one: %q", msg)
			}
			if len(msg) > 4096 {
				t.Errorf("one duplicate produced a %d-byte diagnostic", len(msg))
			}
		})
	}
}

// TestAKnownSegmentIsStillNamed is the positive control. Without it, an
// implementation that replaced EVERY segment with the placeholder — and so
// told an author nothing about where the problem is — would pass every
// assertion above.
func TestAKnownSegmentIsStillNamed(t *testing.T) {
	_, err := ParseSet([]byte(`{"cases":{"a":1,"a":2}}`))
	if err == nil {
		t.Fatal("a document naming a key twice was ACCEPTED")
	}
	msg := err.Error()
	if !strings.Contains(msg, "the object at cases") {
		t.Errorf("a schema name is no longer located for the author: %q", msg)
	}
	if strings.Contains(msg, unrecognisedLiteral) {
		t.Errorf("a key this schema DOES define was reported as unrecognised: %q", msg)
	}
}

// TestTheDuplicateWalkIsBounded.
//
// Measured against the superseded implementation: a 1,760,001-byte document
// produced a 6,159,921-byte error — 3.5x the input, and roughly 28 MB
// extrapolated to MaxSetBytes. The bound is on what is COLLECTED, not only on
// what is printed, so the large string is never built.
func TestTheDuplicateWalkIsBounded(t *testing.T) {
	const ambiguities = 20000

	var b strings.Builder
	b.WriteString(`{`)
	for i := 0; i < ambiguities; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString("cases[" + strings.Repeat("A", 64)))
		b.WriteString(`:{"a":1,"a":2}`)
	}
	b.WriteString(`}`)
	doc := []byte(b.String())

	_, err := ParseSet(doc)
	if err == nil {
		t.Fatal("a document with 20000 ambiguities was ACCEPTED")
	}
	msg := err.Error()

	if len(msg) > 64*1024 {
		t.Errorf("a %d-byte document produced a %d-byte diagnostic", len(doc), len(msg))
	}
	// The bound must not read as a clean bill of health.
	if !strings.Contains(msg, "not listed") {
		t.Errorf("the diagnostic omits problems without saying so: %q", truncate(msg, 400))
	}
	if n := strings.Count(msg, "names"); n > maxReportedProblems {
		t.Errorf("%d problems were listed, above the bound of %d", n, maxReportedProblems)
	}
}

// TestAnOrdinaryAmbiguityIsStillFullyDiagnosed is the other positive control:
// a file with a handful of real mistakes must still name every one of them,
// with no omission notice attached.
func TestAnOrdinaryAmbiguityIsStillFullyDiagnosed(t *testing.T) {
	doc := []byte(`{"cases":{"a":1,"a":2},"version":{"b":1,"b":2}}`)
	_, err := ParseSet(doc)
	if err == nil {
		t.Fatal("an ambiguous document was ACCEPTED")
	}
	msg := err.Error()
	if n := strings.Count(msg, "names"); n != 2 {
		t.Errorf("two ambiguities, %d reported: %q", n, msg)
	}
	if strings.Contains(msg, "not listed") {
		t.Errorf("a two-problem document was reported as truncated: %q", msg)
	}
	for _, want := range []string{"the object at cases", "the object at version"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the diagnostic does not locate %q: %q", want, msg)
		}
	}
}
