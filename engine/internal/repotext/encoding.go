// SPDX-License-Identifier: AGPL-3.0-only

// Package repotext is the repository's own text-integrity control.
//
// # WHY THIS EXISTS
//
// Commit 3152485 rewrote docs/REQUIREMENTS_MATRIX.md through a pipeline that
// read the file's UTF-8 bytes as Latin-1 and re-encoded the result as UTF-8 —
// twice. Every em dash, section sign and ellipsis in a 162 KB authoritative
// document became a six- or four-byte smear. Nothing caught it, because the
// damage is INVISIBLE TO EVERY GATE THE REPOSITORY ALREADY HAD:
//
//   - the result is still well-formed UTF-8, so a decoder validity check
//     passes;
//   - it is still valid Markdown, so a renderer passes;
//   - no Go source changed, so the compiler, the vet pass, the race detector
//     and the test suite are all silent;
//   - `git diff` showed a plausible documentation edit, because the same
//     commit also made legitimate additions.
//
// A corruption that survives every existing gate is exactly the kind that
// reaches an authoritative document and stays there. This package is the gate
// that does see it.
//
// # WHAT IT PROVES
//
//	PROVES     no tracked text file contains a byte run that decodes as
//	           mojibake — that is, a run of characters which, reinterpreted as
//	           bytes, yields different and still-meaningful text.
//	DOES NOT   prove the text is correct, well-written, or says what it should.
//	PROVE      It is a check on ENCODING, not on content.
//
// # WHY A FOLDING DETECTOR AND NOT A PATTERN LIST
//
// A list of literal bad sequences only ever catches the corruption that has
// already happened once. The transformation that produces mojibake is exactly
// invertible, so the detector inverts it instead: any run that folds cleanly
// back into different non-ASCII text was produced by that transformation, and
// no list has to be kept current. DemonstratedSequences below is retained as a
// POSITIVE CONTROL over that detector, not as the detector's input.
package repotext

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// maxFoldDepth bounds how many times Scan will invert the mojibake
// transformation while looking for the original text.
//
// The corruption in 3152485 was applied twice. Three is one more than has ever
// been observed here, and the bound exists so that a pathological input cannot
// drive an unbounded loop — a folding step always shortens its input, so this
// is belt-and-braces rather than a live risk.
const maxFoldDepth = 3

// Kind classifies a finding. It is a closed set: a caller may switch on it.
type Kind string

const (
	// KindInvalidUTF8 is a file that is not well-formed UTF-8 at all.
	KindInvalidUTF8 Kind = "invalid-utf8"
	// KindMojibake is well-formed UTF-8 that decodes to other text when its
	// characters are reinterpreted as bytes.
	KindMojibake Kind = "mojibake"
)

// Finding is one located defect.
//
// Got is reported as a byte listing, never as the raw characters, so that a
// report OF this corruption can never itself be flagged BY it — and so that
// the finding stays readable in a terminal that cannot render the smear.
type Finding struct {
	Kind  Kind
	Line  int    // 1-based
	Bytes []byte // the offending run, verbatim
	Want  string // what the run folds back to, for KindMojibake
	Depth int    // how many folds were needed, for KindMojibake
}

// String renders a finding in a form safe to print anywhere.
func (f Finding) String() string {
	switch f.Kind {
	case KindInvalidUTF8:
		return fmt.Sprintf("line %d: not valid UTF-8 (bytes % X)", f.Line, f.Bytes)
	default:
		return fmt.Sprintf("line %d: mojibake (bytes % X) — %d fold(s) recover %q",
			f.Line, f.Bytes, f.Depth, f.Want)
	}
}

// Fold inverts one round of the mojibake transformation: it reads each
// character of s as a single byte and decodes the result as UTF-8.
//
// It reports false when s contains a character above U+00FF (which therefore
// cannot have come from a single byte) or when the resulting bytes are not
// well-formed UTF-8. Both mean "s was not produced by that transformation",
// which is the answer the caller needs.
func Fold(s string) (string, bool) {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return "", false
		}
		b = append(b, byte(r))
	}
	if len(b) == 0 || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// hasNonASCII reports whether s contains any character outside ASCII.
//
// A fold that lands on pure ASCII is not evidence of mojibake: it is what
// ordinary Latin-1-range text does by accident. Requiring the recovered text
// to still carry a non-ASCII character is what keeps legitimate prose such as
// "café" or "Ça" out of the findings.
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

// Scan reports every encoding defect in data.
//
// Findings are returned in file order. An empty slice means the file is clean.
func Scan(data []byte) []Finding {
	if !utf8.Valid(data) {
		// Locate the first bad byte so the report names a line, then stop:
		// once a file is not UTF-8, every further offset is guesswork.
		line := 1
		for i := 0; i < len(data); {
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size <= 1 {
				end := i + 8
				if end > len(data) {
					end = len(data)
				}
				return []Finding{{Kind: KindInvalidUTF8, Line: line, Bytes: data[i:end]}}
			}
			if data[i] == '\n' {
				line++
			}
			i += size
		}
		return []Finding{{Kind: KindInvalidUTF8, Line: line}}
	}

	var out []Finding
	for i, raw := range strings.Split(string(data), "\n") {
		out = append(out, scanLine(raw, i+1)...)
	}
	return out
}

// scanLine finds the mojibake runs in a single line.
//
// A run is a maximal sequence of characters in U+0080..U+00FF. Runs shorter
// than two characters are skipped: one such character folds to one byte, which
// is never valid multi-byte UTF-8, so it cannot be mojibake and flagging it
// would condemn every legitimate "é" in the tree.
func scanLine(line string, lineNo int) []Finding {
	rs := []rune(line)
	var out []Finding
	for i := 0; i < len(rs); i++ {
		if rs[i] < 0x80 || rs[i] > 0xFF {
			continue
		}
		j := i
		for j < len(rs) && rs[j] >= 0x80 && rs[j] <= 0xFF {
			j++
		}
		run := string(rs[i:j])
		i = j - 1 // continue after the run; j > i always, so this advances
		if len([]rune(run)) < 2 {
			continue
		}
		cur, depth := run, 0
		best, bestDepth := "", 0
		for depth < maxFoldDepth {
			next, ok := Fold(cur)
			if !ok {
				break
			}
			depth++
			cur = next
			if hasNonASCII(next) {
				best, bestDepth = next, depth
			}
		}
		if bestDepth == 0 {
			continue
		}
		out = append(out, Finding{
			Kind:  KindMojibake,
			Line:  lineNo,
			Bytes: []byte(run),
			Want:  best,
			Depth: bestDepth,
		})
	}
	return out
}

// Summarize groups findings by their recovered text, for a report that says
// what the corruption WAS rather than listing several hundred occurrences.
func Summarize(fs []Finding) []string {
	counts := map[string]int{}
	shape := map[string]Finding{}
	for _, f := range fs {
		key := fmt.Sprintf("%X", f.Bytes)
		counts[key]++
		shape[key] = f
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		if counts[keys[a]] != counts[keys[b]] {
			return counts[keys[a]] > counts[keys[b]]
		}
		return keys[a] < keys[b]
	})
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		f := shape[k]
		out = append(out, fmt.Sprintf("%5d × % X → %q (%d fold(s))", counts[k], f.Bytes, f.Want, f.Depth))
	}
	return out
}

// DemonstratedSequence is one corruption actually observed in this repository,
// recorded so the detector can be proven against real damage rather than only
// against damage invented by its own author.
type DemonstratedSequence struct {
	// Bytes is the sequence exactly as it appeared in the corrupted file. It
	// is written as escapes so that this source file stays pure ASCII and can
	// never be flagged by the very control it supports.
	Bytes []byte
	// Want is the character the sequence should have been.
	Want string
	// Depth is how many folds separate Bytes from Want.
	Depth int
	// Count is how many times it occurred in docs/REQUIREMENTS_MATRIX.md at
	// commit 3152485b96cc669bca1f73b8fefa7fd171f7df6f.
	Count int
}

// DemonstratedSequences is the complete corruption census of
// docs/REQUIREMENTS_MATRIX.md at 3152485b96cc669bca1f73b8fefa7fd171f7df6f.
//
// The first five are DOUBLE-encoded (the Latin-1 misreading was applied
// twice); the last five are SINGLE-encoded. Both families are listed because
// both were present in the same file, which is itself evidence that the damage
// accumulated across more than one pass rather than in a single bad write.
var DemonstratedSequences = []DemonstratedSequence{
	{Bytes: []byte("\xC3\x83\xC2\xA2\xC3\x82\xC2\x80\xC3\x82\xC2\x94"), Want: "—", Depth: 2, Count: 317},
	{Bytes: []byte("\xC3\x83\xC2\x82\xC3\x82\xC2\xA7"), Want: "§", Depth: 2, Count: 294},
	{Bytes: []byte("\xC3\x83\xC2\xA2\xC3\x82\xC2\x80\xC3\x82\xC2\xA6"), Want: "…", Depth: 2, Count: 54},
	{Bytes: []byte("\xC3\x83\xC2\xA2\xC3\x82\xC2\x80\xC3\x82\xC2\x93"), Want: "–", Depth: 2, Count: 3},
	{Bytes: []byte("\xC3\x83\xC2\xA2\xC3\x82\xC2\x88\xC3\x82\xC2\x92"), Want: "−", Depth: 2, Count: 2},

	{Bytes: []byte("\xC3\x82\xC2\xA7"), Want: "§", Depth: 1, Count: 5},
	{Bytes: []byte("\xC3\xA2\xC2\x80\xC2\x94"), Want: "—", Depth: 1, Count: 4},
	{Bytes: []byte("\xC3\xA2\xC2\x80\xC2\xA6"), Want: "…", Depth: 1, Count: 1},
	// This one never occurs alone: its single instance abuts a single-encoded
	// section sign, and the detector groups a maximal run, so the run recovers
	// two characters at once. Recorded as observed rather than as tidied.
	{Bytes: []byte("\xC3\xA2\xC2\x80\xC2\x93\xC3\x82\xC2\xA7"), Want: "–§", Depth: 1, Count: 1},
	{Bytes: []byte("\xC3\xA2\xC2\x86\xC2\x92"), Want: "→", Depth: 1, Count: 1},
}
