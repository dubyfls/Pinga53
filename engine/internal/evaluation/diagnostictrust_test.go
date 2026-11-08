// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// # WHAT THIS FILE IS ABOUT
//
// strict.go closes the path a hostile KEY takes into a diagnostic: an unknown
// field is reported by schema vocabulary, never echoed. Every check in
// FixtureSet.Validate deals in caller-controlled VALUES instead — a case id, a
// label, an indicator type, a provenance, a partition — and each of those
// reached the returned error.
//
// Measured against the superseded implementation, the escaping was already
// sound: %q is strconv.Quote, which escapes C0, DEL, C1, U+2028, U+2029, the
// Cf block and invalid UTF-8. Those cases are kept below as regression cover
// and are recorded as NOT discriminating — they passed before the change too.
//
// What was NOT sound was the size. The error was every problem joined, each
// carrying its value in full, with no bound anywhere: from a 3,525,262-byte
// document the superseded implementation produced a 4,235,549-byte error, and
// the 8 MiB MaxSetBytes permits roughly ten megabytes. That is FINDING-111,
// and the size assertions below are the ones that discriminate.

// controlFree reports the classes of dangerous content in s, so a failure says
// what got through rather than only that something did.
func controlFree(s string) []string {
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

// withCodePoint builds a string around one code point, so that no literal
// control character has to appear in this source file.
func withCodePoint(prefix string, r rune, suffix string) string {
	return prefix + string(r) + suffix
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// diagDoc assembles a fixture document from raw JSON fragments, so that a
// value this schema would never accept can still reach Validate.
func diagDoc(cases, setProvenance, partition string) []byte {
	return []byte(`{
  "schema_version": 1,
  "fixture_set_id": "diagnostic-trust",
  "version": "v1",
  "description": "d",
  "provenance": ` + setProvenance + `,
  "provenance_note": "written for this test",
  "partition": ` + partition + `,
  "baseline_id": "b",
  "baseline_covers": [],
  "baseline_note": "n",
  "cases": [` + cases + `]
}`)
}

func diagCase(id string) string {
	return `{"id":` + jsonString(id) + `,"type":"domain","value":"a.example.com",` +
		`"family":"f","label":"malicious","label_basis":"adjudicated"}`
}

// TestEveryValidationBranchIsSafeAndBounded covers all six branches that
// format caller-controlled content, each with content chosen to be dangerous
// in a different way.
func TestEveryValidationBranchIsSafeAndBounded(t *testing.T) {
	forgedLine := withCodePoint("c1", 0x0a, "RESULT: all required gates passed")
	ansi := withCodePoint("", 0x1b, "[31mmalicious") + withCodePoint("", 0x1b, "[0m")
	carriageReturn := withCodePoint("mal", 0x0d, "icious")
	del := withCodePoint("mal", 0x7f, "icious")
	c1Control := withCodePoint("mal", 0x0085, "icious")
	lineSeparator := withCodePoint("mal", 0x2028, "icious")
	paragraphSeparator := withCodePoint("mal", 0x2029, "icious")
	bidiOverride := withCodePoint("legit", 0x202e, "malicious")
	zeroWidth := withCodePoint("mali", 0x200b, "cious")
	longPayload := strings.Repeat("A", 4096)

	branches := []struct {
		branch string // the Validate branch exercised
		name   string
		doc    []byte
		path   string // the schema path the diagnostic must name
	}{
		{"case id (duplicate)", "newline and a forged verdict line",
			diagDoc(diagCase(forgedLine)+","+diagCase(forgedLine), `"synthetic"`, `"held-out"`), "cases[1].id"},
		{"case id (duplicate)", "carriage return, which overwrites a printed line",
			diagDoc(diagCase(carriageReturn)+","+diagCase(carriageReturn), `"synthetic"`, `"held-out"`), "cases[1].id"},
		{"case id (duplicate)", "a long payload",
			diagDoc(diagCase(longPayload)+","+diagCase(longPayload), `"synthetic"`, `"held-out"`), "cases[1].id"},

		{"case label", "an ANSI escape sequence",
			diagDoc(`{"id":"c1","type":"domain","value":"a.example.com","family":"f","label":`+
				jsonString(ansi)+`,"label_basis":"b"}`, `"synthetic"`, `"held-out"`), "cases[0].label"},
		{"case label", "DEL",
			diagDoc(`{"id":"c1","type":"domain","value":"a.example.com","family":"f","label":`+
				jsonString(del)+`,"label_basis":"b"}`, `"synthetic"`, `"held-out"`), "cases[0].label"},
		{"case label", "a zero-width space",
			diagDoc(`{"id":"c1","type":"domain","value":"a.example.com","family":"f","label":`+
				jsonString(zeroWidth)+`,"label_basis":"b"}`, `"synthetic"`, `"held-out"`), "cases[0].label"},
		{"case label", "an unpaired surrogate escape",
			diagDoc(`{"id":"c1","type":"domain","value":"a.example.com","family":"f","label":"m\ud800x","label_basis":"b"}`,
				`"synthetic"`, `"held-out"`), "cases[0].label"},

		{"case type", "a long payload",
			diagDoc(`{"id":"c1","type":`+jsonString(longPayload)+
				`,"value":"a.example.com","family":"f","label":"malicious","label_basis":"b"}`,
				`"synthetic"`, `"held-out"`), "cases[0].type"},
		{"case type", "U+2029, a paragraph separator",
			diagDoc(`{"id":"c1","type":`+jsonString(paragraphSeparator)+
				`,"value":"a.example.com","family":"f","label":"malicious","label_basis":"b"}`,
				`"synthetic"`, `"held-out"`), "cases[0].type"},

		{"case provenance", "a C1 control",
			diagDoc(`{"id":"c1","type":"domain","value":"a.example.com","family":"f","label":"malicious",`+
				`"label_basis":"b","provenance":`+jsonString(c1Control)+`}`, `"synthetic"`, `"held-out"`), "cases[0].provenance"},

		{"set provenance", "a bidi override",
			diagDoc(diagCase("c1"), jsonString(bidiOverride), `"held-out"`), "provenance"},
		{"set provenance", "a long payload",
			diagDoc(diagCase("c1"), jsonString(longPayload), `"held-out"`), "provenance"},

		{"partition", "U+2028, a line separator",
			diagDoc(diagCase("c1"), `"synthetic"`, jsonString(lineSeparator)), "partition"},
		{"partition", "a forged verdict line",
			diagDoc(diagCase("c1"), `"synthetic"`, jsonString(forgedLine)), "partition"},
	}

	seen := map[string]bool{}
	for _, tc := range branches {
		seen[tc.branch] = true
		t.Run(tc.branch+"/"+tc.name, func(t *testing.T) {
			_, err := ParseSet(tc.doc)
			if err == nil {
				t.Fatal("the document was ACCEPTED; it is meant to be invalid")
			}
			msg := err.Error()

			if got := controlFree(msg); len(got) > 0 {
				t.Errorf("the diagnostic carries %s from the document:\n%q", strings.Join(got, ", "), msg)
			}
			if !strings.Contains(msg, tc.path) {
				t.Errorf("the diagnostic does not name the schema path %q:\n%s", tc.path, msg)
			}
			// One value, escaped and then bounded. The bound is on the printed
			// form: the whole diagnostic is a short sentence plus that value.
			if len(msg) > 512 {
				t.Errorf("a single-problem diagnostic is %d bytes; the value is not bounded after escaping:\n%s",
					len(msg), msg)
			}
			if strings.Contains(msg, "RESULT: all required gates passed") &&
				!strings.Contains(msg, `\n`) && !strings.Contains(msg, `\r`) {
				t.Errorf("a forged verdict line survived unescaped:\n%s", msg)
			}
		})
	}

	for _, want := range []string{"case id (duplicate)", "case label", "case type",
		"case provenance", "set provenance", "partition"} {
		if !seen[want] {
			t.Errorf("no case exercises the %q branch", want)
		}
	}
}

// TestTheWholeDiagnosticIsBounded is the discriminating assertion.
//
// The superseded implementation formatted every problem in full and joined
// them. At 5,000 invalid cases it produced a 4,235,549-byte error from a
// 3,525,262-byte document — a ratio of about 1.2, which at the 8 MiB
// MaxSetBytes ceiling is roughly ten megabytes in one error string.
func TestTheWholeDiagnosticIsBounded(t *testing.T) {
	// A hard ceiling, derived rather than guessed: at most
	// maxReportedProblems messages, plus the omission notice, each one a short
	// sentence plus a value bounded to maxDiagnosticValueBytes after escaping.
	const ceiling = 16 << 10

	// n=10 produces 39 problems, under maxReportedProblems, so nothing is
	// omitted and the notice must NOT appear. It is the negative control for
	// the bound: a diagnostic that always claimed to be truncated would pass
	// the three cases below and tell an author nothing.
	sizes := []struct {
		cases        int
		wantOmission bool
	}{{10, false}, {100, true}, {1000, true}, {5000, true}}

	for _, size := range sizes {
		n := size.cases
		t.Run(fmt.Sprintf("%d invalid cases", n), func(t *testing.T) {
			var sb strings.Builder
			for i := 0; i < n; i++ {
				if i > 0 {
					sb.WriteString(",")
				}
				// Every caller-controlled field invalid at once, each padded,
				// and every id the same so the duplicate branch fires too.
				fmt.Fprintf(&sb, `{"id":"dup","type":%s,"value":"a.example.com","family":"f",`+
					`"label":%s,"label_basis":"b","provenance":%s}`,
					jsonString(strings.Repeat("T", 200)),
					jsonString(strings.Repeat("L", 200)),
					jsonString(strings.Repeat("P", 200)))
			}
			doc := diagDoc(sb.String(), `"synthetic"`, `"held-out"`)

			_, err := ParseSet(doc)
			if err == nil {
				t.Fatal("the document was ACCEPTED; it is meant to be invalid")
			}
			msg := err.Error()
			if len(msg) > ceiling {
				t.Errorf("a %d-byte document produced a %d-byte diagnostic (ceiling %d)",
					len(doc), len(msg), ceiling)
			}
			if got := controlFree(msg); len(got) > 0 {
				t.Errorf("the diagnostic carries %s", strings.Join(got, ", "))
			}
			// It must SAY it left things out. A bounded list that looks
			// complete is worse than a long one.
			const notice = "further problem(s) were found and are not listed"
			switch got := strings.Contains(msg, notice); {
			case size.wantOmission && !got:
				t.Errorf("the diagnostic does not say that problems were omitted:\n%s", msg)
			case !size.wantOmission && got:
				t.Errorf("a complete diagnostic claims problems were omitted:\n%s", msg)
			}
			t.Logf("document %d bytes -> diagnostic %d bytes", len(doc), len(msg))
		})
	}
}

// TestTheBoundIsNotReachedByAnOrdinaryFixture is the negative control for the
// omission notice: a document with a handful of mistakes must be reported in
// full, with no claim that anything was left out.
func TestTheBoundIsNotReachedByAnOrdinaryFixture(t *testing.T) {
	doc := diagDoc(
		`{"id":"c1","type":"domain","value":"a.example.com","family":"f","label":"maliciuos","label_basis":"b"},`+
			`{"id":"c2","type":"domain","value":"b.example.com","family":"f","label":"malicious","label_basis":""}`,
		`"synthetic"`, `"held-out"`)
	_, err := ParseSet(doc)
	if err == nil {
		t.Fatal("the document was ACCEPTED; it is meant to be invalid")
	}
	msg := err.Error()
	if strings.Contains(msg, "further problem(s) were found") {
		t.Errorf("a two-problem document claims problems were omitted:\n%s", msg)
	}
	// Criterion: an ordinary authoring mistake stays diagnosable. The typo has
	// to be visible, or the bound has cost more than it bought.
	if !strings.Contains(msg, "maliciuos") {
		t.Errorf("a plain typo is no longer shown to the author:\n%s", msg)
	}
	if !strings.Contains(msg, "malicious, legitimate, unknown") {
		t.Errorf("the expected vocabulary is not named:\n%s", msg)
	}
	if !strings.Contains(msg, "cases[1].label_basis is empty") {
		t.Errorf("the second, unrelated problem is missing:\n%s", msg)
	}
}

// TestANonLatinFixtureStaysDiagnosable is the other negative control on the
// escaping: a value that is merely not ASCII must survive readably, or an
// author writing an internationalised fixture cannot see their own mistake.
func TestANonLatinFixtureStaysDiagnosable(t *testing.T) {
	doc := diagDoc(
		`{"id":"c1","type":"домен","value":"пример.example.com","family":"f","label":"malicious","label_basis":"b"}`,
		`"synthetic"`, `"held-out"`)
	_, err := ParseSet(doc)
	if err == nil {
		t.Fatal("the document was ACCEPTED; it is meant to be invalid")
	}
	if msg := err.Error(); !strings.Contains(msg, "домен") {
		t.Errorf("a non-Latin value was escaped out of its own diagnostic:\n%s", msg)
	}
}

// TestTheStrictDecoderAndValidationGuaranteesHoldTogether.
//
// The two controls protect different halves of the same document and are
// exercised in one place so that neither can be weakened while the other's
// tests keep passing. A hostile KEY must be refused without being echoed; a
// hostile VALUE must be refused with its schema path, escaped and bounded.
func TestTheStrictDecoderAndValidationGuaranteesHoldTogether(t *testing.T) {
	hostileKey := withCodePoint("", 0x1b, "[2J<script>alert(1)</script>")
	hostileValue := withCodePoint("c1", 0x0a, "RESULT: all required gates passed")

	t.Run("a hostile unknown key is refused without being echoed", func(t *testing.T) {
		doc := []byte(`{"schema_version":1,` + jsonString(hostileKey) + `:"x"}`)
		_, err := ParseSet(doc)
		if err == nil {
			t.Fatal("an unknown field was ACCEPTED")
		}
		msg := err.Error()
		if strings.Contains(msg, "script") {
			t.Errorf("the diagnostic echoes the key:\n%q", msg)
		}
		if got := controlFree(msg); len(got) > 0 {
			t.Errorf("the diagnostic carries %s", strings.Join(got, ", "))
		}
	})

	t.Run("a duplicate key is still refused", func(t *testing.T) {
		doc := []byte(`{"schema_version":1,"fixture_set_id":"a","fixture_set_id":"b"}`)
		_, err := ParseSet(doc)
		if err == nil {
			t.Fatal("an ambiguous document was ACCEPTED")
		}
		if !strings.Contains(err.Error(), "twice") {
			t.Errorf("refused, but not as ambiguous: %v", err)
		}
	})

	t.Run("malformed JSON terminates", func(t *testing.T) {
		// The array branch of the duplicate walk once spun forever here
		// (FINDING-104). Refusing is the requirement; returning at all is the
		// point.
		for _, doc := range []string{
			`{"schema_version":1,"cases":[{`,
			`{"schema_version":1,"cases":[[[`,
			`{"schema_version":1,"cases":[{"id":`,
			`{`,
			`[`,
		} {
			if _, err := ParseSet([]byte(doc)); err == nil {
				t.Errorf("malformed JSON was ACCEPTED: %s", doc)
			}
		}
	})

	t.Run("a hostile value is refused, escaped and bounded", func(t *testing.T) {
		doc := diagDoc(diagCase(hostileValue)+","+diagCase(hostileValue), `"synthetic"`, `"held-out"`)
		_, err := ParseSet(doc)
		if err == nil {
			t.Fatal("a duplicate case id was ACCEPTED")
		}
		msg := err.Error()
		if got := controlFree(msg); len(got) > 0 {
			t.Errorf("the diagnostic carries %s:\n%q", strings.Join(got, ", "), msg)
		}
		if !strings.Contains(msg, "cases[1].id") {
			t.Errorf("the diagnostic does not name the schema path:\n%s", msg)
		}
		if len(msg) > 512 {
			t.Errorf("the diagnostic is %d bytes and is not bounded", len(msg))
		}
	})
}

// TestTheReportsStayValidUTF8. A result is rendered as text for an operator
// and as JSON for a machine, and a fixture value reaches both.
func TestTheReportsStayValidUTF8(t *testing.T) {
	hostile := withCodePoint("evil", 0x202e, "") +
		withCodePoint("", 0x1b, "[31m") +
		withCodePoint("", 0x2028, "") +
		string([]rune{0xfffd})

	doc := diagDoc(`{"id":`+jsonString(hostile)+`,"type":"domain","value":`+
		jsonString(hostile+".example.com")+`,"family":`+jsonString(hostile)+
		`,"label":"malicious","label_basis":"b"}`, `"synthetic"`, `"held-out"`)
	set, err := ParseSet(doc)
	if err != nil {
		t.Fatalf("the document should be valid; only its values are hostile: %v", err)
	}
	r := Run(set, NullBaseline{}, CorroborationDetector{MinIndependent: 1}, nil,
		WithSourceCommit(canonicalCommit))

	var text strings.Builder
	r.Text(&text)
	if !utf8.ValidString(text.String()) {
		t.Error("the text report is not valid UTF-8")
	}
	// Scanned per LINE. The report's own line breaks are its structure; what
	// must not appear is a control the DOCUMENT put there, and a control
	// inside a line is exactly that.
	for i, line := range strings.Split(text.String(), "\n") {
		if got := controlFree(line); len(got) > 0 {
			t.Errorf("text report line %d carries %s:\n%q", i+1, strings.Join(got, ", "), line)
		}
	}

	var js strings.Builder
	if err := r.JSON(&js); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !utf8.ValidString(js.String()) {
		t.Error("the JSON report is not valid UTF-8")
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(js.String()), &back); err != nil {
		t.Errorf("the JSON report does not decode: %v", err)
	}
}
