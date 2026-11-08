// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"errors"
	"strings"
	"testing"
)

// setWith builds a minimal valid fixture set whose cases array is injected raw,
// so a test can put a deliberately malformed case in it.
func setWith(cases string) string {
	return `{
  "schema_version": 1,
  "fixture_set_id": "strict-test",
  "version": "v1",
  "description": "d",
  "provenance": "synthetic",
  "provenance_note": "written for this test",
  "partition": "held-out",
  "baseline_id": "b",
  "baseline_covers": [],
  "baseline_note": "n",
  "cases": [` + cases + `]
}`
}

const validCase = `{"id":"c1","type":"domain","value":"a.example","family":"f",` +
	`"label":"legitimate","label_basis":"adjudicated"}`

// TestValidSetStillLoads is the control that keeps every test below honest.
//
// A parser that refused everything would pass all the rejection tests and be
// useless. This is the same document those tests mutate, unmutated.
func TestValidSetStillLoads(t *testing.T) {
	s, err := ParseSet([]byte(setWith(validCase)))
	if err != nil {
		t.Fatalf("the unmutated fixture set was refused: %v", err)
	}
	if s.ID != "strict-test" || len(s.Cases) != 1 {
		t.Fatalf("parsed to id=%q, %d case(s)", s.ID, len(s.Cases))
	}
}

// TestDuplicateKeysAreRefusedAtEveryNestingLevel is the substance of the fix.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// It decoded with encoding/json, which accepts duplicate keys and keeps the
// LAST one. Every case below was ACCEPTED, silently, with the value shown in
// "was" — including a case whose ground-truth label flipped from legitimate to
// malicious, and a set whose identity changed to a different set entirely.
func TestDuplicateKeysAreRefusedAtEveryNestingLevel(t *testing.T) {
	tests := []struct {
		name string
		was  string // what the superseded decoder silently produced
		doc  string
		key  string // the schema key the diagnostic must name
	}{
		{
			name: "top-level identity",
			was:  `fixture_set_id = "OVERRIDDEN"`,
			key:  "fixture_set_id",
			doc: `{"schema_version":1,"fixture_set_id":"strict-test","version":"v1",` +
				`"description":"d","provenance":"synthetic","provenance_note":"n",` +
				`"partition":"held-out","baseline_id":"b","baseline_covers":[],` +
				`"baseline_note":"n","cases":[` + validCase + `],` +
				`"fixture_set_id":"OVERRIDDEN"}`,
		},
		{
			name: "top-level partition",
			was:  `partition = "development"`,
			key:  "partition",
			doc: `{"schema_version":1,"fixture_set_id":"s","version":"v1",` +
				`"description":"d","provenance":"synthetic","provenance_note":"n",` +
				`"partition":"held-out","baseline_id":"b","baseline_covers":[],` +
				`"baseline_note":"n","cases":[` + validCase + `],` +
				`"partition":"development"}`,
		},
		{
			name: "case label",
			was:  `label = "malicious"`,
			key:  "label",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","label":"malicious"}`),
		},
		{
			name: "case value",
			was:  `value = "attacker.example"`,
			key:  "value",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","value":"attacker.example"}`),
		},
		{
			name: "case identity",
			was:  `id = "c2"`,
			key:  "id",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","id":"c2"}`),
		},
		{
			name: "observation source",
			was:  `source_id = "s2"`,
			key:  "source_id",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","observations":[` +
				`{"source_id":"s1","classification":"malicious","state":"active","source_id":"s2"}]}`),
		},
		{
			name: "observation classification",
			was:  `classification = "benign"`,
			key:  "classification",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","observations":[` +
				`{"source_id":"s1","classification":"malicious","state":"active","classification":"benign"}]}`),
		},
		{
			name: "feed claim action",
			was:  `action = "allow"`,
			key:  "action",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b",` +
				`"feed_claim":{"action":"block","confidence":"high","action":"allow"}}`),
		},
		{
			name: "feed claim confidence",
			was:  `confidence = "low"`,
			key:  "confidence",
			doc: setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b",` +
				`"feed_claim":{"action":"block","confidence":"high","confidence":"low"}}`),
		},
		{
			name: "second case in the array",
			was:  `cases[1].label = "malicious"`,
			key:  "label",
			doc: setWith(validCase + `,{"id":"c2","type":"domain","value":"b.example",` +
				`"family":"f","label":"legitimate","label_basis":"b","label":"malicious"}`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSet([]byte(tc.doc))
			if err == nil {
				t.Fatalf("ACCEPTED an ambiguous document; the superseded decoder "+
					"resolved it silently to %s", tc.was)
			}
			if !errors.Is(err, ErrAmbiguousDocument) {
				t.Fatalf("refused, but not as ambiguous: %v", err)
			}
			if !strings.Contains(err.Error(), `"`+tc.key+`"`) {
				t.Errorf("the diagnostic does not name the schema key %q: %v", tc.key, err)
			}
		})
	}
}

// hostileKeys are key names written with JSON escape sequences, so that this
// source file stays pure ASCII while the DECODED key carries the control
// characters an attacker would actually use. None of the decoded form may
// appear in any diagnostic.
var hostileKeys = []struct {
	name    string
	json    string // as it appears inside the document, escapes unexpanded
	decoded string // what the key becomes once JSON unescaping has run
}{
	{"an HTML payload", `<script>alert(1)</script>`, `<script>alert(1)</script>`},
	{"an ANSI colour run", `\u001b[31mFAKE PASS\u001b[0m`, "\x1b[31mFAKE PASS\x1b[0m"},
	{"a forged report line", `x\nRESULT: all required gates passed`, "x\nRESULT: all required gates passed"},
	{"a line-erase sequence", `\u001b[2K\rRESULT: PASS`, "\x1b[2K\rRESULT: PASS"},
	{"a padding run", strings.Repeat("A", 4096), strings.Repeat("A", 4096)},
	{"a traversal", `../../etc/passwd`, `../../etc/passwd`},
}

// TestDuplicateKeyDiagnosticsDoNotReproduceCallerBytes.
//
// The diagnostic names a key only when the key is one of this schema's own.
// Anything else is caller-controlled and must not be echoed: the superseded
// implementation emitted `json: unknown field "<script>alert(1)</script>"`
// verbatim into whatever read its output.
func TestDuplicateKeyDiagnosticsDoNotReproduceCallerBytes(t *testing.T) {
	for _, hk := range hostileKeys {
		t.Run(hk.name, func(t *testing.T) {
			doc := setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","` + hk.json + `":"x","` + hk.json + `":"y"}`)
			_, err := ParseSet([]byte(doc))
			if err == nil {
				t.Fatal("the ambiguous document was accepted")
			}
			assertNoCallerBytes(t, err.Error(), hk.decoded)
		})
	}
}

// TestUnknownFieldErrorDoesNotReproduceCallerBytes covers the same boundary on
// the other path: a key that appears ONCE but is not in the schema. This is
// the path that demonstrably leaked, through encoding/json's own message.
//
// HONEST NOTE ON DISCRIMINATION. Three of the six cases discriminate and three
// do not. Against the superseded implementation the HTML payload, the traversal
// and the 4 KiB padding run were all reproduced verbatim into the error — the
// last inflating one diagnostic to 4137 bytes. The three carrying TERMINAL
// control characters did NOT leak them, because encoding/json builds that
// message with %q, which escapes them to text. They are kept as regression
// cover: %q is an implementation detail of the standard library, not a
// guarantee this package is entitled to rely on.
func TestUnknownFieldErrorDoesNotReproduceCallerBytes(t *testing.T) {
	for _, hk := range hostileKeys {
		t.Run(hk.name, func(t *testing.T) {
			doc := setWith(`{"id":"c1","type":"domain","value":"a.example","family":"f",` +
				`"label":"legitimate","label_basis":"b","` + hk.json + `":"x"}`)
			_, err := ParseSet([]byte(doc))
			if err == nil {
				t.Fatal("an unknown field was accepted")
			}
			assertNoCallerBytes(t, err.Error(), hk.decoded)
		})
	}
}

// assertNoCallerBytes is the shared assertion: a diagnostic may carry this
// schema's own vocabulary and nothing else.
func assertNoCallerBytes(t *testing.T, msg, decoded string) {
	t.Helper()
	if strings.Contains(msg, decoded) {
		t.Errorf("the diagnostic reproduces the caller's key verbatim: %.120q", msg)
	}
	if strings.ContainsAny(msg, "\x1b\r\n") {
		t.Errorf("the diagnostic carries terminal control characters: %.120q", msg)
	}
	if strings.Contains(msg, strings.Repeat("A", 64)) {
		t.Errorf("the diagnostic carries a caller-controlled padding run: %d bytes", len(msg))
	}
	if strings.Contains(msg, "<script>") {
		t.Errorf("the diagnostic carries caller-controlled markup: %.120q", msg)
	}
}

// TestExactlyOneDocumentIsAccepted.
//
// HONEST NOTE ON DISCRIMINATION. These cases do fail against the superseded
// implementation, but NOT on the verdict. That implementation used dec.More()
// and already REJECTED all five; it simply returned a bare errors.New rather
// than a wrapped sentinel, so what these assertions actually discriminate is
// the error IDENTITY, not whether the document was accepted. No input has been
// found that More() got wrong. The change to an explicit second decode
// expecting io.EOF was made because More() derives its answer from a peek that
// swallows any read error it encounters, not because a wrong verdict was
// observed. Recorded this way so the entry cannot be read as a repaired defect.
func TestExactlyOneDocumentIsAccepted(t *testing.T) {
	one := setWith(validCase)
	tests := []struct{ name, doc string }{
		{"a second complete document", one + one},
		{"trailing prose", one + "  and then some words"},
		{"a trailing NUL", one + "\x00"},
		{"a trailing array", one + "[]"},
		{"a trailing scalar", one + "7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSet([]byte(tc.doc)); err == nil {
				t.Fatal("accepted a file holding more than one document")
			} else if !errors.Is(err, ErrTrailingContent) {
				t.Fatalf("refused, but not as trailing content: %v", err)
			}
		})
	}
	// Trailing whitespace is not trailing content, and must still load.
	if _, err := ParseSet([]byte(one + "\n\n\t  \n")); err != nil {
		t.Errorf("trailing whitespace was refused: %v", err)
	}
}

// TestNestingIsBounded. The duplicate walk recurses, so an input nested deeply
// enough would exhaust the stack before any validation ran.
func TestNestingIsBounded(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat(`}`, 5000)
	_, err := ParseSet([]byte(deep))
	if err == nil {
		t.Fatal("a deeply nested document was accepted")
	}
	if !errors.Is(err, ErrTooDeep) {
		t.Logf("refused, though not by the depth bound: %v", err)
	}
}

// TestRepositoryFixtureLoads keeps the strictness honest against the real file.
func TestRepositoryFixtureLoads(t *testing.T) {
	s, err := LoadSet("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatalf("the repository's own fixture set no longer loads: %v", err)
	}
	if len(s.Cases) == 0 {
		t.Fatal("the repository fixture parsed to no cases")
	}
}
