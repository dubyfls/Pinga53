// SPDX-License-Identifier: AGPL-3.0-only

package strictjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type doc struct {
	SchemaVersion int      `json:"schema_version"`
	Name          string   `json:"name"`
	Items         []item   `json:"items"`
	Tags          []string `json:"tags"`
}

type item struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
}

func names() map[string]bool { return FieldNames(doc{}) }

func TestFieldNamesCollectsTheWholeSchema(t *testing.T) {
	got := names()
	for _, want := range []string{"schema_version", "name", "items", "tags", "id", "scope"} {
		if !got[want] {
			t.Errorf("FieldNames did not collect %q", want)
		}
	}
	if got["not_a_field"] {
		t.Error("FieldNames invented a name")
	}
}

func TestADuplicateKeyIsRefusedAtEveryLevel(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		at   string
	}{
		{"top level", `{"schema_version":1,"schema_version":2}`, "the top-level object"},
		{"inside an array element", `{"items":[{"id":"a","id":"b"}]}`, "items[0]"},
		{"deeper", `{"items":[{"id":"a"},{"scope":"x","scope":"y"}]}`, "items[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDuplicates([]byte(tc.doc), names())
			if err == nil {
				t.Fatal("an ambiguous document was ACCEPTED")
			}
			if !errors.Is(err, ErrAmbiguous) {
				t.Fatalf("wrong error: %v", err)
			}
			if !strings.Contains(err.Error(), tc.at) {
				t.Errorf("the diagnostic does not locate the duplicate at %q: %v", tc.at, err)
			}
		})
	}
}

// TestAnUnambiguousDocumentIsAccepted is the positive control. A checker that
// refused everything would satisfy every assertion above.
func TestAnUnambiguousDocumentIsAccepted(t *testing.T) {
	for _, d := range []string{
		`{"schema_version":1,"name":"x","items":[{"id":"a"},{"id":"b"}],"tags":["p","q"]}`,
		// Sibling objects repeating the SAME field names are not duplicates.
		`{"items":[{"id":"a","scope":"exact"},{"id":"a","scope":"exact"}]}`,
		`{}`,
		`[]`,
		`null`,
	} {
		if err := CheckDuplicates([]byte(d), names()); err != nil {
			t.Errorf("a well-formed document was refused: %s\n  %v", d, err)
		}
	}
}

// TestMalformedJSONStopsTheWalkRatherThanHangingIt.
//
// The array loop is `for dec.More()`, and a decoder in an error state keeps
// answering true. A recursive call that returned without consuming anything
// would spin forever — a denial of service reachable from an input file.
func TestMalformedJSONStopsTheWalkRatherThanHangingIt(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- CheckDuplicates([]byte(`{"items":[{"id":}]}`), names())
	}()
	select {
	case err := <-done:
		// Malformed JSON is reported by the decode that follows, not here.
		if err != nil && !errors.Is(err, ErrAmbiguous) {
			t.Logf("walk returned: %v", err)
		}
	case <-timeoutAfterASecond():
		t.Fatal("the walk did not terminate on malformed JSON")
	}
}

func TestDeepNestingIsRefusedRatherThanCrashing(t *testing.T) {
	deep := strings.Repeat(`{"items":[`, 200) + strings.Repeat(`]}`, 200)
	err := CheckDuplicates([]byte(deep), names())
	if err == nil {
		t.Fatal("a 200-level document was walked to the bottom")
	}
	if !errors.Is(err, ErrTooDeep) {
		t.Fatalf("wrong error: %v", err)
	}
}

// TestAHostileKeyReachesNoDiagnostic carries FINDING-112 and FINDING-113
// forward: the path is sanitised where the key ARRIVES, because `.` and `[`
// can both occur inside a key and a render-time clean cannot tell a segment
// the walk produced from one the document supplied.
func TestAHostileKeyReachesNoDiagnostic(t *testing.T) {
	hostile := []string{
		"items[" + string(rune(0x1b)) + "[2J" + string(rune(0x07)) + "forged",
		"items.id",
		"items[999]",
		"name" + string(rune(0x202e)) + "reversed",
		"items[" + strings.Repeat("A", 4096) + "]",
	}
	for _, key := range hostile {
		t.Run(strings.Map(func(r rune) rune {
			if r < 0x20 || r > 0x7e {
				return '?'
			}
			return r
		}, key), func(t *testing.T) {
			raw, err := json.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			err = CheckDuplicates([]byte(`{`+string(raw)+`:{"id":1,"id":2}}`), names())
			if err == nil {
				t.Fatal("ACCEPTED")
			}
			msg := err.Error()
			for _, r := range msg {
				if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
					t.Fatalf("a raw control U+%04X reached the diagnostic: %q", r, msg)
				}
			}
			if !utf8.ValidString(msg) {
				t.Errorf("the diagnostic is not valid UTF-8")
			}
			if tail := strings.TrimPrefix(key, "items"); tail != "" && strings.Contains(msg, tail) {
				t.Errorf("the diagnostic echoes the key %q: %q", tail, msg)
			}
			if strings.Contains(msg, "items.id") {
				t.Errorf("the diagnostic renders a forged schema path: %q", msg)
			}
			if !strings.Contains(msg, UnrecognisedSegment) {
				t.Errorf("an unrecognised segment is not reported as one: %q", msg)
			}
		})
	}
}

// TestAKnownSegmentIsStillNamed is the other positive control: replacing
// every segment with the placeholder would satisfy the test above and tell an
// author nothing about where their typo is.
func TestAKnownSegmentIsStillNamed(t *testing.T) {
	err := CheckDuplicates([]byte(`{"items":[{"id":1,"id":2}]}`), names())
	if err == nil {
		t.Fatal("ACCEPTED")
	}
	if !strings.Contains(err.Error(), "items[0]") {
		t.Errorf("a schema name is no longer located for the author: %v", err)
	}
	if !strings.Contains(err.Error(), `"id"`) {
		t.Errorf("a key this schema DOES define was not named: %v", err)
	}
	if strings.Contains(err.Error(), UnrecognisedSegment) {
		t.Errorf("a known key was reported as unrecognised: %v", err)
	}
}

// TestTheDiagnosticIsBoundedInWhatItBUILDS, not only in what it prints.
//
// FINDING-114 carried forward: every individual problem here is short and
// safe, and the COUNT is caller-controlled.
func TestTheDiagnosticIsBounded(t *testing.T) {
	const n = 20000
	var b strings.Builder
	b.WriteString(`{"schema_version":1`)
	for i := 0; i < n; i++ {
		b.WriteString(`,"schema_version":1`)
	}
	b.WriteString(`}`)

	err := CheckDuplicates([]byte(b.String()), names())
	if err == nil {
		t.Fatal("ACCEPTED")
	}
	if got := len(err.Error()); got > 32*1024 {
		t.Errorf("a %d-byte document produced a %d-byte diagnostic", b.Len(), got)
	}
	if !strings.Contains(err.Error(), "not listed") {
		t.Error("the bound reads as a clean bill of health")
	}
	if got := strings.Count(err.Error(), "names"); got > MaxReported {
		t.Errorf("%d problems listed, above the bound of %d", got, MaxReported)
	}
}

// TestASmallNumberOfProblemsIsListedInFull — the bound must not truncate an
// ordinary mistake, or an author reads a partial list as a complete one.
func TestASmallNumberOfProblemsIsListedInFull(t *testing.T) {
	err := CheckDuplicates([]byte(`{"name":"a","name":"b","schema_version":1,"schema_version":2}`), names())
	if err == nil {
		t.Fatal("ACCEPTED")
	}
	if got := strings.Count(err.Error(), "names"); got != 2 {
		t.Errorf("two duplicates, %d reported: %v", got, err)
	}
	if strings.Contains(err.Error(), "not listed") {
		t.Errorf("a two-problem document was reported as truncated: %v", err)
	}
}

// TestNilKnownNamesNamesNoKey — a caller with no vocabulary still gets a
// located diagnostic and echoes nothing.
func TestNilKnownNamesNamesNoKey(t *testing.T) {
	err := CheckDuplicates([]byte(`{"anything":{"x":1,"x":2}}`), nil)
	if err == nil {
		t.Fatal("ACCEPTED")
	}
	if strings.Contains(err.Error(), "anything") || strings.Contains(err.Error(), `"x"`) {
		t.Errorf("a key was echoed with no known-name set: %v", err)
	}
}

// timeoutAfterASecond is the hang detector for the walk test.
func timeoutAfterASecond() <-chan time.Time { return time.After(time.Second) }
