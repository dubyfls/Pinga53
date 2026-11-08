// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"testing"
	"time"
)

// withinDeadline runs f and fails if it has not returned in time.
//
// The goroutine is deliberately LEAKED on timeout rather than waited for:
// against the superseded implementation it never returns, and a test that
// blocked on it would hang the suite it is meant to protect.
func withinDeadline(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s: the parser hangs on this input", what, d)
	}
}

// TestMalformedJSONInsideAnArrayDoesNotHang.
//
// # THE DEFECT
//
// checkDuplicates walks tokens before the decode, and stopped on a read error
// by returning nil. The array branch is `for dec.More()`, a decoder in an
// error state keeps answering true, and a recursive call that returned nil
// WITHOUT CONSUMING ANYTHING left that loop spinning forever.
//
// Every input below is malformed inside an array, which is the shape a fixture
// set always has — `cases` is an array. The result was an unbounded loop
// before any validation ran: a denial of service reachable from a fixture
// file, and one that no existing test found, because every malformed fixture
// anybody had written was malformed at the top level.
//
// This was introduced by the duplicate-key walk itself. It is recorded here
// rather than quietly repaired because a control that hangs on hostile input
// is worse than the ambiguity it was added to refuse.
func TestMalformedJSONInsideAnArrayDoesNotHang(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"a raw control character in a string inside an array",
			"{\"cases\":[{\"id\":\"a\x1bb\"}]}"},
		{"an unterminated string inside an array", `{"cases":[{"id":"unterminated]}`},
		{"a bare word inside an array", `{"cases":[nonsense]}`},
		{"a truncated object inside an array", `{"cases":[{"id":`},
		{"an unterminated array", `{"cases":[1,2,3`},
		{"a nested malformed array", `{"cases":[[{"id":"a` + "\x1b" + `"}]]}`},
		{"a lone comma in an array", `{"cases":[,]}`},
		{"a control character in a key inside an array",
			"{\"cases\":[{\"a\x00b\":1}]}"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withinDeadline(t, 5*time.Second, "checkDuplicates", func() {
				_ = checkDuplicates([]byte(tc.doc))
			})
			withinDeadline(t, 5*time.Second, "ParseSet", func() {
				// The verdict is not the point here; returning at all is.
				_, _ = ParseSet([]byte(tc.doc))
			})
		})
	}
}

// TestMalformedInputIsStillRefused is the control that keeps the fix honest.
//
// Terminating is necessary and not sufficient: the parser must still say no.
func TestMalformedInputIsStillRefused(t *testing.T) {
	for _, doc := range []string{
		`{"cases":[nonsense]}`,
		`{"cases":[{"id":`,
		"{\"cases\":[{\"id\":\"a\x1bb\"}]}",
	} {
		if _, err := ParseSet([]byte(doc)); err == nil {
			t.Errorf("malformed input was accepted: %.40q", doc)
		}
	}
}
