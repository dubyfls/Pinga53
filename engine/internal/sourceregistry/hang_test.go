// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

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

// TestMalformedRegistryJSONDoesNotHang.
//
// # THE DEFECT
//
// checkNoDuplicateKeys walks tokens before the decode and stopped on a read
// error with a plain `return`. The array branch was `for dec.More()`, a
// decoder in an error state keeps answering true, and a recursive call that
// returned without consuming anything left that loop spinning forever.
//
// The registry file is mostly arrays — sources, retired_source_ids,
// indicator_types, upstream_sources, aggregation_dependencies — so malformed
// JSON almost anywhere in it hung the parser BEFORE validation ran. That is a
// denial of service reachable from a file docs/SOURCE_REGISTRY.md §4 already
// describes as untrusted input.
//
// It was found while auditing the copy of this walk in internal/evaluation,
// not by a test of this package: every malformed-registry fixture written here
// was malformed at the top level, where the object branch returned correctly.
func TestMalformedRegistryJSONDoesNotHang(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"a raw control character inside the sources array",
			"{\"sources\":[{\"source_id\":\"a\x1bb\"}]}"},
		{"an unterminated string inside the sources array",
			`{"sources":[{"source_id":"unterminated]}`},
		{"a bare word inside the sources array", `{"sources":[nonsense]}`},
		{"a truncated record", `{"sources":[{"source_id":`},
		{"an unterminated retired_source_ids array", `{"retired_source_ids":["a","b"`},
		{"a malformed nested indicator_types array",
			"{\"sources\":[{\"indicator_types\":[\"a\x1bb\"]}]}"},
		{"a lone comma in an array", `{"sources":[,]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withinDeadline(t, 5*time.Second, "checkNoDuplicateKeys", func() {
				_ = checkNoDuplicateKeys([]byte(tc.doc))
			})
			withinDeadline(t, 5*time.Second, "Parse", func() {
				_, _, _ = Parse([]byte(tc.doc))
			})
		})
	}
}

// TestMalformedRegistryIsStillRefused. Terminating is necessary, not
// sufficient: the parser must still say no.
func TestMalformedRegistryIsStillRefused(t *testing.T) {
	for _, doc := range []string{
		`{"sources":[nonsense]}`,
		`{"sources":[{"source_id":`,
		"{\"sources\":[{\"source_id\":\"a\x1bb\"}]}",
	} {
		if _, _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("malformed registry input was accepted: %.40q", doc)
		}
	}
}

// TestDuplicateDetectionStillWorksAfterTheLoopFix is the control that the
// repair did not simply stop the walk from doing its job.
func TestDuplicateDetectionStillWorksAfterTheLoopFix(t *testing.T) {
	doc := `{"schema_version":2,"sources":[{"source_id":"a","source_id":"b"}]}`
	problems := checkNoDuplicateKeys([]byte(doc))
	if len(problems) == 0 {
		t.Fatal("a duplicate key inside an array element was not reported")
	}
	// And a duplicate in a LATER array element must still be reached.
	doc2 := `{"sources":[{"source_id":"a"},{"source_id":"b","source_id":"c"}]}`
	if len(checkNoDuplicateKeys([]byte(doc2))) == 0 {
		t.Error("a duplicate in the second array element was not reported; the " +
			"walk stops too early")
	}
}
