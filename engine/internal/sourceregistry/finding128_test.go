// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// FINDING-128. The duplicate-key walk in this package echoed the key it found
// straight into the diagnostic. ORDER 6 corrected that in the walk
// `internal/evaluation` used (FINDING-112, FINDING-113, FINDING-114) and the
// correction was carried into `internal/strictjson`; this package's copy never
// received it. A diagnostic must never reproduce bytes the document chose.
//
// These are the controls. Each one fails against the uncorrected walk.

// hostileKey is a key name a registry author would never write: an escape
// sequence, a NUL, a credential-shaped marker, and enough padding to make an
// unbounded diagnostic obvious.
const (
	secretMarker = "sk_live_51H8xQeRETURNEDVERBATIM"
	padRun       = 4096
)

func hostileKey() string {
	return "note\x1b[31m" + secretMarker + "\x00" + strings.Repeat("A", padRun)
}

// mustKey renders s as a JSON object key.
func mustKey(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	return string(b)
}

// TestDuplicateDiagnosticNeverEchoesTheKey is the control for FINDING-128.
//
// Pre-fix this fails on the first assertion: Problem.Path is the key itself,
// so the diagnostic carries the escape sequence, the NUL, the marker and all
// 4096 bytes of padding.
func TestDuplicateDiagnosticNeverEchoesTheKey(t *testing.T) {
	k := mustKey(t, hostileKey())
	doc := `{"schema_version":2,"sources":[{` + k + `:"a",` + k + `:"b"}]}`

	problems := checkNoDuplicateKeys([]byte(doc))

	// The error class is unchanged: an ambiguous document is still refused.
	if len(problems) == 0 {
		t.Fatal("a duplicate key was not reported at all; the control has " +
			"stopped testing what it was written for")
	}

	got := render(problems)
	for _, forbidden := range []struct{ what, bytes string }{
		{"the credential-shaped marker", secretMarker},
		{"an escape sequence", "\x1b"},
		{"a NUL byte", "\x00"},
		{"the padding run", strings.Repeat("A", 64)},
	} {
		if strings.Contains(got, forbidden.bytes) {
			t.Errorf("the diagnostic reproduces %s from the document.\nDiagnostic: %.300q",
				forbidden.what, got)
		}
	}

	// A fixed code and a position are permitted, and one of them must be
	// present or the diagnostic locates nothing.
	if !strings.Contains(got, "sources[0]") {
		t.Errorf("the diagnostic does not locate the offending object by position.\nDiagnostic: %.300q", got)
	}
}

// TestDuplicateDiagnosticIsBounded. A document may hold as many duplicates as
// it likes; the diagnostic built from it may not grow without limit. Pre-fix
// there is no bound at all: every duplicate appends a full Problem.
func TestDuplicateDiagnosticIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"schema_version":2,"note":"x","sources":[{`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"source_id":"a"`)
	}
	b.WriteString(`}]}`)

	problems := checkNoDuplicateKeys([]byte(b.String()))
	if len(problems) == 0 {
		t.Fatal("20000 duplicates of one key produced no problem")
	}
	if len(problems) > 1001 {
		t.Errorf("the walk collected %d problems from one document; it is "+
			"bounded by neither count nor memory", len(problems))
	}
	if n := len(render(problems)); n > 1<<16 {
		t.Errorf("the rendered diagnostic is %d bytes; a document controls its size", n)
	}
}

// TestDeeplyNestedRegistryDoesNotExhaustTheStack. The walk is recursive and
// had no depth bound, so a nested input reached a crash through the parser.
func TestDeeplyNestedRegistryDoesNotExhaustTheStack(t *testing.T) {
	const depth = 200000
	doc := `{"sources":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = checkNoDuplicateKeys([]byte(doc))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the walk did not finish on a deeply nested document")
	}
}

// TestKnownSchemaNamesAreStillNamed. The fix must not blind the diagnostic:
// a key the schema defines is the author's own word and is safe to repeat.
// Without this, "never echo anything" would pass by saying nothing useful.
func TestKnownSchemaNamesAreStillNamed(t *testing.T) {
	doc := `{"schema_version":2,"note":"a","note":"b","retired_source_ids":[],"sources":[]}`
	problems := checkNoDuplicateKeys([]byte(doc))
	assertProblem(t, problems, "note", "appears twice")

	doc2 := `{"schema_version":2,"note":"n","retired_source_ids":[],"sources":[{"source_id":"a","source_id":"b"}]}`
	assertProblem(t, checkNoDuplicateKeys([]byte(doc2)), "sources[0].source_id", "appears twice")
}

// TestParseStillRefusesTheHostileDocument checks the whole entry point, not
// just the walk: Parse must surface the ambiguity and must not leak the key.
func TestParseStillRefusesTheHostileDocument(t *testing.T) {
	k := mustKey(t, hostileKey())
	doc := `{"schema_version":2,"note":"n","retired_source_ids":[],"sources":[{` + k + `:"a",` + k + `:"b"}]}`

	reg, problems, err := Parse([]byte(doc))
	if len(problems) == 0 && err == nil {
		t.Fatal("Parse accepted a document that names one key twice")
	}
	all := render(problems)
	if err != nil {
		all += "\n" + err.Error()
	}
	if strings.Contains(all, secretMarker) {
		t.Errorf("Parse reproduced the document's key bytes.\nOutput: %.300q", all)
	}
	if reg != nil {
		if p := reg.Validate(time.Now()); strings.Contains(render(p), secretMarker) {
			t.Errorf("Validate reproduced the document's key bytes.\nOutput: %.300q", render(p))
		}
	}
}
