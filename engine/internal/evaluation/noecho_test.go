// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFixtureDuplicateDiagnosticNeverEchoesTheKey.
//
// ORDER 8, item A, sibling sweep. FINDING-128 was that `internal/sourceregistry`
// never received the ORDER 6 corrections this package did. This is the control
// that says so in THIS package rather than in a document: the property holds
// here already (ALREADY-PRESENT), and it is now pinned so that a future edit
// cannot quietly undo it the way the registry's copy did.
func TestFixtureDuplicateDiagnosticNeverEchoesTheKey(t *testing.T) {
	const marker = "sk_live_51H8xQeRETURNEDVERBATIM"
	key := "cases\x1b[31m" + marker + "\x00" + strings.Repeat("A", 4096)

	k, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	doc := `{` + string(k) + `:1,` + string(k) + `:2}`

	err = checkDuplicates([]byte(doc))
	if err == nil {
		t.Fatal("a document naming one key twice was accepted")
	}
	got := err.Error()
	for what, bytes := range map[string]string{
		"the credential-shaped marker": marker,
		"an escape sequence":           "\x1b",
		"a NUL byte":                   "\x00",
		"the padding run":              strings.Repeat("A", 64),
	} {
		if strings.Contains(got, bytes) {
			t.Errorf("the diagnostic reproduces %s from the document.\nDiagnostic: %.200q", what, got)
		}
	}
}
