// SPDX-License-Identifier: AGPL-3.0-only

package mac

import "testing"

// TestAPurposeCannotBeForgedByChoosingTheMessage.
//
// The failure this guards is concatenation. If a tag were computed over
// purpose+message, a caller who chooses the message could move the boundary:
// purpose "ab" with message "cd" is the same bytes as purpose "a" with
// message "bcd". internal/observation's observationDigest documents the same
// attack against delimiter-joined fields and answers it the same way.
//
// This is an internal test because the exported Tag refuses an undeclared
// purpose, and the property is about the ENCODING rather than about the list.
// The closed purpose set happens to contain no prefix pairs today, which is
// exactly the kind of accident that stops being true when somebody adds a
// purpose.
func TestAPurposeCannotBeForgedByChoosingTheMessage(t *testing.T) {
	raw := make([]byte, MinKeyBytes)
	for i := range raw {
		raw[i] = 0x11
	}
	k, err := NewKey(raw)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if a, b := k.tag("report-binding", "x"), k.tag("report-bindin", "gx"); a == b {
		t.Fatalf("a caller moved the purpose boundary by choosing the message: %s", a)
	}
	if a, b := k.tag("ab", "cd"), k.tag("a", "bcd"); a == b {
		t.Fatalf("purpose and message are concatenated without a boundary: %s", a)
	}
}
