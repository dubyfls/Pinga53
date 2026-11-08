// SPDX-License-Identifier: AGPL-3.0-only

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesAndLeavesNoLitter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := Write(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("content is %q, want the second write", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v; a successful write must leave no temp file", names)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode is %v, want 0600", info.Mode().Perm())
	}
}

// TestAFailedWriteChangesNothing is the property the callers depend on.
//
// A truncated ownership ledger is a record that has forgotten what ScamWall
// is holding, and a truncated journal is a household's history with a hole in
// it. Neither may be the result of a write that did not complete.
func TestAFailedWriteChangesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Write(path, []byte("standing"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A target in a directory that does not exist: the temp file cannot be
	// created, so the sequence fails at its first step.
	if err := Write(filepath.Join(dir, "missing", "state.json"), []byte("new"), 0o600); err == nil {
		t.Fatal("a write into a directory that does not exist reported success")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "standing" {
		t.Errorf("the standing file is now %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("a failed write left %d entries behind, want 1", len(entries))
	}
}
