// SPDX-License-Identifier: AGPL-3.0-only

// Package atomicfile replaces a file's contents whole, or not at all.
//
// # WHY THIS IS NOT A ONE-LINER AT EACH CALL SITE
//
// Two callers in this tree persist state a later run makes decisions from:
// the ownership ledger and the journal. Both have the same failure mode if
// the write is interrupted — a truncated document — and a truncated ownership
// record is one that has forgotten what ScamWall is holding, which is the
// input under which a removal run proposes to unblock everything.
//
// The sequence that prevents it is four steps in a fixed order (temp file in
// the SAME directory, write, fsync, rename) and the fsync is the step that
// gets dropped when the sequence is retyped. Written twice, one copy loses it
// and nothing fails until a power cut. Written once, both callers get the
// same guarantee and it is tested in one place.
//
// # WHAT IT DOES NOT PROMISE
//
// That the DIRECTORY entry is durable. The rename is atomic with respect to a
// reader — no reader ever sees a partial file — and this package fsyncs the
// file's contents before the rename, so a reader that sees the new name sees
// whole contents. Surviving a power cut that lands between the rename and the
// directory's own flush would need the directory fsynced too. Not done here,
// and stated rather than implied: the callers' documents are rebuilt from
// their inputs on the next run, so losing the very last write costs a run,
// not the record.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with b, atomically with respect to any reader.
//
// The temp file is created in path's own directory, because a rename across
// filesystems is not atomic and /tmp is very often a different filesystem
// from wherever the caller keeps its state.
func Write(path string, b []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	tmp := f.Name()
	// On every failure the temp file is removed, so a failed write leaves
	// neither a changed target nor litter beside it.
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	if err = f.Chmod(mode); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if _, err = f.Write(b); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	return nil
}
