// SPDX-License-Identifier: AGPL-3.0-only

package ledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The command tests in cmd/scamwall drive Load and the retention rules through
// the real entry point. What is left here is the two things a command test
// cannot see: the boundary of the staleness measurement, and whether a save
// that fails leaves the previous ledger intact.

func TestAnAbsentLedgerIsNotAnEmptyOne(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nothing.json"))
	if err == nil {
		t.Fatal("a missing file loaded as a ledger; an ownership record that is not there and " +
			"one holding nothing are the difference between removing nothing and removing everything")
	}
	if !isAbsent(err) {
		t.Errorf("the failure is not distinguishable as absence: %v", err)
	}
}

func isAbsent(err error) bool {
	for err != nil {
		if err == ErrAbsent {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestAZeroAcquisitionIsStaleRatherThanFresh.
//
// The failure a zero time always causes when it is read as "now". A ledger
// nobody has recorded an acquisition into would otherwise licence a full
// rewrite of the household's enforcement on its first run.
func TestAZeroAcquisitionIsStaleRatherThanFresh(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	l := New()

	stale, why := l.AcquisitionStale(now, time.Hour)
	if !stale {
		t.Error("a ledger with no recorded acquisition was treated as freshly supplied")
	}
	if why == "" {
		t.Error("the staleness verdict carries no reason")
	}

	// An unset limit measures nothing. An unset limit is not a zero one.
	if stale, _ := l.AcquisitionStale(now, 0); stale {
		t.Error("a run that asked for no staleness measurement got one anyway")
	}
}

func TestStalenessIsMeasuredAtTheBoundary(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		age   time.Duration
		stale bool
	}{
		{"inside", 23 * time.Hour, false},
		{"exactly at the limit", 24 * time.Hour, false},
		{"one second past", 24*time.Hour + time.Second, true},
	} {
		l := New()
		l.LastAcquisitionAt = now.Add(-tc.age)
		if got, _ := l.AcquisitionStale(now, 24*time.Hour); got != tc.stale {
			t.Errorf("%s: stale=%v, want %v", tc.name, got, tc.stale)
		}
	}
}

func TestSaveReplacesAtomicallyAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")

	l := New()
	l.Serial = "2026060101"
	l.LastAcquisitionAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	l.Owned = []Owned{{
		Canonical:       "b.example.net",
		AddedAt:         time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		LastJustifiedAt: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
	}, {
		Canonical: "a.example.net",
		AddedAt:   time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
	}}
	if err := l.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Serial != "2026060101" || got.Count() != 2 {
		t.Errorf("round trip lost content: %+v", got)
	}
	// Sorted, so two marshals of one ledger are byte-identical and a save
	// that changed nothing is a no-op in version control.
	if got.Owned[0].Canonical != "a.example.net" {
		t.Errorf("entries are not sorted: %v", got.OwnedNames())
	}

	// No temp file is left behind for a save that succeeded.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "ledger.json" {
			t.Errorf("save left %q behind", e.Name())
		}
	}

	// Mode 0600: the ledger is the list of what this household blocks.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("ledger mode is %v, want 0600", info.Mode().Perm())
	}
}

// TestAFailedSaveLeavesThePreviousLedgerIntact.
//
// Writing in place would leave a truncated ledger behind if anything
// interrupted it, and a truncated ledger is an ownership record that has
// forgotten what ScamWall is holding.
func TestAFailedSaveLeavesThePreviousLedgerIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")

	first := New()
	first.Serial = "2026060101"
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A directory the temp file cannot be created in: the save fails before
	// anything touches the existing file.
	second := New()
	second.Serial = "2026060102"
	if err := second.Save(filepath.Join(dir, "no-such-dir", "ledger.json")); err == nil {
		t.Fatal("a save into a directory that does not exist reported success")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("a failed save changed the standing ledger")
	}
}
