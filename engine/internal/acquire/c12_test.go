// SPDX-License-Identifier: AGPL-3.0-only

package acquire_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/acquire"
)

// C-12 — what a fetch failure, and an internal error, may and may not do.
//
// Three clauses, and the third is the one that turns a bug into an outage:
//
//  1. A failure never withdraws. What was in effect stays in effect.
//  2. No attempt row is left `running`. A row that never closed is
//     indistinguishable from one still in flight, and the next run either
//     waits for it forever or double-fetches.
//  3. The loop continues. One source failing is not a reason to stop asking
//     the others — that turns one broken publisher into a whole-run outage.

var errFetch = errors.New("connection refused")

func TestAFailingSourceWithdrawsNothingAndDoesNotStopTheLoop(t *testing.T) {
	inEffect := map[string]acquire.Snapshot{
		"src-0001": good(t, 100),
		"src-0002": good(t, 100),
		"src-0003": good(t, 100),
	}
	for id, s := range inEffect {
		s.SourceID = id
		inEffect[id] = s
	}

	asked := map[string]bool{}
	run := acquire.Run(acquire.RunInput{
		SourceIDs: []string{"src-0001", "src-0002", "src-0003"},
		InEffect:  inEffect,
		Limits:    sensibleLimits(),
		Now:       now,
		Fetch: func(id string) (acquire.Snapshot, error) {
			asked[id] = true
			if id == "src-0002" {
				return acquire.Snapshot{}, errFetch
			}
			s := good(t, 105)
			s.SourceID = id
			s.IssuedAt = now.Add(-10 * time.Minute)
			return s, nil
		},
	})

	// 3 — the loop continued.
	for _, id := range []string{"src-0001", "src-0002", "src-0003"} {
		if !asked[id] {
			t.Errorf("%s was never asked; one source's failure stopped the loop", id)
		}
	}

	// 1 — nothing was withdrawn from the source that failed.
	if got := len(run.InEffect["src-0002"].Entries); got != 100 {
		t.Errorf("src-0002 has %d entries in effect after a failed fetch, want the 100 it had", got)
	}

	// 2 — no row left running.
	for _, a := range run.Attempts {
		if a.State == acquire.AttemptRunning {
			t.Errorf("attempt row for %s was left %s", a.SourceID, a.State)
		}
		if a.Finished.IsZero() {
			t.Errorf("attempt row for %s has no finish time", a.SourceID)
		}
	}

	byID := map[string]acquire.Attempt{}
	for _, a := range run.Attempts {
		byID[a.SourceID] = a
	}
	if got := byID["src-0002"].State; got != acquire.AttemptFailed {
		t.Errorf("src-0002 attempt state = %s, want %s", got, acquire.AttemptFailed)
	}
	if got := byID["src-0001"].State; got != acquire.AttemptApplied {
		t.Errorf("src-0001 attempt state = %s, want %s", got, acquire.AttemptApplied)
	}
}

// TestAnInternalErrorIsStillAClosedRow — a panic inside the fetch is the case
// the row-closing rule exists for. Every ordinary error path is easy to get
// right; the one that leaves a row `running` forever is the one nobody wrote
// a branch for.
func TestAnInternalErrorIsStillAClosedRow(t *testing.T) {
	inEffect := map[string]acquire.Snapshot{"src-0002": good(t, 100)}
	s := inEffect["src-0002"]
	s.SourceID = "src-0002"
	inEffect["src-0002"] = s

	asked := map[string]bool{}
	run := acquire.Run(acquire.RunInput{
		SourceIDs: []string{"src-0001", "src-0002", "src-0003"},
		InEffect:  inEffect,
		Limits:    sensibleLimits(),
		Now:       now,
		Fetch: func(id string) (acquire.Snapshot, error) {
			asked[id] = true
			if id == "src-0002" {
				panic("a nil map write two layers down")
			}
			s := good(t, 105)
			s.SourceID = id
			s.IssuedAt = now.Add(-10 * time.Minute)
			return s, nil
		},
	})

	if !asked["src-0003"] {
		t.Fatalf("src-0003 was never asked; an internal error in src-0002 took the whole run down")
	}
	byID := map[string]acquire.Attempt{}
	for _, a := range run.Attempts {
		byID[a.SourceID] = a
	}
	got := byID["src-0002"]
	if got.State != acquire.AttemptFailed {
		t.Errorf("state after a panic = %q, want %s", got.State, acquire.AttemptFailed)
	}
	if got.Finished.IsZero() {
		t.Errorf("a panicking fetch left the attempt row open")
	}
	if len(run.InEffect["src-0002"].Entries) != 100 {
		t.Errorf("an internal error withdrew %d entries", 100-len(run.InEffect["src-0002"].Entries))
	}
	if !strings.Contains(got.Error, "internal error") {
		t.Errorf("attempt error = %q; it should say an internal error occurred", got.Error)
	}
}

// TestAQuarantineIsNotAFailure — the row must record which of the two
// happened, because C-11 reads this history and the statuses differ.
func TestAQuarantineIsNotAFailure(t *testing.T) {
	inEffect := map[string]acquire.Snapshot{"src-0001": good(t, 100)}
	s := inEffect["src-0001"]
	s.SourceID = "src-0001"
	inEffect["src-0001"] = s

	run := acquire.Run(acquire.RunInput{
		SourceIDs: []string{"src-0001"},
		InEffect:  inEffect,
		Limits:    sensibleLimits(),
		Now:       now,
		Fetch: func(id string) (acquire.Snapshot, error) {
			s := good(t, 5) // below the floor
			s.SourceID = id
			s.IssuedAt = now.Add(-10 * time.Minute)
			return s, nil
		},
	})

	if got := run.Attempts[0].State; got != acquire.AttemptQuarantined {
		t.Fatalf("state = %s, want %s", got, acquire.AttemptQuarantined)
	}
	if len(run.InEffect["src-0001"].Entries) != 100 {
		t.Errorf("the quarantine withdrew entries")
	}
	if len(run.Events()) != 1 || run.Events()[0].Outcome != acquire.OutcomeQuarantined {
		t.Errorf("Events() = %v; C-11 reads this and must see a quarantine, not a failure", run.Events())
	}
}

// TestAFetchErrorNamesNoURL — C-14's rule, asserted where the row is written.
func TestAFetchErrorNamesNoURL(t *testing.T) {
	run := acquire.Run(acquire.RunInput{
		SourceIDs: []string{"src-0001"},
		Limits:    sensibleLimits(),
		Now:       now,
		Fetch: func(string) (acquire.Snapshot, error) {
			return acquire.Snapshot{}, errors.New("Get \"https://feed.example.com/list?api_key=s3cr3t\": dial tcp: refused")
		},
	})
	if strings.Contains(run.Attempts[0].Error, "s3cr3t") {
		t.Errorf("the attempt row carries the credential from the URL: %q", run.Attempts[0].Error)
	}
}
