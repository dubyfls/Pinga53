// SPDX-License-Identifier: AGPL-3.0-only

package acquire_test

import (
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/acquire"
)

// C-11 — source health, and the one rule that is easy to get wrong.
//
// A quarantine is not a failure. A failure means this host could not get an
// answer; a quarantine means the source gave an answer this build refused to
// believe. The second is a statement about the source and it does not expire
// because the next attempt merely timed out. An implementation that reads the
// most recent event, or that lets a later plain failure overwrite the
// quarantine, reports "degraded — probably the network" about a source that
// last shipped something structurally wrong.

func at(h int) time.Time { return now.Add(time.Duration(h) * time.Hour) }

func TestAQuarantineOutlivesTheFailuresThatFollowIt(t *testing.T) {
	events := []acquire.Event{
		{At: at(0), Outcome: acquire.OutcomeApplied},
		{At: at(1), Outcome: acquire.OutcomeQuarantined},
		{At: at(2), Outcome: acquire.OutcomeFailed},
		{At: at(3), Outcome: acquire.OutcomeFailed},
	}

	h := acquire.AssessHealth(events)
	if h.Status != acquire.Unhealthy {
		t.Fatalf("status = %s, want %s: a quarantine sits after the last good snapshot and two timeouts do not clear it",
			h.Status, acquire.Unhealthy)
	}
	if !h.QuarantinedSinceLastGood {
		t.Errorf("QuarantinedSinceLastGood = false; the quarantine at %s is after the last applied snapshot at %s",
			at(1).Format(time.RFC3339), at(0).Format(time.RFC3339))
	}
}

func TestOrderIsByTimeNotByPosition(t *testing.T) {
	// Same history, delivered out of order. Health is a statement about when
	// things happened, not about how the slice was built.
	events := []acquire.Event{
		{At: at(3), Outcome: acquire.OutcomeFailed},
		{At: at(0), Outcome: acquire.OutcomeApplied},
		{At: at(2), Outcome: acquire.OutcomeFailed},
		{At: at(1), Outcome: acquire.OutcomeQuarantined},
	}
	if got := acquire.AssessHealth(events).Status; got != acquire.Unhealthy {
		t.Errorf("status = %s, want %s", got, acquire.Unhealthy)
	}
}

func TestAGoodSnapshotAfterTheQuarantineClearsIt(t *testing.T) {
	// The control on the control. Unhealthy must be recoverable, or a source
	// that once shipped a bad snapshot is condemned forever and the operator
	// learns to ignore the status.
	events := []acquire.Event{
		{At: at(0), Outcome: acquire.OutcomeApplied},
		{At: at(1), Outcome: acquire.OutcomeQuarantined},
		{At: at(2), Outcome: acquire.OutcomeApplied},
	}
	h := acquire.AssessHealth(events)
	if h.Status != acquire.Healthy {
		t.Fatalf("status = %s, want %s", h.Status, acquire.Healthy)
	}
	if h.QuarantinedSinceLastGood {
		t.Errorf("the quarantine precedes the last applied snapshot and should not count against it")
	}
}

func TestPlainFailuresAloneAreDegradedNotUnhealthy(t *testing.T) {
	// The discrimination this control exists for: these two histories must
	// not report the same thing.
	events := []acquire.Event{
		{At: at(0), Outcome: acquire.OutcomeApplied},
		{At: at(1), Outcome: acquire.OutcomeFailed},
		{At: at(2), Outcome: acquire.OutcomeFailed},
	}
	if got := acquire.AssessHealth(events).Status; got != acquire.Degraded {
		t.Errorf("status = %s, want %s: nothing was refused, the source was merely unreachable", got, acquire.Degraded)
	}
}

func TestASourceThatHasNeverDeliveredIsNotHealthy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []acquire.Event
		want   acquire.Status
	}{
		{"nothing at all", nil, acquire.Unknown},
		{"only failures", []acquire.Event{{At: at(0), Outcome: acquire.OutcomeFailed}}, acquire.Unhealthy},
		{"only quarantines", []acquire.Event{{At: at(0), Outcome: acquire.OutcomeQuarantined}}, acquire.Unhealthy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := acquire.AssessHealth(tc.events).Status; got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHealthReportsWhatItSaw(t *testing.T) {
	events := []acquire.Event{
		{At: at(0), Outcome: acquire.OutcomeApplied},
		{At: at(1), Outcome: acquire.OutcomeQuarantined},
		{At: at(2), Outcome: acquire.OutcomeFailed},
	}
	h := acquire.AssessHealth(events)
	if !h.LastGood.Equal(at(0)) {
		t.Errorf("LastGood = %s, want %s", h.LastGood, at(0))
	}
	if h.FailuresSinceLastGood != 1 {
		t.Errorf("FailuresSinceLastGood = %d, want 1", h.FailuresSinceLastGood)
	}
	if h.QuarantinesSinceLastGood != 1 {
		t.Errorf("QuarantinesSinceLastGood = %d, want 1", h.QuarantinesSinceLastGood)
	}
	if h.Reason == "" {
		t.Errorf("an unhealthy source reported no reason")
	}
}
