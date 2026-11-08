// SPDX-License-Identifier: AGPL-3.0-only

package acquire

import (
	"fmt"
	"slices"
	"time"
)

// Outcome is what one acquisition attempt came to.
//
// The distinction between Failed and Quarantined carries the whole of C-11.
// Failed means this host could not get an answer — a timeout, a refused
// connection, a 500. Quarantined means the source DID answer and the answer
// was refused by the gates in Decide. The first is a statement about the
// network; the second is a statement about the source.
type Outcome string

// The three outcomes.
const (
	OutcomeApplied     Outcome = "applied"
	OutcomeQuarantined Outcome = "quarantined"
	OutcomeFailed      Outcome = "failed"
)

// Event is one attempt's outcome at one time.
type Event struct {
	At      time.Time
	Outcome Outcome
}

// Status is a source's health.
type Status string

// The four statuses.
const (
	// Unknown — nothing has been attempted yet. Distinct from Healthy: a
	// source nobody has asked is not a source that answered.
	Unknown Status = "unknown"
	// Healthy — the most recent thing that happened was a good snapshot.
	Healthy Status = "healthy"
	// Degraded — nothing has been refused, but this host has not been able
	// to reach the source since its last good snapshot.
	Degraded Status = "degraded"
	// Unhealthy — the source shipped something the gates refused, and has
	// not shipped anything good since. Also: it has never shipped anything
	// good at all.
	Unhealthy Status = "unhealthy"
)

// Health is what AssessHealth found, with the arithmetic it used.
type Health struct {
	Status Status
	// LastGood is the time of the most recent applied snapshot; zero if
	// there has never been one.
	LastGood                 time.Time
	QuarantinesSinceLastGood int
	FailuresSinceLastGood    int
	// QuarantinedSinceLastGood is the C-11 rule in one field.
	QuarantinedSinceLastGood bool
	// Reason states the finding in the vocabulary above. Empty when healthy.
	Reason string
}

// AssessHealth computes a source's health from its attempt history.
//
// The rule that is easy to get wrong: a quarantine standing after the last
// good snapshot keeps the source UNHEALTHY however many plain failures come
// after it. An implementation that reads the most recent event, or that lets
// a later failure overwrite the quarantine, reports "degraded — probably the
// network" about a source that last shipped something structurally wrong, and
// the operator reads that as a reason to wait rather than to look.
//
// events need not be sorted; health is a statement about when things
// happened, not about how the slice was built.
func AssessHealth(events []Event) Health {
	if len(events) == 0 {
		return Health{Status: Unknown, Reason: "no acquisition has been attempted"}
	}

	ordered := slices.Clone(events)
	slices.SortStableFunc(ordered, func(a, b Event) int { return a.At.Compare(b.At) })

	var h Health
	for _, e := range ordered {
		if e.Outcome == OutcomeApplied {
			// A good snapshot resets the window. Unhealthy has to be
			// recoverable, or a source that once shipped a bad snapshot is
			// condemned forever and the operator learns to ignore the status.
			h = Health{Status: Healthy, LastGood: e.At}
			continue
		}
		switch e.Outcome {
		case OutcomeQuarantined:
			h.QuarantinesSinceLastGood++
			h.QuarantinedSinceLastGood = true
		default:
			h.FailuresSinceLastGood++
		}
	}

	switch {
	case h.QuarantinedSinceLastGood:
		h.Status = Unhealthy
		h.Reason = fmt.Sprintf("%d snapshot(s) refused by the gates since the last good one; %d further attempt(s) did not reach the source",
			h.QuarantinesSinceLastGood, h.FailuresSinceLastGood)
	case h.LastGood.IsZero():
		h.Status = Unhealthy
		h.Reason = "the source has never delivered a snapshot that passed the gates"
	case h.FailuresSinceLastGood > 0:
		h.Status = Degraded
		h.Reason = fmt.Sprintf("%d attempt(s) did not reach the source since the last good snapshot; nothing was refused",
			h.FailuresSinceLastGood)
	default:
		h.Status = Healthy
	}
	return h
}
