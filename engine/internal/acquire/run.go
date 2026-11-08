// SPDX-License-Identifier: AGPL-3.0-only

package acquire

import (
	"fmt"
	"time"
)

// AttemptState is the lifecycle of one acquisition attempt.
//
// AttemptRunning exists so that an unfinished row is representable and
// therefore detectable. It must never be the state of a row Run has returned:
// a row that never closed is indistinguishable from one still in flight, and
// the next run either waits for it forever or fetches the source twice.
type AttemptState string

// The attempt states.
const (
	AttemptRunning     AttemptState = "running"
	AttemptApplied     AttemptState = "applied"
	AttemptQuarantined AttemptState = "quarantined"
	AttemptFailed      AttemptState = "failed"
)

// Attempt is one source's row for one run.
type Attempt struct {
	SourceID string
	Started  time.Time
	Finished time.Time
	State    AttemptState
	// Error is why a failed attempt failed, with anything URL-shaped
	// redacted — a source URL may carry an API key in its query string and
	// this string is stored and logged. See C-14.
	Error string
	// Gates lists the gates that refused, for a quarantined attempt.
	Gates []Gate
}

// RunInput is what one acquisition pass needs.
type RunInput struct {
	SourceIDs []string
	// InEffect maps source id to the snapshot currently in effect. A source
	// absent from the map has delivered nothing yet.
	InEffect map[string]Snapshot
	Limits   Limits
	Now      time.Time
	// Fetch obtains a source's current snapshot. It may return an error and
	// it may panic; neither is allowed to affect any other source.
	Fetch func(sourceID string) (Snapshot, error)
}

// RunResult is what the pass came to.
type RunResult struct {
	Attempts []Attempt
	// InEffect is the state after the pass. It is a fresh map; the input map
	// is not modified, so a caller holding the previous state still holds it.
	InEffect map[string]Snapshot
}

// Events renders the pass as C-11 health events.
func (r RunResult) Events() []Event {
	out := make([]Event, 0, len(r.Attempts))
	for _, a := range r.Attempts {
		switch a.State {
		case AttemptApplied:
			out = append(out, Event{At: a.Finished, Outcome: OutcomeApplied})
		case AttemptQuarantined:
			out = append(out, Event{At: a.Finished, Outcome: OutcomeQuarantined})
		default:
			out = append(out, Event{At: a.Finished, Outcome: OutcomeFailed})
		}
	}
	return out
}

// Run attempts every source in turn and applies C-10's gates to what comes
// back.
//
// Three properties, and the third is the one that turns a bug into an outage:
//
//  1. A failure withdraws nothing. The snapshot in effect for a source that
//     could not be reached is the snapshot that was already in effect.
//  2. No row is returned in state `running`, including when the fetch panics.
//  3. One source failing does not stop the others being asked.
//
// Run does not fetch. It takes Fetch as an argument so that this control can
// be proven against a function that fails, panics or returns a bad snapshot,
// without a network in the test.
func Run(in RunInput) RunResult {
	out := RunResult{
		Attempts: make([]Attempt, 0, len(in.SourceIDs)),
		InEffect: make(map[string]Snapshot, len(in.InEffect)),
	}
	for k, v := range in.InEffect {
		out.InEffect[k] = v
	}

	for _, id := range in.SourceIDs {
		a := Attempt{SourceID: id, Started: in.Now, State: AttemptRunning}

		snap, err := fetchOne(in.Fetch, id)

		switch {
		case err != nil:
			// Clause 1. The map is not touched, so what was in effect for
			// this source stays in effect.
			a.State = AttemptFailed
			a.Error = Redact(err.Error())
		default:
			var prev *Snapshot
			if p, ok := out.InEffect[id]; ok {
				prev = &p
			}
			d := Decide(prev, snap, in.Limits, in.Now)
			if d.Applied {
				a.State = AttemptApplied
			} else {
				a.State = AttemptQuarantined
				a.Gates = d.FailedGates()
			}
			// Decide returns what is in effect afterwards, which for a
			// quarantine is the previous snapshot unchanged.
			out.InEffect[id] = d.InEffect
		}

		// Clause 2. One assignment, on every path out of the switch.
		a.Finished = in.Now
		out.Attempts = append(out.Attempts, a)
	}
	return out
}

// fetchOne calls fetch and converts a panic into an error.
//
// Recovering from a panic is not this codebase's habit and it is deliberate
// here. C-12 distinguishes a fetch failure from an INTERNAL error and requires
// both to leave a closed row and a continuing loop. A panic two layers down in
// a decoder is the internal error, and without this the row is never written
// at all and every later source is never asked — clause 3 fails in the way
// that is hardest to notice, because the process simply stops.
func fetchOne(fetch func(string) (Snapshot, error), id string) (s Snapshot, err error) {
	defer func() {
		if r := recover(); r != nil {
			// The panic value is not interpolated. It is composed by
			// whatever failed and may carry a host, a URL or a credential.
			_ = r
			err = fmt.Errorf("internal error while acquiring the snapshot")
		}
	}()
	if fetch == nil {
		return Snapshot{}, fmt.Errorf("no fetch function was configured")
	}
	return fetch(id)
}
