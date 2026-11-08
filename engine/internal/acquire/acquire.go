// SPDX-License-Identifier: AGPL-3.0-only

// Package acquire decides whether a newly obtained snapshot of a source may
// replace the one currently in effect, and tracks how well a source has been
// behaving.
//
// # WHAT THIS PACKAGE IS NOT
//
// It does not fetch anything. It has no network dependency and no reference to
// net/http, deliberately: the question "may this snapshot be applied" is a
// decision about two lists and a clock, and keeping it apart from the transport
// means it can be exercised exhaustively without a server. internal/acquire/fetch.go
// carries the bounded transport, and it hands its result here.
//
// # THE PROPERTY THAT MATTERS
//
// A gate that refuses a bad snapshot by emptying the list has converted "this
// update looks wrong" into the exact harm the gate exists to prevent. So a
// refusal here is a QUARANTINE: the snapshot is not applied, and the snapshot
// already in effect stays in effect, entry for entry. Decide never returns a
// smaller set than it was given. See TestEverySevenGateRefusesAndNoneOfThemWithdraws.
package acquire

import (
	"fmt"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// Gate names one reason a snapshot may be refused.
//
// The seven are not a taxonomy for its own sake. Each one is a distinct way
// the feed-update harm arrives: a snapshot that is not what the publisher
// signed (Integrity), one that describes a world that has moved on
// (Freshness, NotRegressive), one that lost its contents (MinEntries,
// MaxShrink, MaxWithdrawal), or one that suddenly asserts far more than it
// ever has (MaxGrowth). The first three groups risk mass UNBLOCKING; the last
// risks mass BLOCKING.
type Gate string

// The seven gates, plus the refusal to decide without limits.
const (
	// GateIntegrity — the snapshot did not verify against the publisher's key.
	// The caller establishes this; this package will not take "probably fine".
	GateIntegrity Gate = "integrity"
	// GateFreshness — issued too long ago to describe the present, or issued
	// in a future further away than clock skew explains.
	GateFreshness Gate = "freshness"
	// GateNotRegressive — issued no later than the snapshot already in effect.
	// Serving an old snapshot again is how a rollback is delivered.
	GateNotRegressive Gate = "not_regressive"
	// GateMinEntries — fewer entries than a working source ever has.
	GateMinEntries Gate = "min_entries"
	// GateMaxShrink — lost more of its count than an ordinary update does.
	GateMaxShrink Gate = "max_shrink_fraction"
	// GateMaxGrowth — grew by more than an ordinary update does.
	GateMaxGrowth Gate = "max_growth_factor"
	// GateMaxWithdrawal — too many entries that WERE in effect are absent.
	// Distinct from MaxShrink on purpose: a snapshot can keep its count and
	// replace every host in it, which shrink arithmetic cannot see and which
	// unblocks everything that was blocked.
	GateMaxWithdrawal Gate = "max_withdrawal_fraction"

	// GateLimitsUnset is not one of the seven. It is what fires when the
	// gates were never configured. A zero limit is an unset gate, not an
	// unbounded one, and an unset gate must not pass silently.
	GateLimitsUnset Gate = "limits_unset"
)

// Snapshot is one source's assertion, at one time, of the hosts it lists.
type Snapshot struct {
	SourceID string
	// IssuedAt is the publisher's own timestamp, not when it was fetched.
	// Fetch time says when this host asked; it says nothing about how old
	// the answer is.
	IssuedAt time.Time
	// Entries are the canonical hosts the snapshot asserts. Order is not
	// significant; duplicates are counted once.
	Entries []domain.Domain
	// Verified records whether the caller established the snapshot's
	// authenticity. It is a field rather than an assumption so that the
	// integrity gate has something to read even when the transport that
	// produced the snapshot is a test.
	Verified bool
}

// count returns the number of distinct entries.
func (s Snapshot) count() int { return len(s.set()) }

func (s Snapshot) set() map[domain.Domain]struct{} {
	m := make(map[domain.Domain]struct{}, len(s.Entries))
	for _, e := range s.Entries {
		m[e] = struct{}{}
	}
	return m
}

// Limits configure the gates. Every field must be set; see GateLimitsUnset.
type Limits struct {
	// MinEntries is the floor below which a snapshot is not believed.
	MinEntries int
	// MaxShrinkFraction is how much of the previous count a snapshot may
	// lose. 0.25 means a snapshot holding fewer than three quarters of the
	// previous count is refused.
	MaxShrinkFraction float64
	// MaxGrowthFactor is the multiple of the previous count a snapshot may
	// reach. 4 means a snapshot more than four times the previous size is
	// refused.
	MaxGrowthFactor float64
	// MaxWithdrawalFraction is how much of what is IN EFFECT may be absent
	// from the new snapshot.
	MaxWithdrawalFraction float64
	// MaxAge is how old a snapshot's issued_at may be.
	MaxAge time.Duration
	// ClockSkew is how far into the future an issued_at may sit.
	ClockSkew time.Duration
}

// unset reports whether any gate was left at its zero value.
func (l Limits) unset() bool {
	return l.MinEntries <= 0 ||
		l.MaxShrinkFraction <= 0 ||
		l.MaxGrowthFactor <= 0 ||
		l.MaxWithdrawalFraction <= 0 ||
		l.MaxAge <= 0 ||
		l.ClockSkew <= 0
}

// Failure is one gate's refusal.
type Failure struct {
	Gate Gate
	// Detail is arithmetic, never contents. A quarantine diagnostic reaches
	// the operator's terminal and the gate log; the source chose the hosts
	// in the snapshot and must not choose what is printed.
	Detail string
}

// Decision is the outcome of applying the gates to one snapshot.
type Decision struct {
	// Applied and Quarantined are mutually exclusive and exhaustive.
	Applied     bool
	Quarantined bool
	Failures    []Failure
	// InEffect is what is in effect AFTER this decision: the new snapshot if
	// it was applied, the previous one unchanged if it was quarantined.
	InEffect Snapshot
}

// Failed reports whether gate g refused.
func (d Decision) Failed(g Gate) bool {
	for _, f := range d.Failures {
		if f.Gate == g {
			return true
		}
	}
	return false
}

// FailedGates lists the gates that refused, for diagnostics.
func (d Decision) FailedGates() []Gate {
	out := make([]Gate, 0, len(d.Failures))
	for _, f := range d.Failures {
		out = append(out, f.Gate)
	}
	return out
}

// Decide applies every gate to next and reports whether it may replace prev.
//
// prev is nil when the source has delivered nothing yet; the relative gates
// then have nothing to measure and pass, while the absolute ones still apply.
//
// Every gate is evaluated even after one has failed. A snapshot refused for
// three reasons should say three, because the operator deciding whether the
// publisher is broken or hostile needs the shape of the failure, not its
// first cause.
func Decide(prev *Snapshot, next Snapshot, limits Limits, now time.Time) Decision {
	var fail []Failure
	add := func(g Gate, format string, args ...any) {
		fail = append(fail, Failure{Gate: g, Detail: fmt.Sprintf(format, args...)})
	}

	if limits.unset() {
		add(GateLimitsUnset, "one or more gate limits are zero; an unset gate is not an unbounded one")
	}

	if !next.Verified {
		add(GateIntegrity, "the snapshot was not verified against the publisher's key")
	}

	switch {
	case next.IssuedAt.IsZero():
		add(GateFreshness, "the snapshot carries no issue time")
	case limits.MaxAge > 0 && now.Sub(next.IssuedAt) > limits.MaxAge:
		add(GateFreshness, "issued %s ago, limit %s", now.Sub(next.IssuedAt).Round(time.Minute), limits.MaxAge)
	case limits.ClockSkew > 0 && next.IssuedAt.Sub(now) > limits.ClockSkew:
		add(GateFreshness, "issued %s in the future, skew tolerance %s", next.IssuedAt.Sub(now).Round(time.Minute), limits.ClockSkew)
	}

	nextCount := next.count()
	if nextCount < limits.MinEntries {
		add(GateMinEntries, "%d entries, floor %d", nextCount, limits.MinEntries)
	}

	if prev != nil {
		if !next.IssuedAt.After(prev.IssuedAt) {
			add(GateNotRegressive, "issued no later than the snapshot in effect")
		}

		prevCount := prev.count()
		if prevCount > 0 {
			if lost := prevCount - nextCount; lost > 0 {
				if f := float64(lost) / float64(prevCount); f > limits.MaxShrinkFraction {
					add(GateMaxShrink, "lost %d of %d entries (%.0f%%), limit %.0f%%",
						lost, prevCount, f*100, limits.MaxShrinkFraction*100)
				}
			}
			if float64(nextCount) > float64(prevCount)*limits.MaxGrowthFactor {
				add(GateMaxGrowth, "%d entries against %d in effect (×%.1f), limit ×%.1f",
					nextCount, prevCount, float64(nextCount)/float64(prevCount), limits.MaxGrowthFactor)
			}

			// Withdrawal is measured over identities, not counts.
			ns := next.set()
			withdrawn := 0
			for e := range prev.set() {
				if _, still := ns[e]; !still {
					withdrawn++
				}
			}
			if f := float64(withdrawn) / float64(prevCount); f > limits.MaxWithdrawalFraction {
				add(GateMaxWithdrawal, "%d of %d entries in effect are absent (%.0f%%), limit %.0f%%",
					withdrawn, prevCount, f*100, limits.MaxWithdrawalFraction*100)
			}
		}
	}

	if len(fail) > 0 {
		// Quarantine. Nothing is withdrawn: what was in effect stays in
		// effect, and when nothing was, nothing becomes so.
		d := Decision{Quarantined: true, Failures: fail}
		if prev != nil {
			d.InEffect = *prev
		} else {
			d.InEffect = Snapshot{SourceID: next.SourceID}
		}
		return d
	}
	return Decision{Applied: true, InEffect: next}
}
