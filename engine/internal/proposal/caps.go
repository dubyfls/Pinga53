// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"fmt"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/safetext"
)

// # THREE STATEMENTS THAT ONE "MAX ADDITIONS" NUMBER IS MISTAKEN FOR
//
// A per-run cap is an ABNORMALITY SIGNAL. One batch far larger than usual
// means something changed upstream, and applying the first N of it vets none
// of it. This build holds the whole run, and that is not weakened here.
//
// A per-day cap is a RATION. Today's budget is spent; the excess waits for
// tomorrow. Nothing is abnormal and nothing is dropped.
//
// The abnormal-removal rule is the MASS-UNBLOCKING GUARD, and it is measured
// against what ScamWall owns rather than against a fixed count: twelve
// removals is routine for a large ledger and catastrophic for a small one.

// AbnormalRemovalFraction is the share of ScamWall-owned entries whose
// removal in one run is treated as abnormal rather than as retention.
//
// Above it the run is held whole. A removal is an unblock, and a run that
// unblocks a quarter of everything ScamWall is holding is either a data
// problem or an attack; in both cases the right answer is to keep the blocks
// and tell someone.
const AbnormalRemovalFraction = 0.25

// Deferral and abnormality reasons.
const (
	// ReasonDeferredDailyCap — the household's daily addition budget is
	// spent. The indicator still qualifies and is carried forward.
	ReasonDeferredDailyCap Reason = "deferred_daily_addition_cap"
	// ReasonDeferredDailyRemovalCap — the same, for removals.
	ReasonDeferredDailyRemovalCap Reason = "deferred_daily_removal_cap"
	// ReasonDeferredRunRemovalCap — this run's removal budget is spent.
	ReasonDeferredRunRemovalCap Reason = "deferred_per_run_removal_cap"
	// ReasonAbnormalRemovalRun — the run would remove an abnormal share of
	// what ScamWall owns. Held whole; see AbnormalRemovalFraction.
	ReasonAbnormalRemovalRun Reason = "abnormal_removal_run"
)

// DayLedger is what has already been done today, across runs.
//
// Known is not decoration. A zero DayLedger is "nobody looked", which is a
// different fact from "nothing has happened today", and enforcing a daily cap
// against an unread journal would be enforcement in name only — it would
// silently treat every run as the day's first. While Known is false the daily
// caps are reported as NOT enforced, exactly as they were before this control
// landed.
type DayLedger struct {
	Known bool
	// Day is the UTC day this ledger covers, for the caller's own checking.
	Day time.Time
	// AutomaticAdditions is what unattended runs added today.
	AutomaticAdditions int
	// ShadowAdditions is what shadow runs PROPOSED today.
	//
	// They count. In this build the only path from a decision to the
	// appliance is an operator applying a shadow plan, so a shadow addition
	// is an addition; a ledger counting only what an enforcing run applied
	// lets the daily cap be walked past by running shadow repeatedly.
	ShadowAdditions int
	// Removals is what has been removed today, by any path.
	Removals int
}

// Additions is the day's addition total. See ShadowAdditions.
func (l DayLedger) Additions() int { return l.AutomaticAdditions + l.ShadowAdditions }

// DeferredItem is something that qualified and is waiting, not something that
// was dropped.
type DeferredItem struct {
	Canonical string `json:"canonical"`
	// NewestEvidence is the recency the queue was ordered by, zero when the
	// caller recorded none.
	NewestEvidence time.Time `json:"newest_evidence,omitempty"`
	Reason         Reason    `json:"reason"`
	Explanation    string    `json:"explanation"`
}

// orderByRecency sorts canonical names newest evidence first, breaking ties
// by name so the queue is deterministic.
//
// A name whose recency nobody recorded sorts LAST. Unknown recency must not
// win a cap by accident, and "the zero time is the oldest time" gets that
// right only if the comparison is written the way round it is here.
func orderByRecency(names []string, newest map[string]time.Time) []string {
	out := append([]string(nil), names...)
	sort.SliceStable(out, func(i, j int) bool {
		ti, oki := newest[out[i]]
		tj, okj := newest[out[j]]
		switch {
		case oki != okj:
			return oki
		case !ti.Equal(tj):
			return ti.After(tj)
		default:
			return out[i] < out[j]
		}
	})
	return out
}

// applyDailyAdditionCap selects which of the qualifying names fit in what is
// left of today's budget, and defers the rest.
//
// Selection is newest-evidence-first; the returned selection is re-sorted by
// name, because the plan's Blocks field is an output contract that readers
// have always been able to rely on being sorted. The queue ORDER is expressed
// in Deferred, where it is new and where the next run reads it.
func applyDailyAdditionCap(blocks []string, in AutoInputs, capPerDay int) (kept []string, deferred []DeferredItem) {
	remaining := capPerDay - in.Today.Additions()
	if remaining < 0 {
		remaining = 0
	}
	ordered := orderByRecency(blocks, in.NewestEvidence)
	if len(ordered) <= remaining {
		return blocks, nil
	}

	kept = append([]string(nil), ordered[:remaining]...)
	sort.Strings(kept)

	explanation := safetext.Clip(fmt.Sprintf(
		"automatic.max_additions_per_day is %d and %d addition(s) have already been made or proposed "+
			"today (%d unattended, %d by shadow runs). This indicator still qualifies and is carried "+
			"forward to the next run; it is not dropped",
		capPerDay, in.Today.Additions(), in.Today.AutomaticAdditions, in.Today.ShadowAdditions),
		MaxExplanation)

	for _, n := range ordered[remaining:] {
		deferred = append(deferred, DeferredItem{
			Canonical:      n,
			NewestEvidence: in.NewestEvidence[n],
			Reason:         ReasonDeferredDailyCap,
			Explanation:    explanation,
		})
	}
	return kept, deferred
}

// RemovalInput is one run's removal question.
type RemovalInput struct {
	// Proposed are the ScamWall-owned entries retention says should go.
	Proposed []string
	// OwnedCount is how many entries ScamWall owns in total. The abnormal
	// rule is a fraction of this, not a fixed count.
	OwnedCount int
	MaxPerRun  int
	MaxPerDay  int
	Today      DayLedger
	// NewestEvidence orders the queue, as for additions.
	NewestEvidence map[string]time.Time
}

// RemovalDecision is what a run would remove, and what it would not.
type RemovalDecision struct {
	Removals []string       `json:"removals"`
	Deferred []DeferredItem `json:"deferred,omitempty"`
	// Held is the abnormal-run rule firing. Distinct from a deferral: a
	// deferral is rationing and resumes tomorrow, a hold says this run looked
	// wrong and wants a person.
	Held        bool   `json:"held,omitempty"`
	Reason      Reason `json:"reason,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}

// AssessRemovals applies the abnormal-run rule and then the caps.
//
// Order matters. Abnormality is judged on what the run WANTED to do, not on
// what survived the caps: a run proposing to unblock half of everything is
// abnormal even if a per-run cap would have trimmed it to something that
// looks ordinary.
func AssessRemovals(in RemovalInput) RemovalDecision {
	if len(in.Proposed) == 0 {
		return RemovalDecision{}
	}

	// An ownership ledger holding nothing cannot justify a removal, and the
	// fraction is undefined. Refusing is not pedantry: it is the state a
	// caller is in when the ledger failed to load, and that is exactly when
	// "remove everything" must not be the answer.
	if in.OwnedCount <= 0 {
		return heldRemoval(in, safetext.Clip(fmt.Sprintf(
			"%d removal(s) were proposed while the ownership ledger holds nothing. A removal ScamWall "+
				"cannot show it owns is not a removal it may make", len(in.Proposed)), MaxExplanation))
	}

	if f := float64(len(in.Proposed)) / float64(in.OwnedCount); f > AbnormalRemovalFraction {
		return heldRemoval(in, safetext.Clip(fmt.Sprintf(
			"this run would remove %d of the %d entries ScamWall owns (%.0f%%), above the abnormal-run "+
				"threshold of %.0f%%. A removal is an unblock; the whole run is held and the blocks stay",
			len(in.Proposed), in.OwnedCount, f*100, AbnormalRemovalFraction*100), MaxExplanation))
	}

	ordered := orderByRecency(in.Proposed, in.NewestEvidence)

	allowed := in.MaxPerRun
	reason := ReasonDeferredRunRemovalCap
	if in.Today.Known {
		if left := in.MaxPerDay - in.Today.Removals; left < allowed {
			allowed, reason = left, ReasonDeferredDailyRemovalCap
		}
	} else if in.MaxPerDay < allowed {
		// The daily ledger was not read. The daily number is still a ceiling
		// on what one run may do — treating it as absent would make an
		// unread journal MORE permissive than a read one.
		allowed, reason = in.MaxPerDay, ReasonDeferredDailyRemovalCap
	}
	if allowed < 0 {
		allowed = 0
	}
	if len(ordered) <= allowed {
		return RemovalDecision{Removals: sortedCopy(ordered)}
	}

	d := RemovalDecision{Removals: sortedCopy(ordered[:allowed])}
	explanation := safetext.Clip(fmt.Sprintf(
		"this run's removal budget allows %d more; the rest are carried forward and are not dropped", allowed),
		MaxExplanation)
	for _, n := range ordered[allowed:] {
		d.Deferred = append(d.Deferred, DeferredItem{
			Canonical:      n,
			NewestEvidence: in.NewestEvidence[n],
			Reason:         reason,
			Explanation:    explanation,
		})
	}
	return d
}

func heldRemoval(in RemovalInput, explanation string) RemovalDecision {
	d := RemovalDecision{Held: true, Reason: ReasonAbnormalRemovalRun, Explanation: explanation}
	for _, n := range orderByRecency(in.Proposed, in.NewestEvidence) {
		d.Deferred = append(d.Deferred, DeferredItem{
			Canonical:      n,
			NewestEvidence: in.NewestEvidence[n],
			Reason:         ReasonAbnormalRemovalRun,
			Explanation:    explanation,
		})
	}
	return d
}
