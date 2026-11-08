// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"fmt"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/safetext"
)

// # WHAT KEEPS A SCAMWALL BLOCK ALIVE, AND WHAT ENDS IT
//
// Four rules, and the interesting part is which of them a FREEZE suspends.
//
// A freeze exists to protect against the ABSENCE of evidence. When the supply
// is degraded, "nobody is saying this is bad any more" stops meaning what it
// usually means, so a block is not allowed to lapse merely for going quiet.
// It is NOT a reason to ignore evidence that did arrive, and it is never a
// reason to override the household. So:
//
//	exception   — always removes. The household said so.       Freeze-proof.
//	withdrawn   — always removes. A retraction ARRIVED.        Freeze-proof.
//	lifetime    — removes unless the freeze holds it.          Suspended by hold.
//	justified   — keeps.
//
// The order is fixed so that the recorded reason is stable: an operator
// reading two runs over the same facts sees the same reason both times.

// Retention reasons.
const (
	// ReasonRetentionExcepted — the household excepted the domain. Their own
	// statement outranks every source, which is this tree's existing rule for
	// ReasonUserException, and a freeze does not suspend it.
	ReasonRetentionExcepted Reason = "retention_household_exception"
	// ReasonRetentionWithdrawn — the evidence that justified the block was
	// retracted upstream. ORDER 9 §1 harm 2 is that a retracted report keeps
	// a block alive, so this removes through a freeze.
	ReasonRetentionWithdrawn Reason = "retention_evidence_withdrawn"
	// ReasonRetentionExpired — past block_lifetime without re-justification.
	ReasonRetentionExpired Reason = "retention_lifetime_expired"
	// ReasonRetentionFrozen — it would have expired and the household chose
	// hold_existing_blocks for a source outage.
	ReasonRetentionFrozen Reason = "retention_frozen_by_source_outage"
	// ReasonRetentionJustified — live evidence still supports it.
	ReasonRetentionJustified Reason = "retention_still_justified"
	// ReasonRetentionLifetimeUnset — no block_lifetime was given. Nothing
	// expires; an unset limit is not a zero one.
	ReasonRetentionLifetimeUnset Reason = "retention_lifetime_unset"
)

// RetentionAction is what retention would do about one owned entry.
type RetentionAction string

// The two actions. There is no third: an entry is either kept or proposed for
// removal, and "frozen" is a REASON for keeping rather than a state of its
// own — a reader who has to distinguish three actions gets the freeze wrong.
const (
	RetentionKeep   RetentionAction = "keep"
	RetentionRemove RetentionAction = "remove"
)

// OwnedEntry is one block ScamWall placed, as an ownership ledger records it.
type OwnedEntry struct {
	Canonical string
	// AddedAt is when ScamWall placed it.
	AddedAt time.Time
	// LastJustifiedAt is when live evidence last supported it.
	//
	// Lifetime runs from here and not from AddedAt. A domain that keeps being
	// reported should not be unblocked on its birthday.
	LastJustifiedAt time.Time
}

// RetentionInput is one retention pass.
type RetentionInput struct {
	// Owned is the ownership ledger. NOTHING outside it can become a plan
	// item: an exception or a withdrawal naming a domain ScamWall does not
	// own must not produce a removal, or ScamWall deletes somebody else's
	// entry on the strength of its own opinion.
	Owned []OwnedEntry
	// StillJustified, Withdrawn and Excepted are sets over canonical names.
	// Membership outside Owned is ignored, deliberately.
	StillJustified map[string]bool
	Withdrawn      map[string]bool
	Excepted       map[string]bool
	// Lifetime is automatic.block_lifetime. Zero means the household has not
	// set one and nothing expires.
	Lifetime     time.Duration
	SourceOutage bool
	OnOutage     OutageBehaviour
	Now          time.Time
}

// RetentionOutcome is what retention decided about one owned entry.
type RetentionOutcome struct {
	Canonical   string          `json:"canonical"`
	Action      RetentionAction `json:"action"`
	Reason      Reason          `json:"reason"`
	Explanation string          `json:"explanation"`
}

// RetentionDecision is the whole pass.
type RetentionDecision struct {
	Outcomes []RetentionOutcome `json:"outcomes"`
	// Removals are the canonical names in RetentionRemove, sorted. They are
	// the INPUT to AssessRemovals, which applies the caps and the
	// abnormal-run rule; retention decides what has stopped being justified,
	// the caps decide how much of that one run may act on.
	Removals []string `json:"removals"`
	// Frozen records that at least one entry was kept only because of the
	// outage behaviour. A plan that silently keeps blocks during an outage
	// and one that has nothing to remove look identical without it.
	Frozen bool `json:"frozen,omitempty"`
}

// AssessRetention applies the four rules to every owned entry.
func AssessRetention(in RetentionInput) RetentionDecision {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	freeze := in.SourceOutage && in.OnOutage == OutageHold

	var d RetentionDecision
	// Owned is walked in a stable order so two runs over the same ledger
	// produce the same document.
	entries := append([]OwnedEntry(nil), in.Owned...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Canonical < entries[j].Canonical })

	for _, e := range entries {
		o := RetentionOutcome{Canonical: e.Canonical}
		switch {
		case in.Excepted[e.Canonical]:
			o.Action, o.Reason = RetentionRemove, ReasonRetentionExcepted
			o.Explanation = "the household excepted this domain; their own statement outranks every " +
				"source, and a source outage does not suspend it"

		case in.Withdrawn[e.Canonical]:
			o.Action, o.Reason = RetentionRemove, ReasonRetentionWithdrawn
			o.Explanation = "the evidence that justified this block was retracted upstream. A freeze " +
				"protects against evidence that stopped arriving; a retraction is evidence that arrived"

		case in.StillJustified[e.Canonical]:
			o.Action, o.Reason = RetentionKeep, ReasonRetentionJustified
			o.Explanation = "live evidence still supports it"

		case in.Lifetime <= 0:
			// An unset lifetime is not a zero one. The same rule as C-10's
			// limits_unset, and it fails the same way if it is missed:
			// silently expiring every block ScamWall holds.
			o.Action, o.Reason = RetentionKeep, ReasonRetentionLifetimeUnset
			o.Explanation = "automatic.block_lifetime is not set, so nothing expires. An unset limit " +
				"is not a zero one"

		case now.Sub(e.LastJustifiedAt) <= in.Lifetime:
			o.Action, o.Reason = RetentionKeep, ReasonRetentionJustified
			o.Explanation = safetext.Clip(fmt.Sprintf(
				"last justified %s ago, inside a block_lifetime of %s",
				now.Sub(e.LastJustifiedAt).Round(time.Hour), in.Lifetime), MaxExplanation)

		case freeze:
			o.Action, o.Reason = RetentionKeep, ReasonRetentionFrozen
			o.Explanation = safetext.Clip(fmt.Sprintf(
				"past its block_lifetime of %s, and the household chose %s for a source outage. "+
					"Nothing is unblocked while the evidence supply is degraded",
				in.Lifetime, OutageHold), MaxExplanation)
			d.Frozen = true

		default:
			o.Action, o.Reason = RetentionRemove, ReasonRetentionExpired
			o.Explanation = safetext.Clip(fmt.Sprintf(
				"last justified %s ago, past a block_lifetime of %s",
				now.Sub(e.LastJustifiedAt).Round(time.Hour), in.Lifetime), MaxExplanation)
		}

		d.Outcomes = append(d.Outcomes, o)
		if o.Action == RetentionRemove {
			d.Removals = append(d.Removals, e.Canonical)
		}
	}
	sort.Strings(d.Removals)
	return d
}
