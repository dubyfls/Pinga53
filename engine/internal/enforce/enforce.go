// SPDX-License-Identifier: AGPL-3.0-only

// Package enforce is the boundary between deciding and doing.
//
// # WHY A BOUNDARY, WHEN THERE IS ONLY ONE THING ON EACH SIDE
//
// Not for pluggability. There is exactly one decider and, as of ORDER 11, two
// things that consume its output, and an interface built for a third that
// nobody has asked for would be the speculative abstraction this repository
// keeps out.
//
// It exists because the two consumers are asymmetric in a way that matters.
// The shadow path READS a household's appliance and reports what it would ask
// of it. The RPZ path WRITES a file that a resolver will act on. Those are
// different powers, and before this package the only thing distinguishing
// them was which function a command happened to call. A shared vocabulary for
// "here is the decided plan" makes the asymmetry explicit: both adapters take
// the same Plan, and the Result says plainly which of them changed anything.
//
// # WHAT AN ADAPTER MAY NOT DO
//
// Decide. An adapter receives a Plan that retention (C-21) and the caps
// (C-20) have already settled, and its only remaining freedom is to REFUSE —
// to write less than it was given, never more. Every Outcome below except
// OutcomeApplied is a refusal of some kind, and there is deliberately no
// outcome meaning "applied something that was not in the plan".
//
// # THIS PACKAGE CHANGES NO EXISTING BEHAVIOUR
//
// It adds a vocabulary and one read-only adapter over the shadow path.
// `cmd/scamwall/shadow.go` is not modified by the order item that introduced
// it, so the shadow command's output is the same bytes it was before —
// asserted in enforce_test.go against a golden over the deterministic part of
// a shadow plan.
package enforce

import (
	"fmt"
	"sort"

	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/shadow"
)

// Plan is a decided plan, in the only vocabulary an adapter sees.
//
// Four fields, because a run that added nothing has four different reasons it
// might have done so and an operator acts differently on each. Collapsing
// Deferred and Review into one list would merge "waiting for budget" with
// "waiting for a person", which are not the same wait.
type Plan struct {
	// Adds are canonical names to start blocking. Sorted.
	Adds []string
	// Removals are canonical names to stop blocking. Sorted.
	Removals []string
	// Deferred qualified and did not fit inside this run's caps. Rationing,
	// not a drop: the next run recomputes it.
	Deferred []proposal.DeferredItem
	// Review needs a person before anything happens. Distinct from Deferred
	// because no amount of waiting resolves it.
	Review []ReviewItem
	// Standing is every host a BLOCK decision covers as of this run: what the
	// resolver's view should CONTAIN once the plan is applied, not the delta.
	// Sorted.
	//
	// Present because the two adapters need different things and a Plan that
	// carried only the delta would force the whole-artefact one to guess. An
	// adapter that ASKS AN APPLIANCE for changes needs Adds and Removals, and
	// the appliance keeps the rest. An adapter that PRODUCES A WHOLE FILE — a
	// zone — has to write every standing entry every time, because a file
	// containing only this run's additions is a file that unblocks everything
	// else. Reconstructing the set by replaying deltas onto whatever is
	// already on disk would make the artefact a function of its own history,
	// and a zone edited or restored out of band would then never converge.
	//
	// ShadowAdapter ignores it. It is not a second opinion about Adds and
	// Removals: an adapter that finds Standing disagreeing with them is
	// looking at a state its own artefact drifted from, which is a fact worth
	// reporting and not one to reconcile silently.
	Standing []StandingEntry
}

// StandingEntry is one host the plan says should be blocked, and the decision
// that put it there.
type StandingEntry struct {
	// Canonical is the canonical name. EMPTY where C-09 withholds it: an
	// adapter that cannot name a host cannot enforce on it, and must say so
	// rather than write an opaque identifier a resolver would treat as a name.
	Canonical string `json:"canonical"`
	// Digest is the decision digest this block stands on. Opaque, and short
	// by the time it reaches an artefact: it names no source, URL or evidence
	// text, and exists so an operator looking at one entry can find the
	// decision behind it without the artefact carrying the decision.
	Digest string `json:"digest,omitempty"`
}

// ReviewItem is one thing an unattended run declined to do by itself.
type ReviewItem struct {
	Canonical   string `json:"canonical"`
	Reason      string `json:"reason"`
	Explanation string `json:"explanation"`
}

// Outcome is what an adapter did. Closed.
type Outcome string

// The outcomes. Every one but OutcomeApplied is a refusal of some kind, and
// there is no outcome meaning "did something the plan did not say".
const (
	// OutcomeApplied — the adapter changed the thing it controls.
	OutcomeApplied Outcome = "applied"
	// OutcomeNoChange — the plan and the current state already agree. A
	// success, and distinct from a refusal: nothing was wrong, there was
	// simply nothing to do.
	OutcomeNoChange Outcome = "no_change"
	// OutcomeFrozen — the inputs were not trustworthy enough to act on, so
	// the previous state was left exactly as it was. The evidence supply is
	// degraded, or the allowlist snapshot could not be read.
	OutcomeFrozen Outcome = "frozen"
	// OutcomeRefused — the plan was well-formed and the adapter declined it
	// on its own safety rules: a size cap, an empty result nobody asked for.
	OutcomeRefused Outcome = "refused"
	// OutcomeReview — the change was large or surprising enough that a person
	// has to look. Nothing was written.
	OutcomeReview Outcome = "routed_to_review"
	// OutcomeReported — the adapter cannot change anything by construction
	// and has reported instead. The shadow path's only outcome.
	OutcomeReported Outcome = "reported_only"
)

// Changed reports whether this outcome means something was actually altered.
//
// One place, so that a caller counting successes cannot quietly include a
// freeze. OutcomeNoChange is a success and is NOT a change: the exit status
// and the question "did the resolver's view move" have different answers.
func (o Outcome) Changed() bool { return o == OutcomeApplied }

// Result is what one adapter did, and what it declined.
type Result struct {
	// Adapter names which one. Present so a result read later does not
	// depend on knowing which command produced it.
	Adapter string  `json:"adapter"`
	Outcome Outcome `json:"outcome"`
	// Reason is why, in the adapter's own words. REQUIRED for every outcome
	// but OutcomeApplied and OutcomeNoChange: a refusal nobody can read is a
	// silent failure with a status code.
	Reason string `json:"reason,omitempty"`
	// Adds and Removals are what the adapter actually did, which is not
	// necessarily what the plan asked: a frozen or refused run reports zero
	// and keeps the plan's own counts out of it.
	Adds     int `json:"adds"`
	Removals int `json:"removals"`
	// Entries is the size of the resulting state, where the adapter has one.
	Entries int `json:"entries,omitempty"`
	// Review is what this adapter sent to a person. Carried on the result
	// rather than left in the plan, because an adapter can add to it: the
	// allowlist snapshot is read at enforcement time and excludes hosts the
	// decider had no way to know about.
	Review []ReviewItem `json:"review,omitempty"`
	// Artifact identifies what was produced, where anything was: a path, a
	// digest, a serial. Empty for an adapter that produces nothing.
	Artifact string `json:"artifact,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Serial   string `json:"serial,omitempty"`
}

// Adapter turns a decided plan into an enforcement result.
//
// Enforce must be safe to call on a plan it will refuse: an adapter that
// half-applies a plan before discovering it should not have is worse than one
// that refuses late, so every implementation in this tree decides first and
// writes once.
type Adapter interface {
	// Name is the adapter's own name, for the Result and for operator output.
	Name() string
	// Enforce applies as much of the plan as the adapter's own rules allow,
	// and reports exactly what it did.
	Enforce(Plan) (Result, error)
}

// ShadowAdapter reports what the Pi-hole shadow path would request, and
// requests nothing.
//
// # IT SATISFIES THE INTERFACE WITHOUT ACQUIRING THE POWER
//
// The whole point of the shadow path is that it cannot write: internal/shadow
// imports no HTTP client and no Pi-hole adapter, and policy.EnforcementCompiledIn
// is false. This adapter does not change that. It holds a finished
// shadow.Plan — a description that has already been computed — and answers
// Enforce by counting it. There is no code path from here to the appliance,
// and OutcomeReported is the only outcome it can return.
type ShadowAdapter struct {
	// Plan is the comparison this adapter reports on. A nil Plan is a run
	// that produced no comparison, which is reported as such rather than as
	// an empty appliance.
	Plan *shadow.Plan
}

// Name is the adapter's name.
func (ShadowAdapter) Name() string { return "shadow" }

// Enforce reports, and changes nothing.
//
// The plan argument is deliberately ignored for the counts: this adapter
// reports what the SHADOW COMPARISON found against the real appliance, which
// is a different and more specific statement than what the decider proposed.
// A host the decider wanted to add and the appliance already blocks is not an
// addition, and reporting the decider's number here would overstate the work.
func (a ShadowAdapter) Enforce(_ Plan) (Result, error) {
	r := Result{Adapter: a.Name(), Outcome: OutcomeReported}
	if a.Plan == nil {
		r.Reason = "no shadow comparison was produced by this run, so there is nothing to " +
			"report. This is not a statement that the appliance holds nothing"
		return r, nil
	}
	counts := a.Plan.Counts()
	r.Adds = counts[shadow.KindAdd]
	r.Removals = counts[shadow.KindRemove]
	r.Entries = a.Plan.Binding.ObservedEntries
	r.Digest = a.Plan.Binding.ObservedStateDigest
	r.Reason = "this adapter describes a change and cannot make one: internal/shadow imports no " +
		"HTTP client and no Pi-hole adapter, and enforcement is not compiled into this build"

	for _, c := range a.Plan.Changes {
		if c.Kind == shadow.KindReview {
			r.Review = append(r.Review, ReviewItem{
				Canonical: c.Domain, Reason: string(c.Kind), Explanation: c.Explanation,
			})
		}
	}
	sort.Slice(r.Review, func(i, j int) bool { return r.Review[i].Canonical < r.Review[j].Canonical })
	return r, nil
}

// FromShadow expresses a finished shadow comparison in the Plan vocabulary.
//
// Used to check the two vocabularies against each other rather than to drive
// anything: if a shadow plan cannot be said in Plan's terms, Plan is missing a
// case that a real appliance produces.
func FromShadow(p *shadow.Plan) Plan {
	var out Plan
	if p == nil {
		return out
	}
	for _, c := range p.Changes {
		switch c.Kind {
		case shadow.KindAdd:
			out.Adds = append(out.Adds, c.Domain)
		case shadow.KindRemove:
			out.Removals = append(out.Removals, c.Domain)
		case shadow.KindReview, shadow.KindAllowNotEvaluable:
			out.Review = append(out.Review, ReviewItem{
				Canonical: c.Domain, Reason: string(c.Kind), Explanation: c.Explanation,
			})
		}
	}
	sort.Strings(out.Adds)
	sort.Strings(out.Removals)
	sort.Slice(out.Review, func(i, j int) bool { return out.Review[i].Canonical < out.Review[j].Canonical })
	return out
}

// Describe renders a result as one operator-readable line plus its reason.
//
// Shared so that two commands reporting the same outcome word it the same
// way. A reason is printed whenever there is one, including on success: an
// adapter that wrote nothing because nothing needed writing should say so.
func Describe(r Result) string {
	s := fmt.Sprintf("%s: %s — %d addition(s), %d removal(s)", r.Adapter, r.Outcome, r.Adds, r.Removals)
	if r.Entries > 0 {
		s += fmt.Sprintf(", %d entr%s standing", r.Entries, plural(r.Entries))
	}
	if len(r.Review) > 0 {
		s += fmt.Sprintf(", %d held for review", len(r.Review))
	}
	if r.Reason != "" {
		s += "\n  " + r.Reason
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
