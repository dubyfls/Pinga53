// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/safetext"
)

// # THE AUTOMATIC BLOCKING CONTRACT
//
// The product plan this order works from says ScamWall maintains its own
// blocks in the household's Pi-hole without asking per domain. That is a
// larger grant than "propose", and the difference is not a flag: it is a set
// of numbers the household has to have decided before anything runs
// unattended. This file is the shape of that decision, and nothing else — no
// build in this repository can apply one, and Qualify below is a statement
// about what WOULD be requested.
//
// # WHY EVERY FIELD IS A POINTER AND NOTHING HAS A DEFAULT
//
// A default here would be ScamWall choosing, on the household's behalf, how
// many of their domains it may block before a person looks at it. Every
// plausible default is either so tight it never runs or so loose it is not a
// limit, and whichever were shipped would be quoted back as a recommendation.
//
// So a missing value is UNRESOLVED, it is named in the output, and while any
// required value is unresolved the answer for every indicator that would
// otherwise have qualified is `abstain` — never `automatic_block`, and never
// a silently substituted number. Unresolved is not an error: the rest of the
// system is expected to keep running, and this order's read-only integration
// runs with the whole block open.

// AutomaticState is how far the household's automatic contract has got.
type AutomaticState string

// The states, in the order a household passes through them.
const (
	// AutomaticAbsent — the policy has no `automatic` block at all. The
	// household has not started. Distinct from Unresolved: one is "not asked
	// for", the other is "asked for and not finished", and an operator
	// chasing a missing block needs to know which.
	AutomaticAbsent AutomaticState = "not_configured"
	// AutomaticUnresolved — the block is present and at least one required
	// value is missing.
	AutomaticUnresolved AutomaticState = "unresolved"
	// AutomaticDisabled — every value is set and `enabled` is false. A
	// complete contract that the household has switched off, which is a
	// different sentence from an incomplete one.
	AutomaticDisabled AutomaticState = "disabled"
	// AutomaticActive — complete and switched on.
	AutomaticActive AutomaticState = "active"
)

// OutageBehaviour is what happens to existing ScamWall blocks when the
// evidence that justified them stops arriving.
//
// There is no third option and no default. A source outage is the case where
// doing nothing and doing something are both defensible, and the household is
// the only party that can say which risk they prefer: keeping a block whose
// justification can no longer be checked, or dropping protection because a
// provider had a bad afternoon.
type OutageBehaviour string

// The outage vocabulary. Closed.
const (
	// OutageHold keeps existing ScamWall blocks in place and proposes no new
	// ones. Fails towards protection and towards staleness.
	OutageHold OutageBehaviour = "hold_existing_blocks"
	// OutageExpire lets existing blocks lapse at their lifetime. Fails
	// towards the household's own traffic and away from unverifiable state.
	OutageExpire OutageBehaviour = "expire_existing_blocks"
)

// Valid reports whether o is one of the two behaviours.
func (o OutageBehaviour) Valid() bool { return o == OutageHold || o == OutageExpire }

// Automatic is the household's unattended-blocking contract.
//
// Every field is required. `Unresolved` names the ones that are not set, and
// that list is what a household fills in.
type Automatic struct {
	// Enabled is the household saying the contract may run unattended.
	// Required even when false, because "we decided not yet" and "we have not
	// decided" are different states and only one of them is finished.
	Enabled *bool `json:"enabled"`

	// MaxAdditionsPerRun and MaxRemovalsPerRun bound one run. A run that
	// would exceed one of them is held ENTIRELY rather than truncated to the
	// limit: a limit reached is the signal that something upstream changed,
	// and blocking the first N of an abnormal batch is the worst of both.
	MaxAdditionsPerRun *int `json:"max_additions_per_run"`
	MaxRemovalsPerRun  *int `json:"max_removals_per_run"`

	// MaxAdditionsPerDay and MaxRemovalsPerDay bound a day across runs.
	//
	// DECLARED HERE AND NOT ENFORCED BY THIS BUILD. Enforcing them needs a
	// journal of what previous runs did, which this order deliberately does
	// not build, and AutoPlan.NotEnforced says so in the output of every run
	// rather than leaving a reader to assume the number is doing something.
	MaxAdditionsPerDay *int `json:"max_additions_per_day"`
	MaxRemovalsPerDay  *int `json:"max_removals_per_day"`

	// BlockLifetime is how long one ScamWall block survives without being
	// re-justified, as a Go duration string.
	//
	// DECLARED HERE AND NOT ENFORCED BY THIS BUILD, for the same reason: a
	// lifetime is measured from when a block was added, and nothing records
	// that yet.
	BlockLifetime *string `json:"block_lifetime"`

	// OnSourceOutage is the OutageBehaviour. See its documentation.
	OnSourceOutage *OutageBehaviour `json:"on_source_outage"`

	// AlertChannel is where an unattended run reports what it did. Free text
	// the household writes; this build never contacts it. Required because an
	// automatic system nobody hears from is an automatic system nobody can
	// correct.
	AlertChannel *string `json:"alert_channel"`

	// EmergencyDisablePath is a path whose EXISTENCE stops automatic
	// blocking. A file rather than a flag in this document: the household
	// needs a way to stop it that does not involve editing a JSON file
	// correctly under pressure.
	//
	// The path is stated here; whether the file exists is decided by the
	// caller and passed to Qualify. This package opens nothing.
	EmergencyDisablePath *string `json:"emergency_disable_path"`
}

// automaticRequired names every required field, in the order a household is
// asked for them. The strings are the JSON names, because that is what the
// household edits.
var automaticRequired = []string{
	"automatic.enabled",
	"automatic.max_additions_per_run",
	"automatic.max_removals_per_run",
	"automatic.max_additions_per_day",
	"automatic.max_removals_per_day",
	"automatic.block_lifetime",
	"automatic.on_source_outage",
	"automatic.alert_channel",
	"automatic.emergency_disable_path",
}

// notEnforcedByThisBuild are values the contract REQUIRES the household to
// state and that this build records without acting on. Carried in every plan.
var notEnforcedByThisBuild = []string{
	"automatic.max_removals_per_day: this build proposes no removals, because it keeps no ownership ledger, so the removal caps have nothing to bound. See proposal.AssessRemovals for the rule that will apply when it does.",
	"automatic.block_lifetime: a lifetime is measured from when a block was added, and this build has no ownership ledger recording that.",
	"automatic.alert_channel: recorded and never contacted. This build performs no outbound notification of any kind.",
	"automatic.emergency_disable_path: the path is the household's; whether the file exists is decided by the caller and passed in. This package opens nothing.",
}

// notEnforced is what this build records without acting on, for one run.
//
// The daily addition cap moved from "never enforced" to "enforced when the
// caller read the journal", so the notice is computed per run rather than
// being a constant. A plan must never say a limit is unenforced while it is
// enforcing it, and must never stop saying so while it is not: an unread
// journal makes every run look like the day's first, which is enforcement in
// name only.
func notEnforced(in AutoInputs) []string {
	out := append([]string(nil), notEnforcedByThisBuild...)
	if !in.Today.Known {
		out = append(out, "automatic.max_additions_per_day: enforced only when a run is given the day's journal. "+
			"This run was not, so the cap was applied against a day assumed empty and has bounded this run alone.")
	}
	return out
}

// unresolvedFields names the required values this contract has not set.
func (a *Automatic) unresolvedFields() []string {
	if a == nil {
		return append([]string(nil), automaticRequired...)
	}
	var out []string
	missing := func(name string, set bool) {
		if !set {
			out = append(out, "automatic."+name)
		}
	}
	missing("enabled", a.Enabled != nil)
	missing("max_additions_per_run", a.MaxAdditionsPerRun != nil)
	missing("max_removals_per_run", a.MaxRemovalsPerRun != nil)
	missing("max_additions_per_day", a.MaxAdditionsPerDay != nil)
	missing("max_removals_per_day", a.MaxRemovalsPerDay != nil)
	missing("block_lifetime", a.BlockLifetime != nil)
	missing("on_source_outage", a.OnSourceOutage != nil)
	missing("alert_channel", a.AlertChannel != nil)
	missing("emergency_disable_path", a.EmergencyDisablePath != nil)
	return out
}

// validateAutomatic refuses a value that is PRESENT and malformed.
//
// Absent is unresolved and is not an error; present and nonsensical is an
// error, because a household that wrote `-1` meant something and this build
// cannot know what.
func validateAutomatic(a *Automatic) error {
	if a == nil {
		return nil
	}
	for _, f := range []struct {
		name string
		v    *int
	}{
		{"max_additions_per_run", a.MaxAdditionsPerRun},
		{"max_removals_per_run", a.MaxRemovalsPerRun},
		{"max_additions_per_day", a.MaxAdditionsPerDay},
		{"max_removals_per_day", a.MaxRemovalsPerDay},
	} {
		if f.v != nil && *f.v < 0 {
			return fmt.Errorf("%w: automatic.%s is %d; a negative limit is not a limit",
				ErrPolicyInvalid, f.name, *f.v)
		}
	}
	if a.BlockLifetime != nil {
		d, err := time.ParseDuration(*a.BlockLifetime)
		if err != nil {
			return fmt.Errorf("%w: automatic.block_lifetime is not a duration: %v", ErrPolicyInvalid, err)
		}
		if d <= 0 {
			return fmt.Errorf("%w: automatic.block_lifetime is %s; a block that expires at or before "+
				"the instant it is created is not a block", ErrPolicyInvalid, d)
		}
	}
	if a.OnSourceOutage != nil && !a.OnSourceOutage.Valid() {
		return fmt.Errorf("%w: automatic.on_source_outage is %q; it must be %q or %q",
			ErrPolicyInvalid, *a.OnSourceOutage, OutageHold, OutageExpire)
	}
	if a.AlertChannel != nil && strings.TrimSpace(*a.AlertChannel) == "" {
		return fmt.Errorf("%w: automatic.alert_channel is empty; an automatic system nobody hears "+
			"from cannot be corrected. Write where the household wants to be told", ErrPolicyInvalid)
	}
	if a.EmergencyDisablePath != nil && strings.TrimSpace(*a.EmergencyDisablePath) == "" {
		return fmt.Errorf("%w: automatic.emergency_disable_path is empty; there would be no way "+
			"to stop this without editing the policy", ErrPolicyInvalid)
	}
	return nil
}

// AutoAction is what an unattended run would do about one indicator.
//
// Three categories, kept apart for the reason Decision documents: an
// abstention is answered by evidence or by a policy number, and a refusal is
// not answerable by either.
type AutoAction string

// The action vocabulary. Closed.
const (
	// AutoBlock — ScamWall would add or keep its own block, with no person
	// asked about this domain.
	AutoBlock AutoAction = "automatic_block"
	// AutoAbstain — it would not, and more or better evidence, or a different
	// policy number, could change that.
	AutoAbstain AutoAction = "abstain"
	// AutoRefuse — it would not, and no amount of evidence changes it. The
	// household excepted it, or a rights position forbids the operation.
	AutoRefuse AutoAction = "refuse"
)

// Automatic-contract reasons. Recorded under their own codes so that "we did
// not block it because the household has not finished deciding" can never be
// read as "the evidence fell short".
const (
	// ReasonAutomaticNotConfigured — no `automatic` block in the policy.
	ReasonAutomaticNotConfigured Reason = "automatic_contract_not_configured"
	// ReasonAutomaticUnresolved — the block exists and required values are
	// missing. They are NAMED; none is defaulted.
	ReasonAutomaticUnresolved Reason = "automatic_contract_unresolved"
	// ReasonAutomaticDisabled — a complete contract, switched off.
	ReasonAutomaticDisabled Reason = "automatic_blocking_disabled"
	// ReasonEmergencyDisabled — the household's stop file is present.
	ReasonEmergencyDisabled Reason = "automatic_blocking_emergency_disabled"
	// ReasonBulkChangeExceedsLimit — this run would change more than the
	// household's per-run limit. The WHOLE run is held; see
	// Automatic.MaxAdditionsPerRun.
	ReasonBulkChangeExceedsLimit Reason = "bulk_change_exceeds_per_run_limit"
	// ReasonAutomaticQualified — it met the contract.
	ReasonAutomaticQualified Reason = "automatic_contract_met"
)

// AutoReasons is the closed automatic vocabulary, in a stable order.
var AutoReasons = []Reason{
	ReasonAutomaticNotConfigured, ReasonAutomaticUnresolved, ReasonAutomaticDisabled,
	ReasonEmergencyDisabled, ReasonBulkChangeExceedsLimit, ReasonAutomaticQualified,
}

// AutoOutcome is what an unattended run would do about one indicator, and why.
type AutoOutcome struct {
	// Canonical is the name, where the report was permitted to name it.
	Canonical string `json:"canonical"`
	// IdentityWithheld carries the proposal report's rights position forward.
	// An outcome whose name was withheld there is NOT named here.
	IdentityWithheld bool `json:"identity_withheld,omitempty"`
	// Action is the category. Three, kept distinct.
	Action AutoAction `json:"action"`
	// Reason is either the proposal reason that decided it or one of the
	// automatic-contract reasons above.
	Reason Reason `json:"reason"`
	// ExportWithheld carries the proposal report's export position forward,
	// for the same reason IdentityWithheld is carried: a plan item is a bare
	// name and is exactly where a withheld host reappears.
	ExportWithheld bool `json:"export_withheld,omitempty"`
	// Explanation is bounded and escaped.
	Explanation string `json:"explanation"`
}

// AutoInputs are the facts outside the policy document that one automatic
// evaluation needs.
type AutoInputs struct {
	// EmergencyStopPresent is whether Automatic.EmergencyDisablePath exists.
	// Decided by the caller: this package opens no files.
	EmergencyStopPresent bool
	// SourceOutage is whether the household's evidence supply is degraded, as
	// the caller determined. Consumed only in the removal direction, and only
	// by a later enforcement milestone; recorded here so that the answer a
	// run gives is bound to the outage state it was given.
	SourceOutage bool

	// Today is what previous runs have already done today, read from the
	// journal by the caller. A zero value means nobody looked; see DayLedger,
	// and see NotEnforced, which goes on saying the daily addition cap is not
	// enforced while that is so.
	Today DayLedger

	// NewestEvidence maps canonical name to the most recent observation
	// supporting it. It orders the deferral queue newest first. A name absent
	// from the map sorts last: unknown recency must not win a cap by accident.
	NewestEvidence map[string]time.Time
}

// AutoPlan is what an unattended run would do, whole.
type AutoPlan struct {
	// State is how far the household's contract has got.
	State AutomaticState `json:"state"`
	// Unresolved names every required value that is not set. Empty unless
	// State is not_configured or unresolved.
	Unresolved []string `json:"unresolved,omitempty"`
	// NotEnforced names values the contract requires and this build records
	// without acting on. Present in EVERY plan, including a qualifying one:
	// a reader who sees a daily limit in the policy and a block in the plan
	// must not be able to conclude the limit was checked.
	NotEnforced []string `json:"not_enforced_by_this_build"`
	// Outcomes is one entry per indicator in the report, in the report's
	// order.
	Outcomes []AutoOutcome `json:"outcomes"`
	// Blocks are the canonical names in AutoBlock, sorted. Empty when the run
	// is held.
	Blocks []string `json:"blocks"`
	// Held is true when a run-level rule withheld everything that would
	// otherwise have been blocked.
	Held bool `json:"held,omitempty"`
	// HeldReason and HeldExplanation say which rule and why.
	HeldReason      Reason `json:"held_reason,omitempty"`
	HeldExplanation string `json:"held_explanation,omitempty"`
	// OutageBehaviour is what the contract says happens to existing blocks
	// during a source outage, echoed so that a plan read later does not need
	// the policy beside it. Empty while unresolved.
	OutageBehaviour OutageBehaviour `json:"outage_behaviour,omitempty"`
	// WithheldFromExport is the single total for this rendering. Zero in a
	// local one, always.
	WithheldFromExport int `json:"withheld_from_export,omitempty"`
	// SourceOutage is the outage state this plan was computed against.
	SourceOutage bool `json:"source_outage"`
	// Deferred is what qualified and is waiting rather than gone. Every
	// indicator that reached AutoBlock appears in exactly one of Blocks and
	// Deferred; see TestNothingIsDropped.
	Deferred []DeferredItem `json:"deferred,omitempty"`
}

// Counts summarises a plan.
func (p *AutoPlan) Counts() (block, abstain, refuse int) {
	for _, o := range p.Outcomes {
		switch o.Action {
		case AutoBlock:
			block++
		case AutoAbstain:
			abstain++
		case AutoRefuse:
			refuse++
		}
	}
	return
}

// Qualify decides what an unattended run would do, for one report under one
// policy.
//
// # IT NEVER UPGRADES A PROPOSAL REPORT'S ANSWER
//
// The proposal decision is the floor. An indicator the report ABSTAINED on is
// abstained here; one it REFUSED is refused here. Qualify only ever moves a
// `propose` DOWN to an abstention, because every rule in the automatic
// contract is a further condition on acting without asking.
//
// So a household that has not finished the contract gets the same protection
// decisions they had before, reported honestly as not-blocked, rather than a
// permissive fallback.
func Qualify(rep *Report, p *Policy, in AutoInputs) *AutoPlan {
	plan := &AutoPlan{
		NotEnforced:  notEnforced(in),
		SourceOutage: in.SourceOutage,
	}
	if rep == nil || p == nil {
		plan.State = AutomaticAbsent
		plan.Unresolved = append([]string(nil), automaticRequired...)
		return plan
	}

	unresolved := p.Automatic.unresolvedFields()
	switch {
	case p.Automatic == nil:
		plan.State = AutomaticAbsent
	case len(unresolved) > 0:
		plan.State = AutomaticUnresolved
	case !*p.Automatic.Enabled:
		plan.State = AutomaticDisabled
	default:
		plan.State = AutomaticActive
	}
	plan.Unresolved = unresolved
	if p.Automatic != nil && p.Automatic.OnSourceOutage != nil {
		plan.OutageBehaviour = *p.Automatic.OnSourceOutage
	}

	// The one gate that is about the contract rather than about a domain. It
	// is computed once and applies to every would-be block identically, so
	// that a report cannot contain two indicators decided under two
	// different readings of the same contract.
	var gate *AutoOutcome
	switch {
	case plan.State == AutomaticAbsent:
		gate = &AutoOutcome{Action: AutoAbstain, Reason: ReasonAutomaticNotConfigured,
			Explanation: "this policy has no `automatic` block, so the household has not stated " +
				"the terms on which ScamWall may block without asking"}
	case plan.State == AutomaticUnresolved:
		gate = &AutoOutcome{Action: AutoAbstain, Reason: ReasonAutomaticUnresolved,
			Explanation: "the automatic contract is incomplete and nothing was substituted for the " +
				"missing values: " + joinBounded(unresolved)}
	case in.EmergencyStopPresent:
		gate = &AutoOutcome{Action: AutoAbstain, Reason: ReasonEmergencyDisabled,
			Explanation: "the household's emergency stop file is present at " +
				safetext.Clip(*p.Automatic.EmergencyDisablePath, 200) + "; automatic blocking is off until it is removed"}
	case plan.State == AutomaticDisabled:
		gate = &AutoOutcome{Action: AutoAbstain, Reason: ReasonAutomaticDisabled,
			Explanation: "the automatic contract is complete and `automatic.enabled` is false"}
	}

	for _, o := range rep.Outcomes {
		plan.Outcomes = append(plan.Outcomes, qualifyOne(o, gate))
	}

	for _, o := range plan.Outcomes {
		if o.Action == AutoBlock {
			plan.Blocks = append(plan.Blocks, o.Canonical)
		}
	}
	sort.Strings(plan.Blocks)

	// RUN-LEVEL: an abnormal batch holds the WHOLE run.
	//
	// Truncating to the limit would apply an unexplained subset of an
	// abnormal change and leave the rest, which is the worst reading of both
	// options: the household gets some of a change nobody vetted AND a
	// partial state that the next run reconciles differently.
	if plan.State == AutomaticActive && !in.EmergencyStopPresent &&
		len(plan.Blocks) > *p.Automatic.MaxAdditionsPerRun {
		plan.Held = true
		plan.HeldReason = ReasonBulkChangeExceedsLimit
		plan.HeldExplanation = safetext.Clip(fmt.Sprintf(
			"this run would add %d block(s); automatic.max_additions_per_run is %d. The whole run "+
				"is held rather than truncated: a limit reached is the signal that something "+
				"upstream changed, and applying the first %d of an abnormal batch vets none of it",
			len(plan.Blocks), *p.Automatic.MaxAdditionsPerRun, *p.Automatic.MaxAdditionsPerRun),
			MaxExplanation)
		for i := range plan.Outcomes {
			if plan.Outcomes[i].Action != AutoBlock {
				continue
			}
			plan.Outcomes[i].Action = AutoAbstain
			plan.Outcomes[i].Reason = ReasonBulkChangeExceedsLimit
			plan.Outcomes[i].Explanation = plan.HeldExplanation
		}
		// Held is not dropped. The queue is recorded, newest evidence first,
		// so a reader can see that the work is waiting rather than gone and
		// the next run has an order to take it in.
		for _, n := range orderByRecency(plan.Blocks, in.NewestEvidence) {
			plan.Deferred = append(plan.Deferred, DeferredItem{
				Canonical:      n,
				NewestEvidence: in.NewestEvidence[n],
				Reason:         ReasonBulkChangeExceedsLimit,
				Explanation:    plan.HeldExplanation,
			})
		}
		plan.Blocks = nil
		return plan
	}

	// RUN-LEVEL: the daily ration.
	//
	// Distinct from the hold above, and deliberately so. A per-run cap
	// reached is an abnormality signal and holds the batch whole; a daily cap
	// reached is a budget spent, which is an ordinary thing to happen on a
	// busy day and must not stop the household being protected from the most
	// recent evidence. So this one selects rather than holds, and the excess
	// is deferred.
	if plan.State == AutomaticActive && !in.EmergencyStopPresent && p.Automatic.MaxAdditionsPerDay != nil {
		kept, deferred := applyDailyAdditionCap(plan.Blocks, in, *p.Automatic.MaxAdditionsPerDay)
		plan.Blocks = kept
		plan.Deferred = append(plan.Deferred, deferred...)
		for _, d := range deferred {
			for i := range plan.Outcomes {
				if plan.Outcomes[i].Action == AutoBlock && plan.Outcomes[i].Canonical == d.Canonical {
					plan.Outcomes[i].Action = AutoAbstain
					plan.Outcomes[i].Reason = d.Reason
					plan.Outcomes[i].Explanation = d.Explanation
				}
			}
		}
	}
	return plan
}

// qualifyOne maps one proposal outcome, then applies the contract gate.
func qualifyOne(o Outcome, gate *AutoOutcome) AutoOutcome {
	out := AutoOutcome{
		Canonical:        o.Canonical,
		IdentityWithheld: o.IdentityWithheld,
		ExportWithheld:   o.ExportWithheld,
		Reason:           o.Reason,
		Explanation:      o.Explanation,
	}
	switch o.Decision {
	case DecisionRefuse:
		// A refusal is carried through unchanged, including its withheld
		// identity. The automatic contract has no opinion that could soften
		// a rights position or overrule the household.
		out.Action = AutoRefuse
		return out
	case DecisionAbstain:
		out.Action = AutoAbstain
		return out
	}
	if gate != nil {
		out.Action = gate.Action
		out.Reason = gate.Reason
		out.Explanation = gate.Explanation
		return out
	}
	out.Action = AutoBlock
	out.Reason = ReasonAutomaticQualified
	out.Explanation = safetext.Clip("corroborated under the policy and inside the household's automatic "+
		"contract: "+o.Explanation, MaxExplanation)
	return out
}
