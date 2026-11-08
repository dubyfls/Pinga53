// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/ledger"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
)

// # WHAT `decide` IS, AND WHY IT IS NOT PART OF `propose` OR `shadow`
//
// It is the *Decide* step of the loop, whole: what an unattended run would
// add, what it would remove, and what it is holding back. `propose` answers
// only the addition question — "which domains meet the policy" — and has no
// concept of something ScamWall already placed. `shadow` answers the
// appliance question and needs a session, a credential and a network to do
// it, which is the wrong price for a decision that is entirely offline.
//
// This command reads files and nothing else. No configuration, no credential,
// no Pi-hole client, no path to a network client — the same standard
// `propose` holds itself to.
//
// # THE RULES IT EXISTS TO GIVE A CALLER
//
// Both were finished, tested and unreachable before it. ORDER 9's own records
// call them RULE VERIFIED (synthetic), NO CALLER:
//
//	C-21  proposal.AssessRetention  — has a block outlived its justification
//	C-20  proposal.AssessRemovals   — how much of that may one run act on
//
// Neither can run without an ownership ledger, and no build kept one. See
// internal/ledger, and see the `--ledger` flag: WITHOUT it this command
// proposes no removals and says why, exactly as `shadow` does today. An
// absent ledger is not an empty one.

// decideDefaults are the bounds on the four documents, shared with `propose`.
const (
	decideMaxEvidenceBytes = defaultMaxEvidenceBytes
	decideMaxRecords       = defaultMaxRecords
)

// decision is one run's decided plan, as this command reports it.
//
// Additions, removals, deferrals and holds are FOUR fields rather than two
// counts. A run that added nothing because nothing qualified and a run that
// added nothing because the whole batch was held are different facts about
// the household, and a reader who cannot tell them apart will read the first
// as safety and the second as quiet.
type decision struct {
	Binding   proposal.Binding        `json:"binding"`
	Ownership string                  `json:"ownership_source"`
	Contract  proposal.AutomaticState `json:"automatic_contract_state"`
	Additions []string                `json:"additions"`
	Removals  []string                `json:"removals"`
	// Deferred is what qualified and is waiting rather than gone.
	//
	// A DEFERRED REMOVAL PERSISTS STRUCTURALLY, not by being written down.
	// The next run recomputes removals from the ledger against that run's
	// qualifying set, so an entry this run could not fit inside its caps is a
	// candidate again next run, and orderByRecency puts the queue in the same
	// order both times. Nothing has to be remembered for that to hold, which
	// is the property a stored queue would only approximate: a stored queue
	// can be lost, and a lost queue is a silent drop.
	Deferred   []proposal.DeferredItem `json:"deferred,omitempty"`
	Held       bool                    `json:"held,omitempty"`
	HeldReason proposal.Reason         `json:"held_reason,omitempty"`
	// HeldExplanation covers the ADDITION hold and the REMOVAL hold, which
	// are different rules with different consequences; RemovalHeld says which
	// fired. A single boolean would let "we added nothing" be read as "we
	// removed nothing".
	HeldExplanation string          `json:"held_explanation,omitempty"`
	RemovalHeld     bool            `json:"removal_held,omitempty"`
	RemovalReason   proposal.Reason `json:"removal_held_reason,omitempty"`
	RemovalDetail   string          `json:"removal_held_explanation,omitempty"`
	// Retention is C-21's answer for every owned entry, kept or removed, with
	// the rule that decided it. WHOLE rather than only the removals: "this
	// block is still justified" and "this block is being held through an
	// outage" are different states of the household's protection, and only
	// one of them is a reason to relax.
	Retention []proposal.RetentionOutcome `json:"retention,omitempty"`
	// Frozen records that at least one entry was kept ONLY because of the
	// outage behaviour. Without it, a run that silently held blocks through a
	// degraded supply and a run with nothing to remove look identical.
	Frozen bool `json:"frozen,omitempty"`
	// SourceOutage and OutageReason are the supply state this run was
	// computed against, bound into the document so a plan read later does not
	// need the operator's memory beside it.
	SourceOutage bool   `json:"source_outage"`
	OutageReason string `json:"source_outage_reason,omitempty"`
	// NotEnforced is carried from the automatic plan unchanged. A reader who
	// sees a limit in the policy and a change in this document must not be
	// able to conclude the limit was checked.
	NotEnforced []string `json:"not_enforced_by_this_build"`
	// Limitations is what this document does not establish. Travels inside
	// it, as internal/proposal's and internal/shadow's do.
	Limitations []string `json:"limitations"`
}

func cmdDecide(w *os.File, args []string) int {
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	fs.SetOutput(w)
	evidencePath := fs.String("evidence", "", "path to the signed evidence document (required)")
	signersPath := fs.String("signers", "", "path to the signer authority document (required)")
	registryPath := fs.String("registry", "", "path to the source registry (required)")
	policyPath := fs.String("policy", "", "path to the proposal policy (required)")
	ledgerPath := fs.String("ledger", "", "path to the ownership ledger; without it no removal is "+
		"decided, because an absent ledger is not an empty one")
	at := fs.String("at", "", "evaluation instant, RFC 3339 (default: now)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	maxBytes := fs.Int64("max-bytes", decideMaxEvidenceBytes, "maximum evidence document size")
	maxRecords := fs.Int("max-records", decideMaxRecords, "maximum records in one evidence document")
	outageReason := fs.String("source-outage", "", "declare the evidence supply degraded, with a "+
		"reason; existing blocks are then held at their lifetime under the household's "+
		"on_source_outage behaviour")
	maxAcqAge := fs.Duration("max-acquisition-age", 0, "treat the supply as degraded when the "+
		"ledger's last acquisition is older than this; unset measures nothing, and an unset "+
		"limit is not a zero one")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	for flagName, v := range map[string]string{
		"-evidence": *evidencePath, "-signers": *signersPath,
		"-registry": *registryPath, "-policy": *policyPath,
	} {
		if v == "" {
			fmt.Fprintf(w, "decide: %s is required\n", flagName)
			return exitUsage
		}
	}

	instant := time.Now().UTC()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintf(w, "decide: -at is not an RFC 3339 instant: %v\n", err)
			return exitUsage
		}
		instant = t.UTC()
	}

	report, pol, code := buildReport(w, *evidencePath, *signersPath, *registryPath, *policyPath,
		*maxBytes, *maxRecords, instant)
	if code != exitOK {
		return code
	}

	var led *ledger.Ledger
	if *ledgerPath != "" {
		var err error
		if led, err = ledger.Load(*ledgerPath); err != nil {
			return fail(w, err)
		}
	}

	d := decide(report, pol, led, instant, proposal.AutoInputs{
		EmergencyStopPresent: emergencyStopPresent(pol),
	}, assessOutage(led, instant, *outageReason, *maxAcqAge))

	bw := bufio.NewWriter(w)
	if *asJSON {
		enc := json.NewEncoder(bw)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			return fail(w, err)
		}
	} else {
		writeDecision(bw, d)
	}
	if err := bw.Flush(); err != nil {
		return fail(w, err)
	}
	return exitOK
}

// decide is the pipeline, separated from the flag parsing so that the RPZ
// command runs the identical one rather than a second reading of it.
//
// Additions come from the automatic contract, which has already applied
// C-20's addition half. Removals come from the ledger, and this is where
// C-20's removal half runs: the abnormal-removal rule first, on what the run
// WANTED to do, then the caps.
func decide(rep *proposal.Report, pol *proposal.Policy, led *ledger.Ledger, now time.Time,
	in proposal.AutoInputs, outage outageState) decision {

	in.SourceOutage = outage.Degraded
	auto := proposal.Qualify(rep, pol, in)

	d := decision{
		Ownership:       ownershipSource(led),
		Contract:        auto.State,
		Additions:       auto.Blocks,
		Deferred:        auto.Deferred,
		Held:            auto.Held,
		HeldReason:      auto.HeldReason,
		HeldExplanation: auto.HeldExplanation,
		NotEnforced:     auto.NotEnforced,
	}
	if rep != nil {
		d.Binding = rep.Binding
	}
	if d.Additions == nil {
		d.Additions = []string{}
	}
	d.Removals = []string{}

	// NO LEDGER, NO REMOVAL. Not "remove nothing because nothing is owned":
	// this run cannot show it owns anything, and a removal ScamWall cannot
	// show it owns is not a removal it may make.
	d.SourceOutage, d.OutageReason = outage.Degraded, outage.Reason

	if led != nil {
		// C-21 FIRST, then C-20. Retention decides what has stopped being
		// justified; the caps decide how much of that one run may act on.
		// The other order would let a cap hide an expiry, and an entry whose
		// basis is gone would then sit in the zone looking current.
		ret := proposal.AssessRetention(retentionInput(led, rep, pol, now, outage))
		d.Retention = ret.Outcomes
		d.Frozen = ret.Frozen

		rem := proposal.AssessRemovals(proposal.RemovalInput{
			Proposed:   ret.Removals,
			OwnedCount: led.Count(),
			MaxPerRun:  intOr(pol, func(a *proposal.Automatic) *int { return a.MaxRemovalsPerRun }),
			MaxPerDay:  intOr(pol, func(a *proposal.Automatic) *int { return a.MaxRemovalsPerDay }),
			Today:      in.Today,
			// The REMOVAL queue's recency comes from the ledger, which is the
			// only place this build records when a block was last justified.
			// The proposal report carries no per-indicator timestamp, so the
			// ADDITION queue is ordered by name alone — deterministic, and
			// stated here rather than left to be inferred from a nil map.
			NewestEvidence: lastJustified(led),
		})
		if rem.Removals != nil {
			d.Removals = rem.Removals
		}
		d.Deferred = append(d.Deferred, rem.Deferred...)
		d.RemovalHeld, d.RemovalReason, d.RemovalDetail = rem.Held, rem.Reason, rem.Explanation
	}
	d.Limitations = decisionLimitations(led)
	return d
}

// outageState is what this run was told, or could work out, about whether the
// evidence supply is degraded.
//
// Two ways in, because there are two different failures. A run can be TOLD by
// an operator who knows a provider is down, and a run can WORK IT OUT from
// how long it has been since the ledger recorded an acquisition. Neither
// subsumes the other: the first catches an outage nothing has recorded yet,
// the second catches one nobody noticed.
type outageState struct {
	Degraded bool
	Reason   string
}

// assessOutage combines the two ways a run learns its supply is degraded.
//
// EITHER is enough. They are ORed rather than ANDed because each catches what
// the other misses, and because the consequence of a false positive is that
// blocks are held a little longer than they need to be, while the consequence
// of a false negative is unblocking a fraud domain during an outage. Those
// are not symmetrical and the rule is not written as though they were.
func assessOutage(led *ledger.Ledger, now time.Time, declared string, maxAge time.Duration) outageState {
	if declared != "" {
		return outageState{Degraded: true, Reason: "declared by the operator: " + declared}
	}
	if led == nil {
		return outageState{}
	}
	if stale, why := led.AcquisitionStale(now, maxAge); stale {
		return outageState{Degraded: true, Reason: why}
	}
	return outageState{}
}

// retentionInput turns a report, a policy and a ledger into C-21's question.
//
// # WHERE EACH SET COMES FROM, AND WHY NOT FROM auto.Blocks
//
// StillJustified is read from the proposal report's OUTCOMES, not from the
// automatic plan's Blocks. They differ, and the difference matters: a host
// the daily addition cap deferred is absent from Blocks and still perfectly
// well justified. Driving retention from Blocks would let a busy day's
// rationing read as "the evidence stopped", and C-21 would then expire the
// blocks the caps were protecting. A cap is about how fast ScamWall may act;
// it is not evidence about a domain.
//
// Withdrawn is ReasonWithdrawnOnly — every live assertion behind the host has
// been retracted upstream. That is evidence that ARRIVED, so it removes
// through a freeze; see AssessRetention's own table.
//
// Excepted is ReasonUserException, the household's own statement, which
// outranks every source and is likewise freeze-proof.
func retentionInput(led *ledger.Ledger, rep *proposal.Report, pol *proposal.Policy,
	now time.Time, outage outageState) proposal.RetentionInput {

	in := proposal.RetentionInput{
		Owned:          led.Entries(),
		StillJustified: map[string]bool{},
		Withdrawn:      map[string]bool{},
		Excepted:       map[string]bool{},
		SourceOutage:   outage.Degraded,
		Now:            now,
	}
	if rep != nil {
		for _, o := range rep.Outcomes {
			// A withheld host has no name here and cannot be matched against
			// a ledger row, which is correct: C-09 says this build may not
			// print it, and a ledger holding it would be printing it.
			if o.Canonical == "" {
				continue
			}
			switch {
			case o.Reason == proposal.ReasonUserException:
				in.Excepted[o.Canonical] = true
			case o.Reason == proposal.ReasonWithdrawnOnly:
				in.Withdrawn[o.Canonical] = true
			case o.Decision == proposal.DecisionPropose:
				in.StillJustified[o.Canonical] = true
			}
		}
	}
	if pol != nil && pol.Automatic != nil {
		if pol.Automatic.BlockLifetime != nil {
			// Already validated by LoadPolicy: present and unparseable is a
			// load error, so a parse failure here cannot happen. Zero on the
			// impossible branch is the safe direction — an unset lifetime
			// expires nothing.
			if d, err := time.ParseDuration(*pol.Automatic.BlockLifetime); err == nil {
				in.Lifetime = d
			}
		}
		if pol.Automatic.OnSourceOutage != nil {
			in.OnOutage = *pol.Automatic.OnSourceOutage
		}
	}
	return in
}

// lastJustified maps each owned host to when live evidence last supported it.
//
// It orders the removal deferral queue. Newest-justified first is the right
// way round for a REMOVAL as well as for an addition: the entry ScamWall has
// most recently had a reason for is the one whose removal most deserves to
// wait for a person.
func lastJustified(led *ledger.Ledger) map[string]time.Time {
	out := make(map[string]time.Time, led.Count())
	for _, o := range led.Owned {
		if !o.LastJustifiedAt.IsZero() {
			out[o.Canonical] = o.LastJustifiedAt
		}
	}
	return out
}

// intOr reads one automatic limit, or zero when the contract has not stated
// it.
//
// Zero is the SAFE direction for a cap: proposal.AssessRemovals treats it as
// "no budget", so an unresolved contract removes nothing rather than removing
// without a limit. The contract state travels in the document beside it, so a
// reader can tell a household that chose zero from one that chose nothing.
func intOr(p *proposal.Policy, pick func(*proposal.Automatic) *int) int {
	if p == nil || p.Automatic == nil {
		return 0
	}
	if v := pick(p.Automatic); v != nil {
		return *v
	}
	return 0
}

func ownershipSource(led *ledger.Ledger) string {
	if led == nil {
		return "no ownership ledger was given to this run, so nothing is proposed for removal. " +
			"An absent ledger is not an empty one"
	}
	return fmt.Sprintf("an ownership ledger holding %d entr%s", led.Count(), plural(led.Count()))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func decisionLimitations(led *ledger.Ledger) []string {
	out := []string{
		"This is a decision, not a change. This command has no client, no configuration and no " +
			"credential; nothing in this build can apply a line of it.",
		"The appliance was not read. A decision says what ScamWall would do; only a shadow " +
			"comparison says what the household's resolver currently holds.",
	}
	if led == nil {
		out = append(out, "No ownership ledger was given, so the removal rules did not run at all. "+
			"This is not a statement that nothing needs removing.")
	}
	return out
}

func writeDecision(w *bufio.Writer, d decision) {
	fmt.Fprintf(w, "decided plan\n")
	fmt.Fprintf(w, "evidence   %s\n", orEmpty(d.Binding.EvidenceDigest))
	fmt.Fprintf(w, "policy     %s\n", orEmpty(d.Binding.PolicyDigest))
	fmt.Fprintf(w, "contract   %s\n", d.Contract)
	fmt.Fprintf(w, "ownership  %s\n\n", d.Ownership)

	fmt.Fprintf(w, "%d addition(s)\n", len(d.Additions))
	for _, n := range d.Additions {
		fmt.Fprintf(w, "  add     %s\n", n)
	}
	fmt.Fprintf(w, "%d removal(s)\n", len(d.Removals))
	for _, n := range d.Removals {
		fmt.Fprintf(w, "  remove  %s\n", n)
	}
	if len(d.Deferred) > 0 {
		fmt.Fprintf(w, "%d deferred — carried forward, not dropped\n", len(d.Deferred))
		for _, it := range d.Deferred {
			fmt.Fprintf(w, "  defer   %s  [%s]\n", it.Canonical, it.Reason)
		}
	}
	if d.Held {
		fmt.Fprintf(w, "\nADDITIONS HELD [%s]: %s\n", d.HeldReason, d.HeldExplanation)
	}
	if d.RemovalHeld {
		fmt.Fprintf(w, "\nREMOVALS HELD [%s]: %s\n", d.RemovalReason, d.RemovalDetail)
	}
	if d.SourceOutage {
		fmt.Fprintf(w, "\nSOURCE OUTAGE: %s\n", d.OutageReason)
	}
	if d.Frozen {
		fmt.Fprintln(w, "  at least one block is kept ONLY by the outage behaviour and would "+
			"otherwise have expired")
	}
	if len(d.Retention) > 0 {
		fmt.Fprintf(w, "\nretention, %d owned entr%s\n", len(d.Retention), plural(len(d.Retention)))
		for _, o := range d.Retention {
			fmt.Fprintf(w, "  %-6s  %s  [%s]\n", o.Action, o.Canonical, o.Reason)
		}
	}

	fmt.Fprintln(w, "\nvalues this build records and does not act on:")
	for _, n := range d.NotEnforced {
		fmt.Fprintf(w, "  - %s\n", n)
	}
	fmt.Fprintln(w, "what this decision does not establish:")
	for _, n := range d.Limitations {
		fmt.Fprintf(w, "  - %s\n", n)
	}
}

func orEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
