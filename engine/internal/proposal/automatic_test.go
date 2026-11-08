// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # THE AUTOMATIC CONTRACT AT ITS BOUNDARY
//
// Every test here drives the real path: a signed synthetic document through
// feed.ValidateEvidence, Build, and Qualify. Nothing restates a rule.
//
// The household's own values are NOT invented anywhere in this file. Where a
// test needs a complete contract it writes obviously-synthetic numbers and
// says so; where it is about the unresolved state it leaves the value out and
// asserts that nothing was substituted for it.

// completeAutomatic is a SYNTHETIC contract. The numbers are chosen to make
// one test's arithmetic legible and are not a recommendation: see Automatic.
func completeAutomatic(maxAddPerRun int) map[string]any {
	return map[string]any{
		"enabled":                true,
		"max_additions_per_run":  maxAddPerRun,
		"max_removals_per_run":   1,
		"max_additions_per_day":  10,
		"max_removals_per_day":   10,
		"block_lifetime":         "720h",
		"on_source_outage":       string(OutageHold),
		"alert_channel":          "synthetic: the test suite is nobody's household",
		"emergency_disable_path": "/run/scamwall/synthetic-stop",
	}
}

// autoPolicy parses a policy document carrying whatever automatic block is
// given. nil means the key is absent entirely.
func autoPolicy(t *testing.T, minIndependent int, automatic map[string]any, exceptions ...Exception) *Policy {
	t.Helper()
	ex := make([]map[string]any, 0, len(exceptions))
	for _, e := range exceptions {
		ex = append(ex, map[string]any{"value": e.Value, "scope": string(e.Scope), "note": e.Note})
	}
	raw := map[string]any{
		"schema_version":          PolicySchemaVersion,
		"min_independent_sources": minIndependent,
		"proposal_scope":          string(ScopeExact),
		"exceptions":              ex,
	}
	if automatic != nil {
		raw["automatic"] = automatic
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	p, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("policy refused: %v", err)
	}
	return p
}

// twoAdverse is the ordinary qualifying shape: two independent sources, each
// asserting the same domain adversely, under a threshold of two.
func twoAdverse(t *testing.T, p *Policy, value string) *Report {
	t.Helper()
	return run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  p,
		records: []feed.EvidenceRecord{
			adverse("src-a", "r1", value),
			adverse("src-b", "r2", value),
		},
	}.do(t)
}

func onlyAuto(t *testing.T, plan *AutoPlan) AutoOutcome {
	t.Helper()
	if len(plan.Outcomes) != 1 {
		t.Fatalf("expected one automatic outcome, got %d: %+v", len(plan.Outcomes), plan.Outcomes)
	}
	return plan.Outcomes[0]
}

func wantAction(t *testing.T, o AutoOutcome, a AutoAction, r Reason) {
	t.Helper()
	if o.Action != a || o.Reason != r {
		t.Errorf("%s: got %s/%s, want %s/%s\n  %s", o.Canonical, o.Action, o.Reason, a, r, o.Explanation)
	}
}

// --- the contract's own states ------------------------------------------

// TestAPolicyWithNoAutomaticBlockHasNotStartedTheContract.
//
// `not_configured` and `unresolved` are different sentences, and an operator
// chasing a missing block needs to know which one they are in.
func TestAPolicyWithNoAutomaticBlockHasNotStartedTheContract(t *testing.T) {
	p := autoPolicy(t, 2, nil)
	rep := twoAdverse(t, p, "bad.example.com")
	if o := only(t, rep); o.Decision != DecisionPropose {
		t.Fatalf("fixture: expected a proposal, got %s/%s", o.Decision, o.Reason)
	}

	plan := Qualify(rep, p, AutoInputs{})
	if plan.State != AutomaticAbsent {
		t.Errorf("state = %s, want %s", plan.State, AutomaticAbsent)
	}
	wantAction(t, onlyAuto(t, plan), AutoAbstain, ReasonAutomaticNotConfigured)
	if len(plan.Blocks) != 0 {
		t.Errorf("a policy that never mentioned automatic blocking produced %d block(s)", len(plan.Blocks))
	}
	// Every required value is named, so the household has a list to fill in.
	if len(plan.Unresolved) != len(automaticRequired) {
		t.Errorf("unresolved lists %d of %d required values", len(plan.Unresolved), len(automaticRequired))
	}
}

// TestAMissingRequiredValueIsVisiblyUnresolvedAndNeverDefaulted.
//
// One field is removed at a time. Each time: the policy still LOADS, the run
// still produces its proposal decision, the automatic answer is `abstain`
// under the unresolved reason, the missing field is NAMED, and nothing was
// substituted for it.
func TestAMissingRequiredValueIsVisiblyUnresolvedAndNeverDefaulted(t *testing.T) {
	for field := range completeAutomatic(5) {
		t.Run("without "+field, func(t *testing.T) {
			a := completeAutomatic(5)
			delete(a, field)
			p := autoPolicy(t, 2, a)
			rep := twoAdverse(t, p, "bad.example.com")

			plan := Qualify(rep, p, AutoInputs{})
			if plan.State != AutomaticUnresolved {
				t.Fatalf("state = %s, want %s", plan.State, AutomaticUnresolved)
			}
			wantAction(t, onlyAuto(t, plan), AutoAbstain, ReasonAutomaticUnresolved)
			if len(plan.Blocks) != 0 {
				t.Error("an incomplete contract authorised an unattended block")
			}
			want := "automatic." + field
			var found bool
			for _, u := range plan.Unresolved {
				if u == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s is missing and was not named; unresolved = %v", want, plan.Unresolved)
			}
			if len(plan.Unresolved) != 1 {
				t.Errorf("exactly one value is missing; unresolved = %v", plan.Unresolved)
			}
			// The explanation an operator reads names it too.
			if !strings.Contains(onlyAuto(t, plan).Explanation, want) {
				t.Errorf("the explanation does not name %s: %s", want, onlyAuto(t, plan).Explanation)
			}
		})
	}
}

// TestACompleteContractSwitchedOffIsNotAnIncompleteOne.
func TestACompleteContractSwitchedOffIsNotAnIncompleteOne(t *testing.T) {
	a := completeAutomatic(5)
	a["enabled"] = false
	p := autoPolicy(t, 2, a)
	plan := Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{})

	if plan.State != AutomaticDisabled {
		t.Errorf("state = %s, want %s", plan.State, AutomaticDisabled)
	}
	if len(plan.Unresolved) != 0 {
		t.Errorf("a complete contract reported unresolved values: %v", plan.Unresolved)
	}
	wantAction(t, onlyAuto(t, plan), AutoAbstain, ReasonAutomaticDisabled)
}

// TestTheEmergencyStopOutranksACompleteEnabledContract.
func TestTheEmergencyStopOutranksACompleteEnabledContract(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5))
	rep := twoAdverse(t, p, "bad.example.com")

	if plan := Qualify(rep, p, AutoInputs{}); len(plan.Blocks) != 1 {
		t.Fatalf("fixture: expected one block without the stop file, got %v", plan.Blocks)
	}
	plan := Qualify(rep, p, AutoInputs{EmergencyStopPresent: true})
	wantAction(t, onlyAuto(t, plan), AutoAbstain, ReasonEmergencyDisabled)
	if len(plan.Blocks) != 0 {
		t.Error("the stop file was present and a block was still planned")
	}
	if !strings.Contains(onlyAuto(t, plan).Explanation, "/run/scamwall/synthetic-stop") {
		t.Error("the refusal does not name the path an operator has to remove")
	}
}

// --- the seven outcomes the order names ---------------------------------

// TestACorroboratedQualifyingDomainIsBlockedWithoutAsking.
//
// The product this is for blocks routine scams without a per-domain question.
// This is that case, and it is the only one in this file that reaches
// `automatic_block`.
func TestACorroboratedQualifyingDomainIsBlockedWithoutAsking(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5))
	plan := Qualify(twoAdverse(t, p, "scam.example.com"), p, AutoInputs{})

	o := onlyAuto(t, plan)
	wantAction(t, o, AutoBlock, ReasonAutomaticQualified)
	if o.Canonical != "scam.example.com" {
		t.Errorf("canonical = %q", o.Canonical)
	}
	if len(plan.Blocks) != 1 || plan.Blocks[0] != "scam.example.com" {
		t.Errorf("blocks = %v", plan.Blocks)
	}
	if plan.Held {
		t.Error("an ordinary single addition was held")
	}
	// A qualifying plan STILL carries what this build does not enforce.
	if len(plan.NotEnforced) == 0 {
		t.Error("a qualifying plan did not say which contract values are not enforced")
	}
}

// TestALegitimateHouseholdExceptionIsRefusedAndNotMerelyNotBlocked.
//
// The household's own statement is a refusal, not an abstention: no amount of
// further evidence changes it, and reporting it as "not enough support" would
// invite an operator to go looking for more.
func TestALegitimateHouseholdExceptionIsRefusedAndNotMerelyNotBlocked(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5),
		Exception{Value: "bank.example.com", Scope: ScopeExact, Note: "the household's own bank"})
	plan := Qualify(twoAdverse(t, p, "bank.example.com"), p, AutoInputs{})

	wantAction(t, onlyAuto(t, plan), AutoRefuse, ReasonUserException)
	if len(plan.Blocks) != 0 {
		t.Error("an excepted domain was planned for an unattended block")
	}
}

// TestConflictingReportsAbstainRatherThanPickASide.
func TestConflictingReportsAbstainRatherThanPickASide(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5))
	benign := adverse("src-b", "r2", "mixed.example.com")
	benign.Classification = "benign"
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  p,
		records: []feed.EvidenceRecord{adverse("src-a", "r1", "mixed.example.com"), benign},
	}.do(t)

	plan := Qualify(rep, p, AutoInputs{})
	wantAction(t, onlyAuto(t, plan), AutoAbstain, ReasonConflict)
}

// TestExpiredAndWithdrawnEvidenceAbstainUnderTheirOwnNames.
func TestExpiredAndWithdrawnEvidenceAbstainUnderTheirOwnNames(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5))

	t.Run("expired", func(t *testing.T) {
		expired := adverse("src-a", "r1", "lapsed.example.com")
		exp := testAt.Add(-time.Hour)
		expired.ExpiresAt = &exp
		rep := run{
			asserts: []string{"src-a"}, sources: twoSources(), policy: p,
			records: []feed.EvidenceRecord{expired},
		}.do(t)
		wantAction(t, onlyAuto(t, Qualify(rep, p, AutoInputs{})), AutoAbstain, ReasonExpiredOnly)
	})

	t.Run("withdrawn", func(t *testing.T) {
		withdrawn := adverse("src-a", "r1", "gone.example.com")
		withdrawn.Status = "withdrawn"
		rep := run{
			asserts: []string{"src-a"}, sources: twoSources(), policy: p,
			records: []feed.EvidenceRecord{withdrawn},
		}.do(t)
		wantAction(t, onlyAuto(t, Qualify(rep, p, AutoInputs{})), AutoAbstain, ReasonWithdrawnOnly)
	})
}

// TestUnestablishedIndependenceDoesNotReachAnUnattendedBlock.
//
// Two sources sharing a documented upstream are one voice. The contract does
// not get its own opinion about that: the proposal layer already abstained,
// and Qualify never upgrades.
func TestUnestablishedIndependenceDoesNotReachAnUnattendedBlock(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5))
	opaque := testSource("src-opaque", nil)
	opaque.UpstreamSourcesCompleteness = sourceregistry.UpstreamUnknown
	rep := run{
		asserts: []string{"src-a", "src-opaque"},
		sources: []sourceregistry.Source{testSource("src-a", nil), opaque},
		policy:  p,
		records: []feed.EvidenceRecord{
			adverse("src-a", "r1", "opaque.example.com"),
			adverse("src-opaque", "r2", "opaque.example.com"),
		},
	}.do(t)

	o := onlyAuto(t, Qualify(rep, p, AutoInputs{}))
	if o.Action != AutoAbstain {
		t.Errorf("a source whose lineage is unestablished reached %s", o.Action)
	}
	if o.Reason != ReasonInsufficientSupport {
		t.Errorf("reason = %s, want %s", o.Reason, ReasonInsufficientSupport)
	}
}

// TestACorrectedFalseBlockStopsQualifying.
//
// The same evidence and the same threshold, with one household exception
// added. Before: a block nobody was asked about. After: a refusal. The
// removal that follows from that is the shadow layer's; what is measured here
// is that the qualifying set SHRANK, which is the only thing that can make a
// correction reach the appliance.
func TestACorrectedFalseBlockStopsQualifying(t *testing.T) {
	before := autoPolicy(t, 2, completeAutomatic(5))
	if got := Qualify(twoAdverse(t, before, "wrong.example.com"), before, AutoInputs{}).Blocks; len(got) != 1 {
		t.Fatalf("fixture: expected the false block first, got %v", got)
	}

	after := autoPolicy(t, 2, completeAutomatic(5),
		Exception{Value: "wrong.example.com", Scope: ScopeExact, Note: "corrected by the household"})
	plan := Qualify(twoAdverse(t, after, "wrong.example.com"), after, AutoInputs{})
	if len(plan.Blocks) != 0 {
		t.Errorf("the correction did not remove it from the qualifying set: %v", plan.Blocks)
	}
	wantAction(t, onlyAuto(t, plan), AutoRefuse, ReasonUserException)

	// The two policies must not share an identity, or a reader comparing two
	// reports would conclude the correction had not been made.
	if before.Digest() == after.Digest() {
		t.Error("adding the household's correction did not change the policy digest")
	}
}

// TestAnAbnormalBulkChangeHoldsTheWholeRun.
//
// Three qualifying domains against a per-run limit of two. Every one of them
// is held, not the first two applied: see Qualify.
func TestAnAbnormalBulkChangeHoldsTheWholeRun(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(2))
	var records []feed.EvidenceRecord
	for _, d := range []string{"one.example.com", "two.example.com", "three.example.com"} {
		records = append(records, adverse("src-a", "a-"+d, d), adverse("src-b", "b-"+d, d))
	}
	rep := run{asserts: []string{"src-a", "src-b"}, sources: twoSources(), policy: p, records: records}.do(t)
	if c := rep.Counts(); c.Proposed != 3 {
		t.Fatalf("fixture: expected 3 proposals, got %d", c.Proposed)
	}

	plan := Qualify(rep, p, AutoInputs{})
	if !plan.Held || plan.HeldReason != ReasonBulkChangeExceedsLimit {
		t.Fatalf("held=%t reason=%s", plan.Held, plan.HeldReason)
	}
	if len(plan.Blocks) != 0 {
		t.Errorf("a held run still planned %d block(s): %v", len(plan.Blocks), plan.Blocks)
	}
	block, abstain, refuse := plan.Counts()
	if block != 0 || abstain != 3 || refuse != 0 {
		t.Errorf("block=%d abstain=%d refuse=%d; want 0/3/0", block, abstain, refuse)
	}
	for _, o := range plan.Outcomes {
		if o.Reason != ReasonBulkChangeExceedsLimit {
			t.Errorf("%s was held under %s rather than the bulk-change rule", o.Canonical, o.Reason)
		}
	}

	// The positive control: the same run one under the limit is NOT held.
	t.Run("two additions against a limit of two", func(t *testing.T) {
		p2 := autoPolicy(t, 2, completeAutomatic(2))
		rep2 := run{asserts: []string{"src-a", "src-b"}, sources: twoSources(), policy: p2,
			records: records[:4]}.do(t)
		plan2 := Qualify(rep2, p2, AutoInputs{})
		if plan2.Held {
			t.Errorf("a run exactly at the limit was held: %s", plan2.HeldExplanation)
		}
		if len(plan2.Blocks) != 2 {
			t.Errorf("blocks = %v", plan2.Blocks)
		}
	})
}

// --- what the contract must not do --------------------------------------

// TestQualifyNeverUpgradesAProposalDecision.
//
// Every abstention and every refusal the proposal layer produced stays one.
// The contract is a further condition on acting, never a way around a
// decision already taken.
func TestQualifyNeverUpgradesAProposalDecision(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(50))
	// One of each: proposed, abstained (single source), refused (excepted).
	pex := autoPolicy(t, 2, completeAutomatic(50),
		Exception{Value: "excepted.example.com", Scope: ScopeExact})
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  pex,
		records: []feed.EvidenceRecord{
			adverse("src-a", "r1", "good.example.com"), adverse("src-b", "r2", "good.example.com"),
			adverse("src-a", "r3", "thin.example.com"),
			adverse("src-a", "r4", "excepted.example.com"), adverse("src-b", "r5", "excepted.example.com"),
		},
	}.do(t)

	plan := Qualify(rep, pex, AutoInputs{})
	if len(plan.Outcomes) != len(rep.Outcomes) {
		t.Fatalf("%d automatic outcomes for %d proposal outcomes", len(plan.Outcomes), len(rep.Outcomes))
	}
	for i, o := range rep.Outcomes {
		got := plan.Outcomes[i]
		switch o.Decision {
		case DecisionRefuse:
			if got.Action != AutoRefuse || got.Reason != o.Reason {
				t.Errorf("%s: refusal became %s/%s", o.Canonical, got.Action, got.Reason)
			}
		case DecisionAbstain:
			if got.Action != AutoAbstain || got.Reason != o.Reason {
				t.Errorf("%s: abstention became %s/%s", o.Canonical, got.Action, got.Reason)
			}
		case DecisionPropose:
			if got.Action != AutoBlock {
				t.Errorf("%s: a proposal under a complete contract became %s", o.Canonical, got.Action)
			}
		}
	}
	_ = p
}

// TestARightsRefusalIsCarriedForwardWithItsIdentityStillWithheld.
//
// FINDING-120 and FINDING-126 are about a refusal that printed what it
// refused. A second renderer of the same decisions is a second chance to
// leak it.
func TestARightsRefusalIsCarriedForwardWithItsIdentityStillWithheld(t *testing.T) {
	p := autoPolicy(t, 1, completeAutomatic(5))
	src := testSource("src-a", nil)
	src.Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
	rep := run{
		asserts: []string{"src-a"},
		sources: []sourceregistry.Source{src, testSource("src-b", nil)},
		policy:  p,
		records: []feed.EvidenceRecord{adverse("src-a", "r1", "secret.example.com")},
	}.do(t)

	o := onlyAuto(t, Qualify(rep, p, AutoInputs{}))
	if o.Action != AutoRefuse {
		t.Fatalf("a rights refusal became %s", o.Action)
	}
	if !o.IdentityWithheld {
		t.Error("the withheld identity was not carried into the automatic plan")
	}
	if o.Canonical != "" {
		t.Errorf("the automatic plan named %q, which the report was not authorised to name", o.Canonical)
	}
	// And not anywhere else in the rendered plan either.
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret.example.com") {
		t.Errorf("the prohibited value appears in the serialised plan: %s", b)
	}
}

// --- the document ------------------------------------------------------

// TestAPresentAndMalformedAutomaticValueIsRefusedRatherThanIgnored.
func TestAPresentAndMalformedAutomaticValueIsRefusedRatherThanIgnored(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"a negative per-run limit":   func(a map[string]any) { a["max_additions_per_run"] = -1 },
		"a negative daily limit":     func(a map[string]any) { a["max_removals_per_day"] = -5 },
		"a lifetime that is no time": func(a map[string]any) { a["block_lifetime"] = "0s" },
		"an unparseable lifetime":    func(a map[string]any) { a["block_lifetime"] = "a fortnight" },
		"an outage word this build does not know": func(a map[string]any) {
			a["on_source_outage"] = "do_something_sensible"
		},
		"an empty alert channel": func(a map[string]any) { a["alert_channel"] = "   " },
		"an empty stop path":     func(a map[string]any) { a["emergency_disable_path"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			a := completeAutomatic(5)
			mutate(a)
			b, err := json.Marshal(map[string]any{
				"schema_version":          PolicySchemaVersion,
				"min_independent_sources": 2,
				"proposal_scope":          string(ScopeExact),
				"exceptions":              []map[string]any{},
				"automatic":               a,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePolicy(b); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// TestAnAbsentExceptionsKeyIsNotAnEmptyOne.
//
// Both decode to no exceptions. They are different statements about whether
// the household has been asked, and unattended blocking is exactly where that
// difference costs something.
func TestAnAbsentExceptionsKeyIsNotAnEmptyOne(t *testing.T) {
	mk := func(t *testing.T, withKey bool) *Policy {
		t.Helper()
		raw := map[string]any{
			"schema_version":          PolicySchemaVersion,
			"min_independent_sources": 2,
			"proposal_scope":          string(ScopeExact),
		}
		if withKey {
			raw["exceptions"] = []map[string]any{}
		}
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePolicy(b)
		if err != nil {
			t.Fatalf("policy refused: %v", err)
		}
		return p
	}
	with, without := mk(t, true), mk(t, false)
	if !with.ExceptionsStated() {
		t.Error("an empty exceptions list did not read as stated")
	}
	if without.ExceptionsStated() {
		t.Error("an absent exceptions key read as stated")
	}
	if with.Digest() == without.Digest() {
		t.Error("the two policies share an identity; a report could not tell them apart")
	}
}

// TestTheAutomaticContractIsInThePolicyIdentity.
//
// One field at a time, as item 4 of the order requires: changing any single
// value must move the digest, because a report cites the policy it was
// decided under and the contract decides whether anybody is asked.
func TestTheAutomaticContractIsInThePolicyIdentity(t *testing.T) {
	base := autoPolicy(t, 2, completeAutomatic(5)).Digest()

	if autoPolicy(t, 2, nil).Digest() == base {
		t.Error("a policy with no automatic block shares the identity of one with a complete contract")
	}

	for field, value := range map[string]any{
		"enabled":                true,
		"max_additions_per_run":  5,
		"max_removals_per_run":   1,
		"max_additions_per_day":  10,
		"max_removals_per_day":   10,
		"block_lifetime":         "720h",
		"on_source_outage":       string(OutageHold),
		"alert_channel":          "synthetic: the test suite is nobody's household",
		"emergency_disable_path": "/run/scamwall/synthetic-stop",
	} {
		t.Run("removing "+field, func(t *testing.T) {
			a := completeAutomatic(5)
			delete(a, field)
			if autoPolicy(t, 2, a).Digest() == base {
				t.Errorf("removing %s did not change the policy digest", field)
			}
			// And the positive control: putting the same value back restores
			// the original identity, so the digest moved BECAUSE of the field
			// rather than because the document was re-serialised.
			a[field] = value
			if autoPolicy(t, 2, a).Digest() != base {
				t.Errorf("restoring %s did not restore the digest", field)
			}
		})
	}
}

// TestEveryAutomaticReasonIsInTheVocabulary mirrors the proposal-side test:
// adding a code without deciding it is one should not be possible.
func TestEveryAutomaticReasonIsInTheVocabulary(t *testing.T) {
	known := map[Reason]bool{}
	for _, r := range append(append([]Reason(nil), AllReasons...), AutoReasons...) {
		known[r] = true
	}
	p := autoPolicy(t, 2, completeAutomatic(5))
	plan := Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{})
	for _, o := range plan.Outcomes {
		if !known[o.Reason] {
			t.Errorf("%s is not in either vocabulary", o.Reason)
		}
	}
}

// TestTheOutageBehaviourIsCarriedAndTheRunRecordsWhatItWasToldMeasures.
//
// The behaviour itself is consumed by a removal path this order does not
// build. What must be true NOW is that a plan says which behaviour was in
// force and which outage state it was computed against, so a plan read later
// is not silently reinterpreted under the other one.
func TestTheOutageBehaviourIsCarriedAndTheRunRecordsWhatItWasTold(t *testing.T) {
	for _, behaviour := range []OutageBehaviour{OutageHold, OutageExpire} {
		for _, outage := range []bool{false, true} {
			a := completeAutomatic(5)
			a["on_source_outage"] = string(behaviour)
			p := autoPolicy(t, 2, a)
			plan := Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{SourceOutage: outage})
			if plan.OutageBehaviour != behaviour {
				t.Errorf("behaviour = %q, want %q", plan.OutageBehaviour, behaviour)
			}
			if plan.SourceOutage != outage {
				t.Errorf("source outage recorded as %t, want %t", plan.SourceOutage, outage)
			}
		}
	}
}

// TestWhatTheContractDoesNotEnforceIsSaidInEveryPlan.
//
// Four of the nine required values are recorded and not acted on. A reader
// who sees a daily limit in the policy and a block in the plan must not be
// able to conclude the limit was checked.
func TestWhatTheContractDoesNotEnforceIsSaidInEveryPlan(t *testing.T) {
	p := autoPolicy(t, 2, completeAutomatic(5))
	for _, plan := range []*AutoPlan{
		Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{}),
		Qualify(twoAdverse(t, autoPolicy(t, 2, nil), "bad.example.com"), autoPolicy(t, 2, nil), AutoInputs{}),
		Qualify(nil, nil, AutoInputs{}),
	} {
		joined := strings.Join(plan.NotEnforced, " ")
		for _, want := range []string{
			"max_additions_per_day", "block_lifetime", "alert_channel", "emergency_disable_path",
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("a plan in state %s does not say that %s is not enforced", plan.State, want)
			}
		}
	}
}

// TestAnExplicitNullIsTheSameAsAnAbsentValue.
//
// deploy/compose/policy.example.json is written with every automatic value
// `null`, because a household filling in a blank needs to see the field names.
// A null that quietly meant something other than "not yet" would make that
// file a trap.
func TestAnExplicitNullIsTheSameAsAnAbsentValue(t *testing.T) {
	b := []byte(`{
	  "schema_version": 1,
	  "min_independent_sources": 2,
	  "proposal_scope": "exact",
	  "exceptions": [],
	  "automatic": {
	    "enabled": null,
	    "max_additions_per_run": null,
	    "max_removals_per_run": null,
	    "max_additions_per_day": null,
	    "max_removals_per_day": null,
	    "block_lifetime": null,
	    "on_source_outage": null,
	    "alert_channel": null,
	    "emergency_disable_path": null
	  }
	}`)
	p, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("a policy of explicit nulls was refused: %v", err)
	}
	plan := Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{})
	if plan.State != AutomaticUnresolved {
		t.Errorf("state = %s, want %s", plan.State, AutomaticUnresolved)
	}
	if len(plan.Unresolved) != len(automaticRequired) {
		t.Errorf("%d of %d values reported unresolved: %v",
			len(plan.Unresolved), len(automaticRequired), plan.Unresolved)
	}
	if len(plan.Blocks) != 0 {
		t.Error("a policy of explicit nulls authorised an unattended block")
	}
	// And it is NOT the same policy as one with no automatic block at all.
	if bare := autoPolicy(t, 2, nil); bare.Digest() == p.Digest() {
		t.Error("`automatic: {all null}` and no automatic key share a policy identity")
	}
}
