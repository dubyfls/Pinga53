// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import "testing"

// ORDER 8, control C-17, second half: "Protected domains and all their
// subdomains are refused."
//
// Status: **ALREADY-PRESENT**, under another name. This tree has no
// `protected_domains` field and does not need one — an `Exception` is the same
// statement, and `ReasonUserException` already outranks every source
// (TestTheHouseholdOutranksEverySource,
// TestALegitimateHouseholdExceptionIsRefusedAndNotMerelyNotBlocked).
//
// This is the control that says so, rather than the crosswalk asserting it.
// It exists because the claim has a sharp edge: `ScopeSubdomains` deliberately
// does NOT cover the apex, so protecting a bank means writing TWO entries.
// If a future change made `subdomains` include the apex, this test would still
// pass; if it made `exact` stop covering the apex, this test catches it.
//
// The two-entry requirement is recorded as an owner question in
// ORDER_8_PROGRESS.md: it is a documentation and example-file matter, not a
// missing control, and inventing a household's bank list is not an agent's
// decision (DESIGN_LEDGER DEC-003).
func TestAProtectedDomainAndItsSubdomainsAreCoveredByTwoExceptions(t *testing.T) {
	apex := Exception{Value: "bank.example.com", Scope: ScopeExact, Note: "the bank"}
	below := Exception{Value: "bank.example.com", Scope: ScopeSubdomains, Note: "and everything under it"}
	p := testPolicy(t, 1, ScopeExact, apex, below)

	for _, name := range []string{
		"bank.example.com",
		"login.bank.example.com",
		"secure.login.bank.example.com",
	} {
		if _, ok := p.MatchException(canon(t, name)); !ok {
			t.Errorf("%q matched no exception; a household that protected its bank "+
				"is not protected", name)
		}
	}

	// And the protection does not leak sideways onto a lookalike.
	for _, name := range []string{
		"bank.example.com.evil.org",
		"notbank.example.com",
		"example.com",
	} {
		if _, ok := p.MatchException(canon(t, name)); ok {
			t.Errorf("%q matched an exception meant for bank.example.com; a "+
				"protection that reaches a lookalike protects the attacker", name)
		}
	}
}

// TestOneExceptionAloneDoesNotProtectBoth is the sharp edge, asserted rather
// than described. It is why the owner question exists.
func TestOneExceptionAloneDoesNotProtectBoth(t *testing.T) {
	only := Exception{Value: "bank.example.com", Scope: ScopeSubdomains, Note: "children only"}
	p := testPolicy(t, 1, ScopeExact, only)

	if _, ok := p.MatchException(canon(t, "login.bank.example.com")); !ok {
		t.Error("a subdomains exception did not reach a subdomain")
	}
	if _, ok := p.MatchException(canon(t, "bank.example.com")); ok {
		t.Error("a subdomains exception reached the apex; ScopeSubdomains is " +
			"documented as covering every name strictly beneath and NOT the " +
			"name itself, and the apex decision is stated where it is implemented")
	}
}
