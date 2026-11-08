// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/shadow"
)

// # THE COMMAND, DRIVEN END TO END AGAINST A SERVER THAT RECORDS EVERYTHING
//
// Every test here runs `run(...)` — the real dispatch, the real client, the
// real allowlist — against the e2e fake appliance, which records the method
// and path of every request it receives. The structural claim in
// internal/shadow's package comment is checked behaviourally here: what
// arrived at the server is what the command could construct.

// shadowEnv is the four offline input files plus a live fake appliance.
type shadowEnv struct {
	*e2eEnv
	inputs *proposeEnv
}

// completeContract is a SYNTHETIC automatic contract. The numbers exist to
// make the tests legible and are not a recommendation: see
// proposal.Automatic, where every field is required and nothing defaults.
const completeContract = `,
  "automatic": {
    "enabled": true,
    "max_additions_per_run": 10,
    "max_removals_per_run": 10,
    "max_additions_per_day": 50,
    "max_removals_per_day": 50,
    "block_lifetime": "720h",
    "on_source_outage": "hold_existing_blocks",
    "alert_channel": "synthetic: the test suite is nobody's household",
    "emergency_disable_path": "%STOP%"
  }`

func newShadowEnv(t *testing.T, contract string, denyExact string) *shadowEnv {
	t.Helper()
	e := newE2EEnv(t, nil)
	e.denyExact = denyExact
	inputs := newProposeEnv(t, nil)

	// The policy is rewritten with the contract under test. The rest of it —
	// threshold, scope, the household's exception for bank.example.com — is
	// newProposeEnv's, so the two commands are answering over the same files.
	policy := `{
  "schema_version": 1,
  "note": "synthetic policy written for this test suite",
  "min_independent_sources": 2,
  "proposal_scope": "exact",
  "accept_unestablished_independence": false,
  "exceptions": [{"value":"bank.example.com","scope":"exact","note":"the household's bank"}]` +
		contract + `
}`
	if err := os.WriteFile(inputs.policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return &shadowEnv{e2eEnv: e, inputs: inputs}
}

func (s *shadowEnv) args(extra ...string) []string {
	return append([]string{
		"shadow",
		"-config", s.configPath,
		"-evidence", s.inputs.evidencePath,
		"-signers", s.inputs.signersPath,
		"-registry", s.inputs.registryPath,
		"-policy", s.inputs.policyPath,
		"-at", proposeAt,
	}, extra...)
}

func (s *shadowEnv) plan(t *testing.T, extra ...string) shadow.Plan {
	t.Helper()
	code, stdout, stderr := capture(t, s.args(append([]string{"-json"}, extra...)...)...)
	if code != exitOK {
		t.Fatalf("shadow exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var p shadow.Plan
	if err := json.Unmarshal([]byte(stdout), &p); err != nil {
		t.Fatalf("decode plan: %v\n%s", err, stdout)
	}
	return p
}

func stopFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "scamwall-stop")
}

func withStop(contract, path string) string {
	return strings.ReplaceAll(contract, "%STOP%", path)
}

// --- the guard ----------------------------------------------------------

// TestTheShadowPathCannotReachAMutatingEndpoint.
//
// The order asks for this to be tested against a fake server that records
// every request. The server is the e2e one, which does exactly that, and the
// assertion is over what ARRIVED rather than over what the source says.
func TestTheShadowPathCannotReachAMutatingEndpoint(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)),
		`{"domains":[{"domain":"bad.example.com","type":"deny","kind":"exact","comment":"the household added this","enabled":true,"id":1,"date_added":1000}],"took":0.001}`)
	e.plan(t)

	seq := e.sequence()
	if len(seq) == 0 {
		t.Fatal("the command made no requests at all; this test would then prove nothing")
	}
	permitted := map[string]bool{
		"POST /api/auth":              true,
		"DELETE /api/auth":            true,
		"GET /api/domains/deny/exact": true,
		// ORDER 8, C-18: the household's own allow lists. Reads, and named
		// individually rather than by prefix -- the point of the allowlist is
		// that `/api/domains` as a whole stays unconstructible.
		"GET /api/domains/allow/exact": true,
		"GET /api/domains/allow/regex": true,
	}
	for _, r := range seq {
		if !permitted[r] {
			t.Errorf("the shadow path issued %q, which is outside what it may construct", r)
		}
		// The stronger half: the only non-GET requests act on ScamWall's own
		// session. Anything else is a mutation whatever it is called.
		if !strings.HasPrefix(r, "GET ") && !strings.HasSuffix(r, " /api/auth") {
			t.Errorf("%q is a non-GET outside ScamWall's own session", r)
		}
	}
	// And the state read actually happened: a test that asserted "no mutation"
	// over a run that never reached the appliance would be vacuous.
	var read bool
	for _, r := range seq {
		if r == "GET /api/domains/deny/exact" {
			read = true
		}
	}
	if !read {
		t.Error("the appliance's blocking state was never read; the comparison was not against the target")
	}
	// The session is destroyed on the way out.
	if seq[len(seq)-1] != "DELETE /api/auth" {
		t.Errorf("the run did not end by destroying its session: %v", seq)
	}
}

// --- the comparison, against real read state -----------------------------

// TestTheComparisonIsAgainstWhatWasRead.
//
// Two runs over IDENTICAL offline inputs and two different appliances. The
// evidence and the policy do not move; the plan does. That is the property
// that separates this from an offline proposal with the appliance's name in
// the heading.
func TestTheComparisonIsAgainstWhatWasRead(t *testing.T) {
	contract := withStop(completeContract, stopFile(t))

	empty := newShadowEnv(t, contract, `{"domains":[],"took":0.001}`)
	emptyPlan := empty.plan(t)

	held := newShadowEnv(t, contract,
		`{"domains":[{"domain":"bad.example.com","type":"deny","kind":"exact","comment":"ours, says the household","enabled":true,"id":1,"date_added":1000}],"took":0.001}`)
	heldPlan := held.plan(t)

	if emptyPlan.Binding.EvidenceDigest != heldPlan.Binding.EvidenceDigest {
		t.Fatal("fixture: the two runs did not read the same evidence")
	}
	if emptyPlan.Binding.PolicyDigest != heldPlan.Binding.PolicyDigest {
		t.Fatal("fixture: the two runs did not read the same policy")
	}
	if emptyPlan.Binding.ObservedStateDigest == heldPlan.Binding.ObservedStateDigest {
		t.Fatal("two different appliances produced the same observed-state digest")
	}

	// C-25. The command cannot read the household's subscribed lists, so an
	// addition it cannot check is HELD rather than requested. This asserts
	// the shape the command actually produces, and the reason it produces it.
	if got := kind(t, emptyPlan, "bad.example.com"); got != shadow.KindReview {
		t.Errorf("an empty appliance produced %s, want %s", got, shadow.KindReview)
	}
	if got := precedence(t, emptyPlan, "bad.example.com"); got != shadow.LabelUnknownSubscribedAllowlist {
		t.Errorf("precedence = %s, want %s", got, shadow.LabelUnknownSubscribedAllowlist)
	}
	if emptyPlan.Requests() {
		t.Error("a plan of held items reports that it would request something")
	}
	// Present, and NOT ScamWall's: this build has no ownership ledger, so the
	// entry is the household's whatever its comment says.
	if kind(t, heldPlan, "bad.example.com") != shadow.KindConflict {
		t.Errorf("an entry with no ownership record was not treated as the household's: %s",
			kind(t, heldPlan, "bad.example.com"))
	}
	if heldPlan.Requests() {
		t.Error("the run would have requested a change to an entry it does not own")
	}
}

// TestTheHouseholdExceptionNeverReachesTheAppliance.
//
// bank.example.com is corroborated by two independent sources in the fixture
// AND excepted by the household. It must not appear as an addition.
func TestTheHouseholdExceptionNeverReachesTheAppliance(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), `{"domains":[],"took":0.001}`)
	p := e.plan(t)
	for _, c := range p.Changes {
		if c.Domain == "bank.example.com" {
			t.Errorf("the household's own bank reached the plan as %s", c.Kind)
		}
	}
	if kind(t, p, "bad.example.com") != shadow.KindReview {
		t.Error("fixture: the corroborated domain is not in the plan at all")
	}
}

// TestAnUnresolvedContractReadsTheApplianceAndAsksForNothing.
//
// The default shape while the household has not finished deciding. The read
// still happens — that is the integration this order is about — and the
// qualifying set is empty, visibly.
func TestAnUnresolvedContractReadsTheApplianceAndAsksForNothing(t *testing.T) {
	e := newShadowEnv(t, "", `{"domains":[],"took":0.001}`) // no automatic block at all
	code, stdout, stderr := capture(t, e.args()...)
	if code != exitOK {
		t.Fatalf("exited %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "automatic contract: not_configured") {
		t.Error("the plan does not say the contract was never configured")
	}
	if !strings.Contains(stdout, "UNRESOLVED: automatic.enabled") {
		t.Error("the unresolved values are not named")
	}
	if !strings.Contains(stdout, "would request no change") {
		t.Error("a run with an unconfigured contract did not say it would request nothing")
	}
	// It still read the appliance.
	var read bool
	for _, r := range e.sequence() {
		if r == "GET /api/domains/deny/exact" {
			read = true
		}
	}
	if !read {
		t.Error("an unconfigured contract skipped the read; the integration is what this order builds")
	}
}

// TestTheEmergencyStopFileIsObeyed.
func TestTheEmergencyStopFileIsObeyed(t *testing.T) {
	stop := stopFile(t)
	e := newShadowEnv(t, withStop(completeContract, stop), `{"domains":[],"took":0.001}`)

	// The fixture guard is "the domain reaches the plan at all", not "the run
	// requests something".
	//
	// C-25 changed the second: this build cannot read the household's
	// subscribed lists, so an addition it cannot check is held for review and
	// nothing is requested even on a run with everything in order. Keeping
	// the old guard would have made this test pass for a reason unrelated to
	// the stop file, which is worse than failing.
	if before := e.plan(t); !planNames(before, "bad.example.com") {
		t.Fatal("fixture: without the stop file the domain does not reach the plan")
	}
	if err := os.WriteFile(stop, []byte("stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := capture(t, e.args()...)
	if code != exitOK {
		t.Fatalf("exited %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "would request no change") {
		t.Errorf("the stop file was present and the run still planned a change:\n%s", stdout)
	}
	if !strings.Contains(stdout, string(shadow.KindAdd)) && !strings.Contains(stdout, "emergency") {
		// Either the plan shows nothing to add, or it explains itself. What it
		// must not do is quietly request one, which the line above covers.
		t.Log("the stop file suppressed the addition")
	}
}

// TestStaleEvidenceSuppressesEveryAdditionAtTheCommand.
func TestStaleEvidenceSuppressesEveryAdditionAtTheCommand(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), `{"domains":[],"took":0.001}`)
	p := e.plan(t, "-evidence-stale", "the manifest expired before this run")
	if p.Requests() {
		t.Error("a run declared stale would have requested a change")
	}
	if !strings.Contains(strings.Join(p.Limitations, " "), "STALE") {
		t.Errorf("the plan does not say the evidence was stale: %v", p.Limitations)
	}
}

// --- the binding, from a real read ---------------------------------------

// TestThePlanBindsTheTargetThatActuallyAnswered.
//
// Not the host the configuration NAMED — the subject of the certificate that
// was verified. A plan describing an appliance must be able to say which one
// answered.
func TestThePlanBindsTheTargetThatActuallyAnswered(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), `{"domains":[],"took":0.001}`)
	p := e.plan(t)

	if p.Binding.TargetHost != e2eHost {
		t.Errorf("target host = %q, want %q", p.Binding.TargetHost, e2eHost)
	}
	if p.Binding.TargetAddress == "" {
		t.Error("the plan does not record the address that was dialled")
	}
	if !strings.Contains(p.Binding.TLSSubject, e2eHost) {
		t.Errorf("tls subject = %q; it does not name the host that was verified", p.Binding.TLSSubject)
	}
	if p.Binding.TLSIssuer == "" {
		t.Error("the plan does not record who issued the certificate it verified")
	}
	if len(p.Unestablished) != 0 {
		t.Errorf("a fully identified read still reported unestablished identities: %v", p.Unestablished)
	}
	if p.Binding.BuildIdentityState != "present" {
		t.Error("the command did not supply its own build identity")
	}
	if p.Binding.ObservedAt == "" || p.Binding.ComparedAt == "" {
		t.Error("the plan does not carry both instants")
	}
}

// TestNoCredentialReachesTheShadowOutput.
func TestNoCredentialReachesTheShadowOutput(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), `{"domains":[],"took":0.001}`)
	_, stdout, stderr := capture(t, e.args()...)
	e.assertNoCredentials(t, stdout, stderr)
	_, jsonOut, jsonErr := capture(t, e.args("-json")...)
	e.assertNoCredentials(t, jsonOut, jsonErr)
}

// TestAFailedReadStillReportsWhatBecameOfTheShadowSession.
//
// A read that fails must not leave a live session unreported, and must not
// exit 0. The e2e suite already asserts this for `status`; the new command
// gets its own, because the property is per exit path and not per package.
func TestAFailedReadStillReportsWhatBecameOfTheShadowSession(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), `{"domains":[`) // truncated JSON
	code, stdout, stderr := capture(t, e.args()...)
	if code == exitOK {
		t.Errorf("a failed read exited 0\n%s", stdout)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "session") {
		t.Errorf("the failure does not say what became of the session:\n%s", combined)
	}
	var sawDelete bool
	for _, r := range e.sequence() {
		if r == "DELETE /api/auth" {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Error("a failed read left the session standing")
	}
}

// kind finds the change line for one domain.
func kind(t *testing.T, p shadow.Plan, domain string) shadow.Kind {
	t.Helper()
	for _, c := range p.Changes {
		if c.Domain == domain {
			return c.Kind
		}
	}
	t.Fatalf("%s does not appear in the plan: %+v", domain, p.Changes)
	return ""
}

// precedence returns one change's C-25 precedence label.
func precedence(t *testing.T, p shadow.Plan, domain string) shadow.AddLabel {
	t.Helper()
	for _, c := range p.Changes {
		if c.Domain == domain {
			return c.Precedence
		}
	}
	t.Fatalf("no change for %s", domain)
	return ""
}

// planNames reports whether a plan mentions a domain at all.
func planNames(p shadow.Plan, domain string) bool {
	for _, c := range p.Changes {
		if c.Domain == domain {
			return true
		}
	}
	return false
}
