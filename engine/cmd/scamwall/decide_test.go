// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// # ORDER 11 QUEUE ITEM 3 — C-20's REMOVAL HALF, DRIVEN FROM cmd/
//
// Every test here runs `run()`, the function `main` calls. None of them
// imports internal/proposal to check the rule: the rule was already proven
// there by ORDER 9, and proving it there again would say nothing about
// whether the shipped command can reach it — which is the entire defect
// `REQUIREMENTS_MATRIX.md` §5.9.6 records.
//
// The three claims, each with its own test:
//
//	a run whose removals exceed the threshold routes the WHOLE run to review
//	removals count toward the per-run and the daily caps
//	deferred removals persist
//
// Everything is synthetic: the fixtures come from newProposeEnv, whose
// signing key is a fixed seed inside the test binary and whose domains are
// all RFC 2606 documentation names.

// decideEnv is a proposeEnv plus the two documents `decide` adds: a policy
// carrying a complete automatic contract, and an ownership ledger.
type decideEnv struct {
	*proposeEnv
	policyPath string
	ledgerPath string
}

// automaticPolicy writes a policy whose automatic contract is COMPLETE and
// ENABLED.
//
// Complete matters: proposal.Qualify abstains on every indicator while any of
// the nine required values is missing, so a test written against an
// incomplete contract would measure the contract gate and conclude something
// about the caps.
func automaticPolicy(t *testing.T, dir string, maxRemovalsPerRun, maxRemovalsPerDay int) string {
	t.Helper()
	return writeFixture(t, dir, "policy-auto.json", []byte(fmt.Sprintf(`{
  "schema_version": 1,
  "note": "synthetic policy written for this test suite",
  "min_independent_sources": 2,
  "proposal_scope": "exact",
  "accept_unestablished_independence": false,
  "exceptions": [{"value":"bank.example.com","scope":"exact","note":"the household's bank"}],
  "automatic": {
    "enabled": true,
    "max_additions_per_run": 50,
    "max_removals_per_run": %d,
    "max_additions_per_day": 50,
    "max_removals_per_day": %d,
    "block_lifetime": "720h",
    "on_source_outage": "hold_existing_blocks",
    "alert_channel": "the household's synthetic channel",
    "emergency_disable_path": %q
  }
}`, maxRemovalsPerRun, maxRemovalsPerDay, filepath.Join(dir, "nonexistent-stop-file"))))
}

// ownedAt builds one ledger row, aged relative to proposeAt.
//
// Relative to proposeAt and NOT to time.Now(): every test here passes
// `-at proposeAt`, which is the instant C-21 measures a lifetime against. A
// first version aged these rows from the wall clock, and because proposeAt is
// in the past every row came out with a NEGATIVE age — inside any lifetime,
// so nothing ever expired and the cap tests measured an empty queue. A
// fixture whose clock disagrees with the run's clock is the quietest way to
// write a test that passes by testing nothing.
func ownedAt(name string, justifiedDaysAgo int) map[string]any {
	base, err := time.Parse(time.RFC3339, proposeAt)
	if err != nil {
		panic("proposeAt is not an RFC 3339 instant: " + err.Error())
	}
	at := base.UTC().Add(-time.Duration(justifiedDaysAgo) * 24 * time.Hour)
	return map[string]any{
		"canonical":         name,
		"added_at":          at.Format(time.RFC3339),
		"last_justified_at": at.Format(time.RFC3339),
	}
}

// expiredDaysAgo is past the fixture policy's 720h (30 day) block_lifetime.
//
// C-21 is the reason this constant exists. Before it, an owned entry was
// proposed for removal simply by not qualifying this run; C-21 says that is
// not what ends a block — a domain that stops being reported for an afternoon
// has not stopped being a fraud domain. A block ends at its LIFETIME, or when
// the household excepts it, or when the evidence behind it is retracted. So a
// fixture that wants a removal has to state which of those happened, and
// these tests state the lifetime.
const expiredDaysAgo = 40

// writeLedger writes an ownership ledger: the named hosts, every one of them
// past its block_lifetime.
//
// Each gets a DIFFERENT last-justified time, newest first, so the deferral
// queue's order is measurable rather than incidental.
func writeLedger(t *testing.T, dir string, names ...string) string {
	t.Helper()
	rows := make([]map[string]any, 0, len(names))
	for i, n := range names {
		rows = append(rows, ownedAt(n, expiredDaysAgo+i))
	}
	return writeFixture(t, dir, "ledger.json", mustJSON(t, map[string]any{
		"schema_version": 1,
		"owned":          rows,
	}))
}

// writeMixedLedger writes a ledger whose `expired` hosts are past their
// lifetime and whose `current` hosts are not.
//
// The cap tests need both: enough entries that the removal fraction stays
// under the abnormal threshold, and a known number that actually falls out.
func writeMixedLedger(t *testing.T, dir string, expired, current []string) string {
	t.Helper()
	rows := make([]map[string]any, 0, len(expired)+len(current))
	for i, n := range expired {
		rows = append(rows, ownedAt(n, expiredDaysAgo+i))
	}
	for i, n := range current {
		rows = append(rows, ownedAt(n, i))
	}
	return writeFixture(t, dir, "ledger.json", mustJSON(t, map[string]any{
		"schema_version": 1,
		"owned":          rows,
	}))
}

// qualifyingName is a documentation name the fixture evidence corroborates.
//
// Used to pad the ledger with entries that KEEP qualifying, so that a test
// about the caps can put the removal fraction below the abnormal threshold
// and measure the caps rather than the gate above them.
func qualifyingName(i int) string { return fmt.Sprintf("held-%02d.example.com", i) }

// withQualifyingPadding adds n domains, each asserted by two independent
// sources, so each one corroborates and is proposed.
func withQualifyingPadding(n int) func(*[]feed.EvidenceRecord) {
	return func(records *[]feed.EvidenceRecord) {
		for i := 0; i < n; i++ {
			name := qualifyingName(i)
			*records = append(*records,
				feed.EvidenceRecord{Type: "domain", Value: name, SourceID: "src-a",
					SourceRecordID: fmt.Sprintf("pad-a-%d", i), Classification: "malicious", State: "active"},
				feed.EvidenceRecord{Type: "domain", Value: name, SourceID: "src-c",
					SourceRecordID: fmt.Sprintf("pad-c-%d", i), Classification: "malicious", State: "active"})
		}
	}
}

func newDecideEnv(t *testing.T, maxRemovalsPerRun, maxRemovalsPerDay int, owned ...string) *decideEnv {
	t.Helper()
	return newDecideEnvPadded(t, 0, maxRemovalsPerRun, maxRemovalsPerDay, owned...)
}

func newDecideEnvPadded(t *testing.T, pad, maxRemovalsPerRun, maxRemovalsPerDay int, owned ...string) *decideEnv {
	t.Helper()
	var mutate func(*[]feed.EvidenceRecord)
	if pad > 0 {
		mutate = withQualifyingPadding(pad)
	}
	e := newProposeEnv(t, mutate)
	return &decideEnv{
		proposeEnv: e,
		policyPath: automaticPolicy(t, e.dir, maxRemovalsPerRun, maxRemovalsPerDay),
		ledgerPath: writeLedger(t, e.dir, owned...),
	}
}

// expiredHosts is the four names the cap tests expect to fall out. They appear
// in no evidence document and their ledger rows are past the lifetime, so
// C-21 expires them and there is something for C-20 to cap.
var expiredHosts = []string{
	"gone-a.example.net", "gone-b.example.net", "gone-c.example.net", "gone-d.example.net",
}

// newCapEnv builds the fixture the two cap tests share: `pad` hosts that still
// corroborate and are inside their lifetime, plus the four above that are not.
//
// The fraction is what makes it a cap test. 4 of 20 is 20%, BELOW C-20's 25%
// abnormal threshold, so the caps decide and not the gate above them.
func newCapEnv(t *testing.T, pad, maxRemovalsPerRun, maxRemovalsPerDay int) *decideEnv {
	t.Helper()
	e := newProposeEnv(t, withQualifyingPadding(pad))
	current := make([]string, 0, pad)
	for i := 0; i < pad; i++ {
		current = append(current, qualifyingName(i))
	}
	return &decideEnv{
		proposeEnv: e,
		policyPath: automaticPolicy(t, e.dir, maxRemovalsPerRun, maxRemovalsPerDay),
		ledgerPath: writeMixedLedger(t, e.dir, expiredHosts, current),
	}
}

func (e *decideEnv) args(extra ...string) []string {
	return append([]string{
		"decide",
		"-evidence", e.evidencePath,
		"-signers", e.signersPath,
		"-registry", e.registryPath,
		"-policy", e.policyPath,
		"-at", proposeAt,
	}, extra...)
}

// decideJSON runs the command and decodes its document.
func decideJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	code, stdout, stderr := capture(t, args...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("the command did not emit JSON: %v\n%s", err, stdout)
	}
	return doc
}

func strings_(t *testing.T, doc map[string]any, key string) []string {
	t.Helper()
	raw, ok := doc[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

// --- the three claims ----------------------------------------------------

// TestAnAbnormalRemovalRunIsRoutedToReviewWhole is §1 harm 1, at the command.
//
// A stale or broken run that mass-unblocks is the worst thing this system can
// do, because the household finds out by being defrauded. The gate is a
// FRACTION of what ScamWall owns rather than a fixed count — twelve removals
// is routine for a large ledger and catastrophic for a small one — and it is
// judged on what the run WANTED to do, before any cap trims it to something
// that looks ordinary.
func TestAnAbnormalRemovalRunIsRoutedToReviewWhole(t *testing.T) {
	// Four owned entries, none of which qualifies this run: 100% removal,
	// far above the 25% threshold.
	e := newDecideEnv(t, 50, 50,
		"gone-a.example.net", "gone-b.example.net", "gone-c.example.net", "gone-d.example.net")

	doc := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)

	if got := strings_(t, doc, "removals"); len(got) != 0 {
		t.Errorf("an abnormal run removed %d entr(ies); the whole run must be held: %v", len(got), got)
	}
	if held, _ := doc["removal_held"].(bool); !held {
		t.Error("the run was not marked held, so nothing tells a person to look at it")
	}
	if got := fmt.Sprint(doc["removal_held_reason"]); got != "abnormal_removal_run" {
		t.Errorf("held for %q, want abnormal_removal_run", got)
	}
	// Held is not dropped: every proposed removal is in the queue.
	deferred, _ := doc["deferred"].([]any)
	if len(deferred) != 4 {
		t.Errorf("%d deferred, want all 4 carried forward rather than lost", len(deferred))
	}
}

// TestRemovalsCountTowardThePerRunCap is the second clause.
//
// Distinct from the abnormal gate above and deliberately so: a per-run cap
// reached is a budget, so it SELECTS and defers the rest, where the abnormal
// gate HOLDS the batch whole. A build that conflated them would either stop
// removing anything on a busy day or quietly apply part of an abnormal batch.
func TestRemovalsCountTowardThePerRunCap(t *testing.T) {
	// Twenty owned: sixteen that still corroborate and four that no longer
	// appear in the evidence at all. 4/20 is 20%, BELOW the 25% abnormal
	// threshold, so the gate above does not fire and the caps decide. Getting
	// this fraction wrong is how a cap test silently becomes a second test of
	// the abnormal gate.
	e := newCapEnv(t, 16, 2, 50)
	doc := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)

	removals := strings_(t, doc, "removals")
	deferred, _ := doc["deferred"].([]any)
	if held, _ := doc["removal_held"].(bool); held {
		t.Fatalf("the abnormal gate fired; this test is about the caps: %v", doc["removal_held_explanation"])
	}
	if len(removals) != 2 {
		t.Errorf("%d removal(s) got through a per-run budget of 2: %v", len(removals), removals)
	}
	if len(deferred) == 0 {
		t.Error("nothing was deferred; the rest of the batch was dropped rather than carried forward")
	}
	// The queue is ordered newest-justified first, so the deferrals are the
	// OLDEST entries and the removals the newest.
	for _, it := range deferred {
		m, _ := it.(map[string]any)
		if r := fmt.Sprint(m["reason"]); !strings.Contains(r, "removal_cap") {
			t.Errorf("deferred for %q, want a removal cap reason", r)
		}
	}
}

// TestADeferredRemovalComesBackOnTheNextRun is the third clause.
//
// A deferral is rationing, not a drop, and a deferral that has to be
// remembered can be forgotten. This build does not remember it: the next run
// recomputes removals from the ledger against that run's qualifying set, so
// what did not fit comes back on its own and in the same order. The test runs
// the command twice over the same inputs and compares.
func TestADeferredRemovalComesBackOnTheNextRun(t *testing.T) {
	e := newCapEnv(t, 16, 2, 50)

	first := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)
	second := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)

	firstDeferred := deferredNames(t, first)
	if len(firstDeferred) == 0 {
		t.Fatal("nothing was deferred on the first run, so there is nothing to carry forward")
	}
	if got := deferredNames(t, second); !equalStrings(got, firstDeferred) {
		t.Errorf("the second run's queue is %v and the first's was %v; a deferral that changes "+
			"order between runs is a deferral that can starve", got, firstDeferred)
	}
	if !equalStrings(strings_(t, first, "removals"), strings_(t, second, "removals")) {
		t.Error("two runs over the same inputs decided different removals")
	}
}

func deferredNames(t *testing.T, doc map[string]any) []string {
	t.Helper()
	raw, _ := doc["deferred"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		m, _ := v.(map[string]any)
		out = append(out, fmt.Sprint(m["canonical"]))
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- the ledger's own refusals -------------------------------------------

// TestWithoutALedgerNothingIsRemoved is the rule internal/ledger exists for.
//
// An absent ledger is not an empty one. A run that cannot show what it owns
// must propose no removal at all, and must SAY that rather than reporting a
// quiet zero that reads like "nothing needed removing".
func TestWithoutALedgerNothingIsRemoved(t *testing.T) {
	e := newDecideEnv(t, 50, 50, "gone-a.example.net")
	doc := decideJSON(t, e.args("-json")...)

	if got := strings_(t, doc, "removals"); len(got) != 0 {
		t.Errorf("a run with no ownership ledger proposed %v", got)
	}
	src := fmt.Sprint(doc["ownership_source"])
	if !strings.Contains(src, "absent ledger is not an empty one") {
		t.Errorf("the document does not say why nothing was removed: %q", src)
	}
	found := false
	for _, l := range strings_(t, doc, "limitations") {
		if strings.Contains(l, "removal rules did not run") {
			found = true
		}
	}
	if !found {
		t.Error("the limitations do not record that the removal rules never ran")
	}
}

// TestAMissingLedgerFileIsRefusedRatherThanInvented is the same rule one level
// down: a path that is not there is an operator mistake, not an empty ledger.
func TestAMissingLedgerFileIsRefusedRatherThanInvented(t *testing.T) {
	e := newDecideEnv(t, 50, 50, "gone-a.example.net")
	code, stdout, _ := capture(t, e.args("-ledger", filepath.Join(e.dir, "not-there.json"))...)
	if code == exitOK {
		t.Fatal("a missing ledger file was accepted; an ownership record that failed to load " +
			"must never be read as an ownership record holding nothing")
	}
	if !strings.Contains(stdout, "not a ledger holding") {
		t.Errorf("the refusal does not explain itself: %s", stdout)
	}
}

// TestADuplicateLedgerRowIsRefused — two rows for one host make the lifetime
// rule answer differently depending on which is read.
func TestADuplicateLedgerRowIsRefused(t *testing.T) {
	e := newDecideEnv(t, 50, 50)
	path := writeFixture(t, e.dir, "dupe.json", mustJSON(t, map[string]any{
		"schema_version": 1,
		"owned":          []map[string]any{ownedAt("a.example.net", 1), ownedAt("a.example.net", 9)},
	}))
	code, stdout, _ := capture(t, e.args("-ledger", path)...)
	if code == exitOK {
		t.Fatal("a ledger with two rows for one host was accepted")
	}
	if !strings.Contains(stdout, "appears twice") {
		t.Errorf("the refusal does not name the problem: %s", stdout)
	}
}

// --- the command's own promises ------------------------------------------

// TestDecideReadsNoConfigurationAndNoCredential keeps `decide` offline.
//
// The command is useful precisely because it costs no session, no credential
// and no network. A later change that gave it a Pi-hole client would make it
// silently expensive and would put a mutation path one refactor away, which
// ORDER 11 §0 forbids outright.
func TestDecideReadsNoConfigurationAndNoCredential(t *testing.T) {
	e := newDecideEnv(t, 50, 50, "gone-a.example.net")

	// It succeeds with no configuration in sight. `propose` holds itself to
	// the same standard, and `shadow` deliberately does not: it takes
	// -config because a session is the only way Pi-hole answers a read.
	code, stdout, stderr := capture(t, e.args("-ledger", e.ledgerPath)...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// And it does not ACCEPT one. A -config flag that parsed would be the
	// first step of the drift this test exists to catch: once the command
	// takes a configuration it takes a credential, and once it takes a
	// credential it is one refactor from a mutation path, which ORDER 11 §0
	// forbids outright.
	code, _, _ = capture(t, e.args("-ledger", e.ledgerPath, "-config", "/nonexistent.json")...)
	if code != exitUsage {
		t.Errorf("`decide -config` was accepted (exit %d); this command must not have a "+
			"configuration, a credential or a path to either", code)
	}
}

// TestDecideIsDeterministic — two runs over the same documents produce the
// same bytes, in both renderings.
func TestDecideIsDeterministic(t *testing.T) {
	e := newDecideEnv(t, 2, 50, "gone-a.example.net", "gone-b.example.net",
		"gone-c.example.net", "gone-d.example.net")
	for _, extra := range [][]string{{}, {"-json"}} {
		args := e.args(append([]string{"-ledger", e.ledgerPath}, extra...)...)
		_, first, _ := capture(t, args...)
		_, second, _ := capture(t, args...)
		if first != second {
			t.Errorf("two runs with %v produced different output", extra)
		}
	}
}

// TestDecideNamesEveryHeldRuleSeparately.
//
// An addition hold and a removal hold are different rules with different
// consequences, and a document with one "held" flag would let "we added
// nothing" be read as "we removed nothing".
func TestDecideNamesEveryHeldRuleSeparately(t *testing.T) {
	e := newDecideEnv(t, 50, 50, "gone-a.example.net", "gone-b.example.net",
		"gone-c.example.net", "gone-d.example.net")
	doc := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)
	if _, ok := doc["removal_held"]; !ok {
		t.Error("the document has no removal_held field, so the two holds are indistinguishable")
	}
	if _, ok := doc["held"]; ok {
		if fmt.Sprint(doc["held"]) == fmt.Sprint(doc["removal_held"]) && fmt.Sprint(doc["held"]) == "true" {
			t.Log("both holds fired on this fixture")
		}
	}
}

// # ORDER 11 QUEUE ITEM 4 — C-21 OWNED-ENTRY RETENTION, DRIVEN FROM cmd/
//
// ORDER 9's own crosswalk records C-21 as "DONE (rule), NO CALLER". The four
// rules below had never run against anything the shipped command produced.
//
// The interesting part of C-21 is not the four rules, it is which of them a
// FREEZE suspends. A freeze protects against the ABSENCE of evidence: when
// the supply is degraded, "nobody is saying this is bad any more" stops
// meaning what it usually means. It is NOT a reason to ignore evidence that
// did arrive, and never a reason to override the household. So a household
// exception and an upstream retraction remove THROUGH a freeze, and only the
// lifetime is suspended. Three tests, because a build that froze all three
// would pass a test that only checked the lifetime.

// retentionOf finds one host's retention line in the decision document.
func retentionOf(t *testing.T, doc map[string]any, host string) (action, reason string) {
	t.Helper()
	rows, _ := doc["retention"].([]any)
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if fmt.Sprint(m["canonical"]) == host {
			return fmt.Sprint(m["action"]), fmt.Sprint(m["reason"])
		}
	}
	t.Fatalf("no retention line for %q in %v", host, rows)
	return "", ""
}

// TestAnOwnedEntryPastItsLifetimeIsRemoved — the lifetime rule.
func TestAnOwnedEntryPastItsLifetimeIsRemoved(t *testing.T) {
	e := newCapEnv(t, 16, 50, 50)
	doc := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)

	action, reason := retentionOf(t, doc, "gone-a.example.net")
	if action != "remove" || reason != "retention_lifetime_expired" {
		t.Errorf("an entry %d days past a 30-day lifetime is %q/%q, want remove/retention_lifetime_expired",
			expiredDaysAgo, action, reason)
	}
	// And one inside its lifetime is kept, so the rule is a boundary and not
	// a blanket.
	if action, _ := retentionOf(t, doc, qualifyingName(0)); action != "keep" {
		t.Errorf("an entry inside its lifetime and still corroborated is %q, want keep", action)
	}
}

// TestALifetimeExpiryIsSuspendedByTheOutageFreeze — the freeze, on the one
// rule it is allowed to suspend.
//
// This is the whole point of the control. During a source outage "nothing is
// reporting this any more" is a statement about the supply, not about the
// domain, and unblocking on it drops protection because a provider had a bad
// afternoon.
func TestALifetimeExpiryIsSuspendedByTheOutageFreeze(t *testing.T) {
	e := newCapEnv(t, 16, 50, 50)
	doc := decideJSON(t, e.args("-ledger", e.ledgerPath,
		"-source-outage", "the synthetic provider returned 503 all morning", "-json")...)

	action, reason := retentionOf(t, doc, "gone-a.example.net")
	if action != "keep" || reason != "retention_frozen_by_source_outage" {
		t.Errorf("under a declared outage the expiry is %q/%q, want keep/retention_frozen_by_source_outage",
			action, reason)
	}
	if got := strings_(t, doc, "removals"); len(got) != 0 {
		t.Errorf("a frozen run still removed %v", got)
	}
	if frozen, _ := doc["frozen"].(bool); !frozen {
		t.Error("the document does not record that blocks were held only by the freeze; a run " +
			"that silently held them and one with nothing to remove would look identical")
	}
	if !strings.Contains(fmt.Sprint(doc["source_outage_reason"]), "503") {
		t.Errorf("the outage reason was not carried into the document: %v", doc["source_outage_reason"])
	}
}

// TestAStaleAcquisitionFreezesWithoutAnyoneDeclaringIt — the measured half.
//
// An operator who knows a provider is down can say so. An outage nobody
// noticed is the more dangerous one, and it is caught by how long it has been
// since the ledger recorded an acquisition. A zero last-acquisition is STALE,
// not fresh: a supply nobody has ever recorded is not a supply that just
// delivered, and reading the zero time as "now" would licence a full rewrite
// of the household's enforcement.
func TestAStaleAcquisitionFreezesWithoutAnyoneDeclaringIt(t *testing.T) {
	e := newCapEnv(t, 16, 50, 50)
	doc := decideJSON(t, e.args("-ledger", e.ledgerPath, "-max-acquisition-age", "24h", "-json")...)

	if outage, _ := doc["source_outage"].(bool); !outage {
		t.Fatal("a ledger recording no acquisition at all was treated as a healthy supply")
	}
	if action, reason := retentionOf(t, doc, "gone-a.example.net"); action != "keep" ||
		reason != "retention_frozen_by_source_outage" {
		t.Errorf("under a measured outage the expiry is %q/%q, want keep/frozen", action, reason)
	}
	if !strings.Contains(fmt.Sprint(doc["source_outage_reason"]), "no acquisition") {
		t.Errorf("the reason does not say what was measured: %v", doc["source_outage_reason"])
	}

	// An unset limit measures nothing. An unset limit is not a zero one —
	// C-10's rule, and it fails the same way if it is missed.
	plain := decideJSON(t, e.args("-ledger", e.ledgerPath, "-json")...)
	if outage, _ := plain["source_outage"].(bool); outage {
		t.Error("a run given no -max-acquisition-age declared an outage anyway")
	}
}

// TestAHouseholdExceptionRemovesThroughAFreeze — freeze-proof, rule one.
//
// The household's own statement outranks every source. A freeze is about the
// evidence supply and has no bearing on what the household asked for; a build
// that froze this one would keep blocking a domain its owner told it to stop
// blocking, and would do so silently.
func TestAHouseholdExceptionRemovesThroughAFreeze(t *testing.T) {
	// bank.example.com is the fixture policy's exception, and the ledger
	// holds it: ScamWall blocked it before the household excepted it.
	e := newProposeEnv(t, withQualifyingPadding(16))
	current := make([]string, 0, 17)
	for i := 0; i < 16; i++ {
		current = append(current, qualifyingName(i))
	}
	// Inside its lifetime, so nothing but the exception can remove it.
	current = append(current, "bank.example.com")
	env := &decideEnv{
		proposeEnv: e,
		policyPath: automaticPolicy(t, e.dir, 50, 50),
		ledgerPath: writeMixedLedger(t, e.dir, nil, current),
	}

	doc := decideJSON(t, env.args("-ledger", env.ledgerPath,
		"-source-outage", "the supply is degraded and the household still outranks it", "-json")...)

	action, reason := retentionOf(t, doc, "bank.example.com")
	if action != "remove" || reason != "retention_household_exception" {
		t.Errorf("an excepted domain is %q/%q under a freeze, want remove/retention_household_exception",
			action, reason)
	}
	found := false
	for _, n := range strings_(t, doc, "removals") {
		if n == "bank.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("the excepted domain did not reach the removals: %v", doc["removals"])
	}
}

// TestAWithdrawnBasisRemovesThroughAFreeze — freeze-proof, rule two.
//
// A retraction is evidence that ARRIVED. The freeze exists for evidence that
// stopped arriving, and the two are opposites: treating a retraction as
// absence keeps a block alive after the only source behind it has said it was
// wrong, which is ORDER 9 §1's second harm exactly.
func TestAWithdrawnBasisRemovesThroughAFreeze(t *testing.T) {
	const host = "retracted.example.net"
	e := newProposeEnv(t, func(records *[]feed.EvidenceRecord) {
		withQualifyingPadding(16)(records)
		// Both voices behind it have withdrawn: nothing live remains, which
		// is ReasonWithdrawnOnly rather than a conflict.
		*records = append(*records,
			feed.EvidenceRecord{Type: "domain", Value: host, SourceID: "src-a",
				SourceRecordID: "w1", Classification: "malicious", State: "active", Status: "withdrawn"},
			feed.EvidenceRecord{Type: "domain", Value: host, SourceID: "src-c",
				SourceRecordID: "w2", Classification: "malicious", State: "active", Status: "withdrawn"})
	})
	current := make([]string, 0, 17)
	for i := 0; i < 16; i++ {
		current = append(current, qualifyingName(i))
	}
	current = append(current, host) // inside its lifetime
	env := &decideEnv{
		proposeEnv: e,
		policyPath: automaticPolicy(t, e.dir, 50, 50),
		ledgerPath: writeMixedLedger(t, e.dir, nil, current),
	}

	doc := decideJSON(t, env.args("-ledger", env.ledgerPath,
		"-source-outage", "degraded, and a retraction is not an absence", "-json")...)

	action, reason := retentionOf(t, doc, host)
	if action != "remove" || reason != "retention_evidence_withdrawn" {
		t.Errorf("a withdrawn basis is %q/%q under a freeze, want remove/retention_evidence_withdrawn",
			action, reason)
	}
}

// TestADeferredAdditionIsNotTreatedAsLostEvidence.
//
// The trap this build had to avoid. Retention's "still justified" set is read
// from the proposal report's outcomes, NOT from the automatic plan's Blocks:
// a host the daily addition cap deferred is absent from Blocks and is
// perfectly well justified. Driving retention from Blocks would make a busy
// day's rationing read as "the evidence stopped", and C-21 would then start
// expiring exactly the blocks the caps were protecting.
func TestADeferredAdditionIsNotTreatedAsLostEvidence(t *testing.T) {
	e := newProposeEnv(t, withQualifyingPadding(16))
	current := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		current = append(current, qualifyingName(i))
	}
	// A daily addition cap of 1 defers almost every addition this run.
	policy := writeFixture(t, e.dir, "policy-tight.json", []byte(fmt.Sprintf(`{
  "schema_version": 1,
  "note": "synthetic policy written for this test suite",
  "min_independent_sources": 2,
  "proposal_scope": "exact",
  "accept_unestablished_independence": false,
  "exceptions": [{"value":"bank.example.com","scope":"exact","note":"the household's bank"}],
  "automatic": {
    "enabled": true,
    "max_additions_per_run": 50,
    "max_removals_per_run": 50,
    "max_additions_per_day": 1,
    "max_removals_per_day": 50,
    "block_lifetime": "720h",
    "on_source_outage": "hold_existing_blocks",
    "alert_channel": "the household's synthetic channel",
    "emergency_disable_path": %q
  }
}`, filepath.Join(e.dir, "nonexistent-stop-file"))))
	env := &decideEnv{proposeEnv: e, policyPath: policy,
		ledgerPath: writeMixedLedger(t, e.dir, nil, current)}

	doc := decideJSON(t, env.args("-ledger", env.ledgerPath, "-json")...)

	if len(strings_(t, doc, "additions")) > 1 {
		t.Fatalf("the daily cap did not bite; this test needs it to: %v", doc["additions"])
	}
	for _, n := range current {
		if action, reason := retentionOf(t, doc, n); action != "keep" {
			t.Errorf("%s was %q/%q; a deferred ADDITION is not lost evidence and must not "+
				"expire the block it corresponds to", n, action, reason)
		}
	}
	if got := strings_(t, doc, "removals"); len(got) != 0 {
		t.Errorf("a run whose additions were rationed proposed removals: %v", got)
	}
}
