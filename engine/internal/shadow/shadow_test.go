// SPDX-License-Identifier: AGPL-3.0-only

package shadow

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// # EVERYTHING HERE IS SYNTHETIC
//
// Every domain is under a documentation-reserved name from RFC 2606. No
// appliance is contacted by anything in this file; the observed state is a
// slice of values, which is exactly the shape Compare is built to take.

var (
	readAt     = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	comparedAt = time.Date(2026, 6, 1, 12, 0, 5, 0, time.UTC)
)

// observation builds a COMPLETE observation with every identity established,
// so a test about one thing is not also a test about missing identities.
func observation(entries ...Entry) Observation {
	return Observation{
		Entries:       entries,
		ReadAt:        readAt,
		TargetHost:    "pi.hole",
		TargetAddress: "127.0.0.1:443",
		TLSSubject:    "CN=pi.hole",
		TLSIssuer:     "CN=pi.hole,O=Pi-hole,C=DE",
		Complete:      true,
	}
}

func enabled(domain string, comment string) Entry {
	return Entry{Domain: domain, Enabled: true, Comment: comment}
}

func input(qualifying []string, obs Observation, owned Ownership) Input {
	return Input{
		Qualifying: qualifying,
		Observed:   obs,
		Owned:      owned,
		// ORDER 8, C-18. AllowNotRead is the honest default for the existing
		// cases: they were written before the allow lists were read at all, and
		// their subject is the deny comparison. The allow behaviour has its own
		// cases in allow_test.go, which pass an ObservedAllowList.
		Allow: AllowNotRead{},
		// C-25. These cases predate the precedence model and their subject is
		// the deny comparison, so they are given a subscription answer that was
		// READ and found nothing — which keeps them asserting what they were
		// written to assert. The not-read case is c25_test.go's, where it is the
		// subject rather than the backdrop.

		Subscribed:        subscribedNothing{},
		EvidenceDigest:    "sha256:evidence",
		PolicyDigest:      "sha256:policy",
		ReportEvaluatedAt: readAt.Format(time.RFC3339),
		ComparedAt:        comparedAt,
		BuildIdentity:     "scamwall test (synthetic)",
	}
}

func mustCompare(t *testing.T, in Input) *Plan {
	t.Helper()
	p, err := Compare(in)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	return p
}

func kindOf(t *testing.T, p *Plan, domain string) Kind {
	t.Helper()
	for _, c := range p.Changes {
		if c.Domain == domain {
			return c.Kind
		}
	}
	t.Fatalf("%s does not appear in the plan at all: %+v", domain, p.Changes)
	return ""
}

// --- the four categories the order names ---------------------------------

// TestTheFourCategoriesAreDecidedFromTheObservedStateAndTheOwnershipRecord.
func TestTheFourCategoriesAreDecidedFromTheObservedStateAndTheOwnershipRecord(t *testing.T) {
	owned := LedgerOwnership{
		Domains: map[string]bool{"kept.example.com": true, "stale.example.com": true},
		Origin:  "a synthetic ledger written by this test",
	}
	obs := observation(
		enabled("kept.example.com", "added by scamwall"),
		enabled("theirs.example.com", "the household added this one"),
		enabled("stale.example.com", "added by scamwall"),
	)
	p := mustCompare(t, input([]string{"new.example.com", "kept.example.com", "theirs.example.com"}, obs, owned))

	for domain, want := range map[string]Kind{
		"new.example.com":    KindAdd,
		"kept.example.com":   KindAlreadyPresent,
		"theirs.example.com": KindConflict,
		"stale.example.com":  KindRemove,
	} {
		if got := kindOf(t, p, domain); got != want {
			t.Errorf("%s: got %s, want %s", domain, got, want)
		}
	}
	if len(p.Changes) != 4 {
		t.Errorf("%d change lines, want 4: %+v", len(p.Changes), p.Changes)
	}
}

// TestAnEntryWithNoOwnershipRecordIsTheHouseholds.
//
// The central rule. Without a ledger every observed entry is theirs, whatever
// its domain looks like and whatever its comment says.
func TestAnEntryWithNoOwnershipRecordIsTheHouseholds(t *testing.T) {
	obs := observation(
		// A comment that says ScamWall put it there. It did not, or at least
		// nothing here establishes that it did.
		enabled("scam.example.com", "added automatically by scamwall"),
		// A domain that looks exactly like what ScamWall blocks.
		enabled("phishing-login.example.com", ""),
	)
	p := mustCompare(t, input(
		[]string{"scam.example.com", "phishing-login.example.com"}, obs, NoOwnership{}))

	for _, d := range []string{"scam.example.com", "phishing-login.example.com"} {
		if got := kindOf(t, p, d); got != KindConflict {
			t.Errorf("%s: got %s; with no ownership record every entry is the household's", d, got)
		}
	}
	if p.Requests() {
		t.Error("a plan over entries ScamWall does not own still requested something")
	}
	// And nothing is proposed for removal, for the stated reason rather than
	// by accident.
	if c := p.Counts(); c[KindRemove] != 0 {
		t.Errorf("%d removals with no ownership ledger", c[KindRemove])
	}
	if !strings.Contains(p.Binding.OwnershipSource, "no ownership ledger") {
		t.Errorf("the plan does not say where its ownership answers came from: %q",
			p.Binding.OwnershipSource)
	}
}

// TestADisabledEntryIsNotProtection.
func TestADisabledEntryIsNotProtection(t *testing.T) {
	obs := observation(Entry{Domain: "off.example.com", Enabled: false, Comment: "paused"})
	p := mustCompare(t, input([]string{"off.example.com"}, obs,
		LedgerOwnership{Domains: map[string]bool{"off.example.com": true}, Origin: "synthetic"}))

	if got := kindOf(t, p, "off.example.com"); got != KindDisabledEntry {
		t.Errorf("a disabled deny entry was reported as %s", got)
	}
	if p.Requests() {
		t.Error("ScamWall would re-enable somebody else's entry")
	}
}

// --- the five runs the order names ---------------------------------------

// TestAnUnchangedSecondRunIsByteIdentical.
//
// Same evidence, same policy, same appliance. Two runs must produce the same
// document, or a diff between two runs is not a diff between two answers.
func TestAnUnchangedSecondRunIsByteIdentical(t *testing.T) {
	in := input([]string{"a.example.com", "b.example.com"},
		observation(enabled("b.example.com", "theirs")), NoOwnership{})

	var first, second strings.Builder
	if err := mustCompare(t, in).JSON(&first); err != nil {
		t.Fatal(err)
	}
	if err := mustCompare(t, in).JSON(&second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Error("two runs over identical inputs produced different documents")
	}

	// The ORDER the appliance listed its entries in is not an answer. Two
	// reads that returned the same entries the other way round observed the
	// same appliance, and a digest over the response bytes would have made
	// every run look like a change.
	forwards := input(nil, observation(
		enabled("a.example.com", "one"), enabled("b.example.com", "two")), NoOwnership{})
	backwards := input(nil, observation(
		enabled("b.example.com", "two"), enabled("a.example.com", "one")), NoOwnership{})
	if mustCompare(t, forwards).Binding.ObservedStateDigest !=
		mustCompare(t, backwards).Binding.ObservedStateDigest {
		t.Error("the observed-state digest depends on the order the entries arrived in")
	}
	// And the control: a digest that ignored order would be useless if it
	// also ignored CONTENT.
	changed := input(nil, observation(
		enabled("a.example.com", "one"), enabled("c.example.com", "two")), NoOwnership{})
	if mustCompare(t, forwards).Binding.ObservedStateDigest ==
		mustCompare(t, changed).Binding.ObservedStateDigest {
		t.Error("two different appliance states share an observed-state digest")
	}
}

// TestTheObservedStateDigestMovesWhenTheApplianceDoes.
//
// The concurrent-change case. Nothing here can stop the appliance moving
// between two runs; what must be true is that the two plans SAY they compared
// against different states, so a reader is not left assuming the second is a
// restatement of the first.
func TestTheObservedStateDigestMovesWhenTheApplianceDoes(t *testing.T) {
	before := mustCompare(t, input([]string{"x.example.com"}, observation(), NoOwnership{}))
	after := mustCompare(t, input([]string{"x.example.com"},
		observation(enabled("x.example.com", "somebody blocked it while we were looking")), NoOwnership{}))

	if before.Binding.ObservedStateDigest == after.Binding.ObservedStateDigest {
		t.Fatal("the appliance changed and both plans claim the same observed state")
	}
	if kindOf(t, before, "x.example.com") != KindAdd {
		t.Error("the first run did not plan the addition")
	}
	if kindOf(t, after, "x.example.com") != KindConflict {
		t.Error("the second run did not see the entry that appeared")
	}
	// The window is stated: two instants, not one.
	if before.Binding.ObservedAt == "" || before.Binding.ComparedAt == "" {
		t.Error("a plan does not carry both instants, so the window in which the appliance " +
			"could move is not visible")
	}
}

// TestAnInterruptedReadIsRefusedRatherThanCompared.
//
// A partial list is not a smaller appliance. This is the case that silently
// produces the worst possible plan, so it is refused outright.
func TestAnInterruptedReadIsRefusedRatherThanCompared(t *testing.T) {
	obs := observation(enabled("seen.example.com", ""))
	obs.Complete = false

	_, err := Compare(input([]string{"a.example.com"}, obs, NoOwnership{}))
	if err == nil {
		t.Fatal("an incomplete read produced a plan")
	}
	if !strings.Contains(err.Error(), "did not complete") {
		t.Errorf("the refusal does not say what went wrong: %v", err)
	}

	// The positive control: the SAME observation with Complete set produces a
	// plan, so the refusal is about completeness and not about the entries.
	obs.Complete = true
	if _, err := Compare(input([]string{"a.example.com"}, obs, NoOwnership{})); err != nil {
		t.Fatalf("the complete form of the same read was also refused: %v", err)
	}
}

// TestStaleEvidenceSuppressesEveryAdditionAndSaysSo.
func TestStaleEvidenceSuppressesEveryAdditionAndSaysSo(t *testing.T) {
	in := input([]string{"a.example.com", "b.example.com"}, observation(), NoOwnership{})
	in.EvidenceStale = true
	in.StaleReason = "the evidence manifest expired at 2026-05-01T00:00:00Z"

	p := mustCompare(t, in)
	if p.Requests() {
		t.Error("a stale run would have requested a change")
	}
	if c := p.Counts(); c[KindAdd] != 0 {
		t.Errorf("%d additions survived a stale run", c[KindAdd])
	}
	// The domains are still SHOWN. A stale run and a run with nothing to do
	// must not produce the same document.
	if len(p.Changes) != 2 {
		t.Errorf("a stale run hid what it would have done: %+v", p.Changes)
	}
	joined := strings.Join(p.Limitations, " ")
	if !strings.Contains(joined, "STALE") || !strings.Contains(joined, "manifest expired") {
		t.Errorf("the plan does not say the evidence was stale: %v", p.Limitations)
	}
}

// TestAHouseholdExceptionNeverReachesTheQualifyingSet.
//
// The exception is applied by internal/proposal, which is where the household
// is a first-class party. What is measured here is the contract between the
// two: a domain absent from Qualifying produces no line at all, and — with an
// ownership record — produces a REMOVAL rather than being quietly left in
// place.
func TestAHouseholdExceptionNeverReachesTheQualifyingSet(t *testing.T) {
	obs := observation(enabled("bank.example.com", "placed by scamwall before the household objected"))
	owned := LedgerOwnership{Domains: map[string]bool{"bank.example.com": true}, Origin: "synthetic"}

	// Before the exception: it qualifies, ScamWall owns it, nothing changes.
	before := mustCompare(t, input([]string{"bank.example.com"}, obs, owned))
	if got := kindOf(t, before, "bank.example.com"); got != KindAlreadyPresent {
		t.Fatalf("fixture: got %s", got)
	}

	// After: the household excepted it, so it is not in the qualifying set,
	// and the block ScamWall placed is proposed for removal. This is the
	// corrected-false-block path end to end.
	after := mustCompare(t, input(nil, obs, owned))
	if got := kindOf(t, after, "bank.example.com"); got != KindRemove {
		t.Errorf("the correction produced %s rather than a removal", got)
	}
}

// --- the binding ---------------------------------------------------------

// TestEveryBindingFieldMovesWithTheInputItIdentifies.
//
// One input at a time, as item 4 of the order requires of the proposal
// binding. A field that does not move is a citation of something else.
func TestEveryBindingFieldMovesWithTheInputItIdentifies(t *testing.T) {
	base := input([]string{"a.example.com"}, observation(), NoOwnership{})
	baseline := mustCompare(t, base).Binding

	for name, mutate := range map[string]func(*Input){
		"evidence_digest":       func(in *Input) { in.EvidenceDigest = "sha256:other" },
		"policy_digest":         func(in *Input) { in.PolicyDigest = "sha256:other" },
		"report_evaluated_at":   func(in *Input) { in.ReportEvaluatedAt = "2026-07-01T00:00:00Z" },
		"observed_state_digest": func(in *Input) { in.Observed.Entries = []Entry{enabled("z.example.com", "")} },
		"target_host":           func(in *Input) { in.Observed.TargetHost = "other.invalid" },
		"target_address":        func(in *Input) { in.Observed.TargetAddress = "10.0.0.1:443" },
		"tls_subject":           func(in *Input) { in.Observed.TLSSubject = "CN=other" },
		"tls_issuer":            func(in *Input) { in.Observed.TLSIssuer = "CN=other-ca" },
		"observed_at":           func(in *Input) { in.Observed.ReadAt = readAt.Add(time.Hour) },
		"compared_at":           func(in *Input) { in.ComparedAt = comparedAt.Add(time.Hour) },
		"ownership_source": func(in *Input) {
			in.Owned = LedgerOwnership{Origin: "a different ownership record"}
		},
		"build_identity": func(in *Input) { in.BuildIdentity = "a different build" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutated.Observed.Entries = append([]Entry(nil), base.Observed.Entries...)
			mutate(&mutated)
			got := mustCompare(t, mutated).Binding
			if got == baseline {
				t.Errorf("changing %s changed no binding field", name)
			}
		})
	}
}

// TestAnIdentityTheProgramCannotEstablishIsStatedRatherThanOmitted.
func TestAnIdentityTheProgramCannotEstablishIsStatedRatherThanOmitted(t *testing.T) {
	bare := Observation{Entries: nil, ReadAt: readAt, Complete: true}
	p := mustCompare(t, input([]string{"a.example.com"}, bare, NoOwnership{}))

	if len(p.Unestablished) != 4 {
		t.Errorf("%d unestablished identities named, want 4: %v", len(p.Unestablished), p.Unestablished)
	}
	for _, want := range []string{"target_host", "target_address", "tls_subject", "tls_issuer"} {
		if !strings.Contains(strings.Join(p.Unestablished, " "), want) {
			t.Errorf("%s is not established and is not named", want)
		}
	}
	// The rendered text says it too, rather than printing an empty column.
	var b strings.Builder
	p.Text(&b)
	if !strings.Contains(b.String(), "NOT ESTABLISHED") {
		t.Error("the text rendering prints a blank where an unestablished identity belongs")
	}

	// The positive control: a fully identified observation names none.
	full := mustCompare(t, input([]string{"a.example.com"}, observation(), NoOwnership{}))
	if len(full.Unestablished) != 0 {
		t.Errorf("a fully identified observation reported %v", full.Unestablished)
	}
}

// TestBuildIdentityAbsenceIsAStatement mirrors the proposal report's position.
func TestBuildIdentityAbsenceIsAStatement(t *testing.T) {
	in := input([]string{"a.example.com"}, observation(), NoOwnership{})
	in.BuildIdentity = ""
	p := mustCompare(t, in)
	if p.Binding.BuildIdentityState != buildIdentityAbsent {
		t.Errorf("state = %q", p.Binding.BuildIdentityState)
	}
	var b strings.Builder
	p.Text(&b)
	if !strings.Contains(b.String(), "NOT SUPPLIED") {
		t.Error("an absent build identity is not reported as absent")
	}
}

// --- refusals ------------------------------------------------------------

// TestANilOwnershipIsRefusedRatherThanReadAsAnEmptyLedger.
func TestANilOwnershipIsRefusedRatherThanReadAsAnEmptyLedger(t *testing.T) {
	in := input([]string{"a.example.com"}, observation(), nil)
	if _, err := Compare(in); err == nil {
		t.Fatal("a nil ownership answer produced a plan")
	}
	// NoOwnership is the thing a caller with no ledger must pass, and it works.
	in.Owned = NoOwnership{}
	if _, err := Compare(in); err != nil {
		t.Fatalf("NoOwnership was refused: %v", err)
	}
}

// TestARepeatedObservedEntryDoesNotMaskADisabledOne.
//
// First occurrence wins. Taking the last would let a second, enabled entry
// for the same domain hide a first that is disabled, and report the household
// as protected when they are not.
func TestARepeatedObservedEntryDoesNotMaskADisabledOne(t *testing.T) {
	obs := observation(
		Entry{Domain: "dup.example.com", Enabled: false},
		Entry{Domain: "dup.example.com", Enabled: true},
	)
	p := mustCompare(t, input([]string{"dup.example.com"}, obs,
		LedgerOwnership{Domains: map[string]bool{"dup.example.com": true}, Origin: "synthetic"}))
	if got := kindOf(t, p, "dup.example.com"); got != KindDisabledEntry {
		t.Errorf("a repeated entry masked the disabled one: got %s", got)
	}
}

// TestTheSameQualifyingNameTwiceIsOneRequest.
func TestTheSameQualifyingNameTwiceIsOneRequest(t *testing.T) {
	p := mustCompare(t, input([]string{"a.example.com", "a.example.com"}, observation(), NoOwnership{}))
	if len(p.Changes) != 1 {
		t.Errorf("%d change lines for one name: %+v", len(p.Changes), p.Changes)
	}
}

// TestAHostileCommentIsBoundedAndStripped.
//
// The appliance's comment field is somewhere a person or a program can put
// arbitrary bytes, and this plan is printed to a terminal.
func TestAHostileCommentIsBoundedAndStripped(t *testing.T) {
	hostile := "\x1b[31mred\x1b[0m\r\nfake line" + strings.Repeat("A", 500)
	obs := observation(enabled("x.example.com", hostile))
	p := mustCompare(t, input([]string{"x.example.com"}, obs, NoOwnership{}))

	var b strings.Builder
	p.Text(&b)
	out := b.String()
	if strings.ContainsAny(out[:strings.Index(out, "what this plan")], "\x1b\r") {
		t.Error("a control character from the appliance's comment reached the rendered plan")
	}
	for _, c := range p.Changes {
		if len(c.ObservedComment) > maxComment+len("…") {
			t.Errorf("an observed comment of %d bytes was printed unbounded", len(c.ObservedComment))
		}
	}
}

// TestThePlanCarriesItsLimitationsInsideTheDocument.
func TestThePlanCarriesItsLimitationsInsideTheDocument(t *testing.T) {
	p := mustCompare(t, input([]string{"a.example.com"}, observation(), NoOwnership{}))
	var b strings.Builder
	if err := p.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal([]byte(b.String()), &round); err != nil {
		t.Fatal(err)
	}
	if _, ok := round["limitations"]; !ok {
		t.Error("the machine-readable plan does not carry its limitations")
	}
	joined := strings.Join(p.Limitations, " ")
	for _, want := range []string{
		"not a request", "imports no HTTP client", "ownership record", "left ALONE",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the limitations do not mention %q", want)
		}
	}
}
