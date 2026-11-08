// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"sync"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT THIS FILE IS
//
// ORDER 6 Stage F: the public path exercised adversarially, not the helpers.
// Every case below goes through sign -> authenticate -> admit -> decide, which
// is what the command does, because a defect that only the helpers are immune
// to is not a defect anyone is protected from.
//
// A case that found nothing is kept and labelled. A red team that reports only
// its hits is indistinguishable from one that found nothing and said nothing.

// --- records: repeated, reordered, corrected -----------------------------

// TestReorderingRecordsDoesNotChangeTheAnswer.
//
// The store breaks ties by ingestion order and documents that it uses it for
// nothing else. If that were untrue, the same evidence shuffled would decide
// differently and a report would depend on the order a provider happened to
// serialise its file in.
func TestReorderingRecordsDoesNotChangeTheAnswer(t *testing.T) {
	forward := []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
		adverse("src-b", "b1", "one.example.com"),
		adverse("src-a", "a2", "two.example.com"),
		adverse("src-b", "b2", "three.example.com"),
	}
	reversed := make([]feed.EvidenceRecord, len(forward))
	for i, r := range forward {
		reversed[len(forward)-1-i] = r
	}

	base := run{asserts: []string{"src-a", "src-b"}, sources: twoSources(), policy: testPolicy(t, 2, ScopeExact)}

	a, b := base, base
	a.records, b.records = forward, reversed

	ra, rb := a.do(t), b.do(t)
	if len(ra.Outcomes) != len(rb.Outcomes) {
		t.Fatalf("reordering changed the indicator count: %d vs %d", len(ra.Outcomes), len(rb.Outcomes))
	}
	for i := range ra.Outcomes {
		x, y := ra.Outcomes[i], rb.Outcomes[i]
		if x.Canonical != y.Canonical || x.Decision != y.Decision || x.Reason != y.Reason {
			t.Errorf("outcome %d differs after a reorder:\n  %+v\n  %+v", i, x, y)
		}
		if strings.Join(x.Sources, ",") != strings.Join(y.Sources, ",") {
			t.Errorf("outcome %d has a different source set after a reorder: %v vs %v",
				i, x.Sources, y.Sources)
		}
	}
}

// TestACorrectionAppliedInTheOtherOrderIsNotTheSameStatement.
//
// **[non-discriminating, and recorded as a deliberate NON-finding.]**
// Reversing two revisions of one provider record DOES change which subject is
// live, and that is correct rather than a defect: rec-1 naming old then new is
// a different sequence of statements from rec-1 naming new then old, and the
// later one is the provider's current position in both. A harness that made
// the two agree would be discarding the revision order the provider published.
func TestACorrectionAppliedInTheOtherOrderIsNotTheSameStatement(t *testing.T) {
	base := run{asserts: []string{"src-a"}, sources: twoSources(), policy: testPolicy(t, 1, ScopeExact)}

	forward, backward := base, base
	forward.records = []feed.EvidenceRecord{
		adverse("src-a", "rec-1", "old.example.com"),
		adverse("src-a", "rec-1", "new.example.com"),
	}
	backward.records = []feed.EvidenceRecord{
		adverse("src-a", "rec-1", "new.example.com"),
		adverse("src-a", "rec-1", "old.example.com"),
	}

	live := func(rep *Report) string {
		for _, o := range rep.Outcomes {
			if o.Decision == DecisionPropose {
				return o.Canonical
			}
		}
		return "(none)"
	}
	f, b := live(forward.do(t)), live(backward.do(t))
	if f != "new.example.com" || b != "old.example.com" {
		t.Errorf("the later revision is not the live one: forward=%s backward=%s", f, b)
	}
}

// --- forged field boundaries ---------------------------------------------

// TestASourceIdCannotBeSmuggledPastTheAuthorityCheck.
//
// MayAssert compares whole strings. Every spelling below is an attempt to make
// one source id read as another.
func TestASourceIdCannotBeSmuggledPastTheAuthorityCheck(t *testing.T) {
	forged := []string{
		"src-a ", " src-a", "src-a\t", "src-a\n", "src-a\x00",
		"SRC-A", "Src-A",
		"src-a\x00src-nobody",
		"src-a" + string(rune(0x200b)),
		"src-a/../src-a",
		"src-a\nsrc-a",
	}
	for _, id := range forged {
		t.Run(strings.ReplaceAll(id, "\x00", "<NUL>"), func(t *testing.T) {
			rep := run{
				asserts: []string{"src-a"},
				sources: twoSources(),
				policy:  testPolicy(t, 1, ScopeExact),
				records: []feed.EvidenceRecord{adverse(id, "x1", "one.example.com")},
			}.do(t)
			if rep.Records[0].Admitted {
				t.Errorf("%q was admitted as src-a", id)
			}
			if rep.Records[0].Authority != feed.AuthorityNone {
				t.Errorf("%q resolved to authority %q", id, rep.Records[0].Authority)
			}
		})
	}
}

// TestAnOversizedProviderFieldIsRefusedRatherThanClipped.
//
// Clipping would admit a record under a source id that is not the one the
// document wrote, which is worse than refusing it.
func TestAnOversizedProviderFieldIsRefusedRatherThanClipped(t *testing.T) {
	long := "src-" + strings.Repeat("a", 4096)
	rep := run{
		asserts: []string{long, "src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{adverse(long, "x1", "one.example.com")},
	}.do(t)

	if rep.Records[0].Admitted {
		t.Error("a 4 KiB source id was admitted")
	}
	if len(rep.Records[0].SourceID) > 200 {
		t.Errorf("the refusal echoed %d bytes of it", len(rep.Records[0].SourceID))
	}
	if len(rep.Records[0].Explanation) > MaxExplanation {
		t.Errorf("the explanation is %d bytes, above the %d bound",
			len(rep.Records[0].Explanation), MaxExplanation)
	}
}

// --- mutation after insertion and through reads --------------------------

// TestAValidatedDocumentCannotBeEditedAfterItIsValidated.
//
// ValidatedEvidence.Records is an exported slice the caller still holds. The
// signature covered what the document said; if a record could be rewritten
// between the verification and the admission, the run would admit a claim
// under a source the signature never covered, while the report went on
// binding the ORIGINAL bytes by digest.
func TestAValidatedDocumentCannotBeEditedAfterItIsValidated(t *testing.T) {
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "k", pub, []string{"src-a", "src-b"}, nil)
	doc := signEvidence(t, priv, "k", "synthetic", []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
	})
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	reg := testRegistry(t, testSource("src-a", nil), testSource("src-b", nil))
	pol := testPolicy(t, 1, ScopeExact)

	if _, err := Build(Input{Evidence: ev, Registry: reg, Policy: pol, At: testAt}); err != nil {
		t.Fatalf("premise broken: the unmodified document does not build: %v", err)
	}

	// The edit: a claim the signer made about src-a becomes a claim about
	// src-b, which it also has authority over, so the authority check alone
	// would not catch it.
	ev.Records[0].SourceID = "src-b"

	_, err = Build(Input{Evidence: ev, Registry: reg, Policy: pol, At: testAt})
	if err == nil {
		t.Fatal("a document edited after it was authenticated was admitted; the report " +
			"would bind the original bytes while reporting something they do not say")
	}
	if !strings.Contains(err.Error(), "after it was authenticated") {
		t.Errorf("the refusal does not say what happened: %v", err)
	}
}

// TestTheSignersGrantCannotBeWidenedAfterTheDocumentIsAdmitted.
//
// The same defect from the other side. ValidatedEvidence carries a POINTER to
// the operator's signer record, so widening it after validation would let a
// document be consumed under an authority the operator did not grant when it
// was admitted.
func TestTheSignersGrantCannotBeWidenedAfterTheDocumentIsAdmitted(t *testing.T) {
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "k", pub, []string{"src-a"}, nil)
	doc := signEvidence(t, priv, "k", "synthetic", []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
		adverse("src-b", "b1", "one.example.com"),
	})
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	reg := testRegistry(t, testSource("src-a", nil), testSource("src-b", nil))
	pol := testPolicy(t, 1, ScopeExact)

	rep, err := Build(Input{Evidence: ev, Registry: reg, Policy: pol, At: testAt})
	if err != nil {
		t.Fatalf("premise broken: %v", err)
	}
	if rep.Records[1].Admitted {
		t.Fatal("premise broken: src-b was already admitted, so widening proves nothing")
	}

	ev.Signer.AssertsSourceIDs = append(ev.Signer.AssertsSourceIDs, "src-b")

	if _, err := Build(Input{Evidence: ev, Registry: reg, Policy: pol, At: testAt}); err == nil {
		t.Fatal("a grant widened after admission was honoured")
	}
}

// TestAReportDoesNotHandBackTheStateItWasBuiltFrom.
//
// A caller editing a returned slice must not change any other reader's view.
func TestAReportDoesNotHandBackTheStateItWasBuiltFrom(t *testing.T) {
	r := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-b", "b1", "one.example.com"),
		},
	}
	rep := r.do(t)
	before := only(t, rep)

	// Rewrite everything a caller can reach.
	rep.Outcomes[0].Sources[0] = "src-forged"
	rep.Outcomes[0].IndependentSources[0] = "src-forged"
	rep.Outcomes[0].Decision = DecisionRefuse

	again := only(t, r.do(t))
	if again.Sources[0] == "src-forged" || again.IndependentSources[0] == "src-forged" {
		t.Error("editing one report's slices changed what a second run reports")
	}
	if again.Decision != before.Decision {
		t.Error("editing one report changed a second run's decision")
	}
}

// TestEditingThePolicyAfterAMatchDoesNotChangeTheMatch.
//
// MatchException returns an Exception by value and the canonical form is
// unexported, so a caller holding a match cannot widen the rule that produced
// it. **[non-discriminating: this held on the first attempt.]**
func TestEditingThePolicyAfterAMatchDoesNotChangeTheMatch(t *testing.T) {
	p := testPolicy(t, 1, ScopeExact, Exception{Value: "bank.example.com", Scope: ScopeExact})
	m, ok := p.MatchException("bank.example.com")
	if !ok {
		t.Fatal("premise broken: the exception did not match")
	}
	m.Exception.Value = "example.com"
	m.Exception.Scope = ScopeSubdomains

	if _, ok := p.MatchException("other.example.com"); ok {
		t.Error("editing a returned match widened the policy")
	}
	if m2, ok := p.MatchException("bank.example.com"); !ok || m2.Exception.Scope != ScopeExact {
		t.Error("editing a returned match changed the stored rule")
	}
}

// --- malformed termination -----------------------------------------------

// TestASecondDocumentCannotRideAlong.
//
// Every one of the three operator/evidence documents holds exactly one JSON
// value, and a second appended after it must not be ignored.
func TestASecondDocumentCannotRideAlong(t *testing.T) {
	priv, pub := testKey(t, 0x31)

	t.Run("evidence", func(t *testing.T) {
		doc := signEvidence(t, priv, "k", "synthetic",
			[]feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")})
		auth := authorityOver(t, "k", pub, []string{"src-a"}, nil)
		trailing := append(append([]byte(nil), doc...), []byte(`{"schema_version":2}`)...)
		if _, err := feed.ValidateEvidence(trailing, feed.EvidenceOptions{
			MaxFileBytes: 1 << 20, MaxRecords: 10, Authority: auth, Now: testAt,
		}); err == nil {
			t.Error("a second document appended to the evidence was ignored")
		}
	})

	t.Run("signer authority", func(t *testing.T) {
		doc := `{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub +
			`","asserts_source_ids":["src-a"]}]}{"schema_version":1,"signers":[]}`
		if _, err := feed.ParseSignerAuthority([]byte(doc)); err == nil {
			t.Error("a second document appended to the authority was ignored")
		}
	})

	t.Run("policy", func(t *testing.T) {
		doc := `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact"}` +
			`{"schema_version":1,"min_independent_sources":99,"proposal_scope":"exact"}`
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Error("a second document appended to the policy was ignored")
		}
	})

	t.Run("bytes that are not a document at all", func(t *testing.T) {
		doc := `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact"} not json`
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Error("trailing garbage was ignored")
		}
	})
}

// --- grants: unknown, conditional, prohibited ----------------------------

// TestEveryGrantStatusIsGivenItsDocumentedMeaningAtThisBoundary.
//
// The registry package assigns these meanings; this asserts that the proposal
// path does not soften any of them on the way through.
func TestEveryGrantStatusIsGivenItsDocumentedMeaningAtThisBoundary(t *testing.T) {
	cases := []struct {
		name     string
		grant    sourceregistry.Grant
		admitted bool
	}{
		{"permitted", permittedGrant(), true},
		{"prohibited", prohibitedGrant(), false},
		{"unknown", unknownGrant(), false},
		{"not applicable", sourceregistry.Grant{Status: sourceregistry.GrantNotApplicable}, false},
		{"conditional, satisfied", conditionalGrant(sourceregistry.ConditionSatisfied), true},
		{"conditional, unsatisfied", conditionalGrant(sourceregistry.ConditionUnsatisfied), false},
		{"conditional, unknown", conditionalGrant(sourceregistry.ConditionUnknown), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srcs := twoSources()
			srcs[0].Permissions[sourceregistry.OpLocalStorage] = tc.grant
			rep := run{
				asserts: []string{"src-a"},
				sources: srcs,
				policy:  testPolicy(t, 1, ScopeExact),
				records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
			}.do(t)
			if got := rep.Records[0].Admitted; got != tc.admitted {
				t.Errorf("admitted = %v, want %v (%s)", got, tc.admitted, rep.Records[0].Explanation)
			}
		})
	}
}

// --- volume ---------------------------------------------------------------

// TestManyRefusalsDoNotInflateTheReport.
//
// Every record is refused and every refusal is reported. The bound is on what
// one refusal can say, not on how many there are — a document losing half its
// records silently is the failure this exists to make visible — so the
// assertion is that the report stays proportionate rather than that it is
// truncated.
func TestManyRefusalsDoNotInflateTheReport(t *testing.T) {
	const n = 900 // under the record bound the harness uses, so the run completes
	records := make([]feed.EvidenceRecord, 0, n)
	hostile := strings.Repeat("A", 2048)
	for i := 0; i < n; i++ {
		records = append(records, adverse("src-nobody-"+hostile, "x", "one.example.com"))
	}
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: records,
	}.do(t)

	if got := rep.Counts().RecordsRefused; got != n {
		t.Fatalf("%d of %d refusals reported", got, n)
	}
	var b strings.Builder
	rep.Text(&b)
	// Each refusal is bounded, so the total is bounded by the count. The
	// number below is generous and the point is the ORDER of magnitude: an
	// unbounded explanation would put 2 KiB per record into this.
	if got, max := b.Len(), n*600; got > max {
		t.Errorf("%d records produced a %d-byte report (bound %d)", n, got, max)
	}
	if strings.Contains(b.String(), strings.Repeat("A", 200)) {
		t.Error("an unbounded field reached the report")
	}
}

// --- concurrency -----------------------------------------------------------

// TestConcurrentRunsOverOneAuthorityAndRegistryAreIndependent.
//
// observation.Store is documented as not safe for concurrent use, and each run
// builds its own. What is SHARED between concurrent runs is the authority, the
// registry and the policy, all of which are read-only during a run. Run under
// -race, this is what says so.
func TestConcurrentRunsOverOneAuthorityAndRegistryAreIndependent(t *testing.T) {
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "k", pub, []string{"src-a", "src-b"}, nil)
	reg := testRegistry(t, testSource("src-a", nil), testSource("src-b", nil))
	pol := testPolicy(t, 2, ScopeExact, Exception{Value: "bank.example.com", Scope: ScopeExact})

	doc := signEvidence(t, priv, "k", "synthetic", []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
		adverse("src-b", "b1", "one.example.com"),
		adverse("src-a", "a2", "bank.example.com"),
		adverse("src-b", "b2", "bank.example.com"),
	})

	const workers = 16
	var wg sync.WaitGroup
	results := make([]string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
				MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
			})
			if err != nil {
				results[i] = "evidence: " + err.Error()
				return
			}
			rep, err := Build(Input{Evidence: ev, Registry: reg, Policy: pol, At: testAt})
			if err != nil {
				results[i] = "build: " + err.Error()
				return
			}
			var b strings.Builder
			rep.Text(&b)
			results[i] = b.String()
		}(i)
	}
	wg.Wait()

	for i := 1; i < workers; i++ {
		if results[i] != results[0] {
			t.Fatalf("worker %d produced a different report from worker 0", i)
		}
	}
	if !strings.Contains(results[0], "corroborated") || !strings.Contains(results[0], "user_exception") {
		t.Errorf("premise broken: the concurrent runs did not exercise the decision path:\n%s", results[0])
	}
}
