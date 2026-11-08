// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// C-24 — a seal names its purpose, a sealed record is never accepted as a
// report, and verification checks every item by digest, host AND MAC.
//
// The three clauses are three different forgeries:
//
//   - A tag with no purpose can be replayed into any other place the same key
//     is used. internal/mac answers this half and proves it there.
//   - A record sealed in the store, presented as a report, is a claim that
//     somebody decided something when all that happened is that something was
//     written down.
//   - An item check that covers the digest and not the host lets an item be
//     moved onto another hostname; one that covers the host and not the
//     digest lets its decision be rewritten; one that covers both and not the
//     whole set lets an item be added or dropped.

func c24Report(t *testing.T) *Report {
	t.Helper()
	return run{
		asserts: []string{"src-a", "src-b"},
		sources: []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil)},
		policy:  testPolicy(t, 1, ScopeExact),
		records: adverseRecords("src-a", "src-b"),
	}.do(t)
}

func TestASealedReportVerifies(t *testing.T) {
	k := c09Key(t, 0x11)
	rep := c24Report(t)
	s := rep.Seal(k)
	if s == nil {
		t.Fatalf("Seal returned nothing")
	}
	if err := VerifySeal(rep, s, k); err != nil {
		t.Fatalf("a report did not verify against its own seal: %v", err)
	}
	if len(s.Items) != len(rep.Outcomes) {
		t.Errorf("the seal covers %d item(s) and the report has %d outcome(s)", len(s.Items), len(rep.Outcomes))
	}
}

func TestAnotherInstallationsKeyDoesNotVerify(t *testing.T) {
	rep := c24Report(t)
	s := rep.Seal(c09Key(t, 0x11))
	if err := VerifySeal(rep, s, c09Key(t, 0x22)); err == nil {
		t.Fatalf("a seal verified under a key that did not make it")
	}
}

// TestAnItemMovedOntoAnotherHostIsRefused — the check covers the host.
func TestAnItemMovedOntoAnotherHostIsRefused(t *testing.T) {
	k := c09Key(t, 0x11)
	rep := c24Report(t)
	s := rep.Seal(k)

	rep.Outcomes[0].Canonical = "someone-elses.example.org"
	err := VerifySeal(rep, s, k)
	if err == nil {
		t.Fatalf("an outcome was moved onto another hostname and the seal still verified")
	}
	if !strings.Contains(err.Error(), "someone-elses.example.org") &&
		!strings.Contains(err.Error(), "item") {
		t.Errorf("the failure does not say which item: %v", err)
	}
}

// TestARewrittenDecisionIsRefused — the check covers the substance.
func TestARewrittenDecisionIsRefused(t *testing.T) {
	k := c09Key(t, 0x11)
	rep := c24Report(t)
	s := rep.Seal(k)

	rep.Outcomes[0].Decision = DecisionRefuse
	if err := VerifySeal(rep, s, k); err == nil {
		t.Fatalf("an outcome's decision was rewritten and the seal still verified")
	}
}

// TestAnAddedOrRemovedItemIsRefused — the check covers the whole set, not
// only the items that happen to be present.
func TestAnAddedOrRemovedItemIsRefused(t *testing.T) {
	k := c09Key(t, 0x11)

	t.Run("removed", func(t *testing.T) {
		rep := c24Report(t)
		s := rep.Seal(k)
		rep.Outcomes = rep.Outcomes[:len(rep.Outcomes)-1]
		if err := VerifySeal(rep, s, k); err == nil {
			t.Fatalf("an outcome was dropped and the seal still verified")
		}
	})

	t.Run("added", func(t *testing.T) {
		rep := c24Report(t)
		s := rep.Seal(k)
		rep.Outcomes = append(rep.Outcomes, Outcome{
			Type: "domain", Canonical: "smuggled.example.com",
			Decision: DecisionPropose, Reason: ReasonCorroborated,
		})
		if err := VerifySeal(rep, s, k); err == nil {
			t.Fatalf("an outcome was smuggled in and the seal still verified")
		}
	})
}

// TestTheBindingIsCovered — a report moved onto another evidence document,
// policy or instant is a different report.
func TestTheBindingIsCovered(t *testing.T) {
	k := c09Key(t, 0x11)
	rep := c24Report(t)
	s := rep.Seal(k)
	rep.Binding.PolicyDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifySeal(rep, s, k); err == nil {
		t.Fatalf("the policy the report was decided under was changed and the seal still verified")
	}
}

// TestASealedRecordIsNeverAcceptedAsAReport is the clause the control names.
func TestASealedRecordIsNeverAcceptedAsAReport(t *testing.T) {
	k := c09Key(t, 0x11)
	rep := c24Report(t)
	s := rep.Seal(k)

	t.Run("a seal claiming the store purpose is refused outright", func(t *testing.T) {
		forged := *s
		forged.Purpose = string(mac.PurposeStoreBinding)
		err := VerifySeal(rep, &forged, k)
		if err == nil {
			t.Fatalf("a store seal was accepted as a report seal")
		}
		if !strings.Contains(err.Error(), string(mac.PurposeStoreBinding)) {
			t.Errorf("the failure does not name the purpose it was given: %v", err)
		}
	})

	t.Run("and the tags themselves do not transfer", func(t *testing.T) {
		// Even with the label corrected back, a tag computed under the store
		// purpose over the same bytes is a different tag. This is the half
		// that holds when somebody rewrites the label.
		forged := *s
		forged.Items = append([]ItemSeal(nil), s.Items...)
		forged.Items[0].Tag = k.Tag(mac.PurposeStoreBinding, itemSealMessage(s.Items[0]))
		if err := VerifySeal(rep, &forged, k); err == nil {
			t.Fatalf("a store-purpose tag verified as a report-purpose tag")
		}
	})
}

func TestNoKeyMeansNoSealRatherThanAnEmptyOne(t *testing.T) {
	rep := c24Report(t)
	if s := rep.Seal(nil); s != nil {
		t.Fatalf("a run with no key produced a seal: %+v", s)
	}
	// And a verifier handed nothing must refuse rather than report success.
	if err := VerifySeal(rep, nil, c09Key(t, 0x11)); err == nil {
		t.Fatalf("verification of an absent seal succeeded")
	}
	if err := VerifySeal(rep, rep.Seal(c09Key(t, 0x11)), nil); err == nil {
		t.Fatalf("verification with no key succeeded")
	}
}

// TestAWithheldItemIsSealedByItsOpaqueIdentifier — a report that may not name
// a host must still be able to prove nobody swapped the item, and C-09's
// identifier is what it has instead of the name.
func TestAWithheldItemIsSealedByItsOpaqueIdentifier(t *testing.T) {
	k := c09Key(t, 0x11)
	rep := run{
		asserts:     []string{"src-a"},
		sources:     []sourceregistry.Source{localOnly("src-a")},
		policy:      testPolicy(t, 1, ScopeExact),
		records:     adverseRecords("src-a"),
		identityKey: k,
	}.do(t).ForAudience(AudienceExport)

	s := rep.Seal(k)
	if err := VerifySeal(rep, s, k); err != nil {
		t.Fatalf("an export report did not verify against its own seal: %v", err)
	}
	for _, it := range s.Items {
		if strings.Contains(it.Host, "example.com") {
			t.Errorf("the seal names a host the report withheld: %s", it.Host)
		}
		if it.Host == "" {
			t.Errorf("a withheld item is sealed under no identity at all; two items could be swapped")
		}
	}
}

// TestEveryOutcomeFieldIsCoveredBySomeDecision.
//
// itemSubstance enumerates the fields it digests rather than reflecting over
// them, for the reason internal/observation's observationDigest gives: a field
// added to Outcome and not added there is invisible to the seal, and no test
// notices because the seal still verifies.
//
// So the enumeration is checked against the struct. A field belongs in
// `sealedOutcomeFields` — covered, so changing it breaks the seal — or in
// `unsealedOutcomeFields`, and choosing is the work.
func TestEveryOutcomeFieldIsCoveredBySomeDecision(t *testing.T) {
	// Nothing is deliberately outside the seal today. The list exists so that
	// the next field which should be can say so in one line, rather than
	// being left out by silence.
	unsealedOutcomeFields := map[string]bool{}

	sealed := map[string]bool{}
	for _, f := range []string{
		"Type", "Canonical", "IdentityWithheld", "ExportWithheld", "OpaqueID", "Scope",
		"Decision", "Reason", "Explanation", "Sources", "IndependentSources",
		"UnestablishedSources", "AdverseSources", "AggregatedSources",
		"AuthoritativeSources", "RefusedSources", "RetractedBy", "SharedOrigins",
		"IndependentOriginGroups", "Signals", "Conflicted", "Exception",
	} {
		sealed[f] = true
	}

	rt := reflect.TypeOf(Outcome{})
	for i := range rt.NumField() {
		name := rt.Field(i).Name
		if !sealed[name] && !unsealedOutcomeFields[name] {
			t.Errorf("Outcome.%s is in neither list: decide whether the seal covers it. A field "+
				"the seal does not cover can be changed without the seal noticing", name)
		}
		delete(sealed, name)
	}
	for name := range sealed {
		t.Errorf("itemSubstance names %s, which Outcome no longer has", name)
	}
}

// TestTheEnumerationIsActuallyWhatIsDigested — the list above is a list. This
// asserts the function agrees with it, by changing each covered field on a
// real outcome and requiring the digest to move.
func TestTheEnumerationIsActuallyWhatIsDigested(t *testing.T) {
	base := Outcome{
		Type: "domain", Canonical: "bad.example.com",
		Decision: DecisionPropose, Reason: ReasonCorroborated, Explanation: "x",
	}
	before := itemSubstance(base)

	mutate := map[string]func(*Outcome){
		"Type":                    func(o *Outcome) { o.Type = "url" },
		"Canonical":               func(o *Outcome) { o.Canonical = "other.example.com" },
		"IdentityWithheld":        func(o *Outcome) { o.IdentityWithheld = true },
		"ExportWithheld":          func(o *Outcome) { o.ExportWithheld = true },
		"OpaqueID":                func(o *Outcome) { o.OpaqueID = "abc" },
		"Scope":                   func(o *Outcome) { o.Scope = ScopeSubdomains },
		"Decision":                func(o *Outcome) { o.Decision = DecisionRefuse },
		"Reason":                  func(o *Outcome) { o.Reason = ReasonConflict },
		"Explanation":             func(o *Outcome) { o.Explanation = "y" },
		"Sources":                 func(o *Outcome) { o.Sources = []string{"src-a"} },
		"IndependentSources":      func(o *Outcome) { o.IndependentSources = []string{"src-a"} },
		"UnestablishedSources":    func(o *Outcome) { o.UnestablishedSources = []string{"src-a"} },
		"AdverseSources":          func(o *Outcome) { o.AdverseSources = []string{"src-a"} },
		"AggregatedSources":       func(o *Outcome) { o.AggregatedSources = []string{"src-a"} },
		"AuthoritativeSources":    func(o *Outcome) { o.AuthoritativeSources = []string{"src-a"} },
		"RefusedSources":          func(o *Outcome) { o.RefusedSources = []string{"src-a"} },
		"RetractedBy":             func(o *Outcome) { o.RetractedBy = []string{"src-a"} },
		"SharedOrigins":           func(o *Outcome) { o.SharedOrigins = []string{"corpus"} },
		"IndependentOriginGroups": func(o *Outcome) { o.IndependentOriginGroups = 3 },
		"Signals":                 func(o *Outcome) { o.Signals = []string{"mixed_script"} },
		"Conflicted":              func(o *Outcome) { o.Conflicted = true },
		"Exception":               func(o *Outcome) { o.Exception = &AppliedException{Canonical: "x"} },
	}
	for name, f := range mutate {
		o := base
		f(&o)
		if itemSubstance(o) == before {
			t.Errorf("changing %s did not change the digest; the seal does not cover it", name)
		}
	}
}
