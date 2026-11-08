// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT THIS FILE IS ABOUT
//
// FINDING-120. `DecideIndicator` filled Canonical, Sources,
// IndependentSources, UnestablishedSources, Signals and the conflict flag
// BEFORE it asked whether `enrichment` and `derived_output` were authorised,
// and then returned a refusal carrying all of them. A report said
//
//	putting a result derived from these sources in a report is not authorised
//
// and printed the result underneath, in both formats, together with the
// record rows naming the same indicator.
//
// The correction is in the DATA MODEL, not in a renderer: the refusal returns
// an Outcome that never held a derived field, so there is nothing for either
// format to hide or to forget to hide.

// assertNoDisclosure fails if a value appears anywhere in either rendering.
//
// Both formats, because a control applied in one renderer is a control with a
// hole in it, and the JSON is the one a machine consumes.
func assertNoDisclosure(t *testing.T, rep *Report, value string) {
	t.Helper()
	var text strings.Builder
	rep.Text(&text)
	if strings.Contains(text.String(), value) {
		t.Errorf("the TEXT report discloses %q:\n%s", value, text.String())
	}
	var js strings.Builder
	if err := rep.JSON(&js); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.Contains(js.String(), value) {
		t.Errorf("the JSON report discloses %q:\n%s", value, js.String())
	}
}

// derivedOutcomeFields is every Outcome field that is computed FROM the
// provider's data, as opposed to being a fact about the operator's registry.
//
// Enumerated by name and checked against the struct by reflection, so a field
// added to Outcome without a decision about whether a refusal may carry it
// fails this file rather than quietly shipping.
var derivedOutcomeFields = []string{
	"Canonical", "Scope", "Sources", "IndependentSources",
	"UnestablishedSources", "AdverseSources", "AggregatedSources", "Signals", "Conflicted",
	// IndependentOriginGroups and SharedOrigins are DERIVED for the same
	// reason as Sources: they describe the provider data behind THIS
	// indicator. That a withheld indicator rests on one origin rather than
	// three is information about the indicator.
	"IndependentOriginGroups", "SharedOrigins", "AuthoritativeSources",
	// RetractedBy is DERIVED: it names which sources retracted what they said
	// about THIS indicator, which is a statement about the provider's data and
	// not about the operator's registry. A refusal must not carry it — that a
	// withheld indicator was retracted by two of four sources is information
	// about the indicator.
	"RetractedBy",
	"Exception",
}

// refusalPermittedFields is what a rights refusal MAY carry.
var refusalPermittedFields = []string{
	"Type", "Decision", "Reason", "Explanation",
	"IdentityWithheld", "RefusedSources",
	// ExportWithheld is a statement about the registry's grants, like
	// RefusedSources beside it, and not about the indicator. A refusal may
	// carry it: "and this one could not have been published either" tells a
	// reader which grant to go and read.
	"ExportWithheld",
	// OpaqueID may be carried by a refusal, and carrying it is the whole
	// point of C-09: the name is taken away and a KEYED identifier put in its
	// place, so two reports can agree they are about the same withheld host
	// while a third party holding one learns no hostname. The placement rests
	// entirely on the key being real — with no key the tag is the empty
	// string, so nothing is carried rather than something weaker.
	"OpaqueID",
}

// TestTheRefusalShapeIsDecidedForEveryOutcomeField.
//
// The two lists above must between them name exactly the fields Outcome has.
// A new field belongs in one of them, and choosing is the work.
func TestTheRefusalShapeIsDecidedForEveryOutcomeField(t *testing.T) {
	decided := map[string]bool{}
	for _, f := range append(append([]string(nil), derivedOutcomeFields...), refusalPermittedFields...) {
		if decided[f] {
			t.Errorf("%s appears in both lists, or twice in one", f)
		}
		decided[f] = true
	}
	rt := reflect.TypeOf(Outcome{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if !decided[name] {
			t.Errorf("Outcome.%s is in neither list: decide whether a rights refusal "+
				"may carry it before it can be reported at all", name)
		}
		delete(decided, name)
	}
	for name := range decided {
		t.Errorf("the lists name %s, which Outcome no longer has", name)
	}
}

// rightsRefusedRun is a two-source indicator where src-a's grant prohibits op
// and src-b permits everything.
//
// Two sources rather than one, because one source could be refused by
// accident of there being nothing else; two is where laundering would happen.
func rightsRefusedRun(t *testing.T, op sourceregistry.Operation, value string) *Report {
	t.Helper()
	srcs := twoSources()
	srcs[0].Permissions[op] = prohibitedGrant()
	return run{
		asserts: []string{"src-a", "src-b"},
		sources: srcs,
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", value),
			adverse("src-b", "b1", value),
		},
	}.do(t)
}

// TestARightsRefusalDisclosesNoResultOfTheProhibitedOperation.
func TestARightsRefusalDisclosesNoResultOfTheProhibitedOperation(t *testing.T) {
	// Named `withheld`, not `secret`: scripts/secret-scan.sh flags a `const
	// secret = "..."` literal, correctly, and the control is not weakened to
	// accommodate a test's choice of identifier.
	const withheld = "hidden.example.com"

	for _, tc := range []struct {
		op     sourceregistry.Operation
		reason Reason
	}{
		{sourceregistry.OpDerivedOutput, ReasonDerivedOutputRefused},
		{sourceregistry.OpEnrichment, ReasonEnrichmentRefused},
	} {
		t.Run(string(tc.op), func(t *testing.T) {
			rep := rightsRefusedRun(t, tc.op, withheld)
			o := only(t, rep)
			wantDecision(t, o, DecisionRefuse, tc.reason)

			// Field by field, by reflection, so this cannot pass because the
			// test happened to check the fields that were already empty.
			v := reflect.ValueOf(o)
			for _, name := range derivedOutcomeFields {
				f := v.FieldByName(name)
				if !f.IsZero() {
					t.Errorf("the refusal carries Outcome.%s = %v, which is derived "+
						"through the operation it says was refused", name, f.Interface())
				}
			}

			// And what it MUST carry, or the operator cannot act on it.
			if !o.IdentityWithheld {
				t.Error("the refusal does not distinguish `withheld` from `there was nothing`")
			}
			if len(o.RefusedSources) != 1 || o.RefusedSources[0] != "src-a" {
				t.Errorf("RefusedSources = %v; the refusal must name the grant to fix", o.RefusedSources)
			}
			if o.Type != "domain" {
				t.Errorf("Type = %q; the indicator type is not the provider's data and is kept", o.Type)
			}
			if !strings.Contains(o.Explanation, "src-a") {
				t.Errorf("the explanation does not name the refusing source: %q", o.Explanation)
			}

			// The record rows too — including src-b's, which permits
			// everything. Withholding only src-a's row would print the value
			// one row down.
			for _, rec := range rep.Records {
				if rec.Canonical != "" {
					t.Errorf("record %d (%s) names the indicator: %q",
						rec.Index, rec.SourceID, rec.Canonical)
				}
				if !rec.CanonicalWithheld {
					t.Errorf("record %d does not say the value was withheld rather than absent", rec.Index)
				}
			}

			assertNoDisclosure(t, rep, withheld)
		})
	}
}

// TestAPermittedRunStillReportsEverything is the positive control, and it is
// required: withholding unconditionally would satisfy every assertion above.
func TestAPermittedRunStillReportsEverything(t *testing.T) {
	const value = "visible.example.com"
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  testPolicy(t, 2, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", value),
			adverse("src-b", "b1", value),
		},
	}.do(t)

	o := only(t, rep)
	wantDecision(t, o, DecisionPropose, ReasonCorroborated)
	if o.Canonical != value {
		t.Errorf("Canonical = %q, want %q", o.Canonical, value)
	}
	if o.IdentityWithheld {
		t.Error("a permitted run withheld the identity")
	}
	if len(o.RefusedSources) != 0 {
		t.Errorf("a permitted run names refused sources: %v", o.RefusedSources)
	}
	if len(o.Sources) != 2 || len(o.IndependentSources) != 2 {
		t.Errorf("a permitted run lost its corroboration: %v / %v", o.Sources, o.IndependentSources)
	}
	for _, rec := range rep.Records {
		if rec.Canonical != value || rec.CanonicalWithheld {
			t.Errorf("record %d withheld a value it was permitted to name: %q withheld=%v",
				rec.Index, rec.Canonical, rec.CanonicalWithheld)
		}
	}
	var text strings.Builder
	rep.Text(&text)
	if !strings.Contains(text.String(), value) {
		t.Error("the permitted value does not appear in the report at all")
	}
}

// TestNoProhibitedContributionIsLaunderedThroughAPermittedSource.
//
// The indicator is asserted by a permitted source and a prohibited one. The
// permitted source's row is withheld too, because printing it would hand the
// reader the prohibited source's indicator.
func TestNoProhibitedContributionIsLaunderedThroughAPermittedSource(t *testing.T) {
	const shared = "shared.example.com"
	const clean = "clean.example.net"

	srcs := twoSources()
	srcs[0].Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: srcs,
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", shared),
			adverse("src-b", "b1", shared),
			// An indicator the prohibited source never touched. It must
			// survive: the rule is about the value src-a supplied, not about
			// every value in the document.
			adverse("src-b", "b2", clean),
		},
	}.do(t)

	assertNoDisclosure(t, rep, shared)

	byName := map[string]Outcome{}
	for _, o := range rep.Outcomes {
		byName[o.Canonical] = o
	}
	if _, ok := byName[clean]; !ok {
		t.Fatalf("the untouched indicator disappeared: %+v", rep.Outcomes)
	}
	var text strings.Builder
	rep.Text(&text)
	if !strings.Contains(text.String(), clean) {
		t.Error("an indicator the prohibited source never touched was withheld too")
	}
	// Exactly one record row still names a value, and it is the clean one.
	named := 0
	for _, rec := range rep.Records {
		if rec.Canonical != "" {
			named++
			if rec.Canonical != clean {
				t.Errorf("record %d names %q", rec.Index, rec.Canonical)
			}
		}
	}
	if named != 1 {
		t.Errorf("%d record rows name a value, want 1", named)
	}
}

// TestALapsedRecordFromARestrictedSourceIsStillThatSourcesData.
//
// # THIS TEST ASSERTED AN ASYMMETRY AND THE ASYMMETRY WAS A DEFECT
//
// Its first version said the RECORD row withholds a lapsed restricted
// source's value while the OUTCOME may still name it, on the ground that
// Indicator.Authorizes does not consult expired contributors.
//
// That ground is real and it answers a different question. "An expired
// contributor contributed nothing to a result computed at `at`" is about
// whether to REFUSE AN OPERATION on stale grounds. It says nothing about
// whether that contributor's indicator VALUE may be printed — and when it is
// the only contributor, printing the value is putting its data in front of
// someone against its grant.
//
// Found by the ORDER 7 red team driving the real process: the value appeared
// once in the report, in the abstention (FINDING-126). The rule is now that a
// value NO supplier permits naming does not appear anywhere, whatever the
// decision turned out to be.
func TestALapsedRecordFromARestrictedSourceIsStillThatSourcesData(t *testing.T) {
	lapsed := testAt.Add(-24 * time.Hour)
	expired := adverse("src-a", "a1", "lapsed.example.com")
	expired.ExpiresAt = &lapsed

	srcs := twoSources()
	srcs[0].Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: srcs,
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{expired},
	}.do(t)

	// No live contributor, so the rights gate is not reached and the outcome
	// is the ordinary expiry abstention.
	o := only(t, rep)
	wantDecision(t, o, DecisionAbstain, ReasonExpiredOnly)

	// The record row is nonetheless withheld: the record is src-a's data.
	if rep.Records[0].Canonical != "" || !rep.Records[0].CanonicalWithheld {
		t.Errorf("a lapsed record from a restricted source names its value: %q withheld=%v",
			rep.Records[0].Canonical, rep.Records[0].CanonicalWithheld)
	}

	// And so is the outcome: src-a is the ONLY supplier and it prohibits
	// naming its data in a report, so the value appears nowhere.
	if o.Canonical != "" || !o.IdentityWithheld {
		t.Errorf("the outcome names a value no supplier permits: %q withheld=%v",
			o.Canonical, o.IdentityWithheld)
	}
	assertNoDisclosure(t, rep, "lapsed.example.com")

	// THE OTHER HALF, and it is what stops the rule being "withhold whenever
	// anything is restricted": a permitted source that independently supplied
	// the same value makes the name its to give, so the outcome prints it.
	second := adverse("src-b", "b1", "lapsed.example.com")
	mixed := run{
		asserts: []string{"src-a", "src-b"},
		sources: srcs,
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{expired, second},
	}.do(t)
	m := only(t, mixed)
	if m.Canonical != "lapsed.example.com" {
		t.Errorf("a value a PERMITTED source supplied was withheld: %q", m.Canonical)
	}
}

// TestARefusedRecordNeverReachedAnIndicatorAtAll.
//
// A record refused at admission — unauthorised signer, unknown source, bad
// syntax — has no canonical to withhold and must not claim one was withheld.
func TestARefusedRecordNeverReachedAnIndicatorAtAll(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-b", "b1", "unauthorised.example.com"),
			adverse("src-a", "a1", "not a domain"),
		},
	}.do(t)

	for _, rec := range rep.Records {
		if rec.Admitted {
			t.Fatalf("record %d was admitted", rec.Index)
		}
		if rec.CanonicalWithheld {
			t.Errorf("record %d claims a value was withheld; none was ever derived", rec.Index)
		}
	}
	wantRefusal(t, rep, 0, ReasonSignerNotAuthorised)
	wantRefusal(t, rep, 1, ReasonValueInvalid)
}

// TestTheTextAndJSONFormatsRefuseTheSameThings.
//
// The boundary is in the data model, so the two renderings cannot disagree.
// This measures that claim rather than trusting it: whatever the text report
// shows for an indicator, the JSON shows for the same indicator, and neither
// shows what the other withholds.
func TestTheTextAndJSONFormatsRefuseTheSameThings(t *testing.T) {
	const withheld = "both.example.com"
	rep := rightsRefusedRun(t, sourceregistry.OpDerivedOutput, withheld)

	var text, js strings.Builder
	rep.Text(&text)
	if err := rep.JSON(&js); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{withheld, "both"} {
		if strings.Contains(text.String(), s) {
			t.Errorf("text discloses %q", s)
		}
		if strings.Contains(js.String(), s) {
			t.Errorf("JSON discloses %q", s)
		}
	}
	// Both must carry the actionable half.
	for name, out := range map[string]string{"text": text.String(), "JSON": js.String()} {
		if !strings.Contains(out, "src-a") {
			t.Errorf("%s does not name the refusing source", name)
		}
		if !strings.Contains(out, string(ReasonDerivedOutputRefused)) {
			t.Errorf("%s does not carry the reason code", name)
		}
	}
}
