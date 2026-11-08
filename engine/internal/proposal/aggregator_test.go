// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT THIS FILE IS ABOUT
//
// FINDING-122. One signer, granted `aggregator_for` over two source ids, in
// ONE signed document, satisfied `min_independent_sources: 2` by itself and
// the report said `corroborated`.
//
// # THE TRACE, FROM GRANT TO COUNT
//
//	Signer.MayAssert(id)       -> AuthorityAggregator
//	RecordOutcome.Authority    -> "aggregator"           <- recorded here
//	observation.New(...)       -> SourceID only          <- and LOST here
//	store.Add                  -> filed under that id
//	Indicator.Corroborate      -> two distinct live source ids
//	registry lineage collapse  -> no shared upstream recorded, so two
//	threshold                  -> 2 >= 2, propose
//
// The provenance survived as far as the report and was gone by the time
// anything counted. `internal/observation` is the right place for it to be
// absent: an Observation is one SOURCE's statement, and how ScamWall came to
// hear it is a property of this run rather than of the statement. So the
// channel is carried beside the store, in Attribution, built from the grant
// that actually admitted each record.
//
// # THE RULE, AND THE PROJECT'S OWN INDEPENDENCE POSITION
//
// internal/sourceregistry: "Independence is a property of what is known about
// lineage, and a record that says `independent` while its upstreams are
// undocumented is asserting the absence of evidence as evidence of absence."
//
// That is about lineage BETWEEN SOURCES. The aggregator question is about the
// CHANNEL: two claims that reached this build through one signer are one
// attestation, however independent the sources are of each other. If that
// signer is wrong, compromised, or simply reformats one upstream into two
// source ids, both claims are wrong together.
//
// So an aggregated claim is evidence and is not independent confirmation, and
// it does not count towards the threshold. The operator who wants it to count
// grants that signer `asserts_source_ids` — which is the operator saying the
// signer speaks for that source in its own right. The schema already had the
// knob; this makes it load-bearing.

// aggregatorRun is the end-to-end case: one signer, one document, two source
// ids, and a threshold the aggregated claims alone would meet.
func aggregatorRun(t *testing.T, asserts, aggregates []string, threshold int) *Report {
	t.Helper()
	return run{
		asserts:    asserts,
		aggregates: aggregates,
		sources: []sourceregistry.Source{
			testSource("src-a", nil), testSource("src-b", nil), testSource("src-c", nil),
		},
		policy: testPolicy(t, threshold, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-b", "b1", "one.example.com"),
		},
	}.do(t)
}

// TestOneAggregatorIsOneAttestationHoweverManySourcesItCarries.
func TestOneAggregatorIsOneAttestationHoweverManySourcesItCarries(t *testing.T) {
	rep := aggregatorRun(t, nil, []string{"src-a", "src-b"}, 2)
	o := only(t, rep)

	wantDecision(t, o, DecisionAbstain, ReasonAggregatedNotIndependent)
	if len(o.AdverseSources) != 0 {
		t.Errorf("an aggregated claim was counted as independent: %v", o.AdverseSources)
	}
	if len(o.AggregatedSources) != 2 {
		t.Errorf("AggregatedSources = %v, want both source ids reported", o.AggregatedSources)
	}
	// It is still EVIDENCE and the report says so, or an operator would think
	// the claims had been discarded.
	if !strings.Contains(o.Explanation, "REPUBLISH") {
		t.Errorf("the explanation does not say why the claims did not count: %q", o.Explanation)
	}
	// And both records were admitted; nothing was refused at the boundary.
	for _, rec := range rep.Records {
		if !rec.Admitted {
			t.Errorf("record %d was refused; an aggregated claim is admissible", rec.Index)
		}
		if rec.Authority != feed.AuthorityAggregator {
			t.Errorf("record %d authority = %q", rec.Index, rec.Authority)
		}
	}
}

// TestTwoDirectAssertionsAreTwoVoices is THE CONTROL, and it is what stops the
// rule above from being satisfied by never proposing anything.
//
// The same two source ids, the same document, the same threshold. The only
// difference is that the operator granted the signer `asserts_source_ids`
// rather than `aggregator_for` — which is the operator stating that the
// signer speaks for those sources in its own right.
func TestTwoDirectAssertionsAreTwoVoices(t *testing.T) {
	rep := aggregatorRun(t, []string{"src-a", "src-b"}, nil, 2)
	o := only(t, rep)

	wantDecision(t, o, DecisionPropose, ReasonCorroborated)
	if len(o.AdverseSources) != 2 {
		t.Errorf("AdverseSources = %v, want two", o.AdverseSources)
	}
	if len(o.AggregatedSources) != 0 {
		t.Errorf("a direct assertion was reported as aggregated: %v", o.AggregatedSources)
	}
	for _, rec := range rep.Records {
		if rec.Authority != feed.AuthorityOwn {
			t.Errorf("record %d authority = %q, want %q", rec.Index, rec.Authority, feed.AuthorityOwn)
		}
	}
}

// TestMixedDirectAndAggregatedClaims.
//
// One signer asserting src-a in its own right and republishing src-b. The
// direct claim is one voice; the aggregated one is not a second.
func TestMixedDirectAndAggregatedClaims(t *testing.T) {
	t.Run("threshold 2 is not met", func(t *testing.T) {
		rep := aggregatorRun(t, []string{"src-a"}, []string{"src-b"}, 2)
		o := only(t, rep)
		wantDecision(t, o, DecisionAbstain, ReasonAggregatedNotIndependent)
		if len(o.AdverseSources) != 1 || o.AdverseSources[0] != "src-a" {
			t.Errorf("AdverseSources = %v, want [src-a]", o.AdverseSources)
		}
		if len(o.AggregatedSources) != 1 || o.AggregatedSources[0] != "src-b" {
			t.Errorf("AggregatedSources = %v, want [src-b]", o.AggregatedSources)
		}
	})

	t.Run("threshold 1 is met by the direct claim alone", func(t *testing.T) {
		rep := aggregatorRun(t, []string{"src-a"}, []string{"src-b"}, 1)
		o := only(t, rep)
		wantDecision(t, o, DecisionPropose, ReasonCorroborated)
		if len(o.AdverseSources) != 1 {
			t.Errorf("AdverseSources = %v", o.AdverseSources)
		}
		// The aggregated claim is still reported. It is evidence; it simply
		// was not what met the threshold.
		if len(o.AggregatedSources) != 1 {
			t.Errorf("the aggregated claim disappeared from the report: %v", o.AggregatedSources)
		}
	})
}

// TestASignerGrantedBothFormsOverOneSourceSpeaksInItsOwnRight.
//
// The schema permits a source id in both lists. MayAssert checks
// `asserts_source_ids` first, so the stronger claim wins — and it must, or an
// operator who added an id to both would have silently weakened the other
// grant. Asserted here because "which list wins" is the kind of thing that
// gets reversed by a refactor.
func TestASignerGrantedBothFormsOverOneSourceSpeaksInItsOwnRight(t *testing.T) {
	rep := aggregatorRun(t, []string{"src-a", "src-b"}, []string{"src-a", "src-b"}, 2)
	o := only(t, rep)
	wantDecision(t, o, DecisionPropose, ReasonCorroborated)
	if len(o.AggregatedSources) != 0 {
		t.Errorf("a source granted BOTH forms was treated as aggregated: %v", o.AggregatedSources)
	}
	for _, rec := range rep.Records {
		if rec.Authority != feed.AuthorityOwn {
			t.Errorf("record %d authority = %q, want %q", rec.Index, rec.Authority, feed.AuthorityOwn)
		}
	}
}

// TestTheShortfallReasonDistinguishesItsTwoCauses.
//
// "Not enough sources said so" and "the sources that said so all came through
// one republisher" want different fixes, so they are different reason codes.
// A single code would tell an operator to go and find more evidence when the
// evidence is already in their hands.
func TestTheShortfallReasonDistinguishesItsTwoCauses(t *testing.T) {
	t.Run("genuinely too few", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil)},
			policy:  testPolicy(t, 2, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		wantDecision(t, only(t, rep), DecisionAbstain, ReasonInsufficientSupport)
	})

	t.Run("enough claims, one channel", func(t *testing.T) {
		rep := aggregatorRun(t, nil, []string{"src-a", "src-b"}, 2)
		wantDecision(t, only(t, rep), DecisionAbstain, ReasonAggregatedNotIndependent)
	})

	t.Run("still too few EVEN counting the aggregated ones", func(t *testing.T) {
		// One aggregated claim against a threshold of three: counting it
		// would not have met the threshold either, so the honest reason is
		// the ordinary shortfall rather than the aggregation.
		rep := run{
			aggregates: []string{"src-a"},
			sources:    []sourceregistry.Source{testSource("src-a", nil)},
			policy:     testPolicy(t, 3, ScopeExact),
			records:    []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		wantDecision(t, only(t, rep), DecisionAbstain, ReasonInsufficientSupport)
	})
}

// TestRepeatedAggregatedRecordsAreStillOneSource.
//
// The per-source counting rule has to survive the new bucket: three records
// from one aggregated source is one aggregated source, not three.
func TestRepeatedAggregatedRecordsAreStillOneSource(t *testing.T) {
	rep := run{
		aggregates: []string{"src-a"},
		sources:    []sourceregistry.Source{testSource("src-a", nil)},
		policy:     testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-a", "a2", "one.example.com"),
			adverse("src-a", "a3", "one.example.com"),
		},
	}.do(t)
	o := only(t, rep)
	wantDecision(t, o, DecisionAbstain, ReasonAggregatedNotIndependent)
	if len(o.AggregatedSources) != 1 {
		t.Errorf("three records from one aggregated source counted as %d: %v",
			len(o.AggregatedSources), o.AggregatedSources)
	}
}

// TestTheAggregatorRuleComposesWithRegistryLineage.
//
// The two mechanisms answer different questions and both have to hold. The
// registry collapses src-agg into its recorded upstream src-up; the
// attribution rule excludes whatever arrived by republication. Neither
// substitutes for the other.
func TestTheAggregatorRuleComposesWithRegistryLineage(t *testing.T) {
	upstream := testSource("src-up", nil)
	agg := testSource("src-agg", []string{"src-up"})
	opaque := testSource("src-opaque", nil)
	opaque.UpstreamSourcesCompleteness = sourceregistry.UpstreamUnknown

	t.Run("registry lineage still collapses a direct assertion", func(t *testing.T) {
		// Both asserted DIRECTLY, so the attribution rule excludes neither.
		// The registry records src-agg as drawing on src-up, so they are one
		// voice and the threshold of two is not met.
		rep := run{
			asserts: []string{"src-up", "src-agg"},
			sources: []sourceregistry.Source{upstream, agg},
			policy:  testPolicy(t, 2, ScopeExact),
			records: []feed.EvidenceRecord{
				adverse("src-up", "u1", "one.example.com"),
				adverse("src-agg", "g1", "one.example.com"),
			},
		}.do(t)
		o := only(t, rep)
		wantDecision(t, o, DecisionAbstain, ReasonInsufficientSupport)
		if len(o.IndependentSources) != 1 {
			t.Errorf("registry lineage did not collapse: independent=%v", o.IndependentSources)
		}
		if len(o.AggregatedSources) != 0 {
			t.Errorf("a direct assertion was marked aggregated: %v", o.AggregatedSources)
		}
	})

	t.Run("unknown lineage and republication are separate exclusions", func(t *testing.T) {
		// src-a is direct and its lineage is documented: it counts.
		// src-opaque is direct and its lineage is unknown: excluded by the
		// registry, and reported as unestablished.
		// src-b is republished: excluded by the attribution rule, and
		// reported as aggregated. The two lists must not overlap.
		rep := run{
			asserts:    []string{"src-a", "src-opaque"},
			aggregates: []string{"src-b"},
			sources: []sourceregistry.Source{
				testSource("src-a", nil), testSource("src-b", nil), opaque,
			},
			policy: testPolicy(t, 3, ScopeExact),
			records: []feed.EvidenceRecord{
				adverse("src-a", "a1", "one.example.com"),
				adverse("src-opaque", "o1", "one.example.com"),
				adverse("src-b", "b1", "one.example.com"),
			},
		}.do(t)
		o := only(t, rep)
		if o.Decision != DecisionAbstain {
			t.Fatalf("three claims through three different problems proposed: %s/%s", o.Decision, o.Reason)
		}
		if len(o.AdverseSources) != 1 || o.AdverseSources[0] != "src-a" {
			t.Errorf("AdverseSources = %v, want [src-a]", o.AdverseSources)
		}
		if len(o.UnestablishedSources) != 1 || o.UnestablishedSources[0] != "src-opaque" {
			t.Errorf("UnestablishedSources = %v, want [src-opaque]", o.UnestablishedSources)
		}
		if len(o.AggregatedSources) != 1 || o.AggregatedSources[0] != "src-b" {
			t.Errorf("AggregatedSources = %v, want [src-b]", o.AggregatedSources)
		}
	})
}

// TestAcceptUnestablishedIndependenceDoesNotAdmitAggregatedClaims.
//
// The two flags are NOT the same escape hatch, and one must not silently open
// the other. `accept_unestablished_independence` is about registry lineage
// between sources; republication is about the channel a claim arrived by.
func TestAcceptUnestablishedIndependenceDoesNotAdmitAggregatedClaims(t *testing.T) {
	loose, err := ParsePolicy([]byte(`{"schema_version":1,"min_independent_sources":2,
		"proposal_scope":"exact","accept_unestablished_independence":true}`))
	if err != nil {
		t.Fatal(err)
	}
	rep := run{
		aggregates: []string{"src-a", "src-b"},
		sources:    []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil)},
		policy:     loose,
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-b", "b1", "one.example.com"),
		},
	}.do(t)
	wantDecision(t, only(t, rep), DecisionAbstain, ReasonAggregatedNotIndependent)
}

// TestAggregatedSupportIsReportedRatherThanDiscarded.
//
// An operator who cannot see the claims cannot act on them. Both formats
// carry the aggregated source list and the reason.
func TestAggregatedSupportIsReportedRatherThanDiscarded(t *testing.T) {
	rep := aggregatorRun(t, nil, []string{"src-a", "src-b"}, 2)

	var text, js strings.Builder
	rep.Text(&text)
	if err := rep.JSON(&js); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "JSON": js.String()} {
		for _, want := range []string{
			string(ReasonAggregatedNotIndependent), "src-a", "src-b",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the %s report does not carry %q", name, want)
			}
		}
	}
}

// TestWhatTheAggregatorRuleDoesNotEstablish.
//
// **[recorded as limits, not as tests of a capability.]** The rule bounds what
// an aggregator can claim. It does not establish:
//
//   - that a DIRECT assertion is true. `asserts_source_ids` is the operator
//     saying a signer speaks for a source; it is not confirmation of anything
//     the signer says.
//   - that two directly-asserting signers are independent OF EACH OTHER. This
//     build sees one document per run and has no way to compare channels
//     across runs.
//   - that a source id names a real organisation, or that two ids are two
//     organisations.
//   - that an aggregator has not silently dropped or altered what it
//     republished. Nothing in schema 2 carries the upstream's own signature.
//
// The function body asserts only the first, because it is the one that could
// be mistaken for a property of the code rather than of the operator's file.
func TestWhatTheAggregatorRuleDoesNotEstablish(t *testing.T) {
	// A direct assertion of something plainly untrue is still admitted and
	// still counts. The rule is about the channel, not about the claim.
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil)},
		policy:  testPolicy(t, 2, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "www.example.com"),
			adverse("src-b", "b1", "www.example.com"),
		},
	}.do(t)
	o := only(t, rep)
	wantDecision(t, o, DecisionPropose, ReasonCorroborated)
	if o.Canonical != "www.example.com" {
		t.Fatalf("premise broken: %q", o.Canonical)
	}
	// The report must not describe this as confirmation of anything.
	var b strings.Builder
	rep.Text(&b)
	out := strings.Join(strings.Fields(b.String()), " ")
	if !strings.Contains(out, "It is not independent confirmation that the named source observed anything") {
		t.Error("the report no longer states that attribution is not confirmation")
	}
}
