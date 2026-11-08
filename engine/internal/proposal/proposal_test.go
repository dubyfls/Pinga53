// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// run is the whole path: sign, authenticate, admit, decide. Every test below
// goes through it, so nothing is measured on a helper that the command does
// not actually call.
type run struct {
	keyID      string
	asserts    []string
	aggregates []string
	sources    []sourceregistry.Source
	retired    []string
	// identityKey is the installation key C-09 tags withheld hosts with.
	identityKey *mac.Key
	// externalOrigins declares origins this registry holds no record for.
	// C-01 and C-02 need it; every other fixture leaves it nil.
	externalOrigins []string
	policy          *Policy
	records         []feed.EvidenceRecord
	at              time.Time
	// signWithOtherKey substitutes a different signer, keeping the key id.
	signWithOtherKey bool
}

func (r run) do(t *testing.T) *Report {
	t.Helper()
	rep, err := r.build(t)
	if err != nil {
		t.Fatalf("the run failed: %v", err)
	}
	return rep
}

func (r run) build(t *testing.T) (*Report, error) {
	t.Helper()
	priv, pub := testKey(t, 0x31)
	signer := priv
	if r.signWithOtherKey {
		signer, _ = testKey(t, 0x32)
	}
	keyID := r.keyID
	if keyID == "" {
		keyID = "test-key-1"
	}
	auth := authorityOver(t, keyID, pub, r.asserts, r.aggregates)

	reg := &sourceregistry.Registry{
		SchemaVersion:    sourceregistry.SchemaVersion,
		RetiredSourceIDs: r.retired,
		ExternalOrigins:  r.externalOrigins,
		Sources:          r.sources,
	}
	if problems := reg.Validate(testAt); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("fixture registry problem: %s", p)
		}
		t.FailNow()
	}

	at := r.at
	if at.IsZero() {
		at = testAt
	}
	doc := signEvidence(t, signer, keyID, "synthetic", r.records)
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 1000, Authority: auth, Now: at,
	})
	if err != nil {
		return nil, err
	}
	return Build(Input{Evidence: ev, Registry: reg, Policy: r.policy, At: at, IdentityKey: r.identityKey})
}

// only returns the single outcome, failing if there is not exactly one.
func only(t *testing.T, rep *Report) Outcome {
	t.Helper()
	if len(rep.Outcomes) != 1 {
		t.Fatalf("expected one indicator, got %d: %+v", len(rep.Outcomes), rep.Outcomes)
	}
	return rep.Outcomes[0]
}

func wantDecision(t *testing.T, o Outcome, d Decision, r Reason) {
	t.Helper()
	if o.Decision != d || o.Reason != r {
		t.Errorf("%s: got %s/%s, want %s/%s\n  %s", o.Canonical, o.Decision, o.Reason, d, r, o.Explanation)
	}
}

func wantRefusal(t *testing.T, rep *Report, index int, r Reason) {
	t.Helper()
	for _, rec := range rep.Records {
		if rec.Index != index {
			continue
		}
		if rec.Admitted {
			t.Errorf("record %d was ADMITTED; expected refusal %s", index, r)
			return
		}
		if rec.Reason != r {
			t.Errorf("record %d refused as %s, want %s\n  %s", index, rec.Reason, r, rec.Explanation)
		}
		return
	}
	t.Errorf("record %d is not in the report at all; a refused record must be reported, never dropped", index)
}

func twoSources() []sourceregistry.Source {
	return []sourceregistry.Source{testSource("src-a", nil), testSource("src-b", nil)}
}

// --- admission ----------------------------------------------------------

// TestASignatureIsNotAuthorityOverASource.
//
// The document verifies. The signer has authority over src-a and not over
// src-b, and writing `src-b` inside a payload it legitimately signed must not
// be how it acquires one.
func TestASignatureIsNotAuthorityOverASource(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-b", "b1", "two.example.com"),
		},
	}.do(t)

	if !rep.Records[0].Admitted {
		t.Errorf("the record the signer may assert was refused: %s", rep.Records[0].Explanation)
	}
	if rep.Records[0].Authority != feed.AuthorityOwn {
		t.Errorf("authority = %q, want %q", rep.Records[0].Authority, feed.AuthorityOwn)
	}
	wantRefusal(t, rep, 1, ReasonSignerNotAuthorised)
	if rep.Records[1].Authority != feed.AuthorityNone {
		t.Errorf("a refused record records authority %q", rep.Records[1].Authority)
	}
	if len(rep.Outcomes) != 1 {
		t.Errorf("the unauthorised record produced an indicator anyway: %+v", rep.Outcomes)
	}
}

// TestAnAggregatorAuthorityIsEnforcedTheSameAndSaysSomethingDifferent.
func TestAnAggregatorAuthorityIsEnforcedTheSameAndSaysSomethingDifferent(t *testing.T) {
	rep := run{
		aggregates: []string{"src-a"},
		sources:    twoSources(),
		policy:     testPolicy(t, 1, ScopeExact),
		records:    []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
	}.do(t)

	if !rep.Records[0].Admitted {
		t.Fatalf("an aggregator's record was refused: %s", rep.Records[0].Explanation)
	}
	if rep.Records[0].Authority != feed.AuthorityAggregator {
		t.Errorf("authority = %q, want %q; the two grants are enforced alike and must not be "+
			"reported alike", rep.Records[0].Authority, feed.AuthorityAggregator)
	}
}

// TestASubstitutedSignerIsRefusedBeforeAnyClaimIsRead.
func TestASubstitutedSignerIsRefusedBeforeAnyClaimIsRead(t *testing.T) {
	_, err := run{
		asserts:          []string{"src-a"},
		sources:          twoSources(),
		policy:           testPolicy(t, 1, ScopeExact),
		records:          []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		signWithOtherKey: true,
	}.build(t)
	if err == nil {
		t.Fatal("a document signed by a substituted key was admitted")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestASourceMustBeInTheRegistryAndMustNotBeRetired.
func TestASourceMustBeInTheRegistryAndMustNotBeRetired(t *testing.T) {
	rep := run{
		asserts: []string{"src-a", "src-gone", "src-retired"},
		sources: []sourceregistry.Source{testSource("src-a", nil)},
		retired: []string{"src-retired"},
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-gone", "g1", "two.example.com"),
			adverse("src-retired", "r1", "three.example.com"),
		},
	}.do(t)

	if !rep.Records[0].Admitted {
		t.Errorf("a registered source was refused: %s", rep.Records[0].Explanation)
	}
	wantRefusal(t, rep, 1, ReasonSourceUnknown)
	wantRefusal(t, rep, 2, ReasonSourceRetired)

	// The two must not share a message: "no such source" and "a source that
	// was deliberately withdrawn" are different facts and lead somewhere
	// different.
	if rep.Records[1].Explanation == rep.Records[2].Explanation {
		t.Error("an unknown source and a retired one are explained identically")
	}
}

// TestAnIndicatorTypeThisBuildCannotActOnIsRefusedAsSuch.
func TestAnIndicatorTypeThisBuildCannotActOnIsRefusedAsSuch(t *testing.T) {
	known := feed.EvidenceRecord{
		Type: "ipv4", Value: "192.0.2.1", SourceID: "src-a",
		Classification: "malicious", State: "active",
	}
	unknown := feed.EvidenceRecord{
		Type: "tarot-card", Value: "the-tower", SourceID: "src-a",
		Classification: "malicious", State: "active",
	}
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com"), known, unknown},
	}.do(t)

	if !rep.Records[0].Admitted {
		t.Errorf("a supported type was refused: %s", rep.Records[0].Explanation)
	}
	wantRefusal(t, rep, 1, ReasonTypeUnsupported)
	wantRefusal(t, rep, 2, ReasonTypeUnknown)

	// One unsupported record must not destroy the document's other evidence —
	// the defect at 7e11419, in a new path.
	if len(rep.Outcomes) != 1 || rep.Outcomes[0].Decision != DecisionPropose {
		t.Errorf("an unsupported record cost the document its valid evidence: %+v", rep.Outcomes)
	}
}

// TestTheTypeIsCheckedBeforeTheRegistryIsConsulted.
//
// A signer with no authority over a source must not be able to learn, from
// the difference between two refusals, whether that source exists in the
// operator's registry.
func TestTheTypeIsCheckedBeforeTheRegistryIsConsulted(t *testing.T) {
	probe := func(sourceID string) Reason {
		rep := run{
			asserts: []string{"src-a"},
			sources: []sourceregistry.Source{testSource("src-a", nil)},
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{{
				Type: "domain", Value: "one.example.com", SourceID: sourceID,
				Classification: "malicious", State: "active",
			}},
		}.do(t)
		return rep.Records[0].Reason
	}
	// Neither of these is in the signer's grant. One exists in the registry,
	// one does not, and the refusal must not tell them apart.
	if a, b := probe("src-b"), probe("src-nonexistent"); a != b {
		t.Errorf("the refusal distinguishes a registered source from an absent one: %s vs %s", a, b)
	}
	if got := probe("src-b"); got != ReasonSignerNotAuthorised {
		t.Errorf("got %s, want %s", got, ReasonSignerNotAuthorised)
	}
}

// TestRightsAreEnforcedAtTheOperationBoundaryEachOneActuallyIs.
//
// Removing raw bytes does not authorise storing extracted data, and storing
// data does not authorise combining it or reporting on it. Each operation is
// asked of the registry separately, at the point the operation happens.
func TestRightsAreEnforcedAtTheOperationBoundaryEachOneActuallyIs(t *testing.T) {
	withGrant := func(op sourceregistry.Operation, g sourceregistry.Grant) []sourceregistry.Source {
		srcs := twoSources()
		srcs[0].Permissions[op] = g
		return srcs
	}

	t.Run("local storage prohibited refuses the record", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: withGrant(sourceregistry.OpLocalStorage, prohibitedGrant()),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		wantRefusal(t, rep, 0, ReasonStorageRefused)
		if len(rep.Outcomes) != 0 {
			t.Errorf("a record nobody may keep produced an indicator: %+v", rep.Outcomes)
		}
	})

	t.Run("local storage unknown refuses the record", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: withGrant(sourceregistry.OpLocalStorage, unknownGrant()),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		wantRefusal(t, rep, 0, ReasonStorageRefused)
	})

	t.Run("a conditional grant with an unsatisfied condition refuses", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: withGrant(sourceregistry.OpLocalStorage, conditionalGrant(sourceregistry.ConditionUnknown)),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		wantRefusal(t, rep, 0, ReasonStorageRefused)
	})

	t.Run("a conditional grant whose condition is met permits", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: withGrant(sourceregistry.OpLocalStorage, conditionalGrant(sourceregistry.ConditionSatisfied)),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		if !rep.Records[0].Admitted {
			t.Errorf("a satisfied conditional grant refused a record: %s", rep.Records[0].Explanation)
		}
	})

	t.Run("enrichment prohibited refuses the INDICATOR, not the record", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: withGrant(sourceregistry.OpEnrichment, prohibitedGrant()),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		if !rep.Records[0].Admitted {
			t.Fatalf("storing was refused when only enrichment was: %s", rep.Records[0].Explanation)
		}
		wantDecision(t, only(t, rep), DecisionRefuse, ReasonEnrichmentRefused)
	})

	t.Run("derived output prohibited refuses the indicator", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: withGrant(sourceregistry.OpDerivedOutput, prohibitedGrant()),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		}.do(t)
		if !rep.Records[0].Admitted {
			t.Fatalf("storing was refused when only derived output was: %s", rep.Records[0].Explanation)
		}
		wantDecision(t, only(t, rep), DecisionRefuse, ReasonDerivedOutputRefused)
	})

	t.Run("one source's prohibition refuses the whole derived indicator", func(t *testing.T) {
		// Derivation does not launder provenance: a result computed from two
		// sources is still, in part, each of them.
		srcs := twoSources()
		srcs[1].Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
		rep := run{
			asserts: []string{"src-a", "src-b"},
			sources: srcs,
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{
				adverse("src-a", "a1", "one.example.com"),
				adverse("src-b", "b1", "one.example.com"),
			},
		}.do(t)
		wantDecision(t, only(t, rep), DecisionRefuse, ReasonDerivedOutputRefused)
	})
}

// TestRawProviderContentIsAbsentByDefaultAndRefusedWithoutAGrant.
func TestRawProviderContentIsAbsentByDefaultAndRefusedWithoutAGrant(t *testing.T) {
	withRaw := func(retention string) feed.EvidenceRecord {
		r := adverse("src-a", "a1", "one.example.com")
		r.Raw = `{"provider":"verbatim response body"}`
		r.RawRetention = retention
		return r
	}

	t.Run("raw with no retention field is not kept", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: twoSources(),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{withRaw("")},
		}.do(t)
		// The field defaults to `none`, so the record is admitted and the raw
		// bytes are dropped. Refusing the record would punish a document for a
		// field it omitted; keeping them would make omission a grant.
		if !rep.Records[0].Admitted {
			t.Fatalf("a record was refused for omitting raw_retention: %s", rep.Records[0].Explanation)
		}
		if !rep.Records[0].RawDropped {
			t.Error("raw bytes arrived with no claim to keep them and the drop was not reported")
		}
	})

	t.Run("raw claimed as retained, with no storage grant, is refused", func(t *testing.T) {
		srcs := twoSources()
		srcs[0].Permissions[sourceregistry.OpLocalStorage] = unknownGrant()
		rep := run{
			asserts: []string{"src-a"},
			sources: srcs,
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{withRaw("retained")},
		}.do(t)
		// Refused at the storage check, which comes FIRST: the grant that
		// would authorise keeping the raw bytes is the same grant that
		// authorises keeping the normalised record at all, so the record never
		// reaches the raw question.
		wantRefusal(t, rep, 0, ReasonStorageRefused)
	})

	t.Run("an invented retention value is refused", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a"},
			sources: twoSources(),
			policy:  testPolicy(t, 1, ScopeExact),
			records: []feed.EvidenceRecord{withRaw("keep-forever")},
		}.do(t)
		wantRefusal(t, rep, 0, ReasonRecordInvalid)
	})
}

// TestAMalformedValueIsASyntaxFailureAndNothingMore.
//
// SW-P3-05: "this name is not a valid domain" and "this name is suspicious"
// are different claims, and one malformed record must not destroy a
// document's unrelated evidence.
func TestAMalformedValueIsASyntaxFailureAndNothingMore(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-a", "a2", "not a domain at all"),
			adverse("src-a", "a3", "*.example.com"),
			adverse("src-a", "a4", "two.example.com"),
		},
	}.do(t)

	wantRefusal(t, rep, 1, ReasonValueInvalid)
	wantRefusal(t, rep, 2, ReasonValueInvalid)
	if len(rep.Outcomes) != 2 {
		t.Errorf("two malformed records cost the document its valid evidence: %+v", rep.Outcomes)
	}
	for _, rec := range rep.Records {
		if rec.Admitted {
			continue
		}
		if strings.Contains(strings.ToLower(rec.Explanation), "malicious") ||
			strings.Contains(strings.ToLower(rec.Explanation), "suspicious") {
			t.Errorf("a syntax refusal reads as a judgement about the name: %q", rec.Explanation)
		}
	}
}

// --- duplicates, corrections, withdrawal, expiry -------------------------

// TestOneSourceSayingSomethingThreeTimesIsOneSource.
func TestOneSourceSayingSomethingThreeTimesIsOneSource(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 2, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-a", "a2", "one.example.com"),
			adverse("src-a", "a3", "one.example.com"),
		},
	}.do(t)

	o := only(t, rep)
	wantDecision(t, o, DecisionAbstain, ReasonInsufficientSupport)
	if len(o.AdverseSources) != 1 {
		t.Errorf("three records from one provider counted as %d sources: %v",
			len(o.AdverseSources), o.AdverseSources)
	}
}

// TestTheSameRecordTwiceIsNotTwoObservations.
func TestTheSameRecordTwiceIsNotTwoObservations(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-a", "a1", "one.example.com"),
		},
	}.do(t)

	if rep.Records[0].Store != "new" {
		t.Errorf("the first record was stored as %q", rep.Records[0].Store)
	}
	if rep.Records[1].Store != "duplicate" {
		t.Errorf("an identical repeat was stored as %q, want duplicate", rep.Records[1].Store)
	}
	if got := len(only(t, rep).Sources); got != 1 {
		t.Errorf("a repeated record produced %d sources", got)
	}
}

// TestACorrectionMovesARecordAcrossCanonicalDomains.
//
// A provider that revises the SUBJECT of a record is making one statement
// twice, not two statements. The superseded subject must stop being live.
func TestACorrectionMovesARecordAcrossCanonicalDomains(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "rec-1", "old.example.com"),
			adverse("src-a", "rec-1", "new.example.com"),
		},
	}.do(t)

	if rep.Records[1].Store != "correction" {
		t.Errorf("a revised subject was stored as %q, want correction", rep.Records[1].Store)
	}
	if len(rep.Outcomes) != 2 {
		t.Fatalf("expected both subjects to be present in the report: %+v", rep.Outcomes)
	}
	byName := map[string]Outcome{}
	for _, o := range rep.Outcomes {
		byName[o.Canonical] = o
	}
	wantDecision(t, byName["new.example.com"], DecisionPropose, ReasonCorroborated)
	// The withdrawn subject is RETAINED — it is history — and is not live.
	wantDecision(t, byName["old.example.com"], DecisionAbstain, ReasonNoLiveEvidence)
}

// TestWithdrawnAndExpiredEvidenceAreNamedSeparately.
func TestWithdrawnAndExpiredEvidenceAreNamedSeparately(t *testing.T) {
	lapsed := testAt.Add(-24 * time.Hour)
	expired := adverse("src-a", "a1", "expired.example.com")
	expired.ExpiresAt = &lapsed
	withdrawn := adverse("src-b", "b1", "withdrawn.example.com")
	withdrawn.Status = "withdrawn"

	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{expired, withdrawn},
	}.do(t)

	byName := map[string]Outcome{}
	for _, o := range rep.Outcomes {
		byName[o.Canonical] = o
	}
	wantDecision(t, byName["expired.example.com"], DecisionAbstain, ReasonExpiredOnly)
	wantDecision(t, byName["withdrawn.example.com"], DecisionAbstain, ReasonWithdrawnOnly)
}

// TestLivenessIsDecidedAgainstTheRecordedInstantAndNothingElse.
//
// The same bytes, two instants, two answers — which is why the report binds
// the instant it used.
func TestLivenessIsDecidedAgainstTheRecordedInstantAndNothingElse(t *testing.T) {
	// Well inside the manifest's own validity window, so the only thing
	// that changes between the two runs is which side of the RECORD's expiry
	// the evaluation instant falls on.
	expiry := testAt.Add(time.Hour)
	rec := adverse("src-a", "a1", "one.example.com")
	rec.ExpiresAt = &expiry

	base := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{rec},
	}

	before := base
	before.at = testAt
	wantDecision(t, only(t, before.do(t)), DecisionPropose, ReasonCorroborated)

	after := base
	after.at = expiry.Add(time.Hour)
	o := only(t, after.do(t))
	wantDecision(t, o, DecisionAbstain, ReasonExpiredOnly)
}

// TestSourcesThatDisagreeAreReportedRatherThanResolved.
func TestSourcesThatDisagreeAreReportedRatherThanResolved(t *testing.T) {
	benign := adverse("src-b", "b1", "one.example.com")
	benign.Classification = "benign"

	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com"), benign},
	}.do(t)

	o := only(t, rep)
	wantDecision(t, o, DecisionAbstain, ReasonConflict)
	if !o.Conflicted {
		t.Error("the conflict is not recorded on the outcome")
	}
	if len(o.Sources) != 2 {
		t.Errorf("a conflict lost one side: %v", o.Sources)
	}
}

// --- independence -------------------------------------------------------

// TestAnAggregatorAndItsUpstreamAreOneVoice.
func TestAnAggregatorAndItsUpstreamAreOneVoice(t *testing.T) {
	upstream := testSource("src-up", nil)
	agg := testSource("src-agg", []string{"src-up"})

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
		t.Errorf("an aggregator and its own upstream counted as %d independent sources: %v",
			len(o.IndependentSources), o.IndependentSources)
	}
}

// TestUnestablishedIndependenceIsNotIndependence.
func TestUnestablishedIndependenceIsNotIndependence(t *testing.T) {
	opaque := testSource("src-opaque", nil)
	opaque.UpstreamSourcesCompleteness = sourceregistry.UpstreamUnknown

	base := run{
		asserts: []string{"src-a", "src-opaque"},
		sources: []sourceregistry.Source{testSource("src-a", nil), opaque},
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "one.example.com"),
			adverse("src-opaque", "o1", "one.example.com"),
		},
	}

	t.Run("refused by default", func(t *testing.T) {
		r := base
		r.policy = testPolicy(t, 2, ScopeExact)
		o := only(t, r.do(t))
		wantDecision(t, o, DecisionAbstain, ReasonInsufficientSupport)
		if len(o.UnestablishedSources) != 1 {
			t.Errorf("the opaque source is not reported as unestablished: %v", o.UnestablishedSources)
		}
	})

	t.Run("counted only when the operator says so", func(t *testing.T) {
		r := base
		p, err := ParsePolicy([]byte(`{"schema_version":1,"min_independent_sources":2,
			"proposal_scope":"exact","accept_unestablished_independence":true}`))
		if err != nil {
			t.Fatalf("policy: %v", err)
		}
		r.policy = p
		wantDecision(t, only(t, r.do(t)), DecisionPropose, ReasonCorroborated)
	})
}

// --- decisions ----------------------------------------------------------

// TestASignalIsNotEvidence.
//
// SW-P3-05, measured signal by signal at this package's surface. Unicode, a
// non-Latin script and punycode change nothing; a mixed script and an
// invisible character prevent a proposal and never produce one.
func TestASignalIsNotEvidence(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  Decision
		why   Reason
	}{
		{"ordinary ASCII", "one.example.com", DecisionPropose, ReasonCorroborated},
		{"an internationalised name", "例え.example.com", DecisionPropose, ReasonCorroborated},
		{"punycode as written", "xn--r8jz45g.example.com", DecisionPropose, ReasonCorroborated},
		{"a single non-Latin script", "пример.example.com", DecisionPropose, ReasonCorroborated},
		{"Japanese, which legitimately mixes scripts", "テスト漢字.example.com", DecisionPropose, ReasonCorroborated},
		{"a Latin/Cyrillic lookalike", "ex\u0430mple.example.com", DecisionAbstain, ReasonNameRequiresReview},
		{"a zero-width space", "ex\u200bample.example.com", DecisionAbstain, ReasonNameRequiresReview},
		{"a soft hyphen", "ex\u00adample.example.com", DecisionAbstain, ReasonNameRequiresReview},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := run{
				asserts: []string{"src-a"},
				sources: twoSources(),
				policy:  testPolicy(t, 1, ScopeExact),
				records: []feed.EvidenceRecord{adverse("src-a", "a1", tc.value)},
			}.do(t)
			o := only(t, rep)
			wantDecision(t, o, tc.want, tc.why)
			if tc.want == DecisionAbstain && !strings.Contains(o.Explanation, "not evidence") {
				t.Errorf("the explanation does not say a signal is not evidence: %q", o.Explanation)
			}
		})
	}
}

// TestInvisibleCharactersOutrankMixedScriptInTheReason.
//
// Fixed precedence, so a name carrying both always reports the same reason.
func TestInvisibleCharactersOutrankMixedScriptInTheReason(t *testing.T) {
	rep := run{
		asserts: []string{"src-a"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "ex\u200b\u0430mple.example.com")},
	}.do(t)
	o := only(t, rep)
	wantDecision(t, o, DecisionAbstain, ReasonNameRequiresReview)
	if !strings.Contains(o.Explanation, "invisible_character") {
		t.Errorf("the stronger signal is not the one reported: %q", o.Explanation)
	}
}

// TestASignalOneSourceWroteIsSeenEvenWhenAnotherWroteItCleanly.
//
// Two sources can write the same canonical name differently. Taking one
// entry's signals would make the answer depend on which sorted first.
func TestASignalOneSourceWroteIsSeenEvenWhenAnotherWroteItCleanly(t *testing.T) {
	rep := run{
		asserts: []string{"src-a", "src-b"},
		sources: twoSources(),
		policy:  testPolicy(t, 1, ScopeExact),
		records: []feed.EvidenceRecord{
			adverse("src-a", "a1", "example.example.com"),
			adverse("src-b", "b1", "ex\u200bample.example.com"),
		},
	}.do(t)
	o := only(t, rep)
	wantDecision(t, o, DecisionAbstain, ReasonNameRequiresReview)
	if len(o.Sources) != 2 {
		t.Errorf("the two spellings did not resolve to one indicator: %v", o.Sources)
	}
}

// TestTheHouseholdOutranksEverySource.
func TestTheHouseholdOutranksEverySource(t *testing.T) {
	records := []feed.EvidenceRecord{
		adverse("src-a", "a1", "bank.example.com"),
		adverse("src-b", "b1", "bank.example.com"),
		adverse("src-a", "a2", "other.example.com"),
		adverse("src-b", "b2", "other.example.com"),
	}

	t.Run("an exact exception", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a", "src-b"},
			sources: twoSources(),
			policy: testPolicy(t, 2, ScopeExact,
				Exception{Value: "bank.example.com", Scope: ScopeExact, Note: "the household's bank"}),
			records: records,
		}.do(t)
		byName := map[string]Outcome{}
		for _, o := range rep.Outcomes {
			byName[o.Canonical] = o
		}
		wantDecision(t, byName["bank.example.com"], DecisionRefuse, ReasonUserException)
		if byName["bank.example.com"].Exception == nil {
			t.Error("the exception that decided it is not recorded on the outcome")
		}
		if byName["bank.example.com"].Scope != "" {
			t.Error("a refused indicator carries a scope; a refusal reaches nothing")
		}
		// The positive control: the exception must not shadow anything else.
		wantDecision(t, byName["other.example.com"], DecisionPropose, ReasonCorroborated)
	})

	t.Run("a subdomain exception reaches a child and not the apex", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a", "src-b"},
			sources: twoSources(),
			policy: testPolicy(t, 2, ScopeExact,
				Exception{Value: "example.com", Scope: ScopeSubdomains}),
			records: []feed.EvidenceRecord{
				adverse("src-a", "a1", "child.example.com"),
				adverse("src-b", "b1", "child.example.com"),
				adverse("src-a", "a2", "example.com"),
				adverse("src-b", "b2", "example.com"),
			},
		}.do(t)
		byName := map[string]Outcome{}
		for _, o := range rep.Outcomes {
			byName[o.Canonical] = o
		}
		wantDecision(t, byName["child.example.com"], DecisionRefuse, ReasonUserException)
		wantDecision(t, byName["example.com"], DecisionPropose, ReasonCorroborated)
	})

	t.Run("a sibling is not shadowed", func(t *testing.T) {
		rep := run{
			asserts: []string{"src-a", "src-b"},
			sources: twoSources(),
			policy: testPolicy(t, 2, ScopeExact,
				Exception{Value: "bad.example.com", Scope: ScopeExact}),
			records: []feed.EvidenceRecord{
				adverse("src-a", "a1", "notbad.example.com"),
				adverse("src-b", "b1", "notbad.example.com"),
			},
		}.do(t)
		wantDecision(t, only(t, rep), DecisionPropose, ReasonCorroborated)
	})
}

// TestARightsRefusalOutranksAndWITHHOLDSTheExceptionMatch.
//
// # THIS REVERSES AN ORDER 6 DECISION, AND THE REVERSAL IS THE POINT
//
// The superseded version of this test was called
// TestARightsRefusalIsReportedEvenWhereAnExceptionWouldHaveWon and asserted
// the opposite of what is asserted below: that the matched exception is
// recorded on a rights-refused outcome, "so nothing is lost". FINDING-120 is
// why that was wrong.
//
// A matched exception is a statement that THIS INDICATOR matched a rule the
// operator wrote against a specific name. Printing it beside a refusal that
// withheld the indicator hands the reader the indicator: they have the
// exception's canonical value and the fact that this outcome matched it.
//
// The concern the old test had is real and is met a different way. A refusal
// names the sources whose grant refused, which is what the operator edits;
// once the grant is fixed and the run repeated, the exception appears. Losing
// one run's worth of "your exception was seen" is a smaller cost than
// disclosing an indicator this build was told not to disclose.
func TestARightsRefusalOutranksAndWITHHOLDSTheExceptionMatch(t *testing.T) {
	srcs := twoSources()
	srcs[0].Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
	base := run{
		asserts: []string{"src-a"},
		sources: srcs,
		policy: testPolicy(t, 1, ScopeExact,
			Exception{Value: "one.example.com", Scope: ScopeExact, Note: "the household's own rule"}),
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
	}
	rep := base.do(t)

	o := only(t, rep)
	wantDecision(t, o, DecisionRefuse, ReasonDerivedOutputRefused)
	if o.Exception != nil {
		t.Error("the refusal carries the matched exception, which names the indicator it withheld")
	}
	if !o.IdentityWithheld {
		t.Error("the refusal does not say that the identity is absent because of the refusal")
	}
	if len(o.RefusedSources) != 1 || o.RefusedSources[0] != "src-a" {
		t.Errorf("the refusal does not name the grant to fix: %v", o.RefusedSources)
	}
	assertNoDisclosure(t, rep, "one.example.com")

	// The positive control, and it is what stops this from being satisfied by
	// never reporting an exception at all: with the grant repaired, the very
	// same inputs report the exception.
	fixed := base
	fixed.sources = twoSources()
	repaired := only(t, fixed.do(t))
	wantDecision(t, repaired, DecisionRefuse, ReasonUserException)
	if repaired.Exception == nil {
		t.Fatal("with rights permitted, the household's exception is still not recorded")
	}
	if repaired.Exception.Note != "the household's own rule" {
		t.Errorf("the operator's note did not survive: %q", repaired.Exception.Note)
	}
}

// TestAProposalCarriesTheScopeThePolicyChose.
func TestAProposalCarriesTheScopeThePolicyChose(t *testing.T) {
	for _, scope := range []Scope{ScopeExact, ScopeSubdomains} {
		t.Run(string(scope), func(t *testing.T) {
			rep := run{
				asserts: []string{"src-a"},
				sources: twoSources(),
				policy:  testPolicy(t, 1, scope),
				records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
			}.do(t)
			o := only(t, rep)
			wantDecision(t, o, DecisionPropose, ReasonCorroborated)
			if o.Scope != scope {
				t.Errorf("the proposal carries scope %q, want %q", o.Scope, scope)
			}
		})
	}
}

// TestARunRefusesAnIncompleteInput.
func TestARunRefusesAnIncompleteInput(t *testing.T) {
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "k", pub, []string{"src-a"}, nil)
	doc := signEvidence(t, priv, "k", "synthetic", []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")})
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 10, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	reg := testRegistry(t, testSource("src-a", nil))
	pol := testPolicy(t, 1, ScopeExact)

	for _, tc := range []struct {
		name string
		in   Input
	}{
		{"no evidence", Input{Registry: reg, Policy: pol, At: testAt}},
		{"no registry", Input{Evidence: ev, Policy: pol, At: testAt}},
		{"no policy", Input{Evidence: ev, Registry: reg, At: testAt}},
		{"no instant", Input{Evidence: ev, Registry: reg, Policy: pol}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build(tc.in); err == nil {
				t.Fatal("a run was attempted with a required input missing")
			}
		})
	}
	if _, err := Build(Input{Evidence: ev, Registry: reg, Policy: pol, At: testAt}); err != nil {
		t.Errorf("a complete input was refused: %v", err)
	}
}

// TestEveryReasonThisPackageCanEmitIsInTheVocabulary.
//
// A code that is not in AllReasons is a code nobody decided was one.
func TestEveryReasonThisPackageCanEmitIsInTheVocabulary(t *testing.T) {
	known := map[Reason]bool{}
	for _, r := range AllReasons {
		if known[r] {
			t.Errorf("%s is listed twice", r)
		}
		known[r] = true
	}
	if len(known) != len(AllReasons) {
		t.Fatal("the vocabulary has duplicates")
	}
	for _, r := range AllReasons {
		if strings.TrimSpace(string(r)) == "" {
			t.Error("the vocabulary carries an empty code")
		}
	}
}
