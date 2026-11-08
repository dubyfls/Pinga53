// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// asOf is fixed so every result here is a function of its inputs. A test that
// reads the clock passes or fails on the day it is run — see FINDING-60.
var asOf = time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

// --- fixtures -----------------------------------------------------------------

func citation() map[string]any {
	return map[string]any{
		"url":        "https://example.org/terms",
		"checked_on": "2026-09-01",
		"quote":      "Use of the data for internal security purposes is permitted.",
	}
}

func evidence() map[string]any {
	return map[string]any{
		"provider_terms":            []any{citation()},
		"technical_capability":      []any{},
		"researcher_interpretation": "read as permitting a local, non-published lookup",
		"unresolved_questions":      []any{},
	}
}

func grant(status string, conditions ...map[string]any) map[string]any {
	c := []any{}
	for _, x := range conditions {
		c = append(c, x)
	}
	g := map[string]any{"status": status, "conditions": c, "evidence": evidence()}
	if status == GrantUnknown || status == GrantNotApplicable {
		g["evidence"] = map[string]any{
			"provider_terms":            []any{},
			"technical_capability":      []any{},
			"researcher_interpretation": "not established",
			"unresolved_questions":      []any{"whether the terms address this at all"},
		}
	}
	return g
}

func condition(id, satisfied string) map[string]any {
	return map[string]any{
		"id":        id,
		"text":      "attribution must accompany any published use",
		"satisfied": satisfied,
		"basis":     "assessed against the intended local-only deployment",
	}
}

// permissions builds a full grant set, defaulting to prohibited so that a test
// which forgets an operation fails closed rather than open.
func permissions(overrides map[Operation]map[string]any) map[string]any {
	out := map[string]any{}
	for _, op := range AllOperations {
		out[string(op)] = grant(GrantProhibited)
	}
	for op, g := range overrides {
		out[string(op)] = g
	}
	return out
}

func validSource() map[string]any {
	return map[string]any{
		"source_id":                     "src-0001",
		"catalog_ref":                   "1",
		"requested_priority":            "VERY HIGH (user-supplied input, not a finding)",
		"official_name":                 "Example Threat Feed",
		"official_documentation":        "https://example.org/docs/feed",
		"verified_on":                   "2026-09-01",
		"kind":                          "bulk feed",
		"indicator_types":               []any{"domain"},
		"classification_meaning":        "the provider labels an entry `phishing` when it has observed credential harvesting",
		"authentication":                "none",
		"quotas":                        "unknown",
		"update_cadence":                "hourly, per the provider's documentation",
		"retention":                     "unknown",
		"withdrawal_behaviour":          "entries disappear without a tombstone",
		"attribution_required":          "yes",
		"derived_data_restrictions":     "unknown",
		"upstream_sources":              []any{},
		"upstream_sources_completeness": UpstreamDocumentedComplete,
		"aggregation_dependencies":      []any{},
		"access_status":                 "verified-available",
		"disposition_reason":            "documentation read in full; terms permit the intended local use",
		"privacy_implications":          "carries no personal data beyond domain registration contacts",
		"intended_permitted_use":        "local blocklist candidate generation for one household",
		"coverage_limitations":          "documented coverage is phishing only; no malware or scam-shop coverage claimed",
		"operational_cost":              "unknown",
		"intended_operations":           []any{string(OpRetrieval), string(OpLocalStorage)},
		"permissions": permissions(map[Operation]map[string]any{
			OpRetrieval:    grant(GrantPermitted),
			OpLocalStorage: grant(GrantPermitted),
		}),
		"enabled": false,
	}
}

func registryWith(sources ...map[string]any) []byte {
	if sources == nil {
		sources = []map[string]any{}
	}
	return registryDoc(1, []any{}, sources)
}

func registryDoc(version int, retired []any, sources []map[string]any) []byte {
	b, err := json.Marshal(map[string]any{
		"schema_version":     SchemaVersion + version - 1, // version==1 -> current
		"note":               "test fixture",
		"retired_source_ids": retired,
		"sources":            sources,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// --- harness ------------------------------------------------------------------

func problemsFor(t *testing.T, b []byte) []Problem {
	t.Helper()
	reg, parseProblems, err := Parse(b)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return append(parseProblems, reg.Validate(asOf)...)
}

func assertProblem(t *testing.T, problems []Problem, wantPath, wantSubstring string) {
	t.Helper()
	for _, p := range problems {
		if p.Path == wantPath && strings.Contains(p.Message, wantSubstring) {
			return
		}
	}
	t.Errorf("no problem at %q containing %q.\nGot:\n%s", wantPath, wantSubstring, render(problems))
}

func assertNoProblems(t *testing.T, problems []Problem) {
	t.Helper()
	if len(problems) != 0 {
		t.Errorf("expected no problems, got:\n%s", render(problems))
	}
}

func render(problems []Problem) string {
	var sb strings.Builder
	for _, p := range problems {
		sb.WriteString("  " + p.String() + "\n")
	}
	if sb.Len() == 0 {
		return "  (none)"
	}
	return sb.String()
}

func decodeOne(t *testing.T, b []byte) *Registry {
	t.Helper()
	reg, _, err := Parse(b)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return reg
}

// --- baseline -----------------------------------------------------------------

func TestAValidRecordPasses(t *testing.T) {
	assertNoProblems(t, problemsFor(t, registryWith(validSource())))
}

func TestAnEmptyRegistryIsValid(t *testing.T) {
	assertNoProblems(t, problemsFor(t, registryWith()))
}

// --- absent is not `unknown` --------------------------------------------------

func TestEveryRequiredFieldIsRequired(t *testing.T) {
	for _, field := range RequiredSourceFields {
		t.Run(field, func(t *testing.T) {
			s := validSource()
			delete(s, field)
			assertProblem(t, problemsFor(t, registryWith(s)), "sources[0]."+field, "required and absent")
		})
	}
}

func TestAnAbsentFieldIsNotTheSameAsUnknown(t *testing.T) {
	absent := validSource()
	delete(absent, "quotas")
	assertProblem(t, problemsFor(t, registryWith(absent)), "sources[0].quotas", "required and absent")

	stated := validSource()
	stated["quotas"] = "unknown"
	assertNoProblems(t, problemsFor(t, registryWith(stated)))
}

// TestAMisspelledFieldIsRefused.
//
// ORDER 8 changed what this diagnostic may say, not whether it says it.
// FINDING-131: the path used to be built from the document's own key, so a
// registry file could put arbitrary bytes into the operator's terminal. An
// unknown key is now located by position, and the help a misspelling actually
// needs comes from the schema's own vocabulary instead — which is a stronger
// statement than the old one, because `quota` never appears in the output at
// all and `quotas` is still named.
func TestAMisspelledFieldIsRefused(t *testing.T) {
	s := validSource()
	delete(s, "quotas")
	s["quota"] = "unknown"
	p := problemsFor(t, registryWith(s))
	assertProblem(t, p, "sources[0].<unrecognised>", "not a field in the schema")
	assertProblem(t, p, "sources[0].<unrecognised>", `the closest field this schema defines is "quotas"`)
	assertProblem(t, p, "sources[0].quotas", "required and absent")

	// The misspelled key itself is never reproduced.
	for _, prob := range p {
		if strings.Contains(prob.Path, "quota\"") || prob.Path == "sources[0].quota" {
			t.Errorf("the diagnostic reproduces the document's key: %s", prob)
		}
	}
}

func TestAnEmptyStringIsRefusedWhereUnknownIsTheAnswer(t *testing.T) {
	s := validSource()
	s["retention"] = "   "
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].retention", "write `unknown`")
}

// --- A. conditional rights and per-operation authorization ---------------------

func TestConditionalAloneAuthorizesNothing(t *testing.T) {
	// The defect this section exists to close: `conditional` in a rights field
	// must not become a permission just by being present.
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantConditional, condition("attribution", ConditionUnknown)),
		OpLocalStorage: grant(GrantPermitted),
	})
	s["enabled"] = true
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].enabled", "satisfaction unknown")
}

func TestAnUnmetConditionPreventsTheOperation(t *testing.T) {
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantConditional, condition("paid-tier", ConditionUnsatisfied)),
		OpLocalStorage: grant(GrantPermitted),
	})
	s["enabled"] = true
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].enabled", "not satisfied")
}

func TestEverySatisfiedConditionAuthorizesTheOperation(t *testing.T) {
	// The positive control. Without it every case above would pass against a
	// validator that simply refused everything conditional.
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantConditional, condition("attribution", ConditionSatisfied)),
		OpLocalStorage: grant(GrantPermitted),
	})
	s["enabled"] = true
	assertNoProblems(t, problemsFor(t, registryWith(s)))
}

func TestConditionalWithNoConditionsIsRefused(t *testing.T) {
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantConditional),
		OpLocalStorage: grant(GrantPermitted),
	})
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].permissions.retrieval.conditions", "enumerate what must hold")
}

func TestAnUnknownGrantPreventsTheOperation(t *testing.T) {
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantUnknown),
		OpLocalStorage: grant(GrantPermitted),
	})
	s["enabled"] = true
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].enabled", "unestablished right is refused")
}

func TestALocalLookupDoesNotRequireRedistributionRights(t *testing.T) {
	// "Do not require redistribution permission merely to perform a permitted
	// local lookup." Redistribution and derived output are both prohibited
	// here; the source intends neither, and must still be usable.
	s := validSource()
	s["intended_operations"] = []any{string(OpRetrieval), string(OpLocalStorage)}
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantPermitted),
		OpLocalStorage: grant(GrantPermitted),
		// everything else, including redistribution, defaults to prohibited
	})
	s["enabled"] = true
	assertNoProblems(t, problemsFor(t, registryWith(s)))
}

func TestPermissionToQueryDoesNotImplyPermissionToPublish(t *testing.T) {
	// The converse, and the more dangerous direction. Retrieval is permitted;
	// the record nonetheless intends to publish derived output, which its terms
	// do not grant.
	s := validSource()
	s["intended_operations"] = []any{string(OpRetrieval), string(OpDerivedOutput)}
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval: grant(GrantPermitted),
	})
	s["enabled"] = true
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].enabled", "derived_output is prohibited")
}

func TestAnOperationWithNoGrantIsNotAuthorizedBySilence(t *testing.T) {
	s := validSource()
	perms := permissions(map[Operation]map[string]any{OpRetrieval: grant(GrantPermitted)})
	delete(perms, string(OpModelTraining))
	s["permissions"] = perms
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].permissions.model_training", "authorised by silence")
}

func TestAuthorizesReportsEachOperationIndependently(t *testing.T) {
	reg := decodeOne(t, registryWith(validSource()))
	s := &reg.Sources[0]
	for _, tc := range []struct {
		op   Operation
		want bool
	}{
		{OpRetrieval, true},
		{OpLocalStorage, true},
		{OpRedistribution, false},
		{OpDerivedOutput, false},
		{OpModelTraining, false},
	} {
		got, why := s.Authorizes(tc.op)
		if got != tc.want {
			t.Errorf("Authorizes(%s) = %v, want %v (%s)", tc.op, got, tc.want, why)
		}
	}
}

func TestConditionsOnANonConditionalGrantAreRefused(t *testing.T) {
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantPermitted, condition("attribution", ConditionSatisfied)),
		OpLocalStorage: grant(GrantPermitted),
	})
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].permissions.retrieval.conditions", "conditions apply to `conditional` grants only")
}

func TestAConditionRecordedSatisfiedNeedsABasis(t *testing.T) {
	c := condition("attribution", ConditionSatisfied)
	c["basis"] = ""
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    grant(GrantConditional, c),
		OpLocalStorage: grant(GrantPermitted),
	})
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].permissions.retrieval.conditions[0].basis", "without a stated basis")
}

func TestEnablingWithNoIntendedOperationsIsRefused(t *testing.T) {
	s := validSource()
	s["intended_operations"] = []any{}
	s["enabled"] = true
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].intended_operations", "enabling nothing in particular")
}

func TestEnablingRequiresAVerifiedAvailableDisposition(t *testing.T) {
	for _, status := range []string{"credentials-required", "commercial-approval-required", "historical", "unavailable", "unresolved"} {
		t.Run(status, func(t *testing.T) {
			s := validSource()
			s["access_status"] = status
			s["enabled"] = true
			assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].enabled", "only `verified-available` may be enabled")
		})
	}
}

// --- B. evidence ---------------------------------------------------------------

func TestARightsAssertionNeedsACitation(t *testing.T) {
	g := grant(GrantPermitted)
	g["evidence"] = map[string]any{
		"provider_terms":            []any{},
		"technical_capability":      []any{},
		"researcher_interpretation": "seems fine",
		"unresolved_questions":      []any{},
	}
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    g,
		OpLocalStorage: grant(GrantPermitted),
	})
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].permissions.retrieval.evidence.provider_terms", "an opinion")
}

func TestACitationNeedsAnHTTPSURLADateAndAQuote(t *testing.T) {
	for _, tc := range []struct{ field, value, want string }{
		{"url", "http://example.org/terms", "must be fetched over https"},
		{"url", "terms.html", "not an absolute URL"},
		{"checked_on", "last Tuesday", "must be a date"},
		{"checked_on", "2027-01-01", "in the future"},
		{"quote", "  ", "record what the page actually said"},
	} {
		t.Run(tc.field+"/"+tc.value, func(t *testing.T) {
			c := citation()
			c[tc.field] = tc.value
			g := grant(GrantPermitted)
			g["evidence"] = map[string]any{
				"provider_terms":            []any{c},
				"technical_capability":      []any{},
				"researcher_interpretation": "x",
				"unresolved_questions":      []any{},
			}
			s := validSource()
			s["permissions"] = permissions(map[Operation]map[string]any{
				OpRetrieval:    g,
				OpLocalStorage: grant(GrantPermitted),
			})
			assertProblem(t, problemsFor(t, registryWith(s)),
				"sources[0].permissions.retrieval.evidence.provider_terms[0]."+tc.field, tc.want)
		})
	}
}

func TestEvidenceKeepsTermsCapabilitiesInterpretationAndQuestionsApart(t *testing.T) {
	// The four are separate fields, and a record can carry all four at once
	// without one standing in for another. This is the structural half of "do
	// not mistake a commercial marketing page for proof of available API
	// fields": the capability citation and the terms citation are different
	// slots and are validated separately.
	g := grant(GrantConditional, condition("attribution", ConditionSatisfied))
	g["evidence"] = map[string]any{
		"provider_terms": []any{citation()},
		"technical_capability": []any{map[string]any{
			"url":        "https://example.org/api",
			"checked_on": "2026-09-01",
			"quote":      "GET /v1/domains returns first_seen and last_seen",
		}},
		"researcher_interpretation": "the API exposes the fields the adapter needs; the terms permit local use only",
		"unresolved_questions":      []any{"whether first_seen is the provider's or the upstream's observation time"},
	}
	s := validSource()
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval:    g,
		OpLocalStorage: grant(GrantPermitted),
	})
	assertNoProblems(t, problemsFor(t, registryWith(s)))

	reg := decodeOne(t, registryWith(s))
	ev := reg.Sources[0].Permissions[OpRetrieval].Evidence
	if len(ev.ProviderTerms) != 1 || len(ev.TechnicalCapability) != 1 {
		t.Fatalf("terms and capabilities did not survive as separate slots: %+v", ev)
	}
	if len(ev.UnresolvedQuestions) != 1 {
		t.Errorf("unresolved questions were not preserved: %+v", ev.UnresolvedQuestions)
	}
	if ev.ResearcherInterpretation == "" {
		t.Error("researcher interpretation was not preserved")
	}
}

// --- C. identifier retirement --------------------------------------------------

func TestDeletingASourceWithoutRetiringItsIDBypassesTheCurrentFileRule(t *testing.T) {
	// The bypass, demonstrated rather than asserted. Each file below validates
	// on its own; only a comparison between them sees the problem.
	before := decodeOne(t, registryWith(validSource()))
	assertNoProblems(t, before.Validate(asOf))

	reused := validSource()
	reused["official_name"] = "A Completely Different Provider"
	after := decodeOne(t, registryWith(reused))
	assertNoProblems(t, after.Validate(asOf))

	// Same id, different provider, and the current-file validator is silent.
	if before.Sources[0].SourceID != after.Sources[0].SourceID {
		t.Fatal("fixture error: the ids should be identical")
	}
	problems := ValidateAgainstBaseline(before, after)
	assertProblem(t, problems, "sources.src-0001.official_name", "in the baseline this id was")
}

func TestARemovedSourceMustBeRetired(t *testing.T) {
	before := decodeOne(t, registryWith(validSource()))
	after := decodeOne(t, registryWith())
	problems := ValidateAgainstBaseline(before, after)
	assertProblem(t, problems, "retired_source_ids", "has not been retired")
}

func TestARemovedAndRetiredSourceIsAccepted(t *testing.T) {
	before := decodeOne(t, registryWith(validSource()))
	after := decodeOne(t, registryDoc(1, []any{"src-0001"}, nil))
	if p := ValidateAgainstBaseline(before, after); len(p) != 0 {
		t.Errorf("retiring a removed id should be accepted, got:\n%s", render(p))
	}
}

func TestRetirementIsPermanent(t *testing.T) {
	before := decodeOne(t, registryDoc(1, []any{"src-0009"}, nil))
	after := decodeOne(t, registryWith())
	assertProblem(t, ValidateAgainstBaseline(before, after), "retired_source_ids", "retirement is permanent")
}

func TestARetiredIDCannotBeTakenAgain(t *testing.T) {
	b := registryDoc(1, []any{"src-0001"}, []map[string]any{validSource()})
	assertProblem(t, problemsFor(t, b), "sources[0].source_id", "retired id is never reused")
}

func TestASourceIDIsNeverReusedWithinTheFile(t *testing.T) {
	a, b := validSource(), validSource()
	b["catalog_ref"] = "2"
	assertProblem(t, problemsFor(t, registryWith(a, b)), "sources[1].source_id", "ids are never reused")
}

// --- D. lineage ----------------------------------------------------------------

func TestARecordCannotDependOnItself(t *testing.T) {
	s := validSource()
	s["aggregation_dependencies"] = []any{"src-0001"}
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].aggregation_dependencies[0]", "cannot be an upstream of itself")
}

func TestATwoNodeLineageCycleIsRefused(t *testing.T) {
	a, b := validSource(), validSource()
	b["source_id"] = "src-0002"
	b["catalog_ref"] = "2"
	a["aggregation_dependencies"] = []any{"src-0002"}
	b["aggregation_dependencies"] = []any{"src-0001"}
	a["upstream_sources"] = []any{"src-0002"}
	b["upstream_sources"] = []any{"src-0001"}
	problems := problemsFor(t, registryWith(a, b))
	found := false
	for _, p := range problems {
		if strings.Contains(p.Message, "lineage cycle") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a lineage cycle finding, got:\n%s", render(problems))
	}
}

func TestAThreeNodeLineageCycleIsRefused(t *testing.T) {
	a, b, c := validSource(), validSource(), validSource()
	b["source_id"], b["catalog_ref"] = "src-0002", "2"
	c["source_id"], c["catalog_ref"] = "src-0003", "3"
	a["aggregation_dependencies"] = []any{"src-0002"}
	b["aggregation_dependencies"] = []any{"src-0003"}
	c["aggregation_dependencies"] = []any{"src-0001"}
	for _, s := range []map[string]any{a, b, c} {
		s["upstream_sources"] = []any{"documented"}
	}
	problems := problemsFor(t, registryWith(a, b, c))
	found := 0
	for _, p := range problems {
		if strings.Contains(p.Message, "lineage cycle") {
			found++
		}
	}
	if found != 1 {
		t.Errorf("expected exactly one cycle finding, got %d:\n%s", found, render(problems))
	}
}

func TestAnAcyclicLineageChainIsAccepted(t *testing.T) {
	a, b := validSource(), validSource()
	b["source_id"], b["catalog_ref"] = "src-0002", "2"
	b["aggregation_dependencies"] = []any{"src-0001"}
	b["upstream_sources"] = []any{"Example Threat Feed"}
	assertNoProblems(t, problemsFor(t, registryWith(a, b)))
}

func TestADependencyMustNameARecordThatExists(t *testing.T) {
	s := validSource()
	s["aggregation_dependencies"] = []any{"src-9999"}
	s["upstream_sources"] = []any{"someone"}
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].aggregation_dependencies[0]", "establishes nothing")
}

func TestADuplicateDependencyIsRefused(t *testing.T) {
	a, b := validSource(), validSource()
	b["source_id"], b["catalog_ref"] = "src-0002", "2"
	b["aggregation_dependencies"] = []any{"src-0001", "src-0001"}
	b["upstream_sources"] = []any{"Example Threat Feed"}
	assertProblem(t, problemsFor(t, registryWith(a, b)), "sources[1].aggregation_dependencies[1]", "twice")
}

func TestAnUnknownUpstreamIsNotDemonstratedIndependence(t *testing.T) {
	for _, tc := range []struct {
		completeness string
		claimable    bool
		want         string
	}{
		{UpstreamDocumentedComplete, true, ""},
		{UpstreamDocumentedPartial, false, "only partially"},
		{UpstreamUnknown, false, "not demonstrated independence"},
	} {
		t.Run(tc.completeness, func(t *testing.T) {
			s := validSource()
			s["upstream_sources_completeness"] = tc.completeness
			reg := decodeOne(t, registryWith(s))
			got, why := reg.Sources[0].IndependenceClaimable()
			if got != tc.claimable {
				t.Fatalf("IndependenceClaimable() = %v, want %v (%s)", got, tc.claimable, why)
			}
			if tc.want != "" && !strings.Contains(why, tc.want) {
				t.Errorf("reason %q does not contain %q", why, tc.want)
			}
		})
	}
}

func TestCompleteUpstreamsContradictedByLineageEdgesIsRefused(t *testing.T) {
	a, b := validSource(), validSource()
	b["source_id"], b["catalog_ref"] = "src-0002", "2"
	b["aggregation_dependencies"] = []any{"src-0001"}
	b["upstream_sources"] = []any{}
	b["upstream_sources_completeness"] = UpstreamDocumentedComplete
	assertProblem(t, problemsFor(t, registryWith(a, b)), "sources[1].upstream_sources", "contradict each other")
}

func TestUpstreamCompletenessIsAClosedVocabulary(t *testing.T) {
	s := validSource()
	s["upstream_sources_completeness"] = "probably complete"
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].upstream_sources_completeness", "permitted values are")
}

// --- E. input handling ---------------------------------------------------------

func TestDuplicateJSONKeysAreRefused(t *testing.T) {
	// encoding/json keeps the last occurrence silently. For a document of
	// record that is the worst possible resolution: the reviewer reads the
	// first value and the program uses the second.
	raw := []byte(`{
	  "schema_version": 2,
	  "note": "x",
	  "retired_source_ids": [],
	  "sources": [],
	  "note": "y"
	}`)
	_, problems, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	assertProblem(t, problems, "note", "appears twice")
}

func TestADuplicateKeyInsideARecordIsRefused(t *testing.T) {
	raw := []byte(`{
	  "schema_version": 2, "note": "x", "retired_source_ids": [],
	  "sources": [ { "source_id": "src-0001", "source_id": "src-0002" } ]
	}`)
	_, problems, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	assertProblem(t, problems, "sources[0].source_id", "appears twice")
}

func TestAFieldOfTheWrongTypeIsLocatedRatherThanFatal(t *testing.T) {
	// A type error must not abort the document and take every other diagnostic
	// with it.
	for _, tc := range []struct {
		field string
		value any
		want  string
	}{
		{"source_id", 7, "is a number; this field must be a string"},
		{"indicator_types", "domain", "is a string; this field must be an array"},
		{"enabled", "true", "is a string; this field must be a boolean"},
		{"permissions", []any{}, "is an array; this field must be an object"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			s := validSource()
			s[tc.field] = tc.value
			_, problems, err := Parse(registryWith(s))
			if err != nil {
				t.Fatalf("a wrong type should be a located problem, not a parse failure: %v", err)
			}
			assertProblem(t, problems, "sources[0]."+tc.field, tc.want)
		})
	}
}

func TestAnUnsupportedSchemaVersionIsRefusedAndStopsThere(t *testing.T) {
	b, err := json.Marshal(map[string]any{
		"schema_version": 1, "note": "x", "retired_source_ids": []any{},
		"sources": []map[string]any{validSource()},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := decodeOne(t, b)
	problems := reg.Validate(asOf)
	assertProblem(t, problems, "schema_version", "accepts version 2 only")
	// It must not go on to emit confident findings about a document whose
	// field meanings it does not know.
	if len(problems) != 1 {
		t.Errorf("expected validation to stop at the version, got:\n%s", render(problems))
	}
}

func TestAnOversizeRegistryIsRefused(t *testing.T) {
	big := make([]byte, MaxRegistryBytes+1)
	for i := range big {
		big[i] = ' '
	}
	if _, _, err := Parse(big); err == nil {
		t.Fatal("expected an oversize registry to be refused")
	} else if !strings.Contains(err.Error(), "over the") {
		t.Errorf("refusal did not name the limit: %v", err)
	}
}

func TestTrailingContentIsRefused(t *testing.T) {
	raw := []byte(`{"schema_version":2,"note":"x","retired_source_ids":[],"sources":[]}{"schema_version":2}`)
	if _, _, err := Parse(raw); err == nil {
		t.Fatal("expected trailing content to be refused")
	}
}

func TestMalformedJSONIsAParseFailureNotAValidationFailure(t *testing.T) {
	if _, _, err := Parse([]byte("{ not json")); err == nil {
		t.Fatal("expected a parse error")
	}
}

func TestInvalidDatesAreRefused(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"2026-13-01", "must be a date"},
		{"2026-02-30", "must be a date"},
		{"09/01/2026", "must be a date"},
		{"2027-01-01", "in the future"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			s := validSource()
			s["verified_on"] = tc.value
			assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].verified_on", tc.want)
		})
	}
}

func TestUnknownTopLevelKeysAreRefused(t *testing.T) {
	raw := []byte(`{"schema_version":2,"note":"x","retired_source_ids":[],"sources":[],"extra":1}`)
	if _, _, err := Parse(raw); err == nil {
		t.Fatal("expected an unknown top-level key to be refused")
	}
}

// --- disposition and documentation --------------------------------------------

func TestAnInventedDispositionIsRefused(t *testing.T) {
	s := validSource()
	s["access_status"] = "probably-fine"
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].access_status", "permitted values are")
}

func TestAResearchedRecordMustCarryItsDateAndURL(t *testing.T) {
	s := validSource()
	s["verified_on"] = "unknown"
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].verified_on", "states nothing current")

	s2 := validSource()
	s2["official_documentation"] = "unknown"
	assertProblem(t, problemsFor(t, registryWith(s2)), "sources[0].official_documentation", "record the URL")
}

func TestAnUnresolvedRecordMayBeUndated(t *testing.T) {
	s := validSource()
	s["access_status"] = "unresolved"
	s["verified_on"] = "unknown"
	s["official_documentation"] = "unknown"
	s["disposition_reason"] = "not yet researched"
	s["enabled"] = false
	s["permissions"] = permissions(map[Operation]map[string]any{
		OpRetrieval: grant(GrantUnknown), OpLocalStorage: grant(GrantUnknown),
		OpEnrichment: grant(GrantUnknown), OpModelTraining: grant(GrantUnknown),
		OpCommercialUse: grant(GrantUnknown), OpRedistribution: grant(GrantUnknown),
		OpDerivedOutput: grant(GrantUnknown),
	})
	assertNoProblems(t, problemsFor(t, registryWith(s)))
}

// --- the shipped registry -----------------------------------------------------

func shippedPath() string { return filepath.Join("..", "..", "docs", "source-registry.json") }

func TestTheShippedRegistryIsValid(t *testing.T) {
	if _, err := os.Stat(shippedPath()); err != nil {
		t.Fatalf("the shipped registry is missing: %v", err)
	}
	reg, parseProblems, err := Load(shippedPath())
	if err != nil {
		t.Fatalf("the shipped registry did not parse: %v", err)
	}
	problems := append(parseProblems, reg.Validate(time.Now())...)
	if len(problems) != 0 {
		t.Fatalf("the shipped registry does not validate:\n%s", render(problems))
	}
}

func TestTheShippedRegistryEnablesNothingAndClaimsNoAvailability(t *testing.T) {
	// The two properties the research pass did not change, and must not.
	//
	// `enabled` is the switch. Nothing may be on, because enabling is a
	// separate decision from researching and nobody has taken it.
	//
	// `verified-available` requires, by §3, that access is CONFIRMED — not
	// merely documented. The order under which every record here was written
	// forbids fetching the data, so no record can honestly claim it, however
	// clear its terms turned out to be. Several records say exactly that in
	// their disposition_reason, and this is the check that keeps them honest.
	reg, _, err := Load(shippedPath())
	if err != nil {
		t.Fatalf("the shipped registry did not parse: %v", err)
	}
	for i, s := range reg.Sources {
		if s.Enabled {
			t.Errorf("sources[%d] (%s) is enabled; no source has been qualified", i, s.SourceID)
		}
		if s.AccessStatus == "verified-available" {
			t.Errorf("sources[%d] (%s) claims verified-available; access has been documented, never confirmed", i, s.SourceID)
		}
	}
}

func TestNoAuthorisedOperationIsAlsoAnIntendedOne(t *testing.T) {
	// THIS TEST REPLACED A STRICTER ONE, AND THE REASON MATTERS.
	//
	// Until the first research pass, the shipped registry authorised no
	// operation at all, and a test asserted exactly that. It could, because the
	// file held zero records. It cannot now: two providers — catalog 37 under
	// CC0 and catalog 80 under CC0 — grant every operation with nothing to
	// satisfy, and recording those as `conditional` or `unknown` to keep a test
	// green would have been a false record. The registry's whole purpose is to
	// stop that, so the record was written truthfully and the test was changed
	// deliberately, which is what its predecessor's comment said should happen.
	//
	// What replaces it is not weaker in the way that matters. A grant says what
	// a PROVIDER permits; `intended_operations` says what this PROJECT proposes
	// to do. Harm needs both. So the invariant is that the two sets never meet
	// in the shipped file: no record may declare an intended operation while
	// its terms authorise it, until somebody deliberately edits this test.
	//
	// Phase E proposes operations in prose — docs/IMPLEMENTATION_PLAN.md — and
	// writes none of them here. Moving a proposal into the registry is the act
	// this test is positioned to catch.
	reg, _, err := Load(shippedPath())
	if err != nil {
		t.Fatalf("the shipped registry did not parse: %v", err)
	}
	authorising := 0
	for i, s := range reg.Sources {
		for _, op := range AllOperations {
			ok, _ := s.Authorizes(op)
			if !ok {
				continue
			}
			authorising++
			if contains(s.IntendedOperations, string(op)) {
				t.Errorf("sources[%d] (%s) both authorises %s and declares it intended; that pair is the step this test exists to make deliberate",
					i, s.SourceID, op)
			}
		}
		if len(s.IntendedOperations) != 0 {
			t.Errorf("sources[%d] (%s) declares intended operations %v; this order proposes operations in prose and writes none into the registry",
				i, s.SourceID, s.IntendedOperations)
		}
	}
	t.Logf("authorised operations across the shipped registry: %d", authorising)
}

func TestTheShippedRegistryReportsItsOwnCoverage(t *testing.T) {
	// A standing statement of where qualification has got to, so the report and
	// the file cannot drift apart.
	reg, _, err := Load(shippedPath())
	if err != nil {
		t.Fatalf("the shipped registry did not parse: %v", err)
	}
	byStatus := map[string]int{}
	for _, s := range reg.Sources {
		byStatus[s.AccessStatus]++
	}
	t.Logf("records=%d retired=%d by disposition=%v", len(reg.Sources), len(reg.RetiredSourceIDs), byStatus)
	if len(reg.Sources) != 0 {
		t.Logf("NOTE: the registry is no longer empty; update the coverage figures in docs/VERIFICATION.md")
	}
}

var _ = fmt.Sprintf

// --- the version walk ----------------------------------------------------------

func TestTheVersionWalkCatchesTheRemovalThatWouldAllowAReuse(t *testing.T) {
	// The bypass as it actually happens: present, then removed without
	// retirement, then taken again by a different provider.
	//
	// The walk flags the MIDDLE step, not the last one. That is worth being
	// precise about, because it is the difference between what this mechanism
	// proves and what it is easy to assume it proves. At v2 -> v3 the id is
	// absent from the baseline, so nothing there can know it ever meant
	// something else; by then the information is gone. The enforceable moment
	// is the removal, and that is where the gate goes red.
	//
	// Three rules together give the invariant, and none of them gives it alone:
	// removing a record must retire its id (here), retirement is permanent
	// (TestRetirementIsPermanent), and a retired id cannot be taken
	// (TestARetiredIDCannotBeTakenAgain).
	present := decodeOne(t, registryWith(validSource()))
	gone := decodeOne(t, registryWith())
	taken := validSource()
	taken["official_name"] = "An Entirely Different Provider"
	reused := decodeOne(t, registryWith(taken))

	problems := ValidateVersionChain(
		[]*Registry{present, gone, reused},
		[]string{"v1", "v2", "v3"},
	)
	assertProblem(t, problems, "v1 -> v2: retired_source_ids", "has not been retired")

	// And explicitly: the last step is silent, which is why the middle one has
	// to be enforced rather than treated as advisory.
	for _, p := range problems {
		if strings.HasPrefix(p.Path, "v2 -> v3") {
			t.Errorf("unexpected finding at the reappearance step; the walk cannot see it, and a test claiming otherwise would overstate the mechanism: %s", p)
		}
	}
}

func TestASwapWithinOneVersionIsCaught(t *testing.T) {
	// When removal and reissue happen in the SAME step, the baseline still
	// carries the old meaning and the swap is caught directly.
	before := decodeOne(t, registryWith(validSource()))
	swapped := validSource()
	swapped["official_name"] = "An Entirely Different Provider"
	after := decodeOne(t, registryWith(swapped))
	assertProblem(t, ValidateVersionChain([]*Registry{before, after}, []string{"v1", "v2"}),
		"v1 -> v2: sources.src-0001.official_name", "in the baseline this id was")
}

func TestTheVersionWalkAcceptsACorrectRetirementAndReissue(t *testing.T) {
	// The same shape done properly: retire the id, and give the new provider a
	// new one. This must be accepted, or the rule would forbid ever removing a
	// source.
	present := decodeOne(t, registryWith(validSource()))
	gone := decodeOne(t, registryDoc(1, []any{"src-0001"}, nil))

	fresh := validSource()
	fresh["source_id"] = "src-0002"
	fresh["catalog_ref"] = "2"
	fresh["official_name"] = "An Entirely Different Provider"
	next := decodeOne(t, registryDoc(1, []any{"src-0001"}, []map[string]any{fresh}))

	if p := ValidateVersionChain([]*Registry{present, gone, next}, nil); len(p) != 0 {
		t.Errorf("a retirement followed by a new id should be accepted, got:\n%s", render(p))
	}
}

// --- FINDING-69: `unknown` in the kind and authentication vocabularies ---------

func TestKindAndAuthenticationAcceptUnknown(t *testing.T) {
	// The gap the first research pass exposed. A provider whose documentation
	// answers HTTP 403 has a product shape and an access model; nobody has read
	// either. docs/SOURCE_REGISTRY.md §2 says "`unknown` is a permitted value
	// and is not the same as absent", and before FINDING-69 these two
	// vocabularies contradicted it — leaving an author to invent a value or to
	// write an empty string, which is refused separately. Both are worse than
	// recording that nobody knows.
	s := validSource()
	s["kind"] = "unknown"
	s["authentication"] = "unknown"
	s["access_status"] = "unresolved"
	s["verified_on"] = "unknown"
	s["official_documentation"] = "unknown"
	assertNoProblems(t, problemsFor(t, registryWith(s)))
}

func TestAnInventedKindIsStillRefused(t *testing.T) {
	// Adding `unknown` must not be read as opening the vocabulary. Everything
	// else outside it is still refused, which is the whole point of a closed
	// set.
	s := validSource()
	s["kind"] = "threat intelligence platform"
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].kind", "permitted values are")
}

func TestAnInventedAuthenticationIsStillRefused(t *testing.T) {
	s := validSource()
	s["authentication"] = "oauth"
	assertProblem(t, problemsFor(t, registryWith(s)), "sources[0].authentication", "permitted values are")
}
