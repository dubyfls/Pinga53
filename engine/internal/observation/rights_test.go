// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// synthReg builds a registry from records written for this test.
//
// It is synthetic on purpose and says so: binding these tests to the shipped
// registry's current contents would make them fail whenever a real research
// pass changed a disposition, which is a change to evidence and not to this
// code. One test below does read the shipped file, and it asserts only
// properties that must hold whatever is in it.
func synthReg(t *testing.T, sources ...sourceregistry.Source) *sourceregistry.Registry {
	t.Helper()
	return &sourceregistry.Registry{SchemaVersion: 2, Sources: sources}
}

func src(id string, completeness string, deps []string, grants map[sourceregistry.Operation]string) sourceregistry.Source {
	perms := map[sourceregistry.Operation]sourceregistry.Grant{}
	for _, op := range sourceregistry.AllOperations {
		status, ok := grants[op]
		if !ok {
			status = sourceregistry.GrantUnknown
		}
		perms[op] = sourceregistry.Grant{Status: status}
	}
	return sourceregistry.Source{
		SourceID:                    id,
		UpstreamSourcesCompleteness: completeness,
		AggregationDependencies:     deps,
		Permissions:                 perms,
	}
}

func allOf(status string) map[sourceregistry.Operation]string {
	m := map[sourceregistry.Operation]string{}
	for _, op := range sourceregistry.AllOperations {
		m[op] = status
	}
	return m
}

func indicatorOf(t *testing.T, sourceIDs ...string) Indicator {
	t.Helper()
	s := NewStore()
	for _, id := range sourceIDs {
		if _, err := s.Add(mustNew(t, "example.com", id)); err != nil {
			t.Fatal(err)
		}
	}
	ind, _ := s.Lookup(Key{Type: TypeDomain, Canonical: "example.com"})
	return ind
}

// --- lineage -------------------------------------------------------------

func TestTwoDocumentedSourcesAreTwoIndependentVoices(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, nil),
	)
	c := indicatorOf(t, "src-0001", "src-0002").Corroborate(reg, t1)
	if c.IndependentCount() != 2 {
		t.Errorf("independent = %v (%d), want 2", c.Independent, c.IndependentCount())
	}
}

// TestAnAggregatorAndItsUpstreamAreOneVoice is the second inflation: counting
// a feed and the feed it copied.
func TestAnAggregatorAndItsUpstreamAreOneVoice(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil),
		src("src-0009", sourceregistry.UpstreamDocumentedComplete, []string{"src-0001"}, nil),
	)
	c := indicatorOf(t, "src-0001", "src-0009").Corroborate(reg, t1)
	if c.IndependentCount() != 1 {
		t.Errorf("independent = %v (%d), want 1; an aggregator and its upstream are one observation", c.Independent, c.IndependentCount())
	}
	if len(c.Collapsed) != 1 || c.Collapsed[0].Source != "src-0009" || c.Collapsed[0].Upstream != "src-0001" {
		t.Errorf("collapsed = %+v", c.Collapsed)
	}
	if c.SupportingCount() != 2 {
		t.Errorf("supporting = %d, want 2; both sources did report it and that is reported too", c.SupportingCount())
	}
}

// TestALineageChainCollapsesThroughItsMiddle covers the transitive case, where
// the aggregator names an intermediary rather than the original.
func TestALineageChainCollapsesThroughItsMiddle(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, []string{"src-0001"}, nil),
		src("src-0003", sourceregistry.UpstreamDocumentedComplete, []string{"src-0002"}, nil),
	)
	c := indicatorOf(t, "src-0001", "src-0003").Corroborate(reg, t1)
	if c.IndependentCount() != 1 {
		t.Errorf("independent = %v; src-0003 draws from src-0001 through src-0002 and is not a second voice", c.Independent)
	}
}

// TestAnUnknownUpstreamIsNotIndependence is the third inflation, and the one
// the registry exists to prevent.
func TestAnUnknownUpstreamIsNotIndependence(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamUnknown, nil, nil),
		src("src-0002", sourceregistry.UpstreamUnknown, nil, nil),
	)
	c := indicatorOf(t, "src-0001", "src-0002").Corroborate(reg, t1)
	if c.IndependentCount() != 0 {
		t.Errorf("independent = %v; nobody has established what either source aggregates", c.Independent)
	}
	if len(c.Unestablished) != 2 {
		t.Errorf("unestablished = %v, want both sources", c.Unestablished)
	}
	if len(c.Notes) == 0 {
		t.Error("the exclusion was silent")
	}
}

func TestPartiallyDocumentedUpstreamsAreNotIndependence(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedPartial, nil, nil),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, nil),
	)
	c := indicatorOf(t, "src-0001", "src-0002").Corroborate(reg, t1)
	if c.IndependentCount() != 1 || c.Independent[0] != "src-0002" {
		t.Errorf("independent = %v, want only src-0002", c.Independent)
	}
}

// TestAnEmptyOrUnknownSourceIDIsNeverCounted is the fourth inflation.
func TestAnUnknownSourceIDIsNeverCounted(t *testing.T) {
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil))
	c := indicatorOf(t, "src-0001", "src-9999").Corroborate(reg, t1)
	if c.IndependentCount() != 1 {
		t.Errorf("independent = %v, want only the resolvable source", c.Independent)
	}
	if len(c.Unresolved) != 1 || c.Unresolved[0] != "src-9999" {
		t.Errorf("unresolved = %v", c.Unresolved)
	}
}

func TestARetiredSourceIDIsDistinguishedFromAnUnknownOne(t *testing.T) {
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil))
	reg.RetiredSourceIDs = []string{"src-0007"}

	c := indicatorOf(t, "src-0001", "src-0007", "src-9999").Corroborate(reg, t1)
	if len(c.Retired) != 1 || c.Retired[0] != "src-0007" {
		t.Errorf("retired = %v", c.Retired)
	}
	if len(c.Unresolved) != 1 || c.Unresolved[0] != "src-9999" {
		t.Errorf("unresolved = %v; a retired id and a typo are different problems", c.Unresolved)
	}
	if c.IndependentCount() != 1 {
		t.Errorf("independent = %v", c.Independent)
	}
}

// TestACyclicLineageTerminates guards the walk against a graph the registry's
// own validator refuses but which this code must not assume away.
func TestACyclicLineageTerminates(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, []string{"src-0002"}, nil),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, []string{"src-0001"}, nil),
	)
	done := make(chan Corroboration, 1)
	go func() { done <- indicatorOf(t, "src-0001", "src-0002").Corroborate(reg, t1) }()
	select {
	case c := <-done:
		if c.IndependentCount() != 0 {
			t.Errorf("independent = %v; each source draws from the other, so neither is a separate voice", c.Independent)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Corroborate did not terminate on a cyclic lineage graph")
	}
}

func TestCorroborationIsDeterministic(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil),
		src("src-0002", sourceregistry.UpstreamUnknown, nil, nil),
		src("src-0003", sourceregistry.UpstreamDocumentedComplete, []string{"src-0001"}, nil),
	)
	ind := indicatorOf(t, "src-0003", "src-0001", "src-0002", "src-9999")
	first := ind.Corroborate(reg, t1)
	for i := 0; i < 20; i++ {
		got := ind.Corroborate(reg, t1)
		if got.IndependentCount() != first.IndependentCount() ||
			len(got.Notes) != len(first.Notes) ||
			len(got.Collapsed) != len(first.Collapsed) {
			t.Fatalf("run %d differs: %+v vs %+v", i, got, first)
		}
		for j := range got.Notes {
			if got.Notes[j] != first.Notes[j] {
				t.Fatalf("run %d note %d differs", i, j)
			}
		}
	}
}

// --- rights --------------------------------------------------------------

func TestADeniedOperationFailsClosed(t *testing.T) {
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil,
		map[sourceregistry.Operation]string{sourceregistry.OpRedistribution: sourceregistry.GrantProhibited}))
	r := indicatorOf(t, "src-0001").Authorizes(reg, sourceregistry.OpRedistribution, t1)
	if r.Permitted {
		t.Error("a prohibited operation was permitted")
	}
	if len(r.Refusals) == 0 {
		t.Error("the refusal carried no reason")
	}
}

func TestAnUnknownGrantFailsClosed(t *testing.T) {
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil))
	for _, op := range sourceregistry.AllOperations {
		if r := indicatorOf(t, "src-0001").Authorizes(reg, op, t1); r.Permitted {
			t.Errorf("%s was permitted while its grant is unknown", op)
		}
	}
}

func TestAnUnresolvableSourceFailsClosed(t *testing.T) {
	reg := synthReg(t)
	r := indicatorOf(t, "src-9999").Authorizes(reg, sourceregistry.OpLocalStorage, t1)
	if r.Permitted {
		t.Error("an operation was authorised by a source that does not exist")
	}
	if r := indicatorOf(t, "src-9999").Authorizes(nil, sourceregistry.OpLocalStorage, t1); r.Permitted {
		t.Error("an operation was authorised with no registry at all")
	}
}

// TestLocalUseDoesNotRequireRedistributionRights is the over-refusal direction,
// which is as much a defect as under-refusal.
func TestLocalUseDoesNotRequireRedistributionRights(t *testing.T) {
	grants := allOf(sourceregistry.GrantPermitted)
	grants[sourceregistry.OpRedistribution] = sourceregistry.GrantProhibited
	grants[sourceregistry.OpDerivedOutput] = sourceregistry.GrantProhibited
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, grants))

	ind := indicatorOf(t, "src-0001")
	if r := ind.UsableLocally(reg, t1); !r.Permitted {
		t.Errorf("a permitted local use was refused: %v", r.Refusals)
	}
	if r := ind.Exportable(reg, t1); r.Permitted {
		t.Error("an indicator that may not be redistributed was reported as exportable")
	}
}

// TestOneRefusingSourceBlocksTheDerivedAggregate is the unanimity rule:
// derivation does not launder provenance.
func TestOneRefusingSourceBlocksTheDerivedAggregate(t *testing.T) {
	permissive := allOf(sourceregistry.GrantPermitted)
	restrictive := allOf(sourceregistry.GrantPermitted)
	restrictive[sourceregistry.OpDerivedOutput] = sourceregistry.GrantProhibited
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, permissive),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, restrictive),
	)

	if r := indicatorOf(t, "src-0001").Exportable(reg, t1); !r.Permitted {
		t.Fatalf("the permissive source alone was refused: %v", r.Refusals)
	}
	r := indicatorOf(t, "src-0001", "src-0002").Exportable(reg, t1)
	if r.Permitted {
		t.Error("one prohibiting contributor did not block the derived aggregate")
	}
	if len(r.Permitting) != 1 || r.Permitting[0] != "src-0001" {
		t.Errorf("permitting = %v; the provenance needed to explain the refusal was lost", r.Permitting)
	}
}

// TestALapsedContributorDoesNotBlockAnOperation is the other side of the same
// rule: an observation that contributed nothing cannot refuse anything.
func TestALapsedContributorDoesNotBlockAnOperation(t *testing.T) {
	permissive := allOf(sourceregistry.GrantPermitted)
	restrictive := allOf(sourceregistry.GrantProhibited)
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, permissive),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, restrictive),
	)

	s := NewStore()
	live := mustNew(t, "example.com", "src-0001")
	lapsed := mustNew(t, "example.com", "src-0002")
	lapsed.ExpiresAt = ptr(t0)
	for _, o := range []Observation{live, lapsed} {
		if _, err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	ind, _ := s.Lookup(live.Key())
	if r := ind.Exportable(reg, t1); !r.Permitted {
		t.Errorf("a lapsed contributor refused an operation it no longer supports: %v", r.Refusals)
	}
}

// TestAnIndicatorWithNoLiveSupportAuthorisesNothing keeps an empty set from
// vacuously permitting everything.
func TestAnIndicatorWithNoLiveSupportAuthorisesNothing(t *testing.T) {
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, allOf(sourceregistry.GrantPermitted)))
	s := NewStore()
	o := mustNew(t, "example.com", "src-0001")
	o.ExpiresAt = ptr(t0)
	if _, err := s.Add(o); err != nil {
		t.Fatal(err)
	}
	ind, _ := s.Lookup(o.Key())
	if r := ind.Exportable(reg, t1); r.Permitted {
		t.Error("an indicator with no live observation was reported exportable")
	}
}

// TestConditionalAloneAuthorisesNothing checks the delegation to the registry
// is real rather than a reimplementation that drifts.
func TestConditionalAloneAuthorisesNothing(t *testing.T) {
	s := src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil)
	s.Permissions[sourceregistry.OpLocalStorage] = sourceregistry.Grant{
		Status: sourceregistry.GrantConditional,
		Conditions: []sourceregistry.Condition{
			{ID: "attribution", Text: "attribute the provider", Satisfied: sourceregistry.ConditionUnknown, Basis: "not assessed"},
		},
	}
	reg := synthReg(t, s)
	if r := indicatorOf(t, "src-0001").Authorizes(reg, sourceregistry.OpLocalStorage, t1); r.Permitted {
		t.Error("an unassessed condition authorised the operation")
	}

	s.Permissions[sourceregistry.OpLocalStorage].Conditions[0].Satisfied = sourceregistry.ConditionSatisfied
	if r := indicatorOf(t, "src-0001").Authorizes(reg, sourceregistry.OpLocalStorage, t1); !r.Permitted {
		t.Error("a satisfied condition did not authorise the operation")
	}
}

func TestRetainingARawResponseNeedsLocalStorageRights(t *testing.T) {
	reg := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil,
		map[sourceregistry.Operation]string{sourceregistry.OpLocalStorage: sourceregistry.GrantProhibited}))

	o := mustNew(t, "example.com", "src-0001")
	if ok, _ := o.RetentionPermitted(reg); !ok {
		t.Error("keeping nothing required permission")
	}
	o.RawRetention = RetentionRetained
	o.Raw = `{"example":"synthetic provider response"}`
	if ok, why := o.RetentionPermitted(reg); ok {
		t.Errorf("a raw response was retained from a source that prohibits local storage (%q)", why)
	}
}

// --- against the shipped registry ----------------------------------------

// TestNothingInTheShippedRegistryAuthorisesAnythingYet asserts a property that
// must hold whatever the file contains: no source is enabled, so no
// observation attributed to one can authorise an operation that the file does
// not independently grant. It reads the real file rather than a fixture
// because the claim is about the real file.
func TestNothingInTheShippedRegistryAuthorisesAnythingYet(t *testing.T) {
	reg, problems, err := sourceregistry.Load(filepath.Join("..", "..", "docs", "source-registry.json"))
	if err != nil {
		t.Fatalf("the shipped registry did not load: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("the shipped registry does not parse cleanly: %v", problems)
	}

	enabled := 0
	for _, s := range reg.Sources {
		if s.Enabled {
			enabled++
		}
	}
	if enabled != 0 {
		t.Errorf("%d sources are enabled; this order does not authorise enabling any", enabled)
	}

	claimable := 0
	for _, s := range reg.Sources {
		if ok, _ := s.IndependenceClaimable(); ok {
			claimable++
		}
	}
	t.Logf("shipped registry: %d sources, %d with independence claimable, %d enabled",
		len(reg.Sources), claimable, enabled)

	// And the binding works against real ids: an observation attributed to the
	// first real source resolves, and one attributed to a made-up id does not.
	if len(reg.Sources) == 0 {
		t.Skip("the shipped registry is empty")
	}
	real := reg.Sources[0].SourceID
	if _, ok := reg.Source(real); !ok {
		t.Errorf("a real source id %q did not resolve", real)
	}
	if _, ok := reg.Source("src-does-not-exist"); ok {
		t.Error("a made-up source id resolved")
	}
	r := indicatorOf(t, "src-does-not-exist").Authorizes(reg, sourceregistry.OpLocalStorage, t1)
	if r.Permitted {
		t.Error("an unresolvable id authorised local storage against the shipped registry")
	}
}

// TestNonCommercialSourcesFeedTheFreeListButNotThePaidFeed is the Pinga53
// licensing split (ORDER 15 §3): a source that permits publishing a derived
// list but not commercial use contributes to the free public list and is kept
// out of the commercial feed.
func TestNonCommercialSourcesFeedTheFreeListButNotThePaidFeed(t *testing.T) {
	nonCommercial := allOf(sourceregistry.GrantPermitted)
	nonCommercial[sourceregistry.OpCommercialUse] = sourceregistry.GrantProhibited
	owned := allOf(sourceregistry.GrantPermitted)
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, owned),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, nonCommercial),
	)

	nc := indicatorOf(t, "src-0002")
	if r := nc.Exportable(reg, t1); !r.Permitted {
		t.Fatalf("a non-commercial source was refused for the free list: %v", r.Refusals)
	}
	if r := nc.CommerciallyExportable(reg, t1); r.Permitted {
		t.Error("a source that prohibits commercial use was admitted to the paid feed")
	}
	if r := indicatorOf(t, "src-0001").CommerciallyExportable(reg, t1); !r.Permitted {
		t.Errorf("a fully licensed source was refused for the paid feed: %v", r.Refusals)
	}
	mixed := indicatorOf(t, "src-0001", "src-0002").CommerciallyExportable(reg, t1)
	if mixed.Permitted {
		t.Error("one non-commercial contributor did not keep the entry out of the paid feed")
	}
	if len(mixed.Permitting) != 1 || mixed.Permitting[0] != "src-0001" {
		t.Errorf("permitting = %v; want only the fully licensed source", mixed.Permitting)
	}
}

// TestCommercialFeedNeverWidensExportable: the paid feed is a subset of the
// free list, never more.
func TestCommercialFeedNeverWidensExportable(t *testing.T) {
	noRedist := allOf(sourceregistry.GrantPermitted)
	noRedist[sourceregistry.OpRedistribution] = sourceregistry.GrantProhibited
	unknownCommercial := allOf(sourceregistry.GrantPermitted)
	unknownCommercial[sourceregistry.OpCommercialUse] = sourceregistry.GrantUnknown
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, noRedist),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, nil, unknownCommercial),
	)
	if r := indicatorOf(t, "src-0001").CommerciallyExportable(reg, t1); r.Permitted {
		t.Error("an entry that may not be redistributed at all was admitted to the paid feed")
	}
	if r := indicatorOf(t, "src-0002").CommerciallyExportable(reg, t1); r.Permitted {
		t.Error("an unknown commercial_use grant was treated as permission")
	}
	if r := indicatorOf(t, "src-9999").CommerciallyExportable(reg, t1); r.Permitted {
		t.Error("an unresolvable source was admitted to the paid feed")
	}
}
