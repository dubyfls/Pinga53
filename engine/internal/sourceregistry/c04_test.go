// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"strings"
	"testing"
	"time"
)

// C-04 — an upstream label is validated, resolved, and refused when it
// resolves to nothing.
//
// `upstream_sources` was a descriptive free-text field that no computation
// read. That is the gap C-01 and C-02 fall into: two sources that both draw
// on an origin which is NOT a registry entry are counted as two independent
// voices, because the only lineage the tree can see is an edge between two
// records it holds. `external_origins` is the vocabulary for an origin
// nobody publishes a registry record for, and a label that resolves to
// nothing is a configuration error rather than a silently-ignored string.

var c04At = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// c04Source is a minimal valid record; every field the validator requires is
// filled with the same "unknown" this registry uses elsewhere.
func c04Source(id string, upstream []string, completeness string) Source {
	perms := map[Operation]Grant{}
	for _, op := range AllOperations {
		perms[op] = Grant{Status: GrantNotApplicable}
	}
	return Source{
		SourceID: id, CatalogRef: "none", RequestedPriority: "unknown",
		OfficialName: "synthetic " + id, OfficialDocumentation: "unknown", VerifiedOn: "unknown",
		Kind: "bulk feed", IndicatorTypes: []string{"domain"},
		ClassificationMeaning: "invented for this test", Authentication: "none",
		Quotas: "unknown", UpdateCadence: "unknown", Retention: "unknown",
		WithdrawalBehaviour: "unknown", AttributionRequired: "unknown",
		DerivedDataRestrictions:     "unknown",
		UpstreamSources:             nil,
		UpstreamLabels:              upstream,
		UpstreamSourcesCompleteness: completeness,
		AggregationDependencies:     nil,
		AccessStatus:                "unresolved",
		DispositionReason:           "synthetic record",
		PrivacyImplications:         "unknown", IntendedPermittedUse: "unknown",
		CoverageLimitations: "unknown", OperationalCost: "unknown",
		Permissions: perms, Enabled: false,
	}
}

func c04Problems(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	for _, p := range r.Validate(c04At) {
		b.WriteString(p.String())
		b.WriteString("\n")
	}
	return b.String()
}

func TestAnUpstreamLabelResolvingToNothingIsAConfigError(t *testing.T) {
	r := &Registry{
		SchemaVersion: SchemaVersion,
		Sources:       []Source{c04Source("src-0001", []string{"some_registry_nobody_declared"}, UpstreamDocumentedComplete)},
	}
	got := c04Problems(t, r)
	if !strings.Contains(got, "upstream_labels[0]") {
		t.Fatalf("an unresolvable upstream label was accepted:\n%s", got)
	}
	if !strings.Contains(got, "external_origins") {
		t.Errorf("the diagnostic does not say how to declare the origin:\n%s", got)
	}
}

func TestADeclaredExternalOriginResolves(t *testing.T) {
	r := &Registry{
		SchemaVersion:   SchemaVersion,
		ExternalOrigins: []string{"a_public_phishing_corpus"},
		Sources:         []Source{c04Source("src-0001", []string{"a_public_phishing_corpus"}, UpstreamDocumentedComplete)},
	}
	if got := c04Problems(t, r); strings.Contains(got, "upstream_labels") {
		t.Fatalf("a declared external origin was refused:\n%s", got)
	}
}

func TestARegistryIDResolvesAsAnUpstreamLabel(t *testing.T) {
	r := &Registry{
		SchemaVersion: SchemaVersion,
		Sources: []Source{
			c04Source("src-0001", nil, UpstreamDocumentedComplete),
			c04Source("src-0002", []string{"src-0001"}, UpstreamDocumentedComplete),
		},
	}
	if got := c04Problems(t, r); strings.Contains(got, "upstream_labels") {
		t.Fatalf("a registry id was refused as an upstream label:\n%s", got)
	}
}

func TestAPrimaryMayNameItsOwnGroup(t *testing.T) {
	// A primary observer's origin is itself. Saying so out loud is how a
	// record states "everything here is mine", as against leaving the list
	// empty, which says the same thing by omission.
	r := &Registry{
		SchemaVersion: SchemaVersion,
		Sources:       []Source{c04Source("src-0001", []string{"src-0001"}, UpstreamDocumentedComplete)},
	}
	if got := c04Problems(t, r); strings.Contains(got, "upstream_labels") {
		t.Fatalf("a primary naming its own group was refused:\n%s", got)
	}
}

func TestAMalformedLabelIsRefusedWithoutBeingEchoed(t *testing.T) {
	// FINDING-128 and FINDING-131 are the reason this is asserted. A registry
	// file is untrusted input; a diagnostic that reproduces a label puts
	// whatever the file chose into the operator's terminal and the gate log.
	hostile := "sk_live_51H8xQe\x1b[31m\x00" + strings.Repeat("A", 4096)
	r := &Registry{
		SchemaVersion: SchemaVersion,
		Sources:       []Source{c04Source("src-0001", []string{hostile}, UpstreamDocumentedComplete)},
	}
	got := c04Problems(t, r)
	if !strings.Contains(got, "upstream_labels[0]") {
		t.Fatalf("a malformed upstream label was accepted:\n%s", got)
	}
	for _, marker := range []string{"sk_live_51H8xQe", "\x1b", "\x00", strings.Repeat("A", 64)} {
		if strings.Contains(got, marker) {
			t.Errorf("the diagnostic reproduces content from the document: %q", firstLine(got))
		}
	}
	if len(got) > 2000 {
		t.Errorf("the diagnostic is %d bytes; the document chose its size", len(got))
	}
}

func TestTheLabelCharsetIsClosed(t *testing.T) {
	for _, bad := range []string{
		"Upper_Case", "has space", "has.dot", "has/slash", "hasπ", "", "  ",
	} {
		r := &Registry{
			SchemaVersion: SchemaVersion,
			Sources:       []Source{c04Source("src-0001", []string{bad}, UpstreamDocumentedComplete)},
		}
		if got := c04Problems(t, r); !strings.Contains(got, "upstream_labels[0]") {
			t.Errorf("label %q was accepted:\n%s", bad, got)
		}
	}
}

func TestAnExternalOriginMayNotShadowASourceID(t *testing.T) {
	// A label that is both a registry id and an external origin resolves two
	// ways, and the two mean different things to the independence
	// computation: one is a record whose lineage can be walked, the other is
	// a leaf. Ambiguity here is silently wrong rather than loudly wrong.
	r := &Registry{
		SchemaVersion:   SchemaVersion,
		ExternalOrigins: []string{"src-0001"},
		Sources:         []Source{c04Source("src-0001", nil, UpstreamDocumentedComplete)},
	}
	if got := c04Problems(t, r); !strings.Contains(got, "external_origins") {
		t.Fatalf("an external origin shadowing a source id was accepted:\n%s", got)
	}
}

func TestADuplicateExternalOriginIsRefused(t *testing.T) {
	r := &Registry{
		SchemaVersion:   SchemaVersion,
		ExternalOrigins: []string{"one_corpus", "one_corpus"},
		Sources:         []Source{c04Source("src-0001", nil, UpstreamDocumentedComplete)},
	}
	if got := c04Problems(t, r); !strings.Contains(got, "external_origins[1]") {
		t.Fatalf("a duplicate external origin was accepted:\n%s", got)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// The shipped registry is covered by the pre-existing
// TestTheShippedRegistryIsValid, which loads it and validates it against
// time.Now(). A validation that invalidated this repository's own document
// would fail there — one test, not two.
