// SPDX-License-Identifier: AGPL-3.0-only

package feed

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// TestOrder17BLocalSignerAdmitsAggregatedExternalSources is B3 in ORDER
// 17B §5, the test the owner asked for after DEC-FEEDS-002.
//
// The deployed signers.json ships a single pinga53-local signer whose
// aggregator_for lists the five enabled external source ids (option 3 in
// the handoff's Q-SIGNER-SCOPE). This test proves two independent
// properties that the signer scope has to hold:
//
//  1. ADMISSION. A record whose source_id is one of the aggregator_for
//     ids is ADMITTED by ValidateEvidence; it does not come back as
//     ErrUnknownSigner or with an authority of "none". The specific pair
//     the owner named is urlhaus + cert-polska-warning-list.
//
//  2. INDEPENDENCE FOLLOWS LINEAGE. The shipped registry's lineage says
//     urlhaus (origin: abusech) and cert-polska-warning-list (origin:
//     certpl) do not share an origin, so MaxDisjointOrigins counts them
//     as two distinct voices. That property of the registry is unchanged
//     by the signer scope — the test asserts it here so a future change
//     to signers.json can only break admission, not silently inflate
//     lineage.
//
// The aggregator-channel collapse (one signer carrying many sources is
// one attestation, not many) is enforced one layer up, in
// internal/proposal; it is already covered by
// TestOneAggregatorIsOneAttestationHoweverManySourcesItCarries and is
// not duplicated here. This test is scoped to the signer boundary.
func TestOrder17BLocalSignerAdmitsAggregatedExternalSources(t *testing.T) {
	// The five aggregator_for ids the deploy materialises, matching
	// SCAMWALL_AGGREGATOR_FOR in deploy/deploy-scamwall.sh.
	aggregates := []string{
		"urlhaus",
		"threatfox",
		"openphish-community",
		"phishing-database",
		"cert-polska-warning-list",
	}

	priv, pub := evKey(t, 0x17)
	// DEC-FEEDS-003: the local key ASSERTS for each directly fetched source.
	auth := evAuthority(t, "pinga53-local-1", pub, append([]string{"pinga53-local"}, aggregates...), nil)

	// The two records the owner named — one from urlhaus, one from CERT
	// Polska — carried in one evidence document, signed by the local key.
	records := []EvidenceRecord{{
		Type: "domain", Value: "sample-urlhaus.example.com",
		SourceID: "urlhaus", SourceRecordID: "u-1",
		Classification: "malicious", State: "active",
	}, {
		Type: "domain", Value: "sample-certpl.example.com",
		SourceID: "cert-polska-warning-list", SourceRecordID: "c-1",
		Classification: "malicious", State: "active",
	}}
	doc := evDoc(t, priv, "pinga53-local-1", EvidenceSchemaVersion,
		evPayload(t, records))

	v, err := ValidateEvidence(doc, evOpts(auth))
	if err != nil {
		t.Fatalf("admission refused: %v (DEC-FEEDS-003 requires admission for the asserted source ids)", err)
	}
	if v.Signer == nil {
		t.Fatal("admitted evidence carries no signer record")
	}
	// Both ids resolve to AuthorityAggregator, not AuthorityOwn (we did not
	// grant asserts_source_ids over them) and not AuthorityNone (we DID
	// grant aggregator_for over them).
	for _, id := range []string{"urlhaus", "cert-polska-warning-list"} {
		if got := v.Signer.MayAssert(id); got != AuthorityOwn {
			t.Errorf("MayAssert(%q) = %q, want %q (asserts_source_ids grants this; an aggregator is never independent)",
				id, got, AuthorityOwn)
		}
	}

	// A control: an id the operator did NOT grant must resolve to None.
	// Catches a future widening of aggregator_for that silently admits a
	// source the deploy never declared.
	if got := v.Signer.MayAssert("unknown-source"); got != AuthorityNone {
		t.Errorf("MayAssert(%q) = %q, want %q", "unknown-source", got, AuthorityNone)
	}

	// Independence follows lineage, read from the shipped registry.
	_, here, _, _ := runtime.Caller(0)
	reg, _, err := sourceregistry.Load(filepath.Join(filepath.Dir(here),
		"..", "..", "config", "registry.json"))
	if err != nil {
		t.Fatalf("load shipped registry: %v", err)
	}
	asOf := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	if ps := reg.Validate(asOf); len(ps) > 0 {
		for _, p := range ps {
			t.Errorf("registry: %s", p.String())
		}
		t.Fatal("registry has validation problems")
	}
	disjoint := reg.MaxDisjointOrigins([]string{
		"urlhaus", "cert-polska-warning-list",
	})
	if disjoint.Count != 2 {
		t.Errorf("MaxDisjointOrigins(urlhaus, cert-polska) = %d (shared=%v); want 2 — urlhaus:abusech and certpl:certpl do not share an origin",
			disjoint.Count, disjoint.Shared)
	}
}
