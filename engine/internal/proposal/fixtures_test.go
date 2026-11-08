// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # EVERYTHING IN THIS FILE IS SYNTHETIC
//
// The signing key is generated from a fixed seed inside the test binary; it
// signs nothing outside it and is not a credential. Every domain is under a
// documentation-reserved name from RFC 2606 and resolves to nothing. Every
// source record is invented, and NO record in docs/source-registry.json is
// enabled, read or contacted by anything here.
//
// The fixed seed is what makes a run deterministic: the same key produces the
// same signature, so the same inputs produce a byte-identical report, which is
// what the determinism test measures.

// testAt is the instant every fixture is judged against.
var testAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// testKey is the synthetic signing key. Seeded, never random: a report's
// digest must be the same on two machines.
func testKey(t *testing.T, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// signEvidence builds a signed evidence document from records.
func signEvidence(t *testing.T, priv ed25519.PrivateKey, keyID, feedID string, records []feed.EvidenceRecord) []byte {
	t.Helper()
	payload, err := json.Marshal(feed.EvidenceManifest{
		ManifestVersion: feed.SupportedEvidenceManifestVersion,
		FeedID:          feedID,
		IssuedAt:        testAt.Add(-time.Hour),
		ExpiresAt:       testAt.Add(24 * time.Hour),
		Records:         records,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return envelopeOver(t, priv, keyID, payload)
}

// envelopeOver wraps an arbitrary payload, so a test can sign something the
// manifest type could not express.
func envelopeOver(t *testing.T, priv ed25519.PrivateKey, keyID string, payload []byte) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, payload)
	doc, err := json.Marshal(struct {
		SchemaVersion int             `json:"schema_version"`
		Signature     any             `json:"signature"`
		Payload       json.RawMessage `json:"payload"`
	}{
		SchemaVersion: feed.EvidenceSchemaVersion,
		Signature: map[string]string{
			"algorithm": feed.SignatureAlgorithm,
			"key_id":    keyID,
			"value":     base64.StdEncoding.EncodeToString(sig),
		},
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return doc
}

// authorityOver builds an authority document granting one signer authority
// over the given source ids.
func authorityOver(t *testing.T, keyID, pubB64 string, asserts, aggregates []string) *feed.SignerAuthority {
	t.Helper()
	b, err := json.Marshal(feed.SignerAuthority{
		SchemaVersion: feed.SignerAuthoritySchemaVersion,
		Signers: []feed.Signer{{
			KeyID:            keyID,
			PublicKey:        pubB64,
			AssertsSourceIDs: asserts,
			AggregatorFor:    aggregates,
			Note:             "synthetic test authority",
		}},
	})
	if err != nil {
		t.Fatalf("marshal authority: %v", err)
	}
	a, err := feed.ParseSignerAuthority(b)
	if err != nil {
		t.Fatalf("authority refused: %v", err)
	}
	return a
}

// permittedGrant is a grant that authorises an operation, with the citation
// the registry requires behind every assertion.
func permittedGrant() sourceregistry.Grant {
	return sourceregistry.Grant{
		Status: sourceregistry.GrantPermitted,
		Evidence: sourceregistry.Evidence{
			ProviderTerms: []sourceregistry.Citation{{
				URL:       "https://example.com/terms",
				CheckedOn: "2026-01-01",
				Quote:     "synthetic terms written for this test suite",
			}},
		},
	}
}

func prohibitedGrant() sourceregistry.Grant {
	return sourceregistry.Grant{
		Status: sourceregistry.GrantProhibited,
		Evidence: sourceregistry.Evidence{
			ProviderTerms: []sourceregistry.Citation{{
				URL:       "https://example.com/terms",
				CheckedOn: "2026-01-01",
				Quote:     "synthetic terms written for this test suite",
			}},
		},
	}
}

func unknownGrant() sourceregistry.Grant {
	return sourceregistry.Grant{Status: sourceregistry.GrantUnknown}
}

func conditionalGrant(satisfied string) sourceregistry.Grant {
	g := permittedGrant()
	g.Status = sourceregistry.GrantConditional
	g.Conditions = []sourceregistry.Condition{{
		ID:        "synthetic-condition",
		Text:      "a condition invented for this test suite",
		Satisfied: satisfied,
		Basis:     "stated so the record is well-formed; it establishes nothing about any real provider",
	}}
	return g
}

// testSource builds a synthetic registry record with every operation
// permitted, so that a test can prohibit exactly the one it is about.
func testSource(id string, upstreams []string) sourceregistry.Source {
	completeness := sourceregistry.UpstreamDocumentedComplete
	perms := map[sourceregistry.Operation]sourceregistry.Grant{}
	for _, op := range sourceregistry.AllOperations {
		perms[op] = permittedGrant()
	}
	return sourceregistry.Source{
		SourceID:                    id,
		CatalogRef:                  "none",
		RequestedPriority:           "unknown",
		OfficialName:                "synthetic source " + id,
		OfficialDocumentation:       "unknown",
		VerifiedOn:                  "unknown",
		Kind:                        "bulk feed",
		IndicatorTypes:              []string{"domain"},
		ClassificationMeaning:       "invented for this test suite; it describes no real provider",
		Authentication:              "none",
		Quotas:                      "unknown",
		UpdateCadence:               "unknown",
		Retention:                   "unknown",
		WithdrawalBehaviour:         "unknown",
		AttributionRequired:         "unknown",
		DerivedDataRestrictions:     "unknown",
		UpstreamSources:             upstreams,
		UpstreamSourcesCompleteness: completeness,
		AggregationDependencies:     upstreams,
		AccessStatus:                "unresolved",
		DispositionReason:           "synthetic record; nobody has looked, because there is nothing to look at",
		PrivacyImplications:         "unknown",
		IntendedPermittedUse:        "unknown",
		CoverageLimitations:         "unknown",
		OperationalCost:             "unknown",
		IntendedOperations:          nil,
		Permissions:                 perms,
		Enabled:                     false,
	}
}

// testRegistry assembles a registry and refuses to hand back one that does
// not validate — a fixture that is itself invalid would make every assertion
// about it meaningless.
func testRegistry(t *testing.T, sources ...sourceregistry.Source) *sourceregistry.Registry {
	t.Helper()
	reg := &sourceregistry.Registry{SchemaVersion: sourceregistry.SchemaVersion, Sources: sources}
	if problems := reg.Validate(testAt); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("fixture registry problem: %s", p)
		}
		t.FailNow()
	}
	return reg
}

// testPolicy builds a policy with the given threshold and exceptions.
func testPolicy(t *testing.T, minIndependent int, scope Scope, exceptions ...Exception) *Policy {
	t.Helper()
	raw := map[string]any{
		"schema_version":          PolicySchemaVersion,
		"min_independent_sources": minIndependent,
		"proposal_scope":          string(scope),
		"exceptions":              []map[string]any{},
	}
	ex := make([]map[string]any, 0, len(exceptions))
	for _, e := range exceptions {
		ex = append(ex, map[string]any{"value": e.Value, "scope": string(e.Scope), "note": e.Note})
	}
	raw["exceptions"] = ex
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	p, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("policy refused: %v", err)
	}
	return p
}

// adverse is a record asserting a domain is malicious.
func adverse(sourceID, recordID, value string) feed.EvidenceRecord {
	return feed.EvidenceRecord{
		Type:           "domain",
		Value:          value,
		SourceID:       sourceID,
		SourceRecordID: recordID,
		Classification: "malicious",
		State:          "active",
	}
}

// jsonString renders s as a JSON string literal, so a hostile key can be put
// into a document without a literal control character appearing in source.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
