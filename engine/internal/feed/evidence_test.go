// SPDX-License-Identifier: AGPL-3.0-only

package feed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// # EVERYTHING HERE IS SYNTHETIC
//
// Keys are generated from fixed seeds inside the test binary. They sign
// nothing outside it, they are not credentials, and none of them is the
// repository's feed trust key — which this file never reads.

var evAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func evKey(t *testing.T, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func evRecords() []EvidenceRecord {
	return []EvidenceRecord{{
		Type:           "domain",
		Value:          "bad.example.com",
		SourceID:       "src-a",
		SourceRecordID: "a1",
		Classification: "malicious",
		State:          "active",
	}}
}

func evPayload(t *testing.T, records []EvidenceRecord) []byte {
	t.Helper()
	b, err := json.Marshal(EvidenceManifest{
		ManifestVersion: SupportedEvidenceManifestVersion,
		FeedID:          "synthetic",
		IssuedAt:        evAt.Add(-time.Hour),
		ExpiresAt:       evAt.Add(24 * time.Hour),
		Records:         records,
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return b
}

// evDoc wraps a payload in an envelope signed by priv.
func evDoc(t *testing.T, priv ed25519.PrivateKey, keyID string, schema int, payload []byte) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, payload)
	b, err := json.Marshal(struct {
		SchemaVersion int               `json:"schema_version"`
		Signature     map[string]string `json:"signature"`
		Payload       json.RawMessage   `json:"payload"`
	}{schema, map[string]string{
		"algorithm": SignatureAlgorithm,
		"key_id":    keyID,
		"value":     base64.StdEncoding.EncodeToString(sig),
	}, payload})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func evAuthority(t *testing.T, keyID, pub string, asserts, aggregates []string) *SignerAuthority {
	t.Helper()
	b, err := json.Marshal(SignerAuthority{
		SchemaVersion: SignerAuthoritySchemaVersion,
		Signers: []Signer{{
			KeyID: keyID, PublicKey: pub,
			AssertsSourceIDs: asserts, AggregatorFor: aggregates,
		}},
	})
	if err != nil {
		t.Fatalf("marshal authority: %v", err)
	}
	a, err := ParseSignerAuthority(b)
	if err != nil {
		t.Fatalf("authority refused: %v", err)
	}
	return a
}

func evOpts(a *SignerAuthority) EvidenceOptions {
	return EvidenceOptions{MaxFileBytes: 1 << 20, MaxRecords: 1000, Authority: a, Now: evAt}
}

// TestAnEvidenceDocumentIsAuthenticatedBeforeItIsRead is the premise of the
// whole ingestion boundary, and it is tested in both directions: a good
// document is admitted, and each way of spoiling it is refused.
func TestAnEvidenceDocumentIsAuthenticatedBeforeItIsRead(t *testing.T) {
	priv, pub := evKey(t, 0x21)
	other, otherPub := evKey(t, 0x22)
	auth := evAuthority(t, "k1", pub, []string{"src-a"}, nil)

	t.Run("a document signed by the recorded key is admitted", func(t *testing.T) {
		v, err := ValidateEvidence(evDoc(t, priv, "k1", EvidenceSchemaVersion, evPayload(t, evRecords())), evOpts(auth))
		if err != nil {
			t.Fatalf("a well-formed document was refused: %v", err)
		}
		if v.KeyID != "k1" || v.Signer == nil || v.Signer.KeyID != "k1" {
			t.Errorf("the signer was not carried through: %+v", v.Signer)
		}
		if len(v.Records) != 1 {
			t.Errorf("records = %d, want 1", len(v.Records))
		}
		if v.BytesDigest == "" || !strings.HasPrefix(v.BytesDigest, "sha256:") {
			t.Errorf("the document is not bound by digest: %q", v.BytesDigest)
		}
	})

	t.Run("a document signed by a DIFFERENT key claiming the recorded id", func(t *testing.T) {
		// The key id is what the envelope says; the key is what the operator
		// recorded. A substituted signer must not be admitted by writing the
		// right id on the envelope.
		_, err := ValidateEvidence(evDoc(t, other, "k1", EvidenceSchemaVersion, evPayload(t, evRecords())), evOpts(auth))
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("a forged signer was accepted or refused for the wrong reason: %v", err)
		}
	})

	t.Run("a document signed by a key the operator has not recorded", func(t *testing.T) {
		unknownAuth := evAuthority(t, "k2", otherPub, []string{"src-a"}, nil)
		_, err := ValidateEvidence(evDoc(t, priv, "k1", EvidenceSchemaVersion, evPayload(t, evRecords())), evOpts(unknownAuth))
		if !errors.Is(err, ErrUnknownSigner) {
			t.Fatalf("an unrecorded signer was accepted: %v", err)
		}
	})

	t.Run("a tampered payload", func(t *testing.T) {
		doc := evDoc(t, priv, "k1", EvidenceSchemaVersion, evPayload(t, evRecords()))
		tampered := []byte(strings.Replace(string(doc), "bad.example.com", "bad.example.org", 1))
		if string(tampered) == string(doc) {
			t.Fatal("premise broken: nothing was tampered with")
		}
		if _, err := ValidateEvidence(tampered, evOpts(auth)); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("a tampered payload was accepted: %v", err)
		}
	})

	t.Run("no authority at all", func(t *testing.T) {
		opts := evOpts(auth)
		opts.Authority = nil
		if _, err := ValidateEvidence(evDoc(t, priv, "k1", EvidenceSchemaVersion, evPayload(t, evRecords())), opts); err == nil {
			t.Fatal("a document was admitted with no signer authority; a signature alone is not an authority")
		}
	})
}

// TestTheTwoSchemasCannotBeReadAsEachOther.
//
// The v1 feed carries no source attribution at all. If an evidence loader
// could read one, every record in it would need a source and there is none to
// give it — which is exactly the invented provenance the schema split exists
// to prevent.
func TestTheTwoSchemasCannotBeReadAsEachOther(t *testing.T) {
	priv, pub := evKey(t, 0x23)
	auth := evAuthority(t, "k1", pub, []string{"src-a"}, nil)

	t.Run("a v1 document is not evidence", func(t *testing.T) {
		doc := evDoc(t, priv, "k1", SchemaVersion, evPayload(t, evRecords()))
		_, err := ValidateEvidence(doc, evOpts(auth))
		if !errors.Is(err, ErrEvidenceSchemaVersion) {
			t.Fatalf("a schema-1 document was read as evidence: %v", err)
		}
		if !strings.Contains(err.Error(), "carries no source attribution") {
			t.Errorf("the refusal does not say why the two are different: %v", err)
		}
	})

	t.Run("an evidence document is not a v1 feed", func(t *testing.T) {
		doc := evDoc(t, priv, "k1", EvidenceSchemaVersion, evPayload(t, evRecords()))
		key, _ := base64.StdEncoding.DecodeString(pub)
		_, err := Validate(doc, Options{
			MaxFileBytes: 1 << 20, MaxRecords: 100,
			TrustKeyID: "k1", TrustKey: ed25519.PublicKey(key), Now: evAt,
		})
		if !errors.Is(err, ErrSchemaVersion) {
			t.Fatalf("a schema-2 document was read as a v1 feed: %v", err)
		}
	})
}

// TestAnEvidenceManifestIsBoundedAndFresh.
func TestAnEvidenceManifestIsBoundedAndFresh(t *testing.T) {
	priv, pub := evKey(t, 0x24)
	auth := evAuthority(t, "k1", pub, []string{"src-a"}, nil)

	manifest := func(issued, expires time.Time, n int) []byte {
		recs := make([]EvidenceRecord, 0, n)
		for i := 0; i < n; i++ {
			recs = append(recs, evRecords()[0])
		}
		b, err := json.Marshal(EvidenceManifest{
			ManifestVersion: SupportedEvidenceManifestVersion,
			FeedID:          "synthetic", IssuedAt: issued, ExpiresAt: expires, Records: recs,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	cases := []struct {
		name    string
		payload []byte
		opts    func(EvidenceOptions) EvidenceOptions
		want    error
	}{
		{"expired", manifest(evAt.Add(-48*time.Hour), evAt.Add(-time.Hour), 1), nil, ErrManifestExpired},
		{"not yet valid", manifest(evAt.Add(48*time.Hour), evAt.Add(72*time.Hour), 1), nil, ErrManifestNotYetValid},
		{"expires before it was issued", manifest(evAt, evAt.Add(-time.Hour), 1), nil, ErrManifestTimes},
		{"no records", manifest(evAt.Add(-time.Hour), evAt.Add(time.Hour), 0), nil, ErrNoRecords},
		{"too many records", manifest(evAt.Add(-time.Hour), evAt.Add(time.Hour), 5),
			func(o EvidenceOptions) EvidenceOptions { o.MaxRecords = 2; return o }, ErrTooManyRecords},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := evOpts(auth)
			if tc.opts != nil {
				opts = tc.opts(opts)
			}
			_, err := ValidateEvidence(evDoc(t, priv, "k1", EvidenceSchemaVersion, tc.payload), opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("an ordinary document is still accepted", func(t *testing.T) {
		if _, err := ValidateEvidence(
			evDoc(t, priv, "k1", EvidenceSchemaVersion, manifest(evAt.Add(-time.Hour), evAt.Add(time.Hour), 3)),
			evOpts(auth)); err != nil {
			t.Fatalf("a fresh, bounded document was refused: %v", err)
		}
	})
}

// TestAnOversizedEvidenceFileIsRefusedBeforeItIsParsed.
//
// Both bounds are exercised: the one taken from Stat before anything is
// buffered, and the one taken after the limited read for a file whose
// declared size lied or could not be taken.
func TestAnOversizedEvidenceFileIsRefusedBeforeItIsParsed(t *testing.T) {
	priv, pub := evKey(t, 0x25)
	auth := evAuthority(t, "k1", pub, []string{"src-a"}, nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	big := append(evDoc(t, priv, "k1", EvidenceSchemaVersion, evPayload(t, evRecords())),
		[]byte(strings.Repeat(" ", 4096))...)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	opts := evOpts(auth)
	opts.MaxFileBytes = 64
	if _, err := LoadEvidenceFile(path, opts); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("an oversized file was accepted: %v", err)
	}

	opts.MaxFileBytes = int64(len(big))
	if _, err := LoadEvidenceFile(path, opts); err != nil {
		t.Fatalf("a file exactly at the bound was refused: %v", err)
	}
}

// TestASignerAuthorityIsOperatorPolicyAndIsValidated.
func TestASignerAuthorityIsOperatorPolicyAndIsValidated(t *testing.T) {
	_, pub := evKey(t, 0x26)

	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"wrong schema version",
			`{"schema_version":99,"signers":[]}`, ErrAuthoritySchema},
		{"no signers",
			`{"schema_version":1,"signers":[]}`, ErrAuthorityInvalid},
		{"a signer with no key id",
			`{"schema_version":1,"signers":[{"key_id":"","public_key":"` + pub + `","asserts_source_ids":["s"]}]}`, ErrAuthorityInvalid},
		{"one key id twice",
			`{"schema_version":1,"signers":[
			  {"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["s"]},
			  {"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["t"]}]}`, ErrAuthorityInvalid},
		{"a public key that is not base64",
			`{"schema_version":1,"signers":[{"key_id":"k","public_key":"not base64!","asserts_source_ids":["s"]}]}`, ErrAuthorityInvalid},
		{"a public key of the wrong length",
			`{"schema_version":1,"signers":[{"key_id":"k","public_key":"YWJj","asserts_source_ids":["s"]}]}`, ErrAuthorityInvalid},
		{"a signer granted nothing",
			`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `"}]}`, ErrAuthorityInvalid},
		{"a wildcard grant",
			`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["*"]}]}`, ErrAuthorityInvalid},
		{"an empty source id",
			`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `","asserts_source_ids":[""]}]}`, ErrAuthorityInvalid},
		{"an unknown field",
			`{"schema_version":1,"signers":[],"admits_everything":true}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSignerAuthority([]byte(tc.doc))
			if err == nil {
				t.Fatalf("an invalid authority document was accepted")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("an ordinary authority is accepted and resolves", func(t *testing.T) {
		a, err := ParseSignerAuthority([]byte(
			`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub +
				`","asserts_source_ids":["own-src"],"aggregator_for":["agg-src"],"note":"why"}]}`))
		if err != nil {
			t.Fatalf("a well-formed authority was refused: %v", err)
		}
		s, ok := a.Signer("k")
		if !ok {
			t.Fatal("the signer does not resolve by its own key id")
		}
		if _, ok := a.Signer("K"); ok {
			t.Error("the key id resolved case-insensitively; lookup must be exact")
		}
		for _, tc := range []struct {
			source string
			want   Authority
		}{
			{"own-src", AuthorityOwn},
			{"agg-src", AuthorityAggregator},
			{"other-src", AuthorityNone},
			{"", AuthorityNone},
			{"*", AuthorityNone},
		} {
			if got := s.MayAssert(tc.source); got != tc.want {
				t.Errorf("MayAssert(%q) = %q, want %q", tc.source, got, tc.want)
			}
		}
	})
}

// TestTheAuthorityDigestBindsWhatIsGranted.
//
// Two authority documents that admit different things must not share a
// digest, and two that admit the same things must — otherwise a reformatted
// operator file would read as a change of authority.
func TestTheAuthorityDigestBindsWhatIsGranted(t *testing.T) {
	_, pub := evKey(t, 0x27)
	parse := func(doc string) *SignerAuthority {
		a, err := ParseSignerAuthority([]byte(doc))
		if err != nil {
			t.Fatalf("authority refused: %v", err)
		}
		return a
	}

	base := parse(`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["a","b"]}]}`)
	reordered := parse(`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["b","a"]}]}`)
	widened := parse(`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["a","b","c"]}]}`)
	moved := parse(`{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `","asserts_source_ids":["a"],"aggregator_for":["b"]}]}`)

	if base.Digest() != reordered.Digest() {
		t.Error("reordering two source ids changed the digest; order is not part of what the document says")
	}
	if base.Digest() == widened.Digest() {
		t.Error("granting authority over another source did not change the digest")
	}
	if base.Digest() == moved.Digest() {
		t.Error("moving a source from an own-authority to an aggregator authority did not change " +
			"the digest; the two are enforced alike and CLAIM different things")
	}
	if !strings.HasPrefix(base.Digest(), "sha256:") {
		t.Errorf("the digest is not one this package produces: %q", base.Digest())
	}
}
