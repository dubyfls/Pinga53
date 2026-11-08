// SPDX-License-Identifier: AGPL-3.0-only

package feed_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

const testKeyID = "test-key-1"

var testNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{pub: pub, priv: priv}
}

// envelope wraps a raw payload with a signature over exactly those bytes.
func (s signer) envelope(payload string, keyID string) []byte {
	sig := ed25519.Sign(s.priv, []byte(payload))
	return []byte(fmt.Sprintf(
		`{"schema_version":1,"signature":{"algorithm":"ed25519","key_id":%q,"value":%q},"payload":%s}`,
		keyID, base64.StdEncoding.EncodeToString(sig), payload))
}

func (s signer) opts() feed.Options {
	return feed.Options{
		MaxFileBytes: 1 << 20,
		MaxRecords:   1000,
		TrustKeyID:   testKeyID,
		TrustKey:     s.pub,
		Now:          testNow,
	}
}

func payload(records string) string {
	return `{"manifest_version":"1.0","feed_id":"test-feed",` +
		`"issued_at":"2026-09-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z",` +
		`"records":[` + records + `]}`
}

const oneBlockRecord = `{"domain":"bad.example.com","action":"block","confidence":"high","category":"phishing"}`

func TestValidateAcceptsWellFormedFeed(t *testing.T) {
	s := newSigner(t)
	v, err := feed.Validate(s.envelope(payload(oneBlockRecord), testKeyID), s.opts())
	if err != nil {
		t.Fatalf("valid feed rejected: %v", err)
	}
	if len(v.Indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(v.Indicators))
	}
	if v.Indicators[0].Domain != "bad.example.com" {
		t.Errorf("domain = %q", v.Indicators[0].Domain)
	}
	if v.FeedID != "test-feed" || v.KeyID != testKeyID {
		t.Errorf("metadata not carried through: %+v", v)
	}
}

func TestValidateRejectsBadSignature(t *testing.T) {
	s := newSigner(t)
	env := s.envelope(payload(oneBlockRecord), testKeyID)
	// Flip a byte inside the payload. The signature no longer covers it.
	tampered := strings.Replace(string(env), "bad.example.com", "evil.example.com", 1)
	_, err := feed.Validate([]byte(tampered), s.opts())
	if !errors.Is(err, feed.ErrSignatureInvalid) {
		t.Fatalf("tampered payload must fail verification, got %v", err)
	}
}

func TestValidateRejectsWrongKey(t *testing.T) {
	signerA, signerB := newSigner(t), newSigner(t)
	env := signerA.envelope(payload(oneBlockRecord), testKeyID)
	// Same key id, different key: the id check passes and the signature fails.
	_, err := feed.Validate(env, signerB.opts())
	if !errors.Is(err, feed.ErrSignatureInvalid) {
		t.Fatalf("feed signed by an unknown key must fail, got %v", err)
	}
}

func TestValidateRejectsUntrustedKeyID(t *testing.T) {
	s := newSigner(t)
	env := s.envelope(payload(oneBlockRecord), "some-other-key")
	_, err := feed.Validate(env, s.opts())
	if !errors.Is(err, feed.ErrSignatureKeyID) {
		t.Fatalf("want ErrSignatureKeyID, got %v", err)
	}
}

func TestValidateRejectsMalformedSignature(t *testing.T) {
	s := newSigner(t)
	for _, bad := range []string{"not-base64!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		env := fmt.Sprintf(
			`{"schema_version":1,"signature":{"algorithm":"ed25519","key_id":%q,"value":%q},"payload":%s}`,
			testKeyID, bad, payload(oneBlockRecord))
		if _, err := feed.Validate([]byte(env), s.opts()); !errors.Is(err, feed.ErrSignatureMalformed) {
			t.Errorf("value %q: want ErrSignatureMalformed, got %v", bad, err)
		}
	}
}

func TestValidateRejectsUnsupportedAlgorithm(t *testing.T) {
	s := newSigner(t)
	env := fmt.Sprintf(
		`{"schema_version":1,"signature":{"algorithm":"rsa","key_id":%q,"value":"AAAA"},"payload":%s}`,
		testKeyID, payload(oneBlockRecord))
	if _, err := feed.Validate([]byte(env), s.opts()); !errors.Is(err, feed.ErrSignatureAlgorithm) {
		t.Fatalf("want ErrSignatureAlgorithm, got %v", err)
	}
}

func TestValidateRejectsUnsupportedSchemaVersion(t *testing.T) {
	s := newSigner(t)
	env := strings.Replace(string(s.envelope(payload(oneBlockRecord), testKeyID)),
		`"schema_version":1`, `"schema_version":2`, 1)
	if _, err := feed.Validate([]byte(env), s.opts()); !errors.Is(err, feed.ErrSchemaVersion) {
		t.Fatalf("want ErrSchemaVersion, got %v", err)
	}
}

func TestValidateRejectsExpiredManifest(t *testing.T) {
	s := newSigner(t)
	p := `{"manifest_version":"1.0","feed_id":"test-feed",` +
		`"issued_at":"2025-01-01T00:00:00Z","expires_at":"2025-06-01T00:00:00Z",` +
		`"records":[` + oneBlockRecord + `]}`
	if _, err := feed.Validate(s.envelope(p, testKeyID), s.opts()); !errors.Is(err, feed.ErrManifestExpired) {
		t.Fatalf("want ErrManifestExpired, got %v", err)
	}
}

func TestValidateRejectsFutureManifest(t *testing.T) {
	s := newSigner(t)
	p := `{"manifest_version":"1.0","feed_id":"test-feed",` +
		`"issued_at":"2030-01-01T00:00:00Z","expires_at":"2031-01-01T00:00:00Z",` +
		`"records":[` + oneBlockRecord + `]}`
	if _, err := feed.Validate(s.envelope(p, testKeyID), s.opts()); !errors.Is(err, feed.ErrManifestNotYetValid) {
		t.Fatalf("want ErrManifestNotYetValid, got %v", err)
	}
}

func TestValidateRejectsInconsistentTimestamps(t *testing.T) {
	s := newSigner(t)
	p := `{"manifest_version":"1.0","feed_id":"test-feed",` +
		`"issued_at":"2026-09-01T00:00:00Z","expires_at":"2026-08-01T00:00:00Z",` +
		`"records":[` + oneBlockRecord + `]}`
	if _, err := feed.Validate(s.envelope(p, testKeyID), s.opts()); !errors.Is(err, feed.ErrManifestTimes) {
		t.Fatalf("want ErrManifestTimes, got %v", err)
	}
}

func TestValidateDropsExpiredIndicators(t *testing.T) {
	s := newSigner(t)
	records := oneBlockRecord + `,` +
		`{"domain":"stale.example.com","action":"block","confidence":"high","expires_at":"2026-01-01T00:00:00Z"}`
	v, err := feed.Validate(s.envelope(payload(records), testKeyID), s.opts())
	if err != nil {
		t.Fatalf("an expired record is a lifecycle event, not a malformed feed: %v", err)
	}
	if len(v.Indicators) != 1 {
		t.Fatalf("expired indicator should be dropped, got %d", len(v.Indicators))
	}
	if v.ExpiredCount != 1 {
		t.Errorf("ExpiredCount = %d, want 1", v.ExpiredCount)
	}
}

func TestValidateRejectsDuplicateAndConflictingRecords(t *testing.T) {
	s := newSigner(t)

	dup := oneBlockRecord + `,` + oneBlockRecord
	if _, err := feed.Validate(s.envelope(payload(dup), testKeyID), s.opts()); !errors.Is(err, feed.ErrDuplicateRecord) {
		t.Errorf("duplicate: want ErrDuplicateRecord, got %v", err)
	}

	conflict := oneBlockRecord + `,` +
		`{"domain":"bad.example.com","action":"allow","confidence":"high"}`
	if _, err := feed.Validate(s.envelope(payload(conflict), testKeyID), s.opts()); !errors.Is(err, feed.ErrConflictingRecord) {
		t.Errorf("conflict: want ErrConflictingRecord, got %v", err)
	}
}

// TestValidateDetectsDuplicatesAfterNormalisation is the interesting case:
// two spellings of the same name must collide, or the same domain could be
// proposed twice.
func TestValidateDetectsDuplicatesAfterNormalisation(t *testing.T) {
	s := newSigner(t)
	records := `{"domain":"bad.example.com","action":"block","confidence":"high"},` +
		`{"domain":"BAD.Example.COM.","action":"block","confidence":"high"}`
	if _, err := feed.Validate(s.envelope(payload(records), testKeyID), s.opts()); !errors.Is(err, feed.ErrDuplicateRecord) {
		t.Fatalf("case and trailing-dot variants must collide, got %v", err)
	}
}

func TestValidateRejectsInvalidDomains(t *testing.T) {
	s := newSigner(t)
	for _, bad := range []string{
		"192.0.2.1", "localhost", "*.example.com", "printer.local",
		"com", "co.uk", "example.com/path", "single",
	} {
		records := fmt.Sprintf(`{"domain":%q,"action":"block","confidence":"high"}`, bad)
		_, err := feed.Validate(s.envelope(payload(records), testKeyID), s.opts())
		if !errors.Is(err, feed.ErrInvalidRecord) {
			t.Errorf("domain %q: want ErrInvalidRecord, got %v", bad, err)
		}
	}
}

func TestValidateRejectsInvalidActionAndConfidence(t *testing.T) {
	s := newSigner(t)

	r := `{"domain":"bad.example.com","action":"nuke","confidence":"high"}`
	if _, err := feed.Validate(s.envelope(payload(r), testKeyID), s.opts()); !errors.Is(err, feed.ErrInvalidAction) {
		t.Errorf("want ErrInvalidAction, got %v", err)
	}

	r = `{"domain":"bad.example.com","action":"block","confidence":"certain"}`
	if _, err := feed.Validate(s.envelope(payload(r), testKeyID), s.opts()); !errors.Is(err, feed.ErrInvalidConfidence) {
		t.Errorf("want ErrInvalidConfidence, got %v", err)
	}
}

func TestValidateRejectsUnknownFields(t *testing.T) {
	s := newSigner(t)
	// A field ScamWall does not understand may carry meaning the publisher
	// expects honoured; ignoring it would mean acting on a different feed.
	r := `{"domain":"bad.example.com","action":"block","confidence":"high","severity":"critical"}`
	if _, err := feed.Validate(s.envelope(payload(r), testKeyID), s.opts()); err == nil {
		t.Fatal("unknown record field must be rejected")
	}
}

func TestValidateRejectsTrailingData(t *testing.T) {
	s := newSigner(t)
	env := append(s.envelope(payload(oneBlockRecord), testKeyID), []byte(`{"extra":1}`)...)
	if _, err := feed.Validate(env, s.opts()); err == nil {
		t.Fatal("a second JSON document must not ride along")
	}
}

func TestValidateRejectsTooManyRecords(t *testing.T) {
	s := newSigner(t)
	var parts []string
	for i := range 20 {
		parts = append(parts, fmt.Sprintf(`{"domain":"d%d.example.com","action":"block","confidence":"high"}`, i))
	}
	opts := s.opts()
	opts.MaxRecords = 10
	_, err := feed.Validate(s.envelope(payload(strings.Join(parts, ",")), testKeyID), opts)
	if !errors.Is(err, feed.ErrTooManyRecords) {
		t.Fatalf("want ErrTooManyRecords, got %v", err)
	}
}

func TestValidateRejectsEmptyRecordSet(t *testing.T) {
	s := newSigner(t)
	if _, err := feed.Validate(s.envelope(payload(""), testKeyID), s.opts()); !errors.Is(err, feed.ErrNoRecords) {
		t.Fatalf("want ErrNoRecords, got %v", err)
	}
}

func TestValidateRequiresTrustKey(t *testing.T) {
	s := newSigner(t)
	opts := s.opts()
	opts.TrustKey = nil
	if _, err := feed.Validate(s.envelope(payload(oneBlockRecord), testKeyID), opts); !errors.Is(err, feed.ErrTrustKeyMissing) {
		t.Fatalf("want ErrTrustKeyMissing, got %v", err)
	}
}

func TestLoadFileRejectsOversizedFile(t *testing.T) {
	s := newSigner(t)
	p := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(p, s.envelope(payload(oneBlockRecord), testKeyID), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := s.opts()
	opts.MaxFileBytes = 10
	if _, err := feed.LoadFile(p, opts); !errors.Is(err, feed.ErrFileTooLarge) {
		t.Fatalf("want ErrFileTooLarge, got %v", err)
	}
}

func TestLoadFileMissing(t *testing.T) {
	s := newSigner(t)
	if _, err := feed.LoadFile(filepath.Join(t.TempDir(), "absent.json"), s.opts()); err == nil {
		t.Fatal("missing feed must be an error")
	}
}

// TestRepositoryFixtureIsValid exercises the committed fixture end to end,
// using the committed public key as the trust anchor.
func TestRepositoryFixtureIsValid(t *testing.T) {
	keyB64, err := os.ReadFile(filepath.Join("..", "..", "testdata", "feed_trust_key.pub"))
	if err != nil {
		t.Skipf("fixture trust key not present: %v", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyB64)))
	if err != nil {
		t.Fatalf("fixture trust key is not base64: %v", err)
	}

	v, err := feed.LoadFile(filepath.Join("..", "..", "testdata", "feed.json"), feed.Options{
		MaxFileBytes: 1 << 20,
		MaxRecords:   1000,
		TrustKeyID:   "scamwall-test-key-1",
		TrustKey:     key,
		Now:          testNow,
	})
	if err != nil {
		t.Fatalf("committed fixture must validate: %v", err)
	}

	// 8 records: 5 live block/high, 1 block/medium, 1 allow/high, 1 expired.
	if len(v.Indicators) != 7 {
		t.Errorf("expected 7 live indicators, got %d", len(v.Indicators))
	}
	if v.ExpiredCount != 1 {
		t.Errorf("expected 1 expired indicator, got %d", v.ExpiredCount)
	}

	// The IDN and trailing-dot entries must have been canonicalised. The exact
	// punycode is not asserted: the guarantee is that a non-ASCII name becomes
	// an "xn--" A-label, not that this test restates the IDNA algorithm.
	var found bool
	for _, ind := range v.Indicators {
		if strings.Contains(string(ind.Domain), "xn--") {
			found = true
		}
		for _, r := range string(ind.Domain) {
			if r > 127 {
				t.Errorf("non-ASCII survived normalisation: %q", ind.Domain)
				break
			}
		}
		if strings.HasSuffix(string(ind.Domain), ".") {
			t.Errorf("trailing dot survived normalisation: %q", ind.Domain)
		}
		if strings.ToLower(string(ind.Domain)) != string(ind.Domain) {
			t.Errorf("uppercase survived normalisation: %q", ind.Domain)
		}
	}
	if !found {
		var got []string
		for _, ind := range v.Indicators {
			got = append(got, string(ind.Domain))
		}
		t.Errorf("IDN entry was not canonicalised to punycode; got %v", got)
	}
}
