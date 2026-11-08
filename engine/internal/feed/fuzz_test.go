// SPDX-License-Identifier: AGPL-3.0-only

package feed_test

import (
	"crypto/ed25519"
	b64 "encoding/base64"
	"encoding/json"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// FuzzValidate drives the feed decoder with arbitrary bytes under a FIXED
// trust key that the fuzzer does not hold.
//
// That framing is the point. The interesting question is not whether the
// decoder survives bad input — it is whether anything the fuzzer can write
// gets past the signature. A feed is the one input that comes from outside the
// household, and everything downstream of Validate treats an Indicator as
// something a trusted publisher asserted.
func FuzzValidate(f *testing.F) {
	// A deterministic key, so a crash found here is reproducible. It is a test
	// key with no counterpart anywhere and signs nothing outside this test.
	seedKey := ed25519.NewKeyFromSeed([]byte("scamwall-fuzz-seed-key-32-bytes!"))
	pub := seedKey.Public().(ed25519.PublicKey)

	sign := func(payload string) []byte {
		sig := ed25519.Sign(seedKey, []byte(payload))
		return []byte(`{"schema_version":1,"signature":{"algorithm":"ed25519","key_id":"fuzz-key",` +
			`"value":"` + base64Std(sig) + `"},"payload":` + payload + `}`)
	}

	validPayload := `{"manifest_version":"1.0","feed_id":"fuzz","issued_at":"2026-01-01T00:00:00Z",` +
		`"expires_at":"2099-01-01T00:00:00Z","records":[` +
		`{"domain":"bad.example.com","action":"block","confidence":"high"},` +
		`{"domain":"аpple.example.com","action":"block","confidence":"high"}]}`

	f.Add(sign(validPayload))
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema_version":1,"signature":{"algorithm":"ed25519","key_id":"fuzz-key","value":""},"payload":{}}`))
	f.Add([]byte(`{"schema_version":2}`))
	f.Add([]byte(`{"schema_version":1,"signature":{"algorithm":"none","key_id":"fuzz-key","value":"AA=="},"payload":{}}`))
	f.Add(append(sign(validPayload), []byte(`{"trailing":1}`)...))

	opts := feed.Options{
		MaxFileBytes: 1 << 20,
		MaxRecords:   1000,
		TrustKeyID:   "fuzz-key",
		TrustKey:     pub,
		Now:          testNow,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// INVARIANT 1: no panic on any input.
		v, err := feed.Validate(data, opts)
		if err != nil {
			// INVARIANT 2: a rejected feed yields nothing usable.
			if v != nil {
				t.Fatalf("Validate failed but returned a result: %+v", v)
			}
			return
		}
		if v == nil {
			t.Fatal("Validate succeeded and returned nil")
		}

		// INVARIANT 3: bounded acceptance. Nothing beyond the declared record
		// ceiling reaches a caller.
		if len(v.Indicators) > opts.MaxRecords {
			t.Fatalf("%d indicators exceed the ceiling of %d", len(v.Indicators), opts.MaxRecords)
		}

		// INVARIANT 4: every surviving indicator is canonical, distinct, and
		// carries a recognised action and confidence. Deduplication downstream
		// assumes all three.
		seen := map[domain.Domain]bool{}
		for _, ind := range v.Indicators {
			if ind.Domain == "" {
				t.Fatal("an indicator has an empty domain")
			}
			round, nerr := domain.Normalize(ind.Domain.String())
			if nerr != nil || round != ind.Domain {
				t.Fatalf("indicator domain %q is not canonical: %v", ind.Domain, nerr)
			}
			if seen[ind.Domain] {
				t.Fatalf("duplicate indicator survived validation: %q", ind.Domain)
			}
			seen[ind.Domain] = true
			if !ind.Action.Valid() {
				t.Fatalf("indicator %q has an unrecognised action %q", ind.Domain, ind.Action)
			}
			if !ind.Confidence.Valid() {
				t.Fatalf("indicator %q has an unrecognised confidence %q", ind.Domain, ind.Confidence)
			}
			// INVARIANT 5: signals are a closed set. A signal invented by the
			// input would flow into a plan and into a policy decision.
			for _, s := range ind.Signals {
				switch s {
				case domain.SignalNonASCII, domain.SignalPunycodeInput,
					domain.SignalSingleNonLatinScript, domain.SignalMixedScript:
				default:
					t.Fatalf("indicator %q carries an unknown signal %q", ind.Domain, s)
				}
			}
		}

		// INVARIANT 6: an accepted feed was signed by the trusted key. Stated
		// explicitly because it is the property everything else rests on: the
		// fuzzer does not hold the private key, so any acceptance here that
		// was not produced from a seed is a signature-verification failure.
		if v.KeyID != opts.TrustKeyID {
			t.Fatalf("a feed signed by key id %q was accepted", v.KeyID)
		}
		if !ed25519.Verify(pub, mustPayload(t, data), mustSignature(t, data)) {
			t.Fatalf("an accepted feed does not verify against the trust key")
		}
	})
}

// The helpers below re-extract the signed material from the raw bytes, so that
// INVARIANT 6 is checked against the input rather than against anything the
// package under test reported about it.

func base64Std(b []byte) string { return b64.StdEncoding.EncodeToString(b) }

func mustPayload(t *testing.T, data []byte) []byte {
	t.Helper()
	var env struct {
		Payload jsonRaw `json:"payload"`
	}
	if err := jsonUnmarshal(data, &env); err != nil {
		t.Fatalf("an accepted feed could not be re-parsed: %v", err)
	}
	return env.Payload
}

func mustSignature(t *testing.T, data []byte) []byte {
	t.Helper()
	var env struct {
		Signature struct {
			Value string `json:"value"`
		} `json:"signature"`
	}
	if err := jsonUnmarshal(data, &env); err != nil {
		t.Fatalf("an accepted feed could not be re-parsed: %v", err)
	}
	sig, err := b64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		t.Fatalf("an accepted feed has a signature that is not base64: %v", err)
	}
	return sig
}

type jsonRaw = json.RawMessage

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
