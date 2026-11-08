// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"errors"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/strictjson"
)

// # WHAT THIS FILE IS ABOUT
//
// FINDING-127, found by the ORDER 7 red team driving the real command.
//
// encoding/json accepts a duplicate key and silently keeps the LAST one. For
// a document of record that is the worst available behaviour, and all three
// documents `scamwall propose` reads were subject to it:
//
//	{"min_independent_sources": 1, ..., "min_independent_sources": 99}
//
// was accepted, and the report's every abstention read "of 99 required". A
// reviewer reading that file sees 1. Both are reading the same bytes.
//
// internal/evaluation and internal/sourceregistry each already refused this,
// for their own documents, with their own copy of the walk. The proposal path
// had neither. See internal/strictjson for why the third copy is a package.

// TestAnAmbiguousPolicyIsRefusedRatherThanResolved.
func TestAnAmbiguousPolicyIsRefusedRatherThanResolved(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"the threshold, twice",
			`{"schema_version":1,"min_independent_sources":1,
			  "min_independent_sources":99,"proposal_scope":"exact"}`},
		{"the scope, twice",
			`{"schema_version":1,"min_independent_sources":1,
			  "proposal_scope":"exact","proposal_scope":"subdomains"}`},
		{"the escape hatch, twice",
			`{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			  "accept_unestablished_independence":false,
			  "accept_unestablished_independence":true}`},
		{"an exception's scope, twice",
			`{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			  "exceptions":[{"value":"a.example.com","scope":"exact","scope":"subdomains"}]}`},
		{"the schema version, twice",
			`{"schema_version":1,"schema_version":99,
			  "min_independent_sources":1,"proposal_scope":"exact"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tc.doc))
			if err == nil {
				t.Fatal("an ambiguous policy was ACCEPTED")
			}
			if !errors.Is(err, strictjson.ErrAmbiguous) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestAnOrdinaryPolicyIsStillAccepted is the positive control. A check that
// refused every document would satisfy every assertion above.
func TestAnOrdinaryPolicyIsStillAccepted(t *testing.T) {
	p, err := ParsePolicy([]byte(`{"schema_version":1,"note":"ordinary",
		"min_independent_sources":2,"proposal_scope":"exact",
		"accept_unestablished_independence":false,
		"exceptions":[
		  {"value":"bank.example.com","scope":"exact","note":"one"},
		  {"value":"work.example.net","scope":"subdomains","note":"two"}]}`))
	if err != nil {
		t.Fatalf("a well-formed policy was refused: %v", err)
	}
	if *p.MinIndependentSources != 2 || len(p.Exceptions) != 2 {
		t.Errorf("the policy did not decode as written: %+v", p)
	}
	// Two exceptions both carrying a `value` key is not a duplicate: they are
	// different objects. A walk that reported it would be unusable.
	if len(p.Exceptions) != 2 {
		t.Error("two sibling objects with the same field names were treated as a duplicate")
	}
}

// TestAnAmbiguousSignerAuthorityIsRefused.
//
// The worst of the three: a grant stated twice decides which source ids a
// signer may speak for, and the operator sees the first.
func TestAnAmbiguousSignerAuthorityIsRefused(t *testing.T) {
	_, pub := testKey(t, 0x31)
	doc := `{"schema_version":1,"signers":[{"key_id":"k","public_key":"` + pub + `",
		"asserts_source_ids":["src-a"],"asserts_source_ids":["src-a","src-b","src-c"]}]}`
	_, err := feed.ParseSignerAuthority([]byte(doc))
	if err == nil {
		t.Fatal("an ambiguous authority document was ACCEPTED")
	}
	if !errors.Is(err, strictjson.ErrAmbiguous) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if !strings.Contains(err.Error(), "signers[0]") {
		t.Errorf("the diagnostic does not locate the duplicate: %v", err)
	}
}

// TestAnAmbiguousEvidenceDocumentIsRefused, at both levels.
//
// The envelope is checked before the signature, because an ambiguous envelope
// cannot be authenticated coherently. The PAYLOAD is checked after it, because
// nothing may interpret payload bytes the signer did not produce.
func TestAnAmbiguousEvidenceDocumentIsRefused(t *testing.T) {
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "k", pub, []string{"src-a"}, nil)
	opts := feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	}

	t.Run("the envelope", func(t *testing.T) {
		doc := signEvidence(t, priv, "k", "synthetic",
			[]feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")})
		ambiguous := strings.Replace(string(doc),
			`"schema_version":2,`, `"schema_version":2,"schema_version":1,`, 1)
		if ambiguous == string(doc) {
			t.Fatal("premise broken: nothing was duplicated")
		}
		_, err := feed.ValidateEvidence([]byte(ambiguous), opts)
		if err == nil {
			t.Fatal("an ambiguous envelope was ACCEPTED")
		}
		if !errors.Is(err, strictjson.ErrAmbiguous) {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("the payload, which is checked AFTER the signature", func(t *testing.T) {
		// Signed over the ambiguous bytes, so the signature verifies and the
		// document is still refused. This is the case that matters: a signer
		// CAN sign an ambiguous payload, and a human reading it sees the
		// first value.
		payload := []byte(`{"manifest_version":"1.0","feed_id":"f",` +
			`"issued_at":"2026-05-31T23:00:00Z","expires_at":"2026-06-02T00:00:00Z",` +
			`"feed_id":"a-different-feed",` +
			`"records":[{"type":"domain","value":"one.example.com","source_id":"src-a",` +
			`"classification":"malicious","state":"active"}]}`)
		doc := envelopeOver(t, priv, "k", payload)
		_, err := feed.ValidateEvidence(doc, opts)
		if err == nil {
			t.Fatal("an ambiguous PAYLOAD was accepted, with a valid signature over it")
		}
		if !errors.Is(err, strictjson.ErrAmbiguous) {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("an ordinary document is still admitted", func(t *testing.T) {
		doc := signEvidence(t, priv, "k", "synthetic",
			[]feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")})
		if _, err := feed.ValidateEvidence(doc, opts); err != nil {
			t.Fatalf("a well-formed document was refused: %v", err)
		}
	})
}

// TestAnAmbiguityDiagnosticEchoesNoKeyAndIsBounded.
//
// The corrections ORDER 6 made to internal/evaluation's copy of this walk —
// FINDING-112, FINDING-113, FINDING-114 — are carried by the shared package
// and asserted here, at the surface that uses it.
func TestAnAmbiguityDiagnosticEchoesNoKeyAndIsBounded(t *testing.T) {
	t.Run("a hostile key is not echoed", func(t *testing.T) {
		hostile := "exceptions[" + string(rune(0x1b)) + "[2J" + string(rune(0x07)) + "forged"
		doc := `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",` +
			jsonString(hostile) + `:{"a":1,"a":2}}`
		_, err := ParsePolicy([]byte(doc))
		if err == nil {
			t.Fatal("an ambiguous policy was ACCEPTED")
		}
		msg := err.Error()
		for _, r := range msg {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("a raw control U+%04X reached the diagnostic: %q", r, msg)
			}
		}
		if strings.Contains(msg, "forged") {
			t.Errorf("the diagnostic echoes the key: %q", msg)
		}
		if !strings.Contains(msg, strictjson.UnrecognisedSegment) {
			t.Errorf("an unrecognised segment is not reported as one: %q", msg)
		}
	})

	t.Run("a known key IS named, so a typo is findable", func(t *testing.T) {
		_, err := ParsePolicy([]byte(`{"schema_version":1,"min_independent_sources":1,
			"min_independent_sources":2,"proposal_scope":"exact"}`))
		if err == nil {
			t.Fatal("accepted")
		}
		if !strings.Contains(err.Error(), `"min_independent_sources"`) {
			t.Errorf("a key this schema DOES define was not named: %v", err)
		}
	})

	t.Run("many duplicates produce a bounded diagnostic", func(t *testing.T) {
		const n = 20000
		var b strings.Builder
		b.WriteString(`{"schema_version":1,"proposal_scope":"exact"`)
		for i := 0; i < n; i++ {
			b.WriteString(`,"min_independent_sources":1`)
		}
		b.WriteString(`}`)
		_, err := ParsePolicy([]byte(b.String()))
		if err == nil {
			t.Fatal("accepted")
		}
		if got := len(err.Error()); got > 32*1024 {
			t.Errorf("a %d-byte document produced a %d-byte diagnostic", b.Len(), got)
		}
		if !strings.Contains(err.Error(), "not listed") {
			t.Error("the diagnostic omits problems without saying so")
		}
	})
}
