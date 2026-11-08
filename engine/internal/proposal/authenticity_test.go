// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// # WHAT THIS FILE IS ABOUT
//
// FINDING-121. IntactSinceAuthentication covered the two fields somebody had
// noticed — Records and the signer's grant — and was therefore exactly as
// complete as the noticing. Four more exported fields could be rewritten
// after ValidateEvidence returned, and the run proceeded.
//
// Three classes, and they are worth keeping apart because they fail
// differently:
//
//	a DECISION change     the run admits or refuses different records
//	a FALSE ATTRIBUTION   the report says the document was signed by, or came
//	                      from, something it did not
//	a FALSE IDENTITY      the report names a digest nothing ever verified
//
// Only the first changes what the command concluded. The other two are worse
// in a specific way: the conclusion is correct and the citation is a lie, so
// nothing about the answer looks wrong.

// authedEvidence returns a freshly authenticated document and an Input that
// consumes it.
func authedEvidence(t *testing.T) (*feed.ValidatedEvidence, Input) {
	t.Helper()
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "authentic-key", pub, []string{"src-a"}, nil)
	doc := signEvidence(t, priv, "authentic-key", "authentic-feed", []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
	})
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	return ev, Input{
		Evidence: ev,
		Registry: testRegistry(t, testSource("src-a", nil)),
		Policy:   testPolicy(t, 1, ScopeExact),
		At:       testAt,
	}
}

// TestEveryExportedFieldOfTheAuthenticatedValueIsBound.
//
// By REFLECTION over the struct, so a field added to ValidatedEvidence is
// covered the day it is added rather than the day somebody remembers. A field
// this cannot generate a distinct value for fails the test rather than being
// skipped.
func TestEveryExportedFieldOfTheAuthenticatedValueIsBound(t *testing.T) {
	rt := reflect.TypeOf(feed.ValidatedEvidence{})
	exported := 0

	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		exported++
		t.Run(f.Name, func(t *testing.T) {
			ev, in := authedEvidence(t)
			if _, err := Build(in); err != nil {
				t.Fatalf("premise broken: the unmodified value does not build: %v", err)
			}

			target := reflect.ValueOf(ev).Elem().Field(i)
			alt, ok := distinctValue(target)
			if !ok {
				t.Fatalf("no distinct value can be generated for %s (%s); this test "+
					"cannot cover it and must be taught how rather than skipping it",
					f.Name, f.Type)
			}
			if reflect.DeepEqual(target.Interface(), alt.Interface()) {
				t.Fatalf("premise broken: the alternate value for %s equals the bound one", f.Name)
			}
			target.Set(alt)

			_, err := Build(in)
			if err == nil {
				t.Fatalf("%s was rewritten after authentication and the run proceeded", f.Name)
			}
			if !strings.Contains(err.Error(), "after it was authenticated") {
				t.Errorf("%s was refused for the wrong reason: %v", f.Name, err)
			}
		})
	}

	if exported < 7 {
		t.Errorf("only %d exported fields were found; this test is not covering the type", exported)
	}
}

// distinctValue produces a value of the same type that differs from v.
func distinctValue(v reflect.Value) (reflect.Value, bool) {
	switch v.Kind() {
	case reflect.String:
		return reflect.ValueOf(v.String() + "-rewritten").Convert(v.Type()), true
	case reflect.Pointer:
		if v.Type() == reflect.TypeOf((*feed.Signer)(nil)) {
			s := feed.Signer{KeyID: "rewritten", PublicKey: "rewritten",
				AssertsSourceIDs: []string{"src-b"}}
			return reflect.ValueOf(&s), true
		}
		return reflect.Value{}, false
	case reflect.Slice:
		if v.Type() == reflect.TypeOf([]feed.EvidenceRecord(nil)) {
			return reflect.ValueOf([]feed.EvidenceRecord{
				adverse("src-a", "rewritten", "rewritten.example.com"),
			}), true
		}
		return reflect.Value{}, false
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			t := v.Interface().(time.Time).Add(time.Hour)
			return reflect.ValueOf(t), true
		}
		return reflect.Value{}, false
	default:
		return reflect.Value{}, false
	}
}

// TestTheThreeWaysARewriteFails names each class, with the field that
// demonstrates it.
//
// The reflective test above proves coverage. This one records WHAT each
// rewrite would have produced, because "a field was unbound" is a weaker
// statement than "the report would have said the document was signed by a key
// that did not sign it".
func TestTheThreeWaysARewriteFails(t *testing.T) {
	cases := []struct {
		field string
		class string
		what  string
		apply func(*feed.ValidatedEvidence)
	}{
		{"BytesDigest", "FALSE IDENTITY",
			"the report names a digest nothing ever verified",
			func(e *feed.ValidatedEvidence) { e.BytesDigest = "sha256:" + strings.Repeat("00", 32) }},
		{"KeyID", "FALSE ATTRIBUTION",
			"the report says the document was signed by a key that did not sign it",
			func(e *feed.ValidatedEvidence) { e.KeyID = "a-key-that-did-not-sign" }},
		{"FeedID", "FALSE ATTRIBUTION",
			"the report says the records came from a document they did not",
			func(e *feed.ValidatedEvidence) { e.FeedID = "a-feed-it-did-not-come-from" }},
		{"Records", "DECISION CHANGE",
			"the run admits a claim the signature never covered",
			func(e *feed.ValidatedEvidence) { e.Records[0].SourceID = "src-b" }},
		{"Signer", "DECISION CHANGE",
			"the grant is widened after the admission was decided",
			func(e *feed.ValidatedEvidence) {
				e.Signer.AssertsSourceIDs = append(e.Signer.AssertsSourceIDs, "src-b")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.field+"/"+tc.class, func(t *testing.T) {
			ev, in := authedEvidence(t)
			tc.apply(ev)
			if _, err := Build(in); err == nil {
				t.Fatalf("%s: %s", tc.class, tc.what)
			}
		})
	}
}

// TestTheEvidenceDigestIsStillTheDigestOfTheAuthenticatedBytes.
//
// The correction must not have turned the binding into a digest of the
// DECODED value. The report cites the signed FILE, and a reader has to be
// able to recompute it from the bytes on disk.
func TestTheEvidenceDigestIsStillTheDigestOfTheAuthenticatedBytes(t *testing.T) {
	priv, pub := testKey(t, 0x31)
	auth := authorityOver(t, "k", pub, []string{"src-a"}, nil)
	doc := signEvidence(t, priv, "k", "synthetic", []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
	})
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	rep, err := Build(Input{Evidence: ev,
		Registry: testRegistry(t, testSource("src-a", nil)),
		Policy:   testPolicy(t, 1, ScopeExact), At: testAt})
	if err != nil {
		t.Fatal(err)
	}

	if rep.Binding.EvidenceDigest != ev.BytesDigest {
		t.Errorf("the report's evidence digest is not the document's:\n  report %q\n  bytes  %q",
			rep.Binding.EvidenceDigest, ev.BytesDigest)
	}
	// Recomputable from the bytes alone, which is the property that makes it
	// a citation rather than a label.
	again, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.BytesDigest != rep.Binding.EvidenceDigest {
		t.Error("re-reading the same bytes produced a different digest")
	}
	// And a different document must not share it.
	other := signEvidence(t, priv, "k", "synthetic", []feed.EvidenceRecord{
		adverse("src-a", "a1", "two.example.com"),
	})
	ev2, err := feed.ValidateEvidence(other, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev2.BytesDigest == rep.Binding.EvidenceDigest {
		t.Error("two different documents share an evidence digest")
	}
}

// TestTheCheckDoesNotReplaceTheSignature.
//
// Two different properties. A document whose signature does not verify never
// reaches the integrity check, and a document that is intact says nothing
// about who produced it. Asserting both directions keeps a future
// simplification from collapsing them.
func TestTheCheckDoesNotReplaceTheSignature(t *testing.T) {
	_, pub := testKey(t, 0x31)
	other, _ := testKey(t, 0x32)
	auth := authorityOver(t, "k", pub, []string{"src-a"}, nil)

	// Signed by a key the operator did not record as `k`. The bytes are
	// internally consistent and their integrity digest would be perfectly
	// well-formed; the signature is what refuses them.
	forged := signEvidence(t, other, "k", "synthetic", []feed.EvidenceRecord{
		adverse("src-a", "a1", "one.example.com"),
	})
	if _, err := feed.ValidateEvidence(forged, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	}); err == nil {
		t.Fatal("a forged signature reached the integrity check")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// And the converse: an intact value is intact whoever signed it, so
	// intactness alone establishes nothing about authenticity.
	ev, _ := authedEvidence(t)
	if !ev.IntactSinceAuthentication() {
		t.Fatal("a freshly validated value is not intact")
	}
}

// TestWhatTheIntegrityCheckDoesNotDefeat.
//
// # THE HONEST LIMIT, MEASURED RATHER THAN ASSERTED
//
// The check is one comparison at one instant, and a check before a loop says
// nothing about the loop. Build closes the window by taking a snapshot
// immediately after the check; this measures that the snapshot is real.
//
// It does NOT test a write racing the copy. That is unsynchronised access in
// the caller's program, it is a data race under Go's memory model, and a test
// that performed one would be asserting behaviour Go does not define — and
// would make `go test -race` fail this suite, which is the race detector
// working correctly rather than a defect to be silenced. The limit is
// recorded in Build's own comment and in IntactSinceAuthentication's.
func TestWhatTheIntegrityCheckDoesNotDefeat(t *testing.T) {
	t.Run("an edit AFTER Build returns cannot change what it reported", func(t *testing.T) {
		ev, in := authedEvidence(t)
		rep, err := Build(in)
		if err != nil {
			t.Fatal(err)
		}
		digestBefore := rep.Binding.EvidenceDigest
		keyBefore := rep.Binding.SigningKeyID
		canonicalBefore := only(t, rep).Canonical

		ev.BytesDigest = "sha256:" + strings.Repeat("ff", 32)
		ev.KeyID = "rewritten"
		ev.Records[0].SourceID = "src-b"

		if rep.Binding.EvidenceDigest != digestBefore {
			t.Error("editing the evidence changed a report that had already been produced")
		}
		if rep.Binding.SigningKeyID != keyBefore {
			t.Error("editing the key id changed a report that had already been produced")
		}
		if only(t, rep).Canonical != canonicalBefore {
			t.Error("editing a record changed a report that had already been produced")
		}
	})

	t.Run("the snapshot is deep: the record slice is not shared", func(t *testing.T) {
		ev, in := authedEvidence(t)
		snap := ev.Snapshot()
		ev.Records[0].SourceID = "src-b"
		if snap.Records[0].SourceID != "src-a" {
			t.Error("the snapshot shares the caller's record array")
		}
		ev.Signer.AssertsSourceIDs[0] = "src-b"
		if snap.Signer.AssertsSourceIDs[0] != "src-a" {
			t.Error("the snapshot shares the caller's grant slice")
		}
		if snap.Signer == ev.Signer {
			t.Error("the snapshot shares the caller's Signer pointer")
		}
		_ = in
	})

	t.Run("concurrent READERS of one validated value agree", func(t *testing.T) {
		// Read-only sharing IS safe and is the case a caller actually has:
		// one authenticated document, several runs. Under -race this says so.
		ev, in := authedEvidence(t)
		const workers = 12
		var wg sync.WaitGroup
		out := make([]string, workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rep, err := Build(Input{Evidence: ev, Registry: in.Registry,
					Policy: in.Policy, At: in.At})
				if err != nil {
					out[i] = "error: " + err.Error()
					return
				}
				var b strings.Builder
				rep.Text(&b)
				out[i] = b.String()
			}(i)
		}
		wg.Wait()
		for i := 1; i < workers; i++ {
			if out[i] != out[0] {
				t.Fatalf("worker %d produced a different report", i)
			}
		}
		if strings.HasPrefix(out[0], "error:") {
			t.Fatalf("every worker failed: %s", out[0])
		}
	})
}

// TestFieldsThatChangeNeitherTheDecisionNorTheReport.
//
// **[recorded as a NON-finding.]** IssuedAt and ExpiresAt are consumed by
// feed.ValidateEvidence — freshness, clock skew, ordering — and by nothing
// downstream. Rewriting them after validation is now refused, like every
// other field, but it was never a disclosure or a false claim: before the
// correction it changed no decision and no reported value.
//
// Kept so a reader does not infer that the whole class was dangerous, and so
// that a future change which STARTS consuming those fields is a change to a
// documented assumption.
func TestFieldsThatChangeNeitherTheDecisionNorTheReport(t *testing.T) {
	_, in := authedEvidence(t)
	rep, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	rep.Text(&b)
	for _, stamp := range []string{
		in.Evidence.IssuedAt.UTC().Format(time.RFC3339),
		in.Evidence.ExpiresAt.UTC().Format(time.RFC3339),
	} {
		if strings.Contains(b.String(), stamp) {
			t.Errorf("the report now carries %q; this test's premise — that the "+
				"manifest window is consumed only by validation — no longer holds", stamp)
		}
	}
}
