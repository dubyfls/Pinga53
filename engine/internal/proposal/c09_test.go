// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// C-09 — a host a report may not name still gets an identifier, and the
// identifier is KEYED.
//
// An unkeyed digest of a hostname is not an opaque identifier. Anyone who can
// guess the name computes the digest and confirms the guess, and the same
// digest appears in every installation, so two reports from two households are
// correlatable by a third party who has neither. The key is the whole control.

func c09Key(t *testing.T, b byte) *mac.Key {
	t.Helper()
	raw := make([]byte, mac.MinKeyBytes)
	for i := range raw {
		raw[i] = b
	}
	k, err := mac.NewKey(raw)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func c09Report(t *testing.T, k *mac.Key, sources ...sourceregistry.Source) *Report {
	t.Helper()
	ids := make([]string, 0, len(sources))
	for _, s := range sources {
		ids = append(ids, s.SourceID)
	}
	return run{
		asserts:     ids,
		sources:     sources,
		policy:      testPolicy(t, 1, ScopeExact),
		records:     adverseRecords(ids...),
		identityKey: k,
	}.do(t)
}

func withheldOutcome(t *testing.T, r *Report) Outcome {
	t.Helper()
	for _, o := range r.Outcomes {
		if o.IdentityWithheld {
			return o
		}
	}
	t.Fatalf("no withheld outcome in the report")
	return Outcome{}
}

// TestAWithheldHostGetsAnIdentifier.
func TestAWithheldHostGetsAnIdentifier(t *testing.T) {
	rep := c09Report(t, c09Key(t, 0x11), localOnly("src-a"))
	o := withheldOutcome(t, rep.ForAudience(AudienceExport))
	if o.OpaqueID == "" {
		t.Fatalf("a withheld outcome carries no identifier at all; two reports about the same host "+
			"cannot be told to be about the same host\n%+v", o)
	}
	if strings.Contains(o.OpaqueID, "example") || strings.Contains(o.OpaqueID, "bad") {
		t.Errorf("the identifier reproduces the name: %s", o.OpaqueID)
	}
}

// TestTwoInstallationsProduceDifferentIdentifiersForOneHost is the control.
// An unkeyed digest passes every other test in this file and fails this one.
func TestTwoInstallationsProduceDifferentIdentifiersForOneHost(t *testing.T) {
	a := withheldOutcome(t, c09Report(t, c09Key(t, 0x11), localOnly("src-a")).ForAudience(AudienceExport))
	b := withheldOutcome(t, c09Report(t, c09Key(t, 0x22), localOnly("src-a")).ForAudience(AudienceExport))
	if a.OpaqueID == b.OpaqueID {
		t.Fatalf("two installations produced the same identifier for one host: %s", a.OpaqueID)
	}
}

// TestOneInstallationProducesTheSameIdentifierTwice — the identifier is only
// worth having if it correlates.
func TestOneInstallationProducesTheSameIdentifierTwice(t *testing.T) {
	k := c09Key(t, 0x11)
	a := withheldOutcome(t, c09Report(t, k, localOnly("src-a")).ForAudience(AudienceExport))
	b := withheldOutcome(t, c09Report(t, k, localOnly("src-a")).ForAudience(AudienceExport))
	if a.OpaqueID != b.OpaqueID {
		t.Fatalf("two runs of one installation gave one host two identifiers: %s and %s", a.OpaqueID, b.OpaqueID)
	}
}

// TestNoKeyMeansNoIdentifierAndTheReportSaysSo.
//
// The failure that must not happen is a fallback to an unkeyed digest, which
// would look exactly like a working control and be none.
func TestNoKeyMeansNoIdentifierAndTheReportSaysSo(t *testing.T) {
	rep := c09Report(t, nil, localOnly("src-a"))
	o := withheldOutcome(t, rep.ForAudience(AudienceExport))
	if o.OpaqueID != "" {
		t.Fatalf("a run with no identity key produced an identifier anyway: %s", o.OpaqueID)
	}
	joined := strings.Join(rep.Limitations(), " ")
	if !strings.Contains(joined, "identity key") {
		t.Errorf("the report does not say it had no identity key:\n%s", joined)
	}
}

// TestARecordWithAWithheldValueGetsTheSameIdentifier — the record list and
// the outcome list must agree, or a reader correlating them learns nothing.
func TestARecordWithAWithheldValueGetsTheSameIdentifier(t *testing.T) {
	rep := c09Report(t, c09Key(t, 0x11), localOnly("src-a")).ForAudience(AudienceExport)
	want := withheldOutcome(t, rep).OpaqueID
	found := false
	for _, rec := range rep.Records {
		if !rec.CanonicalWithheld {
			continue
		}
		found = true
		if rec.OpaqueID != want {
			t.Errorf("record %d has identifier %q, the outcome has %q", rec.Index, rec.OpaqueID, want)
		}
	}
	if !found {
		t.Fatalf("no record had its value withheld")
	}
}

// TestTheIdentifierIsUnderItsOwnPurpose — C-24's rule reaching back into this
// one. A tag over a hostname must not be the same bytes as a tag over the
// same string computed to seal a record.
func TestTheIdentifierIsUnderItsOwnPurpose(t *testing.T) {
	k := c09Key(t, 0x11)
	o := withheldOutcome(t, c09Report(t, k, localOnly("src-a")).ForAudience(AudienceExport))
	if o.OpaqueID == k.Tag(mac.PurposeStoreBinding, "bad.example.com") {
		t.Fatalf("the withheld-host identifier is the store-binding tag over the same name")
	}
	if o.OpaqueID != k.Tag(mac.PurposeWithheldHost, "bad.example.com") {
		t.Fatalf("the identifier is not the withheld-host tag over the canonical name")
	}
}
