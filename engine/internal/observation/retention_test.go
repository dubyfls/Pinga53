// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"errors"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// retained builds a valid observation that carries raw provider content.
func retained(t *testing.T, sourceID string) Observation {
	t.Helper()
	o := mustNew(t, "retain.example.com", sourceID)
	o.Classification = ClassMalicious
	o.State = StateActive
	o.Status = StatusCurrent
	o.RawRetention = RetentionRetained
	o.Raw = `{"provider":"verbatim response body"}`
	if err := o.Validate(); err != nil {
		t.Fatalf("the fixture is invalid before the rights question is reached: %v", err)
	}
	return o
}

// TestRetainedContentCannotEnterTheTrustedStoreUnauthorised.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// RetentionPermitted existed, returned the RIGHT answer, and documented itself
// as the question that "is asked rather than assumed by the presence of the
// field". Nothing on the ingest path asked it. Demonstrated verbatim:
//
//	Validate()              = <nil>
//	RetentionPermitted(nil) = false  (no registry, so no grant can be read)
//	Store.Add               -> outcome=new
//	IN THE TRUSTED STORE: raw="{\"provider\":\"verbatim response body\"}"
//
// A function that answers a question nobody asks is not an enforcement point.
func TestRetainedContentCannotEnterTheTrustedStoreUnauthorised(t *testing.T) {
	prohibits := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil,
		map[sourceregistry.Operation]string{sourceregistry.OpLocalStorage: sourceregistry.GrantProhibited}))
	unknownGrant := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil, nil))
	retiredReg := &sourceregistry.Registry{
		SchemaVersion:    2,
		RetiredSourceIDs: []string{"src-0001"},
	}
	empty := synthReg(t)

	tests := []struct {
		name string
		reg  *sourceregistry.Registry
	}{
		{"no registry at all", nil},
		{"an empty registry: the source does not resolve", empty},
		{"a source that is not in the registry", retiredReg},
		{"a retired source", retiredReg},
		{"a source whose local-storage grant is unknown", unknownGrant},
		{"a source that prohibits local storage", prohibits},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStoreWithRights(tc.reg)
			_, err := s.Add(retained(t, "src-0001"))
			if err == nil {
				t.Fatal("retained provider content entered the trusted store unauthorised")
			}
			if !errors.Is(err, ErrRetentionRefused) {
				t.Errorf("refused, but not as a retention refusal: %v", err)
			}
			if s.Len() != 0 {
				t.Errorf("the store holds %d indicator(s) after refusing", s.Len())
			}
			// And no raw content is reachable anywhere in it.
			for _, ind := range s.Indicators() {
				for _, e := range ind.Entries {
					if e.Observation.Raw != "" {
						t.Error("raw provider content is present in the store")
					}
				}
			}
		})
	}
}

// TestTheDefaultStoreFailsClosed. NewStore has no rights authority, and a
// store that cannot read a grant does not get to assume one.
func TestTheDefaultStoreFailsClosed(t *testing.T) {
	s := NewStore()
	if _, err := s.Add(retained(t, "src-0001")); err == nil {
		t.Fatal("the default store accepted retained content with no authority to do so")
	}
}

// TestAuthorisedRetentionIsAdmitted is the POSITIVE CONTROL.
//
// Without it, a gate that refused everything would pass every test above and
// would have replaced a rights hole with a rights wall.
func TestAuthorisedRetentionIsAdmitted(t *testing.T) {
	permits := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil,
		map[sourceregistry.Operation]string{sourceregistry.OpLocalStorage: sourceregistry.GrantPermitted}))

	s := NewStoreWithRights(permits)
	out, err := s.Add(retained(t, "src-0001"))
	if err != nil {
		t.Fatalf("an authorised retention was refused: %v", err)
	}
	if out != OutcomeNew {
		t.Errorf("outcome = %v, want %v", out, OutcomeNew)
	}
	ind, ok := s.Lookup(Key{Type: TypeDomain, Canonical: "retain.example.com"})
	if !ok {
		t.Fatal("the authorised record is not in the store")
	}
	if ind.Entries[0].Observation.Raw == "" {
		t.Error("the authorised raw content was dropped")
	}
}

// TestARecordWithNoRetainedContentNeedsNoGrant is the other half of the
// control: the gate must not refuse work that involves no retention at all.
func TestARecordWithNoRetainedContentNeedsNoGrant(t *testing.T) {
	// No registry, no grants, nothing retained.
	s := NewStore()
	o := mustNew(t, "plain.example.com", "src-UNLISTED")
	o.Classification = ClassMalicious
	o.State = StateActive
	o.Status = StatusCurrent

	if _, err := s.Add(o); err != nil {
		t.Fatalf("a record retaining nothing was refused: %v", err)
	}
	if s.Len() != 1 {
		t.Errorf("the store holds %d indicator(s), want 1", s.Len())
	}
}

// TestWithoutRawIsTheSupportedWayIn.
//
// Validation may need the provider's own response while the rights position
// forbids keeping it. The separation lives in the caller's scope: hold the raw
// bytes locally, admit the record with WithoutRaw, let the bytes go out of
// scope. What enters the store then provably carries nothing forbidden.
func TestWithoutRawIsTheSupportedWayIn(t *testing.T) {
	prohibits := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil,
		map[sourceregistry.Operation]string{sourceregistry.OpLocalStorage: sourceregistry.GrantProhibited}))

	staged := retained(t, "src-0001")
	s := NewStoreWithRights(prohibits)
	if _, err := s.Add(staged); err == nil {
		t.Fatal("premise: the retained form should have been refused")
	}

	admitted := staged.WithoutRaw()
	if admitted.Raw != "" || admitted.RawRetention != RetentionNone {
		t.Fatalf("WithoutRaw left raw=%q retention=%q", admitted.Raw, admitted.RawRetention)
	}
	// The original is untouched: it is the caller's staging copy.
	if staged.Raw == "" {
		t.Error("WithoutRaw mutated the caller's own record")
	}

	if _, err := s.Add(admitted); err != nil {
		t.Fatalf("the rights-stripped record was refused: %v", err)
	}
	ind, ok := s.Lookup(Key{Type: TypeDomain, Canonical: "retain.example.com"})
	if !ok {
		t.Fatal("the rights-stripped record is not in the store")
	}
	// It is still the same evidence about who said what.
	if got := ind.Entries[0].Observation.SourceID; got != "src-0001" {
		t.Errorf("source id = %q, want src-0001", got)
	}
	if ind.Entries[0].Observation.Raw != "" {
		t.Error("raw content reached the store through WithoutRaw")
	}
}

// TestCorrectionsAreGatedToo. A record may become retained on a later
// revision, and the gate must be on every entry rather than only the first.
func TestCorrectionsAreGatedToo(t *testing.T) {
	prohibits := synthReg(t, src("src-0001", sourceregistry.UpstreamDocumentedComplete, nil,
		map[sourceregistry.Operation]string{sourceregistry.OpLocalStorage: sourceregistry.GrantProhibited}))
	s := NewStoreWithRights(prohibits)

	clean := mustNew(t, "retain.example.com", "src-0001")
	clean.Classification = ClassMalicious
	clean.State = StateActive
	clean.Status = StatusCurrent
	clean.SourceRecordID = "rec-1"
	if _, err := s.Add(clean); err != nil {
		t.Fatalf("the clean first revision was refused: %v", err)
	}

	// The same record, corrected to carry raw content.
	dirty := retained(t, "src-0001")
	dirty.SourceRecordID = "rec-1"
	if _, err := s.Add(dirty); err == nil {
		t.Fatal("a correction smuggled retained content past the gate")
	}

	ind, _ := s.Lookup(Key{Type: TypeDomain, Canonical: "retain.example.com"})
	if n := len(ind.History()); n != 1 {
		t.Errorf("the refused correction changed the history to %d entries", n)
	}
	for _, e := range ind.History() {
		if e.Observation.Raw != "" {
			t.Error("raw content reached the store through a correction")
		}
	}
}
