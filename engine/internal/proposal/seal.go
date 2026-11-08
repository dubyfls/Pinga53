// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"errors"
	"fmt"

	"github.com/dubyfls/Pinga53/engine/internal/mac"
)

// # C-24: THREE CLAUSES, THREE DIFFERENT FORGERIES
//
// A tag with NO PURPOSE can be replayed anywhere the same key is used.
// internal/mac answers that half and proves it there.
//
// A record SEALED IN THE STORE, presented as a report, is a claim that
// somebody decided something when all that happened is that something was
// written down. Two defences, because either alone is thin: the seal names
// its purpose and a store purpose is refused outright, and — for the case
// where somebody simply rewrites the label — the tags themselves are computed
// under mac.PurposeReportBinding and a store-purpose tag over the same bytes
// is a different tag.
//
// An ITEM CHECK is three checks or it is none. Covering the digest and not
// the host lets an item be moved onto another hostname. Covering the host and
// not the digest lets its decision be rewritten. Covering both and not the
// whole set lets an item be added or dropped, which is how a report loses the
// one outcome somebody did not like.

// ErrSealInvalid is a report that does not match its seal.
var ErrSealInvalid = errors.New("proposal: the report does not match its seal")

// ItemSeal binds one outcome.
type ItemSeal struct {
	// Host is the canonical name, or — where the report may not name it —
	// the C-09 opaque identifier. A withheld item still has to be
	// distinguishable from the item beside it, or two of them can be swapped.
	Host string `json:"host"`
	// Digest is over the outcome's substance.
	Digest string `json:"digest"`
	// Tag is the keyed tag over (host, digest), under the report purpose.
	Tag string `json:"tag"`
}

// Seal binds a whole report.
type Seal struct {
	// Purpose is written down so a reader can see which one was claimed, and
	// so a seal claiming another one is refused before any tag is compared.
	Purpose string     `json:"purpose"`
	Binding string     `json:"binding_digest"`
	Items   []ItemSeal `json:"items"`
	// Tag covers the binding digest AND every item tag in order, so adding,
	// dropping or reordering items is a different seal.
	Tag string `json:"tag"`
}

// itemSealMessage is the message an item tag is computed over.
//
// Length-prefixed by mac.Tag's own encoding at the outer level; the two
// fields are joined here with a separator that cannot appear in either — a
// digest is "sha256:" plus hex, and a canonical host or an opaque identifier
// is LDH or base64url. Neither contains a newline.
func itemSealMessage(it ItemSeal) string { return it.Host + "\n" + it.Digest }

// itemSubstance is what a change to an outcome is measured over.
//
// Enumerated rather than reflected: a field added to Outcome and not added
// here would be invisible to the seal, and a test would not notice because
// the seal would still verify. internal/observation's observationDigest makes
// the same choice for the same reason.
func itemSubstance(o Outcome) string {
	return digestJSON("proposal-outcome", struct {
		Type                    string   `json:"type"`
		Canonical               string   `json:"canonical"`
		IdentityWithheld        bool     `json:"identity_withheld"`
		ExportWithheld          bool     `json:"export_withheld"`
		OpaqueID                string   `json:"opaque_id"`
		Scope                   Scope    `json:"scope"`
		Decision                Decision `json:"decision"`
		Reason                  Reason   `json:"reason"`
		Explanation             string   `json:"explanation"`
		Sources                 []string `json:"sources"`
		IndependentSources      []string `json:"independent_sources"`
		UnestablishedSources    []string `json:"unestablished_sources"`
		AdverseSources          []string `json:"adverse_sources"`
		AggregatedSources       []string `json:"aggregated_sources"`
		AuthoritativeSources    []string `json:"authoritative_sources"`
		RefusedSources          []string `json:"refused_sources"`
		RetractedBy             []string `json:"retracted_by"`
		SharedOrigins           []string `json:"shared_origins"`
		IndependentOriginGroups int      `json:"independent_origin_groups"`
		Signals                 []string `json:"signals"`
		Conflicted              bool     `json:"conflicted"`
		Exception               any      `json:"exception"`
	}{
		o.Type, o.Canonical, o.IdentityWithheld, o.ExportWithheld, o.OpaqueID,
		o.Scope, o.Decision, o.Reason, o.Explanation,
		o.Sources, o.IndependentSources, o.UnestablishedSources, o.AdverseSources,
		o.AggregatedSources, o.AuthoritativeSources, o.RefusedSources, o.RetractedBy,
		o.SharedOrigins, o.IndependentOriginGroups, o.Signals, o.Conflicted, o.Exception,
	})
}

// itemIdentity is what the seal calls an outcome.
//
// The canonical name where the report may print it, the C-09 opaque
// identifier where it may not. A withheld item sealed under the empty string
// is indistinguishable from the withheld item beside it, and two of them
// could be swapped without the seal noticing.
func itemIdentity(o Outcome) string {
	if o.Canonical != "" {
		return o.Canonical
	}
	if o.OpaqueID != "" {
		return "opaque:" + o.OpaqueID
	}
	// Neither a name nor an identifier: the run had no key and the host is
	// withheld. Say so rather than sealing under nothing — a reader can then
	// see that this item is not individually distinguishable, instead of
	// being told it is when it is not.
	return "unidentified"
}

// Seal binds the report under mac.PurposeReportBinding.
//
// A NIL KEY RETURNS NIL. There is no unkeyed seal: a digest anybody can
// recompute proves the report has not been corrupted and proves nothing at
// all about who produced it, and calling that a seal would be the same
// mistake C-09 refuses for hostnames.
func (r *Report) Seal(k *mac.Key) *Seal {
	if k == nil {
		return nil
	}
	s := &Seal{
		Purpose: string(mac.PurposeReportBinding),
		Binding: digestJSON("proposal-binding", r.Binding),
		Items:   make([]ItemSeal, 0, len(r.Outcomes)),
	}
	msg := s.Binding
	for _, o := range r.Outcomes {
		it := ItemSeal{Host: itemIdentity(o), Digest: itemSubstance(o)}
		it.Tag = k.Tag(mac.PurposeReportBinding, itemSealMessage(it))
		s.Items = append(s.Items, it)
		msg += "\n" + it.Tag
	}
	s.Tag = k.Tag(mac.PurposeReportBinding, msg)
	return s
}

// VerifySeal checks a report against a seal.
//
// Every failure names what did not match. A verifier that says only "invalid"
// tells the reader to distrust the whole document when one item was changed,
// which is both less useful and less likely to be acted on.
func VerifySeal(r *Report, s *Seal, k *mac.Key) error {
	switch {
	case s == nil:
		return fmt.Errorf("%w: there is no seal. An unsealed report is not a report that passed", ErrSealInvalid)
	case k == nil:
		return fmt.Errorf("%w: no key was supplied, so no tag can be checked; an unchecked tag is not a passed one", ErrSealInvalid)
	case s.Purpose != string(mac.PurposeReportBinding):
		// C-24's clause, refused before any tag is compared.
		return fmt.Errorf("%w: the seal claims purpose %q and a report is sealed under %q. "+
			"A record sealed in the store is a statement that something was written down, not that "+
			"anybody decided anything", ErrSealInvalid, s.Purpose, mac.PurposeReportBinding)
	case len(s.Items) != len(r.Outcomes):
		return fmt.Errorf("%w: the seal covers %d item(s) and the report has %d",
			ErrSealInvalid, len(s.Items), len(r.Outcomes))
	}

	if got := digestJSON("proposal-binding", r.Binding); got != s.Binding {
		return fmt.Errorf("%w: the report was decided under different inputs from the ones sealed", ErrSealInvalid)
	}

	msg := s.Binding
	for i, o := range r.Outcomes {
		want := ItemSeal{Host: itemIdentity(o), Digest: itemSubstance(o)}
		it := s.Items[i]
		switch {
		case it.Host != want.Host:
			return fmt.Errorf("%w: item %d is sealed for %q and the report carries %q",
				ErrSealInvalid, i, it.Host, want.Host)
		case it.Digest != want.Digest:
			return fmt.Errorf("%w: item %d (%s) has been changed since it was sealed",
				ErrSealInvalid, i, it.Host)
		case !mac.Equal(it.Tag, k.Tag(mac.PurposeReportBinding, itemSealMessage(want))):
			return fmt.Errorf("%w: item %d (%s) carries a tag this key did not make",
				ErrSealInvalid, i, it.Host)
		}
		msg += "\n" + it.Tag
	}

	if !mac.Equal(s.Tag, k.Tag(mac.PurposeReportBinding, msg)) {
		return fmt.Errorf("%w: the seal over the whole report does not match; items have been added, "+
			"removed or reordered", ErrSealInvalid)
	}
	return nil
}
