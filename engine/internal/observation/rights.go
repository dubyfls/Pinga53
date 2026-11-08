// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"fmt"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// Rights is the outcome of asking whether an operation is permitted.
//
// It carries the refusals rather than just a boolean, because "no" without
// "which source, and why" cannot be acted on: the operator's next move is
// different depending on whether one provider prohibits redistribution, a
// condition is unassessed, or an id does not resolve at all.
type Rights struct {
	// Permitted is true only when every source consulted authorises the
	// operation. It is false whenever anything is refused, unknown, or
	// unresolvable.
	Permitted bool
	// Permitting lists the sources that authorise it.
	Permitting []string
	// Refusals explains every source that does not, in a stable order.
	Refusals []string
}

// Authorizes reports whether one source authorises one operation.
//
// Fail-closed in three directions, all of which are the same rule: an
// operation is permitted only when something establishes that it is.
//
//   - An id that does not resolve is refused. Not knowing whose data this is
//     is the strongest possible reason not to act on it.
//   - A retired id is refused, and is distinguished from an unknown one.
//   - Everything else is delegated to the registry's own Authorizes, which is
//     where `conditional`, `unknown` and `not_applicable` are already given
//     their meanings. Duplicating that logic here would create a second
//     answer to drift from the first.
func (o Observation) Authorizes(reg *sourceregistry.Registry, op sourceregistry.Operation) (bool, string) {
	if reg == nil {
		return false, fmt.Sprintf("%s: no source registry was supplied, so no grant can be read; an unread grant is refused", o.SourceID)
	}
	src, ok := reg.Source(o.SourceID)
	if !ok {
		if reg.Retired(o.SourceID) {
			return false, fmt.Sprintf("%s is retired; its records cannot authorise %s", o.SourceID, op)
		}
		return false, fmt.Sprintf("%s does not appear in the source registry; %s cannot be authorised by a source nobody can look up", o.SourceID, op)
	}
	ok, why := src.Authorizes(op)
	if ok {
		return true, ""
	}
	return false, fmt.Sprintf("%s: %s", o.SourceID, why)
}

// Authorizes reports whether an operation is permitted for a DERIVED result —
// anything computed from this indicator's observations.
//
// The rule is unanimity over live contributors, and it is the rule because
// derivation does not launder provenance. A blocklist computed from four feeds
// is still, in part, each of those four feeds; if one of them forbids
// redistribution then the derived list cannot be redistributed either, however
// much the other three permit.
//
// Expired and superseded observations are not consulted. They contributed
// nothing to a result computed at t, so requiring rights for them would refuse
// operations on grounds that no longer apply.
func (i Indicator) Authorizes(reg *sourceregistry.Registry, op sourceregistry.Operation, at time.Time) Rights {
	var r Rights
	current := i.Current(at)
	if len(current) == 0 {
		r.Refusals = append(r.Refusals, fmt.Sprintf("no live observation supports this indicator at %s, so there is nothing whose terms could permit %s",
			at.UTC().Format(time.RFC3339), op))
		return r
	}

	seen := map[string]bool{}
	for _, e := range current {
		id := e.Observation.SourceID
		if seen[id] {
			continue
		}
		seen[id] = true
		if ok, why := e.Observation.Authorizes(reg, op); ok {
			r.Permitting = append(r.Permitting, id)
		} else {
			r.Refusals = append(r.Refusals, why)
		}
	}

	sort.Strings(r.Permitting)
	sort.Strings(r.Refusals)
	r.Refusals = dedupe(r.Refusals)
	r.Permitted = len(r.Refusals) == 0 && len(r.Permitting) > 0
	return r
}

// Exportable reports whether this indicator may leave the household.
//
// It is a named question rather than a call to Authorizes with a constant,
// because it is the question that gets asked carelessly. A local blocklist and
// a published blocklist are different operations under most providers' terms,
// and a helper called Exportable is harder to use by accident than
// Authorizes(reg, "derived_output", now).
//
// Both grants are required: a derived output that is published is a
// redistribution of something, and a provider that permits one and not the
// other has said something specific that must not be averaged away.
func (i Indicator) Exportable(reg *sourceregistry.Registry, at time.Time) Rights {
	derived := i.Authorizes(reg, sourceregistry.OpDerivedOutput, at)
	redist := i.Authorizes(reg, sourceregistry.OpRedistribution, at)

	var r Rights
	r.Permitting = intersect(derived.Permitting, redist.Permitting)
	r.Refusals = append(append([]string(nil), derived.Refusals...), redist.Refusals...)
	sort.Strings(r.Refusals)
	r.Refusals = dedupe(r.Refusals)
	r.Permitted = derived.Permitted && redist.Permitted
	return r
}

// CommerciallyExportable reports whether this indicator may go into the PAID
// commercial feed.
//
// It is Exportable plus commercial_use, and the extra grant is the whole point.
// The free public list is published under non-commercial terms, so a provider
// whose licence permits non-commercial redistribution (abuse.ch and the
// Spamhaus free feeds, at the time of writing) can contribute to it. The paid
// feed is a commercial use of every source behind every entry, so an entry is
// eligible only when each live contributor also grants commercial_use. A source
// that is silent on commercial use refuses it, as every unestablished grant does.
//
// The free-list writer asks Exportable; the commercial-feed writer must ask
// this. Two named questions keep the paid tier from inheriting rights it was
// never given.
func (i Indicator) CommerciallyExportable(reg *sourceregistry.Registry, at time.Time) Rights {
	export := i.Exportable(reg, at)
	commercial := i.Authorizes(reg, sourceregistry.OpCommercialUse, at)

	var r Rights
	r.Permitting = intersect(export.Permitting, commercial.Permitting)
	r.Refusals = append(append([]string(nil), export.Refusals...), commercial.Refusals...)
	sort.Strings(r.Refusals)
	r.Refusals = dedupe(r.Refusals)
	r.Permitted = export.Permitted && commercial.Permitted
	return r
}

// UsableLocally reports whether the indicator may be held and consulted here.
//
// Separate from Exportable, and it is the separation that matters. The first
// version of the rights model required redistribution rights to perform a
// purely local lookup, which is a category error in the direction that refuses
// permitted work; asking the two questions with two functions is how that
// stays fixed.
func (i Indicator) UsableLocally(reg *sourceregistry.Registry, at time.Time) Rights {
	storage := i.Authorizes(reg, sourceregistry.OpLocalStorage, at)
	enrich := i.Authorizes(reg, sourceregistry.OpEnrichment, at)

	var r Rights
	r.Permitting = intersect(storage.Permitting, enrich.Permitting)
	r.Refusals = append(append([]string(nil), storage.Refusals...), enrich.Refusals...)
	sort.Strings(r.Refusals)
	r.Refusals = dedupe(r.Refusals)
	r.Permitted = storage.Permitted && enrich.Permitted
	return r
}

// RetentionPermitted reports whether keeping this observation's raw provider
// response is authorised.
//
// Retention is a local-storage operation and is checked as one.
//
// # WHERE THIS IS ENFORCED
//
// Store.Add calls it on every record, before anything is filed, and refuses
// with ErrRetentionRefused when it says no. That sentence is worth being
// precise about, because the superseded version of this comment claimed the
// question was "asked rather than assumed by the presence of the field" while
// nothing on the ingest path asked it. Demonstrated against that version:
//
//	Validate()              = <nil>
//	RetentionPermitted(nil) = false  (no registry, so no grant can be read)
//	Store.Add               -> outcome=new
//	IN THE TRUSTED STORE: raw="{\"provider\":\"verbatim response body\"}"
//
// A function that returns the right answer to a question nobody asks is not an
// enforcement point. Calling it from the one place every record must pass is.
//
// A record with no retained content is permitted trivially: there is nothing
// being kept, so there is no local-storage operation to authorise.
func (o Observation) RetentionPermitted(reg *sourceregistry.Registry) (bool, string) {
	if o.RawRetention != RetentionRetained {
		return true, ""
	}
	return o.Authorizes(reg, sourceregistry.OpLocalStorage)
}

// WithoutRaw returns a copy that keeps no raw provider content.
//
// # WHY THIS EXISTS RATHER THAN A STAGING STORE
//
// Validation sometimes needs the provider's own response, and the rights
// position may forbid keeping it. Those two facts together are the argument
// for a separate untrusted representation — but a second STORE holding refused
// records would be a bucket that grows from hostile input and that a later
// reader could mistake for evidence.
//
// The separation is therefore in the caller's own scope: hold the raw response
// in a local variable for as long as validation needs it, admit the record
// with WithoutRaw, and let the raw bytes go out of scope. What enters the
// trusted store then provably carries nothing the rights position forbids,
// and there is no second collection to audit, bound or accidentally trust.
//
// The observation is otherwise unchanged, so it remains the same record, the
// same revision of the same provider record, and the same evidence about who
// said what.
func (o Observation) WithoutRaw() Observation {
	c := o.clone()
	c.Raw = ""
	c.RawRetention = RetentionNone
	return c
}

func intersect(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range a {
		in[s] = true
	}
	var out []string
	for _, s := range b {
		if in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// RetractedBy returns the sources whose CURRENT standing on this indicator is
// an explicit withdrawal, and whose registry record permits op.
//
// # A RETRACTION IS NOT AN ABSENCE
//
// An expired observation is a source going quiet. A withdrawal is a source
// speaking, and what it says — "we were wrong about this" — contradicts the
// sources still asserting. Corroborate already keeps the two apart; this is
// what reads the distinction out.
//
// # WHY THE GRANT IS CHECKED
//
// A source whose grant does not permit its records being combined with others
// cannot be used to justify a block. It must not be usable to veto one
// either: rights cut both ways or they are not rights, and a source nobody
// may count is a source whose opinion this build has no standing to act on in
// either direction.
//
// window bounds how long a retraction goes on contradicting, measured from
// when ScamWall took the withdrawal in. Zero means unbounded, which is the
// conservative reading: a retraction that aged out would let a block resume
// with nobody having said anything new.
func (i Indicator) RetractedBy(reg *sourceregistry.Registry, op sourceregistry.Operation, at time.Time, window time.Duration) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range i.Entries {
		if e.Superseded || e.Observation.Status != StatusWithdrawn {
			continue
		}
		o := e.Observation
		if window > 0 && at.Sub(o.IngestedAt) > window {
			continue
		}
		if seen[o.SourceID] {
			continue
		}
		if ok, _ := o.Authorizes(reg, op); !ok {
			continue
		}
		seen[o.SourceID] = true
		out = append(out, o.SourceID)
	}
	sort.Strings(out)
	return out
}
