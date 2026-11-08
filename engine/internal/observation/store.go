// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// Outcome is what adding an observation did.
type Outcome string

// The outcomes of Add.
const (
	// OutcomeNew — a source record not previously held.
	OutcomeNew Outcome = "new"
	// OutcomeDuplicate — the same source record with the same content. The
	// store is unchanged, which is what makes re-ingestion idempotent.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeCorrection — the same source record with different content. The
	// earlier revision is retained and marked superseded; a correction changes
	// what is current and must not erase what was previously reported.
	OutcomeCorrection Outcome = "correction"
)

// Entry is one observation plus its standing within the store.
type Entry struct {
	Observation Observation
	// Revision counts from 0 for the first observation received for a source
	// record.
	Revision int
	// Superseded is true when a later revision replaced this one. Superseded
	// entries are kept and are returned by History.
	Superseded bool
	// sequence is the store-wide ingestion order, used only to break ties
	// deterministically. It is not exported: it is an implementation detail of
	// ordering, not a fact about the observation.
	sequence int
}

// Indicator is every observation the store holds for one canonical value.
type Indicator struct {
	Key     Key
	Entries []Entry
}

// Store holds observations, keyed by indicator.
//
// It is not safe for concurrent use. Callers that need concurrency own the
// lock, because a lock inside here would make Add look atomic across an
// indicator when it is not.
type Store struct {
	byKey map[Key]*Indicator
	// byRecord indexes provider records GLOBALLY within a source, across
	// indicators. See providerRecord and Add.
	byRecord map[providerRecord]entryRef
	// reg is the rights authority consulted at the boundary. Nil means no
	// authority, which refuses retention rather than permitting it.
	reg  *sourceregistry.Registry
	next int
}

// providerRecord is the identity of one record a provider published.
//
// # WHY A STRUCT AND NOT A JOINED STRING
//
// The superseded implementation joined the two fields with a NUL byte:
//
//	SourceID "src-A\x00rec", SourceRecordID "1"   -> "src-A\x00rec\x001"
//	SourceID "src-A",        SourceRecordID "rec\x001" -> "src-A\x00rec\x001"
//
// Two different provider records with the same key. SourceID is validated
// only for emptiness, so a NUL in it is reachable, and the consequence is that
// one provider's record silently supersedes another's. A struct key has no
// field boundary to forge: Go compares the fields, not a concatenation.
type providerRecord struct {
	SourceID       string
	SourceRecordID string
}

// entryRef locates one entry. Entries are only ever appended and marked, never
// removed or reordered in place, so an index stays valid for the store's life.
type entryRef struct {
	Key   Key
	Index int
}

// NewStore returns an empty store with NO rights authority.
//
// Such a store refuses every record that carries retained raw provider
// content, because there is nothing present that could establish the right to
// keep it. That is the fail-closed direction: a store that cannot read a grant
// does not get to assume one. Use NewStoreWithRights to supply the registry.
func NewStore() *Store {
	return &Store{
		byKey:    map[Key]*Indicator{},
		byRecord: map[providerRecord]entryRef{},
	}
}

// NewStoreWithRights returns an empty store that enforces retention rights
// against reg.
//
// A nil registry is accepted and behaves exactly like NewStore: it is not an
// error to have no registry, it is simply a reason to refuse retention.
func NewStoreWithRights(reg *sourceregistry.Registry) *Store {
	s := NewStore()
	s.reg = reg
	return s
}

// Add validates and files one observation.
//
// It never merges. An observation that agrees with one already held is still
// stored as its own entry unless it is literally the same source record
// saying the same thing, in which case storing it again would manufacture
// corroboration out of one statement made twice.
func (s *Store) Add(o Observation) (Outcome, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	// THE RIGHTS GATE. Asked here, at the transition into trusted retained
	// state, because this is the only place every record must pass. See
	// FINDING-102: RetentionPermitted existed and documented itself as the
	// question that gets asked, and no code on the ingest path asked it.
	if ok, why := o.RetentionPermitted(s.reg); !ok {
		return "", fmt.Errorf("%w: %s", ErrRetentionRefused, why)
	}
	o = o.clone()

	k := o.Key()
	ind, ok := s.byKey[k]
	if !ok {
		ind = &Indicator{Key: k}
		s.byKey[k] = ind
	}

	// --- records the provider identifies: global within the source ---
	if o.SourceRecordID != "" {
		pr := providerRecord{SourceID: o.SourceID, SourceRecordID: o.SourceRecordID}
		if ref, held := s.byRecord[pr]; held {
			prev := &s.byKey[ref.Key].Entries[ref.Index]
			if ref.Key == k && prev.Observation.sameContent(o) {
				return OutcomeDuplicate, nil
			}
			// Marked BEFORE the append below. When ref.Key == k, prev points
			// into the very slice that append may reallocate; writing through
			// it first means the flag is copied into the new array rather
			// than lost with the old one.
			prev.Superseded = true
			revision := prev.Revision + 1

			s.next++
			ind.Entries = append(ind.Entries, Entry{
				Observation: o,
				Revision:    revision,
				sequence:    s.next,
			})
			s.byRecord[pr] = entryRef{Key: k, Index: len(ind.Entries) - 1}
			return OutcomeCorrection, nil
		}

		s.next++
		ind.Entries = append(ind.Entries, Entry{Observation: o, sequence: s.next})
		s.byRecord[pr] = entryRef{Key: k, Index: len(ind.Entries) - 1}
		return OutcomeNew, nil
	}

	// --- records the provider does not identify: per source, per indicator ---
	//
	// Without a record id there is no cross-indicator identity to follow, so
	// the scope is the indicator. Indexing these globally would be actively
	// wrong: a source that legitimately reports twenty different domains would
	// have each report supersede the last, leaving one live observation out of
	// twenty. The cost of this narrower scope is stated in the Add doc above.
	latest := -1
	for i := range ind.Entries {
		e := &ind.Entries[i]
		if e.Superseded || e.Observation.SourceID != o.SourceID || e.Observation.SourceRecordID != "" {
			continue
		}
		latest = i
	}

	if latest >= 0 {
		if ind.Entries[latest].Observation.sameContent(o) {
			return OutcomeDuplicate, nil
		}
		ind.Entries[latest].Superseded = true
		s.next++
		ind.Entries = append(ind.Entries, Entry{
			Observation: o,
			Revision:    ind.Entries[latest].Revision + 1,
			sequence:    s.next,
		})
		return OutcomeCorrection, nil
	}

	s.next++
	ind.Entries = append(ind.Entries, Entry{Observation: o, sequence: s.next})
	return OutcomeNew, nil
}

// Indicators returns every indicator, in a deterministic order.
//
// Order is by (type, canonical value), and entries within an indicator are
// ordered by (source id, source record id, revision). Ingestion order is used
// for nothing except breaking a tie that cannot otherwise occur, so two stores
// built from the same observations in different orders are byte-identical.
func (s *Store) Indicators() []Indicator {
	out := make([]Indicator, 0, len(s.byKey))
	for _, ind := range s.byKey {
		c := Indicator{Key: ind.Key, Entries: cloneEntries(ind.Entries)}
		sortEntries(c.Entries)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key.Type != out[j].Key.Type {
			return out[i].Key.Type < out[j].Key.Type
		}
		return out[i].Key.Canonical < out[j].Key.Canonical
	})
	return out
}

// Lookup returns one indicator.
func (s *Store) Lookup(k Key) (Indicator, bool) {
	ind, ok := s.byKey[k]
	if !ok {
		return Indicator{}, false
	}
	c := Indicator{Key: ind.Key, Entries: cloneEntries(ind.Entries)}
	sortEntries(c.Entries)
	return c, true
}

// Len returns the number of distinct indicators.
func (s *Store) Len() int { return len(s.byKey) }

// cloneEntries copies entries so that a reader cannot reach the store's own
// observations. See Observation.clone.
func cloneEntries(es []Entry) []Entry {
	out := make([]Entry, len(es))
	for i, e := range es {
		out[i] = e
		out[i].Observation = e.Observation.clone()
	}
	return out
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		a, b := es[i].Observation, es[j].Observation
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		if a.SourceRecordID != b.SourceRecordID {
			return a.SourceRecordID < b.SourceRecordID
		}
		if es[i].Revision != es[j].Revision {
			return es[i].Revision < es[j].Revision
		}
		return es[i].sequence < es[j].sequence
	})
}

// Current returns the entries that are neither superseded nor expired at t.
//
// Expiry is applied here rather than at ingestion. An observation that has
// passed its expiry is still evidence that the source once said something, and
// deleting it would make "nobody ever reported this" and "somebody reported it
// and it lapsed" look the same.
func (i Indicator) Current(at time.Time) []Entry {
	var out []Entry
	for _, e := range i.Entries {
		if !e.Superseded && e.Observation.Live(at) {
			out = append(out, e)
		}
	}
	return out
}

// History returns every entry the indicator has ever held, current, superseded
// and expired alike, in the same deterministic order.
func (i Indicator) History() []Entry { return cloneEntries(i.Entries) }

// Superseded returns the entries a later revision replaced.
func (i Indicator) Superseded() []Entry {
	var out []Entry
	for _, e := range i.Entries {
		if e.Superseded {
			out = append(out, e)
		}
	}
	return out
}

// Expired returns entries that are current revisions but past their expiry.
func (i Indicator) Expired(at time.Time) []Entry {
	var out []Entry
	for _, e := range i.Entries {
		if !e.Superseded && e.Observation.Expired(at) {
			out = append(out, e)
		}
	}
	return out
}

// Classifications returns the classification each source currently asserts.
//
// Conflicts are RETAINED, not resolved. If one source says malicious and
// another says benign, this returns both, and the caller has to decide what to
// do with a disagreement rather than being handed a winner chosen by whichever
// record happened to arrive second.
func (i Indicator) Classifications(at time.Time) map[Classification][]string {
	out := map[Classification][]string{}
	for _, e := range i.Current(at) {
		c := e.Observation.Classification
		out[c] = append(out[c], e.Observation.SourceID)
	}
	for c := range out {
		sort.Strings(out[c])
	}
	return out
}

// Conflicted reports whether current sources disagree about what this is.
//
// Disagreement is defined as an asserted classification alongside a
// contradictory one. `unknown` is not a contradiction of anything: a source
// that declines to classify is not disputing a source that does.
func (i Indicator) Conflicted(at time.Time) bool {
	byClass := i.Classifications(at)
	adverse := len(byClass[ClassMalicious]) > 0 || len(byClass[ClassSuspicious]) > 0
	return adverse && len(byClass[ClassBenign]) > 0
}

// observationDigest renders an observation as a stable string and hashes it.
//
// Every field a consumer can see is included, so that any change to any of
// them is a correction rather than a silently-accepted rewrite. The rendering
// is explicit rather than reflective: a field added to the struct and not
// added here would be invisible to change detection, and a test asserts that
// cannot happen.
func observationDigest(o Observation) string {
	var b strings.Builder
	// LENGTH-PREFIXED, not delimiter-separated.
	//
	// The superseded encoding wrote key \x1f value \x1e and joined references
	// with \x1d and \x1c. Every one of those delimiters appears inside fields
	// the PROVIDER controls, so a field boundary could be forged. Demonstrated:
	//
	//	A: References = [{URL: "u\x1dn", Note: ""}]
	//	B: References = [{URL: "u",      Note: "n\x1d"}]
	//
	// Two different reference sets, byte-identical encodings, one digest. A
	// digest whose boundaries can be moved by its own input is not an identity;
	// it is a suggestion. Writing the byte LENGTH before each value removes
	// the question: no content can extend a field past its declared length.
	w := func(k, v string) {
		fmt.Fprintf(&b, "%s:%d:%s", k, len(v), v)
	}

	w("type", string(o.Type))
	w("canonical", o.Canonical)
	w("observed_value", o.ObservedValue)
	sigs := make([]string, len(o.Signals))
	for i, s := range o.Signals {
		sigs[i] = string(s)
	}
	sort.Strings(sigs)
	w("signals_count", strconv.Itoa(len(sigs)))
	for i, s := range sigs {
		w("signal_"+strconv.Itoa(i), s)
	}
	w("source_id", o.SourceID)
	w("source_record_id", o.SourceRecordID)
	w("source_first_seen", renderTime(o.SourceFirstSeen))
	w("source_last_seen", renderTime(o.SourceLastSeen))
	w("ingested_at", o.IngestedAt.UTC().Format(time.RFC3339Nano))
	w("expires_at", renderTime(o.ExpiresAt))
	w("provider_classification", o.ProviderClassification)
	w("classification", string(o.Classification))
	// Presence is its own field rather than a magic value. The superseded
	// encoding wrote the sentinel "\x00absent" into the same slot the real
	// value uses, so "the provider published nothing" and "the provider
	// published that exact string" were the same bytes. Scale and value are
	// separate fields for the same reason: joining them with "=" put a
	// boundary inside a provider-controlled string.
	w("provider_confidence_present", strconv.FormatBool(o.ProviderConfidence != nil))
	if o.ProviderConfidence != nil {
		w("provider_confidence_scale", o.ProviderConfidence.Scale)
		w("provider_confidence_value", strconv.FormatFloat(o.ProviderConfidence.Value, 'g', -1, 64))
	}
	w("report_count_present", strconv.FormatBool(o.ReportCount != nil))
	if o.ReportCount != nil {
		w("report_count", strconv.Itoa(*o.ReportCount))
	}
	w("state", string(o.State))
	w("category", o.Category)
	w("status", string(o.Status))
	// Each reference is itself length-prefixed, for the same reason, and the
	// encoded forms are sorted so that ordering is not part of identity.
	refs := make([]string, len(o.References))
	for i, r := range o.References {
		refs[i] = fmt.Sprintf("%d:%s%d:%s", len(r.URL), r.URL, len(r.Note), r.Note)
	}
	sort.Strings(refs)
	w("references_count", strconv.Itoa(len(refs)))
	for i, r := range refs {
		w("reference_"+strconv.Itoa(i), r)
	}
	w("raw_retention", string(o.RawRetention))
	w("raw", o.Raw)

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// renderTime distinguishes an absent timestamp from every present one.
//
// The sentinel is not a time. Rendering nil as the zero time would make an
// observation with no first-seen date digest identically to one first seen in
// year 1, and those are different records.
func renderTime(t *time.Time) string {
	if t == nil {
		return "\x00absent"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// Digest returns a stable digest of the whole store.
//
// It covers every entry, current and superseded, so that a report claiming to
// describe a store can be tied to the store it described.
func (s *Store) Digest() string {
	var b strings.Builder
	// Length-prefixed throughout, for the reason observationDigest gives. The
	// version is v2 because the encoding changed: a v1 digest and a v2 digest
	// of the same store are different strings, and silently reusing the label
	// would make two incomparable values look like a disagreement about the
	// data rather than about the encoding.
	lp := func(s string) { fmt.Fprintf(&b, "%d:%s", len(s), s) }
	fmt.Fprintf(&b, "indicators:%d:", len(s.byKey))
	for _, ind := range s.Indicators() {
		lp(string(ind.Key.Type))
		lp(ind.Key.Canonical)
		fmt.Fprintf(&b, "entries:%d:", len(ind.Entries))
		for _, e := range ind.Entries {
			fmt.Fprintf(&b, "%d:%t:", e.Revision, e.Superseded)
			lp(observationDigest(e.Observation))
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "scamwall-observations-v2:" + hex.EncodeToString(sum[:])
}
