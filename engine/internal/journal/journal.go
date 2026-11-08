// SPDX-License-Identifier: AGPL-3.0-only

// Package journal records what ScamWall's runs have decided about a host, so
// that a later run can tell what changed and a person can tell what happened.
//
// # THREE RULES THAT PULL AGAINST EACH OTHER
//
// Journal only on SUBSTANTIVE change. A run reaching the same conclusion as
// the last one has nothing new to say, and a journal that appends a revision
// every run is a log file with a schema: it grows without bound and the one
// line that matters is invisible in it.
//
// A previously journalled host STAYS journalled. "Nothing changed" must never
// become "this host is gone" — the whole point is that a host ScamWall has
// ever acted on can be found afterwards.
//
// The LAST-BLOCK TIME is kept and moves on every blocking run, substantive or
// not. C-21 measures a block's lifetime from when it was last justified, and
// there is nowhere else to read it. A block re-justified every hour would
// otherwise look a week stale.
//
// # WHAT IT IS NOT
//
// Not a log. A log answers "what happened at 03:14"; this answers "what does
// ScamWall currently say about this host, and when did that last change". The
// two want different retention, different formats and different sizes, and a
// structure that tried to be both would be a bad log with an unusable index.
package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"os"

	"github.com/dubyfls/Pinga53/engine/internal/atomicfile"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"time"
)

// SchemaVersion is the only journal version this build reads.
const SchemaVersion = 1

// MaxJournalBytes bounds a journal document on load.
const MaxJournalBytes = 64 << 20

// ErrNoObservedState is C-23: a run that did not read the appliance may not
// journal what it would have done to it.
var ErrNoObservedState = errors.New("journal: this run recorded no observed appliance state")

// ErrSchema is a document that is not a journal this build reads.
var ErrSchema = errors.New("journal: unsupported schema version")

// Item is one host's outcome in one run.
type Item struct {
	Canonical string
	// Substance is the part of the outcome a CHANGE is measured over.
	//
	// The caller chooses it, and the choice is the control: put a timestamp
	// or a run id in it and every run is substantive, put too little in it
	// and a real change goes unrecorded. It is a string rather than a struct
	// so that this package cannot quietly acquire an opinion about what
	// matters in somebody else's decision.
	Substance string
	// Blocked is whether this run would have had the host blocked.
	Blocked bool
}

// Revision is one substantive statement about a host.
type Revision struct {
	At        time.Time `json:"at"`
	Substance string    `json:"substance"`
	Blocked   bool      `json:"blocked"`
	// ObservedDigest binds the revision to the appliance state the run read.
	// See C-23: a revision that cannot say what it was looking at is a
	// revision about nothing.
	ObservedDigest string `json:"observed_digest"`
}

// Entry is everything the journal holds about one host.
type Entry struct {
	Canonical string `json:"canonical"`
	// FirstJournalledAt never moves. It is what "previously journalled"
	// means.
	FirstJournalledAt time.Time `json:"first_journalled_at"`
	// LastSeenAt is the most recent run that said anything about this host,
	// substantive or not.
	LastSeenAt time.Time `json:"last_seen_at"`
	// LastBlockAt is the most recent run that would have had it blocked.
	// Zero if there has never been one.
	LastBlockAt time.Time `json:"last_block_at,omitempty"`
	// Revisions is how many substantive statements stand. Derived from
	// History and carried so a reader does not have to count.
	Revisions int        `json:"revisions"`
	History   []Revision `json:"history"`
}

// Journal is the whole record.
type Journal struct {
	SchemaVersion int `json:"schema_version"`
	// Entries are sorted by canonical name, so two marshals of one journal
	// are byte-identical and a journal in version control diffs as the change
	// it records rather than as a reordering.
	Entries []Entry `json:"entries"`
}

// New returns an empty journal.
//
// An empty journal is not the same as no journal, and the difference is the
// whole of C-20's DayLedger.Known: this one KNOWS the day is empty.
func New() *Journal { return &Journal{SchemaVersion: SchemaVersion} }

// RunInput is one run's statement.
type RunInput struct {
	At time.Time
	// Observed is whether this run read the appliance. C-23.
	Observed bool
	// ObservedDigest identifies what it read.
	ObservedDigest string
	Items          []Item
}

// Result is what Record did.
type Result struct {
	// Appended is how many revisions were written. Zero is the ordinary
	// outcome of a run that changed nothing.
	Appended int
	// NewHosts is how many hosts appear in the journal for the first time.
	NewHosts int
}

// index finds an entry by canonical name.
func (j *Journal) index(canonical string) int {
	i := sort.SearchStrings(j.names(), canonical)
	if i < len(j.Entries) && j.Entries[i].Canonical == canonical {
		return i
	}
	return -1
}

func (j *Journal) names() []string {
	out := make([]string, len(j.Entries))
	for i, e := range j.Entries {
		out[i] = e.Canonical
	}
	return out
}

// Entry returns what the journal holds about one host.
func (j *Journal) Entry(canonical string) (Entry, bool) {
	if i := j.index(canonical); i >= 0 {
		return j.Entries[i], true
	}
	return Entry{}, false
}

// Revisions is how many substantive statements stand for one host.
func (j *Journal) Revisions(canonical string) int {
	e, _ := j.Entry(canonical)
	return e.Revisions
}

// Record writes one run's statement into the journal.
//
// It REFUSES when the run recorded no observed appliance state (C-23). The
// refusal is total: nothing is written, not even for the hosts whose outcome
// needed no appliance to decide, because a journal half-written under a rule
// that says it should not have been written at all is worse than none.
func (j *Journal) Record(in RunInput) (Result, error) {
	if !in.Observed || in.ObservedDigest == "" {
		return Result{}, fmt.Errorf("%w: a run that did not read the appliance cannot record what "+
			"it would have changed there", ErrNoObservedState)
	}

	var res Result
	for _, it := range in.Items {
		if it.Canonical == "" {
			continue
		}
		i := j.index(it.Canonical)
		if i < 0 {
			e := Entry{
				Canonical:         it.Canonical,
				FirstJournalledAt: in.At,
				LastSeenAt:        in.At,
				Revisions:         1,
				History: []Revision{{
					At: in.At, Substance: it.Substance, Blocked: it.Blocked,
					ObservedDigest: in.ObservedDigest,
				}},
			}
			if it.Blocked {
				e.LastBlockAt = in.At
			}
			j.Entries = append(j.Entries, e)
			sort.Slice(j.Entries, func(a, b int) bool { return j.Entries[a].Canonical < j.Entries[b].Canonical })
			res.Appended++
			res.NewHosts++
			continue
		}

		e := &j.Entries[i]
		e.LastSeenAt = in.At
		if it.Blocked {
			// Moves whether or not the substance changed. See the package
			// comment: a block re-justified every hour would otherwise look a
			// week stale.
			e.LastBlockAt = in.At
		}
		if last := e.History[len(e.History)-1]; last.Substance == it.Substance && last.Blocked == it.Blocked {
			continue
		}
		e.History = append(e.History, Revision{
			At: in.At, Substance: it.Substance, Blocked: it.Blocked,
			ObservedDigest: in.ObservedDigest,
		})
		e.Revisions = len(e.History)
		res.Appended++
	}
	return res, nil
}

// DayLedger is what one UTC day's runs did, in the shape C-20 reads.
//
// Known is true for every ledger this package returns, INCLUDING an empty
// one. "No journal" and "a journal that says nothing happened today" are
// different facts, and C-20's daily cap is enforcement in name only when it
// cannot tell them apart.
type DayLedger struct {
	Known     bool
	Day       time.Time
	Additions int
	Removals  int
}

// Day summarises the UTC day containing t.
func (j *Journal) Day(t time.Time) DayLedger {
	start := t.UTC().Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour)
	l := DayLedger{Known: true, Day: start}
	for _, e := range j.Entries {
		for _, r := range e.History {
			u := r.At.UTC()
			if u.Before(start) || !u.Before(end) {
				continue
			}
			if r.Blocked {
				l.Additions++
			} else if len(e.History) > 1 {
				// A first revision that is not a block is not a removal; it
				// is a host the journal has started following. Only a
				// TRANSITION away from blocked is a removal.
				l.Removals++
			}
		}
	}
	return l
}

// Marshal renders the journal.
//
// Indented, with entries sorted and history in run order, so two marshals of
// one journal are byte-identical.
func (j *Journal) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(j); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Unmarshal reads a journal, refusing unknown fields and the wrong version.
func Unmarshal(b []byte) (*Journal, error) {
	if len(b) > MaxJournalBytes {
		return nil, fmt.Errorf("journal: document is %d bytes, over the %d-byte limit", len(b), MaxJournalBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j Journal
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	if dec.More() {
		return nil, errors.New("journal: unexpected trailing data")
	}
	if j.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSchema, j.SchemaVersion, SchemaVersion)
	}
	sort.Slice(j.Entries, func(a, b int) bool { return j.Entries[a].Canonical < j.Entries[b].Canonical })
	return &j, nil
}

// Seal binds the journal under mac.PurposeStoreBinding.
//
// The purpose is the point. A journal entry is a record that something was
// WRITTEN DOWN; a report is a record that something was DECIDED. C-24 requires
// that the first is never accepted as the second, and a tag under this purpose
// is a different tag from one under mac.PurposeReportBinding over the same
// bytes — so the separation holds even if somebody rewrites the label.
//
// A nil key returns the empty string. There is no unkeyed seal: a digest
// anybody can recompute proves the file has not been corrupted and proves
// nothing about who wrote it.
func (j *Journal) Seal(k *mac.Key) string {
	b, err := j.Marshal()
	if err != nil {
		return ""
	}
	return k.Tag(mac.PurposeStoreBinding, string(b))
}

// VerifySeal checks a journal against a seal made by Seal.
func (j *Journal) VerifySeal(seal string, k *mac.Key) error {
	switch {
	case seal == "":
		return errors.New("journal: there is no seal; an unsealed journal is not a journal that passed")
	case k == nil:
		return errors.New("journal: no key was supplied, so no tag can be checked")
	}
	if !mac.Equal(seal, j.Seal(k)) {
		return errors.New("journal: the journal does not match its seal")
	}
	return nil
}

// ErrAbsent is a journal file that is not there.
//
// Distinguished from every other load failure, and NOT treated as an empty
// journal by this package: LoadFile returns it, and the caller decides. The
// distinction is C-20's DayLedger.Known in file form — "no journal" and "a
// journal that says nothing happened today" are different facts, and the
// daily cap is enforcement in name only when it cannot tell them apart.
//
// A caller starting a household's first journal answers it with New(). A
// caller that expected one and found none has an operator problem, not an
// empty day.
var ErrAbsent = errors.New("journal: no journal at that path")

// LoadFile reads a journal from disk.
func LoadFile(path string) (*Journal, error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("%w: %s", ErrAbsent, path)
	case err != nil:
		return nil, fmt.Errorf("journal: %w", err)
	}
	return Unmarshal(b)
}

// SaveFile writes the journal atomically.
//
// Mode 0600: a journal is the record of what ScamWall has decided about the
// household's hosts, which is the same class of information as the ledger.
func (j *Journal) SaveFile(path string) error {
	b, err := j.Marshal()
	if err != nil {
		return err
	}
	if err := atomicfile.Write(path, b, 0o600); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return nil
}
