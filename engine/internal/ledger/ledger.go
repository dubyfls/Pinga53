// SPDX-License-Identifier: AGPL-3.0-only

// Package ledger is the record of what ScamWall itself has blocked.
//
// # WHY THIS PACKAGE EXISTS AT ALL
//
// Two finished controls had no caller before it. C-21 decides whether a block
// ScamWall placed has outlived its justification, and C-20's removal half
// decides how much of that one run may act on. Both take an OWNERSHIP LEDGER
// — the set of entries ScamWall can show it placed — and no build in this
// repository kept one, so `cmd/scamwall/shadow.go` passed
// shadow.NoOwnership{} explicitly and said so in its own comment. A rule with
// no caller protects nobody.
//
// # WHY A MISSING FILE IS NOT AN EMPTY LEDGER
//
// The same refusal internal/shadow makes about a partial read and
// internal/proposal makes about an unread journal. A ledger that failed to
// load and a household ScamWall has never blocked anything for produce the
// same empty slice and mean opposite things — and the difference is the
// difference between "propose no removals" and "propose removing everything".
// Load REFUSES a missing file. A caller that has no ledger says so by not
// passing one, and gets NoOwnership, which is a statement rather than a guess.
//
// proposal.AssessRemovals takes the same position from the other side: an
// ownership count of zero holds the run rather than permitting it.
//
// # WHAT IT IS NOT
//
// Not a journal. internal/journal answers "what has ScamWall said about this
// host over time"; this answers "what is ScamWall holding right now, since
// when, and on what". They have different lifetimes and different sizes, and
// a structure that tried to be both would be a bad journal with an unusable
// index — internal/journal's own package comment makes the same distinction
// against a log.
package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/atomicfile"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
)

// SchemaVersion is the only ledger version this build reads.
const SchemaVersion = 1

// MaxLedgerBytes bounds a ledger document on load, as internal/journal bounds
// its own.
const MaxLedgerBytes = 64 << 20

// Errors this package returns.
var (
	// ErrAbsent is a ledger file that is not there. Distinguished from every
	// other load failure because it is the one an operator answers by
	// deciding whether this installation has a ledger at all.
	ErrAbsent = errors.New("ledger: no ownership ledger at that path")
	// ErrSchema is a document that is not a ledger this build reads.
	ErrSchema = errors.New("ledger: unsupported schema version")
)

// Owned is one block ScamWall placed.
type Owned struct {
	Canonical string `json:"canonical"`
	// AddedAt is when ScamWall placed it.
	AddedAt time.Time `json:"added_at"`
	// LastJustifiedAt is when live evidence last supported it. Lifetime runs
	// from here and not from AddedAt: a domain that keeps being reported
	// should not be unblocked on its birthday. See proposal.OwnedEntry.
	LastJustifiedAt time.Time `json:"last_justified_at"`
	// Digest is the decision digest this block was placed on, as the RPZ
	// zone's per-entry comment carries it. Opaque and short; it names no
	// source, URL or feed.
	Digest string `json:"digest,omitempty"`
}

// Ledger is the whole record.
type Ledger struct {
	SchemaVersion int `json:"schema_version"`
	// Serial is the most recent RPZ zone serial, YYYYMMDDnn. Kept here
	// because it must be strictly increasing across runs and there is
	// nowhere else that survives one. Empty until a zone has been written.
	Serial string `json:"serial,omitempty"`
	// LastAcquisitionAt is when the evidence supply last delivered. Zero
	// means nothing has recorded one, which is NOT "just now": see
	// AcquisitionStale.
	LastAcquisitionAt time.Time `json:"last_acquisition_at,omitempty"`
	// Owned is sorted by canonical name, so two marshals of one ledger are
	// byte-identical and a ledger in version control diffs as the change it
	// records rather than as a reordering.
	Owned []Owned `json:"owned"`
	// Deferred is what a previous run decided to do and could not fit inside
	// its caps. It PERSISTS: a deferral is rationing, not a drop, and a
	// deferral that only ever lived in one run's output is a drop with better
	// wording. C-20.
	Deferred []proposal.DeferredItem `json:"deferred,omitempty"`
}

// New returns an empty ledger.
//
// An empty ledger is not the same as no ledger. This one knows it is holding
// nothing; Load refuses to invent one.
func New() *Ledger { return &Ledger{SchemaVersion: SchemaVersion} }

// Load reads a ledger.
func Load(path string) (*Ledger, error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("%w: %s. A ledger that is not there is not a ledger holding "+
			"nothing; if this installation has never blocked anything, say so by not passing one",
			ErrAbsent, path)
	case err != nil:
		return nil, fmt.Errorf("ledger: %w", err)
	case len(b) > MaxLedgerBytes:
		return nil, fmt.Errorf("ledger: document is %d bytes, over the %d-byte limit", len(b), MaxLedgerBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var l Ledger
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	if dec.More() {
		return nil, errors.New("ledger: unexpected trailing data")
	}
	if l.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSchema, l.SchemaVersion, SchemaVersion)
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	l.sort()
	return &l, nil
}

// validate refuses a ledger that cannot mean anything.
//
// A duplicate name is refused rather than merged: two rows for one host with
// two different LastJustifiedAt values make the lifetime rule answer
// differently depending on which one is read, and picking either would be
// this package deciding something the operator meant to state.
func (l *Ledger) validate() error {
	seen := make(map[string]bool, len(l.Owned))
	for _, o := range l.Owned {
		switch {
		case o.Canonical == "":
			return errors.New("ledger: an owned entry has no canonical name")
		case seen[o.Canonical]:
			return fmt.Errorf("ledger: %q appears twice. Two rows for one host make the lifetime "+
				"rule answer differently depending on which is read", o.Canonical)
		case o.AddedAt.IsZero():
			return fmt.Errorf("ledger: %q records no added_at. A block whose age is unknown cannot "+
				"be aged out, and a zero time would age it out immediately", o.Canonical)
		}
		seen[o.Canonical] = true
	}
	return nil
}

func (l *Ledger) sort() {
	sort.Slice(l.Owned, func(i, j int) bool { return l.Owned[i].Canonical < l.Owned[j].Canonical })
	sort.Slice(l.Deferred, func(i, j int) bool { return l.Deferred[i].Canonical < l.Deferred[j].Canonical })
}

// Count is how many entries ScamWall owns. C-20's abnormal-removal rule is a
// fraction of this rather than a fixed count.
func (l *Ledger) Count() int { return len(l.Owned) }

// Holds reports whether ScamWall owns this host.
func (l *Ledger) Holds(canonical string) bool {
	for _, o := range l.Owned {
		if o.Canonical == canonical {
			return true
		}
	}
	return false
}

// Entries renders the ledger in the shape C-21 reads.
func (l *Ledger) Entries() []proposal.OwnedEntry {
	out := make([]proposal.OwnedEntry, 0, len(l.Owned))
	for _, o := range l.Owned {
		out = append(out, proposal.OwnedEntry{
			Canonical:       o.Canonical,
			AddedAt:         o.AddedAt,
			LastJustifiedAt: o.LastJustifiedAt,
		})
	}
	return out
}

// OwnedNames is every held host, sorted.
func (l *Ledger) OwnedNames() []string {
	out := make([]string, 0, len(l.Owned))
	for _, o := range l.Owned {
		out = append(out, o.Canonical)
	}
	sort.Strings(out)
	return out
}

// AcquisitionStale reports whether the evidence supply has gone quiet for
// longer than maxAge, and why.
//
// A ZERO LastAcquisitionAt IS STALE, not fresh. The failure this prevents is
// the one a zero time always causes when it is read as "now": a ledger nobody
// has recorded an acquisition into would otherwise licence a full rewrite of
// the household's enforcement. maxAge of zero disables the measurement — an
// unset limit is not a zero one, which is C-10's rule and C-21's.
func (l *Ledger) AcquisitionStale(now time.Time, maxAge time.Duration) (bool, string) {
	if maxAge <= 0 {
		return false, ""
	}
	if l.LastAcquisitionAt.IsZero() {
		return true, "the ledger records no acquisition at all. A supply nobody has recorded is " +
			"not a supply that just delivered"
	}
	if age := now.Sub(l.LastAcquisitionAt); age > maxAge {
		return true, fmt.Sprintf("the last acquisition was %s ago, past the %s this run was given",
			age.Round(time.Minute), maxAge)
	}
	return false, ""
}

// Marshal renders the ledger.
//
// Indented, with entries sorted, so two marshals of one ledger are
// byte-identical and a save that changed nothing is a no-op in version
// control.
func (l *Ledger) Marshal() ([]byte, error) {
	l.SchemaVersion = SchemaVersion
	l.sort()
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	return append(b, '\n'), nil
}

// Save writes the ledger atomically.
//
// Writing in place leaves a truncated ledger behind if anything interrupts
// it, and a truncated ledger is an ownership record that has forgotten what
// ScamWall is holding — which is the input under which AssessRemovals holds
// the run, but only if the file parses at all. internal/atomicfile is where
// the sequence lives and where it is tested.
//
// Mode 0600: the ledger is the list of what this household blocks.
func (l *Ledger) Save(path string) error {
	b, err := l.Marshal()
	if err != nil {
		return err
	}
	if err := atomicfile.Write(path, b, 0o600); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	return nil
}
