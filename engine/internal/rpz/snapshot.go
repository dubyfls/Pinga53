// SPDX-License-Identifier: AGPL-3.0-only

package rpz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/dubyfls/Pinga53/engine/internal/policy"
	"github.com/dubyfls/Pinga53/engine/internal/shadow"
)

// # WHY THE SNAPSHOT ARRIVES AS A FILE AND NOT AS A LIVE READ
//
// ORDER 11 §4.2 says the snapshot is "populated only from the in-process
// fake" in this order, and §0 forbids contacting the household's appliance.
// Taken literally that leaves `scamwall rpz` unable to produce a zone at all,
// which would make §4.5's "exit 0, written" unreachable from `cmd/` and A2
// unverifiable. A file is the reading that keeps both rules: it is offline,
// it is the operator's own export, and it is the same shape the live read in
// ORDER 12 will produce. Recorded as an owner question.
//
// # A SNAPSHOT THAT DOES NOT SAY IT WAS READ IS NOT READ
//
// `subscribed_read` defaults to FALSE and an absent file is not an empty one.
// Both produce a freeze rather than a zone, for internal/shadow's reason: a
// run that never read the lists and a household with no entries produce the
// same empty slice and mean opposite things.

// SnapshotSchemaVersion is the document version this build reads.
const SnapshotSchemaVersion = 1

// MaxSnapshotBytes bounds the document.
const MaxSnapshotBytes = 8 << 20

var (
	// ErrSnapshotAbsent is a snapshot file that is not there.
	ErrSnapshotAbsent = errors.New("rpz: no allow-list snapshot at that path")
	// ErrSnapshotSchema is a document this build does not read.
	ErrSnapshotSchema = errors.New("rpz: unsupported allow-list snapshot schema")
)

// SnapshotFile is the operator's export of what the household allows.
type SnapshotFile struct {
	SchemaVersion int `json:"schema_version"`
	// Origin is free text describing where the export came from and when. It
	// travels into the plan's account of its own inputs and nowhere near the
	// zone file.
	Origin string `json:"origin,omitempty"`
	// ExactAllow and RegexAllow are the household's own allow entries.
	ExactAllow []string `json:"exact_allow"`
	RegexAllow []string `json:"regex_allow"`
	// SubscribedAllow is the third kind: hosts covered by an allowlist the
	// household subscribed to.
	SubscribedAllow []string `json:"subscribed_allow"`
	// SubscribedRead says whether the subscribed lists were consulted at all.
	// FALSE BY DEFAULT: see the package note above.
	SubscribedRead bool `json:"subscribed_read"`
}

// LoadSnapshot reads an allow-list snapshot.
func LoadSnapshot(path string) (Snapshot, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrSnapshotAbsent, path)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("rpz: allow-list snapshot: %w", err)
	}
	if fi.Size() > MaxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("rpz: the allow-list snapshot is %d bytes, over the %d-byte limit",
			fi.Size(), MaxSnapshotBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("rpz: allow-list snapshot: %w", err)
	}

	var f SnapshotFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Snapshot{}, fmt.Errorf("rpz: allow-list snapshot: %w", err)
	}
	if f.SchemaVersion != SnapshotSchemaVersion {
		return Snapshot{}, fmt.Errorf("%w: got %d, want %d", ErrSnapshotSchema,
			f.SchemaVersion, SnapshotSchemaVersion)
	}
	return f.Snapshot(), nil
}

// Snapshot expresses the document as the two interfaces the writer takes.
//
// Coverage is answered by internal/policy.CoverAllow, which is where the
// POSIX-versus-RE2 question lives. A second copy of that answer here would be
// a second place for it to be answered differently, and the direction the
// difference would fall in is "ScamWall thought the household had not allowed
// this".
func (f SnapshotFile) Snapshot() Snapshot {
	exact, regexes := f.ExactAllow, f.RegexAllow
	cover := func(host string) policy.Coverage { return policy.CoverAllow(host, exact, regexes) }

	// Measured once, over a name no household uses, because Unevaluable is a
	// property of the PATTERNS and not of the host being asked about.
	unevaluable := cover("unevaluable-probe.invalid").Unevaluable

	allow := shadow.ObservedAllowList{
		CoverKind:    func(d string) (bool, bool) { c := cover(d); return c.ExactMatch, c.RegexMatch },
		Covers:       func(d string) bool { c := cover(d); return c.ExactMatch || c.RegexMatch },
		Exact:        len(exact),
		Regex:        len(regexes),
		NotEvaluable: unevaluable,
		Origin:       f.Origin,
	}

	var subscribed shadow.SubscribedLists = shadow.SubscribedNotRead{}
	if f.SubscribedRead {
		set := make(map[string]bool, len(f.SubscribedAllow))
		for _, h := range f.SubscribedAllow {
			set[h] = true
		}
		subscribed = subscribedSnapshot{allow: set, origin: f.Origin}
	}
	return Snapshot{Allow: allow, Subscribed: subscribed}
}

// subscribedSnapshot answers membership from an export.
//
// It answers No rather than Unknown for a host it does not hold, which is
// only honest because Read() is true: the export is a statement about the
// WHOLE subscribed set, so a host absent from it is a host the lists do not
// cover. shadow.SubscribedNotRead is what an unread run uses, and it answers
// Unknown for everything.
type subscribedSnapshot struct {
	allow  map[string]bool
	origin string
}

func (s subscribedSnapshot) Membership(d string) (shadow.Tristate, shadow.Tristate) {
	if s.allow[d] {
		return shadow.Yes, shadow.No
	}
	return shadow.No, shadow.No
}

func (s subscribedSnapshot) Read() bool { return true }

func (s subscribedSnapshot) Source() string {
	if s.origin != "" {
		return "subscribed-list export: " + s.origin
	}
	return fmt.Sprintf("subscribed-list export naming %d allowed host(s)", len(s.allow))
}
