// SPDX-License-Identifier: AGPL-3.0-only

package rpz

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// # THE PINGA53 SNAPSHOT IS A SEPARATE FILE FROM ORDER 11's SnapshotFile
//
// ORDER 11 built the writer against a snapshot format keyed
// `schema_version`, with an `origin` field and no timestamp. It was designed
// for the offline in-process fake: the caller knew when the snapshot was
// produced because the caller made it.
//
// Pinga53's operator export is not that. It is written by
// scripts/pinga53-allowlist-export.py every 15 minutes and read by
// `scamwall rpz` an hour later, on a different clock, from disk. Two things
// change:
//
//   - `generated_at` becomes MANDATORY, because a snapshot the writer cannot
//     date is a snapshot the writer cannot refuse for being stale. On Pinga53
//     an RPZ entry overrides the household's own allowlist, so a run that
//     wrote a zone against a snapshot from before an allow entry the operator
//     added five minutes ago would unblockably block something the household
//     just decided to permit. The default max age is two hours: a run that
//     misses one export cycle survives; a run that misses eight does not.
//
//   - `source_sha256` becomes MANDATORY, so the exporter can prove the DB it
//     read had a fixed content, and so a truncated / half-written snapshot is
//     rejected at read time rather than turned into a zone. The Pinga53
//     exporter writes it atomically (temp + rename) precisely so this stays
//     honest end-to-end.
//
// Everything else — the cover / coverage / subscribed-list machinery — is
// the ORDER 11 machinery unchanged, reached by translating the Pinga53
// document into `SnapshotFile` and calling its `Snapshot()` method. A second
// translation of the same thing is a second place for it to be answered
// differently, and the direction the difference would fall in is "ScamWall
// thought the household had not allowed this".
//
// # REJECTION IS TOTAL
//
// The order says "Rejection = the zone writer freezes." That is exactly the
// design shape: any load failure returns an error, the caller does not get a
// `Snapshot`, and `Snapshot{}.Readable()` refuses. There is no partial mode,
// no "load what you can". A partial allowlist is worse than none: it means
// the writer would confidently emit a zone that overrides household allows
// it never saw.

// Pinga53SnapshotSchemaVersion is the document version this build reads.
const Pinga53SnapshotSchemaVersion = 1

// DefaultMaxPinga53SnapshotAge bounds how far behind the exporter the
// snapshot may be. Chosen at 2h so a run that misses one 15-minute export
// cycle still succeeds, but a run that has been idle for the better part of
// a day does not. The order pins this default.
const DefaultMaxPinga53SnapshotAge = 2 * time.Hour

// MaxPinga53SnapshotEntries caps the sum of exact + regex + subscribed
// entries. A snapshot with more is refused before the zone writer sees it.
// The current household lists are three orders of magnitude smaller than
// this; the cap is there to bound the damage from an exporter that decides
// to hand back the entire domainlist table.
const MaxPinga53SnapshotEntries = 100_000

// ErrPinga53SnapshotSchema, ErrPinga53SnapshotStale, ErrPinga53SnapshotOverCap
// and ErrPinga53SnapshotIntegrity are the four rejection sentinels the
// caller may match on. ErrSnapshotAbsent is reused from snapshot.go: an
// absent Pinga53 snapshot means the same thing.
var (
	// ErrPinga53SnapshotSchema is a document with a schema this build does
	// not read.
	ErrPinga53SnapshotSchema = errors.New("rpz: unsupported Pinga53 snapshot schema")
	// ErrPinga53SnapshotStale is a snapshot older than the caller's max age.
	ErrPinga53SnapshotStale = errors.New("rpz: Pinga53 snapshot older than max age")
	// ErrPinga53SnapshotOverCap is a snapshot whose entry sum exceeds
	// MaxPinga53SnapshotEntries.
	ErrPinga53SnapshotOverCap = errors.New("rpz: Pinga53 snapshot exceeds entry cap")
	// ErrPinga53SnapshotIntegrity is a source_sha256 that isn't a
	// well-formed hex sha256, or a generated_at that isn't RFC 3339. The
	// exporter writes both by machine, so a malformed field means the file
	// has been tampered with or truncated.
	ErrPinga53SnapshotIntegrity = errors.New("rpz: Pinga53 snapshot integrity field malformed")
)

// Pinga53SnapshotFile is the on-disk shape of what
// scripts/pinga53-allowlist-export.py writes.
type Pinga53SnapshotFile struct {
	// Schema pins the document version. Any value other than 1 is refused.
	Schema int `json:"schema"`
	// GeneratedAt is when the exporter finished reading gravity.db. RFC 3339.
	GeneratedAt time.Time `json:"generated_at"`
	// SourceSHA256 is the sha256 of the export's gravity.db bytes at read
	// time, hex-encoded lowercase. Not a validation of the allow entries;
	// it identifies WHICH DB was read.
	SourceSHA256 string `json:"source_sha256"`
	// ExactAllow, RegexAllow and SubscribedAllow are the household's
	// enabled allow entries and the domains of enabled allow-type
	// subscriptions.
	ExactAllow      []string `json:"exact_allow"`
	RegexAllow      []string `json:"regex_allow"`
	SubscribedAllow []string `json:"subscribed_allow"`
}

// LoadPinga53Snapshot reads and validates the operator's export at path,
// with the default clock (time.Now) and the default max age
// (DefaultMaxPinga53SnapshotAge).
func LoadPinga53Snapshot(path string) (Snapshot, error) {
	return LoadPinga53SnapshotAt(path, time.Now(), DefaultMaxPinga53SnapshotAge)
}

// LoadPinga53SnapshotAt is the injected-clock form used by tests. It also
// lets a caller with a different freshness target (e.g. a manual "load
// this old thing anyway" tool that this order does NOT ship) opt into a
// different max age explicitly.
//
// Argument order matches the natural sentence: "load the snapshot at
// this path, evaluated as of this clock, refusing anything older than
// this many seconds."
func LoadPinga53SnapshotAt(path string, now time.Time, maxAge time.Duration) (Snapshot, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrSnapshotAbsent, path)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("rpz: Pinga53 snapshot: %w", err)
	}
	if fi.Size() > MaxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("rpz: Pinga53 snapshot is %d bytes, over the %d-byte limit",
			fi.Size(), MaxSnapshotBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("rpz: Pinga53 snapshot: %w", err)
	}

	var f Pinga53SnapshotFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Snapshot{}, fmt.Errorf("rpz: Pinga53 snapshot: %w", err)
	}

	if f.Schema != Pinga53SnapshotSchemaVersion {
		return Snapshot{}, fmt.Errorf("%w: got %d, want %d", ErrPinga53SnapshotSchema,
			f.Schema, Pinga53SnapshotSchemaVersion)
	}
	if f.GeneratedAt.IsZero() {
		return Snapshot{}, fmt.Errorf("%w: generated_at is missing or the zero time",
			ErrPinga53SnapshotIntegrity)
	}
	if !isHexSHA256(f.SourceSHA256) {
		return Snapshot{}, fmt.Errorf("%w: source_sha256 is not a lowercase hex sha256",
			ErrPinga53SnapshotIntegrity)
	}

	// Staleness is answered against the CALLER's clock. `now.Before(genAt)`
	// (a future timestamp) is not a rejection here — the exporter and the
	// reader run on the same host, but a small clock skew is possible and
	// the meaningful failure is the OTHER direction.
	age := now.Sub(f.GeneratedAt)
	if age > maxAge {
		return Snapshot{}, fmt.Errorf("%w: generated_at %s is %s old, max is %s",
			ErrPinga53SnapshotStale, f.GeneratedAt.Format(time.RFC3339), age.Round(time.Second), maxAge)
	}

	sum := len(f.ExactAllow) + len(f.RegexAllow) + len(f.SubscribedAllow)
	if sum > MaxPinga53SnapshotEntries {
		return Snapshot{}, fmt.Errorf("%w: %d entries (exact=%d regex=%d subscribed=%d), max is %d",
			ErrPinga53SnapshotOverCap, sum, len(f.ExactAllow), len(f.RegexAllow), len(f.SubscribedAllow),
			MaxPinga53SnapshotEntries)
	}

	return f.toSnapshotFile().Snapshot(), nil
}

// toSnapshotFile translates a Pinga53 document into ORDER 11's SnapshotFile
// so the writer's cover/coverage/subscribed machinery is reached without
// being copied. `SubscribedRead` is TRUE: the Pinga53 exporter reads the
// enabled allow-type subscriptions explicitly (item 2), so an empty
// SubscribedAllow means "no allow-type subscription named this host", not
// "we did not check".
func (f Pinga53SnapshotFile) toSnapshotFile() SnapshotFile {
	origin := fmt.Sprintf("pinga53 export at %s (source_sha256=%s)",
		f.GeneratedAt.UTC().Format(time.RFC3339), shortHex(f.SourceSHA256))
	return SnapshotFile{
		SchemaVersion:   SnapshotSchemaVersion,
		Origin:          origin,
		ExactAllow:      f.ExactAllow,
		RegexAllow:      f.RegexAllow,
		SubscribedAllow: f.SubscribedAllow,
		SubscribedRead:  true,
	}
}

// isHexSHA256 returns true only for a 64-character lowercase hex string.
// The exporter writes the digest lowercase; a mixed-case value would still
// hex-decode, but the exporter never produces one, so accepting one would
// hide a class of tampering that leaves the value valid-looking.
func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	// hex.DecodeString gives us belt-and-braces: catches anything the char
	// scan missed (shouldn't, but the exporter is external code).
	_, err := hex.DecodeString(s)
	return err == nil
}

// shortHex returns the first 12 chars of a hex digest, or the whole string
// if it is shorter than that. Used only for the origin string that flows
// into the plan's account of its inputs.
func shortHex(s string) string {
	if len(s) >= 12 {
		return s[:12]
	}
	return s
}
