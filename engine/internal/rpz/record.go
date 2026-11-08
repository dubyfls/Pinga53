// SPDX-License-Identifier: AGPL-3.0-only

package rpz

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/atomicfile"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
)

// # WHY A ZONE WRITE LEAVES A SEALED RECORD BEHIND
//
// C-24. The zone itself is a file anybody with write access to the directory
// can produce; nothing in it says a ScamWall run decided its contents. The
// record is the statement that one did, bound to the exact bytes: the zone's
// sha256, the serial it was issued under, and the counts. A zone whose digest
// does not match its record is a zone somebody else wrote.
//
// It is sealed under mac.PurposeRPZZone and not under the store purpose,
// because the two claims are different. "This document was written down" and
// "this file, which a resolver will act on, was produced by a run holding the
// key" must not be interchangeable — under one shared purpose the first could
// be presented as the second.

// ErrRecordInvalid is a record that does not verify.
var ErrRecordInvalid = errors.New("rpz: the record does not verify")

// Record is one zone write, as the run that made it describes it.
type Record struct {
	// Purpose is written down so a reader sees which one was claimed, and so
	// a record claiming another is refused before any tag is compared.
	Purpose string `json:"purpose"`
	Origin  string `json:"origin"`
	Serial  string `json:"serial"`
	// Digest is over the zone bytes as written, "sha256:" and hex.
	Digest  string `json:"zone_sha256"`
	Entries int    `json:"entries"`
	// Adds and Removals are the difference this write made to the zone that
	// was there before, not the plan's own counts.
	Adds      int       `json:"adds"`
	Removals  int       `json:"removals"`
	WrittenAt time.Time `json:"written_at"`
	// Tag is the keyed tag. EMPTY on a build with no key, and empty means
	// unsealed: there is no unkeyed fallback, because a digest anybody can
	// recompute proves the record was not corrupted and proves nothing about
	// who wrote it.
	Tag string `json:"tag,omitempty"`
}

// RecordPath is where the record for a zone lives.
func RecordPath(zonePath string) string { return zonePath + ".record.json" }

// message is what the tag is computed over.
//
// Enumerated, not reflected. A field added to Record and not added here would
// be outside the seal, and no test would notice because the seal would still
// verify — internal/proposal's itemSubstance makes the same choice for the
// same reason. The separator is a newline, which none of these fields can
// contain: three are digits, two are generated identifiers, one is an
// RFC 3339 instant.
func (r Record) message() string {
	return r.Purpose + "\n" + r.Origin + "\n" + r.Serial + "\n" + r.Digest + "\n" +
		strconv.Itoa(r.Entries) + "\n" + strconv.Itoa(r.Adds) + "\n" +
		strconv.Itoa(r.Removals) + "\n" + r.WrittenAt.UTC().Format(time.RFC3339Nano)
}

// sealed returns the record with its tag filled in. A nil key returns it
// unsealed rather than inventing a tag.
func (r Record) sealed(k *mac.Key) Record {
	if k == nil {
		return r
	}
	r.Tag = k.Tag(mac.PurposeRPZZone, r.message())
	return r
}

// VerifyRecord checks a record against a key.
//
// Every failure names what did not match, for the reason proposal.VerifySeal
// gives: "invalid" tells a reader to distrust the whole document when one
// field was changed.
func VerifyRecord(r Record, k *mac.Key) error {
	switch {
	case k == nil:
		return fmt.Errorf("%w: no key was supplied, so no tag can be checked; an unchecked tag is "+
			"not a passed one", ErrRecordInvalid)
	case r.Tag == "":
		return fmt.Errorf("%w: the record carries no tag. An unsealed record is not a record that "+
			"passed", ErrRecordInvalid)
	case r.Purpose != string(mac.PurposeRPZZone):
		return fmt.Errorf("%w: the record claims purpose %q and a zone record is sealed under %q",
			ErrRecordInvalid, r.Purpose, mac.PurposeRPZZone)
	case !mac.Equal(r.Tag, k.Tag(mac.PurposeRPZZone, r.message())):
		return fmt.Errorf("%w: the record has been changed since it was sealed, or carries a tag "+
			"this key did not make", ErrRecordInvalid)
	}
	return nil
}

// writeRecord puts the record beside the zone, atomically.
func writeRecord(zonePath string, r Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("rpz: encode the record: %w", err)
	}
	if err := atomicfile.Write(RecordPath(zonePath), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("rpz: write the record: %w", err)
	}
	return nil
}
