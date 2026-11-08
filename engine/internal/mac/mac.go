// SPDX-License-Identifier: AGPL-3.0-only

// Package mac produces keyed, purpose-separated tags.
//
// # WHY A KEY, AND NOT A DIGEST
//
// Everything this tree identifies today it identifies by an unkeyed digest,
// and for a hostname that is not an identifier at all. Anyone who can guess
// the name can compute the digest and confirm the guess, so an "opaque"
// identifier over a domain is a lookup table away from being the domain. Worse,
// the same digest appears in every installation, so two reports from two
// households can be correlated by a third party who has neither.
//
// A key removes both. The tag is stable within one installation, which is what
// makes two of its reports comparable, and means nothing outside it.
//
// # WHY A PURPOSE, AND WHY IT IS LENGTH-PREFIXED
//
// One key is used for several jobs, and a tag computed for one job must not be
// accepted as a tag for another — a record sealed in the store must not be
// presentable as a report over the same bytes.
//
// The naive spelling, HMAC(key, purpose+message), does not achieve that: a
// caller who chooses the message can move the boundary, because purpose "ab"
// with message "cd" is the same bytes as purpose "a" with message "bcd".
// internal/observation's observationDigest documents this attack against
// delimiter-joined fields and answers it the same way, by writing each value's
// length before it. Nothing a caller supplies can extend a field past its
// declared length.
package mac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// MinKeyBytes is the shortest key this package accepts. HMAC-SHA256's block
// structure gives nothing beyond 32 bytes of key, and less than 32 is a key
// somebody typed rather than generated.
const MinKeyBytes = 32

// Purpose is the job a tag was computed for. A closed set: a purpose nobody
// declared separates nothing, because the separation is only as good as the
// list somebody reviewed.
type Purpose string

// The declared purposes.
const (
	// PurposeWithheldHost identifies a host a report may not name. C-09.
	PurposeWithheldHost Purpose = "withheld-host-identifier"
	// PurposeReportBinding seals a report to the inputs it was computed
	// from. C-24.
	PurposeReportBinding Purpose = "report-binding"
	// PurposeStoreBinding seals a record as stored. C-24 requires that a
	// sealed record is never accepted as a report, and this is the half of
	// that which lives here: the two are different purposes, so a tag under
	// one never verifies under the other.
	PurposeStoreBinding Purpose = "store-binding"
	// PurposeRPZZone seals the record of one RPZ zone write: the zone digest,
	// its serial and its counts. C-24, and its OWN purpose rather than
	// PurposeStoreBinding because the two say different things. A store
	// binding says a document was written down; this says a FILE A RESOLVER
	// WILL ACT ON was produced, with these contents, by a run holding this
	// key. Under one shared purpose a stored report could be presented as a
	// zone record and its tag would verify.
	PurposeRPZZone Purpose = "rpz-zone"
)

// AllPurposes is the closed set.
var AllPurposes = []Purpose{PurposeWithheldHost, PurposeReportBinding, PurposeStoreBinding, PurposeRPZZone}

// ErrKeyTooShort is a key below MinKeyBytes.
var ErrKeyTooShort = errors.New("mac: key is shorter than the minimum")

// ErrKeyNoEntropy is a key of the right length and no content.
var ErrKeyNoEntropy = errors.New("mac: key is all zero bytes")

// Key is an installation's tagging key.
type Key struct {
	k []byte
}

// NewKey wraps raw key material.
//
// It copies: a caller that zeroes its buffer after this call must not be able
// to leave this package holding a key of zeroes, which is worse than holding
// none because it still produces plausible output.
func NewKey(raw []byte) (*Key, error) {
	if len(raw) < MinKeyBytes {
		return nil, fmt.Errorf("%w: %d bytes, need %d", ErrKeyTooShort, len(raw), MinKeyBytes)
	}
	// An all-zero key of the right length is the shape a caller lands in when
	// a read returned an empty buffer and nobody checked the error. Constant
	// time, because the comparison is against key material.
	zero := make([]byte, len(raw))
	if subtle.ConstantTimeCompare(raw, zero) == 1 {
		return nil, ErrKeyNoEntropy
	}
	k := make([]byte, len(raw))
	copy(k, raw)
	return &Key{k: k}, nil
}

// Tag returns the keyed tag of msg under purpose.
//
// A NIL KEY RETURNS THE EMPTY STRING. It does not fall back to an unkeyed
// digest: a build with no key must report that it has none, not produce
// something that looks like an identifier and is not one. Callers check for
// the empty string and say so in their output.
//
// An undeclared purpose panics. It is a programming error and not a runtime
// condition — the set is a compile-time constant of this package — and
// returning a tag for it would silently remove the separation every other
// caller depends on.
func (k *Key) Tag(p Purpose, msg string) string {
	if k == nil {
		return ""
	}
	declared := false
	for _, q := range AllPurposes {
		if q == p {
			declared = true
			break
		}
	}
	if !declared {
		panic("mac: undeclared purpose " + string(p))
	}

	return k.tag(p, msg)
}

// tag is the computation, without the purpose check, so that
// mac_internal_test.go can exercise the boundary property with purposes the
// exported entry point refuses.
func (k *Key) tag(p Purpose, msg string) string {
	h := hmac.New(sha256.New, k.k)
	write(h, string(p))
	write(h, msg)
	// URL-safe and unpadded: a tag travels in JSON, in file names and in log
	// lines, and a '/' or a '=' in any of those is somebody's escaping bug.
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Equal compares two tags in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// write appends a length-prefixed value. See the package comment.
func write(h interface{ Write([]byte) (int, error) }, s string) {
	var n [8]byte
	l := uint64(len(s))
	for i := range n {
		n[i] = byte(l >> (8 * (7 - i)))
	}
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

// LoadKeyFile reads an installation key from a file.
//
// # WHY THIS IS NOT config.LoadSecretFile
//
// It performs the same three checks, and it is deliberately not that
// function. `cmd/scamwall propose` is guarded, by a test over its own source,
// against referencing `config.` at all — the guard exists because the
// configuration file names the Pi-hole application password, and a command
// with no business near a credential must not acquire a reason to open the
// document that points at one. An identity key is this package's own secret
// and nothing to do with the appliance, so it is read here, and the guard
// stays exactly as strict as it was.
//
// The checks themselves are the ones that matter for any key on disk:
// a regular file, a bounded size, and not world-readable. A key every process
// on the host can read is not a key.
func LoadKeyFile(path string) (*Key, error) {
	f, err := os.Open(path)
	if err != nil {
		// os errors include the path and never the contents.
		return nil, fmt.Errorf("open identity key: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat identity key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("mac: identity key %s is not a regular file", path)
	}
	if info.Size() > MaxKeyFileBytes {
		return nil, fmt.Errorf("mac: identity key %s is %d bytes (max %d)", path, info.Size(), MaxKeyFileBytes)
	}
	if info.Mode().Perm()&0o004 != 0 {
		return nil, fmt.Errorf("mac: identity key %s has mode %#o and is world-readable; "+
			"a key every process on this host can read is not a key", path, info.Mode().Perm())
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read identity key: %w", err)
	}
	// Trailing newline only. Anything else is key material: a file written by
	// `head -c 32 /dev/urandom > key` may legitimately end in 0x0a, and one
	// written by an editor ends in exactly one.
	raw = bytes.TrimRight(raw, "\n")
	k, err := NewKey(raw)
	for i := range raw {
		raw[i] = 0
	}
	return k, err
}

// MaxKeyFileBytes bounds an identity key file.
const MaxKeyFileBytes = 4096
