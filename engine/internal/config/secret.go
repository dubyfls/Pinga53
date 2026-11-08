// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxSecretBytes bounds how much of a secret file is read. A credential file
// that is larger than this is a configuration mistake, and reading it whole
// would let a mispointed mount consume memory.
const MaxSecretBytes = 4096

// redactedPlaceholder is what a Secret renders as on every formatting path.
const redactedPlaceholder = "[REDACTED]"

// Errors returned when loading a secret.
var (
	ErrSecretEmpty      = errors.New("secret is empty")
	ErrSecretTooLarge   = errors.New("secret exceeds maximum size")
	ErrSecretNotRegular = errors.New("secret path is not a regular file")
	ErrSecretWorldRead  = errors.New("secret file is world-readable")
)

// Secret holds sensitive bytes that must never be logged, printed, serialised,
// or included in an error message.
//
// Every formatting path is overridden: String, GoString, Format, MarshalJSON
// and MarshalText all yield a placeholder. That matters because the realistic
// leak is not a deliberate print — it is a struct containing a Secret being
// passed to %v, or being marshalled into a debug dump. Redacting only String()
// would leave both of those open.
//
// The plaintext is reachable only through Reveal.
type Secret struct {
	b []byte
}

// NewSecret wraps b. The caller must not retain or mutate b afterwards; the
// slice is adopted, not copied, so that the plaintext exists in exactly one
// place and can be zeroed deterministically.
func NewSecret(b []byte) Secret { return Secret{b: b} }

// NewSecretString wraps s. Prefer NewSecret where the bytes can be zeroed;
// Go strings are immutable and cannot be wiped.
func NewSecretString(s string) Secret { return Secret{b: []byte(s)} }

// String implements fmt.Stringer and always redacts.
func (s Secret) String() string { return redactedPlaceholder }

// GoString implements fmt.GoStringer so %#v also redacts.
func (s Secret) GoString() string { return redactedPlaceholder }

// Format implements fmt.Formatter so every verb redacts, including %s, %q, %v,
// %#v and %x. Without this, %x on the underlying bytes would print the secret.
func (s Secret) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		_, _ = io.WriteString(f, `"`+redactedPlaceholder+`"`)
	default:
		_, _ = io.WriteString(f, redactedPlaceholder)
	}
}

// MarshalJSON ensures a Secret cannot be serialised into a JSON dump.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedPlaceholder + `"`), nil
}

// MarshalText ensures text encoders redact too.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redactedPlaceholder), nil }

// Redacted implements the audit.Redactor interface, so the logger recognises
// this type structurally without importing this package.
func (s Secret) Redacted() string { return redactedPlaceholder }

// IsZero reports whether the secret carries no bytes.
func (s Secret) IsZero() bool { return len(s.b) == 0 }

// Len returns the length of the secret. Safe to log: a length is not a secret,
// and it is useful when diagnosing an empty-credential mount.
func (s Secret) Len() int { return len(s.b) }

// Reveal returns the plaintext.
//
// This is the only sanctioned escape hatch. It appears in exactly two places
// in the tree, both of which are the moment a credential is put on the wire:
// building the authentication request body, and setting the X-FTL-SID header.
// A test enforces that count. If you are adding a third call site, you are
// almost certainly introducing a leak.
func (s Secret) Reveal() string { return string(s.b) }

// Scrub replaces every occurrence of the secret in s with the placeholder.
//
// It exists for one situation: a peer echoing back something we sent it. A
// Pi-hole that answered POST /api/auth by quoting the value it was sent back
// in its error message would put the credential into an error string, and from
// there into a log or a diagnostic capture, without any code in ScamWall
// having printed it.
//
// This is deliberately NOT Reveal. Reveal is the sanctioned way to put a
// credential on the wire and its call sites are counted by a test; scrubbing is
// the opposite operation and must not compete for that budget. The conversion
// below does materialise a copy of the plaintext for the duration of the
// comparison, which is the same limitation Destroy already documents.
func (s Secret) Scrub(in string) string {
	if len(s.b) == 0 || in == "" {
		return in
	}
	return strings.ReplaceAll(in, string(s.b), redactedPlaceholder)
}

// Destroy zeroes the underlying bytes.
//
// This reduces the window in which the credential sits in process memory. It
// is not a guarantee: Go may have copied the bytes during a heap move, and
// Reveal necessarily produces an immutable string. It is a meaningful
// reduction, not an absolute one.
func (s *Secret) Destroy() {
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}

// LoadSecretFile reads a credential from path with bounded size and a
// permission check.
//
// A trailing newline is stripped, because writing a secret with a text editor
// almost always appends one and a newline in a password is never intended.
func LoadSecretFile(path string) (Secret, error) {
	f, err := os.Open(path)
	if err != nil {
		// os errors include the path but never the contents.
		return Secret{}, fmt.Errorf("open secret: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Secret{}, fmt.Errorf("stat secret: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Secret{}, fmt.Errorf("%w: %s", ErrSecretNotRegular, path)
	}
	if info.Size() > MaxSecretBytes {
		return Secret{}, fmt.Errorf("%w: %d bytes (max %d)", ErrSecretTooLarge, info.Size(), MaxSecretBytes)
	}
	// A world-readable credential is readable by every process on the host.
	// Refusing is better than working: the failure is loud and fixable, while
	// silently proceeding leaves an exposure nobody notices.
	if info.Mode().Perm()&0o004 != 0 {
		return Secret{}, fmt.Errorf("%w: %s has mode %#o", ErrSecretWorldRead, path, info.Mode().Perm())
	}

	// Read one byte beyond the limit so that growth between Stat and Read is
	// detected rather than silently truncated.
	buf, err := io.ReadAll(io.LimitReader(f, MaxSecretBytes+1))
	if err != nil {
		return Secret{}, fmt.Errorf("read secret: %w", err)
	}
	if len(buf) > MaxSecretBytes {
		return Secret{}, fmt.Errorf("%w: max %d", ErrSecretTooLarge, MaxSecretBytes)
	}

	trimmed := strings.TrimRight(string(buf), "\r\n")
	for i := range buf {
		buf[i] = 0
	}
	if trimmed == "" {
		return Secret{}, fmt.Errorf("%w: %s", ErrSecretEmpty, path)
	}
	return NewSecretString(trimmed), nil
}
