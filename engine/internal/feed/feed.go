// SPDX-License-Identifier: AGPL-3.0-only

// Package feed loads, verifies and validates signed threat feeds.
//
// A signed feed is still an untrusted feed. A signature proves who produced
// the bytes, not that the contents are correct or safe, so every record is
// bounds-checked and sanity-checked after the signature verifies.
package feed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// SchemaVersion is the only envelope version this build understands.
const SchemaVersion = 1

// SupportedManifestVersion is the only manifest version this build understands.
const SupportedManifestVersion = "1.0"

// SignatureAlgorithm is the only accepted signature algorithm.
const SignatureAlgorithm = "ed25519"

// ClockSkewTolerance is how far into the future an issued_at timestamp may sit
// before it is treated as invalid. Some skew between the signer's clock and
// ours is normal; a lot of it suggests a replay or a forged timestamp.
const ClockSkewTolerance = 5 * time.Minute

// Errors returned by Load and Validate.
var (
	ErrFileTooLarge        = errors.New("feed file exceeds maximum size")
	ErrSchemaVersion       = errors.New("unsupported feed schema version")
	ErrManifestVersion     = errors.New("unsupported manifest version")
	ErrSignatureAlgorithm  = errors.New("unsupported signature algorithm")
	ErrSignatureKeyID      = errors.New("feed signed by an untrusted key id")
	ErrSignatureMalformed  = errors.New("feed signature is malformed")
	ErrSignatureInvalid    = errors.New("feed signature verification failed")
	ErrManifestExpired     = errors.New("feed manifest has expired")
	ErrManifestNotYetValid = errors.New("feed manifest is not yet valid")
	ErrManifestTimes       = errors.New("feed manifest has inconsistent timestamps")
	ErrTooManyRecords      = errors.New("feed exceeds maximum record count")
	ErrNoRecords           = errors.New("feed contains no records")
	ErrDuplicateRecord     = errors.New("feed contains a duplicate domain")
	ErrConflictingRecord   = errors.New("feed contains conflicting records for a domain")
	ErrInvalidAction       = errors.New("feed record has an invalid action")
	ErrInvalidConfidence   = errors.New("feed record has an invalid confidence")
	ErrInvalidRecord       = errors.New("feed record failed validation")
	ErrTrustKeyMissing     = errors.New("no trust key configured")
)

// Action is what a feed asks be done with a domain.
type Action string

// Supported actions.
const (
	ActionBlock Action = "block"
	ActionAllow Action = "allow"
)

// Valid reports whether a is a recognised action.
func (a Action) Valid() bool { return a == ActionBlock || a == ActionAllow }

// Confidence is the publisher's stated confidence in a record.
type Confidence string

// Supported confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Valid reports whether c is a recognised confidence level.
func (c Confidence) Valid() bool {
	return c == ConfidenceHigh || c == ConfidenceMedium || c == ConfidenceLow
}

// signatureBlock describes how the payload was signed.
type signatureBlock struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// envelope is the on-disk feed file.
//
// Payload is captured as raw bytes so the signature can be verified over
// exactly what was written, rather than over a re-serialisation. Verifying a
// re-encoded structure would allow a parser-differential attack: two decoders
// that disagree about the same bytes would produce a signature that validates
// over content nobody signed.
type envelope struct {
	SchemaVersion int             `json:"schema_version"`
	Signature     signatureBlock  `json:"signature"`
	Payload       json.RawMessage `json:"payload"`
}

// Record is a single feed entry as written on disk.
type Record struct {
	Domain     string     `json:"domain"`
	Action     Action     `json:"action"`
	Confidence Confidence `json:"confidence"`
	Category   string     `json:"category,omitempty"`
	Reference  string     `json:"reference,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// Manifest is the signed payload.
type Manifest struct {
	ManifestVersion string    `json:"manifest_version"`
	FeedID          string    `json:"feed_id"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Records         []Record  `json:"records"`
}

// Indicator is a validated record with a canonical domain.
type Indicator struct {
	Domain     domain.Domain
	Action     Action
	Confidence Confidence
	Category   string
	ExpiresAt  *time.Time
	// Signals are what the domain package observed about the name. They are
	// carried, not acted on: this package decides whether a feed is WELL
	// FORMED, and whether a name is worth blocking is a policy question with
	// different inputs. Sorted and deduplicated, so a plan built from them is
	// deterministic.
	Signals []domain.Signal
}

// Validated is the result of loading and validating a feed.
type Validated struct {
	FeedID          string
	ManifestVersion string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	KeyID           string

	// Indicators are the records that passed every check and are still live.
	Indicators []Indicator
	// ExpiredCount records how many otherwise-valid records were dropped for
	// having passed their own expiry.
	ExpiredCount int
}

// Options configure loading.
type Options struct {
	MaxFileBytes int64
	MaxRecords   int
	TrustKeyID   string
	TrustKey     ed25519.PublicKey
	// Now allows deterministic testing of expiry behaviour.
	Now time.Time
}

// LoadFile reads, verifies and validates a feed from path.
func LoadFile(path string, opts Options) (*Validated, error) {
	if opts.MaxFileBytes <= 0 {
		return nil, errors.New("feed: MaxFileBytes must be positive")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open feed: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Check the declared size first so an oversized file is rejected before
	// any of it is buffered.
	if info, err := f.Stat(); err == nil && info.Size() > opts.MaxFileBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrFileTooLarge, info.Size(), opts.MaxFileBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, opts.MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read feed: %w", err)
	}
	if int64(len(data)) > opts.MaxFileBytes {
		return nil, fmt.Errorf("%w: max %d", ErrFileTooLarge, opts.MaxFileBytes)
	}

	return Validate(data, opts)
}

// Validate verifies and validates a feed held in memory.
func Validate(data []byte, opts Options) (*Validated, error) {
	if opts.MaxRecords <= 0 {
		return nil, errors.New("feed: MaxRecords must be positive")
	}
	if len(opts.TrustKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d-byte ed25519 key", ErrTrustKeyMissing, ed25519.PublicKeySize)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	var env envelope
	if err := strictUnmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse feed envelope: %w", err)
	}
	if env.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSchemaVersion, env.SchemaVersion, SchemaVersion)
	}
	if env.Signature.Algorithm != SignatureAlgorithm {
		return nil, fmt.Errorf("%w: %q", ErrSignatureAlgorithm, env.Signature.Algorithm)
	}
	if opts.TrustKeyID != "" && env.Signature.KeyID != opts.TrustKeyID {
		// The key id is compared before the signature is checked so that a
		// feed signed by the wrong key fails with a clear reason.
		return nil, fmt.Errorf("%w: %q", ErrSignatureKeyID, env.Signature.KeyID)
	}
	if len(env.Payload) == 0 {
		return nil, errors.New("feed payload is empty")
	}

	sig, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64", ErrSignatureMalformed)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrSignatureMalformed, len(sig), ed25519.SignatureSize)
	}

	// Verify before interpreting. Nothing below this line should be reachable
	// with attacker-chosen content that has not been signed by a trusted key.
	if !ed25519.Verify(opts.TrustKey, env.Payload, sig) {
		return nil, ErrSignatureInvalid
	}

	var m Manifest
	if err := strictUnmarshal(env.Payload, &m); err != nil {
		return nil, fmt.Errorf("parse feed manifest: %w", err)
	}
	if m.ManifestVersion != SupportedManifestVersion {
		return nil, fmt.Errorf("%w: %q", ErrManifestVersion, m.ManifestVersion)
	}
	if m.IssuedAt.IsZero() || m.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: issued_at and expires_at are required", ErrManifestTimes)
	}
	if !m.ExpiresAt.After(m.IssuedAt) {
		return nil, fmt.Errorf("%w: expires_at is not after issued_at", ErrManifestTimes)
	}
	if m.IssuedAt.After(now.Add(ClockSkewTolerance)) {
		return nil, fmt.Errorf("%w: issued_at is %s", ErrManifestNotYetValid, m.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !m.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: expired at %s", ErrManifestExpired, m.ExpiresAt.UTC().Format(time.RFC3339))
	}

	if len(m.Records) == 0 {
		return nil, ErrNoRecords
	}
	if len(m.Records) > opts.MaxRecords {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManyRecords, len(m.Records), opts.MaxRecords)
	}

	out := &Validated{
		FeedID:          m.FeedID,
		ManifestVersion: m.ManifestVersion,
		IssuedAt:        m.IssuedAt,
		ExpiresAt:       m.ExpiresAt,
		KeyID:           env.Signature.KeyID,
		Indicators:      make([]Indicator, 0, len(m.Records)),
	}

	// seen maps canonical domain to the action already recorded for it, so
	// that both exact duplicates and contradictory entries are caught.
	seen := make(map[domain.Domain]Action, len(m.Records))

	for i, r := range m.Records {
		// Assess, not Normalize: this needs both the canonical form and what
		// was observed about the name.
		//
		// Only a SYNTAX failure rejects the feed. That distinction is the
		// whole of SW-P3-05: a syntactically valid name that happens to mix
		// scripts used to return an error here, and an error here destroys
		// the entire signed feed — every unrelated indicator in it — because
		// a malformed file and a suspicious entry were the same outcome.
		// Whole-feed rejection is retained for exactly what it is for:
		// integrity, signature and structural failures.
		assessment, err := domain.Assess(r.Domain)
		if err != nil {
			// The raw value is clipped. It comes from a signed feed and an
			// operator needs to know which entry is wrong, but the length is
			// the publisher's choice and this message is already wrapping an
			// error that quoted the value once.
			return nil, fmt.Errorf("%w: record %d (%q): %v", ErrInvalidRecord, i, domain.Clip(r.Domain), err)
		}
		canonical := assessment.Domain
		if !r.Action.Valid() {
			return nil, fmt.Errorf("%w: record %d (%s): %q", ErrInvalidAction, i, canonical, r.Action)
		}
		if !r.Confidence.Valid() {
			return nil, fmt.Errorf("%w: record %d (%s): %q", ErrInvalidConfidence, i, canonical, r.Confidence)
		}

		if prior, dup := seen[canonical]; dup {
			if prior != r.Action {
				return nil, fmt.Errorf("%w: %s is both %q and %q", ErrConflictingRecord, canonical, prior, r.Action)
			}
			return nil, fmt.Errorf("%w: %s", ErrDuplicateRecord, canonical)
		}
		seen[canonical] = r.Action

		// An expired indicator is a normal lifecycle event rather than a
		// malformed feed, so it is dropped and counted rather than fatal.
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			out.ExpiredCount++
			continue
		}

		out.Indicators = append(out.Indicators, Indicator{
			Domain:     canonical,
			Action:     r.Action,
			Confidence: r.Confidence,
			Category:   r.Category,
			ExpiresAt:  r.ExpiresAt,
			Signals:    assessment.Signals(),
		})
	}

	return out, nil
}

// strictUnmarshal decodes JSON rejecting unknown fields and trailing data.
//
// Unknown fields are refused because a field ScamWall does not understand may
// carry meaning the publisher expects to be honoured. Silently ignoring it
// would mean acting on a different feed than the one that was signed.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing content so that a second JSON document appended after
	// the signed one cannot ride along.
	if dec.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}
