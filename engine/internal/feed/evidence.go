// SPDX-License-Identifier: AGPL-3.0-only

package feed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/strictjson"
)

// # THE EVIDENCE DOCUMENT, AND WHY IT IS NOT THE v1 FEED
//
// The v1 feed in feed.go is a publisher's list of domains to block. Every
// record carries an action and a confidence and nothing else; there is no
// field that says WHO observed the domain, and there could not be, because
// the document has exactly one author and asserts everything in its own
// voice.
//
// That is the right shape for what it is and the wrong shape for provenance.
// internal/observation represents one SOURCE's statement about one indicator
// at one time, and `docs/REQUIREMENTS_MATRIX.md` records the consequence:
// the package "is not reachable from cmd/scamwall", because nothing the
// command can read carries a source at all.
//
// # THE ONE THING THAT MUST NOT BE DONE ABOUT IT
//
// A v1 record could be given a source. It must not be. A v1 document says
// nothing whatever about who observed anything, and assigning its records to
// some invented source — the feed id, the key id, a literal "legacy" — would
// manufacture provenance that nobody asserted and that would then be counted
// by every rule that counts sources.
//
// So v1 is left exactly as it is, and evidence arrives under an explicit
// second schema version. `Validate` refuses schema_version 2 and
// `ValidateEvidence` refuses schema_version 1; neither can be read as the
// other by accident, and a v1 feed goes on working unchanged.

// EvidenceSchemaVersion is the envelope version of a signed evidence
// document. Deliberately not 1: see above.
const EvidenceSchemaVersion = 2

// SupportedEvidenceManifestVersion is the payload version this build reads.
const SupportedEvidenceManifestVersion = "1.0"

// SignerAuthoritySchemaVersion is the version of the operator's signer
// authority document.
const SignerAuthoritySchemaVersion = 1

// Bounds on the operator's own documents.
//
// The signer authority file is written by the operator, which makes it
// trusted to be their intent and not trusted to be well-formed. A bound here
// costs nothing and removes one way a mistyped path — a log file, a core dump
// — turns into a very long parse.
const (
	// MaxSignerAuthorityBytes bounds the authority document.
	MaxSignerAuthorityBytes = 1 << 20
	// MaxSigners bounds how many signers one authority document may name.
	MaxSigners = 64
	// MaxAuthoritySourceIDs bounds how many source ids one signer may be
	// given authority over.
	MaxAuthoritySourceIDs = 4096
)

// Errors raised by the evidence path.
var (
	// ErrEvidenceSchemaVersion is a document that is not an evidence
	// document of a version this build reads.
	ErrEvidenceSchemaVersion = errors.New("unsupported evidence schema version")
	// ErrUnknownSigner is a document signed by a key id the operator's
	// authority document does not name.
	ErrUnknownSigner = errors.New("evidence signed by a key id no signer authority names")
	// ErrAuthoritySchema is a malformed or unsupported authority document.
	ErrAuthoritySchema = errors.New("signer authority document is not one this build reads")
	// ErrAuthorityInvalid is an authority document that parses and is still
	// not usable.
	ErrAuthorityInvalid = errors.New("signer authority document is invalid")
	// ErrAuthorityTooLarge is an authority document above the bound.
	ErrAuthorityTooLarge = errors.New("signer authority document exceeds the maximum accepted size")
)

// Signer is one key the operator recognises, and what it may speak for.
//
// # A SIGNATURE IS NOT AN AUTHORITY
//
// Verifying a signature establishes that the holder of a key produced the
// bytes. It establishes nothing about whether that holder may attribute a
// record to a given source: `source_id` is a field INSIDE the signed payload,
// so a signer that could write any source id it liked would be able to
// manufacture corroboration by asserting the same indicator under three
// source ids and collecting three independent votes for it. Signing the claim
// does not make the claim true; it makes it attributable to the signer, which
// is a different and much weaker fact.
//
// Authority is therefore recorded by the OPERATOR, in this document, and
// enforced against every record. There is deliberately no wildcard spelling.
type Signer struct {
	// KeyID is the id the envelope's signature block must carry.
	KeyID string `json:"key_id"`
	// PublicKey is the base64 ed25519 public key.
	//
	// It lives here, in an operator file on an explicit path, rather than
	// being read from the deployed configuration: this path must be usable
	// without opening anything the production configuration points at.
	PublicKey string `json:"public_key"`
	// AssertsSourceIDs are the source ids this signer may speak for in its
	// own right.
	AssertsSourceIDs []string `json:"asserts_source_ids"`
	// AggregatorFor are the source ids this signer is an approved AGGREGATOR
	// for — it republishes what those sources said rather than observing it.
	//
	// ADMISSION is identical: a record under either grant is admitted.
	// COUNTING is not, and this is the field that decides it. A claim that
	// reached this build only by republication is evidence and is NOT
	// independent confirmation, so it does not count towards
	// min_independent_sources — one signer republishing two upstreams in one
	// document is one attestation (FINDING-122). An operator who wants a
	// source's claim to count independently lists it above instead, which is
	// the operator saying this signer speaks for that source in its own
	// right. See internal/proposal.Attribution.
	//
	// A source id in BOTH lists resolves to AuthorityOwn: the stronger claim
	// wins, or adding an id to one list would silently weaken the other.
	AggregatorFor []string `json:"aggregator_for"`
	// Note is the operator's own record of why this authority exists.
	Note string `json:"note,omitempty"`
}

// SignerAuthority is the operator's whole statement about who may speak for
// what.
type SignerAuthority struct {
	SchemaVersion int      `json:"schema_version"`
	Note          string   `json:"note,omitempty"`
	Signers       []Signer `json:"signers"`
}

// Authority is how a signer came to be allowed to assert a source id.
type Authority string

// The authority vocabulary. A record admitted under one of these is admitted
// for a stated reason; there is no third, unstated way in.
const (
	// AuthorityOwn — the signer is listed as asserting this source directly.
	AuthorityOwn Authority = "own"
	// AuthorityAggregator — the signer is listed as an approved aggregator
	// for this source.
	AuthorityAggregator Authority = "aggregator"
	// AuthorityNone — the signer may not speak for this source at all.
	AuthorityNone Authority = "none"
)

// LoadSignerAuthority reads and validates the operator's authority document.
func LoadSignerAuthority(path string) (*SignerAuthority, error) {
	f, err := os.Open(path) //nolint:gosec // an operator path given on the command line
	if err != nil {
		return nil, fmt.Errorf("open signer authority: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err == nil && info.Size() > MaxSignerAuthorityBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrAuthorityTooLarge, info.Size(), MaxSignerAuthorityBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSignerAuthorityBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read signer authority: %w", err)
	}
	if int64(len(b)) > MaxSignerAuthorityBytes {
		return nil, fmt.Errorf("%w: max %d", ErrAuthorityTooLarge, MaxSignerAuthorityBytes)
	}
	return ParseSignerAuthority(b)
}

// ParseSignerAuthority validates an authority document held in memory.
// authorityNames is this document's closed set of field names, for the
// duplicate-key diagnostic. Built once from the struct tags, so it is this
// package's own bytes and never the document's.
var authorityNames = sync.OnceValue(func() map[string]bool {
	return strictjson.FieldNames(SignerAuthority{})
})

func ParseSignerAuthority(b []byte) (*SignerAuthority, error) {
	// AMBIGUITY IS CHECKED BEFORE THE DECODE, over the raw tokens. After the
	// decode the duplicate is already gone: encoding/json keeps the last value
	// and reports nothing, so there would be no evidence left to check. An
	// operator file that grants a signer two different source-id lists must be
	// refused, not resolved to whichever one a decoder happened to keep
	// (FINDING-127).
	if err := strictjson.CheckDuplicates(b, authorityNames()); err != nil {
		return nil, fmt.Errorf("parse signer authority: %w", err)
	}
	var a SignerAuthority
	if err := strictUnmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("parse signer authority: %w", err)
	}
	if a.SchemaVersion != SignerAuthoritySchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrAuthoritySchema, a.SchemaVersion, SignerAuthoritySchemaVersion)
	}
	if len(a.Signers) == 0 {
		return nil, fmt.Errorf("%w: it names no signers, so nothing could ever be admitted", ErrAuthorityInvalid)
	}
	if len(a.Signers) > MaxSigners {
		return nil, fmt.Errorf("%w: %d signers (max %d)", ErrAuthorityInvalid, len(a.Signers), MaxSigners)
	}

	seen := make(map[string]bool, len(a.Signers))
	for i := range a.Signers {
		s := &a.Signers[i]
		switch {
		case s.KeyID == "":
			return nil, fmt.Errorf("%w: signer %d has no key id", ErrAuthorityInvalid, i)
		case seen[s.KeyID]:
			// Two records for one key id would make the authority depend on
			// which one was found first. Refused rather than resolved.
			return nil, fmt.Errorf("%w: key id %q is named twice", ErrAuthorityInvalid, clipID(s.KeyID))
		}
		seen[s.KeyID] = true

		key, err := base64.StdEncoding.DecodeString(s.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: signer %q public key is not base64", ErrAuthorityInvalid, clipID(s.KeyID))
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: signer %q public key is %d bytes, want %d",
				ErrAuthorityInvalid, clipID(s.KeyID), len(key), ed25519.PublicKeySize)
		}

		// A signer with no authority at all is refused rather than admitted
		// with an empty scope: an operator who wrote the record meant
		// something by it, and silently granting nothing would look identical
		// to granting everything in a report that only listed refusals.
		if len(s.AssertsSourceIDs)+len(s.AggregatorFor) == 0 {
			return nil, fmt.Errorf("%w: signer %q is granted no authority over any source; "+
				"remove the record or state what it may assert", ErrAuthorityInvalid, clipID(s.KeyID))
		}
		if n := len(s.AssertsSourceIDs) + len(s.AggregatorFor); n > MaxAuthoritySourceIDs {
			return nil, fmt.Errorf("%w: signer %q is granted authority over %d sources (max %d)",
				ErrAuthorityInvalid, clipID(s.KeyID), n, MaxAuthoritySourceIDs)
		}
		for _, id := range append(append([]string(nil), s.AssertsSourceIDs...), s.AggregatorFor...) {
			if id == "" {
				return nil, fmt.Errorf("%w: signer %q is granted authority over an empty source id",
					ErrAuthorityInvalid, clipID(s.KeyID))
			}
			if id == "*" {
				// Spelled out so the refusal names the thing somebody tried.
				return nil, fmt.Errorf("%w: signer %q claims wildcard authority; "+
					"there is no spelling for `may assert anything`, because a signer "+
					"that may assert anything can manufacture its own corroboration",
					ErrAuthorityInvalid, clipID(s.KeyID))
			}
		}
	}
	return &a, nil
}

// Signer returns the authority record for a key id.
//
// Exact match only. There is no fallback and no prefix comparison: a key id
// that does not resolve is an unknown signer, and quietly resolving it some
// other way would hide exactly the case this exists to catch.
func (a *SignerAuthority) Signer(keyID string) (*Signer, bool) {
	for i := range a.Signers {
		if a.Signers[i].KeyID == keyID {
			return &a.Signers[i], true
		}
	}
	return nil, false
}

// MayAssert reports how, if at all, this signer came to be allowed to speak
// for a source id.
func (s *Signer) MayAssert(sourceID string) Authority {
	if sourceID == "" {
		return AuthorityNone
	}
	for _, id := range s.AssertsSourceIDs {
		if id == sourceID {
			return AuthorityOwn
		}
	}
	for _, id := range s.AggregatorFor {
		if id == sourceID {
			return AuthorityAggregator
		}
	}
	return AuthorityNone
}

// Digest is the authority document's identity, over its canonical contents.
//
// Over the VALUE and not the file bytes, so that reformatting the operator's
// file does not read as a change of authority, while adding a source id to a
// signer does. Sorted, because the order two ids appear in is not part of
// what the document says.
func (a *SignerAuthority) Digest() string {
	type canonicalSigner struct {
		KeyID     string   `json:"key_id"`
		PublicKey string   `json:"public_key"`
		Asserts   []string `json:"asserts_source_ids"`
		Aggregate []string `json:"aggregator_for"`
	}
	out := make([]canonicalSigner, 0, len(a.Signers))
	for _, s := range a.Signers {
		out = append(out, canonicalSigner{
			KeyID:     s.KeyID,
			PublicKey: s.PublicKey,
			Asserts:   sortedCopy(s.AssertsSourceIDs),
			Aggregate: sortedCopy(s.AggregatorFor),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return digestJSON("signer-authority", struct {
		SchemaVersion int               `json:"schema_version"`
		Signers       []canonicalSigner `json:"signers"`
	}{a.SchemaVersion, out})
}

// EvidenceRecord is one source's statement, as a signed document carries it.
//
// It is deliberately a near-transcription of the fields
// internal/observation.Observation accepts from a provider, and deliberately
// NOT that type: this is what arrived, and Observation is what survived
// validation. Keeping them apart is what makes "the document said X and we
// refused it" expressible.
type EvidenceRecord struct {
	// Type is the indicator type, from internal/observation's vocabulary.
	// Required: a bare string is not an indicator.
	Type string `json:"type"`
	// Value is the indicator as the SOURCE wrote it, before canonicalisation.
	Value string `json:"value"`
	// SourceID is who the document says observed it. Authenticated, and not
	// thereby true — see Signer.
	SourceID string `json:"source_id"`
	// SourceRecordID is the provider's own record id, where it publishes one.
	// It is what makes a correction attachable to the thing it corrects.
	SourceRecordID string `json:"source_record_id,omitempty"`

	// ProviderClassification is the provider's own word, verbatim.
	ProviderClassification string `json:"provider_classification,omitempty"`
	// Classification is that word mapped into the closed vocabulary.
	Classification string `json:"classification"`
	// State is what the provider says about liveness.
	State string `json:"state"`
	// Status is the standing of the statement: current, or withdrawn.
	Status string `json:"status,omitempty"`
	// Category is the provider's scam category, where it publishes one.
	Category string `json:"category,omitempty"`

	// FirstSeen and LastSeen are the provider's own window. Absent is absent,
	// never the zero time.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	// ExpiresAt is when the provider says the statement stops applying.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// RawRetention says whether Raw may be present at all. Absent means
	// `none`, so a document that simply omits it cannot carry raw bytes.
	RawRetention string `json:"raw_retention,omitempty"`
	// Raw is the provider's own response. Refused unless RawRetention says
	// retained AND the source's registry record authorises local storage —
	// the second check happens where the storing happens, not here.
	Raw string `json:"raw,omitempty"`
}

// EvidenceManifest is the signed payload.
type EvidenceManifest struct {
	ManifestVersion string           `json:"manifest_version"`
	FeedID          string           `json:"feed_id"`
	IssuedAt        time.Time        `json:"issued_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
	Records         []EvidenceRecord `json:"records"`
}

// EvidenceOptions are the bounds and the authority a load is subject to.
type EvidenceOptions struct {
	MaxFileBytes int64
	MaxRecords   int
	// Authority is the operator's signer authority document. Required: there
	// is no mode in which a signature alone admits a document.
	Authority *SignerAuthority
	// Now is the instant freshness is judged at. Zero means time.Now.
	Now time.Time
}

// ValidatedEvidence is a document that was authenticated and structurally
// accepted.
//
// It is NOT a document whose claims were believed. Every record in it still
// has to clear signer authority per source, the source registry, indicator
// support and the rights boundary before it becomes an observation.
type ValidatedEvidence struct {
	FeedID          string
	ManifestVersion string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	// KeyID is the key that signed it.
	KeyID string
	// Signer is the authority record that key id resolved to. Carried so that
	// the per-record authority check cannot be performed against a different
	// signer than the one that actually signed.
	Signer *Signer
	// Records are the records as they arrived, in document order.
	Records []EvidenceRecord
	// BytesDigest is over the exact bytes the document was read from, so a
	// report can bind the input it was computed from rather than name it.
	BytesDigest string
	// AuthorityDigest is over the WHOLE signer-authority document this
	// document was admitted under, not only the signer that signed it.
	//
	// Both facts are worth having and they are different. The selected
	// signer's grant is what decided THIS run; the whole document is what the
	// operator wrote, and removing a DIFFERENT signer's authority changes
	// what this operator would admit even though it changes nothing here. A
	// reader comparing two reports should be able to see either.
	AuthorityDigest string

	// admittedDigest is over the records and the signer's grant, taken the
	// instant validation finished. See IntactSinceAuthentication.
	admittedDigest string
}

// IntactSinceAuthentication reports whether this value still says what the
// signature and the operator's authority covered.
//
// # WHY THIS EXISTS
//
// Every exported field is reachable from any holder of the value. The
// signature covered what the DOCUMENT said, and BytesDigest goes on naming
// the original file — so a record rewritten between the verification and the
// consumption would be consumed under a source the signature never covered,
// inside a report that binds bytes which do not say it (FINDING-119), and a
// rewritten BytesDigest, KeyID, FeedID or ManifestVersion would make the
// report claim an identity or an attribution nothing established
// (FINDING-121).
//
// Unexporting the fields was rejected for the reason internal/evaluation
// rejected it for FixtureSet: reading the records is the whole point of the
// type, and a copy-on-every-read would be paid by every caller to prevent a
// mistake one caller might make. The case is DETECTED instead, and the
// consumer refuses rather than proceeding.
//
// # WHAT THIS IS NOT
//
// It is not the signature check and does not replace it. The signature
// establishes that a key the operator recorded produced the payload bytes.
// This establishes that the decoded value a consumer is about to read is the
// one that check was performed on. Two different properties: the first can
// hold while the second fails, which is the whole of FINDING-119 and
// FINDING-121, and the second holding says nothing whatever about who
// produced the bytes.
//
// # WHAT IT DOES NOT DEFEAT
//
// It is a check at an instant. It defeats a mutation made BEFORE a consumer
// calls it. It does NOT make a value safe to mutate concurrently while a
// consumer reads it: a check performed once before a loop says nothing about
// the loop. proposal.Build takes a defensive copy immediately after calling
// this, which closes the window between the check and the reads — but a write
// racing the copy itself is a data race in the CALLER's program, is
// unsynchronised under Go's memory model, and no check inside this package
// can make it defined. See TestWhatTheIntegrityCheckDoesNotDefeat.
func (v *ValidatedEvidence) IntactSinceAuthentication() bool {
	return v.admittedDigest != "" && v.admittedDigest == v.currentDigest()
}

// Snapshot returns a deep copy a consumer can read without the caller's later
// edits, or the caller's concurrent edits, being visible through it.
//
// # WHY A CONSUMER NEEDS THIS AND NOT JUST THE CHECK
//
// IntactSinceAuthentication is one comparison at one instant. A consumer that
// checks and then loops over v.Records is reading, on every iteration, a slice
// the caller still holds. Copying once, immediately after the check, is what
// makes "the records this run used" a fixed thing rather than a sequence of
// reads whose answers could differ.
//
// The copy is deep for exactly what is mutable through this value: the record
// slice and the Signer pointer, including the two string slices inside it. A
// shallow copy of the struct would copy the slice HEADER and share the array,
// which is the bug this exists to prevent rather than a smaller version of
// the fix.
func (v *ValidatedEvidence) Snapshot() *ValidatedEvidence {
	c := *v
	c.Records = append([]EvidenceRecord(nil), v.Records...)
	if v.Signer != nil {
		s := *v.Signer
		s.AssertsSourceIDs = append([]string(nil), v.Signer.AssertsSourceIDs...)
		s.AggregatorFor = append([]string(nil), v.Signer.AggregatorFor...)
		c.Signer = &s
	}
	return &c
}

// currentDigest is over EVERY EXPORTED FIELD, by marshalling the value.
//
// # WHY EVERY FIELD, AND WHY REFLECTIVELY
//
// The first version of this listed the two fields somebody had noticed —
// Records and the signer's grant — and it was therefore exactly as complete
// as the noticing. Measured against that version (FINDING-121), four more
// exported fields could be rewritten after verification and the run
// proceeded:
//
//	BytesDigest      a FALSE IDENTITY CLAIM. The report named
//	                 sha256:0000…0000 as the digest of the authenticated
//	                 document. Nothing ever verified those bytes.
//	KeyID            FALSE ATTRIBUTION. The report said the document was
//	                 signed by a key that did not sign it.
//	FeedID           FALSE ATTRIBUTION.
//	ManifestVersion  FALSE ATTRIBUTION.
//
// IssuedAt and ExpiresAt could be rewritten too, and changed neither the
// decision nor the report: they are consumed by ValidateEvidence and by
// nothing downstream. That is recorded as a non-finding rather than counted
// as a fix.
//
// encoding/json walks the exported fields, so a field ADDED to this struct is
// covered the day it is added rather than the day somebody remembers. The
// unexported admittedDigest is not marshalled, which is what stops this from
// hashing its own answer. Map keys are sorted by encoding/json, and every
// slice here has a document order that is itself part of what was signed, so
// the encoding is deterministic without further canonicalisation.
func (v *ValidatedEvidence) currentDigest() string {
	return digestJSON("evidence-admitted", v)
}

// LoadEvidenceFile reads, authenticates and structurally validates a signed
// evidence document.
func LoadEvidenceFile(path string, opts EvidenceOptions) (*ValidatedEvidence, error) {
	if opts.MaxFileBytes <= 0 {
		return nil, errors.New("feed: MaxFileBytes must be positive")
	}
	f, err := os.Open(path) //nolint:gosec // an operator path given on the command line
	if err != nil {
		return nil, fmt.Errorf("open evidence: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err == nil && info.Size() > opts.MaxFileBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrFileTooLarge, info.Size(), opts.MaxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, opts.MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	if int64(len(data)) > opts.MaxFileBytes {
		return nil, fmt.Errorf("%w: max %d", ErrFileTooLarge, opts.MaxFileBytes)
	}
	return ValidateEvidence(data, opts)
}

// ValidateEvidence authenticates and structurally validates a document held
// in memory.
//
// The order of operations is the point of the function. Nothing below the
// ed25519.Verify call is reachable with bytes the signer did not produce, and
// nothing above it interprets a single field of the payload.
func ValidateEvidence(data []byte, opts EvidenceOptions) (*ValidatedEvidence, error) {
	if opts.MaxRecords <= 0 {
		return nil, errors.New("feed: MaxRecords must be positive")
	}
	if opts.Authority == nil {
		return nil, errors.New("feed: an evidence document cannot be admitted without a signer authority")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Ambiguity first, over the raw tokens, for the reason
	// ParseSignerAuthority gives. The ENVELOPE only: the payload is checked
	// after the signature, because nothing may interpret payload bytes the
	// signer did not produce.
	if err := strictjson.CheckDuplicates(data, envelopeNames()); err != nil {
		return nil, fmt.Errorf("parse evidence envelope: %w", err)
	}
	var env envelope
	if err := strictUnmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse evidence envelope: %w", err)
	}
	if env.SchemaVersion != EvidenceSchemaVersion {
		// Named explicitly against the v1 feed, because the two files look
		// alike and the mistake is easy to make.
		return nil, fmt.Errorf("%w: got %d, want %d (schema %d is the v1 feed, which carries no source attribution)",
			ErrEvidenceSchemaVersion, env.SchemaVersion, EvidenceSchemaVersion, SchemaVersion)
	}
	if env.Signature.Algorithm != SignatureAlgorithm {
		return nil, fmt.Errorf("%w: %q", ErrSignatureAlgorithm, clipID(env.Signature.Algorithm))
	}

	// The signer is resolved BEFORE the signature is checked, because the key
	// to check it with comes from the authority document and nowhere else.
	// There is no fallback key: a document signed by a key the operator has
	// not recorded is not admitted on the strength of being well-formed.
	signer, known := opts.Authority.Signer(env.Signature.KeyID)
	if !known {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSigner, clipID(env.Signature.KeyID))
	}
	key, err := base64.StdEncoding.DecodeString(signer.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		// ParseSignerAuthority already refused this, so reaching it means the
		// authority was built in memory and not through the parser.
		return nil, fmt.Errorf("%w: signer %q has no usable public key", ErrAuthorityInvalid, clipID(signer.KeyID))
	}

	if len(env.Payload) == 0 {
		return nil, errors.New("evidence payload is empty")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64", ErrSignatureMalformed)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrSignatureMalformed, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(key), env.Payload, sig) {
		return nil, ErrSignatureInvalid
	}

	// --- everything below here is authenticated, and none of it is trusted ---

	if err := strictjson.CheckDuplicates(env.Payload, manifestNames()); err != nil {
		return nil, fmt.Errorf("parse evidence manifest: %w", err)
	}
	var m EvidenceManifest
	if err := strictUnmarshal(env.Payload, &m); err != nil {
		return nil, fmt.Errorf("parse evidence manifest: %w", err)
	}
	if m.ManifestVersion != SupportedEvidenceManifestVersion {
		return nil, fmt.Errorf("%w: %q", ErrManifestVersion, clipID(m.ManifestVersion))
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

	v := &ValidatedEvidence{
		FeedID:          m.FeedID,
		ManifestVersion: m.ManifestVersion,
		IssuedAt:        m.IssuedAt,
		ExpiresAt:       m.ExpiresAt,
		KeyID:           env.Signature.KeyID,
		Signer:          signer,
		Records:         m.Records,
		BytesDigest:     digestBytes("evidence-document", data),
		AuthorityDigest: opts.Authority.Digest(),
	}
	// Taken last, over the value exactly as a caller first receives it.
	v.admittedDigest = v.currentDigest()
	return v, nil
}

// clipID bounds a caller-controlled identifier on its way into a diagnostic.
//
// These come out of a file that has not necessarily been authenticated yet —
// the key id and the algorithm are read from the envelope, before any
// signature is verified — so they are exactly as trustworthy as the file, and
// the file is an argument.
func clipID(s string) string {
	const max = 64
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// digestJSON is the digest of a labelled value; digestBytes of exact bytes.
// The label is part of the input so that two different kinds of thing cannot
// collide by encoding identically.
func digestJSON(label string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "undigestable:" + err.Error()
	}
	return digestBytes(label, b)
}

func digestBytes(label string, b []byte) string {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// The closed field-name sets for the duplicate-key diagnostics. Built from
// this package's own struct tags, so a diagnostic names a key only when the
// key is one of ours.
var (
	envelopeNames = sync.OnceValue(func() map[string]bool {
		return strictjson.FieldNames(envelope{})
	})
	manifestNames = sync.OnceValue(func() map[string]bool {
		return strictjson.FieldNames(EvidenceManifest{})
	})
)
