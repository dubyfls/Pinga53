// SPDX-License-Identifier: AGPL-3.0-only

// Package observation records WHO said WHAT about an indicator, and WHEN.
//
// # Why this is not a blocklist
//
// The obvious shape for this data is a set of bad things. That shape destroys
// the only information that makes a decision defensible, and it does so
// irreversibly:
//
//   - Two providers reporting the same domain become one entry, so nobody can
//     tell corroboration from a single noisy feed.
//   - A provider that later withdraws a record cannot withdraw it, because the
//     record no longer says who contributed it.
//   - An aggregator and the upstream it copied become two entries, and
//     "reported by three sources" starts counting one observation three times.
//   - A licence that permits local lookup but forbids redistribution cannot be
//     honoured, because the exported set no longer knows where anything came
//     from.
//
// So the unit stored here is an OBSERVATION — one source's statement about one
// indicator at one time — and an indicator is the set of observations that
// share a canonical value. Nothing here merges two observations into one, and
// nothing here decides what should be blocked. Deciding is internal/policy's
// job and it is a different question with different inputs.
//
// # What this package deliberately does not carry
//
// There is no ScamWall confidence score. The field would be trivial to add and
// impossible to justify: no documented calculation exists that turns provider
// confidences on incomparable scales into one number, and a score invented to
// fill a struct field is worse than an absent one because it looks like
// evidence. ProviderConfidence carries what the provider said, on the scale
// the provider said it, or nothing at all.
//
// There is no lineage field either. Lineage is a property of a SOURCE, it is
// already recorded in internal/sourceregistry, and copying it onto every
// observation would create a second copy to drift. Corroborate reads it from
// the registry at the moment it is needed.
package observation

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// Type is the kind of thing an indicator names.
//
// The vocabulary is the one docs/source-registry.json already uses in
// indicator_types, so that a source's declared types and an observation's type
// are the same words. Being in the vocabulary is NOT the same as being
// supported: see Supported.
type Type string

// The indicator types the source registry's vocabulary contains.
const (
	TypeDomain                Type = "domain"
	TypeURL                   Type = "url"
	TypeIPv4                  Type = "ipv4"
	TypeIPv6                  Type = "ipv6"
	TypeIPNetblock            Type = "ip-netblock"
	TypeASN                   Type = "asn"
	TypeEmailAddress          Type = "email-address"
	TypeDisposableEmailDomain Type = "disposable-email-domain"
	TypeUsername              Type = "username"
	TypeSocialHandle          Type = "social-handle"
	TypePhoneNumber           Type = "phone-number"
	TypeCryptoAddress         Type = "crypto-address"
	TypeFileHash              Type = "file-hash"
	TypeCertificateThumbprint Type = "certificate-fingerprint"
	TypeJA3Fingerprint        Type = "ja3-fingerprint"
	TypeIDSRule               Type = "ids-rule"
	TypeCVE                   Type = "cve"
	TypeRegistrationRecord    Type = "registration-record"
	TypeMessageCorpus         Type = "message-corpus"
	TypeFeatureVector         Type = "feature-vector"
	TypeUnknown               Type = "unknown"
)

// KnownTypes is the closed vocabulary.
var KnownTypes = []Type{
	TypeDomain, TypeURL, TypeIPv4, TypeIPv6, TypeIPNetblock, TypeASN,
	TypeEmailAddress, TypeDisposableEmailDomain, TypeUsername, TypeSocialHandle,
	TypePhoneNumber, TypeCryptoAddress, TypeFileHash, TypeCertificateThumbprint,
	TypeJA3Fingerprint, TypeIDSRule, TypeCVE, TypeRegistrationRecord,
	TypeMessageCorpus, TypeFeatureVector, TypeUnknown,
}

// Known reports whether t is in the vocabulary at all.
func (t Type) Known() bool {
	for _, k := range KnownTypes {
		if k == t {
			return true
		}
	}
	return false
}

// Supported reports whether ScamWall can canonicalise a value of this type.
//
// Exactly one type is supported. That is not an oversight and it is not a
// placeholder: canonicalising a URL, an e-mail address or a crypto address
// correctly is each its own problem with its own confusables and its own
// identity rules, and a parser written to make a type appear in a coverage
// table would be a parser nobody has tested against the way that type is
// actually attacked. An unsupported type is refused with ErrUnsupportedType,
// which is a different fact from "this value is malformed" and is reported as
// one.
func (t Type) Supported() bool { return t == TypeDomain }

// Classification is what a source says an indicator IS, in ScamWall's closed
// vocabulary.
type Classification string

// The classification vocabulary.
const (
	// ClassMalicious — the source asserts the indicator is harmful.
	ClassMalicious Classification = "malicious"
	// ClassSuspicious — the source asserts something short of harmful.
	ClassSuspicious Classification = "suspicious"
	// ClassBenign — the source asserts the indicator is NOT harmful. Kept
	// because an explicit negative is evidence, and folding it into "absent"
	// would throw away the strongest thing a source can say against a block.
	ClassBenign Classification = "benign"
	// ClassUnknown — the source listed the indicator without saying what it
	// is. Distinct from benign, from an absent observation, and from a refused
	// one; it is a statement that the source has nothing to say, which is not
	// the same as the source saying nothing.
	ClassUnknown Classification = "unknown"
)

// ValidClassifications is the closed vocabulary. The zero value is not in it:
// a record whose classification was never set is refused rather than being
// read as `unknown`, because silence from the author and `unknown` from the
// provider are different facts.
var ValidClassifications = []Classification{
	ClassMalicious, ClassSuspicious, ClassBenign, ClassUnknown,
}

// State is what the source says about whether the indicator is live.
type State string

// The state vocabulary.
const (
	StateActive   State = "active"
	StateInactive State = "inactive"
	StateExpired  State = "expired"
	StateUnknown  State = "unknown"
)

// ValidStates is the closed vocabulary.
var ValidStates = []State{StateActive, StateInactive, StateExpired, StateUnknown}

// Status is the standing of the observation itself, as opposed to of the
// indicator it describes.
type Status string

// The status vocabulary.
const (
	// StatusCurrent — the source still stands behind this observation.
	StatusCurrent Status = "current"
	// StatusWithdrawn — the source has withdrawn it. The observation is
	// RETAINED: a withdrawal is evidence about the source, and deleting the
	// record would destroy the only trace that the claim was ever made.
	StatusWithdrawn Status = "withdrawn"
)

// ValidStatuses is the closed vocabulary.
var ValidStatuses = []Status{StatusCurrent, StatusWithdrawn}

// Retention says what may be kept of the provider's own response.
type Retention string

// The retention vocabulary.
const (
	// RetentionNone — nothing of the raw response is kept. The default, and
	// the only value that needs no rights decision.
	RetentionNone Retention = "none"
	// RetentionRetained — the raw response is kept, which is a local-storage
	// operation and is authorised as one.
	RetentionRetained Retention = "retained"
)

// ValidRetentions is the closed vocabulary.
var ValidRetentions = []Retention{RetentionNone, RetentionRetained}

// ProviderConfidence is the provider's own confidence, on the provider's own
// scale.
//
// Scale is required and is not a number. "80" means nothing without knowing
// whether the provider counts to 100, to 10, or in the other direction; two
// providers' 80s are not comparable and this type exists so that nothing
// treats them as if they were.
type ProviderConfidence struct {
	// Scale names the provider's scale, e.g. "abuse.ch:confidence_level_0_100".
	Scale string
	// Value is the number the provider gave, unmodified.
	Value float64
}

// Reference is a pointer to evidence the provider published.
type Reference struct {
	// URL of the provider's own page for this observation, where one exists.
	URL string
	// Note is a short description of what the reference shows. Bounded, and
	// never the provider's full response.
	Note string
}

// Observation is one source's statement about one indicator at one time.
//
// Construct it with New, which canonicalises the value and fills Canonical and
// Signals. Building one by hand and skipping Validate is how an unattributed
// record reaches the trusted path, which is what Validate exists to prevent.
type Observation struct {
	// --- what was observed ---

	// Type is the indicator type. Part of identity: the same string may be a
	// domain to one source and a username to another, and those are not the
	// same indicator.
	Type Type
	// Canonical is the canonical form, produced by New. Part of identity.
	Canonical string
	// ObservedValue is the form the SOURCE wrote, clipped to a bounded length.
	//
	// It is kept because canonicalisation is lossy by design and a risk signal
	// cannot be explained without it: "this entry is example.com" and "this
	// entry was written with a zero-width space inside example.com" are
	// different facts and only one of them survives canonicalisation.
	ObservedValue string
	// Signals are what internal/domain observed about the written form.
	Signals []domain.Signal

	// --- who said it ---

	// SourceID is the source registry's identifier. Required. An observation
	// with no source is not evidence of anything and is refused.
	SourceID string
	// SourceRecordID is the provider's own identifier for the record, where it
	// publishes one. Optional, and load-bearing when present: it is what makes
	// a correction attachable to the thing it corrects.
	//
	// # SCOPE: one record id identifies one provider record, ACROSS indicators
	//
	// This is a decision, not an accident of the storage layout, and it was
	// made the other way round first. Under the superseded implementation a
	// record id was scoped to the INDICATOR: the store looked for a matching
	// record only among the entries already filed under the canonical value
	// being added. A provider that corrected the subject of a record —
	//
	//	rec-1: old.example.com     then     rec-1: new.example.com
	//
	// therefore produced two indicators, both live, neither superseding the
	// other, and the outcome reported was `new` rather than `correction`. The
	// withdrawn subject stayed current for the rest of the store's life, and
	// nothing in the data said it had been corrected.
	//
	// WHY GLOBAL IS THE RIGHT SCOPE. A provider record id names a record in
	// the provider's catalogue, not a row in ScamWall's index. When the
	// provider says "rec-1 now names something else", that is one statement
	// being revised, and the only faithful representation is the previous
	// revision being superseded. The indicator-scoped reading would have to
	// claim the provider is making two independent assertions, which is the
	// exact double-count the provenance model exists to prevent.
	//
	// WHAT IT COSTS. Two sources may legitimately use the same record id; the
	// key is therefore (SourceID, SourceRecordID), never the record id alone.
	// A source that reuses one record id for genuinely unrelated indicators
	// will have them supersede one another — that is a misuse of a record id,
	// and it is visible, because the history retains every revision.
	//
	// An observation with NO record id is scoped to the indicator instead, and
	// Store.Add says why.
	SourceRecordID string

	// --- when ---

	// SourceFirstSeen and SourceLastSeen are the provider's own window.
	// Absent is nil, and nil is NOT the zero time: a missing timestamp that
	// became the Unix epoch would make every undated observation look like the
	// oldest evidence in the system.
	SourceFirstSeen *time.Time
	SourceLastSeen  *time.Time
	// IngestedAt is when ScamWall took the record in. Required, and ours
	// rather than the provider's, so that it is always present and always
	// means the same thing.
	IngestedAt time.Time
	// ExpiresAt is when the provider says the observation stops applying.
	ExpiresAt *time.Time

	// --- what they said ---

	// ProviderClassification is the provider's own word for it, verbatim and
	// bounded. Kept next to the normalised form so that a mapping can be
	// audited rather than trusted.
	ProviderClassification string
	// Classification is that word mapped into ValidClassifications.
	Classification Classification
	// ProviderConfidence is the provider's confidence, or nil if none was
	// published. There is no ScamWall confidence; see the package comment.
	ProviderConfidence *ProviderConfidence
	// ReportCount is how many times the provider says it was reported, or nil
	// if the provider does not say. Nil is not zero.
	ReportCount *int
	// State is what the provider says about liveness.
	State State
	// Category is the provider's scam category, where it publishes one.
	Category string

	// --- standing, evidence and rights ---

	// Status is the standing of this observation.
	Status Status
	// References point at evidence the provider published.
	References []Reference
	// RawRetention says whether Raw may be populated.
	RawRetention Retention
	// Raw is the provider's own response. Empty unless RawRetention is
	// RetentionRetained, and keeping it is a local-storage operation that the
	// source's registry record has to authorise.
	Raw string
}

// Errors returned when constructing or validating an observation.
var (
	ErrUnknownType      = errors.New("indicator type is not in the vocabulary")
	ErrUnsupportedType  = errors.New("indicator type is not supported by this build")
	ErrInvalidValue     = errors.New("indicator value is not valid for its type")
	ErrNoSource         = errors.New("observation carries no source identity")
	ErrInvalidField     = errors.New("observation field is invalid")
	ErrImpossibleTimes  = errors.New("observation timestamps are in an impossible order")
	ErrRetentionRefused = errors.New("observation carries raw content its retention policy forbids")
)

// maxObservedValue bounds the written form that is carried alongside the
// canonical one. internal/domain refuses anything longer as an indicator, so
// this only ever bounds a value that was already refused.
const maxObservedValue = 1024

// maxProviderText bounds free text taken verbatim from a provider.
const maxProviderText = 256

// Bounds on everything else a provider controls.
//
// # WHY EVERY ONE OF THESE EXISTS
//
// Before this pass, ObservedValue and ProviderClassification were bounded and
// nothing else was. A provider record carrying a 200 KB Category, a 200 KB
// Raw, a 200 KB confidence scale name, a 200 KB source id, or a hundred
// thousand references was accepted by Validate without complaint. None of that
// is a plausible record; all of it is retained in memory, copied on every
// clone, walked on every digest and rendered into reports.
//
// The numbers are chosen to be far above any real record and far below
// anything that costs. A provider that needs more than this is not publishing
// an observation.
const (
	// maxSourceID bounds the registry identifier and the provider's record id.
	// Registry ids are short by construction; a long one is a mistake or an
	// attempt to make a key unwieldy.
	maxSourceID = 128
	// maxReferences bounds how many pieces of evidence one observation may
	// point at.
	maxReferences = 32
	// maxReferenceURL bounds one reference URL.
	maxReferenceURL = 2048
	// maxSignals bounds the derived signal set. It is derived rather than
	// provider-supplied, so this only catches a caller building a record by
	// hand.
	maxSignals = 64
	// maxRaw bounds retained provider content. Retention is already gated on
	// rights (see rights.go); this bounds the size once it is permitted.
	maxRaw = 64 << 10
)

// New canonicalises raw and returns an observation ready to validate.
//
// The three failures are kept apart, because a caller that cannot tell them
// apart makes the wrong decision about each:
//
//   - ErrUnknownType — nobody has ever defined this type. A schema problem.
//   - ErrUnsupportedType — the type is real and this build cannot handle it.
//     Not a statement about the value, which may be perfectly good.
//   - ErrInvalidValue — the type is handled and the value is malformed.
//
// None of the three means the indicator is malicious, and nothing here says
// anything about whether it is.
func New(t Type, raw, sourceID string, ingestedAt time.Time) (Observation, error) {
	if !t.Known() {
		return Observation{}, fmt.Errorf("%w: %q", ErrUnknownType, domain.Clip(string(t)))
	}
	if !t.Supported() {
		return Observation{}, fmt.Errorf("%w: %q cannot be canonicalised by this build", ErrUnsupportedType, t)
	}

	a, err := domain.Assess(raw)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: %s: %v", ErrInvalidValue, t, err)
	}

	return Observation{
		Type:          t,
		Canonical:     a.Domain.String(),
		ObservedValue: clip(raw, maxObservedValue),
		Signals:       a.Signals(),
		SourceID:      sourceID,
		IngestedAt:    ingestedAt,
		// Defaults that are safe rather than convenient. A caller that means
		// something else has to say so.
		Classification: ClassUnknown,
		State:          StateUnknown,
		Status:         StatusCurrent,
		RawRetention:   RetentionNone,
	}, nil
}

// Key identifies the INDICATOR this observation is about.
//
// Type is part of the key. The same characters reported as a domain by one
// source and as a username by another are two different claims about two
// different things, and collapsing them would let a username report
// corroborate a domain block.
type Key struct {
	Type      Type
	Canonical string
}

// Key returns the indicator identity.
func (o Observation) Key() Key { return Key{Type: o.Type, Canonical: o.Canonical} }

// Validate reports every problem with the observation, or nil.
//
// Every error here is about the RECORD, never about the indicator. A record
// that fails validation is one ScamWall cannot attribute or cannot interpret;
// it says nothing at all about whether the thing it names is dangerous.
func (o Observation) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	switch {
	case !o.Type.Known():
		add("type %q is not in the vocabulary", domain.Clip(string(o.Type)))
	case !o.Type.Supported():
		add("type %q is not supported by this build", o.Type)
	}
	if o.Canonical == "" {
		add("canonical value is empty")
	}
	if strings.TrimSpace(o.SourceID) == "" {
		return fmt.Errorf("%w: an observation with no source is not evidence and cannot enter the store", ErrNoSource)
	}
	if o.IngestedAt.IsZero() {
		add("ingested_at is unset; it is ScamWall's own timestamp and is always available")
	}
	if !containsClass(ValidClassifications, o.Classification) {
		add("classification %q is not one of %s (the zero value is refused: an unset field is not the provider saying `unknown`)",
			domain.Clip(string(o.Classification)), joinClasses(ValidClassifications))
	}
	if !containsState(ValidStates, o.State) {
		add("state %q is not one of %s", domain.Clip(string(o.State)), joinStates(ValidStates))
	}
	if !containsStatus(ValidStatuses, o.Status) {
		add("status %q is not one of %s", domain.Clip(string(o.Status)), joinStatuses(ValidStatuses))
	}
	if !containsRetention(ValidRetentions, o.RawRetention) {
		add("raw_retention %q is not one of %s", domain.Clip(string(o.RawRetention)), joinRetentions(ValidRetentions))
	}
	if o.Raw != "" && o.RawRetention != RetentionRetained {
		return fmt.Errorf("%w: raw content is present while raw_retention is %q", ErrRetentionRefused, o.RawRetention)
	}
	if o.ProviderConfidence != nil {
		if strings.TrimSpace(o.ProviderConfidence.Scale) == "" {
			add("provider_confidence has a value but no scale; a number on an unnamed scale is not comparable with anything")
		}
		if len(o.ProviderConfidence.Scale) > maxProviderText {
			add("provider_confidence.scale is %d bytes", len(o.ProviderConfidence.Scale))
		}
		// NaN and the infinities are REFUSED, not clamped. A confidence that
		// is not a number cannot be compared, ordered or thresholded, and NaN
		// in particular compares false against everything including itself —
		// so a rule written as `value >= threshold` silently excludes it and a
		// rule written as `value < threshold` silently excludes it too. Both
		// readings look like a deliberate decision about the record and
		// neither is. There is no safe value to substitute, so it is refused
		// at the boundary.
		if math.IsNaN(o.ProviderConfidence.Value) || math.IsInf(o.ProviderConfidence.Value, 0) {
			add("provider_confidence.value is not a finite number")
		}
	}
	if o.ReportCount != nil && *o.ReportCount < 0 {
		add("report_count is %d", *o.ReportCount)
	}
	if len(o.ObservedValue) > maxObservedValue {
		add("observed_value is %d bytes", len(o.ObservedValue))
	}
	if len(o.ProviderClassification) > maxProviderText {
		add("provider_classification is %d bytes", len(o.ProviderClassification))
	}
	if len(o.Category) > maxProviderText {
		add("category is %d bytes", len(o.Category))
	}
	if len(o.SourceID) > maxSourceID {
		add("source_id is %d bytes", len(o.SourceID))
	}
	if len(o.SourceRecordID) > maxSourceID {
		add("source_record_id is %d bytes", len(o.SourceRecordID))
	}
	if len(o.Raw) > maxRaw {
		add("raw is %d bytes", len(o.Raw))
	}
	if len(o.Signals) > maxSignals {
		add("signals holds %d entries", len(o.Signals))
	}
	if len(o.References) > maxReferences {
		add("references holds %d entries", len(o.References))
	}
	for i, r := range o.References {
		if len(r.URL) > maxReferenceURL {
			add("references[%d].url is %d bytes", i, len(r.URL))
		}
		if len(r.Note) > maxProviderText {
			add("references[%d].note is %d bytes", i, len(r.Note))
		}
	}

	problems = append(problems, o.derivationProblems()...)

	if err := o.timeProblems(); err != nil {
		return err
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%w: %s", ErrInvalidField, strings.Join(problems, "; "))
}

// Expired reports whether the provider's own expiry has passed at t.
//
// An expired observation is not deleted and does not stop being attributable.
// It stops being CURRENT evidence, which is a different thing and is why this
// is a question rather than a filter.
func (o Observation) Expired(at time.Time) bool {
	return o.ExpiresAt != nil && !o.ExpiresAt.After(at)
}

// Live reports whether the observation counts as current evidence at t.
func (o Observation) Live(at time.Time) bool {
	return o.Status == StatusCurrent && !o.Expired(at) && o.State != StateExpired
}

// sameContent reports whether two observations say the same thing.
//
// Re-importing an unchanged record must be a no-op, and changing any field a
// consumer can see must be a correction. The comparison therefore covers every
// field except IngestedAt, which changes on every import by construction and
// would make idempotence impossible if it counted.
func (o Observation) sameContent(other Observation) bool {
	a, b := o, other
	a.IngestedAt, b.IngestedAt = time.Time{}, time.Time{}
	return observationDigest(a) == observationDigest(b)
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func containsClass(hay []Classification, n Classification) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func containsState(hay []State, n State) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func containsStatus(hay []Status, n Status) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func containsRetention(hay []Retention, n Retention) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func joinClasses(v []Classification) string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return strings.Join(out, ", ")
}

func joinStates(v []State) string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return strings.Join(out, ", ")
}

func joinStatuses(v []Status) string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return strings.Join(out, ", ")
}

func joinRetentions(v []Retention) string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return strings.Join(out, ", ")
}

// clone returns a copy that shares no mutable state with o.
//
// The store is the provenance record, and a record a caller can rewrite
// through a read is not one. Observation is a value type, so assigning it
// copies the scalars — but Signals and References are slices, and copying the
// struct copies the headers rather than the elements. Until this existed, a
// caller holding the result of Lookup could change a stored source's signals
// or its evidence references in place, with no revision, no supersession and
// no trace: FINDING-85.
//
// Cloning happens on the way in as well as on the way out, so that a caller
// that keeps its own slice after Add cannot reach into the store through it
// either.
func (o Observation) clone() Observation {
	c := o
	if o.Signals != nil {
		c.Signals = append([]domain.Signal(nil), o.Signals...)
	}
	if o.References != nil {
		c.References = append([]Reference(nil), o.References...)
	}
	if o.SourceFirstSeen != nil {
		t := *o.SourceFirstSeen
		c.SourceFirstSeen = &t
	}
	if o.SourceLastSeen != nil {
		t := *o.SourceLastSeen
		c.SourceLastSeen = &t
	}
	if o.ExpiresAt != nil {
		t := *o.ExpiresAt
		c.ExpiresAt = &t
	}
	if o.ProviderConfidence != nil {
		p := *o.ProviderConfidence
		c.ProviderConfidence = &p
	}
	if o.ReportCount != nil {
		n := *o.ReportCount
		c.ReportCount = &n
	}
	return c
}

// derivationProblems checks that Canonical and Signals were DERIVED from
// ObservedValue rather than asserted by the caller.
//
// # WHY THIS CANNOT BE LEFT TO A DOC COMMENT
//
// Observation's fields are exported, so New is a convenience and not a gate.
// The superseded Validate checked only that Canonical was non-empty, and the
// consequence was demonstrated directly:
//
//	after New:        observed="innocent.example.com" canonical="innocent.example.com"
//	after tampering:  observed="innocent.example.com" canonical="bank.example.com"
//	Validate() = <nil>
//	Store.Add -> outcome=new   filed under: bank.example.com
//
// The canonical value is the INDICATOR IDENTITY — what gets proposed for
// blocking, what corroboration is counted against, what a report names. A
// caller could set it to anything and the trusted store accepted it. "Use New"
// in a doc comment is not a boundary; re-deriving the value and requiring
// agreement is.
//
// The check is skipped for types this build cannot canonicalise, because there
// is nothing to derive from and the type check above has already refused them.
func (o Observation) derivationProblems() []string {
	if !o.Type.Supported() {
		return nil
	}
	a, err := domain.Assess(o.ObservedValue)
	if err != nil {
		return []string{fmt.Sprintf(
			"observed_value does not canonicalise (%v), so canonical and signals "+
				"cannot have been derived from it", err)}
	}

	var problems []string
	if want := a.Domain.String(); o.Canonical != want {
		// Neither value is echoed: both are caller-controlled, and a
		// diagnostic that quoted them would carry provider bytes into logs.
		// The mismatch is the whole finding; the values add nothing to it.
		problems = append(problems, "canonical does not match the canonicalisation of "+
			"observed_value; the indicator identity must be DERIVED from what was "+
			"observed, never asserted alongside it")
	}
	if !sameSignalSet(o.Signals, a.Signals()) {
		problems = append(problems, "signals do not match those derived from "+
			"observed_value; a signal set that is asserted rather than derived can "+
			"hide the evidence for a risk or invent evidence for one")
	}
	return problems
}

// sameSignalSet compares two signal sets irrespective of order.
func sameSignalSet(got, want []domain.Signal) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[domain.Signal]int, len(want))
	for _, s := range want {
		counts[s]++
	}
	for _, s := range got {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

// timeProblems refuses timestamp relationships that are GENUINELY impossible.
//
// # WHAT IS DELIBERATELY NOT CHECKED
//
// Nothing here compares a provider's timestamps with IngestedAt. A record
// whose first_seen is slightly after the moment ScamWall took it in is
// ordinary clock skew between two machines, not an impossibility, and refusing
// it would discard good evidence for a reason that has nothing to do with the
// evidence. Only relationships that cannot hold on any clock are refused.
func (o Observation) timeProblems() error {
	// A non-nil pointer to the zero time is not "absent": it is a claim that
	// the observation was first seen in January of year 1. The package
	// documents nil as the way to say absent precisely so that this is
	// distinguishable, and a zero time reaching the store would make the
	// record the oldest evidence in the system.
	for _, f := range []struct {
		name string
		t    *time.Time
	}{
		{"first_seen", o.SourceFirstSeen},
		{"last_seen", o.SourceLastSeen},
		{"expires_at", o.ExpiresAt},
	} {
		if f.t != nil && f.t.IsZero() {
			return fmt.Errorf("%w: %s is present but zero; absent is nil, and the "+
				"zero time is a claim about January of year 1", ErrImpossibleTimes, f.name)
		}
	}

	if o.SourceFirstSeen != nil && o.SourceLastSeen != nil && o.SourceFirstSeen.After(*o.SourceLastSeen) {
		return fmt.Errorf("%w: first_seen %s is after last_seen %s",
			ErrImpossibleTimes,
			o.SourceFirstSeen.UTC().Format(time.RFC3339),
			o.SourceLastSeen.UTC().Format(time.RFC3339))
	}

	// An observation that stopped applying before it was first seen never
	// applied at all.
	if o.ExpiresAt != nil && o.SourceFirstSeen != nil && o.ExpiresAt.Before(*o.SourceFirstSeen) {
		return fmt.Errorf("%w: expires_at %s is before first_seen %s",
			ErrImpossibleTimes,
			o.ExpiresAt.UTC().Format(time.RFC3339),
			o.SourceFirstSeen.UTC().Format(time.RFC3339))
	}
	return nil
}
