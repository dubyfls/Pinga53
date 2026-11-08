// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/observation"
	"github.com/dubyfls/Pinga53/engine/internal/safetext"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// Decision is what this build does about one indicator.
type Decision string

// The decision vocabulary. Closed.
const (
	// DecisionPropose — the indicator met the policy. Not permission to
	// enforce; see the package comment.
	DecisionPropose Decision = "propose"
	// DecisionAbstain — the evidence was admissible and did not meet the
	// policy. A policy question, answerable by changing the policy.
	DecisionAbstain Decision = "abstain"
	// DecisionRefuse — this build will not propose it, and not because the
	// evidence fell short. A rights position forbids the operation, or the
	// household excepted it. NOT a policy question: changing
	// min_independent_sources cannot turn a refusal into a proposal, and
	// folding the two together would invite an operator to try.
	DecisionRefuse Decision = "refuse"
)

// Reason is a stable machine-readable code.
//
// These appear in reports and in the report digest. Changing one is a change
// to the output format, not a rename, and a test enumerates the whole
// vocabulary so that adding a code without deciding it is one is not possible.
type Reason string

// Record-admission reasons. Each is a way a record does not become evidence.
const (
	// ReasonValueInvalid — the indicator value is not valid for its type.
	// A SYNTAX failure and nothing more: it is not a claim that the name is
	// suspicious. See SW-P3-05.
	ReasonValueInvalid Reason = "record_value_invalid"
	// ReasonTypeUnknown — the indicator type is not in the vocabulary at all.
	ReasonTypeUnknown Reason = "indicator_type_unknown"
	// ReasonTypeUnsupported — a known type this build does not implement.
	// Distinct from unknown: one is a document this build cannot read, the
	// other is a document it reads and cannot act on.
	ReasonTypeUnsupported Reason = "indicator_type_unsupported"
	// ReasonSignerNotAuthorised — the signature verified and the signer has
	// no authority over the source id the record claims.
	ReasonSignerNotAuthorised Reason = "signer_not_authorised_for_source"
	// ReasonSourceUnknown — the source id is not in the registry.
	ReasonSourceUnknown Reason = "source_not_in_registry"
	// ReasonSourceRetired — the source id was used once and withdrawn.
	ReasonSourceRetired Reason = "source_retired"
	// ReasonStorageRefused — the source's registry record does not authorise
	// keeping the record locally.
	ReasonStorageRefused Reason = "source_rights_refuse_local_storage"
	// ReasonRawRefused — the record carries the provider's raw response and
	// the rights position does not authorise keeping it.
	ReasonRawRefused Reason = "raw_retention_not_authorised"
	// ReasonRecordInvalid — the record failed observation validation for a
	// reason the codes above do not name.
	ReasonRecordInvalid Reason = "record_invalid"
)

// Indicator-outcome reasons.
const (
	// ReasonCorroborated — the policy's independent-source threshold was met
	// with adverse classifications.
	ReasonCorroborated Reason = "corroborated"
	// ReasonInsufficientSupport — admissible evidence, below the threshold.
	ReasonInsufficientSupport Reason = "insufficient_independent_support"
	// ReasonNoLiveEvidence — nothing current supports it at the evaluation
	// instant, for a reason the two below do not name.
	ReasonNoLiveEvidence Reason = "no_live_evidence"
	// ReasonExpiredOnly — every supporting observation has passed its expiry.
	ReasonExpiredOnly Reason = "expired_only"
	// ReasonWithdrawnOnly — every supporting source has withdrawn.
	ReasonWithdrawnOnly Reason = "withdrawn_only"
	// ReasonConflict — current sources disagree about what this is. Reported
	// rather than resolved: this build does not take a side.
	ReasonConflict Reason = "sources_conflict"
	// ReasonNameRequiresReview — the written form carried a signal that wants
	// a human. A property of the NAME; never evidence of maliciousness.
	ReasonNameRequiresReview Reason = "name_requires_review"
	// ReasonAuthoritativeSource — the independent-voice threshold was NOT
	// met, and one adverse source holds the registry's `authoritative` tier
	// while the policy sets `accept_authoritative_alone`. Its own code, so
	// that a one-source proposal can never be read as ordinary corroboration.
	ReasonAuthoritativeSource Reason = "authoritative_source_accepted_alone"
	// ReasonAggregatedNotIndependent — enough adverse sources said so, and
	// the ones needed to reach the threshold arrived only through a signer
	// approved to REPUBLISH them. Authority to carry a claim is not
	// independent confirmation of it. Distinct from
	// ReasonInsufficientSupport because the operator's fix is different:
	// grant that signer `asserts_source_ids`, or obtain the claim through
	// another channel.
	ReasonAggregatedNotIndependent Reason = "aggregated_claims_are_not_independent_confirmation"
	// ReasonUserException — the household excepted it. Outranks every source.
	ReasonUserException Reason = "user_exception"
	// ReasonDerivedOutputRefused — a contributing source's rights do not
	// authorise putting a derived result in front of anyone.
	ReasonDerivedOutputRefused Reason = "source_rights_refuse_derived_output"
	// ReasonEnrichmentRefused — a contributing source's rights do not
	// authorise combining its data with another's.
	ReasonEnrichmentRefused Reason = "source_rights_refuse_enrichment"
)

// AllReasons is the closed vocabulary, in a stable order.
var AllReasons = []Reason{
	ReasonValueInvalid, ReasonTypeUnknown, ReasonTypeUnsupported,
	ReasonSignerNotAuthorised, ReasonSourceUnknown, ReasonSourceRetired,
	ReasonStorageRefused, ReasonRawRefused, ReasonRecordInvalid,

	ReasonCorroborated, ReasonInsufficientSupport, ReasonNoLiveEvidence,
	ReasonExpiredOnly, ReasonWithdrawnOnly, ReasonConflict,
	ReasonNameRequiresReview, ReasonAuthoritativeSource, ReasonAggregatedNotIndependent, ReasonUserException,
	ReasonDerivedOutputRefused, ReasonEnrichmentRefused,
}

// MaxExplanation bounds one human-readable explanation as it is printed.
//
// The explanation is built from this project's own vocabulary, but that
// vocabulary quotes source ids and values that came out of a signed document
// somebody else wrote. A bound here means one hostile record cannot inflate a
// report, and safetext escapes what survives.
const MaxExplanation = 300

// RecordOutcome is what happened to one record of the evidence document.
type RecordOutcome struct {
	// Index is the record's position in the document. It locates the record
	// without reproducing anything the document chose.
	Index int `json:"index"`
	// Admitted is true when the record became an observation.
	Admitted bool `json:"admitted"`
	// SourceID is what the record claimed, escaped and bounded. Present even
	// on refusal, because "which source was this attributed to" is the first
	// thing an operator asks about a refused record.
	SourceID string `json:"source_id"`
	// Authority is how the signer came to be allowed to assert that source,
	// or `none`.
	Authority feed.Authority `json:"authority"`
	// Canonical is the canonical indicator value, where one could be derived
	// AND the source's rights permit naming it in a report.
	Canonical string `json:"canonical,omitempty"`
	// CanonicalWithheld distinguishes "there is no canonical value" from
	// "there is one and this build may not print it". An empty field that
	// means both would let a rights refusal read as a parse failure.
	CanonicalWithheld bool `json:"canonical_withheld,omitempty"`
	// ExportWithheld says a contributing source permits this value being used
	// here and not republished. See Audience: the LOCAL report names it and
	// the EXPORT report does not.
	ExportWithheld bool `json:"export_withheld,omitempty"`
	// OpaqueID identifies a value this record may not name. See Outcome.OpaqueID.
	OpaqueID string `json:"opaque_id,omitempty"`
	// Store is the store's own outcome for an admitted record: new,
	// correction, or duplicate.
	Store observation.Outcome `json:"store_outcome,omitempty"`
	// RawDropped is true when the record carried the provider's own response
	// and this build did not keep it. Reported rather than silent: a sender
	// that shipped raw bytes should be able to see that they went nowhere.
	RawDropped bool `json:"raw_dropped,omitempty"`
	// Reason is why it was refused. Empty when admitted.
	Reason Reason `json:"reason,omitempty"`
	// Explanation is the bounded, escaped human-readable form.
	Explanation string `json:"explanation,omitempty"`
}

// Outcome is the decision about one indicator.
//
// # WHAT A RIGHTS REFUSAL MAY SAY
//
// Every field below except Type, Decision, Reason, Explanation and
// RefusedSources is DERIVED from the provider's data: the canonical value is
// the indicator itself, and the source lists, the signals and the conflict
// flag are what combining and assessing those observations produced.
//
// A refusal on `enrichment` or `derived_output` says this build was not
// authorised to combine those observations or to put a result derived from
// them in front of anyone. Emitting the derived result beside that sentence
// performs the operation the sentence says was refused (FINDING-120). So on
// those two refusals the derived fields are NOT FILLED — not hidden by a
// renderer, not omitted from one of the two formats, but absent from the
// value both formats render.
//
// What survives is the minimum an operator needs to find and fix the grant:
// the indicator TYPE, the reason code, an explanation built only from the
// registry's own refusal vocabulary, and RefusedSources. All four are facts
// about the operator's own registry and about the source ids they wrote into
// it; none is the provider's data.
//
// `enrichment` is treated exactly like `derived_output` here even though it
// is the narrower prohibition. An indicator is by construction a combination
// of what its sources said, so naming one in a report is reporting a
// combination; separating the two would mean deciding, per field, which half
// of a join each value came from, and getting that wrong is a disclosure.
type Outcome struct {
	Type string `json:"type"`
	// Canonical is the indicator, when this build may name it.
	Canonical string `json:"canonical"`
	// IdentityWithheld states that the derived fields are absent BECAUSE of
	// the refusal rather than because there was nothing to report. Without
	// it a refused outcome and an empty one are the same document.
	IdentityWithheld bool `json:"identity_withheld,omitempty"`
	// RefusedSources are the source ids whose recorded grant refused the
	// operation, sorted. This is the actionable half of a refusal: it is what
	// the operator edits.
	RefusedSources []string `json:"refused_sources,omitempty"`
	// Scope is how far a proposal reaches. Present only on a proposal: an
	// abstention and a refusal reach nothing, and printing a scope beside one
	// would suggest otherwise.
	Scope Scope `json:"scope,omitempty"`

	Decision    Decision `json:"decision"`
	Reason      Reason   `json:"reason"`
	Explanation string   `json:"explanation"`

	// Sources are every source with a live observation, sorted.
	Sources []string `json:"sources"`
	// IndependentSources are those the registry establishes as independent.
	IndependentSources []string `json:"independent_sources"`
	// UnestablishedSources report it and cannot be established independent.
	UnestablishedSources []string `json:"unestablished_sources,omitempty"`
	// AdverseSources asserted malicious or suspicious and were eligible to
	// count towards the threshold.
	AdverseSources []string `json:"adverse_sources,omitempty"`
	// AggregatedSources asserted adversely and reached this build only
	// through a signer approved to republish them. Reported, and NOT counted
	// towards the threshold. See Attribution.
	AggregatedSources []string `json:"aggregated_sources,omitempty"`
	// Signals are what internal/domain observed about the written forms.
	Signals []string `json:"signals,omitempty"`
	// Conflicted records that current sources disagree.
	Conflicted bool `json:"conflicted,omitempty"`
	// AuthoritativeSources are adverse sources holding the registry's
	// `authoritative` tier, sorted. Reported whether or not the policy
	// permitted acting on one: an operator deciding whether to turn
	// `accept_authoritative_alone` on needs to see that it would have made a
	// difference.
	AuthoritativeSources []string `json:"authoritative_sources,omitempty"`
	// IndependentOriginGroups is how many independent VOICES the adverse
	// sources amount to: the largest family of adverse sources whose origin
	// sets are pairwise disjoint. It is the number the threshold is compared
	// against, and it is at most len(AdverseSources).
	//
	// Reported beside the source list rather than instead of it, because
	// "three sources, one voice" and "one source" are different facts and a
	// reader chasing a shortfall needs both.
	IndependentOriginGroups int `json:"independent_origin_groups,omitempty"`
	// SharedOrigins names the origins that two or more adverse sources draw
	// on, sorted. The actionable half: it says WHY the count is below the
	// number of sources.
	SharedOrigins []string `json:"shared_origins,omitempty"`
	// ExportWithheld says a contributing source permits this indicator being
	// acted on here and not republished — `derived_output` without
	// `redistribution`. The LOCAL report names it; the EXPORT report does
	// not. See Audience.
	ExportWithheld bool `json:"export_withheld,omitempty"`
	// OpaqueID identifies a host this report may not name: a keyed tag under
	// mac.PurposeWithheldHost. Empty when the name was printed, and empty when
	// no identity key was supplied. See Input.IdentityKey.
	OpaqueID string `json:"opaque_id,omitempty"`
	// RetractedBy are sources entitled to be counted that have explicitly
	// withdrawn what they said about this indicator. A retraction is a
	// disagreement with the sources still asserting, so it sets Conflicted;
	// it is reported separately because "one source says benign" and "one
	// source says it was wrong" are different facts and an operator chases
	// them differently.
	RetractedBy []string `json:"retracted_by,omitempty"`
	// Exception records the household statement that matched, if any — even
	// when a different reason won, so that an operator is never left
	// wondering whether their exception was seen.
	Exception *AppliedException `json:"exception,omitempty"`
}

// AppliedException is the exception that matched an indicator.
type AppliedException struct {
	Canonical string `json:"canonical"`
	Scope     Scope  `json:"scope"`
	Note      string `json:"note,omitempty"`
}

// Attribution records which sources' claims reached this build ONLY through a
// signer the operator approved to republish them.
//
// # AUTHORISED TO REPUBLISH IS NOT INDEPENDENT CONFIRMATION
//
// `aggregator_for` says the operator accepts that this signer carries what
// those sources said. It says nothing about whether those sources said it
// independently of one another, and — more to the point — it says nothing
// about how many times THIS BUILD heard it. One signer republishing two
// upstreams in one document is one attestation. If that signer is wrong, or
// compromised, or simply reformats a single upstream into two source ids,
// both claims are wrong together.
//
// Measured against dd38a72, one signer granted `aggregator_for` over two
// source ids satisfied `min_independent_sources: 2` by itself, in one signed
// document, and the report said `corroborated` (FINDING-122).
//
// # WHY THE FIX IS NOT A NEW POLICY FLAG
//
// The schema already has the knob, and this makes it load-bearing. An
// operator who wants a source's claim to count independently grants that
// signer `asserts_source_ids` for it — which is precisely the operator
// saying "this signer speaks for that source in its own right". Adding
// `count_aggregated_as_independent` beside that would be a second way to say
// the same thing, and the two would drift.
//
// `AcceptUnestablishedIndependence` is deliberately NOT reused either. It
// means "the registry cannot establish lineage between these sources", which
// is a different problem with a different fix; one flag covering both would
// let an operator loosen one and silently loosen the other.
//
// # LIMITS
//
// This bounds what an aggregator can claim. It does not establish that a
// DIRECT assertion is true, that two directly-asserting signers are
// independent of each other, or that a source id names a real organisation.
// None of those is knowable from these inputs, and none is claimed.
//
// The zero value aggregates nothing, which is correct for a caller that
// models no signer at all — internal/evaluation's fixtures are observations
// with source ids and no channel, and treating them as spoken in their own
// right is a property of those fixtures rather than a claim about the world.
type Attribution struct {
	// ViaAggregator holds the source ids admitted under AuthorityAggregator.
	ViaAggregator map[string]bool
}

// Aggregated reports whether this source's claims arrived only by republication.
func (a Attribution) Aggregated(sourceID string) bool { return a.ViaAggregator[sourceID] }

// Input is everything one run reads. Every field is required.
type Input struct {
	// Evidence is an AUTHENTICATED document. The type can only be obtained
	// from feed.ValidateEvidence, which is where the signature is checked, so
	// there is no way to reach this package with unverified claims.
	Evidence *feed.ValidatedEvidence
	// Registry is the source registry.
	Registry *sourceregistry.Registry
	// Policy is the operator's proposal policy.
	Policy *Policy
	// At is the instant expiry and withdrawal are judged against. Required
	// and explicit: a run that moved with the clock would be a different
	// answer every time it was repeated, and the report binds it.
	At time.Time
	// BuildIdentity identifies the code producing this report. OPTIONAL, and
	// the one optional field here.
	//
	// Only the caller knows it: cmd/scamwall has it from its own -ldflags,
	// and this package will not go looking. A plausible wrong answer — the
	// commit the working tree happens to sit at, say — is worse here than an
	// absent one, which is the position internal/evaluation.WithSourceCommit
	// took for the same reason.
	//
	// Absent is REPORTED as absent. A report that does not identify the code
	// that produced it is a weaker artefact, and saying so is cheaper than
	// letting a reader assume SemanticsVersion covers it.
	BuildIdentity string
	// IdentityKey is this installation's tagging key. OPTIONAL.
	//
	// When present, every host this report may not name carries a keyed,
	// opaque identifier under mac.PurposeWithheldHost, so two reports about
	// the same withheld host can be told to be about the same host without
	// either naming it.
	//
	// When ABSENT there is no identifier and Limitations says so. There is no
	// fallback to an unkeyed digest: a digest of a hostname is a lookup table
	// away from being the hostname, and it would look exactly like a working
	// control while being none.
	IdentityKey *mac.Key
	// RetractionWindow bounds how long an explicit upstream retraction goes
	// on contradicting the sources still asserting, measured from when
	// ScamWall took the withdrawal in.
	//
	// ZERO MEANS UNBOUNDED, and that is the conservative direction: a
	// retraction that aged out would let a block resume with nobody having
	// said anything new. Nothing sets this yet; it is here so the bound is
	// expressible without the household's policy having to grow a field for
	// a question nobody has asked them.
	RetractionWindow time.Duration
}

// ErrIncompleteInput is a run that cannot be attempted.
var ErrIncompleteInput = errors.New("a proposal run is missing a required input")

// Build admits the evidence and decides every indicator it yields.
//
// # THE ORDER OF THE ADMISSION CHECKS IS PART OF THE ANSWER
//
// A record can fail several checks at once, and which failure is reported
// changes what an operator does next. The order is:
//
//  1. the indicator TYPE, because a record this build cannot act on is not a
//     provenance problem and reporting it as one wastes the operator's time;
//  2. SIGNER AUTHORITY, before the registry is consulted at all. A signer with
//     no authority over a source must not be able to learn, from the
//     difference between two refusal messages, whether that source exists in
//     the operator's registry;
//  3. the REGISTRY — unknown, and retired, reported separately;
//  4. the value's SYNTAX;
//  5. the RIGHTS position for keeping the record at all;
//  6. observation validation and the store, which enforce retention rights
//     again at the point of storage and collapse duplicates and corrections.
//
// A refused record is REPORTED, never silently dropped. A document quietly
// losing half its records is the failure mode this exists to make visible.
func Build(in Input) (*Report, error) {
	switch {
	case in.Evidence == nil:
		return nil, fmt.Errorf("%w: no authenticated evidence document", ErrIncompleteInput)
	case in.Registry == nil:
		return nil, fmt.Errorf("%w: no source registry; without one no grant can be read, "+
			"and an unread grant is refused", ErrIncompleteInput)
	case in.Policy == nil:
		return nil, fmt.Errorf("%w: no proposal policy", ErrIncompleteInput)
	case in.At.IsZero():
		return nil, fmt.Errorf("%w: no evaluation instant; expiry and withdrawal are decided "+
			"against it and nothing else", ErrIncompleteInput)
	case !in.Evidence.IntactSinceAuthentication():
		// Every exported field of the validated value is reachable from any
		// holder of it. A record rewritten between the verification and here
		// would be consumed under a source the signature never covered
		// (FINDING-119); a rewritten BytesDigest, KeyID, FeedID or
		// ManifestVersion would make the report claim an identity or an
		// attribution that nothing established (FINDING-121).
		return nil, fmt.Errorf("%w: the evidence was modified after it was authenticated; "+
			"the signature covered what the document said, and the report would bind those "+
			"bytes while reporting something they do not say", ErrIncompleteInput)
	}

	// THE COPY, TAKEN IMMEDIATELY AFTER THE CHECK.
	//
	// The check above is one comparison at one instant. Everything below reads
	// in.Evidence repeatedly — once per record in the admission loop, and
	// again when the binding is assembled — and each of those reads would
	// otherwise go to a slice and a pointer the caller still holds.
	//
	// So the run continues against a snapshot. What this closes is the window
	// between the check and the reads: an edit made after Build was called
	// cannot change what this run decided or what it reports, and the two are
	// guaranteed to describe the same thing.
	//
	// What it does NOT close is a write racing the copy itself. That is
	// unsynchronised access in the CALLER's program, it is a data race under
	// Go's memory model, and no amount of checking inside this package makes
	// it defined. It is stated here rather than implied away, and
	// TestWhatTheIntegrityCheckDoesNotDefeat is where it is measured.
	in.Evidence = in.Evidence.Snapshot()

	rep := &Report{
		Binding: bindingFor(in),
		Records: make([]RecordOutcome, 0, len(in.Evidence.Records)),
	}
	store := observation.NewStoreWithRights(in.Registry)

	// restricted holds every canonical value that some record's OWN source may
	// not have named in a report.
	//
	// # WHY THE RECORD LIST NEEDS ITS OWN RULE
	//
	// The outcome list reports a result computed at `at`, and
	// Indicator.Authorizes governs it: unanimity over LIVE contributors, with
	// expired and superseded ones deliberately not consulted because they
	// contributed nothing to that result.
	//
	// The record list reports what ARRIVED. A record from a source that
	// prohibits derived output is that source's data whether or not it is
	// still live, so the question here is per record and per source, and the
	// answer does not change when the record expires.
	//
	// Where the two rules differ they differ by exactly the expiry position
	// internal/observation states and defends, and that is recorded rather
	// than smoothed over: an expired record from a restricted source has its
	// value withheld in the record list while a live permitted source's
	// outcome may still name the same value.
	restricted := map[string]bool{}
	// nameable holds canonical values that at least one PERMITTED source
	// supplied. A value nobody permitted may not appear in the report at all,
	// in any section, under any decision — see the outcome pass below.
	nameable := map[string]bool{}
	householdLocal := in.Policy != nil && in.Policy.HouseholdLocalUse
	// attr records which source ids reached this run only by republication.
	// Built from the signer grant that actually admitted each record, so it
	// cannot disagree with the admission.
	attr := Attribution{ViaAggregator: map[string]bool{}}

	for i, rec := range in.Evidence.Records {
		out := admit(i, rec, in, store)
		rep.Records = append(rep.Records, out)
		if out.Admitted {
			rep.Admitted++
		}
		// rec.SourceID, not out.SourceID: the latter is clipped for printing
		// and a long id would not resolve in the registry.
		if out.Canonical != "" {
			// A household-local run (policy.household_local_use) reports only to
			// the household, so a name its own resolver will block may be shown
			// there. The export audience still withholds it (ExportWithheld).
			if householdLocal || sourceMayBeNamedInOutput(in.Registry, rec.SourceID) {
				nameable[out.Canonical] = true
			} else {
				restricted[out.Canonical] = true
			}
		}
		if out.Admitted && out.Authority == feed.AuthorityAggregator {
			attr.ViaAggregator[rec.SourceID] = true
		}
	}

	// ANTI-LAUNDERING. Withholding only the restricted source's own row would
	// print the same value one row down, under a source that permits it, and
	// a reader would have the restricted source's indicator anyway. So a
	// value restricted by ANY contributor is withheld from EVERY record.
	//
	// recordValues keeps what each row named before it was taken away. C-09
	// needs it: an identifier for a value this report may not print has to be
	// computed from the value. It is a local, never a field, so it cannot be
	// serialised by accident.
	recordValues := make([]string, len(rep.Records))
	for i := range rep.Records {
		recordValues[i] = rep.Records[i].Canonical
		if rep.Records[i].Canonical != "" && restricted[rep.Records[i].Canonical] {
			rep.Records[i].Canonical = ""
			rep.Records[i].CanonicalWithheld = true
		}
	}

	// indicators is kept beside the outcomes, in the same order, because the
	// canonical name is needed AFTER it has been withheld — an identifier for
	// a host this report may not name has to be computed from the name.
	indicators := store.Indicators()
	for _, ind := range indicators {
		rep.Outcomes = append(rep.Outcomes, DecideIndicator(ind, in.Registry, in.Policy, in.At, attr))
	}
	// A VALUE NO CONTRIBUTING SOURCE PERMITS NAMING DOES NOT APPEAR AT ALL.
	//
	// The rights gate inside DecideIndicator asks Indicator.Authorizes, which
	// consults LIVE contributors only — deliberately, because an expired
	// contributor contributed nothing to a result computed at `at` and
	// refusing on its account would refuse on grounds that no longer apply.
	//
	// That is right for whether to REFUSE AN OPERATION and wrong for whether
	// to PRINT A NAME. Measured against 9dcb191 through the real process: an
	// indicator whose only contributor was expired AND prohibited derived
	// output fell past the gate to the ordinary expiry abstention, and the
	// report printed its value (FINDING-126). The record row withheld it; the
	// outcome named it one section further down.
	//
	// So the name is withheld whenever NO supplier permits it, whatever the
	// decision turned out to be. Where a permitted source independently
	// supplied the same value the name is its to give, and it is printed.
	for i := range rep.Outcomes {
		o := &rep.Outcomes[i]
		if o.Canonical == "" || nameable[o.Canonical] || !restricted[o.Canonical] {
			continue
		}
		o.Canonical = ""
		// The matched exception names a canonical value too.
		o.Exception = nil
		o.IdentityWithheld = true
	}

	// THE SAME ANTI-LAUNDERING RULE, FOR THE EXPORT AUDIENCE (C-08).
	//
	// Withholding a value on the outcome and printing it one section up, in
	// the record list, withholds it nowhere — which is FINDING-126's shape,
	// arriving through the audience split instead of through expiry. So a
	// value that any outcome marks unexportable is marked unexportable on
	// every record that names it.
	exportRestricted := map[string]bool{}
	for _, o := range rep.Outcomes {
		if o.ExportWithheld && o.Canonical != "" {
			exportRestricted[o.Canonical] = true
		}
	}
	for i := range rep.Records {
		if rep.Records[i].Canonical != "" && exportRestricted[rep.Records[i].Canonical] {
			rep.Records[i].ExportWithheld = true
		}
	}

	// C-09. A host this report may not name still gets an identifier, keyed,
	// under its own MAC purpose.
	//
	// Computed here rather than in DecideIndicator for one reason: the
	// canonical name is needed AFTER it has been taken away, and here both
	// the indicator and the outcome are in hand. `indicators` is in the same
	// order as `rep.Outcomes` because the loop above appended one per entry.
	//
	// When Input.IdentityKey is nil every tag is the empty string, and
	// Limitations says the report carried no key. There is no fallback to an
	// unkeyed digest: a digest of a hostname is a lookup table away from
	// being the hostname, and it would look exactly like a working control.
	for i := range rep.Outcomes {
		o := &rep.Outcomes[i]
		if !o.IdentityWithheld && !o.ExportWithheld {
			continue
		}
		o.OpaqueID = in.IdentityKey.Tag(mac.PurposeWithheldHost, indicators[i].Key.Canonical)
	}
	// The record rows carry the same identifier for the same value, or a
	// reader correlating the two lists learns nothing from either.
	byValue := map[string]string{}
	for i, ind := range indicators {
		if id := rep.Outcomes[i].OpaqueID; id != "" {
			byValue[ind.Key.Canonical] = id
		}
	}
	for i := range rep.Records {
		rec := &rep.Records[i]
		if !rec.CanonicalWithheld && !rec.ExportWithheld {
			continue
		}
		if id, ok := byValue[recordValues[i]]; ok {
			rec.OpaqueID = id
		}
	}

	// THE OPERATOR DOCUMENTS ARE RE-CHECKED AFTER THE RUN.
	//
	// The binding was assembled before the first record and the decisions
	// read in.Registry and in.Policy throughout. A report bound to one state
	// and decided under another would cite a configuration it was not
	// computed from, and nothing in it would look wrong.
	//
	// Unlike the evidence, these two are not snapshotted: a Registry carries
	// maps of grants per source and a deep copy of it would be paid on every
	// run to prevent a mutation no synchronous path in this package performs.
	// They are RE-DIGESTED instead, and a run whose configuration moved is
	// REFUSED rather than marked — internal/evaluation marks, because a
	// measurement whose inputs moved is still a measurement of something, and
	// a proposal report decided under two policies should simply not exist.
	//
	// No synchronous path reaches this today, which is why it is a check and
	// not a fix: it converts an unreachable mismatch into a detected one if
	// the code ever grows a path to it.
	if d := digestJSON("source-registry", in.Registry); d != rep.Binding.RegistryDigest {
		return nil, fmt.Errorf("%w: the source registry changed while the run was in "+
			"progress; the report would be bound to one registry and decided under "+
			"another", ErrIncompleteInput)
	}
	if d := in.Policy.Digest(); d != rep.Binding.PolicyDigest {
		return nil, fmt.Errorf("%w: the proposal policy changed while the run was in "+
			"progress; the report would be bound to one policy and decided under "+
			"another", ErrIncompleteInput)
	}

	sort.Slice(rep.Outcomes, func(i, j int) bool {
		if rep.Outcomes[i].Type != rep.Outcomes[j].Type {
			return rep.Outcomes[i].Type < rep.Outcomes[j].Type
		}
		return rep.Outcomes[i].Canonical < rep.Outcomes[j].Canonical
	})
	return rep, nil
}

// admit runs one record through the admission checks in Build's stated order.
func admit(i int, rec feed.EvidenceRecord, in Input, store *observation.Store) RecordOutcome {
	out := RecordOutcome{
		Index:    i,
		SourceID: safetext.Clip(rec.SourceID, 128),
	}
	refuse := func(r Reason, format string, args ...any) RecordOutcome {
		out.Reason = r
		out.Explanation = safetext.Clip(fmt.Sprintf(format, args...), MaxExplanation)
		return out
	}

	// 1. type
	t := observation.Type(rec.Type)
	switch {
	case !t.Known():
		return refuse(ReasonTypeUnknown, "%q is not an indicator type this build has a vocabulary for",
			safetext.Clip(rec.Type, 32))
	case !t.Supported():
		return refuse(ReasonTypeUnsupported, "%s is a known indicator type that this build does not implement", t)
	}

	// 2. signer authority, before the registry is consulted
	out.Authority = in.Evidence.Signer.MayAssert(rec.SourceID)
	if out.Authority == feed.AuthorityNone {
		return refuse(ReasonSignerNotAuthorised,
			"the document is signed by key %q, which the signer authority does not permit to "+
				"speak for source %q; a signature over a source id is not authority over that source",
			safetext.Clip(in.Evidence.KeyID, 64), safetext.Clip(rec.SourceID, 64))
	}

	// 3. registry
	if _, ok := in.Registry.Source(rec.SourceID); !ok {
		if in.Registry.Retired(rec.SourceID) {
			return refuse(ReasonSourceRetired,
				"source %q was used once and withdrawn; its records must not be re-attributed",
				safetext.Clip(rec.SourceID, 64))
		}
		return refuse(ReasonSourceUnknown,
			"source %q does not appear in the source registry, so nothing establishes whose data this is",
			safetext.Clip(rec.SourceID, 64))
	}

	// 4. syntax. A failure here is a malformed VALUE and never a claim that
	//    the name is suspicious — see SW-P3-05.
	o, err := observation.New(t, rec.Value, rec.SourceID, in.At)
	if err != nil {
		return refuse(ReasonValueInvalid, "record %d does not carry a valid %s: %v", i, t, err)
	}
	out.Canonical = o.Canonical

	// 5. rights to keep it at all
	if ok, why := o.Authorizes(in.Registry, sourceregistry.OpLocalStorage); !ok {
		return refuse(ReasonStorageRefused, "%s", why)
	}

	// 6. the provider's own fields, then the store
	o.SourceRecordID = rec.SourceRecordID
	o.ProviderClassification = rec.ProviderClassification
	o.Classification = observation.Classification(rec.Classification)
	o.State = observation.State(rec.State)
	o.Status = observation.Status(rec.Status)
	if o.Status == "" {
		o.Status = observation.StatusCurrent
	}
	o.Category = rec.Category
	o.SourceFirstSeen = rec.FirstSeen
	o.SourceLastSeen = rec.LastSeen
	o.ExpiresAt = rec.ExpiresAt

	// RAW IS ABSENT BY DEFAULT, AND ITS ABSENCE IS NOT THE WHOLE ANSWER.
	//
	// Three cases, and only one of them keeps anything:
	//
	//   - the field is absent or `none`. Absent means none, so a document
	//     that omits it cannot thereby carry raw bytes. If it sent some
	//     anyway, they are dropped and the drop is REPORTED — a sender that
	//     shipped bytes nobody asked for should be able to see that they
	//     went nowhere.
	//   - `retained`, and the source's registry record authorises local
	//     storage. Kept.
	//   - `retained`, and it does not. Dropped, reported, and the RECORD IS
	//     STILL ADMITTED: the normalised observation had to clear the
	//     local-storage grant separately at step 5, and refusing the whole
	//     record here would throw away evidence over a field that is now
	//     empty.
	//
	// Anything else is a malformed field rather than a retention policy.
	//
	// Note what dropping raw does NOT do: it does not authorise keeping the
	// extracted fields. Those are a separate operation, asked separately,
	// above.
	switch observation.Retention(rec.RawRetention) {
	case "", observation.RetentionNone:
		o.RawRetention = observation.RetentionNone
		out.RawDropped = rec.Raw != ""
	case observation.RetentionRetained:
		o.RawRetention = observation.RetentionRetained
		o.Raw = rec.Raw
		if ok, _ := o.RetentionPermitted(in.Registry); !ok {
			o = o.WithoutRaw()
			out.RawDropped = rec.Raw != ""
		}
	default:
		return refuse(ReasonRecordInvalid,
			"raw_retention is %q; it must be %q, %q, or absent",
			safetext.Clip(rec.RawRetention, 32), observation.RetentionNone, observation.RetentionRetained)
	}

	outcome, err := store.Add(o)
	if err != nil {
		if errors.Is(err, observation.ErrRetentionRefused) {
			return refuse(ReasonRawRefused, "%v", err)
		}
		return refuse(ReasonRecordInvalid, "%v", err)
	}

	out.Admitted = true
	out.Store = outcome
	return out
}

// DecideIndicator answers for one indicator, under one policy, one registry
// and one instant.
//
// Exported so that a harness measuring this rule measures THE rule rather than
// a restatement of it. internal/evaluation.PolicyDetector exists for the same
// reason and says the same thing: a detector that reimplemented the decision
// would be scoring its own copy, and the copy is the thing that drifts.
//
// # PRECEDENCE, IN ORDER, AND WHY
//
//  1. RIGHTS. A refusal here is a defect in the configuration and must surface
//     even where the outcome would have been the same anyway. Reporting the
//     household's exception instead would hide it behind an expected result.
//  2. The household's EXCEPTION. It outranks every source; no amount of
//     corroboration from strangers overrides the person whose network it is.
//  3. Whether anything is LIVE at all, with expiry and withdrawal separated
//     from "there was never anything".
//  4. CONFLICT. Sources disagreeing is reported, never resolved.
//  5. The NAME's signals. A signal is not evidence, so it cannot produce a
//     proposal; it can and does prevent one.
//  6. The policy's independent-source THRESHOLD.
//
// A matched exception is recorded on the outcome whichever reason wins, so an
// operator is never left wondering whether theirs was seen.
func DecideIndicator(ind observation.Indicator, reg *sourceregistry.Registry, p *Policy, at time.Time, attr Attribution) Outcome {
	in := Input{Registry: reg, Policy: p, At: at}

	// 1. RIGHTS FIRST, AND BEFORE ANYTHING DERIVED EXISTS.
	//
	// This block runs before the corroboration, the signals, the conflict
	// flag and the exception match are computed, and it returns an Outcome
	// that never held any of them. That ordering is the control: the
	// superseded implementation filled every derived field first and then
	// returned a refusal carrying all of it, so a report said "putting a
	// result derived from these sources in a report is not authorised" and
	// printed the result underneath (FINDING-120).
	//
	// Only `current` is read here, because the rights question is about live
	// contributors and cannot be asked without knowing who they are. Reading
	// the store is not enrichment and not output.
	current := ind.Current(at)
	if len(current) > 0 {
		for _, gate := range []struct {
			op     sourceregistry.Operation
			reason Reason
			why    string
		}{
			{sourceregistry.OpEnrichment, ReasonEnrichmentRefused,
				"combining these sources is not authorised"},
			{sourceregistry.OpDerivedOutput, ReasonDerivedOutputRefused,
				"putting a result derived from these sources in a report is not authorised"},
		} {
			if gate.op == sourceregistry.OpDerivedOutput && in.Policy != nil && in.Policy.HouseholdLocalUse {
				// Household-only run: nothing derived leaves the house, so
				// derived_output is not the question. Export stays withheld
				// per source below (ExportWithheld) and at publish time.
				continue
			}
			r := ind.Authorizes(in.Registry, gate.op, at)
			if r.Permitted {
				continue
			}
			return Outcome{
				Type:             string(ind.Key.Type),
				Decision:         DecisionRefuse,
				Reason:           gate.reason,
				IdentityWithheld: true,
				RefusedSources:   refusingSources(current, in.Registry, gate.op),
				// Built only from the registry's own vocabulary. Rights
				// refusals name a source id and an operation and never an
				// indicator value; joinBounded is still applied, because a
				// source id came out of a signed document somebody else
				// wrote.
				Explanation: safetext.Clip(gate.why+": "+joinBounded(r.Refusals), MaxExplanation),
			}
		}
	}

	// --- past this line the operation is authorised, and deriving may begin ---

	out := Outcome{
		Type:      string(ind.Key.Type),
		Canonical: ind.Key.Canonical,
	}
	corr := ind.Corroborate(in.Registry, at)
	out.Sources = liveSources(current)
	out.IndependentSources = append([]string(nil), corr.Independent...)
	out.UnestablishedSources = append([]string(nil), corr.Unestablished...)
	out.Signals = signalsOf(current)
	out.ExportWithheld = !ind.Exportable(in.Registry, at).Permitted
	out.Conflicted = ind.Conflicted(at)

	// C-19. An explicit retraction by a source entitled to be counted is a
	// disagreement, not an absence, and until this was written it was
	// invisible: a withdrawn source drops out of the live set, Corroboration
	// records it, and nothing read that field unless EVERY source had
	// withdrawn. Two sources asserting and one retracting proposed a block
	// and said nothing about the retraction.
	//
	// OpEnrichment is the operation checked because it is this tree's
	// spelling of "may be counted towards a decision" — see the C-06 row of
	// ORDER_8_CROSSWALK.md — and it is the same gate a source must pass to
	// support a block.
	out.RetractedBy = ind.RetractedBy(in.Registry, sourceregistry.OpEnrichment, at, in.RetractionWindow)
	if len(out.RetractedBy) > 0 {
		out.Conflicted = true
	}

	if m, ok := in.Policy.MatchException(ind.Key.Canonical); ok {
		out.Exception = &AppliedException{
			Canonical: m.Exception.canonical,
			Scope:     m.Exception.Scope,
			Note:      safetext.Clip(m.Exception.Note, MaxNoteBytes),
		}
	}

	decideWith := func(d Decision, r Reason, format string, args ...any) Outcome {
		out.Decision = d
		out.Reason = r
		out.Explanation = safetext.Clip(fmt.Sprintf(format, args...), MaxExplanation)
		if d == DecisionPropose {
			out.Scope = in.Policy.ProposalScope
		}
		return out
	}

	// 2. the household
	if out.Exception != nil {
		return decideWith(DecisionRefuse, ReasonUserException,
			"excepted by the household: %s at scope %s", out.Exception.Canonical, out.Exception.Scope)
	}

	// 3. liveness, with the two lapse modes named separately
	if len(current) == 0 {
		switch {
		case len(corr.ExpiredOnly) > 0 && len(corr.Withdrawn) == 0:
			return decideWith(DecisionAbstain, ReasonExpiredOnly,
				"every supporting observation had expired by %s", at.UTC().Format(time.RFC3339))
		case len(corr.Withdrawn) > 0 && len(corr.ExpiredOnly) == 0:
			return decideWith(DecisionAbstain, ReasonWithdrawnOnly,
				"every supporting source has withdrawn its observation")
		default:
			return decideWith(DecisionAbstain, ReasonNoLiveEvidence,
				"nothing supports this indicator at %s", at.UTC().Format(time.RFC3339))
		}
	}

	// 4. disagreement
	if out.Conflicted {
		if len(out.RetractedBy) > 0 {
			return decideWith(DecisionAbstain, ReasonConflict,
				"one or more sources have retracted what they said about this while others still "+
					"assert it; this build does not take a side. Retracted by: %s", joinBounded(out.RetractedBy))
		}
		return decideWith(DecisionAbstain, ReasonConflict,
			"current sources disagree about what this is; this build does not take a side")
	}

	// 5. the name itself
	if s, found := reviewSignal(out.Signals); found {
		return decideWith(DecisionAbstain, ReasonNameRequiresReview,
			"the written form carried %s, which is a property of the NAME and is not evidence "+
				"that it is malicious", s)
	}

	// 6. the threshold
	eligible := map[string]bool{}
	for _, id := range corr.Independent {
		eligible[id] = true
	}
	if in.Policy.AcceptUnestablishedIndependence {
		for _, id := range corr.Unestablished {
			eligible[id] = true
		}
	}

	// AGGREGATED CLAIMS ARE EVIDENCE AND ARE NOT INDEPENDENT CONFIRMATION.
	//
	// See Attribution. A claim that reached this build only through a signer
	// the operator approved to REPUBLISH it arrived through that signer's
	// channel, whatever the registry says about lineage between the sources
	// themselves. One signer republishing two upstreams is one attestation,
	// and counting it as two is the inflation the whole provenance model
	// exists to prevent, arriving one layer above the layer that prevents it
	// (FINDING-122).
	adverse := map[string]bool{}
	aggregatedAdverse := map[string]bool{}
	for _, e := range current {
		o := e.Observation
		if o.Classification != observation.ClassMalicious && o.Classification != observation.ClassSuspicious {
			continue
		}
		if attr.Aggregated(o.SourceID) {
			// Recorded, reported, and not counted. It is support; it is not
			// the second voice the threshold is asking for.
			aggregatedAdverse[o.SourceID] = true
			continue
		}
		if !eligible[o.SourceID] {
			continue
		}
		adverse[o.SourceID] = true
	}
	out.AdverseSources = sortedKeys(adverse)
	out.AggregatedSources = sortedKeys(aggregatedAdverse)

	// Counted per SOURCE and never per record. One provider publishing the
	// same indicator under three record ids is one source, and counting the
	// records would reintroduce the inflation the provenance model exists to
	// prevent, one layer above it.
	//
	// C-01: and never per SOURCE either, where their lineage says otherwise.
	// Independence is a property of origins. Collapsing already folded a
	// source into an upstream that is ALSO reporting; this is the case it
	// cannot see, where the shared upstream reports nothing because it is a
	// corpus or a submission queue that this registry holds no record for.
	// The count is the largest family of adverse sources whose origin sets
	// are pairwise disjoint, which is at most the number of sources and is
	// the number the threshold is compared against.
	groups := in.Registry.MaxDisjointOrigins(out.AdverseSources)
	out.IndependentOriginGroups = groups.Count
	out.SharedOrigins = groups.Shared

	for _, id := range out.AdverseSources {
		if s, ok := in.Registry.Source(id); ok && s.Authoritative() {
			out.AuthoritativeSources = append(out.AuthoritativeSources, id)
		}
	}

	need := *in.Policy.MinIndependentSources
	if out.IndependentOriginGroups < need {
		// C-07. One authoritative source may stand in for the threshold, and
		// only because the HOUSEHOLD said so. The registry's tier is a claim
		// about a provider; acting on one source is a decision about this
		// network's risk, and a registry must not be able to grant itself
		// permission to take it.
		//
		// It sits below the ordinary threshold rather than above it, so a
		// proposal that met the threshold on its own evidence is still
		// reported as corroborated. The tier is a fallback, not a relabelling
		// of every proposal an authoritative source takes part in.
		if in.Policy.AcceptAuthoritativeAlone && len(out.AuthoritativeSources) > 0 {
			return decideWith(DecisionPropose, ReasonAuthoritativeSource,
				"%d independent voice(s) of %d required, and %s holds the registry's authoritative "+
					"tier, which this policy accepts alone (accept_authoritative_alone)",
				out.IndependentOriginGroups, need, joinBounded(out.AuthoritativeSources))
		}
		if len(out.SharedOrigins) > 0 && len(out.AdverseSources) >= need {
			return decideWith(DecisionAbstain, ReasonInsufficientSupport,
				"%d adverse source(s) amount to %d independent voice(s) of %d required: they draw on "+
					"shared origin(s) %s, and a corpus republished twice is one observation delivered "+
					"twice",
				len(out.AdverseSources), out.IndependentOriginGroups, need, joinBounded(out.SharedOrigins))
		}
		// Two different shortfalls, two different reasons, because the
		// operator's next move differs. "Not enough sources said so" is
		// answered by more evidence; "the sources that said so all came
		// through one republisher" is answered by granting that signer
		// `asserts_source_ids` for them, or by obtaining the claim through
		// another channel.
		if len(out.AdverseSources)+len(out.AggregatedSources) >= need {
			return decideWith(DecisionAbstain, ReasonAggregatedNotIndependent,
				"%d independent adverse source(s) of %d required; %d further adverse "+
					"source(s) reached this build only through a signer approved to "+
					"REPUBLISH them, which is authority to carry a claim and not "+
					"independent confirmation of it",
				len(out.AdverseSources), need, len(out.AggregatedSources))
		}
		return decideWith(DecisionAbstain, ReasonInsufficientSupport,
			"%d adverse supporting source(s) of %d required (independent=%d, unestablished=%d, aggregated=%d)",
			len(out.AdverseSources), need, len(corr.Independent), len(corr.Unestablished),
			len(out.AggregatedSources))
	}
	return decideWith(DecisionPropose, ReasonCorroborated,
		"%d adverse supporting source(s) in %d independent origin group(s), %d required",
		len(out.AdverseSources), out.IndependentOriginGroups, need)
}

// reviewSignal reports the strongest name signal that prevents a proposal.
//
// Fixed precedence, so that a name carrying both always reports the same
// reason. Invisible characters come first because they are the stronger
// statement: a mixed-script name at least LOOKS like what it is, whereas a
// name whose written form contained removed characters does not. This mirrors
// internal/policy.Decide, which makes the same choice for the v1 plan path.
//
// Every other signal internal/domain produces — non_ascii, punycode_input,
// single_non_latin_script — changes nothing here, deliberately. Most of the
// internationalised internet is ordinary.
func reviewSignal(signals []string) (string, bool) {
	for _, want := range []domain.Signal{domain.SignalInvisibleCharacter, domain.SignalMixedScript} {
		for _, s := range signals {
			if s == string(want) {
				return s, true
			}
		}
	}
	return "", false
}

// signalsOf is the union of the signals over every live observation.
//
// A union, not the first entry's: two sources can write the same canonical
// name differently, and only one of them may have used an invisible
// character. Taking one entry's signals would make the answer depend on which
// source happened to sort first.
func signalsOf(entries []observation.Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, s := range e.Observation.Signals {
			if seen[string(s)] {
				continue
			}
			seen[string(s)] = true
			out = append(out, string(s))
		}
	}
	sort.Strings(out)
	return out
}

// refusingSources names the live contributors whose recorded grant refuses op.
//
// It is the actionable half of a rights refusal, and it is the ONLY list a
// refusal carries: a source id is something the operator typed into their own
// registry, and telling them which one to edit is the point of reporting the
// refusal at all. It is deliberately not the complementary list — naming the
// sources that DID permit would say how many contributors an indicator has,
// which is a fact about the combination this build was not authorised to make.
func refusingSources(entries []observation.Entry, reg *sourceregistry.Registry, op sourceregistry.Operation) []string {
	refusing := map[string]bool{}
	for _, e := range entries {
		if ok, _ := e.Observation.Authorizes(reg, op); !ok {
			refusing[e.Observation.SourceID] = true
		}
	}
	out := make([]string, 0, len(refusing))
	for id := range refusing {
		out = append(out, safetext.Clip(id, 128))
	}
	sort.Strings(out)
	return out
}

// sourceMayBeNamedInOutput reports whether a source's own grant permits its
// indicator value appearing in the record list.
//
// Used for the RECORD list, per record and per source, which is a different
// question from the one Indicator.Authorizes answers. See Build.
//
// # BOTH OPERATIONS, AND THE COST OF THAT
//
// It asks for `derived_output` AND `enrichment`, and requires both. The first
// is obvious. The second is the deliberately strict half and it is worth
// naming the case it is strict about: a source that prohibits only
// `enrichment` permits its own data being put in front of someone, so a
// single-source indicator of its own could legitimately be printed, and this
// withholds it anyway.
//
// It is one rule rather than a conditional one because the alternative is
// deciding, per row, whether the surrounding rows make the list a join. Two
// records naming one value, from two sources, adjacent and index-keyed, IS
// the combination `enrichment` governs; a rule that permitted the first row
// and forbade the second would depend on which order the document listed
// them in.
//
// The cost is bounded and the operator is not left blind: a withheld row
// still carries the index, the source id, the admission outcome and
// `canonical_withheld`, which is everything needed to find the grant and
// change it.
func sourceMayBeNamedInOutput(reg *sourceregistry.Registry, sourceID string) bool {
	if reg == nil {
		return false
	}
	src, ok := reg.Source(sourceID)
	if !ok {
		return false
	}
	for _, op := range []sourceregistry.Operation{
		sourceregistry.OpDerivedOutput, sourceregistry.OpEnrichment,
	} {
		if permitted, _ := src.Authorizes(op); !permitted {
			return false
		}
	}
	return true
}

func liveSources(entries []observation.Entry) []string {
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Observation.SourceID] = true
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// joinBounded renders a list of refusals into one bounded string.
func joinBounded(in []string) string {
	var b []byte
	for i, s := range in {
		if i > 0 {
			b = append(b, "; "...)
		}
		b = append(b, s...)
		if len(b) > MaxExplanation {
			break
		}
	}
	return string(b)
}

// strictUnmarshal decodes JSON refusing unknown fields and trailing data.
//
// Unknown fields are refused because a field this build does not understand
// may qualify what the operator meant, and acting on a policy that is not the
// one they wrote is worse than refusing to act.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// A second Decode required to return io.EOF, rather than dec.More():
	// More() derives its answer from a peek that swallows the read error it
	// may encounter, so it cannot distinguish a clean end from input that is
	// not JSON at all.
	var rest json.RawMessage
	switch err := dec.Decode(&rest); {
	case errors.Is(err, io.EOF):
		return nil
	case err == nil:
		return errors.New("a second document follows; this file holds exactly one")
	default:
		return errors.New("the bytes after the document are not a document either")
	}
}

// digestJSON is the digest of a labelled value. The label is part of the
// input so two different kinds of thing cannot collide by encoding
// identically.
func digestJSON(label string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "undigestable:" + err.Error()
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
