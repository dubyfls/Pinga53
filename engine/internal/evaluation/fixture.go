// SPDX-License-Identifier: AGPL-3.0-only

// Package evaluation measures whether a candidate decision rule catches more
// than a named baseline without proposing more legitimate activity.
//
// # What a result from this package is, and is not
//
// It is a measurement over fixtures held in this repository. Every fixture
// here is SYNTHETIC — written for this test suite, using documentation-reserved
// names — and a synthetic result is not a product claim. It cannot be: the
// fixtures were written by the same project that wrote the detector, which is
// the tautology docs/EVALUATION_PROTOCOL.md §3 exists to forbid.
//
// What it IS for is regression. A change to a decision rule either improves
// these numbers or does not, and a harness that can show both is the
// difference between "the tests still pass" and "this change was an
// improvement". Every report this package emits says so in its own output, so
// that a number cannot be lifted out of context without the caveat coming
// with it.
//
// # The definitions are the protocol's, not convenient ones
//
// Precision, recall and coverage are used loosely everywhere and are worth
// nothing used loosely. docs/EVALUATION_PROTOCOL.md §5.1 fixes them, and this
// package implements those definitions rather than easier ones:
//
//   - Precision is over ADDITIONAL proposals — the candidate proposes and the
//     baseline does not — that received a label. Unlabelled proposals are
//     excluded from the ratio and reported beside it.
//   - Recall is over labelled-malicious cases the harness actually saw. Never
//     over "all scams", which is not a set anyone can enumerate.
//   - Coverage is the fraction of cases any label could be obtained for, and
//     it BOUNDS the other two.
//
// Every proportion carries a Wilson 95% interval, and a stratum with fewer
// than ten labelled observations is reported as counts with no rate at all.
package evaluation

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/observation"
)

// SchemaVersion is the only fixture-set schema this build understands.
const SchemaVersion = 1

// MaxSetBytes bounds a fixture file.
//
// The fixtures in this repository are small and are written by this project,
// so nothing hostile is expected here. The bound exists anyway because "the
// input is trusted" is an assumption about the caller rather than about the
// code, and a loader with no bound is one refactor away from being pointed at
// something else. 8 MiB is far above any fixture set a person would write and
// far below anything that would exhaust memory.
const MaxSetBytes = 8 << 20

// Label is the ground truth for one case.
type Label string

// The label vocabulary.
const (
	// LabelMalicious — an independent labeller adjudicated it harmful.
	LabelMalicious Label = "malicious"
	// LabelLegitimate — an independent labeller adjudicated it not harmful.
	LabelLegitimate Label = "legitimate"
	// LabelUnknown — no qualifying labeller would adjudicate it. A first-class
	// outcome, reported as its own number and NEVER redistributed into the
	// other two. Treating unlabelled data as negative is the single easiest
	// way to manufacture a good precision figure.
	LabelUnknown Label = "unknown"
)

// ValidLabels is the closed vocabulary.
var ValidLabels = []Label{LabelMalicious, LabelLegitimate, LabelUnknown}

// Provenance says where a fixture came from.
//
// It is required. A fixture set with no stated provenance cannot be assessed
// for the leakage and rights questions that decide whether its results mean
// anything, and "we wrote these ourselves" is a perfectly good answer that
// simply has to be said out loud.
type Provenance string

// The provenance vocabulary.
const (
	// ProvenanceSynthetic — written for this repository. Carries no rights
	// question and no real-world validity.
	ProvenanceSynthetic Provenance = "synthetic"
	// ProvenanceTransformed — derived from real data, altered so that the
	// original is not recoverable. Carries the original's rights question.
	ProvenanceTransformed Provenance = "transformed"
	// ProvenancePublicDomain — published without restriction.
	ProvenancePublicDomain Provenance = "public-domain"
	// ProvenanceLicensed — used under a licence, which must be named.
	ProvenanceLicensed Provenance = "licensed"
)

// ValidProvenances is the closed vocabulary.
var ValidProvenances = []Provenance{
	ProvenanceSynthetic, ProvenanceTransformed, ProvenancePublicDomain, ProvenanceLicensed,
}

// Partition separates the cases a rule may be developed against from the cases
// it is judged on.
//
// No tuning exists in ScamWall today, so nothing currently depends on this.
// It is here because the moment a threshold is chosen by looking at results,
// a partition that was not recorded from the start cannot be reconstructed,
// and the study is unrecoverable.
type Partition string

// The partition vocabulary.
const (
	PartitionDevelopment Partition = "development"
	PartitionHeldOut     Partition = "held-out"
)

// ValidPartitions is the closed vocabulary.
var ValidPartitions = []Partition{PartitionDevelopment, PartitionHeldOut}

// FeedClaim is what a signed feed asserts about a case.
//
// It is the input the current ScamWall decision rule actually consumes, so a
// fixture that omits it cannot exercise that rule.
type FeedClaim struct {
	Action     feed.Action     `json:"action"`
	Confidence feed.Confidence `json:"confidence"`
	Category   string          `json:"category,omitempty"`
}

// CaseObservation is one source's statement about a case, in fixture form.
//
// It exists so that the provenance-bearing fixture families — repeated
// observations from one source, corroboration from independent sources,
// aggregator and upstream, corrections, expiry, conflicting classifications —
// are cases in this harness rather than only unit tests elsewhere. A detector
// that reads corroboration can then be measured against one that does not.
type CaseObservation struct {
	SourceID       string                     `json:"source_id"`
	SourceRecordID string                     `json:"source_record_id,omitempty"`
	Classification observation.Classification `json:"classification"`
	State          observation.State          `json:"state"`
	Status         observation.Status         `json:"status,omitempty"`
	ExpiresAt      *time.Time                 `json:"expires_at,omitempty"`
}

// Case is one thing to decide about, and the truth about it.
type Case struct {
	ID    string           `json:"id"`
	Type  observation.Type `json:"type"`
	Value string           `json:"value"`
	// Family names the fixture family, so results can be read per family as
	// well as pooled. A pooled number hides a rule that is excellent on
	// ordinary names and catastrophic on internationalised ones.
	Family string `json:"family"`
	// Category is the scam category, where the case has one.
	Category string `json:"category,omitempty"`
	Label    Label  `json:"label"`
	// LabelBasis records WHY the label is what it is. "Reported as spam" and
	// "observed serving a credential-harvesting page" are different claims and
	// must not be pooled; recording the basis is what keeps them apart.
	LabelBasis string `json:"label_basis"`
	// Provenance overrides the set's, for a set that mixes.
	Provenance   Provenance        `json:"provenance,omitempty"`
	FeedClaim    *FeedClaim        `json:"feed_claim,omitempty"`
	Observations []CaseObservation `json:"observations,omitempty"`
}

// FixtureSet is a versioned, named collection of cases.
type FixtureSet struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"fixture_set_id"`
	// Version is the fixture set's own version. A result is reproducible only
	// against the version it was computed from, and this is what names it.
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Provenance  Provenance `json:"provenance"`
	// ProvenanceNote is required. For a synthetic set it says what the names
	// are drawn from; for anything else it says what the rights position is.
	ProvenanceNote string    `json:"provenance_note"`
	Partition      Partition `json:"partition"`
	// Baseline names the domains a list-shaped baseline already covers, so
	// that "additional" has something to be additional TO. See §2.1: a
	// baseline that is described rather than named makes every quantity in §5
	// uninterpretable.
	BaselineID      string   `json:"baseline_id"`
	BaselineCovers  []string `json:"baseline_covers"`
	BaselineNote    string   `json:"baseline_note"`
	Cases           []Case   `json:"cases"`
	UnsupportedNote string   `json:"unsupported_note,omitempty"`

	// bytesDigest is the digest of the exact bytes this set was parsed from.
	//
	// Unexported, and therefore not settable from the document: a fixture file
	// that could assert its own digest would be asserting its own identity,
	// which is the thing the digest exists to establish independently.
	bytesDigest string
	// parsedDigest is the digest of the DECODED value as it stood the instant
	// parsing finished. See BytesDigest.
	parsedDigest string
}

// BytesDigest is the digest of the exact bytes the set was parsed from, or
// digestMutated when the set no longer holds what those bytes decoded to.
//
// Empty for a FixtureSet that was constructed in memory rather than parsed,
// which is why Improved refuses a comparison when it is absent instead of
// treating two empty digests as a match.
//
// # WHY THE VALUE IS RE-CHECKED AND NOT JUST RETURNED
//
// Every field a run reads — Cases above all — is EXPORTED and therefore
// settable after ParseSet returns. The digest is over the bytes and is taken
// once, so the superseded implementation would hand back the original digest
// for a set whose cases had since been replaced: a binding asserting that the
// run was over file X while the run was over something the file never said
// (FINDING-116). Nothing in the result said otherwise, and a comparison
// against a genuine run of X would have been accepted.
//
// Unexporting the fields was rejected: Case and FixtureSet are constructed
// directly by this package's own tests and by any caller building a set in
// memory, and that is a legitimate use — such a set simply has no bytes digest
// at all. What must not happen is a set claiming the identity of bytes it no
// longer matches, so that specific case is DETECTED rather than prevented. The
// marker is not a digest this package produces, so Reproducible and
// comparableWith both refuse it; Reproducible says why in its own words.
func (s *FixtureSet) BytesDigest() string {
	if s.bytesDigest == "" {
		return ""
	}
	if digestValue(parsedValueLabel, s) != s.parsedDigest {
		return digestMutated
	}
	return s.bytesDigest
}

// parsedValueLabel labels the digest of the decoded fixture value. It is
// distinct from the label used for the raw bytes so that the two can never
// collide.
const parsedValueLabel = "fixture-set-value"

// digestMutated is what BytesDigest reports for a set that was modified after
// it was parsed.
//
// A value, not an empty string and not the original digest: "nobody supplied
// one" and "the one supplied is no longer true" are different facts, and only
// the second is a defect in the caller.
const digestMutated = "mutated-after-parse"

// Errors returned when loading a fixture set.
var (
	ErrSchemaVersion = errors.New("unsupported fixture schema version")
	ErrInvalidSet    = errors.New("fixture set is invalid")
	ErrSetTooLarge   = errors.New("fixture set exceeds the maximum accepted size")
)

// LoadSet reads and validates a fixture set.
func LoadSet(path string) (*FixtureSet, error) {
	f, err := os.Open(path) //nolint:gosec // a fixture path chosen by the caller
	if err != nil {
		return nil, fmt.Errorf("open fixture set: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err == nil && info.Size() > MaxSetBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrSetTooLarge, info.Size(), MaxSetBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read fixture set: %w", err)
	}
	if int64(len(b)) > MaxSetBytes {
		return nil, fmt.Errorf("%w: max %d", ErrSetTooLarge, MaxSetBytes)
	}
	return ParseSet(b)
}

// ParseSet validates a fixture set held in memory.
//
// Unknown fields are refused. A fixture set is a claim about ground truth, and
// a field this build does not understand may carry a qualification on that
// claim; ignoring it silently would mean measuring against different truth
// than the one that was written down.
func ParseSet(b []byte) (*FixtureSet, error) {
	// Ambiguity is checked BEFORE the decode, over the raw tokens. After the
	// decode the duplicate is already gone: encoding/json keeps the last value
	// and reports nothing, so there would be no evidence left to check.
	if err := checkDuplicates(b); err != nil {
		return nil, fmt.Errorf("parse fixture set: %w", err)
	}
	var s FixtureSet
	if err := decodeExactlyOne(b, &s); err != nil {
		return nil, fmt.Errorf("parse fixture set: %w", err)
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSchemaVersion, s.SchemaVersion, SchemaVersion)
	}
	if problems := s.Validate(); len(problems) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSet, strings.Join(problems, "; "))
	}
	// Over the bytes as they arrived, before any interpretation of them.
	s.bytesDigest = digestBytes("fixture-set", b)
	// And over what those bytes decoded to, so that a later edit to an
	// exported field can be told from none. Taken last, so it covers the set
	// exactly as a caller first receives it.
	s.parsedDigest = digestValue(parsedValueLabel, &s)
	return &s, nil
}

// The bounds on one diagnostic.
//
// # WHY A DIAGNOSTIC NEEDS A BOUND AT ALL
//
// Strict decoding refuses a hostile KEY without echoing it (see strict.go).
// That was once read as meaning the strict path needed no bound of its own,
// which was wrong in both halves: the echo suppression had a hole in it
// (FINDING-112) and the COUNT of duplicate-key findings was caller-controlled
// regardless of how short each one was (FINDING-114). strict.go now applies
// the same two bounds declared here, to the same constants.
//
// Every check below deals in caller-controlled VALUES instead, and
// those reach the returned error. Escaping them is not sufficient on its own:
// an 8 MiB fixture — the largest MaxSetBytes permits — can hold thousands of
// invalid records, and the superseded implementation formatted every one of
// them into a single joined string. Measured against it, the error came out at
// about 1.2x the size of the document: 4,235,549 bytes from a 3.5 MB file, and
// by extrapolation roughly 10 MB from a file at the limit. That error is
// returned to a caller, printed by an operator, and written to a log, and none
// of those has any use for ten megabytes (FINDING-111).
//
// Three bounds, each answering a different way the size can run away:
//
//   - maxDiagnosticValueBytes bounds ONE value, applied AFTER escaping so that
//     the bound is on what is printed rather than on what arrived.
//   - maxReportedProblems bounds how many problems the diagnostic lists.
//   - maxCollectedProblems bounds how many are built in memory at all, so that
//     a document full of errors is not first rendered and then discarded.
//
// The count of what was left out is always reported, so the bound never looks
// like a clean bill of health.
const (
	maxDiagnosticValueBytes = 64
	maxReportedProblems     = 50
	maxCollectedProblems    = 1000
)

// boundedValue renders a caller-controlled value for a diagnostic.
//
// truncate escapes first and cuts second, which is the order that matters: a
// bound applied before escaping bounds the input, and one escaped byte can
// become six printed ones. The quotes are added here rather than by %q because
// %q would escape the escapes.
//
// The value is included at all — rather than being replaced by its schema path
// alone — because the path and the vocabulary name WHERE and WHAT WAS WANTED,
// and only the value tells an author that they typed "maliciuos". That is the
// ordinary case this file is read in; the bound and the escaping are what make
// including it safe in the other one.
func boundedValue(v string) string {
	return `"` + truncate(v, maxDiagnosticValueBytes) + `"`
}

// Validate reports the problems with the set, bounded.
//
// It reports at most maxReportedProblems of them, sorted, followed by a count
// of any it did not list. The sort happens BEFORE the cut, so which problems
// are shown is a property of the set and not of the order a walk happened to
// visit it in.
func (s *FixtureSet) Validate() []string {
	var problems []string
	total := 0
	add := func(format string, args ...any) {
		total++
		if len(problems) < maxCollectedProblems {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	if strings.TrimSpace(s.ID) == "" {
		add("fixture_set_id is empty")
	}
	if strings.TrimSpace(s.Version) == "" {
		add("version is empty; a result is only reproducible against a named version")
	}
	if !containsProvenance(ValidProvenances, s.Provenance) {
		add("provenance %s is not one of %s", boundedValue(string(s.Provenance)), joinProvenances())
	}
	if strings.TrimSpace(s.ProvenanceNote) == "" {
		add("provenance_note is empty; a stated provenance with no note says where the data came from but not what that means for using it")
	}
	if !containsPartition(ValidPartitions, s.Partition) {
		add("partition %s is not one of %s", boundedValue(string(s.Partition)), joinPartitions())
	}
	if strings.TrimSpace(s.BaselineID) == "" {
		add("baseline_id is empty; a baseline that is described rather than named makes `additional` mean nothing")
	}
	if len(s.Cases) == 0 {
		add("the set has no cases")
	}

	seen := map[string]bool{}
	for i, c := range s.Cases {
		at := fmt.Sprintf("cases[%d]", i)
		if strings.TrimSpace(c.ID) == "" {
			add("%s.id is empty", at)
		} else if seen[c.ID] {
			add("%s.id %s is used twice", at, boundedValue(c.ID))
		}
		seen[c.ID] = true

		if !c.Type.Known() {
			add("%s.type %s is not in the indicator vocabulary", at, boundedValue(string(c.Type)))
		}
		if strings.TrimSpace(c.Value) == "" {
			add("%s.value is empty", at)
		}
		if !containsLabel(ValidLabels, c.Label) {
			add("%s.label %s is not one of %s", at, boundedValue(string(c.Label)), joinLabels())
		}
		if strings.TrimSpace(c.LabelBasis) == "" {
			add("%s.label_basis is empty; a label with no recorded basis cannot be pooled with one that has a different basis", at)
		}
		if strings.TrimSpace(c.Family) == "" {
			add("%s.family is empty; results are reported per family and an unfamilied case cannot appear in one", at)
		}
		if c.Provenance != "" && !containsProvenance(ValidProvenances, c.Provenance) {
			add("%s.provenance %s is not one of %s", at, boundedValue(string(c.Provenance)), joinProvenances())
		}
		for j, o := range c.Observations {
			op := fmt.Sprintf("%s.observations[%d]", at, j)
			if strings.TrimSpace(o.SourceID) == "" {
				add("%s.source_id is empty; an observation with no source is not evidence", op)
			}
		}
	}

	sort.Strings(problems)
	if len(problems) > maxReportedProblems {
		problems = problems[:maxReportedProblems]
	}
	if omitted := total - len(problems); omitted > 0 {
		// Appended after the sort so that it is last, and phrased as a count
		// rather than as an ellipsis: a reader who acts on a bounded list
		// without knowing it was bounded will believe they have fixed
		// everything.
		problems = append(problems, fmt.Sprintf(
			"and %d further problem(s) were found and are not listed; this "+
				"diagnostic is bounded, so a document full of errors cannot "+
				"produce an unbounded error", omitted))
	}
	return problems
}

// CaseProvenance returns the provenance in force for a case.
func (s *FixtureSet) CaseProvenance(c Case) Provenance {
	if c.Provenance != "" {
		return c.Provenance
	}
	return s.Provenance
}

func containsLabel(hay []Label, n Label) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func containsProvenance(hay []Provenance, n Provenance) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func containsPartition(hay []Partition, n Partition) bool {
	for _, h := range hay {
		if h == n {
			return true
		}
	}
	return false
}

func joinLabels() string {
	out := make([]string, len(ValidLabels))
	for i, l := range ValidLabels {
		out[i] = string(l)
	}
	return strings.Join(out, ", ")
}

func joinProvenances() string {
	out := make([]string, len(ValidProvenances))
	for i, p := range ValidProvenances {
		out[i] = string(p)
	}
	return strings.Join(out, ", ")
}

func joinPartitions() string {
	out := make([]string, len(ValidPartitions))
	for i, p := range ValidPartitions {
		out[i] = string(p)
	}
	return strings.Join(out, ", ")
}
