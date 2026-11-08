// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// SemanticsVersion is the version of this package's SCORING RULES.
//
// # WHY A NUMBER AND NOT A DATE OR A COMMIT
//
// Two results are comparable only if the same questions were asked of both. A
// change to what counts as a true positive, or to which cases enter a
// denominator, silently changes every rate in this package — and a stored
// result from before the change looks exactly like one from after it. Nothing
// in the numbers says otherwise, so the number has to be carried.
//
// History:
//
//	1  the scoring as ORDER 5 first built it.
//	2  invalid-observation cases are excluded from Counts.Cases and therefore
//	   from every rate (FINDING-92). Denominators computed under 1 include
//	   cases that 2 excludes, so a 1 result and a 2 result are NOT comparable
//	   even over identical fixtures.
const SemanticsVersion = 2

// Binding is the complete identity of the inputs a result was computed from.
//
// # WHY EVERY FIELD IS HERE
//
// The superseded Result identified its inputs by NAME: a fixture set id and
// version, both self-declared strings inside the fixture file, and a detector
// name that for a list was "label (N entries)". None of that is a binding.
// Two fixture files with different cases can declare the same id and version;
// two lists with different contents can share a label and a count. A result
// carrying only those could be compared against a run that shared nothing with
// it, and the comparison would report an improvement.
//
// Each field below is a digest of CONTENT, not an assertion about it.
type Binding struct {
	// FixtureDigest is over the exact bytes the fixture set was parsed from,
	// captured at parse time. Not over the decoded value: two different files
	// can decode to equal values, and it is the file that is cited.
	FixtureDigest string `json:"fixture_digest"`
	// FixtureSetID and FixtureSetVersion are what the file CLAIMS about
	// itself. Kept for readability; never relied on for comparability.
	FixtureSetID      string    `json:"fixture_set_id"`
	FixtureSetVersion string    `json:"fixture_set_version"`
	Partition         Partition `json:"partition"`

	// RegistryDigest is over the registry's canonical contents. Empty when no
	// registry was supplied, which RegistryState distinguishes from a registry
	// that happened to digest to nothing.
	RegistryDigest string `json:"registry_digest"`
	// RegistryState is "absent" or "present". A run with no registry cannot
	// establish independence at all, so it is not comparable with one that
	// could, and that difference must be visible without interpreting a digest.
	RegistryState string `json:"registry_state"`

	// BaselineName and BaselineDigest identify what the candidate was measured
	// AGAINST. "Additional" is defined relative to the baseline, so two runs
	// with different baselines measure different quantities under one word.
	BaselineName   string `json:"baseline_name"`
	BaselineDigest string `json:"baseline_digest"`
	// CandidateName and CandidateDigest identify the configuration measured.
	// These are EXPECTED to differ between two runs being compared; that is
	// what the comparison is for.
	CandidateName   string `json:"candidate_name"`
	CandidateDigest string `json:"candidate_digest"`

	// SemanticsVersion is the scoring rules in force. See above.
	SemanticsVersion int `json:"semantics_version"`
	// EvaluationTime is the instant every observation was assessed at, in the
	// canonical UTC RFC 3339 spelling.
	//
	// It is fixed, so it is not a nondeterminism. It is LOAD-BEARING rather
	// than decorative: an observation carries an expiry and a withdrawal
	// status, and which of them are live is decided against this instant and
	// nothing else. Two runs evaluated at different instants can see different
	// evidence over byte-identical fixtures, so a result that does not record
	// it cannot be reproduced, and two results that disagree about it are not
	// measuring the same thing. Reproducible and comparableWith both say so.
	EvaluationTime string `json:"evaluation_time"`

	// SourceCommit is the commit the tested code came from, when the caller
	// supplied one. Empty means NOT SUPPLIED, and is reported as such: this
	// package cannot discover it, and guessing would be worse than absent.
	//
	// A value that is present is required to LOOK like a commit — see
	// validCommitID. That is a check on the identifier and never on the
	// object: this package does not and cannot establish that the commit is
	// still obtainable from any repository.
	SourceCommit string `json:"source_commit,omitempty"`
}

// digestUnavailable is the digest recorded for a detector that cannot state
// its own configuration.
//
// It is a value, not an empty string, so that "this detector did not say" is
// carried explicitly rather than looking like a field nobody filled in.
const digestUnavailable = "unavailable"

// digestUnstable is the digest recorded for an input whose identity CHANGED
// between the start of a run and the end of it.
//
// A binding is captured before the cases are decided, because that is the
// configuration the decisions are about to be made under. Nothing stops a
// caller mutating a detector or a registry while the run is in progress — a
// detector is an interface and may keep state, and the registry is a pointer
// the caller still holds. The identity recorded would then describe a
// configuration that stopped existing part-way through the measurement
// (FINDING-117).
//
// Run re-captures every digest after the last case and replaces any that moved
// with this marker. It is not a digest this package produces, so Reproducible
// and comparableWith both refuse it rather than treating a run under two
// configurations as a run under either one.
const digestUnstable = "unstable-during-run"

// ConfigIdentified is a detector that can state its configuration exactly.
//
// It is an optional interface rather than part of Detector because a detector
// written outside this package is still a legitimate detector; it simply
// cannot be compared across runs, and Improved says so rather than assuming.
type ConfigIdentified interface {
	// ConfigDigest is a stable digest over everything that changes what the
	// detector decides, and nothing that does not.
	ConfigDigest() string
}

// digestValue is the canonical digest of a labelled value.
//
// The label is part of the input so that two different kinds of thing cannot
// collide by encoding identically — a bare list of strings and a bare list of
// members would otherwise be the same bytes.
func digestValue(label string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Unreachable for the types used here, and reported rather than
		// swallowed: a digest that silently became a constant would make every
		// comparison below pass.
		return "undigestable:" + err.Error()
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// digestBytes is the digest of exact bytes.
func digestBytes(label string, b []byte) string {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// shortDigest renders a digest briefly for a name, keeping the algorithm
// prefix so that a short form is never mistaken for a full one.
func shortDigest(d string) string {
	const shown = 12
	if len(d) <= len("sha256:")+shown {
		return d
	}
	return d[:len("sha256:")+shown]
}

// detectorDigest returns a detector's configuration digest, or
// digestUnavailable when it does not provide one.
func detectorDigest(d Detector) string {
	if ci, ok := d.(ConfigIdentified); ok {
		return ci.ConfigDigest()
	}
	return digestUnavailable
}

// registryDigest is over the registry's canonical contents.
//
// The registry is digested as a VALUE rather than as the bytes of the file it
// came from, because a caller may build one in memory and because reformatting
// the file must not look like a different registry. Every field is exported
// with a stable JSON name, and encoding/json sorts map keys, so the encoding
// is deterministic.
func registryDigest(reg *sourceregistry.Registry) (digest, state string) {
	if reg == nil {
		return "", registryAbsent
	}
	return digestValue("source-registry", reg), registryPresent
}

// The registry-state vocabulary. It is a closed set of two, and a binding
// carrying anything else is not making either statement.
const (
	registryAbsent  = "absent"
	registryPresent = "present"
)

// statedRegistryState reports whether the value makes either statement.
//
// Anything else — the empty string above all — makes neither, and two results
// that both make neither have not agreed about anything.
func statedRegistryState(s string) bool {
	return s == registryAbsent || s == registryPresent
}

// evaluationTimeLayout is the one spelling of the evaluation instant.
//
// One instant must have exactly one spelling here, because comparableWith
// compares the recorded strings. "2026-06-01T00:00:00Z" and
// "2026-06-01T00:00:00+00:00" are the same moment and different bytes, and a
// comparison that refused the pair would be refusing over a formatting choice
// rather than over a measurement difference.
const evaluationTimeLayout = time.RFC3339

// isLowerHex reports whether s is exactly n lowercase hexadecimal digits.
//
// Lowercase only, and no trimming. Both are deliberate: git emits lowercase,
// and accepting either case — or accepting padding — would let one commit have
// several spellings, which turns a string comparison between two bindings into
// a comparison between two typing habits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validCommitID reports whether s is a full, canonical git object name.
//
// # WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT
//
// It establishes that the recorded value IDENTIFIES a commit: that it has the
// shape of a whole object name and could therefore only ever name one object.
// It establishes NOTHING about that object. This package does not run git —
// see WithSourceCommit for why — so it cannot and does not claim that the
// commit still exists in this working tree, in any clone, or on any remote. A
// result whose source commit passes this check is identified, not retrievable.
//
// An ABBREVIATION is refused rather than accepted as a weaker form. "deadbeef"
// is not a commit; it is a prefix that may match one object today, several
// tomorrow and none in a different clone. A binding whose whole purpose is to
// say which code was measured cannot be satisfied by a value that will not
// resolve the same way twice.
//
// Both current git object-name lengths are accepted: 40 hex digits for SHA-1
// and 64 for SHA-256. Which one a repository uses is a property of the
// repository, not of this measurement, and hard-coding 40 would refuse a
// perfectly well-identified result from a SHA-256 repository.
func validCommitID(s string) bool {
	return isLowerHex(s, 40) || isLowerHex(s, 64)
}

// validDigest reports whether s is one of this package's digests: the
// algorithm name, a colon, and the full hex of that algorithm's output.
//
// digestValue and digestBytes only ever produce this shape. The check exists
// because Reproducible is answered about a STORED result — one decoded from a
// JSON file that some other process wrote — and a field that merely happens to
// be non-empty is not a binding. "x" is not a digest and binds nothing.
func validDigest(s string) bool {
	const prefix = "sha256:"
	return strings.HasPrefix(s, prefix) && isLowerHex(s[len(prefix):], sha256.Size*2)
}

// validEvaluationTime reports whether s is the canonical UTC RFC 3339
// spelling of an instant.
//
// The round-trip is the check. Parsing alone would accept every equivalent
// spelling of one moment — a non-zero offset, a lowercase "z", trailing
// fractional zeros — and each of those is a different string, so two runs at
// the SAME instant could be refused as incomparable. Requiring the value to be
// exactly what this package would have written makes one instant one string.
func validEvaluationTime(s string) bool {
	t, err := time.Parse(evaluationTimeLayout, s)
	if err != nil {
		return false
	}
	return t.UTC().Format(evaluationTimeLayout) == s
}

// RunOption adjusts what a run records about itself.
type RunOption func(*runConfig)

type runConfig struct {
	sourceCommit string
}

// WithSourceCommit records the commit the tested code came from.
//
// Only the caller knows this. This package will not run git to find out: the
// commit that the harness's own working tree happens to sit at is not
// necessarily the commit the detector under test was built from, and a
// plausible wrong answer is worse here than an absent one.
func WithSourceCommit(commit string) RunOption {
	return func(c *runConfig) { c.sourceCommit = commit }
}

// bindingFor assembles the binding for a run.
func bindingFor(set *FixtureSet, baseline, candidate Detector, reg *sourceregistry.Registry, cfg runConfig) Binding {
	regDigest, regState := registryDigest(reg)
	return Binding{
		FixtureDigest:     set.BytesDigest(),
		FixtureSetID:      set.ID,
		FixtureSetVersion: set.Version,
		Partition:         set.Partition,

		RegistryDigest: regDigest,
		RegistryState:  regState,

		BaselineName:    baseline.Name(),
		BaselineDigest:  detectorDigest(baseline),
		CandidateName:   candidate.Name(),
		CandidateDigest: detectorDigest(candidate),

		SemanticsVersion: SemanticsVersion,
		EvaluationTime:   evaluationTime.UTC().Format(evaluationTimeLayout),
		SourceCommit:     cfg.sourceCommit,
	}
}

// reconfirm re-takes every digest after a run and marks the ones that moved.
//
// # WHY A SECOND CAPTURE
//
// bindingFor runs before the first case, because the binding is meant to state
// the configuration the decisions are about to be taken under. But a Detector
// is an interface — an implementation outside this package may keep state and
// change it as it decides — a *sourceregistry.Registry is a pointer the caller
// still holds, and every field of FixtureSet that a run reads is exported. A
// run whose inputs changed under it was measured under no single
// configuration, and the binding captured at the start would name only the
// first of them (FINDING-117).
//
// Marking is the honest answer rather than erasing or panicking: the case
// results are real, they are simply not attributable to one configuration, and
// a marker says exactly that where the original digest would have lied.
//
// The FixtureDigest check is separate in kind — BytesDigest already reports
// digestMutated for a set edited after parsing — but it is re-read here for
// the same reason: the edit may have happened during the loop.
func reconfirm(b *Binding, set *FixtureSet, baseline, candidate Detector, reg *sourceregistry.Registry) {
	after := bindingFor(set, baseline, candidate, reg, runConfig{sourceCommit: b.SourceCommit})
	b.FixtureDigest = stillTrue(b.FixtureDigest, after.FixtureDigest)
	b.RegistryDigest = stillTrue(b.RegistryDigest, after.RegistryDigest)
	b.BaselineDigest = stillTrue(b.BaselineDigest, after.BaselineDigest)
	b.CandidateDigest = stillTrue(b.CandidateDigest, after.CandidateDigest)
}

// stillTrue returns the digest taken before the run, or digestUnstable when
// the one taken after it disagrees.
func stillTrue(before, after string) string {
	if before != after {
		return digestUnstable
	}
	return before
}

// Reproducible reports whether the result carries every binding needed to
// reproduce it, and what is missing when it does not.
//
// # WHY THIS IS A METHOD AND NOT A COMMENT
//
// The superseded Result documented its Cases field as being there "so a run is
// fully reproducible from its own output". That was not true: the output named
// its fixture set but did not bind it, named its detectors but did not
// identify them, and said nothing at all about the registry, the scoring
// semantics or the source commit. A claim of reproducibility that a reader
// cannot check is worse than no claim, because it stops them checking.
//
// This answers the question instead of asserting the answer.
//
// # WHAT "REPRODUCIBLE" CLAIMS
//
// That the result IDENTIFIES every input it was computed from, precisely
// enough that a reader could go and get them. It does NOT claim the inputs are
// still obtainable. The fixture digest does not prove the file still exists;
// the source commit is checked for the shape of a whole object name and never
// for the existence of the object — this package does not run git. Identified
// and retrievable are different claims, and only the first is made here.
func (r *Result) Reproducible() (bool, []string) {
	var missing []string
	b := r.Binding

	// Each check below asks the same question of a different field: does the
	// value IDENTIFY the thing it names, or is it merely non-empty? The
	// superseded implementation asked only the second question, and a stored
	// result is a file some other process wrote — a field that happens to hold
	// "x" or "deadbeef" satisfied it (FINDING-108, FINDING-110).
	switch {
	case b.FixtureDigest == "":
		missing = append(missing, "the exact fixture bytes are not bound; the set is named but its contents are not pinned")
	case b.FixtureDigest == digestMutated:
		missing = append(missing, "the fixture set was modified after it was parsed, so the bytes it was read from no longer describe the cases that were evaluated")
	case !validDigest(b.FixtureDigest):
		missing = append(missing, "the recorded fixture digest is not a digest this package produces, so it pins no bytes")
	}

	switch b.RegistryState {
	case "":
		missing = append(missing, "it is not recorded whether a source registry was supplied")
	case registryAbsent:
		if b.RegistryDigest != "" {
			missing = append(missing, "the result states that no source registry was supplied and carries a registry digest anyway; the two cannot both be true")
		}
	case registryPresent:
		switch {
		case b.RegistryDigest == "":
			missing = append(missing, "a registry was used but its contents are not bound")
		case b.RegistryDigest == digestUnstable:
			missing = append(missing, "the source registry changed while the run was in progress, so no single registry describes the corroboration the result was computed from")
		case !validDigest(b.RegistryDigest):
			missing = append(missing, "the recorded registry digest is not a digest this package produces, so it binds no registry")
		}
	default:
		missing = append(missing, "the recorded registry state is neither `absent` nor `present`, so it is not stated whether independence could be established at all")
	}

	switch {
	case b.BaselineDigest == "" || b.BaselineDigest == digestUnavailable:
		missing = append(missing, "the baseline configuration is not bound, so `additional` cannot be reconstructed")
	case b.BaselineDigest == digestUnstable:
		missing = append(missing, "the baseline's configuration changed while the run was in progress, so `additional` was not measured against one thing")
	case !validDigest(b.BaselineDigest):
		missing = append(missing, "the recorded baseline digest is not a digest this package produces, so the baseline configuration is not bound")
	}

	switch {
	case b.CandidateDigest == "" || b.CandidateDigest == digestUnavailable:
		missing = append(missing, "the candidate configuration is not bound")
	case b.CandidateDigest == digestUnstable:
		missing = append(missing, "the candidate's configuration changed while the run was in progress, so the result does not measure one configuration")
	case !validDigest(b.CandidateDigest):
		missing = append(missing, "the recorded candidate digest is not a digest this package produces, so the candidate configuration is not bound")
	}

	switch {
	case b.SemanticsVersion == 0:
		missing = append(missing, "the scoring semantics are not recorded")
	case b.SemanticsVersion < 0:
		missing = append(missing, "the recorded scoring semantics are not a version this package ever issued")
	case b.SemanticsVersion > SemanticsVersion:
		missing = append(missing, fmt.Sprintf(
			"the result was scored under semantics v%d, which this build does not "+
				"implement (it implements v%d); the rates cannot be recomputed here",
			b.SemanticsVersion, SemanticsVersion))
	}

	// The instant, not merely a timestamp field. Expiry and withdrawal are
	// decided against it and against nothing else, so a result that does not
	// record which instant it used has not recorded which evidence was live
	// (FINDING-109).
	switch {
	case b.EvaluationTime == "":
		missing = append(missing, "the instant the observations were assessed at is not recorded; expiry and withdrawal are decided against it, so which evidence was live cannot be reconstructed")
	case !validEvaluationTime(b.EvaluationTime):
		missing = append(missing, "the recorded evaluation instant is not a canonical UTC RFC 3339 timestamp, so it names no instant; expiry and withdrawal were decided against something that cannot be reconstructed")
	}

	// A commit that is identified is not a commit that is obtainable. The
	// wording says which of the two this establishes, because the difference
	// is the whole distance between "you can check this" and "you can find
	// out what this was".
	switch {
	case b.SourceCommit == "":
		missing = append(missing, "no source commit was supplied, so the code under test is not identified")
	case !validCommitID(b.SourceCommit):
		missing = append(missing, "the recorded source commit is not a full commit identifier (40 or 64 lowercase hex digits), so it names no object and the code under test is not identified")
	}

	return len(missing) == 0, missing
}

// comparableWith reports whether two results measured the same thing, and why
// not when they did not.
//
// Every check here is a way two runs can differ that makes their numbers mean
// different things.
//
// # WHAT IS DELIBERATELY NOT CHECKED, AND WHY
//
//   - The CANDIDATE digest and name. Two runs with the same candidate are a
//     repeat, not a comparison; differing here is the purpose of the
//     operation. The digest must still be PRESENT for the result to be
//     reproducible, which Reproducible enforces separately.
//   - The SOURCE COMMIT. A before/after comparison is normally between two
//     commits. Requiring equality would refuse exactly the comparison this
//     package exists to make.
//   - The baseline and candidate NAMES. A name is a label a caller chose;
//     BaselineDigest is what the baseline actually is, and it is compared.
//     Refusing a pair because someone renamed a list would be a comparison
//     between two labels rather than between two measurements.
//   - FixtureSetID, FixtureSetVersion and Partition are each inside the
//     fixture document, so FixtureDigest already binds them. They are
//     compared anyway as defence in depth for a Binding some future caller
//     assembles by hand rather than through ParseSet; see
//     TestPartitionGuardIsExercisedDirectly.
//
// # TWO MISSING VALUES ARE NOT AN AGREEMENT
//
// Every check below was once written as `b.X != a.X`, which answers "do these
// two results disagree". That is the wrong question. A stored result is a file
// some other process wrote, and two files that are both SILENT about the
// baseline, the registry state or the scoring version compare equal on every
// one of those fields — so the pair passed every check and was declared
// comparable on the strength of neither run having said anything
// (FINDING-118). Improved then reported an improvement between two
// measurements that had not been established to measure the same thing.
//
// So each field is now asked the question twice: is the value one that MAKES A
// STATEMENT, on both sides, and only then do the two statements agree. The
// first half is what stops silence from being read as consensus, and it is
// also what refuses the two markers this package writes for inputs that went
// missing or moved — digestUnavailable, digestMutated and digestUnstable.
//
// Values interpolated below are truncated, which escapes them first: a stored
// result is a file some other process wrote, and a refusal is read by a person
// in a terminal.
func comparableWith(before, after *Result) (string, bool) {
	b, a := before.Binding, after.Binding

	switch {
	case b.SemanticsVersion <= 0 || a.SemanticsVersion <= 0:
		return "at least one run does not record which scoring rules it was " +
			"computed under; two results that both fail to say are not thereby " +
			"agreed, and their denominators cannot be established to be the " +
			"same quantity", false

	case b.SemanticsVersion != a.SemanticsVersion:
		return fmt.Sprintf("the two runs were scored under different rules "+
			"(semantics v%d and v%d); their denominators are not the same quantity",
			b.SemanticsVersion, a.SemanticsVersion), false

	case b.FixtureDigest == "" || a.FixtureDigest == "":
		return "at least one run does not bind its fixture bytes, so it cannot be " +
			"established that the two were measured over the same cases", false

	case !validDigest(b.FixtureDigest) || !validDigest(a.FixtureDigest):
		return "at least one run's fixture binding is not a digest this package " +
			"produces — it was never taken, the set was modified after it was " +
			"parsed, or the value was written by something else — so it pins no " +
			"bytes and cannot establish that the two runs saw the same cases", false

	case b.FixtureDigest != a.FixtureDigest:
		return "the two runs are over different fixture CONTENTS and are not comparable", false

	case b.FixtureSetID != a.FixtureSetID || b.FixtureSetVersion != a.FixtureSetVersion:
		return "the two runs are over different fixture sets and are not comparable", false

	case b.Partition != a.Partition:
		return fmt.Sprintf("the two runs are over different partitions (%s and %s); "+
			"a development result must not be compared with a held-out one",
			truncate(string(b.Partition), 32), truncate(string(a.Partition), 32)), false

	case !statedRegistryState(b.RegistryState) || !statedRegistryState(a.RegistryState):
		return "at least one run does not state whether a source registry was " +
			"supplied; two runs that are both silent about it have not thereby " +
			"agreed, and whether `independent` could be established at all is " +
			"unknown for one of them", false

	case b.RegistryState != a.RegistryState:
		return fmt.Sprintf("one run had a source registry and the other did not "+
			"(%s and %s); independence is established in one and unestablished in "+
			"the other", truncate(b.RegistryState, 32), truncate(a.RegistryState, 32)), false

	case b.RegistryState == registryPresent &&
		(!validDigest(b.RegistryDigest) || !validDigest(a.RegistryDigest)):
		return "both runs state that a source registry was used, but at least " +
			"one does not bind which one — or its binding changed while the run " +
			"was in progress — so `independent` cannot be established to mean the " +
			"same thing in both", false

	case b.RegistryDigest != a.RegistryDigest:
		return "the two runs used different source registries, so `independent` " +
			"does not mean the same thing in both", false

	// The evaluation instant decides which observations were live, which had
	// expired and which had been withdrawn. Two runs that assessed the same
	// fixture bytes at different instants did not see the same evidence, so
	// their counts are not the same quantity — and nothing in the numbers says
	// so (FINDING-109).
	case b.EvaluationTime == "" || a.EvaluationTime == "":
		return "at least one run does not record the instant it evaluated at; " +
			"expiry and withdrawal are decided against that instant, so it cannot " +
			"be established that the same evidence was live in both", false

	case !validEvaluationTime(b.EvaluationTime) || !validEvaluationTime(a.EvaluationTime):
		return "at least one run records an evaluation instant that is not a " +
			"canonical UTC RFC 3339 timestamp, so the instant its expiry and " +
			"withdrawal decisions were taken against is not established", false

	case b.EvaluationTime != a.EvaluationTime:
		return fmt.Sprintf("the two runs were evaluated at different instants "+
			"(%s and %s); expiry and withdrawal are decided against that instant, "+
			"so an observation live in one run may be expired or withdrawn in the "+
			"other and the two counts are not the same quantity",
			truncate(b.EvaluationTime, 40), truncate(a.EvaluationTime, 40)), false

	case b.BaselineDigest == digestUnavailable || a.BaselineDigest == digestUnavailable:
		return "at least one baseline cannot state its own configuration, so it " +
			"cannot be established that both runs measured `additional` against " +
			"the same thing", false

	case !validDigest(b.BaselineDigest) || !validDigest(a.BaselineDigest):
		return "at least one run's baseline binding is not a digest this package " +
			"produces — it was never taken, it changed while the run was in " +
			"progress, or the value was written by something else — so it cannot " +
			"be established that both runs measured `additional` against the same " +
			"thing", false

	case b.BaselineDigest != a.BaselineDigest:
		return "the two runs used different baselines, so `additional` is " +
			"measured against different configurations and the counts are not " +
			"comparable", false
	}
	return "", true
}
