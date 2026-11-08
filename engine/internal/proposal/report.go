// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/safetext"
)

// SemanticsVersion is the version of THIS PACKAGE'S DECISION RULES.
//
// Not a build stamp and not a date. Two reports are comparable only if the
// same questions were asked of both, and a change to what counts as adverse
// support, to the precedence order in decide, or to what a scope reaches,
// silently changes the answer for inputs that did not move. Nothing in the
// output would say so, so the number is carried.
//
// History:
//
//	1  the rules as ORDER 6 first built them.
const SemanticsVersion = 1

// evaluationTimeLayout is the one spelling of the evaluation instant.
//
// One instant must have exactly one spelling, because a binding is compared as
// a string. "2026-06-01T00:00:00Z" and "2026-06-01T00:00:00+00:00" are the
// same moment and different bytes.
const evaluationTimeLayout = time.RFC3339

// Binding is the complete identity of the inputs a report was computed from.
//
// # WHY EVERY FIELD IS A DIGEST AND NOT A NAME
//
// A report that named its evidence file, its registry and its policy would be
// citing three things by titles their own authors chose. Two policy files with
// different exceptions can carry the same note; two evidence documents with
// different records can carry the same feed id. A reader could then compare a
// report against a run that shared nothing with it.
//
// Each field below is over CONTENT. The evidence document is digested over its
// exact bytes, because it is the signed file that is cited; the operator's two
// documents are digested over their canonical values, because reformatting an
// operator's file must not read as a change of policy.
type Binding struct {
	// EvidenceDigest is over the exact bytes of the signed document.
	EvidenceDigest string `json:"evidence_digest"`
	// EvidenceFeedID and EvidenceManifestVersion are what the document CLAIMS
	// about itself. Kept for readability; never relied on for identity.
	EvidenceFeedID          string `json:"evidence_feed_id"`
	EvidenceManifestVersion string `json:"evidence_manifest_version"`
	// SigningKeyID is the key that signed it, as the envelope carried it.
	SigningKeyID string `json:"signing_key_id"`
	// AuthorityDigest is over the WHOLE signer-authority document. It is
	// load-bearing: the same signed evidence admitted under two different
	// authorities is two different sets of admitted records.
	AuthorityDigest string `json:"authority_digest"`
	// SignerGrantDigest is over the ONE signer that signed this document —
	// its key id, its public key and its two source-id lists.
	//
	// Kept beside the field above rather than instead of it, because the two
	// say different things and the superseded implementation conflated them:
	// it was named `authority_digest`, documented as covering the whole
	// document, and computed over the selected signer alone (FINDING-124).
	// Whichever of the two a reader wants, a field that claims to be one and
	// is the other is worse than either.
	SignerGrantDigest string `json:"signer_grant_digest"`
	// BuildIdentity is the code that produced this report, when the caller
	// supplied one. EMPTY MEANS NOT SUPPLIED and is reported as such.
	//
	// SemanticsVersion below is a manually maintained RULE version and is not
	// this. A report can carry semantics v1 from any number of commits, and
	// presenting a rule number as proof of which binary ran would be the
	// strongest false claim in the whole binding.
	//
	// This package cannot discover it: the value the command knows comes from
	// its own -ldflags, and guessing would be worse than absent.
	BuildIdentity string `json:"build_identity,omitempty"`
	// BuildIdentityState is "absent" or "present", so that a missing build
	// identity is a statement rather than an empty field somebody might read
	// as "there was nothing to say".
	BuildIdentityState string `json:"build_identity_state"`
	// RegistryDigest is over the source registry's canonical contents.
	RegistryDigest string `json:"registry_digest"`
	// PolicyDigest is over the proposal policy's canonical contents.
	PolicyDigest string `json:"policy_digest"`
	// EvaluatedAt is the instant expiry and withdrawal were decided against,
	// in the canonical UTC RFC 3339 spelling. Load-bearing rather than
	// decorative: two runs over byte-identical evidence at different instants
	// can see different evidence.
	EvaluatedAt string `json:"evaluated_at"`
	// SemanticsVersion is the decision rules in force. See above.
	SemanticsVersion int `json:"semantics_version"`
}

// Counts are the totals a reader wants before any list.
type Counts struct {
	Records         int `json:"records"`
	RecordsAdmitted int `json:"records_admitted"`
	RecordsRefused  int `json:"records_refused"`
	// RecordsValueWithheld is how many admitted records could not name their
	// indicator, because a contributing source does not authorise it.
	RecordsValueWithheld int `json:"records_value_withheld"`
	Indicators           int `json:"indicators"`
	Proposed             int `json:"proposed"`
	Abstained            int `json:"abstained"`
	Refused              int `json:"refused"`
	// ExportWithheld is a SINGLE total: how many indicators this rendering
	// withheld because a contributing source permits them being acted on here
	// and not republished. One number rather than a breakdown, because a
	// breakdown by decision is itself information about what was withheld.
	//
	// Zero in a local rendering, always: nothing is withheld from the
	// household about its own network.
	ExportWithheld int `json:"export_withheld,omitempty"`
}

// Report is everything one run produced.
type Report struct {
	Binding Binding `json:"binding"`
	// Admitted is how many records became observations.
	Admitted int             `json:"-"`
	Records  []RecordOutcome `json:"records"`
	Outcomes []Outcome       `json:"outcomes"`
}

// bindingFor assembles the binding for a run.
func bindingFor(in Input) Binding {
	return Binding{
		EvidenceDigest:          in.Evidence.BytesDigest,
		EvidenceFeedID:          safetext.Clip(in.Evidence.FeedID, 128),
		EvidenceManifestVersion: safetext.Clip(in.Evidence.ManifestVersion, 32),
		SigningKeyID:            safetext.Clip(in.Evidence.KeyID, 128),
		AuthorityDigest:         safetext.Clip(in.Evidence.AuthorityDigest, 128),
		SignerGrantDigest:       signerGrantDigest(in),
		BuildIdentity:           safetext.Clip(in.BuildIdentity, 200),
		BuildIdentityState:      buildIdentityState(in.BuildIdentity),
		RegistryDigest:          digestJSON("source-registry", in.Registry),
		PolicyDigest:            in.Policy.Digest(),
		EvaluatedAt:             in.At.UTC().Format(evaluationTimeLayout),
		SemanticsVersion:        SemanticsVersion,
	}
}

// signerGrantDigest binds the ONE signer that signed this document.
//
// Narrower than Binding.AuthorityDigest deliberately, and NAMED for what it
// is. The superseded function was called authorityDigest, documented as
// covering the whole document, and computed this (FINDING-124).
func signerGrantDigest(in Input) string {
	if in.Evidence.Signer == nil {
		return ""
	}
	return digestJSON("signer-authority-record", struct {
		KeyID     string   `json:"key_id"`
		PublicKey string   `json:"public_key"`
		Asserts   []string `json:"asserts_source_ids"`
		Aggregate []string `json:"aggregator_for"`
	}{
		in.Evidence.Signer.KeyID,
		in.Evidence.Signer.PublicKey,
		sortedCopy(in.Evidence.Signer.AssertsSourceIDs),
		sortedCopy(in.Evidence.Signer.AggregatorFor),
	})
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// Counts totals the report.
func (r *Report) Counts() Counts {
	c := Counts{
		Records:    len(r.Records),
		Indicators: len(r.Outcomes),
	}
	for _, rec := range r.Records {
		if rec.Admitted {
			c.RecordsAdmitted++
		} else {
			c.RecordsRefused++
		}
		if rec.CanonicalWithheld {
			c.RecordsValueWithheld++
		}
	}
	for _, o := range r.Outcomes {
		switch o.Decision {
		case DecisionPropose:
			c.Proposed++
		case DecisionAbstain:
			c.Abstained++
		case DecisionRefuse:
			c.Refused++
		}
		if o.IdentityWithheld && o.ExportWithheld {
			c.ExportWithheld++
		}
	}
	return c
}

// Proposed reports whether anything at all was proposed.
func (r *Report) Proposed() bool { return r.Counts().Proposed > 0 }

// jsonReport is the wire shape. Counts are computed, so they are added here
// rather than stored and risked going stale.
type jsonReport struct {
	Binding Binding `json:"binding"`
	Counts  Counts  `json:"counts"`
	// Limitations travels INSIDE the document, so that quoting a count
	// without it takes effort.
	Limitations []string        `json:"limitations"`
	Records     []RecordOutcome `json:"records"`
	Outcomes    []Outcome       `json:"outcomes"`
}

// Limitations is what this report does not establish, carried in its own
// output.
//
// It is not a disclaimer bolted on. Each line is a specific thing a reader
// might otherwise conclude from the numbers above it, and the numbers are
// worth nothing read without them.
func (r *Report) Limitations() []string {
	return []string{
		"A proposal is not permission to enforce anything. This build contains no code that can apply one: policy.EnforcementCompiledIn is false and policy.Apply returns an error.",
		"A verified signature establishes AUTHENTICITY only — that a key the operator recorded produced these bytes. It establishes nothing about whether any claim in them is accurate.",
		"Source attribution is what the signed document CLAIMS, admitted because the operator granted that signer authority over that source id. It is not independent confirmation that the named source observed anything.",
		"`independent` means the source registry's lineage records do not show a shared upstream. It is a statement about what has been recorded, not about the world.",
		"Expiry and withdrawal were decided against the evaluation instant in the binding and against nothing else. A run at another instant over the same bytes can differ.",
		identityKeyLimitation(r),
		"Nothing here was fetched: every input was a local file named on the command line, and this command has no code path to a network client, a credential or a Pi-hole session. That it COMPLETED no network operation is measured — the same inputs produce a byte-identical report inside an empty network namespace, with `scamwall status` failing there as the control. That no socket was ATTEMPTED is NOT established: a connect() that failed and was ignored would look identical. See docs/VERIFICATION.md for the syscall-level evidence that would settle it and is not available here.",
	}
}

// JSON writes the machine-readable report.
//
// Indented, with every list already in a deterministic order, so that two runs
// over the same inputs produce byte-identical files and a diff between two
// runs is a diff between two answers.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// SetEscapeHTML stays ON. The fields below are already escaped by
	// safetext, and leaving the encoder's own escaping in place is one more
	// layer between a hostile field and anything that renders this as HTML.
	return enc.Encode(jsonReport{
		Binding:     r.Binding,
		Counts:      r.Counts(),
		Limitations: r.Limitations(),
		Records:     r.Records,
		Outcomes:    r.Outcomes,
	})
}

// Text writes the operator-readable report.
//
// Every caller-controlled field printed below has already been escaped and
// bounded where it was built — see safetext, MaxExplanation and the clips in
// admit and decide. Nothing is re-escaped here, because escaping twice
// produces output that looks corrupted and teaches a reader to ignore it.
func (r *Report) Text(w io.Writer) {
	c := r.Counts()
	fmt.Fprintln(w, "scamwall proposals (offline, from signed evidence)")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "bindings")
	fmt.Fprintf(w, "  evidence         %s\n", r.Binding.EvidenceDigest)
	fmt.Fprintf(w, "  feed id          %s (manifest %s)\n", r.Binding.EvidenceFeedID, r.Binding.EvidenceManifestVersion)
	fmt.Fprintf(w, "  signed by        %s\n", r.Binding.SigningKeyID)
	fmt.Fprintf(w, "  signer authority %s  (the whole document)\n", r.Binding.AuthorityDigest)
	fmt.Fprintf(w, "  signer grant     %s  (the one signer that signed)\n", r.Binding.SignerGrantDigest)
	fmt.Fprintf(w, "  source registry  %s\n", r.Binding.RegistryDigest)
	fmt.Fprintf(w, "  policy           %s\n", r.Binding.PolicyDigest)
	fmt.Fprintf(w, "  evaluated at     %s\n", r.Binding.EvaluatedAt)
	fmt.Fprintf(w, "  semantics        v%d  (a RULE version, not a build stamp)\n", r.Binding.SemanticsVersion)
	if r.Binding.BuildIdentityState == buildIdentityPresent {
		fmt.Fprintf(w, "  built by         %s\n", r.Binding.BuildIdentity)
	} else {
		fmt.Fprintln(w, "  built by         NOT SUPPLIED — this report does not identify the code")
		fmt.Fprintln(w, "                   that produced it. The semantics version above is a rule")
		fmt.Fprintln(w, "                   number and says nothing about which commit or binary ran.")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%d record(s): %d admitted, %d refused\n", c.Records, c.RecordsAdmitted, c.RecordsRefused)
	if n := c.RecordsValueWithheld; n > 0 {
		// Said out loud. "2 admitted" with the values silently absent would
		// read as a formatting fault rather than as a rights position.
		fmt.Fprintf(w, "%d record(s) had their indicator value WITHHELD: a contributing source\n"+
			"  does not authorise naming it in a report. The index, the source id and the\n"+
			"  admission outcome are still below; the value is not.\n", n)
	}
	if n := c.ExportWithheld; n > 0 {
		// The export audience's single total, said in the same voice and for
		// the same reason: a count with the names silently absent reads as a
		// formatting fault rather than as a rights position.
		fmt.Fprintf(w, "%d indicator(s) WITHHELD FROM THIS RENDERING: a contributing source\n"+
			"  permits them being acted on here and not republished. This is the EXPORT\n"+
			"  audience; the local report names them.\n", n)
	}
	if c.RecordsRefused > 0 {
		fmt.Fprintln(w, "\nrecords not admitted as evidence:")
		for _, rec := range r.Records {
			if rec.Admitted {
				continue
			}
			fmt.Fprintf(w, "  record %d  [%s]  source %q\n", rec.Index, rec.Reason, rec.SourceID)
			for _, line := range wrap(rec.Explanation, 72) {
				fmt.Fprintf(w, "            %s\n", line)
			}
		}
	}

	if c.RecordsValueWithheld > 0 {
		fmt.Fprintln(w, "\nadmitted records whose indicator value is withheld:")
		for _, rec := range r.Records {
			if !rec.CanonicalWithheld {
				continue
			}
			fmt.Fprintf(w, "  record %d  source %q  %s  (value withheld)\n",
				rec.Index, rec.SourceID, rec.Store)
		}
	}

	fmt.Fprintf(w, "\n%d indicator(s): %d proposed, %d abstained, %d refused\n",
		c.Indicators, c.Proposed, c.Abstained, c.Refused)

	writeOutcomes(w, "proposed", r.Outcomes, DecisionPropose)
	writeOutcomes(w, "abstained", r.Outcomes, DecisionAbstain)
	writeOutcomes(w, "refused", r.Outcomes, DecisionRefuse)

	fmt.Fprintln(w, "\nwhat this report does not establish")
	for _, l := range r.Limitations() {
		for i, line := range wrap(l, 74) {
			prefix := "  - "
			if i > 0 {
				prefix = "    "
			}
			fmt.Fprintf(w, "%s%s\n", prefix, line)
		}
	}
}

func writeOutcomes(w io.Writer, title string, all []Outcome, d Decision) {
	var sel []Outcome
	for _, o := range all {
		if o.Decision == d {
			sel = append(sel, o)
		}
	}
	if len(sel) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s:\n", title)
	for _, o := range sel {
		scope := ""
		if o.Scope != "" {
			scope = "  scope=" + string(o.Scope)
		}
		name := o.Canonical
		if o.IdentityWithheld {
			// Not an empty column. An operator reading a blank where a name
			// belongs reads a bug; this says the absence is the answer.
			name = "(identity withheld — see below)"
		}
		fmt.Fprintf(w, "  %-8s %s  [%s]%s\n", o.Type, name, o.Reason, scope)
		for _, line := range wrap(o.Explanation, 70) {
			fmt.Fprintf(w, "           %s\n", line)
		}
		if len(o.Sources) > 0 {
			fmt.Fprintf(w, "           sources: %s\n", strings.Join(o.Sources, ", "))
		}
		if len(o.IndependentSources) > 0 {
			fmt.Fprintf(w, "           independent: %s\n", strings.Join(o.IndependentSources, ", "))
		}
		if len(o.AggregatedSources) > 0 {
			fmt.Fprintf(w, "           aggregated (NOT counted as independent): %s\n",
				strings.Join(o.AggregatedSources, ", "))
		}
		if len(o.RefusedSources) > 0 {
			fmt.Fprintf(w, "           refused by: %s  (edit this grant, then re-run)\n",
				strings.Join(o.RefusedSources, ", "))
		}
		if o.IdentityWithheld {
			fmt.Fprintln(w, "           the indicator and everything derived from it are ABSENT from")
			fmt.Fprintln(w, "           this report, not hidden by it: printing them would perform the")
			fmt.Fprintln(w, "           operation the line above says was refused.")
		}
		if len(o.Signals) > 0 {
			fmt.Fprintf(w, "           signals: %s  (a signal is not evidence)\n", strings.Join(o.Signals, ", "))
		}
		if o.Exception != nil && o.Reason != ReasonUserException {
			fmt.Fprintf(w, "           note: a household exception also matched (%s at %s)\n",
				o.Exception.Canonical, o.Exception.Scope)
		}
	}
}

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}
	return append(lines, line)
}

// buildIdentityState renders the two-valued vocabulary for Binding.
//
// A closed set of two, so that "the caller did not supply one" is carried
// explicitly rather than looking like a field nobody filled in.
func buildIdentityState(id string) string {
	if strings.TrimSpace(id) == "" {
		return buildIdentityAbsent
	}
	return buildIdentityPresent
}

// The build-identity vocabulary.
const (
	buildIdentityAbsent  = "absent"
	buildIdentityPresent = "present"
)

// identityKeyLimitation says whether this report could identify the hosts it
// was not allowed to name.
//
// A separate line rather than silence, because the two states look identical
// in the output: a report with no withheld hosts and a report that withheld
// several and could not label any of them both show no identifiers.
func identityKeyLimitation(r *Report) string {
	for _, o := range r.Outcomes {
		if (o.IdentityWithheld || o.ExportWithheld) && o.OpaqueID == "" {
			return "This run was given no identity key, so hosts this report may not name carry NO " +
				"identifier: two reports about the same withheld host cannot be told to be about the " +
				"same host. Nothing was substituted — an unkeyed digest of a hostname is a lookup " +
				"table away from being the hostname, and would look exactly like a working control."
		}
	}
	return "Hosts this report may not name carry a keyed identifier under this installation's own " +
		"key. It is stable here and meaningless anywhere else, so two of these reports can be " +
		"compared and a third party holding one learns no hostname from it."
}
