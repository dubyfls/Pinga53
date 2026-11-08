// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import "strings"

// # A REPORT HAS AN AUDIENCE
//
// This tree already refuses an indicator outright when a contributing source
// does not authorise `derived_output`, which is the strongest half of C-08 and
// was in place before this control was written. What it did not have is the
// split.
//
// `redistribution` and `derived_output` are different grants, and
// observation.Indicator.Exportable already asks them separately — it existed
// and nothing in the report path called it. A source that permits a household
// to compute a blocklist and forbids publishing one is a real and common
// position, and until now its hosts were named in the only report there was.
//
// So: the LOCAL report is what the household may see about its own network.
// The EXPORT report is what may leave it. The second is a strict subset of the
// first and is produced by narrowing, never by building something separate —
// two renderers diverge, and the one nobody reads is the one that leaks.

// Audience is who a rendering of a report is for.
type Audience string

// The two audiences. There is no third, and an unrecognised value is treated
// as export: failing closed here means a typo costs a diagnostic, and failing
// open means it costs somebody's hostname.
const (
	AudienceLocal  Audience = "local"
	AudienceExport Audience = "export"
)

// ForAudience returns a rendering of r for audience a.
//
// The receiver is never modified. A caller writing the export report first
// must not get a redacted local report afterwards; see
// TestForAudienceDoesNotMutateTheReport.
func (r *Report) ForAudience(a Audience) *Report {
	if a == AudienceLocal {
		return r
	}

	out := &Report{
		Binding:  r.Binding,
		Admitted: r.Admitted,
		Records:  make([]RecordOutcome, len(r.Records)),
		Outcomes: make([]Outcome, len(r.Outcomes)),
	}
	copy(out.Records, r.Records)
	copy(out.Outcomes, r.Outcomes)

	for i := range out.Records {
		if !out.Records[i].ExportWithheld {
			continue
		}
		out.Records[i].Canonical = ""
		out.Records[i].CanonicalWithheld = true
	}
	for i := range out.Outcomes {
		if !out.Outcomes[i].ExportWithheld {
			continue
		}
		out.Outcomes[i] = withholdForExport(out.Outcomes[i])
	}
	return out
}

// withholdForExport removes everything that identifies the indicator.
//
// The name is not the only identifier. A source list, a signal list and an
// origin-group count are a fingerprint that a reader holding the same evidence
// can match against a guess, so the derived fields go with the name. What is
// kept is this build's own vocabulary: the type, the decision, the reason, and
// the leading clause of the explanation.
func withholdForExport(o Outcome) Outcome {
	return Outcome{
		Type:             o.Type,
		Decision:         o.Decision,
		Reason:           o.Reason,
		IdentityWithheld: true,
		ExportWithheld:   true,
		// The identifier survives the withholding. It is the point of the
		// withholding: a host nobody may name is still a host two reports can
		// agree they are both talking about.
		OpaqueID: o.OpaqueID,
		// Truncated at the first colon. The leading clause is this build's
		// own words; everything after it is detail quoted from the evidence
		// and the registry — source ids, counts, origin names. A withheld
		// item carrying the detail has had its name removed and its
		// fingerprint left behind.
		Explanation: beforeColon(o.Explanation),
	}
}

// beforeColon returns s up to its first colon, trimmed.
func beforeColon(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ForAudience returns a rendering of the automatic plan for audience a.
//
// C-08 names plan items and deferred samples specifically, and they need
// saying separately because they are the one place a withheld host reappears
// as a bare string. An outcome carries a decision and a reason around its
// name; `Blocks` and `Deferred` are lists of names and nothing else, so a
// withholding that stopped at the outcome list would publish the same hosts
// one field down.
func (p *AutoPlan) ForAudience(a Audience) *AutoPlan {
	if p == nil || a == AudienceLocal {
		return p
	}

	withheld := map[string]bool{}
	out := *p
	out.Outcomes = make([]AutoOutcome, len(p.Outcomes))
	copy(out.Outcomes, p.Outcomes)
	for i := range out.Outcomes {
		if !out.Outcomes[i].ExportWithheld {
			continue
		}
		if out.Outcomes[i].Canonical != "" {
			withheld[out.Outcomes[i].Canonical] = true
		}
		out.Outcomes[i].Canonical = ""
		out.Outcomes[i].IdentityWithheld = true
		out.Outcomes[i].Explanation = beforeColon(out.Outcomes[i].Explanation)
		out.WithheldFromExport++
	}

	out.Blocks = keepNamed(p.Blocks, withheld)
	out.Deferred = nil
	for _, d := range p.Deferred {
		if withheld[d.Canonical] {
			continue
		}
		out.Deferred = append(out.Deferred, d)
	}
	return &out
}

// keepNamed drops the names the export audience may not have.
func keepNamed(in []string, withheld map[string]bool) []string {
	var out []string
	for _, n := range in {
		if withheld[n] {
			continue
		}
		out = append(out, n)
	}
	return out
}
