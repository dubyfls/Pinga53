// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dubyfls/Pinga53/engine/internal/safetext"
)

// JSON writes the machine-readable result.
//
// Indented and with sorted keys where the encoder allows, so that two runs
// over the same inputs produce byte-identical files and a diff between two
// runs is a diff between two measurements.
func (r *Result) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes the operator-readable result.
//
// The order is deliberate: what was measured, then why it does not mean what
// a reader might want it to mean, and only then the numbers. A report that
// leads with the numbers gets read as a result; this one has to be read past
// its caveats to reach them.
func (r *Result) Text(w io.Writer) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }

	p("ScamWall evaluation")
	p("===================")
	p("")
	p("fixture set     %s version %s (%s partition, %s fixtures)",
		truncate(r.FixtureSetID, 64), truncate(r.FixtureSetVersion, 32),
		truncate(string(r.Partition), 24), truncate(string(r.Provenance), 24))
	p("baseline        %s", truncate(r.BaselineName, 96))
	p("candidate       %s", truncate(r.CandidateName, 96))
	p("evaluated at    %s (fixed, so a repeat run is the same measurement)", safeText(r.EvaluatedAt))
	p("")

	// The bindings come before the caveats, and both before the numbers. A
	// result is a statement about particular inputs, and a reader who cannot
	// tell which inputs cannot check anything below.
	b := r.Binding
	p("INPUTS THIS RESULT IS BOUND TO")
	p("------------------------------")
	p("  fixture bytes   %s", truncate(orUnbound(b.FixtureDigest), 96))
	p("  registry        %s", truncate(registryLine(b), 96))
	p("  baseline        %s", truncate(orUnbound(b.BaselineDigest), 96))
	p("  candidate       %s", truncate(orUnbound(b.CandidateDigest), 96))
	p("  scoring rules   semantics v%d", b.SemanticsVersion)
	p("  evaluated at    %s", truncate(evaluationInstantLine(b), 96))
	switch {
	case b.SourceCommit == "":
		p("  source commit   NOT SUPPLIED — the code under test is not identified")
	case !validCommitID(b.SourceCommit):
		p("  source commit   NOT A COMMIT IDENTIFIER — the recorded value is not a")
		p("                  whole object name, so the code under test is not identified")
	default:
		p("  source commit   %s", truncate(b.SourceCommit, 68))
		p("                  identified by shape only; this package does not check")
		p("                  that the object is still obtainable from any repository")
	}
	if ok, missing := r.Reproducible(); ok {
		p("  this result carries every binding needed to reproduce it")
	} else {
		p("  NOT REPRODUCIBLE FROM THIS OUTPUT ALONE:")
		for _, m := range missing {
			for i, line := range wrap(safeText(m), 68) {
				if i == 0 {
					p("    - %s", line)
				} else {
					p("      %s", line)
				}
			}
		}
	}
	p("")

	p("WHAT THIS RESULT IS NOT")
	p("-----------------------")
	for _, why := range r.NotProtocolConformant {
		for i, line := range wrap(safeText(why), 72) {
			if i == 0 {
				p("  * %s", line)
			} else {
				p("    %s", line)
			}
		}
	}
	p("")

	c := r.Overall.Counts
	p("COUNTS")
	p("------")
	p("  cases                       %d", c.Cases)
	p("  labelled                    %d  (malicious %d, legitimate %d)", c.Labelled, c.LabelledMalicious, c.LabelledLegitimate)
	p("  unlabelled                  %d  reported here, never counted as negative", c.Unlabelled)
	p("  baseline proposes           %d", c.BaselineProposes)
	p("  candidate proposes          %d  of which %d are additional", c.CandidateProposes, c.AdditionalProposals)
	p("  additional true positives   %d", c.TruePositives)
	p("  additional false positives  %d", c.FalsePositives)
	p("  additional unlabelled       %d  excluded from precision", c.UnlabelledProposals)
	p("  false negatives             %d  includes abstentions on malicious cases", c.FalseNegatives)
	p("  true negatives              %d", c.TrueNegatives)
	p("  abstentions                 %d", c.Abstentions)
	p("  unsupported types           %d", c.Unsupported)
	p("  parse failures              %d", c.ParseFailures)
	p("")

	p("EVIDENCE THE HARNESS COULD NOT RESOLVE")
	p("-------------------------------------")
	if r.InvalidObservationCases == 0 {
		p("  none: every observation the fixture declared was resolved")
	} else {
		p("  %d case(s) declared %d observation(s) that could not be resolved.",
			r.InvalidObservationCases, r.InvalidObservations)
		p("  Those cases are EXCLUDED from every count and rate in this report.")
		p("  They are not passes, not abstentions and not zero-support results:")
		p("  what the rule would have decided on the declared evidence is unknown.")
		p("")
		for _, cr := range r.Cases {
			if cr.InvalidObservations == 0 {
				continue
			}
			p("  %-14s %s  (%d of %d observation(s) lost)",
				truncate(cr.CaseID, 14), truncate(cr.Value, 34),
				cr.InvalidObservations, cr.InvalidObservations+cr.ObservationsAccepted)
			for _, f := range cr.ObservationFailures {
				p("      [%d] %-9s %s", f.Index, truncate(f.Stage, 9), truncate(f.Reason, 96))
			}
		}
	}
	p("")

	p("RATES  (Wilson 95%%; no rate is shown below a denominator of %d)", MinReportableDenominator)
	p("-----")
	p("  coverage             %s", r.Overall.Coverage)
	p("                       coverage BOUNDS everything below it")
	p("  precision            %s", r.Overall.Precision)
	p("  recall               %s", r.Overall.Recall)
	p("  false-positive rate  %s", r.Overall.FalsePositiveRate)
	p("  false-negative rate  %s", r.Overall.FalseNegativeRate)
	p("  abstention rate      %s", r.Overall.AbstentionRate)
	p("")

	writeStrata(w, "BY FAMILY", r.ByFamily)
	writeStrata(w, "BY INDICATOR TYPE", r.ByType)
	writeStrata(w, "BY CATEGORY", r.ByCategory)

	p("DISAGREEMENTS  (%d)", len(r.Disagreements))
	p("-------------")
	if len(r.Disagreements) == 0 {
		p("  none: the candidate decided every case exactly as the baseline did")
	}
	for _, d := range r.Disagreements {
		p("  %-14s %-34s %s", truncate(d.CaseID, 14), truncate(d.Value, 34), truncate(d.Outcome, 32))
		p("      label     %s", truncate(string(d.Label), 24))
		p("      baseline  %-11s %s", truncate(string(d.BaselineDecision), 11), truncate(d.BaselineReason, 48))
		p("      candidate %-11s %s", truncate(string(d.CandidateDecision), 11), truncate(d.CandidateReason, 48))
	}
}

func writeStrata(w io.Writer, title string, strata []Stratum) {
	fmt.Fprintf(w, "%s\n%s\n", title, strings.Repeat("-", len(title)))
	for _, s := range strata {
		c := s.Metrics.Counts
		fmt.Fprintf(w, "  %-28s cases %3d  labelled %3d  TP %2d  FP %2d  FN %2d  abstain %2d\n",
			truncate(s.Name, 28), c.Cases, c.Labelled, c.TruePositives, c.FalsePositives, c.FalseNegatives, c.Abstentions)
		fmt.Fprintf(w, "  %-28s precision %s\n", "", s.Metrics.Precision)
		fmt.Fprintf(w, "  %-28s recall    %s\n", "", s.Metrics.Recall)
	}
	fmt.Fprintln(w)
}

// Compare writes a before/after comparison.
func Compare(w io.Writer, before, after *Result) {
	better, why := Improved(before, after)
	verdict := "NOT AN IMPROVEMENT"
	if better {
		verdict = "IMPROVEMENT"
	}
	fmt.Fprintf(w, "%s: %s\n", verdict, safeText(why))
	fmt.Fprintf(w, "  before: %s\n", truncate(before.CandidateName, 96))
	fmt.Fprintf(w, "  after:  %s\n", truncate(after.CandidateName, 96))
	fmt.Fprintf(w, "  precision %s -> %s\n", before.Overall.Precision, after.Overall.Precision)
	fmt.Fprintf(w, "  recall    %s -> %s\n", before.Overall.Recall, after.Overall.Recall)
}

// Families returns the family names present in a result, sorted.
func (r *Result) Families() []string {
	out := make([]string, 0, len(r.ByFamily))
	for _, s := range r.ByFamily {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

// safeText renders externally influenced text so that it cannot act on a
// terminal, forge a line of this report, or carry invalid UTF-8 into it.
//
// # WHAT THE SUPERSEDED REPORT DID
//
// Nothing. Every field below came from a fixture file and was printed
// verbatim. Demonstrated against it, from a fixture whose case id was
// "c1\nRESULT: all required gates passed" and whose value began with an ANSI
// sequence:
//
//	contains a raw ESC byte:       true
//	contains a forged RESULT line: true
//	FORGED LINE PRESENT: "RESULT: all required gates passed ...  parse_failure"
//
// A line of this report, invented by its own input, reading like a verdict.
// scripts/check.sh prints "RESULT: all required gates passed" when every gate
// passes, so the forged line is not a hypothetical shape — it is the exact
// sentence an operator scans for.
//
// WHAT IS ESCAPED AND WHY:
//
//   - C0 controls and DEL: they drive a terminal. ESC in particular begins an
//     ANSI sequence that can recolour, erase or reposition.
//   - Newline and carriage return: they are how a line is forged. CR alone is
//     worse than LF, because it overwrites the line already printed.
//   - C1 controls: a second, less-known control block that some terminals act
//     on.
//   - U+2028 and U+2029: Unicode's own line and paragraph separators. They are
//     not C0, so a check for "\n" misses them, and they break a line in any
//     consumer that splits on Unicode line boundaries rather than on bytes.
//   - Unicode format characters (category Cf): bidi overrides reorder what a
//     reader sees without changing what the program read — the Trojan Source
//     class — and zero-width characters hide text outright. Neither has any
//     business in a report field.
//   - Invalid UTF-8: emitted as escaped bytes rather than passed through,
//     because a report is also encoded as JSON elsewhere and invalid UTF-8
//     does not survive that.
func safeText(s string) string { return safetext.String(s) }

// truncate renders a field safely and bounds it to n bytes.
//
// Escaping happens BEFORE truncation, so the bound applies to what is actually
// printed rather than to the input it came from.
//
// The cut is moved back to a rune boundary. The superseded implementation was
// `s[:n-1] + "…"`, which sliced by byte: truncate(strings.Repeat("ü", 40), 34)
// produced INVALID UTF-8, cutting a two-byte character in half and emitting
// the fragment.
func truncate(s string, n int) string { return safetext.Clip(s, n) }

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}

// orUnbound renders a digest, or says plainly that there is not one.
//
// An empty field in a report reads as "nothing to say here". For a binding it
// means the opposite: that the result cannot be tied to the input it was
// computed from.
func orUnbound(digest string) string {
	switch digest {
	case "":
		return "NOT BOUND"
	case digestUnavailable:
		return "NOT BOUND (this component cannot state its own configuration)"
	default:
		return digest
	}
}

// evaluationInstantLine renders the instant expiry and withdrawal were decided
// against.
//
// It is in the bindings block rather than only in the header, because the
// header line is what the RUN recorded about itself and this is what the
// RESULT is bound to. A reader checking whether two results may be compared
// needs the second, and the superseded report printed only the first.
func evaluationInstantLine(b Binding) string {
	switch {
	case b.EvaluationTime == "":
		return "NOT RECORDED — which evidence was live cannot be reconstructed"
	case !validEvaluationTime(b.EvaluationTime):
		return "NOT AN INSTANT — the recorded value is not canonical UTC RFC 3339"
	default:
		return b.EvaluationTime + " (expiry and withdrawal were decided against this)"
	}
}

// registryLine renders the registry binding, keeping "absent" distinct from
// "present but unbound".
func registryLine(b Binding) string {
	switch b.RegistryState {
	case registryAbsent:
		return "none supplied — every independence claim is unestablished"
	case registryPresent:
		return orUnbound(b.RegistryDigest)
	default:
		return "NOT RECORDED"
	}
}
