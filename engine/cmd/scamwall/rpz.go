// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/enforce"
	"github.com/dubyfls/Pinga53/engine/internal/ledger"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/rpz"
)

// # WHAT `rpz` IS, AND WHY IT IS NOT A FLAG ON `decide`
//
// `decide` answers a question and prints the answer. This command takes the
// same answer and WRITES A FILE A RESOLVER WILL ACT ON. That is a different
// power, and the repository's own rule — the one `sync --dry-run` follows and
// the one ORDER 8's C-17 note follows — is that a new power gets a new verb,
// so that "what can this command do" is answerable from the command line
// rather than from the flag list.
//
// It runs the IDENTICAL decision pipeline: `decide()`, the same function, not
// a second reading of it. A second pipeline is how the zone and the decision
// come to disagree.
//
// # IT STILL CONTACTS NOTHING
//
// Files in, files out. No configuration, no credential, no Pi-hole client, no
// path to a network client, and nothing that reloads a resolver. The allow
// list arrives as the operator's own offline export; see rpz.LoadSnapshot for
// why it is a file in this order and what ORDER 12 replaces it with.

// Exit codes, documented in --help because an unattended caller reads them
// and not this comment.
//
// Four outcomes rather than one failure code. "The zone is stale because the
// evidence supply is degraded", "the zone was not written because the run
// looked abnormal" and "the zone was not written because it would have been
// empty" call for three different actions from whoever is on the other end,
// and a single non-zero would make them one alert.
const (
	// exitReview — nothing written; a person has to look. Shares 3 with
	// propose's exitPartial: both mean "ran fine, did less than asked".
	exitReview = exitPartial
	// exitFrozen — nothing written; the inputs were not trustworthy.
	exitFrozen = 4
	// exitRefused — nothing written; the adapter's own safety rules said no.
	exitRefused = 5
)

// rpzResult is the JSON document, when asked for one.
type rpzResult struct {
	Result enforce.Result `json:"result"`
	// Standing is how many hosts the decision says should be blocked, before
	// the writer's own exclusions. Present so that a reader can see the
	// difference between "the plan is small" and "the writer excluded most of
	// it", which the entry count alone does not distinguish.
	Standing int `json:"standing"`
	// Decision is the run this zone was computed from, whole. The zone is one
	// rendering of it and carries none of the reasoning by design.
	Decision decision `json:"decision"`
}

func cmdRPZ(w *os.File, args []string) int {
	fs := flag.NewFlagSet("rpz", flag.ContinueOnError)
	fs.SetOutput(w)
	evidencePath := fs.String("evidence", "", "path to the signed evidence document (required)")
	signersPath := fs.String("signers", "", "path to the signer authority document (required)")
	registryPath := fs.String("registry", "", "path to the source registry (required)")
	policyPath := fs.String("policy", "", "path to the proposal policy (required)")
	ledgerPath := fs.String("ledger", "", "path to the ownership ledger (required: the zone is the "+
		"whole standing set, and a run that cannot show what it owns cannot write one)")
	allowPath := fs.String("allowlist", "", "path to the household's allow-list snapshot; without "+
		"it the run freezes and the existing zone is left alone")
	outPath := fs.String("out", "", "path to write the zone to; omitted implies --dry-run")
	dryRun := fs.Bool("dry-run", false, "compute everything and write nothing")
	allowEmpty := fs.Bool("allow-empty", false, "permit a zone with no entries, which withdraws "+
		"every block ScamWall is holding")
	origin := fs.String("origin", rpz.DefaultOrigin, "the zone origin")
	maxEntries := fs.Int("max-entries", rpz.DefaultMaxEntries, "refuse a zone larger than this")
	keyPath := fs.String("key", "", "path to the MAC key file; without it the decision record "+
		"beside the zone is written UNSEALED and says so")
	at := fs.String("at", "", "evaluation instant, RFC 3339 (default: now)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	maxBytes := fs.Int64("max-bytes", decideMaxEvidenceBytes, "maximum evidence document size")
	maxRecords := fs.Int("max-records", decideMaxRecords, "maximum records in one evidence document")
	outageReason := fs.String("source-outage", "", "declare the evidence supply degraded, with a "+
		"reason; the zone is then left exactly as it is")
	maxAcqAge := fs.Duration("max-acquisition-age", 0, "treat the supply as degraded when the "+
		"ledger's last acquisition is older than this; unset measures nothing")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	for flagName, v := range map[string]string{
		"-evidence": *evidencePath, "-signers": *signersPath, "-registry": *registryPath,
		"-policy": *policyPath, "-ledger": *ledgerPath,
	} {
		if v == "" {
			fmt.Fprintf(w, "rpz: %s is required\n", flagName)
			return exitUsage
		}
	}

	instant := time.Now().UTC()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintf(w, "rpz: -at is not an RFC 3339 instant: %v\n", err)
			return exitUsage
		}
		instant = t.UTC()
	}

	report, pol, code := buildReport(w, *evidencePath, *signersPath, *registryPath, *policyPath,
		*maxBytes, *maxRecords, instant)
	if code != exitOK {
		return code
	}
	led, err := ledger.Load(*ledgerPath)
	if err != nil {
		return fail(w, err)
	}

	// A MISSING SNAPSHOT IS NOT AN EMPTY ONE, and is not a usage error
	// either: the zone must survive it unchanged, which means running the
	// adapter and letting it freeze rather than exiting before it.
	var snapshot rpz.Snapshot
	if *allowPath != "" {
		if snapshot, err = rpz.LoadSnapshot(*allowPath); err != nil {
			return fail(w, err)
		}
	}

	var key *mac.Key
	if *keyPath != "" {
		if key, err = mac.LoadKeyFile(*keyPath); err != nil {
			return fail(w, err)
		}
	}

	outage := assessOutage(led, instant, *outageReason, *maxAcqAge)
	d := decide(report, pol, led, instant, proposal.AutoInputs{
		EmergencyStopPresent: emergencyStopPresent(pol),
	}, outage)
	plan := planFrom(d, led, report)

	writer := &rpz.Writer{
		Path:              *outPath,
		Origin:            *origin,
		Now:               instant,
		Snapshot:          snapshot,
		Policy:            pol,
		PrevSerial:        led.Serial,
		MaxEntries:        *maxEntries,
		AllowEmpty:        *allowEmpty,
		DryRun:            *dryRun || *outPath == "",
		Stale:             outage.Degraded,
		StaleReason:       outage.Reason,
		MaxAddsPerRun:     intOr(pol, func(a *proposal.Automatic) *int { return a.MaxAdditionsPerRun }),
		MaxRemovalsPerRun: intOr(pol, func(a *proposal.Automatic) *int { return a.MaxRemovalsPerRun }),
		Key:               key,
	}
	res, err := writer.Enforce(plan)
	if err != nil {
		return fail(w, err)
	}

	bw := bufio.NewWriter(w)
	if *asJSON {
		enc := json.NewEncoder(bw)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rpzResult{Result: res, Standing: len(plan.Standing), Decision: d}); err != nil {
			return fail(w, err)
		}
	} else {
		writeRPZ(bw, res, plan)
	}
	if err := bw.Flush(); err != nil {
		return fail(w, err)
	}
	return exitFor(res.Outcome)
}

// exitFor maps an outcome onto a status an unattended caller can branch on.
//
// OutcomeApplied and OutcomeNoChange are both 0: the run did what it was
// asked, and "the zone already said this" is a success. OutcomeReported is 0
// as well, because a dry run that reached the end succeeded at being a dry
// run. Everything else is a refusal of some kind and gets its own code.
func exitFor(o enforce.Outcome) int {
	switch o {
	case enforce.OutcomeApplied, enforce.OutcomeNoChange, enforce.OutcomeReported:
		return exitOK
	case enforce.OutcomeReview:
		return exitReview
	case enforce.OutcomeFrozen:
		return exitFrozen
	case enforce.OutcomeRefused:
		return exitRefused
	default:
		// An outcome this build does not know is not a success. A future
		// outcome added to the vocabulary must not default to "written".
		return exitFailure
	}
}

// planFrom expresses one decided run in the adapter vocabulary.
//
// # THE STANDING SET IS THE LEDGER, PLUS THIS RUN, MINUS THIS RUN
//
// The zone is whole-state: it must contain every host that should be blocked
// once this run is applied, which is what ScamWall already owns, plus what
// this run adds, minus what it removes. Building it from the plan's additions
// alone would write a zone holding only today's work and unblock everything
// else; building it from the ledger alone would write a zone that ignores the
// decision that was just made.
//
// A HOLD IS NOT A DEFERRAL and both reach the adapter as themselves. C-20's
// run-level holds are carried as Review with no canonical name, because they
// are statements about the RUN rather than about a host, and an operator
// seeing them beside the per-host exclusions needs to be able to tell which
// is which.
func planFrom(d decision, led *ledger.Ledger, rep *proposal.Report) enforce.Plan {
	p := enforce.Plan{
		Adds:     append([]string(nil), d.Additions...),
		Removals: append([]string(nil), d.Removals...),
		Deferred: d.Deferred,
	}
	if d.Held {
		p.Review = append(p.Review, enforce.ReviewItem{
			Reason: string(d.HeldReason), Explanation: d.HeldExplanation,
		})
	}
	if d.RemovalHeld {
		p.Review = append(p.Review, enforce.ReviewItem{
			Reason: string(d.RemovalReason), Explanation: d.RemovalDetail,
		})
	}

	going := make(map[string]bool, len(d.Removals))
	for _, n := range d.Removals {
		going[n] = true
	}
	standing := make(map[string]string, led.Count()+len(d.Additions))
	for _, o := range led.Owned {
		if !going[o.Canonical] {
			standing[o.Canonical] = o.Digest
		}
	}
	// AN ADDITION HAS NO LEDGER ROW YET, so its entry comment carries the
	// digest of the evidence document the decision was made from. It names
	// the run rather than the indicator, which is less than a per-host digest
	// and is what this build actually has: proposal.Report seals per-outcome
	// digests inside its own seal and exports none of them.
	var runDigest string
	if rep != nil {
		runDigest = rep.Binding.EvidenceDigest
	}
	for _, n := range d.Additions {
		if _, held := standing[n]; !held {
			standing[n] = runDigest
		}
	}

	p.Standing = make([]enforce.StandingEntry, 0, len(standing))
	for name, digest := range standing {
		p.Standing = append(p.Standing, enforce.StandingEntry{Canonical: name, Digest: digest})
	}
	sort.Slice(p.Standing, func(i, j int) bool { return p.Standing[i].Canonical < p.Standing[j].Canonical })
	return p
}

// writeRPZ renders the result for a person.
func writeRPZ(w *bufio.Writer, r enforce.Result, p enforce.Plan) {
	fmt.Fprintln(w, enforce.Describe(r))
	fmt.Fprintf(w, "  %d host(s) standing in the decision, %d written\n", len(p.Standing), r.Entries)
	if r.Artifact != "" {
		fmt.Fprintf(w, "  zone:   %s\n", r.Artifact)
		fmt.Fprintf(w, "  serial: %s\n", r.Serial)
		fmt.Fprintf(w, "  digest: %s\n", r.Digest)
	}
	if len(r.Review) > 0 {
		fmt.Fprintf(w, "\nheld for a person (%d):\n", len(r.Review))
		for _, item := range r.Review {
			name := item.Canonical
			if name == "" {
				name = "(this run)"
			}
			fmt.Fprintf(w, "  %-40s %s\n", name, item.Reason)
			if item.Explanation != "" {
				fmt.Fprintf(w, "      %s\n", item.Explanation)
			}
		}
	}
	fmt.Fprintln(w, "\nNothing here reloads a resolver. Loading the zone is an operator step.")
}
