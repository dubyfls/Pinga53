// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHY THIS COMMAND TAKES NO CONFIGURATION FILE
//
// Every other subcommand begins with loadConfig, because every other
// subcommand either talks to Pi-hole or reads the feed the deployment is
// configured with. This one does neither.
//
// The configuration file names the Pi-hole host, the CA, and the path to the
// application password. Opening it is how a command that has no business near
// a credential ends up near one — not by reading the secret, but by acquiring
// a reason to. So `propose` takes four explicit paths and nothing else: there
// is no code path from this command to config.Load, to
// config.LoadSecretFile, or to the Pi-hole adapter, and that is asserted by
// a test rather than by this comment.
//
// It also means the command runs on a machine that has no deployment at all,
// which is what makes it reviewable.

// exitPartial is returned when the run COMPLETED and at least one record was
// not admitted as evidence.
//
// A third status, because the two that exist cannot say this. Exit 0 would
// tell a script that a document half of which was refused was processed
// normally; exit 1 would say the run failed, which it did not — a refused
// record is a reported outcome and the report is complete. An operator
// piping this into anything needs to be able to tell the three apart.
const exitPartial = 3

// Defaults for the input bounds.
//
// They bound a local file the operator named, so they are generous rather
// than tight. They exist because "the operator named it" is not the same as
// "the operator meant it": a mistyped path finding a core dump should be
// refused by size rather than parsed.
const (
	defaultMaxEvidenceBytes = 8 << 20
	defaultMaxRecords       = 100000
)

func cmdPropose(w *os.File, args []string) int {
	fs := flag.NewFlagSet("propose", flag.ContinueOnError)
	fs.SetOutput(w)
	evidencePath := fs.String("evidence", "", "path to the signed evidence document (required)")
	signersPath := fs.String("signers", "", "path to the signer authority document (required)")
	registryPath := fs.String("registry", "", "path to the source registry (required)")
	policyPath := fs.String("policy", "", "path to the proposal policy (required)")
	at := fs.String("at", "", "evaluation instant, RFC 3339 (default: now)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	audience := fs.String("audience", string(proposal.AudienceLocal),
		"who the report is for: `local` (the household's own network) or `export` (what may leave it)")
	outPath := fs.String("out", "", "write the report to this file instead of stdout")
	maxBytes := fs.Int64("max-bytes", defaultMaxEvidenceBytes, "maximum evidence document size")
	maxRecords := fs.Int("max-records", defaultMaxRecords, "maximum records in one evidence document")
	identityKeyPath := fs.String("identity-key", "",
		"path to this installation's identity key; without it, hosts the report may not name carry no identifier")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	missing := map[string]string{
		"-evidence": *evidencePath,
		"-signers":  *signersPath,
		"-registry": *registryPath,
		"-policy":   *policyPath,
	}
	for flagName, v := range missing {
		if v == "" {
			fmt.Fprintf(w, "propose: %s is required\n", flagName)
			return exitUsage
		}
	}

	// THE IDENTITY KEY, WHERE THE OPERATOR SUPPLIED ONE.
	//
	// Optional, and its absence is REPORTED rather than worked around: a
	// report with no key labels no withheld host, and Report.Limitations says
	// so. Substituting an unkeyed digest would look exactly like a working
	// control and be none (C-09).
	//
	// Read through mac.LoadKeyFile and deliberately NOT through the
	// configuration package: this command is guarded, by a test over its own
	// source, against referencing that package at all, because the
	// configuration document names the Pi-hole application password. An
	// identity key is this build's own secret and nothing to do with the
	// appliance. The guard stays exactly as strict as it was.
	var identityKey *mac.Key
	if *identityKeyPath != "" {
		k, err := mac.LoadKeyFile(*identityKeyPath)
		if err != nil {
			// The error names the path and the length, never the content.
			return fail(w, err)
		}
		identityKey = k
	}

	// THE AUDIENCE IS CHECKED BEFORE ANYTHING IS READ.
	//
	// An unrecognised value falls through to the EXPORT rendering inside
	// ForAudience, which is the safe direction. It is still refused here:
	// a typo that silently produced a redacted report would be read as
	// "nothing qualified", which is a wrong answer delivered confidently.
	if *audience != string(proposal.AudienceLocal) && *audience != string(proposal.AudienceExport) {
		fmt.Fprintf(w, "propose: -audience must be %q or %q\n",
			proposal.AudienceLocal, proposal.AudienceExport)
		return exitUsage
	}

	// The instant is resolved BEFORE anything is read, so that every one of
	// the four inputs is judged against the same moment and the report binds
	// the one that was used.
	instant := time.Now().UTC()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintf(w, "propose: -at is not an RFC 3339 instant: %v\n", err)
			return exitUsage
		}
		instant = t.UTC()
	}

	authority, err := feed.LoadSignerAuthority(*signersPath)
	if err != nil {
		return fail(w, err)
	}

	// The registry is parsed and validated before it is used to authorise
	// anything. A registry with problems is refused rather than consulted:
	// every grant this run reads comes out of it, and a file that says
	// something impossible cannot be the thing that permits an operation.
	reg, problems, err := sourceregistry.Load(*registryPath)
	if err != nil {
		return fail(w, err)
	}
	problems = append(problems, reg.Validate(instant)...)
	if len(problems) > 0 {
		fmt.Fprintf(w, "error: the source registry has %d problem(s); every grant this command "+
			"reads comes out of it, so it is refused rather than consulted:\n", len(problems))
		for i, p := range problems {
			if i >= 20 {
				fmt.Fprintf(w, "  ... and %d more not listed\n", len(problems)-i)
				break
			}
			fmt.Fprintf(w, "  %s\n", p)
		}
		return exitFailure
	}

	policy, err := proposal.LoadPolicy(*policyPath)
	if err != nil {
		return fail(w, err)
	}

	evidence, err := feed.LoadEvidenceFile(*evidencePath, feed.EvidenceOptions{
		MaxFileBytes: *maxBytes,
		MaxRecords:   *maxRecords,
		Authority:    authority,
		Now:          instant,
	})
	if err != nil {
		return fail(w, err)
	}

	report, err := proposal.Build(proposal.Input{
		Evidence: evidence,
		Registry: reg,
		Policy:   policy,
		At:       instant,
		// The build identity comes from THIS command's own -ldflags and from
		// nowhere else. internal/proposal will not go looking for it: the
		// commit a working tree happens to sit at is not necessarily the
		// commit a binary was built from, and a plausible wrong answer is
		// worse than an absent one. A default build says `dev/unknown`, and
		// the report prints that rather than pretending to more.
		BuildIdentity: buildIdentity(),
		IdentityKey:   identityKey,
	})
	if err != nil {
		return fail(w, err)
	}

	report = report.ForAudience(proposal.Audience(*audience))

	if code := emit(w, report, *asJSON, *outPath); code != exitOK {
		return code
	}
	if report.Counts().RecordsRefused > 0 {
		return exitPartial
	}
	return exitOK
}

// emit writes the report where the operator asked for it.
//
// Writing a file is the only side effect this command has, it happens only
// when -out names one, and the name is the operator's. Nothing is written
// anywhere else, and nothing is sent anywhere at all.
func emit(w *os.File, report *proposal.Report, asJSON bool, outPath string) int {
	write := func(f *os.File) error {
		bw := bufio.NewWriter(f)
		if asJSON {
			if err := report.JSON(bw); err != nil {
				return err
			}
		} else {
			report.Text(bw)
		}
		return bw.Flush()
	}

	if outPath == "" {
		if err := write(w); err != nil {
			return fail(w, err)
		}
		return exitOK
	}

	// THE NAME THE OPERATOR ASKED FOR NEVER HOLDS A PARTIAL REPORT.
	//
	// The superseded implementation opened outPath directly and, when the
	// write failed, closed it and returned an error — leaving the truncated
	// bytes on disk under exactly the name the operator asked for. Measured
	// against 9dcb191 under `ulimit -f 4`: a 4,096-byte file, not valid JSON,
	// ending mid-record, sitting where a completed report belongs
	// (FINDING-129). A script globbing *.json, or a person reading a
	// truncated TEXT report — which is still readable prose — would take it
	// for evidence.
	//
	// So the content is written to a sibling temporary file, flushed, synced
	// and closed, and only then linked into place. The target name appears
	// atomically, already complete. A crash mid-write leaves the temporary
	// file, which is not the name anyone is looking for.
	//
	// os.Link rather than os.Rename: Rename REPLACES, and this command does
	// not overwrite a report. An operator who meant to replace one can remove
	// it; a script that silently overwrote yesterday's evidence would be
	// destroying the thing this command exists to produce.
	tmp := outPath + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(w, fmt.Errorf("%s exists; a previous run was interrupted "+
				"while writing. Remove it, then re-run", tmp))
		}
		return fail(w, err)
	}
	discard := func(cause error) int {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fail(w, cause)
	}
	if err := write(f); err != nil {
		return discard(err)
	}
	// Sync before Close: a deferred write error that only surfaces at close
	// would otherwise be reported after the link had already been made.
	if err := f.Sync(); err != nil {
		return discard(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fail(w, err)
	}
	if err := os.Link(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, os.ErrExist) {
			return fail(w, fmt.Errorf("%s already exists; this command does not overwrite a report", outPath))
		}
		return fail(w, err)
	}
	if err := os.Remove(tmp); err != nil {
		// The report IS written and complete; only the temporary copy
		// survives. Reported rather than swallowed, and not a failure of the
		// run.
		fmt.Fprintf(w, "warning: the report was written to %s but %s could not be removed: %v\n",
			outPath, tmp, err)
	}
	fmt.Fprintf(w, "report written to %s\n", outPath)
	return exitOK
}

// buildIdentity renders what this binary knows about itself.
//
// The three values are set with -ldflags at build time and default to
// "dev"/"unknown". Rendering the defaults rather than suppressing them is
// deliberate: "dev (commit unknown)" is a true statement about an
// unstamped build, and an empty field would be read as "the report forgot".
func buildIdentity() string {
	return fmt.Sprintf("scamwall %s (commit %s, built %s)", version, commit, built)
}
