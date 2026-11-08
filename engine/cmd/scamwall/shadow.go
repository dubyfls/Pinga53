// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/adapters/pihole"
	"github.com/dubyfls/Pinga53/engine/internal/audit"
	"github.com/dubyfls/Pinga53/engine/internal/config"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/journal"
	"github.com/dubyfls/Pinga53/engine/internal/policy"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/shadow"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT `shadow` IS
//
// It reads the appliance and reports the exact change ScamWall would request
// of it. It is the first command in this repository that needs the target's
// own state, and that is the whole point: `propose` answers "which domains
// meet the policy", which is the same answer whether the household already
// blocks all of them or none.
//
// # WHAT IT CANNOT DO
//
// Request anything. The only Pi-hole calls it can construct are the four in
// pihole.PermittedOperations that this path reaches — POST and DELETE on
// ScamWall's own session, and GET /api/domains/deny/exact — and the allowlist
// is checked before name resolution and again on every redirect. A test drives
// this command against a server that records every request it receives and
// asserts that no other method or path arrives.
//
// Unlike `propose`, it DOES take the configuration file and DOES open the
// application password, because a session is the only way Pi-hole will answer
// a state read. That is the cost of comparing against the real appliance
// rather than an assumption about it.

func cmdShadow(ctx context.Context, w *os.File, log *audit.Logger, args []string) int {
	fs, cfgPath := newFlagSet("shadow", w)
	evidencePath := fs.String("evidence", "", "path to the signed evidence document (required)")
	signersPath := fs.String("signers", "", "path to the signer authority document (required)")
	registryPath := fs.String("registry", "", "path to the source registry (required)")
	policyPath := fs.String("policy", "", "path to the proposal policy (required)")
	at := fs.String("at", "", "evaluation instant, RFC 3339 (default: now)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	maxBytes := fs.Int64("max-bytes", defaultMaxEvidenceBytes, "maximum evidence document size")
	maxRecords := fs.Int("max-records", defaultMaxRecords, "maximum records in one evidence document")
	staleReason := fs.String("evidence-stale", "", "declare the evidence stale, with a reason; "+
		"every addition is then reported and NOT requested")
	journalPath := fs.String("journal", "", "path to the decision journal; a revision is appended "+
		"only where the verdict for a host has substantively changed, and NOTHING is recorded "+
		"at all if this run did not read the appliance")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	for flagName, v := range map[string]string{
		"-evidence": *evidencePath, "-signers": *signersPath,
		"-registry": *registryPath, "-policy": *policyPath,
	} {
		if v == "" {
			fmt.Fprintf(w, "shadow: %s is required\n", flagName)
			return exitUsage
		}
	}

	instant := time.Now().UTC()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintf(w, "shadow: -at is not an RFC 3339 instant: %v\n", err)
			return exitUsage
		}
		instant = t.UTC()
	}

	report, policy, code := buildReport(w, *evidencePath, *signersPath, *registryPath, *policyPath,
		*maxBytes, *maxRecords, instant)
	if code != exitOK {
		return code
	}

	// THE AUTOMATIC CONTRACT DECIDES WHAT WOULD BE REQUESTED.
	//
	// Not the proposal decision. A proposal is a statement that a domain met
	// the policy; a request to the appliance is an unattended act, and the
	// contract is what the household wrote about those. A run whose contract
	// is unresolved therefore compares an EMPTY qualifying set against the
	// real appliance, which is the honest shape: it still reads the target,
	// still binds what it saw, and asks for nothing.
	//
	// The emergency stop is consulted here and nowhere else. This command
	// opens the path the household named and reports whether it was there;
	// internal/proposal opens nothing.
	auto := proposal.Qualify(report, policy, proposal.AutoInputs{
		EmergencyStopPresent: emergencyStopPresent(policy),
	})

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(w, err)
	}
	secret, err := config.LoadSecretFile(cfg.Pihole.SecretPath)
	if err != nil {
		return fail(w, err)
	}
	defer secret.Destroy()

	client, err := pihole.New(cfg, log)
	if err != nil {
		return fail(w, err)
	}

	// observed is filled inside the session and read after it. Complete stays
	// false unless the read returned: an interrupted read must not reach
	// shadow.Compare, which refuses one, and a zero Observation would be an
	// empty appliance rather than an unknown one.
	var observed shadow.Observation
	// allow carries the household's own allow lists. It stays AllowNotRead
	// unless BOTH reads return: a half-read allow list is the same hazard as
	// a half-read deny list, and "the entries I managed to fetch do not cover
	// this" is not the statement the plan needs.
	var allow shadow.AllowList = shadow.AllowNotRead{}
	err = client.WithSession(ctx, secret, func(ctx context.Context) error {
		entries, readErr := client.DenyExactDomains(ctx)
		if readErr != nil {
			return readErr
		}
		allowExact, readErr := client.AllowExactDomains(ctx)
		if readErr != nil {
			return readErr
		}
		allowRegex, readErr := client.AllowRegexDomains(ctx)
		if readErr != nil {
			return readErr
		}
		allow = newAllowList(allowExact, allowRegex)
		observed = shadow.Observation{
			Entries:       toShadowEntries(entries),
			ReadAt:        time.Now().UTC(),
			TargetHost:    cfg.Pihole.Host,
			TargetAddress: cfg.DialAddress(),
			Complete:      true,
		}
		if s, i, ok := client.PeerCertificateIdentity(); ok {
			observed.TLSSubject, observed.TLSIssuer = s, i
		}
		return nil
	})
	if err != nil {
		// THE READ FAILED, AND THE JOURNAL IS STILL ASKED.
		//
		// C-23 is a control only if something actually asks for the thing it
		// refuses. Calling Record only on the success path would leave the
		// refusal as a branch no run can reach, and the operator would see
		// nothing rather than a stated reason. So the attempt is made, it is
		// refused, and the run is reported INCOMPLETE — which is a different
		// sentence from a run that had nothing to say.
		if *journalPath != "" {
			fmt.Fprintf(w, "%s\n", journalRun(*journalPath, nil, observed, instant).note)
		}
		return failWithTeardown(w, err, client.SessionTeardown())
	}

	// The session outcome is bound into the plan, so a filed JSON document
	// records whether ScamWall left a session standing on the appliance.
	// Read here rather than inside the closure: the teardown has not happened
	// until WithSession's deferred logout has run.
	observed.SessionTeardown = client.SessionTeardown().String()

	plan, err := shadow.Compare(shadow.Input{
		Qualifying: auto.Blocks,
		Observed:   observed,
		// NoOwnership, explicitly. This build keeps no ownership ledger, so
		// every entry the appliance holds is the household's and nothing is
		// proposed for removal. Passing an empty ledger instead would answer
		// every domain the same way and describe itself as a ledger.
		Owned: shadow.NoOwnership{},
		// C-25. SubscribedNotRead, explicitly. This build cannot read gravity —
		// the endpoint that answers "which lists contain this host" takes the
		// host in the URL path, and the client's allowlist is over exact
		// (method, path) pairs — so every addition is held for review rather
		// than requested. See internal/shadow.SubscribedNotRead.
		Subscribed:        shadow.SubscribedNotRead{},
		Allow:             allow,
		EvidenceDigest:    report.Binding.EvidenceDigest,
		PolicyDigest:      report.Binding.PolicyDigest,
		ReportEvaluatedAt: report.Binding.EvaluatedAt,
		ComparedAt:        time.Now().UTC(),
		BuildIdentity:     buildIdentity(),
		EvidenceStale:     *staleReason != "",
		StaleReason:       *staleReason,
	})
	if err != nil {
		return failWithTeardown(w, err, client.SessionTeardown())
	}

	// THE JOURNAL IS WRITTEN BEFORE ANYTHING IS RENDERED.
	//
	// So that a journal failure is reported like every other failure that
	// happens before output — as an error and a non-zero exit — rather than
	// as prose appended after a JSON document, which would stop the output
	// being JSON. A run whose journal could not be written has not finished,
	// whichever rendering was asked for.
	var journalled journalOutcome
	if *journalPath != "" {
		journalled = journalRun(*journalPath, plan, observed, instant)
		if !journalled.ok {
			fmt.Fprintf(w, "%s\n", journalled.note)
			_ = reportTeardown(w, client.SessionTeardown())
			return exitFailure
		}
	}

	bw := bufio.NewWriter(w)
	if *asJSON {
		if err := plan.JSON(bw); err != nil {
			return fail(w, err)
		}
		if err := bw.Flush(); err != nil {
			return fail(w, err)
		}
		// No trailing prose. The teardown is a field of the document
		// above; printing it again after the closing brace would make the
		// output stop being JSON.
		return teardownExit(client.SessionTeardown())
	}
	plan.Text(bw)
	writeContractState(bw, auto)
	if journalled.note != "" {
		fmt.Fprintf(bw, "\n%s\n", journalled.note)
	}
	if err := bw.Flush(); err != nil {
		return fail(w, err)
	}
	return reportTeardown(w, client.SessionTeardown())
}

// writeContractState says why the qualifying set was the size it was.
//
// A shadow plan with no additions and an unresolved contract looks exactly
// like one with no additions because nothing qualified, and those are
// different facts about the household.
func writeContractState(w *bufio.Writer, auto *proposal.AutoPlan) {
	block, abstain, refuse := auto.Counts()
	fmt.Fprintf(w, "\nautomatic contract: %s\n", auto.State)
	fmt.Fprintf(w, "  %d would be blocked without asking, %d abstained, %d refused\n",
		block, abstain, refuse)
	if auto.Held {
		fmt.Fprintf(w, "  THE RUN IS HELD: %s\n", auto.HeldExplanation)
	}
	for _, u := range auto.Unresolved {
		fmt.Fprintf(w, "  UNRESOLVED: %s — no value was substituted\n", u)
	}
	fmt.Fprintln(w, "  values this build records and does not act on:")
	for _, n := range auto.NotEnforced {
		fmt.Fprintf(w, "    - %s\n", n)
	}
}

// emergencyStopPresent reports whether the household's stop file is there.
//
// os.Stat, and an ERROR OTHER THAN "does not exist" counts as PRESENT. A stop
// file this process cannot stat is a stop file whose state is unknown, and
// the fail-closed reading of "I could not tell whether you asked me to stop"
// is to stop.
func emergencyStopPresent(p *proposal.Policy) bool {
	if p == nil || p.Automatic == nil || p.Automatic.EmergencyDisablePath == nil {
		return false
	}
	_, err := os.Stat(*p.Automatic.EmergencyDisablePath)
	if err == nil {
		return true
	}
	return !errors.Is(err, os.ErrNotExist)
}

func toShadowEntries(in []pihole.DomainEntry) []shadow.Entry {
	out := make([]shadow.Entry, 0, len(in))
	for _, e := range in {
		out = append(out, shadow.Entry{Domain: e.Domain, Enabled: e.Enabled, Comment: e.Comment})
	}
	return out
}

// buildReport is the four-document offline path `propose` also runs.
//
// Shared rather than copied: two readings of the same four files would drift,
// and the one that drifted would be the one nobody ran.
func buildReport(w *os.File, evidencePath, signersPath, registryPath, policyPath string,
	maxBytes int64, maxRecords int, instant time.Time) (*proposal.Report, *proposal.Policy, int) {

	authority, err := feed.LoadSignerAuthority(signersPath)
	if err != nil {
		return nil, nil, fail(w, err)
	}
	reg, problems, err := sourceregistry.Load(registryPath)
	if err != nil {
		return nil, nil, fail(w, err)
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
		return nil, nil, exitFailure
	}
	policy, err := proposal.LoadPolicy(policyPath)
	if err != nil {
		return nil, nil, fail(w, err)
	}
	evidence, err := feed.LoadEvidenceFile(evidencePath, feed.EvidenceOptions{
		MaxFileBytes: maxBytes, MaxRecords: maxRecords, Authority: authority, Now: instant,
	})
	if err != nil {
		return nil, nil, fail(w, err)
	}
	report, err := proposal.Build(proposal.Input{
		Evidence: evidence, Registry: reg, Policy: policy, At: instant,
		BuildIdentity: buildIdentity(),
	})
	if err != nil {
		return nil, nil, fail(w, err)
	}
	return report, policy, exitOK
}

// newAllowList turns the appliance's allow rows into the answer shadow needs.
//
// The POSIX-versus-RE2 question lives in internal/policy and is answered
// there; this function only carries the answer across, so that internal/shadow
// keeps its property of depending on nothing else in the tree.
//
// ORDER 8 control C-18, FINDING-132.
func newAllowList(exact, regex []pihole.DomainEntry) shadow.AllowList {
	exactNames := make([]string, 0, len(exact))
	for _, e := range exact {
		// A DISABLED allow entry allows nothing, exactly as a disabled deny
		// entry blocks nothing. Counting it would report the household as
		// having permitted something it switched off.
		if !e.Enabled {
			continue
		}
		exactNames = append(exactNames, e.Domain)
	}
	patterns := make([]string, 0, len(regex))
	for _, e := range regex {
		if !e.Enabled {
			continue
		}
		patterns = append(patterns, e.Domain)
	}

	// Evaluability is a property of the patterns, not of any one host, so it
	// is measured once here rather than recomputed for every candidate.
	unevaluable := 0
	for _, p := range patterns {
		if !policy.ParseAllowRegex(p).Evaluable {
			unevaluable++
		}
	}

	return shadow.ObservedAllowList{
		Covers: func(d string) bool {
			return policy.CoverAllow(d, exactNames, patterns).Allowed()
		},
		Exact:        len(exactNames),
		Regex:        len(patterns),
		NotEvaluable: unevaluable,
	}
}

// # C-22 AND C-23, WIRED INTO THE ONE COMMAND THAT READS THE APPLIANCE
//
// internal/journal was complete, tested and imported by nothing outside its
// own tests. `REQUIREMENTS_MATRIX.md` §5.9.6 records it as RULE VERIFIED
// (synthetic), NO CALLER, which for C-23 is a particularly hollow state: the
// rule says a run that did not read the appliance may not journal what it
// would have changed there, and no run was journalling anything.
//
// `shadow` is the only command that reads an appliance, so it is the only
// place those rules can be reached honestly. A journal written by an offline
// command would be a journal of what ScamWall thought, filed as a record of
// what it saw — which is the exact substitution C-23 exists to refuse.

// journalOutcome is what one journal attempt came to.
//
// Returned rather than printed, because `shadow --json` must emit a JSON
// document and nothing else: a paragraph after the closing brace makes the
// output stop being JSON, which the text/JSON split in cmdShadow already
// refuses for the session teardown. The caller decides where this goes.
type journalOutcome struct {
	ok   bool
	note string
}

// journalRun records one shadow run, and reports what became of the attempt.
//
// It is called on BOTH paths, including the one where the read failed. That
// is deliberate: C-23's refusal is only a control if something actually asks
// for the thing it refuses. Calling Record only after a successful read would
// leave the refusal as an unreachable branch that no run can demonstrate, and
// the operator would see nothing at all rather than a stated reason.
func journalRun(path string, plan *shadow.Plan, observed shadow.Observation, at time.Time) journalOutcome {
	j, err := journal.LoadFile(path)
	switch {
	case errors.Is(err, journal.ErrAbsent):
		// A household's first run. Distinct from a journal that failed to
		// parse, which is not recoverable by starting a new one.
		j = journal.New()
	case err != nil:
		return journalOutcome{note: fmt.Sprintf("JOURNAL NOT WRITTEN: %v", err)}
	}

	in := journal.RunInput{
		At:       at,
		Observed: observed.Complete,
		Items:    journalItems(plan),
	}
	if plan != nil {
		in.ObservedDigest = plan.Binding.ObservedStateDigest
	}

	res, err := j.Record(in)
	if err != nil {
		// C-23. The refusal is total — not one row for the hosts whose
		// outcome needed no appliance to decide — and the run is reported as
		// INCOMPLETE rather than as a run that had nothing to say.
		return journalOutcome{note: fmt.Sprintf(
			"JOURNAL NOT WRITTEN, AND THE RUN IS INCOMPLETE: %v\n"+
				"  Nothing was recorded, for any host. A journal half-written under a rule\n"+
				"  that says it should not have been written at all is worse than none.", err)}
	}
	if err := j.SaveFile(path); err != nil {
		return journalOutcome{note: fmt.Sprintf("JOURNAL NOT WRITTEN: %v", err)}
	}

	note := fmt.Sprintf("journal: %d revision(s) appended, %d host(s) recorded for the first time",
		res.Appended, res.NewHosts)
	if res.Appended == 0 {
		note += "\n  Nothing changed substantively since the last run, so nothing was appended.\n" +
			"  Every host this journal has ever held is still in it: C-22 keeps a host\n" +
			"  once it has been recorded, and silence is not deletion."
	}
	return journalOutcome{ok: true, note: note}
}

// journalItems turns a shadow plan into one statement per host.
//
// # WHAT COUNTS AS SUBSTANCE
//
// The KIND and the precedence label, and nothing else. internal/journal takes
// substance as an opaque string precisely so that it cannot acquire an
// opinion about what matters in somebody else's decision, and the choice is
// the control: put the comparison instant or a run id in it and every run is
// substantive, which turns the journal into the unbounded log its package
// comment refuses to be. Put too little in and a real change goes unrecorded.
//
// The explanation is deliberately NOT included. Two runs can word the same
// verdict differently — a count inside a sentence is enough — and a journal
// that appended a revision for that would be recording this program's prose
// rather than the household's protection.
func journalItems(plan *shadow.Plan) []journal.Item {
	if plan == nil {
		return nil
	}
	out := make([]journal.Item, 0, len(plan.Changes))
	for _, c := range plan.Changes {
		out = append(out, journal.Item{
			Canonical: c.Domain,
			Substance: string(c.Kind) + "|" + string(c.Precedence),
			// BLOCKED means ScamWall would have this host blocked after the
			// run: it is adding one, or one it owns is already there. A
			// household-allowed or held-for-review host is NOT blocked, and
			// a disabled entry blocks nothing — counting either would let
			// C-21 read a lifetime from a run that protected nobody.
			Blocked: c.Kind == shadow.KindAdd || c.Kind == shadow.KindAlreadyPresent,
		})
	}
	return out
}
