// SPDX-License-Identifier: AGPL-3.0-only

// Command scamwall is the ScamWall command-line interface.
//
// Phase 1 is read-only and dry-run. No subcommand can modify Pi-hole.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/adapters/pihole"
	"github.com/dubyfls/Pinga53/engine/internal/audit"
	"github.com/dubyfls/Pinga53/engine/internal/config"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/policy"
)

// Build metadata, overridable with -ldflags at build time.
var (
	version = "dev"
	commit  = "unknown"
	built   = "unknown"
)

// Exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}

	cmd := args[0]
	rest := args[1:]

	// Signals are translated into context cancellation so that an interrupted
	// run still unwinds through the deferred logout rather than dying with a
	// live session on the server.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := audit.New(stderr)

	switch cmd {
	case "version":
		return cmdVersion(stdout, rest)
	case "doctor":
		return cmdDoctor(ctx, stdout, log, rest)
	case "status":
		return cmdStatus(ctx, stdout, log, rest)
	case "validate-feed":
		return cmdValidateFeed(stdout, log, rest)
	case "plan":
		return cmdPlan(stdout, log, rest)
	case "propose":
		return cmdPropose(stdout, rest)
	case "decide":
		return cmdDecide(stdout, rest)
	case "rpz":
		return cmdRPZ(stdout, rest)
	case "check":
		return cmdCheck(stdout, rest)
	case "shadow":
		return cmdShadow(ctx, stdout, log, rest)
	case "sync":
		return cmdSync(ctx, stdout, log, rest)
	case "gen-signer-key":
		return cmdGenSignerKey(stdout, rest)
	case "acquire":
		return cmdAcquire(stdout, rest)
	case "fetch":
		return cmdFetch(stdout, rest)
	case "merge-records":
		return cmdMergeRecords(stdout, rest)
	case "metrics":
		return cmdMetrics(stdout, rest)
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return exitUsage
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `scamwall - local-first fraud-domain protection for Pi-hole

Usage:
  scamwall <command> [flags]

Commands:
  version         Print build and enforcement information
  doctor          Check configuration, trust material and connectivity
                    --offline        skip every connectivity check
                    --no-credential  do not open the application password
  status          Authenticate, read Pi-hole version, log out
  validate-feed   Verify and validate the configured signed feed
  plan            Compute the proposed blocking plan (offline)
  propose         Turn a signed evidence document into domain proposals (offline)
                    --evidence  signed evidence document (schema 2)
                    --signers   signer authority: which key may speak for which source
                    --registry  source registry
                    --policy    proposal policy: threshold, scope, exceptions
                    --at        evaluation instant, RFC 3339 (default: now)
                    --json      machine-readable output
                    --out       write the report to a file instead of stdout
                  Reads only the paths given. No Pi-hole client, no credential,
                  and no code path to a network client. A proposal is not
                  permission to enforce it.
  decide          Decide one run whole: what would be added, what would be
                  removed, and what is held back (offline)
                    --evidence  signed evidence document (schema 2)
                    --signers   signer authority
                    --registry  source registry
                    --policy    proposal policy, including the automatic contract
                    --ledger    ownership ledger; WITHOUT it no removal is
                                decided, because an absent ledger is not an
                                empty one
                    --at        evaluation instant, RFC 3339 (default: now)
                    --json      machine-readable output
                  Drives the retention rules (C-21) and the removal caps and
                  abnormal-removal gate (C-20) that propose cannot reach.
                  Reads only the paths given: no configuration, no credential,
                  no Pi-hole client. A decision is not permission to apply it.
  rpz             Write the decided plan as an RPZ zone file for the owned
                  resolver (offline; files only)
                    --evidence  signed evidence document (schema 2)
                    --signers   signer authority
                    --registry  source registry
                    --policy    proposal policy, including the automatic contract
                    --ledger    ownership ledger (REQUIRED: the zone is the whole
                                standing set, and a run that cannot show what it
                                owns cannot write one)
                    --allowlist the household's allow-list snapshot; WITHOUT it the
                                run freezes and the existing zone is left alone
                    --out       where to write the zone; omitted implies --dry-run
                    --dry-run   compute everything and write nothing
                    --allow-empty  permit a zone with no entries
                    --origin    zone origin (default scamwall.rpz.)
                    --max-entries  refuse a zone larger than this (default 50000)
                    --key       MAC key file; without it the record beside the zone
                                is written UNSEALED and says so
                    --at        evaluation instant, RFC 3339 (default: now)
                    --json      machine-readable output
                    --source-outage REASON  declare the supply degraded; the zone is
                                            then left exactly as it is
                  Exit codes:
                    0  written, or the zone already said this, or a dry run
                    2  usage
                    3  nothing written, a person has to look (review)
                    4  nothing written, the inputs were not trustworthy (freeze)
                    5  nothing written, the writer's own safety rules refused
                    1  any other failure
                  Exact hosts only, NXDOMAIN, no wildcards. A host the household
                  allows is excluded and held for review, never written: on the
                  owned resolver an RPZ entry would override the household's own
                  allow entry. Nothing here reloads a resolver.
  shadow          Read the installed Pi-hole and report the exact change
                  ScamWall would request of it
                    --evidence  signed evidence document (schema 2)
                    --signers   signer authority
                    --registry  source registry
                    --policy    proposal policy, including the automatic contract
                    --at        evaluation instant, RFC 3339 (default: now)
                    --json      machine-readable output
                    --evidence-stale REASON  declare the evidence stale; every
                                             addition is then reported and NOT requested
                    --journal PATH  append to the decision journal, but only
                                    where a host's verdict substantively
                                    changed. A run that did not read the
                                    appliance records NOTHING, for any host,
                                    and is reported incomplete.
                  Authenticates, reads GET /api/domains/deny/exact, logs out.
                  It cannot construct a mutating request: see
                  pihole.PermittedOperations.
  sync --dry-run  Compute the plan and report it without submitting anything
  gen-signer-key  Generate an ed25519 signer keypair for a local Pinga53 install
                    --out      path to write the 32-byte seed (mode 0600)
                    --pub-out  path to write the base64 public key
                  Both paths are refused if they already exist. The seed is
                  the operator's secret; the public key fills the
                  "public_key" field of a signers.json record.
  fetch           Run each enabled source's fetcher, write per-source records
                    --registry    source registry (required)
                    --out-dir     directory to write per-source records files to
                                  (default /var/lib/scamwall/records)
                    --secrets-dir directory holding per-source credential files
                                  (default /etc/pinga53/scamwall/secrets)
                    --cache-dir   directory to persist per-source ETag / LMod
                                  (default /var/lib/scamwall/cache)
                    --timeout     per-fetch deadline (default 30s)
                    --only        restrict to a comma-separated subset of ids
                  Returns 0 if every enabled fetcher succeeded, 1 otherwise.
  merge-records   Concatenate per-source records files (--dir) newer than
                  2 × each source's cadence and print the merged JSON array.
                  Used by scamwall-run.sh to produce SENTINEL_RECORDS.
  metrics         Write a daily metrics document for the gate measurement
                    --shadow-zone      the ScamWall shadow zone (standing set)
                    --unbound-rpz      directory of free-stack RPZ zones
                    --journal          Unbound's shadow-hits journal
                    --allowlist        current Pi-hole allowlist snapshot
                    --protected        protected.txt
                    --baseline-dir     daily snapshots of the free stack
                    --records-dir      ScamWall per-source records files
                    --out-dir          where to write <date>.json + summary.json
                    --now              RFC 3339 instant (default: now)
                  Produces no client data in its output.
  acquire         Build and sign an evidence document (offline; files only)
                    --signer-key  path to the ed25519 seed (required)
                    --key-id      the key id as it appears in signers.json (required)
                    --out         path to write the signed envelope to (required)
                    --feed-id     feed id to bind into the manifest (default pinga53-local)
                    --records     path to a JSON array of EvidenceRecords
                                  (omit for a zero-record manifest)
                    --ttl         ExpiresAt = IssuedAt + ttl (default 24h)
                    --issued-at   IssuedAt, RFC 3339 (default: now)
                  Zero-record is the first-install shape; see
                  scripts/scamwall-run.sh.
  check           Verify the ScamWall configuration's own invariants (offline)
                    --registry   path to the source registry (required)
                    --protected  path to the protected-domains file, one host
                                 per line, '#' comments and blank lines allowed
                                 (required)
                    --quiet      print only the summary + failures
                  Currently checks: every registered source URL's host is
                  covered by protected_domains (ORDER 12A item 5). A live
                  run must never emit an RPZ entry for a feed host, so this
                  check fails until every registered source URL's host is
                  covered by a suffix in the protected-domains file.
                  Exits 0 pass, 1 fail, 2 usage, 3 could-not-check.

Phase 1 is read-only. No command modifies Pi-hole.
`)
}

// newFlagSet builds a flag set with the shared -config flag.
func newFlagSet(name string, w *os.File) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	cfgPath := fs.String("config", config.DefaultConfigPath, "path to the configuration file")
	return fs, cfgPath
}

func loadConfig(path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("configuration: %w", err)
	}
	return cfg, nil
}

func cmdVersion(w *os.File, args []string) int {
	fs, _ := newFlagSet("version", w)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	rev := commit
	if rev == "unknown" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" {
					rev = s.Value
				}
			}
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "scamwall\t%s\n", version)
	fmt.Fprintf(tw, "commit\t%s\n", rev)
	fmt.Fprintf(tw, "built\t%s\n", built)
	fmt.Fprintf(tw, "enforcement compiled in\t%t\n", policy.EnforcementCompiledIn)
	fmt.Fprintf(tw, "mode\tread-only, dry-run\n")
	_ = tw.Flush()
	return exitOK
}

// checkState is the outcome of one doctor check.
//
// Three states, not two. A check that was deliberately not performed is not a
// pass: reporting it as one would let `doctor --no-credential` be read as
// evidence that the credential is readable, which is the exact opposite of
// what that flag establishes.
type checkState int

const (
	checkOK checkState = iota
	checkFailed
	checkSkipped
)

// check is one doctor result line.
type check struct {
	name   string
	state  checkState
	detail string
}

func cmdDoctor(ctx context.Context, w *os.File, log *audit.Logger, args []string) int {
	fs, cfgPath := newFlagSet("doctor", w)
	skipNet := fs.Bool("offline", false, "skip connectivity checks")
	// --no-credential exists for one operator step: a connectivity and TLS
	// probe that must be provably credential-free. Without it there is no way
	// to run doctor at all without opening /run/secrets/pihole_app_password,
	// because the secret check is unconditional — so a procedure claiming "no
	// password is read" while running plain `doctor` was contradicted by
	// doctor's own output line.
	//
	// It skips the read entirely. It does not weaken any other check, and it
	// makes no claim about the credential in either direction.
	noSecret := fs.Bool("no-credential", false, "do not open the application password; make no claim about it")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	var checks []check
	add := func(name string, err error, okDetail string) bool {
		if err != nil {
			checks = append(checks, check{name, checkFailed, err.Error()})
			return false
		}
		checks = append(checks, check{name, checkOK, okDetail})
		return true
	}
	skip := func(name, detail string) {
		checks = append(checks, check{name, checkSkipped, detail})
	}

	cfg, err := loadConfig(*cfgPath)
	if !add("configuration", err, fmt.Sprintf("loaded (dry_run=%t)", cfg.Runtime.DryRun)) {
		return report(w, checks)
	}

	add("enforcement absent", func() error {
		if policy.EnforcementCompiledIn {
			return errors.New("enforcement is compiled into this build, which Phase 1 forbids")
		}
		return nil
	}(), "not compiled in")

	// The secret is checked for presence and shape only. Its content is never
	// read into a report.
	//
	// The byte count this line used to carry has been removed. LoadSecretFile
	// already refuses an empty credential, so the length diagnosed nothing
	// that the pass/fail result did not, and a length is still a fact about a
	// credential disclosed into an operator log.
	if *noSecret {
		skip("application password", "NOT READ (--no-credential): this run makes no claim about the credential")
	} else {
		secret, secErr := config.LoadSecretFile(cfg.Pihole.SecretPath)
		if add("application password", secErr, "readable") {
			defer secret.Destroy()
		}
	}

	// Offline validates the same CA file with the same parser, and does not
	// build the Client, transport, dialler or redirect policy that New()
	// carries. It DOES build the tls.Config — that construction IS the CA
	// validation — but a tls.Config holds no socket and no connection and is
	// handed to nothing here. FINDING-80: the first version of this comment
	// listed the TLS configuration among what was avoided, which was wrong.
	//
	// "No socket was opened" and "nothing that could open one was built" are
	// different claims, and --offline is the flag an operator procedure cites
	// for the second.
	var client *pihole.Client
	var cliErr error
	caDetail := "loaded and parsed: " + cfg.Pihole.CAPath
	if *skipNet {
		cliErr = pihole.ValidateCA(cfg)
		caDetail += " (no network client constructed)"
	} else {
		client, cliErr = pihole.New(cfg, log)
	}
	add("certificate authority", cliErr, caDetail)

	_, feedErr := loadFeed(cfg)
	add("feed", feedErr, "signature and manifest valid: "+cfg.Feed.Path)

	if !*skipNet && cliErr == nil {
		state, probeErr := client.ProbeAuth(ctx)
		detail := "reachable over TLS"
		if probeErr == nil && state.Message != "" {
			detail += "; " + state.Message
		}
		add("pi-hole connectivity", probeErr, detail)
	}

	return report(w, checks)
}

func report(w *os.File, checks []check) int {
	failed, skipped := 0, 0
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range checks {
		mark := "ok"
		switch c.state {
		case checkFailed:
			mark = "FAIL"
			failed++
		case checkSkipped:
			mark = "SKIP"
			skipped++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", mark, c.name, c.detail)
	}
	_ = tw.Flush()
	// Skipped checks are counted separately and are NOT folded into the passed
	// total. A summary that said "5 checks, 0 failed" for a run in which one
	// check never happened would be the false-pass shape this repository keeps
	// finding.
	fmt.Fprintf(w, "\n%d checks, %d failed, %d skipped\n", len(checks), failed, skipped)
	if failed > 0 {
		return exitFailure
	}
	return exitOK
}

func cmdStatus(ctx context.Context, w *os.File, log *audit.Logger, args []string) int {
	fs, cfgPath := newFlagSet("status", w)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
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

	var info *pihole.VersionInfo
	err = client.WithSession(ctx, secret, func(ctx context.Context) error {
		var innerErr error
		info, innerErr = client.Version(ctx)
		return innerErr
	})
	if err != nil {
		return failWithTeardown(w, err, client.SessionTeardown())
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "component\tlocal\tbranch\tremote\n")
	fmt.Fprintf(tw, "core\t%s\t%s\t%s\n", info.Core.LocalVersion, info.Core.LocalBranch, info.Core.RemoteVersion)
	fmt.Fprintf(tw, "web\t%s\t%s\t%s\n", info.Web.LocalVersion, info.Web.LocalBranch, info.Web.RemoteVersion)
	fmt.Fprintf(tw, "ftl\t%s\t%s\t%s\n", info.FTL.LocalVersion, info.FTL.LocalBranch, info.FTL.RemoteVersion)
	_ = tw.Flush()
	return reportTeardown(w, client.SessionTeardown())
}

// reportTeardown states what actually became of the session and returns the
// exit status that outcome deserves.
//
// This replaced an unconditional "session closed" line. WithSession attempts
// the logout in a deferred call and deliberately does not let a logout failure
// mask the caller's error, so a run whose logout failed still returned nil —
// and the command printed a success line for a cleanup it had not observed
// succeed. The three outcomes are kept distinct because they are three
// different claims, and none of them is "the appliance has confirmed the
// session is gone", which this client cannot establish at all: the endpoint
// that would list sessions is outside the permitted set.
func reportTeardown(w *os.File, t pihole.Teardown) int {
	switch t {
	case pihole.TeardownAccepted:
		fmt.Fprintln(w, "\nsession logout ACCEPTED by Pi-hole")
		fmt.Fprintln(w, "  This records that the DELETE was accepted. It is not independent")
		fmt.Fprintln(w, "  confirmation that the appliance's session table no longer holds it.")
		return exitOK
	case pihole.TeardownAlreadyAbsent:
		fmt.Fprintln(w, "\nsession ALREADY ABSENT on Pi-hole (nothing was left to destroy)")
		return exitOK
	case pihole.TeardownFailed:
		fmt.Fprintln(w, "\nWARNING: session logout FAILED.")
		fmt.Fprintln(w, "  The session id has been discarded locally, so nothing can retry it.")
		fmt.Fprintln(w, "  A session may remain valid on the appliance until it expires.")
		return exitFailure
	default:
		fmt.Fprintln(w, "\nWARNING: no session logout was attempted.")
		return exitFailure
	}
}

func loadFeed(cfg config.Config) (*feed.Validated, error) {
	key, err := cfg.TrustPublicKeyBytes()
	if err != nil {
		return nil, err
	}
	return feed.LoadFile(cfg.Feed.Path, feed.Options{
		MaxFileBytes: cfg.Feed.MaxFileBytes,
		MaxRecords:   cfg.Feed.MaxRecords,
		TrustKeyID:   cfg.Feed.TrustKeyID,
		TrustKey:     key,
	})
}

func cmdValidateFeed(w *os.File, _ *audit.Logger, args []string) int {
	fs, cfgPath := newFlagSet("validate-feed", w)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(w, err)
	}
	v, err := loadFeed(cfg)
	if err != nil {
		return fail(w, err)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "feed id\t%s\n", v.FeedID)
	fmt.Fprintf(tw, "manifest version\t%s\n", v.ManifestVersion)
	fmt.Fprintf(tw, "signing key id\t%s\n", v.KeyID)
	fmt.Fprintf(tw, "issued at\t%s\n", v.IssuedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(tw, "expires at\t%s\n", v.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(tw, "valid indicators\t%d\n", len(v.Indicators))
	fmt.Fprintf(tw, "expired indicators\t%d\n", v.ExpiredCount)
	_ = tw.Flush()
	fmt.Fprintln(w, "\nsignature verified")
	return exitOK
}

func cmdPlan(w *os.File, _ *audit.Logger, args []string) int {
	fs, cfgPath := newFlagSet("plan", w)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(w, err)
	}
	v, err := loadFeed(cfg)
	if err != nil {
		return fail(w, err)
	}
	printPlan(w, policy.Compute(v))
	return exitOK
}

func printPlan(w *os.File, p *policy.Plan) {
	fmt.Fprintf(w, "proposed plan (%s)\n", p.FormatVersion)
	fmt.Fprintf(w, "feed:   %s (manifest %s)\n", p.FeedID, p.ManifestVersion)
	fmt.Fprintf(w, "digest: %s\n\n", p.Digest)

	if p.IsEmpty() {
		fmt.Fprintln(w, "no domains proposed for blocking")
	} else {
		for _, e := range p.Entries {
			fmt.Fprintf(w, "  block  %s", e.Domain)
			if e.Category != "" {
				fmt.Fprintf(w, "  [%s]", e.Category)
			}
			fmt.Fprintln(w)
		}
	}

	if p.ReviewCount() > 0 {
		fmt.Fprintln(w, "\nheld for review — eligible on the feed's terms, not proposed:")
		for _, r := range p.Review {
			fmt.Fprintf(w, "  review %s  [%s]", r.Domain, r.Reason)
			if len(r.Signals) > 0 {
				signals := make([]string, 0, len(r.Signals))
				for _, s := range r.Signals {
					signals = append(signals, string(s))
				}
				fmt.Fprintf(w, "  signals: %s", strings.Join(signals, ","))
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "  A signal is not evidence. Nothing above is claimed to be malicious.")
	}

	fmt.Fprintf(w, "\n%d proposed, %d held for review, %d excluded (%d not block, %d below confidence, %d expired)\n",
		p.Count(), p.ReviewCount(), p.Exclusions.Total(),
		p.Exclusions.NotBlockAction, p.Exclusions.BelowConfidence, p.Exclusions.ExpiredInFeed)
}

func cmdSync(ctx context.Context, w *os.File, log *audit.Logger, args []string) int {
	fs, cfgPath := newFlagSet("sync", w)
	// Dry-run is the immutable default. The flag exists so that an explicit
	// --dry-run reads naturally and so that --dry-run=false fails loudly
	// rather than silently doing nothing an operator might misread as success.
	dryRun := fs.Bool("dry-run", true, "compute and report the plan without submitting it (always required in Phase 1)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if !*dryRun {
		fmt.Fprintln(w, "refusing to run: --dry-run=false is not available.")
		fmt.Fprintln(w, "ScamWall Phase 1 is read-only; enforcement is not compiled into this build.")
		return exitUsage
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(w, err)
	}
	v, err := loadFeed(cfg)
	if err != nil {
		return fail(w, err)
	}
	plan := policy.Compute(v)

	secret, err := config.LoadSecretFile(cfg.Pihole.SecretPath)
	if err != nil {
		return fail(w, err)
	}
	defer secret.Destroy()

	client, err := pihole.New(cfg, log)
	if err != nil {
		return fail(w, err)
	}

	var info *pihole.VersionInfo
	err = client.WithSession(ctx, secret, func(ctx context.Context) error {
		var innerErr error
		info, innerErr = client.Version(ctx)
		return innerErr
	})
	if err != nil {
		return failWithTeardown(w, err, client.SessionTeardown())
	}

	fmt.Fprintf(w, "connected to Pi-hole (core %s, web %s, ftl %s)\n\n",
		info.Core.LocalVersion, info.Web.LocalVersion, info.FTL.LocalVersion)
	printPlan(w, plan)

	fmt.Fprintln(w, "\nDRY RUN: nothing was submitted to Pi-hole.")
	fmt.Fprintln(w, "No blocking change was made. Enforcement is not compiled into this build.")
	// Same reason as status: the session this command created is its own to
	// clean up, and a failed cleanup is part of the verdict rather than a line
	// in an audit stream nobody reads.
	return reportTeardown(w, client.SessionTeardown())
}

func fail(w *os.File, err error) int {
	fmt.Fprintf(w, "error: %v\n", err)
	return exitFailure
}

// failWithTeardown reports a failed operation AND what became of the session
// it had already opened.
//
// Before this, a command whose read failed printed the read error and
// returned, never reaching reportTeardown. The exit status was 1 either way,
// which is why it went unnoticed: the verdict was correct and the reason was
// half-told. A run whose read failed AND whose logout failed said nothing
// about the session — the one case where the operator most needs to know that
// one may still be live on the appliance. The primary failure is printed
// first, and neither report is allowed to suppress the other; the status is
// always a failure, because the operation failed regardless of how cleanly it
// was cleaned up.
func failWithTeardown(w *os.File, err error, t pihole.Teardown) int {
	fmt.Fprintf(w, "error: %v\n", err)
	_ = reportTeardown(w, t)
	return exitFailure
}

// teardownExit is reportTeardown's verdict WITHOUT its prose.
//
// A machine-readable command binds the teardown into its own document and
// must not also print a paragraph after it. The exit status is the same
// either way: a failed or unattempted logout is a failed run, whichever
// format was asked for.
func teardownExit(t pihole.Teardown) int {
	switch t {
	case pihole.TeardownAccepted, pihole.TeardownAlreadyAbsent:
		return exitOK
	default:
		return exitFailure
	}
}
