// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dubyfls/Pinga53/engine/internal/policy"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT `check` IS
//
// It runs the invariants ScamWall's own configuration must satisfy before
// any other subcommand's output can be trusted. `doctor` looks at the
// world (network, credentials, feed signatures). `check` looks at what
// we've asked ScamWall to do, and says whether it CAN be done without
// contradicting an earlier promise.
//
// ORDER 12A item 5 is the first invariant this subcommand carries:
// every registered source URL's host must be covered by protected_domains,
// so a live run cannot emit an RPZ entry that would block the very feed
// the next run needs to prove the block was wrong.
//
// The check reads two files and writes a report. It never opens a
// network connection, never touches a credential, and never writes to
// disk. That is the whole point: an invariant check that can fail for a
// non-invariant reason is not a check.
//
// # EXIT CODES
//
//   0 — every check passed.
//   1 — at least one check failed; details are printed in the report.
//   2 — bad usage (missing required flag, malformed argument).
//   3 — configuration or filesystem error prevented the check from
//       running. Distinct from 1 so a wrapper does not misread "we could
//       not check" as "we checked and it passed".

func cmdCheck(w *os.File, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(w)
	registryPath := fs.String("registry", "",
		"path to the source registry (required)")
	protectedPath := fs.String("protected", "",
		"path to the protected-domains file, one host per line, "+
			"'#' comments and blank lines allowed (required)")
	quiet := fs.Bool("quiet", false,
		"print only the summary line and any failures")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *registryPath == "" {
		fmt.Fprintln(w, "check: --registry is required")
		return exitUsage
	}
	if *protectedPath == "" {
		fmt.Fprintln(w, "check: --protected is required")
		return exitUsage
	}

	reg, problems, err := sourceregistry.Load(*registryPath)
	if err != nil {
		fmt.Fprintf(w, "check: loading source registry: %v\n", err)
		return 3
	}
	if len(problems) > 0 && !*quiet {
		fmt.Fprintf(w, "note: source registry has %d validation problem(s); running check anyway\n",
			len(problems))
	}

	protected, err := readProtectedList(*protectedPath)
	if err != nil {
		fmt.Fprintf(w, "check: reading protected-domains file: %v\n", err)
		return 3
	}

	uncovered := policy.UncoveredFeedHosts(reg, protected)
	total := len(policy.FeedHosts(reg))

	if len(uncovered) == 0 {
		if !*quiet {
			fmt.Fprintf(w, "ok  every registered feed host (%d) is covered by protected_domains (%d suffixes)\n",
				total, len(protected))
		} else {
			fmt.Fprintf(w, "ok  %d/%d\n", total, total)
		}
		return exitOK
	}

	fmt.Fprintln(w, "check FAILED: feed hosts not covered by protected_domains")
	fmt.Fprintln(w, "  (a live run could emit an RPZ entry for one of these and starve the next run)")
	for _, h := range uncovered {
		fmt.Fprintf(w, "  FAIL  %s   [source %s]   %s\n", h.Host, h.SourceID, h.URL)
	}
	fmt.Fprintf(w, "\n%d of %d feed host(s) uncovered — add them to %s\n",
		len(uncovered), total, *protectedPath)
	return exitFailure
}

// readProtectedList returns the non-blank, non-comment lines of the file
// as a slice of protected suffixes. Whitespace around each entry is
// trimmed so an operator can indent for readability without silently
// changing the match semantics.
func readProtectedList(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
