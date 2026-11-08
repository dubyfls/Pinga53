// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// # ORDER 11 QUEUE ITEM 2 — THE INVENTORY, MEASURED FROM cmd/
//
// ORDER 9 left several controls in the state `REQUIREMENTS_MATRIX.md` §5.9.6
// calls RULE VERIFIED (synthetic), NO CALLER: the rule is implemented and
// tested in `internal/`, and nothing the shipped command can be asked to do
// ever executes it. A control in that state protects nobody, and a records
// table that lists it beside a control with a caller is the false-pass shape
// this repository keeps finding.
//
// This file is the inventory as a PROBE rather than as a list. Every entry
// drives the real command — `run()`, the same function `main` calls — and
// fails while the control has no cmd/ surface. Nothing here reads `internal/`
// directly: a test that imports the package it is measuring the reachability
// of would pass for a command that reaches nothing.
//
// The inventory this file was built from, and where each line came from:
//
//	control                  ORDER 9 status              where the rule lives
//	C-20 removal half        DONE, no caller             internal/proposal.AssessRemovals
//	C-21                     DONE (rule), NO CALLER      internal/proposal.AssessRetention
//	C-22, C-23               DONE, no caller             internal/journal
//	C-24 store-seal half     DONE, no caller             internal/journal.Seal
//	C-10…C-13 (SW-P2-09)     DONE, not reachable         internal/acquire
//	C-14 audit half          DONE                        internal/audit
//	C-25                     PARTIAL                     internal/shadow (gravity unread)

// reachablePackages is what `go list -deps ./cmd/...` reports, as a set.
//
// Computed with the toolchain rather than by reading import lines: a
// transitive import reaches a rule just as well as a direct one, and only the
// toolchain knows the whole graph. internal/acquire's own
// TestTheFetcherIsNotReachableFromTheCommand takes the same position for the
// opposite conclusion.
func reachablePackages(t *testing.T) map[string]bool {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "./...").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable in this environment: %v", err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		set[strings.TrimSpace(line)] = true
	}
	return set
}

const pkgPrefix = "github.com/dubyfls/Pinga53/engine/"

// TestTheCommandCanBeAskedToDecideRemovals is C-20's removal half and C-21.
//
// Both rules take an ownership ledger, and before ORDER 11 no command could be
// given one: `shadow` passes shadow.NoOwnership explicitly and says so. So
// retention never ran, and the abnormal-removal gate that is the whole of
// §1 harm 1 had nothing to gate.
func TestTheCommandCanBeAskedToDecideRemovals(t *testing.T) {
	code, stdout, stderr := capture(t, "decide", "-h")
	if code == exitUsage && strings.Contains(stderr, "unknown command") {
		t.Fatalf("the command has no entry point that decides removals, so C-20's removal half "+
			"and C-21 have no caller:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

// TestTheDecideHelpNamesEveryRuleItDrives keeps the entry point honest about
// which controls run through it.
//
// A command that silently acquired or lost a rule would otherwise leave this
// file's inventory as a claim about a previous build.
func TestTheDecideHelpNamesEveryRuleItDrives(t *testing.T) {
	_, stdout, _ := capture(t, "decide", "-h")
	both := stdout
	_, usage, _ := capture(t, "help")
	both += usage
	for _, want := range []string{"retention", "removal", "journal"} {
		if !strings.Contains(strings.ToLower(both), want) {
			t.Errorf("neither `decide -h` nor the usage text mentions %q, so an operator "+
				"cannot tell which rules the command drives", want)
		}
	}
}

// TestTheFetcherStaysUnreachable is the inventory's one deliberate NO.
//
// C-10…C-13 and SW-P2-09 live in internal/acquire, and internal/acquire's own
// TestTheFetcherIsNotReachableFromTheCommand requires that cmd/ never reach
// it. The two tests are a matched pair: this one exists so that a later order
// reading the inventory sees that the gap is a decision with a gate behind it
// and not an oversight, and so that anything which makes the fetcher reachable
// fails twice rather than once.
func TestTheFetcherStaysUnreachable(t *testing.T) {
	if reachablePackages(t)[pkgPrefix+"internal/acquire"] {
		t.Fatal("cmd/ now reaches internal/acquire. ORDER 8's reason for not shipping a feed " +
			"fetcher unattended has to be answered before this is allowed, and ORDER 11 §0 " +
			"forbids weakening the gate that says so")
	}
}

// TestTheRedactorIsReachableFromTheCommand is SW-P2-11's reachable half.
//
// The row cites two test files: internal/acquire's, which no command reaches,
// and internal/audit's, which every command does — `run` builds an
// audit.Logger over stderr before it dispatches. The rule that a credential in
// a source URL never reaches a log line therefore DOES constrain the shipped
// program, and the matrix row saying otherwise is about the wrong half.
func TestTheRedactorIsReachableFromTheCommand(t *testing.T) {
	if !reachablePackages(t)[pkgPrefix+"internal/audit"] {
		t.Fatal("cmd/ does not reach internal/audit, so SW-P2-11 has no reachable half at all")
	}
}

// TestTheJournalIsReachableFromTheCommand is C-22, C-23 and C-24's store-seal
// half at the package level.
//
// ORDER 9 shipped internal/journal complete and imported by nothing outside
// its own tests. A journal no run ever writes records nothing, so C-23's
// refusal — that a run which did not read the appliance may not journal what
// it would have done to it — had never once been asked for by the program it
// is supposed to constrain. `shadow --journal` asks for it now, on the
// failure path as well as the success path.
func TestTheJournalIsReachableFromTheCommand(t *testing.T) {
	if !reachablePackages(t)[pkgPrefix+"internal/journal"] {
		t.Fatal("cmd/ does not reach internal/journal: C-22, C-23 and C-24's store-seal half " +
			"are implemented and never executed by the shipped command")
	}
}
