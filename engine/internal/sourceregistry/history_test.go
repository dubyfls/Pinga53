// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoIdentifierReuseAcrossHistory walks every committed version of the
// registry and checks each consecutive pair for identifier reuse.
//
// # WHY A HISTORY WALK IS NECESSARY
//
// Validate enforces id uniqueness within one file and refuses an id listed in
// retired_source_ids. Neither sees history, and the bypass is ordinary:
//
//	commit N     src-0007 = "Provider A"
//	commit N+1   the record is deleted, src-0007 is NOT retired
//	commit N+2   src-0007 = "Provider B"
//
// Every one of those files validates on its own. TestDeletingASourceWithout
// RetiringItsIDBypassesTheCurrentFileRule demonstrates that directly.
// ValidateAgainstBaseline closes one step of it. This closes the rest, by
// applying that comparison to every step the file has ever taken.
//
// STATED LIMIT. This checks the history that git can show it. It says nothing
// about a history that was rewritten, and nothing about a version that never
// reached a commit. It is the strongest check available from the repository,
// and it is not a proof about the world.
func TestNoIdentifierReuseAcrossHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available; the history check needs the repository")
	}
	const path = "docs/source-registry.json"

	// --reverse so pairs are (older, newer). --follow is deliberately NOT used:
	// a rename would change what the id space means, and quietly following it
	// would compare two different documents.
	out, err := exec.Command("git", "-C", "../..", "log", "--format=%H", "--reverse", "--", path).Output()
	if err != nil {
		t.Skipf("git log failed; not a usable repository here: %v", err)
	}
	commits := strings.Fields(string(out))
	if len(commits) == 0 {
		t.Skip("the registry has no committed history yet")
	}

	load := func(ref string) *Registry {
		t.Helper()
		blob, err := exec.Command("git", "-C", "../..", "show", ref+":"+path).Output()
		if err != nil {
			return nil // the file did not exist at that revision
		}
		reg, _, err := Parse(blob)
		if err != nil {
			t.Fatalf("the registry at %s does not parse: %v", ref[:8], err)
		}
		return reg
	}

	checked := 0
	for i := 1; i < len(commits); i++ {
		before, after := load(commits[i-1]), load(commits[i])
		if before == nil || after == nil {
			continue
		}
		if problems := ValidateAgainstBaseline(before, after); len(problems) != 0 {
			t.Errorf("identifier reuse between %s and %s:\n%s",
				commits[i-1][:8], commits[i][:8], render(problems))
		}
		checked++
	}

	// The working tree counts as the newest version: a reuse introduced but not
	// yet committed must fail here rather than at review time.
	if head := load(commits[len(commits)-1]); head != nil {
		working, _, err := Load(shippedPath())
		if err != nil {
			t.Fatalf("the working-tree registry did not parse: %v", err)
		}
		if problems := ValidateAgainstBaseline(head, working); len(problems) != 0 {
			t.Errorf("identifier reuse between the last commit and the working tree:\n%s", render(problems))
		}
		checked++
	}

	t.Logf("checked %d consecutive version pair(s) across %d committed revision(s)", checked, len(commits))
}

// TestEveryControlThisPackageCitesExists is the regression for FINDING-88.
//
// ValidateAgainstBaseline's doc comment used to cite a shell script under
// scripts/ as the thing that closes the history gap. That script has never
// existed in this repository. A comment naming a control that is not there is
// worse than no comment: a reader checking whether the gap is closed finds a
// name and stops looking. The name is not written out here, because this test
// reads this package's own source and would then find its own prose.
//
// This walks every path this package's source mentions and asserts it is
// present, so the next such citation fails here rather than at review time.
func TestEveryControlThisPackageCitesExists(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// Matches a repository-relative path with a directory component and an
	// extension, which is the shape a citation takes.
	cite := regexp.MustCompile(`\b((?:scripts|docs|internal|cmd|deploy|container)/[A-Za-z0-9._/-]+\.(?:sh|go|json|md|yaml|yml))`)

	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range cite.FindAllStringSubmatch(string(src), -1) {
			path := filepath.Join("..", "..", filepath.FromSlash(m[1]))
			if _, err := os.Stat(path); err != nil {
				t.Errorf("%s cites %s, which does not exist", e.Name(), m[1])
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no citation was found to check; this test would pass vacuously")
	}
	t.Logf("checked %d cited path(s)", checked)
}
