// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"fmt"
	"sort"
)

// ValidateAgainstBaseline compares an earlier version of the registry with the
// current one and reports identifier reuse that the current file cannot show on
// its own.
//
// # WHY THE CURRENT-FILE VALIDATOR IS NOT ENOUGH
//
// docs/SOURCE_REGISTRY.md §2 says a source_id is "never reused, never
// renumbered". Validate enforces uniqueness WITHIN one file, and refuses an id
// listed in retired_source_ids. Neither of those sees history, and the bypass is
// ordinary rather than exotic:
//
//	commit N     src-0007 = "Provider A"
//	commit N+1   the record is deleted, and src-0007 is NOT retired
//	commit N+2   src-0007 = "Provider B"
//
// Every one of those files validates. Nothing in the third one knows that
// src-0007 ever meant something else, so anything that referenced src-0007 —
// an observation, a decision, an evaluation result — now points at a different
// provider with no diagnostic anywhere.
//
// This function closes that by comparing two versions: any id present in the
// baseline and absent from the current registry must appear in the current
// registry's retired_source_ids. Retirement becomes the required way to remove
// a record, and the rule becomes enforceable rather than merely stated.
//
// STATED LIMIT — and it matters. One call compares ONE pair of versions. That
// establishes non-reuse across that step and nothing more: it cannot see an id
// that was dropped and reused entirely within the range it did not examine. To
// make a claim about the whole history, every consecutive pair of versions of
// the file has to be checked, which is what TestNoIdentifierReuseAcrossHistory
// in history_test.go does by walking the file's committed revisions and the
// working tree. The current-file validator alone proves nothing at all about
// history, and this function alone proves only one step of it.
//
// That citation used to name a shell script under scripts/ which has never
// existed in this repository: FINDING-88. A comment pointing at a control
// that is not there is worse than no comment, because a reader checking
// whether the gap is closed finds a name and stops looking.
func ValidateAgainstBaseline(baseline, current *Registry) []Problem {
	if baseline == nil || current == nil {
		return nil
	}

	retiredNow := map[string]bool{}
	for _, id := range current.RetiredSourceIDs {
		retiredNow[id] = true
	}
	presentNow := map[string]bool{}
	for _, s := range current.Sources {
		presentNow[s.SourceID] = true
	}
	baselineName := map[string]string{}
	for _, s := range baseline.Sources {
		baselineName[s.SourceID] = s.OfficialName
	}
	retiredBefore := map[string]bool{}
	for _, id := range baseline.RetiredSourceIDs {
		retiredBefore[id] = true
	}

	var problems []Problem

	dropped := make([]string, 0)
	for id := range baselineName {
		if !presentNow[id] {
			dropped = append(dropped, id)
		}
	}
	sort.Strings(dropped)
	for _, id := range dropped {
		if !retiredNow[id] {
			problems = append(problems, Problem{
				"retired_source_ids",
				fmt.Sprintf("%q was a source in the baseline (%s) and is absent now, but it has not been retired. A removed id must be retired, or a later record could take it and silently mean something else", id, baselineName[id]),
			})
		}
	}

	// Retirement is not reversible. An id that left the retired list is an id
	// that has become available again, which is the same defect arriving by the
	// opposite route.
	unretired := make([]string, 0)
	for id := range retiredBefore {
		if !retiredNow[id] {
			unretired = append(unretired, id)
		}
	}
	sort.Strings(unretired)
	for _, id := range unretired {
		problems = append(problems, Problem{
			"retired_source_ids",
			fmt.Sprintf("%q was retired in the baseline and is no longer listed; retirement is permanent, and dropping it makes the id available again", id),
		})
	}

	// An identifier that reappears carrying a different provider is the defect
	// itself rather than a step towards it, and it is worth naming separately
	// from the missing retirement that allowed it.
	for _, s := range current.Sources {
		if was, existed := baselineName[s.SourceID]; existed && was != s.OfficialName {
			problems = append(problems, Problem{
				fmt.Sprintf("sources.%s.official_name", s.SourceID),
				fmt.Sprintf("is %q; in the baseline this id was %q. An id is stable — if this is a different source it needs a new id, and if the provider merely renamed itself, record that in disposition_reason", s.OfficialName, was),
			})
		}
	}

	sort.Slice(problems, func(a, b int) bool {
		if problems[a].Path != problems[b].Path {
			return problems[a].Path < problems[b].Path
		}
		return problems[a].Message < problems[b].Message
	})
	return problems
}

// ValidateVersionChain applies ValidateAgainstBaseline to every consecutive
// pair in an ordered sequence of registry versions, oldest first.
//
// It exists so the walk itself is testable without a repository. The history
// test supplies versions read out of git; a unit test supplies a synthetic
// sequence. Both exercise the same loop, so "the comparison is correct" and
// "the walk applies it to every step" are two facts established separately
// rather than one assumed from the other.
//
// Each problem is prefixed with the step it was found at, because a reuse three
// versions back and a reuse in the working tree call for different actions.
func ValidateVersionChain(versions []*Registry, labels []string) []Problem {
	var problems []Problem
	for i := 1; i < len(versions); i++ {
		if versions[i-1] == nil || versions[i] == nil {
			continue
		}
		step := fmt.Sprintf("step %d", i)
		if len(labels) == len(versions) {
			step = labels[i-1] + " -> " + labels[i]
		}
		for _, p := range ValidateAgainstBaseline(versions[i-1], versions[i]) {
			problems = append(problems, Problem{step + ": " + p.Path, p.Message})
		}
	}
	return problems
}
