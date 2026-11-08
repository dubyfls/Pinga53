// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"fmt"
	"sort"
	"strings"
)

// Upstream-completeness vocabulary.
//
// docs/SOURCE_REGISTRY.md offers `aggregation_dependencies` as the thing that
// "stops three feeds being counted as three independent sources". It does that
// only for dependencies somebody recorded. The field below records how much is
// known about the upstreams at all, which is the difference between "this
// source aggregates nothing" and "nobody has established what it aggregates".
//
// An unknown upstream is not demonstrated independence. Treating it as such is
// how three feeds sharing one upstream get counted as three.
const (
	// UpstreamDocumentedComplete — the provider documents its upstreams and
	// the record reflects all of them.
	UpstreamDocumentedComplete = "documented_complete"
	// UpstreamDocumentedPartial — some upstreams are documented and the
	// provider does not claim the list is exhaustive.
	UpstreamDocumentedPartial = "documented_partial"
	// UpstreamUnknown — the provider does not say. The default, and the honest
	// answer for most aggregators.
	UpstreamUnknown = "unknown"
)

// ValidUpstreamCompleteness is the closed vocabulary.
var ValidUpstreamCompleteness = []string{
	UpstreamDocumentedComplete, UpstreamDocumentedPartial, UpstreamUnknown,
}

// IndependenceClaimable reports whether this source may be COUNTED as
// independent of the others, and why not when it may not.
//
// This is deliberately not a field an author can set. Independence is a
// property of what is known about lineage, and a record that says "independent"
// while its upstreams are undocumented is asserting the absence of evidence as
// evidence of absence.
//
// It is the gate for first-wave selection: a wave that wants N independent
// sources must satisfy this for each of them, or say plainly that it is
// choosing sources whose independence is unestablished.
func (s *Source) IndependenceClaimable() (bool, string) {
	switch s.UpstreamSourcesCompleteness {
	case UpstreamDocumentedComplete:
		return true, ""
	case UpstreamDocumentedPartial:
		return false, fmt.Sprintf(
			"%s documents its upstreams only partially, so an upstream shared with another registry entry may exist and be unrecorded",
			s.SourceID)
	case UpstreamUnknown:
		return false, fmt.Sprintf(
			"%s does not document its upstreams, so nothing is known about what it aggregates; an unknown upstream is not demonstrated independence",
			s.SourceID)
	default:
		return false, fmt.Sprintf("%s carries an unrecognised upstream_sources_completeness %q", s.SourceID, s.UpstreamSourcesCompleteness)
	}
}

// validateLineage checks the dependency graph as a graph.
//
// aggregation_dependencies is a LINEAGE edge: "this source's records are drawn,
// in whole or in part, from that source". It is not a general relatedness link,
// and it is not the place to record that two sources happen to cover the same
// sector or that one is a good cross-check for another. Lineage has to stay
// lineage, because the deduplication and independence reasoning that will
// eventually read this graph is only correct if every edge means the same
// thing.
//
// A cycle in lineage is therefore a contradiction rather than a curiosity: A
// cannot be derived from B while B is derived from A. Where two aggregators
// genuinely exchange data in both directions, that is a shared-upstream
// relationship to be recorded on both records, not a loop.
func (r *Registry) validateLineage(problems *[]Problem) {
	index := map[string]int{}
	for i, s := range r.Sources {
		if _, dup := index[s.SourceID]; !dup {
			index[s.SourceID] = i
		}
	}

	for i := range r.Sources {
		s := &r.Sources[i]
		at := func(f string) string { return fmt.Sprintf("sources[%d].%s", i, f) }

		if !contains(ValidUpstreamCompleteness, s.UpstreamSourcesCompleteness) {
			*problems = append(*problems, Problem{
				at("upstream_sources_completeness"),
				fmt.Sprintf("is %q; permitted values are %s", s.UpstreamSourcesCompleteness, strings.Join(ValidUpstreamCompleteness, ", ")),
			})
		}

		// A record claiming complete upstream documentation while listing no
		// upstreams is making a strong claim — "this source aggregates nothing"
		// — and it is a legitimate one for a primary observer. It is only
		// refused when it contradicts the lineage edges the same record
		// carries.
		if s.UpstreamSourcesCompleteness == UpstreamDocumentedComplete &&
			len(s.UpstreamSources) == 0 && len(s.AggregationDependencies) > 0 {
			*problems = append(*problems, Problem{
				at("upstream_sources"),
				"is empty and upstream_sources_completeness is `documented_complete`, but aggregation_dependencies names registry entries this source draws from — the two statements contradict each other",
			})
		}

		seen := map[string]bool{}
		for j, dep := range s.AggregationDependencies {
			p := at(fmt.Sprintf("aggregation_dependencies[%d]", j))
			switch {
			case strings.TrimSpace(dep) == "":
				*problems = append(*problems, Problem{p, "is empty"})
			case dep == s.SourceID:
				*problems = append(*problems, Problem{
					p,
					"names its own record; a source cannot be an upstream of itself, and a self-edge would make every downstream independence calculation wrong",
				})
			case seen[dep]:
				*problems = append(*problems, Problem{p, fmt.Sprintf("names %q twice", dep)})
			default:
				if _, ok := index[dep]; !ok {
					*problems = append(*problems, Problem{
						p,
						fmt.Sprintf("names %q, which is not a source_id in this registry; a lineage edge to a record that does not exist establishes nothing", dep),
					})
				}
			}
			seen[dep] = true
		}
	}

	for _, cycle := range r.dependencyCycles() {
		*problems = append(*problems, Problem{
			"sources." + cycle[0] + ".aggregation_dependencies",
			fmt.Sprintf("takes part in a lineage cycle: %s. Lineage is directional — a source cannot be derived from something that is derived from it — so this is a contradiction, not a loop to be broken arbitrarily", strings.Join(cycle, " -> ")),
		})
	}
}

// dependencyCycles finds every cycle in the lineage graph, each reported once,
// canonicalised so that the same cycle is not reported from several starting
// points.
func (r *Registry) dependencyCycles() [][]string {
	adj := map[string][]string{}
	for _, s := range r.Sources {
		adj[s.SourceID] = append(adj[s.SourceID], s.AggregationDependencies...)
	}

	const (
		white = 0 // unvisited
		grey  = 1 // on the current path
		black = 2 // finished
	)
	colour := map[string]int{}
	var path []string
	found := map[string][]string{}

	var visit func(string)
	visit = func(n string) {
		colour[n] = grey
		path = append(path, n)
		for _, m := range adj[n] {
			if _, known := adj[m]; !known {
				continue // dangling edge; reported separately
			}
			switch colour[m] {
			case white:
				visit(m)
			case grey:
				// Cycle: from m's position on the current path, back to m.
				start := 0
				for k, p := range path {
					if p == m {
						start = k
						break
					}
				}
				cycle := append([]string{}, path[start:]...)
				cycle = append(cycle, m)
				found[canonicalCycle(cycle)] = cycle
			}
		}
		path = path[:len(path)-1]
		colour[n] = black
	}

	ids := make([]string, 0, len(adj))
	for id := range adj {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic reporting
	for _, id := range ids {
		if colour[id] == white {
			visit(id)
		}
	}

	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, found[k])
	}
	return out
}

// canonicalCycle gives a cycle a single name regardless of where the walk
// entered it, so A->B->A and B->A->B are one finding rather than two.
func canonicalCycle(cycle []string) string {
	nodes := append([]string{}, cycle[:len(cycle)-1]...)
	sort.Strings(nodes)
	return strings.Join(nodes, "|")
}

// # UPSTREAM LABELS
//
// `upstream_labels` is the machine-readable half of lineage. `upstream_sources`
// beside it stays what it is in this tree — human-readable provider names —
// and no computation reads it. That is the gap C-01 and C-02 fall into: two
// sources drawing on an origin which is NOT a registry entry are counted as two
// independent voices, because the only lineage the tree can see is an edge
// between two records it holds. `aggregation_dependencies` cannot close it — an
// edge there must name a record in this file, and the shared origin is by
// definition not one.
//
// So a label resolves three ways, and to nothing else:
//
//  1. a source_id in this registry — lineage that can be walked;
//  2. the record's OWN source_id — a primary observer saying "everything here
//     is mine" out loud, as against saying it by leaving the list empty;
//  3. an entry in the registry's `external_origins` — a leaf, an origin
//     nobody here holds a record for.
//
// Anything else is a configuration error. A label nobody can resolve is not a
// weaker claim about lineage; it is an unreadable one, and treating it as
// absent is how "we do not know" becomes "there is nothing".

// MaxLabelBytes bounds an upstream label. The value is generous for a name
// and small enough that a document cannot choose the size of a diagnostic.
const MaxLabelBytes = 64

// labelCharset is the closed character set for an upstream label and an
// external origin.
//
// ORDER 8 §4's own spelling of this rule, as the crosswalk records it, is
// [a-z0-9_]. The hyphen is admitted here because this registry's source ids
// are `src-0001`, and rule 1 above — a label may be a registered id — would
// otherwise be unsatisfiable by every record in the file. Recorded as an owner
// question rather than taken silently.
func labelOK(s string) (bad rune, ok bool) {
	if s == "" || len(s) > MaxLabelBytes {
		return 0, false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return r, false
		}
	}
	return 0, true
}

// validateLabels checks external_origins and every upstream_sources entry.
//
// A MALFORMED label is never echoed. A registry file is untrusted input
// (docs/SOURCE_REGISTRY.md §4) and FINDING-128 and FINDING-131 were both this
// package putting a document's own bytes into the operator's terminal; the
// offending RUNE is named instead, which is what internal/domain does for the
// same reason. A label that passed the charset check is at most 64 bytes of
// [a-z0-9_-] and is quoted, because "which label" is the whole content of an
// unresolvable-label diagnostic.
func (r *Registry) validateLabels(problems *[]Problem) {
	ids := map[string]bool{}
	for _, s := range r.Sources {
		ids[s.SourceID] = true
	}

	origins := map[string]bool{}
	for i, o := range r.ExternalOrigins {
		at := fmt.Sprintf("external_origins[%d]", i)
		if bad, ok := labelOK(o); !ok {
			*problems = append(*problems, Problem{at, badLabelReason(bad, len(o))})
			continue
		}
		if ids[o] {
			*problems = append(*problems, Problem{at, fmt.Sprintf(
				"is %q, which is also a source_id in this registry. A label that resolves two ways "+
					"resolves to two different things — a record whose lineage can be walked, and a "+
					"leaf — and the independence computation would silently pick one", o)})
			continue
		}
		if origins[o] {
			*problems = append(*problems, Problem{at, fmt.Sprintf("names %q twice", o)})
			continue
		}
		origins[o] = true
	}

	for i := range r.Sources {
		s := &r.Sources[i]
		seen := map[string]bool{}
		for j, label := range s.UpstreamLabels {
			at := fmt.Sprintf("sources[%d].upstream_labels[%d]", i, j)
			bad, ok := labelOK(label)
			if !ok {
				*problems = append(*problems, Problem{at, badLabelReason(bad, len(label))})
				continue
			}
			if seen[label] {
				*problems = append(*problems, Problem{at, fmt.Sprintf("names %q twice", label)})
				continue
			}
			seen[label] = true
			if ids[label] || origins[label] {
				continue
			}
			*problems = append(*problems, Problem{at, fmt.Sprintf(
				"is %q, which is neither a source_id in this registry nor an entry in the "+
					"top-level `external_origins` list. An upstream nobody can resolve establishes "+
					"nothing; declare it in `external_origins` if this registry holds no record for it", label)})
		}
	}
}

// badLabelReason describes a malformed label without reproducing it.
func badLabelReason(bad rune, n int) string {
	switch {
	case n == 0:
		return "is empty; an upstream nobody named is not an upstream"
	case n > MaxLabelBytes:
		return fmt.Sprintf("is %d bytes, over the %d-byte limit for a label", n, MaxLabelBytes)
	default:
		return fmt.Sprintf(
			"contains %q, which is not permitted in a label. Labels are lower-case letters, digits, "+
				"underscore and hyphen; the value is not reproduced here because a registry file is "+
				"untrusted input", bad)
	}
}

// # THE AUTHORITATIVE TIER
//
// A tier is a claim the registry author makes about a provider: that its
// assertion is worth acting on without a second voice. Two rules keep it from
// becoming a way around the provenance model.
//
// ONLY PRIMARY LINEAGE. An aggregator marked authoritative would let one
// republished corpus block on its own, which is precisely the inflation C-01
// and C-02 refuse — arriving through a field instead of through a count. So
// the tier requires a source that draws on nothing and documents that it
// draws on nothing.
//
// AND THE HOUSEHOLD STILL DECIDES. The registry cannot grant itself
// permission to act on one source; `accept_authoritative_alone` in the
// household's proposal policy is a separate statement, and internal/proposal
// is where it is read.

// Trust tiers. Absent is TierOrdinary: a record that says nothing about its
// tier is making no claim, which is the same as claiming nothing special.
const (
	TierOrdinary      = "ordinary"
	TierAuthoritative = "authoritative"
)

// ValidTiers is the closed vocabulary. The empty string is accepted as
// TierOrdinary and is not listed: it is an absent claim, not a value.
var ValidTiers = []string{TierOrdinary, TierAuthoritative}

// Authoritative reports whether this source holds the authoritative tier.
func (s *Source) Authoritative() bool { return s.TrustTier == TierAuthoritative }

// validateTiers refuses an unrecognised tier, and refuses the authoritative
// tier to anything that is not a primary observer.
func (r *Registry) validateTiers(problems *[]Problem) {
	for i := range r.Sources {
		s := &r.Sources[i]
		at := fmt.Sprintf("sources[%d].trust_tier", i)
		if s.TrustTier == "" || s.TrustTier == TierOrdinary {
			continue
		}
		if !contains(ValidTiers, s.TrustTier) {
			*problems = append(*problems, Problem{at, fmt.Sprintf(
				"is not a recognised tier; permitted values are %s, or the key may be omitted",
				strings.Join(ValidTiers, ", "))})
			continue
		}
		// TierAuthoritative from here.
		if s.UpstreamSourcesCompleteness != UpstreamDocumentedComplete {
			*problems = append(*problems, Problem{at, fmt.Sprintf(
				"is %q while upstream_sources_completeness is %q. A source may be trusted alone only "+
					"when it is known to draw on nothing; an undocumented upstream is not demonstrated "+
					"primacy", TierAuthoritative, s.UpstreamSourcesCompleteness)})
			continue
		}
		var drawn []string
		for _, l := range s.UpstreamLabels {
			if l != s.SourceID {
				drawn = append(drawn, l)
			}
		}
		drawn = append(drawn, s.AggregationDependencies...)
		if len(drawn) > 0 {
			*problems = append(*problems, Problem{at, fmt.Sprintf(
				"is %q on a record that names %d upstream(s). Only primary lineage may be "+
					"authoritative: an aggregator trusted alone lets one republished corpus block by "+
					"itself, which is the inflation the independence count exists to refuse",
				TierAuthoritative, len(drawn))})
		}
	}
}
