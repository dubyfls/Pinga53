// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"math/bits"
	"sort"
)

// # INDEPENDENCE IS A PROPERTY OF ORIGINS, NOT A COUNT OF FEEDS
//
// "Three sources say so" is the number the whole provenance model exists to
// protect, and counting reporting feeds is the wrong way to compute it. Three
// feeds that all republish one corpus are one observation delivered three
// times.
//
// So each source resolves to the SET OF ORIGINS its records could have come
// from, and the answer to "how many independent voices" is the largest number
// of those sets that are pairwise disjoint. Two sources sharing any origin can
// contribute at most one between them.
//
// Collapsing (internal/observation) answers a narrower question and remains
// necessary: it folds a source into an upstream that is ALSO reporting. Origin
// groups answer the case collapsing cannot see, where the shared upstream is
// reporting nothing — because it is a corpus, a submission queue, or somebody
// else's aggregate that this registry holds no record for at all.

// MaxOriginWalk bounds the lineage walk. The registry's own validator refuses
// cycles, and this function must not assume that away: it is called on
// documents that have not necessarily been validated.
const MaxOriginWalk = 1000

// Origins returns the set of origins a source's records could have come from,
// sorted.
//
// A source that names no upstream at all is a primary observer and its origin
// is itself. A source that names upstreams resolves to the union of THEIR
// origins, so a chain of republishers collapses onto the thing at the end of
// it. An id that resolves to nothing is its own origin: an unresolvable
// upstream cannot be shown to be shared, and inventing a shared origin for it
// would merge sources that might be independent.
func (r *Registry) Origins(id string) []string {
	seen := map[string]bool{}
	out := map[string]bool{}
	external := map[string]bool{}
	for _, o := range r.ExternalOrigins {
		external[o] = true
	}

	queue := []string{id}
	steps := 0
	for len(queue) > 0 && steps < MaxOriginWalk {
		steps++
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true

		if external[cur] {
			out[cur] = true
			continue
		}
		src, ok := r.Source(cur)
		if !ok {
			// Not a record and not a declared origin. It is its own origin;
			// see the doc comment.
			out[cur] = true
			continue
		}

		// Both lists are lineage. upstream_labels is the machine-readable
		// one; aggregation_dependencies predates it and names registry ids.
		var next []string
		next = append(next, src.UpstreamLabels...)
		next = append(next, src.AggregationDependencies...)
		if len(next) == 0 {
			out[cur] = true
			continue
		}
		selfNamed := false
		for _, n := range next {
			if n == cur {
				// A primary naming its own group. It is an origin, and it
				// does not stop the record's other upstreams counting.
				selfNamed = true
				continue
			}
			queue = append(queue, n)
		}
		if selfNamed {
			out[cur] = true
		}
	}
	if steps >= MaxOriginWalk {
		// The walk was truncated, so the origin set is incomplete. An
		// incomplete origin set can only make two sources look MORE
		// independent than they are, so the source is given an origin nobody
		// else can share and then one that everybody shares — the second is
		// what makes it collapse against everything rather than count alone.
		out[id] = true
		out["\x00truncated"] = true
	}

	res := make([]string, 0, len(out))
	for o := range out {
		res = append(res, o)
	}
	sort.Strings(res)
	return res
}

// OriginGroups is the result of grouping sources by shared origin.
type OriginGroups struct {
	// Count is the maximum number of pairwise-disjoint origin sets, which is
	// the number of independent voices among the ids given.
	Count int
	// Representatives are one id from each group in the chosen maximum,
	// sorted. Reported so a reader can see WHICH sources the count came from.
	Representatives []string
	// Shared lists the origins that two or more of the ids draw on, sorted.
	// This is the actionable half: it names why the count is below the
	// number of sources.
	Shared []string
	// Exact is false when the maximum was approximated. See the comment in
	// MaxDisjointOrigins.
	Exact bool
}

// exactLimit is the largest number of sources for which the maximum is
// computed exactly. Above it a greedy lower bound is used; see below.
const exactLimit = 16

// MaxDisjointOrigins computes the number of independent voices among ids.
//
// The answer is the size of the largest pairwise-disjoint family of origin
// sets. For up to exactLimit sources that is computed exactly, by enumerating
// subsets over a bitmask of origins. Above it a greedy lower bound is used —
// smallest origin set first — and Exact is false.
//
// A lower bound is the safe approximation. It can only report FEWER
// independent voices than there are, which makes a threshold harder to meet
// and produces fewer blocks; an upper bound would manufacture corroboration,
// which is the one thing this computation exists to prevent.
func (r *Registry) MaxDisjointOrigins(ids []string) OriginGroups {
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	if len(ids) == 0 {
		return OriginGroups{Exact: true}
	}

	// Index every origin so a set is a bitmask.
	index := map[string]int{}
	sets := make([]uint64, len(ids))
	counts := map[string]int{}
	for i, id := range ids {
		for _, o := range r.Origins(id) {
			bit, ok := index[o]
			if !ok {
				bit = len(index)
				index[o] = bit
			}
			counts[o]++
			if bit < 64 {
				sets[i] |= 1 << uint(bit)
			} else {
				// More than 64 distinct origins among these sources. Give up
				// on precision in the safe direction: this source shares an
				// origin with everything, so it can never add a voice.
				sets[i] = ^uint64(0)
			}
		}
	}

	var shared []string
	for o, n := range counts {
		if n > 1 {
			shared = append(shared, o)
		}
	}
	sort.Strings(shared)

	g := OriginGroups{Shared: shared}
	if len(ids) <= exactLimit {
		g.Exact = true
		best := 0
		var bestMask uint
		for mask := range uint(1) << uint(len(ids)) {
			if bits.OnesCount(mask) <= best {
				continue
			}
			var union uint64
			total := 0
			ok := true
			for i := range ids {
				if mask&(1<<uint(i)) == 0 {
					continue
				}
				if union&sets[i] != 0 {
					ok = false
					break
				}
				union |= sets[i]
				total++
			}
			if ok && total > best {
				best, bestMask = total, mask
			}
		}
		g.Count = best
		for i, id := range ids {
			if bestMask&(1<<uint(i)) != 0 {
				g.Representatives = append(g.Representatives, id)
			}
		}
		return g
	}

	// Greedy lower bound: smallest origin set first, because a source drawing
	// on one origin blocks fewer later candidates than one drawing on ten.
	order := make([]int, len(ids))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return bits.OnesCount64(sets[order[a]]) < bits.OnesCount64(sets[order[b]])
	})
	var union uint64
	for _, i := range order {
		if union&sets[i] != 0 {
			continue
		}
		union |= sets[i]
		g.Count++
		g.Representatives = append(g.Representatives, ids[i])
	}
	sort.Strings(g.Representatives)
	return g
}
