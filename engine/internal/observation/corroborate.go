// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"fmt"
	"sort"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// Corroboration is what the evidence for one indicator actually supports.
//
// The number this answers to is "how many sources say so", and it is the
// number most easily inflated. Four inflations are possible and each is
// refused here:
//
//  1. One source imported twice. Handled at the store: a second import of the
//     same source record is a duplicate or a correction, never a second voice.
//  2. An aggregator counted alongside the upstream it copied. Collapsed, using
//     the lineage edges in the source registry.
//  3. A source whose upstreams nobody has documented, counted as independent.
//     Refused: an unknown upstream is not demonstrated independence, and the
//     registry's IndependenceClaimable is what says so.
//  4. A source id that resolves to nothing. Refused, and reported, because a
//     record attributed to a source nobody can look up is not attributable.
//
// The result is deliberately a breakdown rather than a number. A single
// integer cannot distinguish "two sources, both independent" from "two
// sources, neither of whose lineage anyone has established", and the
// difference between those is the whole content of the claim.
type Corroboration struct {
	// Independent are sources whose independence the registry supports, after
	// lineage collapsing.
	Independent []string
	// Unestablished are sources that report the indicator but whose
	// independence cannot be established. They are evidence; they are not
	// evidence of INDEPENDENT corroboration.
	Unestablished []string
	// Collapsed records each source folded into an upstream, and which one.
	Collapsed []Collapse
	// Unresolved are source ids that do not appear in the registry at all.
	Unresolved []string
	// Retired are source ids the registry has withdrawn. Distinguished from
	// Unresolved because they mean something different: the source existed and
	// was deliberately taken out of service, so a live reference to one is a
	// stale pointer rather than a typo.
	Retired []string
	// ExpiredOnly are sources whose only current revision has passed its
	// expiry. Counted nowhere else: an indicator supported solely by lapsed
	// evidence has no live support, and saying so is the point.
	ExpiredOnly []string
	// Withdrawn are sources that have withdrawn their observation.
	Withdrawn []string
	// Notes explain every exclusion, in a stable order.
	Notes []string
}

// Collapse is one source folded into an upstream it draws from.
type Collapse struct {
	Source   string
	Upstream string
}

// Corroborate assesses the support for one indicator at a point in time.
//
// It answers a question about EVIDENCE. It does not decide whether the
// indicator should be blocked, it does not produce a score, and it does not
// take a side in a classification conflict: all three are policy questions
// that need inputs this function does not have.
func (i Indicator) Corroborate(reg *sourceregistry.Registry, at time.Time) Corroboration {
	var c Corroboration
	if reg == nil {
		c.Notes = append(c.Notes, "no source registry was supplied; no independence claim can be assessed without one")
	}

	// One entry per source: several records from one provider are one voice.
	live := map[string]bool{}
	seen := map[string]bool{}
	for _, e := range i.Entries {
		if e.Superseded {
			continue
		}
		id := e.Observation.SourceID
		seen[id] = true
		if e.Observation.Live(at) {
			live[id] = true
		}
	}

	for id := range seen {
		if live[id] {
			continue
		}
		withdrawn := false
		for _, e := range i.Entries {
			if !e.Superseded && e.Observation.SourceID == id && e.Observation.Status == StatusWithdrawn {
				withdrawn = true
			}
		}
		if withdrawn {
			c.Withdrawn = append(c.Withdrawn, id)
			c.Notes = append(c.Notes, fmt.Sprintf("%s has withdrawn its observation; the record is retained and is not counted as support", id))
		} else {
			c.ExpiredOnly = append(c.ExpiredOnly, id)
			c.Notes = append(c.Notes, fmt.Sprintf("%s reported this but its evidence has lapsed; retained as history and not counted as live support", id))
		}
	}

	candidates := make([]string, 0, len(live))
	for id := range live {
		candidates = append(candidates, id)
	}
	sort.Strings(candidates)

	if reg == nil {
		c.Unestablished = candidates
		for _, id := range candidates {
			c.Notes = append(c.Notes, fmt.Sprintf("%s cannot be assessed without a registry", id))
		}
		sort.Strings(c.Notes)
		finalise(&c)
		return c
	}

	// Resolve every id first. An unresolvable id is not carried into the
	// lineage walk, because an edge from a record that does not exist
	// establishes nothing in either direction.
	resolved := make([]string, 0, len(candidates))
	for _, id := range candidates {
		if _, ok := reg.Source(id); ok {
			resolved = append(resolved, id)
			continue
		}
		if reg.Retired(id) {
			c.Retired = append(c.Retired, id)
			c.Notes = append(c.Notes, fmt.Sprintf("%s is retired; a retired id is never reused, so an observation still carrying it cannot be attributed to a current source", id))
			continue
		}
		c.Unresolved = append(c.Unresolved, id)
		c.Notes = append(c.Notes, fmt.Sprintf("%s does not appear in the source registry; an observation attributed to a source nobody can look up is not attributable", id))
	}

	// Collapse lineage. A source that draws from another source ALSO present
	// here is folded into it, so that an aggregator and the feed it copied are
	// one voice rather than two. The upstream is kept because it is the nearer
	// observer; that is a choice, and it is a conservative one either way
	// since the pair contributes exactly one count.
	present := map[string]bool{}
	for _, id := range resolved {
		present[id] = true
	}
	folded := map[string]bool{}
	for _, id := range resolved {
		src, _ := reg.Source(id)
		for _, up := range reachableUpstreams(reg, src) {
			if !present[up] || up == id {
				continue
			}
			folded[id] = true
			c.Collapsed = append(c.Collapsed, Collapse{Source: id, Upstream: up})
			c.Notes = append(c.Notes, fmt.Sprintf("%s draws from %s, which also reports this; counted once, not twice", id, up))
		}
	}

	for _, id := range resolved {
		if folded[id] {
			continue
		}
		src, _ := reg.Source(id)
		if ok, why := chainClaimable(reg, src); ok {
			c.Independent = append(c.Independent, id)
		} else {
			c.Unestablished = append(c.Unestablished, id)
			c.Notes = append(c.Notes, why)
		}
	}

	finalise(&c)
	return c
}

// reachableUpstreams walks the lineage graph from s, following
// aggregation_dependencies transitively.
//
// The walk is bounded by a visited set, so a cycle in the registry — which the
// registry's own validator refuses, but which this function must not assume
// away — terminates instead of recurring forever.
func reachableUpstreams(reg *sourceregistry.Registry, s *sourceregistry.Source) []string {
	if s == nil {
		return nil
	}
	visited := map[string]bool{s.SourceID: true}
	queue := append([]string(nil), s.AggregationDependencies...)
	var out []string
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true
		out = append(out, id)
		if up, ok := reg.Source(id); ok {
			queue = append(queue, up.AggregationDependencies...)
		}
	}
	sort.Strings(out)
	return out
}

func finalise(c *Corroboration) {
	sort.Strings(c.Independent)
	sort.Strings(c.Unestablished)
	sort.Strings(c.Unresolved)
	sort.Strings(c.Retired)
	sort.Strings(c.ExpiredOnly)
	sort.Strings(c.Withdrawn)
	sort.Strings(c.Notes)
	sort.Slice(c.Collapsed, func(i, j int) bool {
		if c.Collapsed[i].Source != c.Collapsed[j].Source {
			return c.Collapsed[i].Source < c.Collapsed[j].Source
		}
		return c.Collapsed[i].Upstream < c.Collapsed[j].Upstream
	})
	c.Notes = dedupe(c.Notes)
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// IndependentCount is the conservative headline number.
//
// It counts ONLY sources whose independence the registry supports. Sources
// whose lineage is undocumented are excluded from it entirely rather than
// discounted, because there is no principled weight to give them: the fact is
// not that their contribution is small, it is that nobody knows whether it is
// a separate contribution at all.
func (c Corroboration) IndependentCount() int { return len(c.Independent) }

// CollapsedSources are the DISTINCT sources folded into an upstream.
//
// Collapsed itself is a list of EDGES and stays one: an aggregator drawing
// from three present upstreams has three reasons to be folded, and a reviewer
// asking "why is this not counted separately" needs all three. This is the
// same information asked as "how many sources", which is a different question
// with a different answer.
func (c Corroboration) CollapsedSources() []string {
	if len(c.Collapsed) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(c.Collapsed))
	for _, e := range c.Collapsed {
		if seen[e.Source] {
			continue
		}
		seen[e.Source] = true
		out = append(out, e.Source)
	}
	sort.Strings(out)
	return out
}

// SupportingCount is every live, attributable source, independent or not.
//
// Reported alongside IndependentCount and never instead of it. The two
// together say "N sources report this, of which M are established as
// independent"; either on its own is misleading in a different direction.
//
// # WHY THIS COUNTS SOURCES AND NOT EDGES
//
// The superseded implementation added len(c.Collapsed), which is the number of
// LINEAGE EDGES, not the number of sources those edges fold away. One source
// folded for three separate reasons was counted three times. Measured directly
// against it:
//
//	one aggregator over two present upstreams   3 live sources -> reported 4
//	one aggregator over three present upstreams 4 live sources -> reported 6
//	transitive lineage a->b->c                  3 live sources -> reported 4
//
// That is count inflation in the headline support number — the precise error
// the whole provenance model exists to prevent, reintroduced one layer above
// the place it is prevented. Two shapes happened to come out right (two
// aggregators over one upstream, and a two-source cycle), which is exactly why
// a single example would not have found this.
func (c Corroboration) SupportingCount() int {
	return len(c.Independent) + len(c.Unestablished) + len(c.CollapsedSources())
}

// chainClaimable reports whether s may be counted as independent once the
// whole lineage chain beneath it is taken into account, and why not when it
// may not.
//
// # WHY THE SOURCE'S OWN FIELD IS NOT THE ANSWER
//
// FINDING-134, ORDER 8 control C-05. `Source.IndependenceClaimable` reads one
// field of one record: that source's own `upstream_sources_completeness`. A
// source may therefore document its own upstreams completely, and be counted
// independent, while an upstream it names documents nothing at all.
//
// The claim is then true and useless. "I know everything I draw from" says
// nothing about whether what I draw from knows what IT draws from, so a shared
// origin one hop further out is exactly as possible as if the first source had
// documented nothing. Two sources that both name the same undocumented
// upstream were counted as two independent voices, which satisfies a
// two-independent-source threshold with what may be one observation relayed
// twice. That is the third inflation this file exists to refuse, one hop
// beyond the place it was refused.
//
// Collapsing does not catch it: collapsing folds a source into an upstream
// that is ALSO reporting the indicator, and the undocumented upstream here
// reports nothing. The two controls answer different questions and both are
// needed.
//
// A chain every link of which documents its upstreams completely still counts.
// The rule is inheritance of "unestablished", not a penalty for having
// lineage — a source that documents a deep chain is the case the registry
// rewards, and TestADocumentedChainStillCounts holds that line.
func chainClaimable(reg *sourceregistry.Registry, s *sourceregistry.Source) (bool, string) {
	if ok, why := s.IndependenceClaimable(); !ok {
		return false, why
	}
	for _, upID := range reachableUpstreams(reg, s) {
		up, ok := reg.Source(upID)
		if !ok {
			if reg.Retired(upID) {
				return false, fmt.Sprintf(
					"%s draws from %s, which is retired; a retired record documents nothing current, so %s's lineage is not established",
					s.SourceID, upID, s.SourceID)
			}
			return false, fmt.Sprintf(
				"%s draws from %s, which does not appear in the source registry; an upstream nobody can look up documents nothing, so %s's lineage is not established",
				s.SourceID, upID, s.SourceID)
		}
		if ok, _ := up.IndependenceClaimable(); !ok {
			return false, fmt.Sprintf(
				"%s documents its own upstreams, but %s, which it draws from, does not document what IT draws from; a shared origin one hop further out is exactly as possible, so %s's independence is not established",
				s.SourceID, upID, s.SourceID)
		}
	}
	return true, ""
}
