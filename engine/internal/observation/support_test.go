// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// TestSupportingCountCountsSourcesNotLineageEdges.
//
// # WHAT THE SUPERSEDED IMPLEMENTATION DID
//
// SupportingCount was len(Independent) + len(Unestablished) + len(Collapsed),
// and Collapsed is a list of EDGES. One source folded for three separate
// reasons was counted three times. Measured against it:
//
//	one aggregator over two present upstreams   3 live -> reported 4
//	one aggregator over three present upstreams 4 live -> reported 6
//	transitive lineage a->b->c                  3 live -> reported 4
//	two aggregators over one upstream           3 live -> reported 3  (right by accident)
//	a cycle a<->b                               2 live -> reported 2  (right by accident)
//
// The last two are why this is a table and not an example: two of the five
// shapes gave the correct answer for the wrong reason, so a single fixture had
// an even chance of proving nothing.
func TestSupportingCountCountsSourcesNotLineageEdges(t *testing.T) {
	complete := sourceregistry.UpstreamDocumentedComplete

	tests := []struct {
		name    string
		sources []sourceregistry.Source
		ids     []string
		// wantSupporting is the number of distinct live attributable sources.
		wantSupporting int
		// wantIndependent is how many survive lineage collapsing.
		wantIndependent int
		// wantEdges is how many collapse edges the breakdown retains.
		wantEdges int
		// wantCollapsedSources is how many DISTINCT sources those edges fold.
		wantCollapsedSources int
		// supersededReported is what the edge-counting version said.
		supersededReported int
	}{
		{
			name: "one aggregator over two present upstreams",
			sources: []sourceregistry.Source{
				src("agg-1", complete, []string{"up-1", "up-2"}, nil),
				src("up-1", complete, nil, nil),
				src("up-2", complete, nil, nil),
			},
			ids:                  []string{"agg-1", "up-1", "up-2"},
			wantSupporting:       3,
			wantIndependent:      2,
			wantEdges:            2,
			wantCollapsedSources: 1,
			supersededReported:   4,
		},
		{
			name: "one aggregator over three present upstreams",
			sources: []sourceregistry.Source{
				src("agg-1", complete, []string{"up-1", "up-2", "up-3"}, nil),
				src("up-1", complete, nil, nil),
				src("up-2", complete, nil, nil),
				src("up-3", complete, nil, nil),
			},
			ids:                  []string{"agg-1", "up-1", "up-2", "up-3"},
			wantSupporting:       4,
			wantIndependent:      3,
			wantEdges:            3,
			wantCollapsedSources: 1,
			supersededReported:   6,
		},
		{
			name: "two aggregators over one upstream",
			sources: []sourceregistry.Source{
				src("agg-1", complete, []string{"up-1"}, nil),
				src("agg-2", complete, []string{"up-1"}, nil),
				src("up-1", complete, nil, nil),
			},
			ids:                  []string{"agg-1", "agg-2", "up-1"},
			wantSupporting:       3,
			wantIndependent:      1,
			wantEdges:            2,
			wantCollapsedSources: 2,
			supersededReported:   3,
		},
		{
			name: "transitive lineage a->b->c",
			sources: []sourceregistry.Source{
				src("a", complete, []string{"b"}, nil),
				src("b", complete, []string{"c"}, nil),
				src("c", complete, nil, nil),
			},
			ids:                  []string{"a", "b", "c"},
			wantSupporting:       3,
			wantIndependent:      1,
			wantEdges:            3,
			wantCollapsedSources: 2,
			supersededReported:   4,
		},
		{
			name: "a two-source cycle",
			sources: []sourceregistry.Source{
				src("a", complete, []string{"b"}, nil),
				src("b", complete, []string{"a"}, nil),
			},
			ids:                  []string{"a", "b"},
			wantSupporting:       2,
			wantIndependent:      0,
			wantEdges:            2,
			wantCollapsedSources: 2,
			supersededReported:   2,
		},
		{
			name: "a three-source cycle",
			sources: []sourceregistry.Source{
				src("a", complete, []string{"b"}, nil),
				src("b", complete, []string{"c"}, nil),
				src("c", complete, []string{"a"}, nil),
			},
			ids:                  []string{"a", "b", "c"},
			wantSupporting:       3,
			wantIndependent:      0,
			wantEdges:            6,
			wantCollapsedSources: 3,
			supersededReported:   6,
		},
		{
			name: "no lineage at all",
			sources: []sourceregistry.Source{
				src("x", complete, nil, nil),
				src("y", complete, nil, nil),
			},
			ids:                  []string{"x", "y"},
			wantSupporting:       2,
			wantIndependent:      2,
			wantEdges:            0,
			wantCollapsedSources: 0,
			supersededReported:   2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := synthReg(t, tc.sources...)
			c := indicatorOf(t, tc.ids...).Corroborate(reg, t1)

			if got := c.SupportingCount(); got != tc.wantSupporting {
				t.Errorf("SupportingCount() = %d, want %d (the superseded "+
					"edge-counting version reported %d, from %d live source(s))",
					got, tc.wantSupporting, tc.supersededReported, len(tc.ids))
			}
			// It can never exceed the number of live sources that exist.
			if got := c.SupportingCount(); got > len(tc.ids) {
				t.Errorf("SupportingCount() = %d with only %d live source(s)", got, len(tc.ids))
			}
			if got := c.IndependentCount(); got != tc.wantIndependent {
				t.Errorf("IndependentCount() = %d, want %d", got, tc.wantIndependent)
			}
			// The detailed edges are PRESERVED, not reduced to the count.
			if got := len(c.Collapsed); got != tc.wantEdges {
				t.Errorf("Collapsed holds %d edge(s), want %d; the detailed "+
					"collapse reasons must survive the counting fix", got, tc.wantEdges)
			}
			if got := len(c.CollapsedSources()); got != tc.wantCollapsedSources {
				t.Errorf("CollapsedSources() = %d, want %d", got, tc.wantCollapsedSources)
			}
			// Independence is never claimed for a folded source.
			folded := map[string]bool{}
			for _, s := range c.CollapsedSources() {
				folded[s] = true
			}
			for _, id := range c.Independent {
				if folded[id] {
					t.Errorf("%s is both folded and counted as independent", id)
				}
			}
		})
	}
}

// TestSupportingCountNeverExceedsLiveSources is the invariant behind every
// case above, stated once so a future shape cannot slip past the table.
func TestSupportingCountNeverExceedsLiveSources(t *testing.T) {
	complete := sourceregistry.UpstreamDocumentedComplete
	// A deliberately dense lineage: everything draws from everything earlier.
	var sources []sourceregistry.Source
	var ids []string
	for i, id := range []string{"s1", "s2", "s3", "s4", "s5"} {
		sources = append(sources, src(id, complete, ids[:i], nil))
		ids = append(ids, id)
	}
	reg := synthReg(t, sources...)
	c := indicatorOf(t, ids...).Corroborate(reg, t1)

	if got := c.SupportingCount(); got > len(ids) {
		t.Errorf("SupportingCount() = %d with %d live sources; %d collapse edges",
			got, len(ids), len(c.Collapsed))
	}
	if len(c.Collapsed) <= len(ids) {
		t.Logf("note: this shape produced only %d edges for %d sources; it is "+
			"meant to produce many more than one per source", len(c.Collapsed), len(ids))
	}
}

// TestExcludedSourcesAreNotSupport. Expired, withdrawn, retired and
// unresolvable sources are live in no sense and must not be counted.
func TestExcludedSourcesAreNotSupport(t *testing.T) {
	complete := sourceregistry.UpstreamDocumentedComplete
	reg := synthReg(t, src("good", complete, nil, nil))

	s := NewStore()
	for _, id := range []string{"good", "missing"} {
		if _, err := s.Add(mustNew(t, "example.com", id)); err != nil {
			t.Fatal(err)
		}
	}
	// A withdrawn source.
	w := mustNew(t, "example.com", "gone")
	w.Status = StatusWithdrawn
	if _, err := s.Add(w); err != nil {
		t.Fatal(err)
	}

	ind, _ := s.Lookup(Key{Type: TypeDomain, Canonical: "example.com"})
	c := ind.Corroborate(reg, t1)

	if got := c.SupportingCount(); got != 1 {
		t.Errorf("SupportingCount() = %d, want 1: only `good` is live and attributable "+
			"(unresolved=%v withdrawn=%v)", got, c.Unresolved, c.Withdrawn)
	}
	if len(c.Withdrawn) != 1 {
		t.Errorf("Withdrawn = %v, want one entry", c.Withdrawn)
	}
	if len(c.Unresolved) != 1 {
		t.Errorf("Unresolved = %v, want one entry", c.Unresolved)
	}
}
