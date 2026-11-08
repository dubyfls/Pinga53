// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// ORDER 8, control C-05: "Undisclosed (empty upstreams) or heuristic lineage
// never counts toward the threshold. A chain reaching one inherits
// 'independence unestablished'."
//
// The first half of that is this tree's strongest control and is already
// tested (TestAnUnknownUpstreamIsNotIndependence). The second half — the
// INHERITANCE — is what these cover.
//
// # WHY IT MATTERS
//
// `IndependenceClaimable` reads one field of one source: its own
// `upstream_sources_completeness`. A source may therefore document its own
// upstreams completely, and be counted independent, while an upstream it
// declares documents nothing at all. The claim "I know everything I draw from"
// is then true and useless: what it draws from does not know what IT draws
// from, so a shared origin one level up is exactly as possible as if the first
// source had documented nothing.
//
// That is the third inflation the registry exists to prevent, one hop further
// out than the place it is prevented.

// TestCompletenessIsNotInheritedFromAnUndocumentedUpstream.
func TestCompletenessIsNotInheritedFromAnUndocumentedUpstream(t *testing.T) {
	reg := synthReg(t,
		// Documents its own upstreams completely, and names one.
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, []string{"src-0002"}, nil),
		// The upstream it names documents nothing. It does not report the
		// indicator itself, so lineage collapsing never fires.
		src("src-0002", sourceregistry.UpstreamUnknown, nil, nil),
	)
	c := indicatorOf(t, "src-0001").Corroborate(reg, t1)

	if c.IndependentCount() != 0 {
		t.Errorf("independent = %v (%d), want 0.\n"+
			"src-0001 documents what it draws from, but src-0002 does not document "+
			"what IT draws from. A shared origin one hop further out is exactly as "+
			"possible as if src-0001 had documented nothing.",
			c.Independent, c.IndependentCount())
	}
	if len(c.Unestablished) != 1 || c.Unestablished[0] != "src-0001" {
		t.Errorf("unestablished = %v, want [src-0001]", c.Unestablished)
	}
	var named bool
	for _, n := range c.Notes {
		if strings.Contains(n, "src-0002") {
			named = true
		}
	}
	if !named {
		t.Errorf("no note names the upstream that broke the chain.\nNotes: %v", c.Notes)
	}
}

// TestTwoSourcesSharingAnUndocumentedUpstreamAreNotTwoVoices is the harm the
// inheritance rule exists to stop, stated as the number it corrupts.
//
// Neither source reports through the other, so collapsing does not fire; both
// declare complete upstreams, so both are claimable; and the threshold sees
// two independent voices for what may be one.
func TestTwoSourcesSharingAnUndocumentedUpstreamAreNotTwoVoices(t *testing.T) {
	reg := synthReg(t,
		src("src-0001", sourceregistry.UpstreamDocumentedComplete, []string{"src-0009"}, nil),
		src("src-0002", sourceregistry.UpstreamDocumentedComplete, []string{"src-0009"}, nil),
		src("src-0009", sourceregistry.UpstreamUnknown, nil, nil),
	)
	c := indicatorOf(t, "src-0001", "src-0002").Corroborate(reg, t1)

	if c.IndependentCount() >= 2 {
		t.Errorf("independent = %v (%d); a policy asking for two independent "+
			"sources is satisfied by what may be one observation relayed twice",
			c.Independent, c.IndependentCount())
	}
}

// TestADocumentedChainStillCounts is the control on the control. Inheritance
// must not turn into "any declared upstream disqualifies you", which would
// make the whole lineage model unusable: a source that documents its upstreams
// completely, all the way down, is exactly the case the registry rewards.
func TestADocumentedChainStillCounts(t *testing.T) {
	complete := sourceregistry.UpstreamDocumentedComplete
	reg := synthReg(t,
		src("src-0001", complete, []string{"src-0002"}, nil),
		src("src-0002", complete, []string{"src-0003"}, nil),
		src("src-0003", complete, nil, nil),
	)
	c := indicatorOf(t, "src-0001").Corroborate(reg, t1)
	if c.IndependentCount() != 1 {
		t.Errorf("independent = %v (%d), want 1; every link in this chain "+
			"documents what it draws from", c.Independent, c.IndependentCount())
	}
}
