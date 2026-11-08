// SPDX-License-Identifier: AGPL-3.0-only

package proposal_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/proposal"
)

func names(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("r%04d.example.com", i))
	}
	return out
}

// reportOf builds a report whose every outcome is a proposal, which is what
// the cap rules act on.
func reportOf(t *testing.T, canonical ...string) *proposal.Report {
	t.Helper()
	rep := &proposal.Report{}
	for _, c := range canonical {
		rep.Outcomes = append(rep.Outcomes, proposal.Outcome{
			Canonical:   c,
			Decision:    proposal.DecisionPropose,
			Reason:      proposal.ReasonCorroborated,
			Explanation: "synthetic",
		})
	}
	return rep
}

// activePolicy is a complete, enabled automatic contract with the two
// addition caps set as given.
func activePolicy(t *testing.T, perRun, perDay int) *proposal.Policy {
	t.Helper()
	yes := true
	zero := 1000
	life := "168h"
	outage := proposal.OutageHold
	chan_ := "the household's inbox"
	stop := "/var/lib/scamwall/STOP"
	return &proposal.Policy{
		Automatic: &proposal.Automatic{
			Enabled:              &yes,
			MaxAdditionsPerRun:   &perRun,
			MaxRemovalsPerRun:    &zero,
			MaxAdditionsPerDay:   &perDay,
			MaxRemovalsPerDay:    &zero,
			BlockLifetime:        &life,
			OnSourceOutage:       &outage,
			AlertChannel:         &chan_,
			EmergencyDisablePath: &stop,
		},
	}
}

func anyContains(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}
