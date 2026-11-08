// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"
)

// TestTheNetworkClaimIsNoStrongerThanTheEvidence.
//
// # WHY A TEST GUARDS A SENTENCE
//
// The report's limitations travel inside the document so that quoting a count
// without them takes effort. One of them said, unconditionally:
//
//	no network communication was attempted
//
// The evidence does not support that. What was measured is an empty network
// namespace, with `scamwall status` failing in it as the positive control:
// that establishes the command COMPLETES no network operation. A connect()
// that failed and was ignored would look exactly the same.
//
// A claim in a report is an artefact like any other, and this is the
// regression that keeps it at the strength the evidence supports.
func TestTheNetworkClaimIsNoStrongerThanTheEvidence(t *testing.T) {
	joined := strings.Join((&Report{}).Limitations(), " ")

	for _, forbidden := range []string{
		"no network communication was attempted",
		"no socket was opened",
		"opens no socket",
		"attempted no network",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("the report claims %q, which the evidence does not establish", forbidden)
		}
	}

	for _, required := range []string{
		// what IS established
		"COMPLETED no network operation",
		"empty network namespace",
		// and what is not
		"NOT established",
		"connect() that failed and was ignored",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("the report no longer states %q", required)
		}
	}

	// The weaker claims that ARE supported must survive; a correction that
	// deleted the whole line would satisfy the first half of this test.
	for _, kept := range []string{
		"Nothing here was fetched",
		"every input was a local file named on the command line",
	} {
		if !strings.Contains(joined, kept) {
			t.Errorf("the report lost the claim %q, which the evidence does support", kept)
		}
	}
}
