// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

// # ORDER 11 QUEUE ITEM 6 — SW-P2-11, MEASURED AT THE SHIPPED COMMAND
//
// SW-P2-11 is "a credential carried in a source URL reaches neither a stored
// row, nor an error, nor a log line, whoever composed the message". The
// matrix row cites two test files: `internal/acquire/c14_test.go`, which no
// command reaches, and `internal/audit/c14_test.go`, which every command
// does — `run()` builds `audit.New(stderr)` before it dispatches and hands it
// to the Pi-hole client.
//
// §5.9.6 filed SW-P2-11 under "carries SW-P2-10's qualifier … the three stand
// or fall together". That is right about the acquire half and wrong about
// this one, and the difference matters: the reachable half is the half that
// protects a household today.
//
// This is the shortest real path from a credential in a URL to a log line,
// and it is the one FINDING-135 and §4.45.4 describe. Pi-hole accepts a
// session id as a `sid` QUERY parameter; the client's redirect policy refuses
// a redirect carrying a query for exactly that reason; and the *url.Error
// describing the refusal quotes the URL in full. The fake appliance is made
// to issue that redirect on logout, and the run's whole stderr is then
// searched for the session id.

// TestASessionIdInARedirectUrlNeverReachesTheLog.
//
// Two defences stand between the peer-chosen URL and the log, and this test
// is deliberately indifferent to which one fires: the transport strips the
// `Method "URL": ` prefix an *url.Error adds, and audit.RedactURLs drops
// userinfo, query and fragment from anything that still looks like a URL. A
// test that asserted which layer caught it would start failing the day the
// other one was strengthened, and would say nothing about the household.
func TestASessionIdInARedirectUrlNeverReachesTheLog(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	// The appliance answers the logout with a redirect whose query carries
	// the session id — the shape the client's own CheckRedirect exists for.
	e.redirectLogoutTo = "/api/auth?sid=" + e.sid

	_, stdout, stderr := capture(t, e.args()...)
	both := stdout + stderr

	if e.sid == "" {
		t.Fatal("the fixture has no session id, so this test would prove nothing")
	}
	if strings.Contains(both, e.sid) {
		t.Errorf("the session id reached the output:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
	// And the password never appears either, on any path.
	if strings.Contains(both, e.password) {
		t.Errorf("the application password reached the output:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
	// The run still SAYS the logout failed. A redaction that also removed the
	// diagnosis would have made the household safer and the operator blind;
	// this asserts the second half did not happen.
	if !strings.Contains(both, "logout") {
		t.Errorf("the failed logout is not reported at all:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

// TestNoCredentialAppearsInAnyOrdinaryRun is the wider net.
//
// The test above constructs the one path that is known to carry a URL. This
// one drives an ordinary successful run and asserts the same two secrets are
// absent from everything the command wrote, which catches a leak introduced
// somewhere nobody thought to construct a case for.
func TestNoCredentialAppearsInAnyOrdinaryRun(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)),
		`{"domains":[{"domain":"bad.example.com","type":"deny","kind":"exact",`+
			`"comment":"the household added this","enabled":true,"id":1,"date_added":1000}],"took":0.001}`)

	for _, args := range [][]string{e.args(), e.args("-json")} {
		_, stdout, stderr := capture(t, args...)
		both := stdout + stderr
		for name, secret := range map[string]string{"session id": e.sid, "password": e.password} {
			if strings.Contains(both, secret) {
				t.Errorf("the %s reached the output of %v:\nstdout: %s\nstderr: %s",
					name, args[0], stdout, stderr)
			}
		}
	}
}
