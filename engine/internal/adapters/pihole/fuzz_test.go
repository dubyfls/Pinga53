// SPDX-License-Identifier: AGPL-3.0-only

package pihole_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/adapters/pihole"
	"github.com/dubyfls/Pinga53/engine/internal/audit"
	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// FuzzAuthResponse drives the real client, over real TLS, against a server
// that answers the authentication request with arbitrary bytes.
//
// The invariant is the one that matters for an authentication client: no
// malformed, hostile or merely unexpected response may be interpreted as a
// successful authorisation. A decoder-level fuzz would not establish it —
// "the JSON parsed" and "we now believe we hold a valid session" are different
// claims, and the gap between them is where this kind of defect lives.
//
// The server is local. Nothing here contacts anything outside the machine.
func FuzzAuthResponse(f *testing.F) {
	seeds := []struct {
		status int
		body   string
	}{
		{200, `{"session":{"valid":true,"totp":false,"sid":"s","csrf":"c","validity":1800,"message":null},"took":0.1}`},
		{200, `{"session":{"valid":true,"sid":null,"validity":1800}}`},
		{200, `{"session":{"valid":true,"sid":"","validity":1800}}`},
		{200, `{"session":{"valid":false}}`},
		{200, `{}`},
		{200, `null`},
		{200, `[]`},
		{200, ``},
		{200, `{"session":`},
		{401, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null}}`},
		{429, `{"error":{"key":"rate_limit","message":"slow down","hint":null}}`},
		{204, ``},
		{500, `<html>not json</html>`},
		{200, strings.Repeat("A", 4096)},
	}
	for _, s := range seeds {
		f.Add(s.body, uint16(s.status))
	}

	var mu sync.Mutex
	body := ""
	status := 200
	contentType := "application/json; charset=utf-8"

	ca := newTestCA(f)
	srv := newFakePihole(f, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		b, st := body, status
		mu.Unlock()
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(st)
		_, _ = io.WriteString(w, b)
	}))
	cfg := configFor(f, srv, ca.path)
	c, err := pihole.New(cfg, audit.New(io.Discard))
	if err != nil {
		f.Fatalf("client construction failed: %v", err)
	}
	// Generated per run rather than written as a literal, for the same reason
	// the session values in testserver_test.go are: a credential-shaped literal
	// in a public repository is what the secret scanner exists to stop, and a
	// fresh value cannot collide with something a response legitimately
	// contains, which would make the leak assertion quietly meaningless.
	password := randomToken("pw")

	f.Fuzz(func(t *testing.T, respBody string, respStatus uint16) {
		// Only FINAL statuses are fuzzed.
		//
		// Outside 100..599 the test server panics, which is a property of
		// net/http rather than of the client. 1xx is excluded for a subtler
		// reason, and it is written down because the first run of this target
		// reported it as a client defect: net/http's SERVER treats a 1xx from
		// WriteHeader as an informational block and then sends its own 200 as
		// the final status, so the client correctly saw a 200 while this test
		// believed it had sent a 120. The invariant below compares against the
		// status the peer actually sent, so a status the server will not send
		// as final has no place in it.
		st := int(respStatus)
		if st < 200 || st > 599 {
			t.Skip()
		}
		mu.Lock()
		body, status = respBody, st
		mu.Unlock()

		// One client for the whole campaign, not one per iteration.
		//
		// A fresh client builds a fresh http.Transport, and a transport that is
		// never closed keeps its idle connections. At tens of thousands of
		// executions that exhausts the process's file descriptors and the fuzz
		// worker dies mid-run — which the fuzzer reports as \"hung or terminated
		// unexpectedly\", an alarming message for what is only the test leaking.
		// Observed at ~17k executions before this was changed.
		//
		// The session is cleared first so each iteration starts unauthenticated;
		// Logout discards the id whatever the peer answers.
		_ = c.Logout(t.Context())

		// INVARIANT 1: no panic, for any body and any status.
		state, err := c.Login(t.Context(), config.NewSecretString(password))

		if err != nil {
			// INVARIANT 2: a failed authentication holds no session. A client
			// that kept one would send a fabricated id on the next request and
			// would not know it was unauthenticated.
			if c.SessionActive() {
				t.Fatalf("Login failed (%v) but a session is held", err)
			}
			// INVARIANT 3: the credential never appears in the error, however
			// the peer replied.
			if strings.Contains(err.Error(), password) {
				t.Fatal("the credential appears in an error returned to the caller")
			}
			return
		}

		// INVARIANT 4: success requires a session. Login may only return nil
		// when it actually obtained a non-empty session id — the whole point
		// of the ErrNoSessionID branch.
		if !c.SessionActive() {
			t.Fatalf("Login succeeded with no session held; state=%+v body=%q status=%d", state, respBody, st)
		}

		// INVARIANT 5: success requires a 2xx. No 4xx or 5xx may be read as an
		// authorisation, whatever its body says.
		if st < 200 || st >= 300 {
			t.Fatalf("status %d was interpreted as a successful authorisation (body %q)", st, respBody)
		}

		// INVARIANT 6: nothing the peer said reaches the caller unbounded. The
		// session state is the only thing returned, and its message is capped.
		if len(state.Message) > 200 {
			t.Fatalf("a peer-supplied message of %d bytes reached the caller", len(state.Message))
		}
		for _, r := range state.Message {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("a control character reached the caller in %q", state.Message)
			}
		}

		// Reset for the next iteration: the server answers logout with the
		// same fuzzed body, which Logout must survive, and which must always
		// leave the client with no session.
		_ = c.Logout(t.Context())
		if c.SessionActive() {
			t.Fatal("a session survived Logout")
		}
	})
}
