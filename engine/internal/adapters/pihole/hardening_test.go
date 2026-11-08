// SPDX-License-Identifier: AGPL-3.0-only

// Tests added by the Phase 2 readiness review. Each one below either pins a
// property the earlier suite asserted nowhere, or is the failing case that
// demonstrated a defect before it was fixed. Where a case is the latter, the
// finding is named in the doc comment so the test and the record cannot drift
// apart.
//
// None of these contacts a real appliance: every case runs against a local
// HTTPS server with a per-run throwaway CA and a synthetic credential.

package pihole_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/adapters/pihole"
	"github.com/dubyfls/Pinga53/engine/internal/audit"
	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// --- FINDING-72: trailing content after the JSON value -----------------------
//
// encoding/json's Decoder reads ONE value and stops. A peer that answers with
// `{...}{...}` therefore has its first document accepted and its second
// silently discarded, with no diagnostic anywhere. This repository has already
// ruled that shape a defect once — internal/sourceregistry/strictjson.go
// refuses it for the registry, for the reason that "there was more here and it
// was ignored" is not an acceptable outcome for a document of record. A
// Pi-hole response that becomes step D's operator evidence is a document of
// record by the same argument, and the client did not apply the same rule.
func TestTrailingContentAfterTheResponseIsRefused(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One complete, valid session envelope, followed by a second document.
		writeJSON(w, http.StatusOK, loginOKBody()+`{"session":{"valid":false,"sid":null}}`)
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Login(context.Background(), config.NewSecretString(testPassword))
	if err == nil {
		t.Fatal("a response with a second JSON document after the first was accepted")
	}
	if c.SessionActive() {
		t.Error("a session was established from an ambiguous response")
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Error("the credential reached the error")
	}
}

// The same rule on the read endpoint, because the fix has to be in the shared
// decode path rather than at one call site.
func TestTrailingContentOnTheReadEndpointIsRefused(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSON(w, http.StatusOK, loginOKBody())
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, versionOKBody()+"\n[]")
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Logout(context.Background()) }()
	if _, err := c.Version(context.Background()); err == nil {
		t.Fatal("a version response with trailing content was accepted")
	}
}

// --- FINDING-73: duplicate keys ----------------------------------------------
//
// encoding/json accepts an object that names a key twice and keeps the LAST
// occurrence. That is not a parse error, it is a silent choice between two
// readings of the same bytes. An operator reading step D's captured transcript
// sees the first; the program acted on the second. strictjson.go refuses this
// for the registry on exactly that reasoning; the client did not.
func TestDuplicateKeysInAResponseAreRefused(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			"duplicate sid inside the session object",
			`{"session":{"valid":true,"totp":false,"sid":"` + sessionSID +
				`","sid":"` + sessionSID + `-second","csrf":null,"validity":1800},"took":0.1}`,
		},
		{
			"duplicate session object at the top level",
			`{"session":{"valid":false,"sid":null},"session":{"valid":true,"sid":"` +
				sessionSID + `","validity":1800},"took":0.1}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, tc.body)
			}))
			c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err == nil {
				t.Fatal("an ambiguous response was resolved instead of refused")
			}
			if c.SessionActive() {
				t.Error("a session was established from an ambiguous response")
			}
		})
	}
}

// A response whose shape is exactly as documented must still decode. Without
// this, the two cases above could be satisfied by a decoder that refuses
// everything.
func TestAWellFormedResponseStillDecodes(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSON(w, http.StatusOK, loginOKBody())
			return
		}
		writeJSON(w, http.StatusOK, versionOKBody())
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err != nil {
		t.Fatalf("a documented response was refused: %v", err)
	}
	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("a documented version response was refused: %v", err)
	}
	if v.Core.LocalVersion == "" {
		t.Error("the version response decoded to nothing")
	}
}

// Pi-hole may add fields in a future release, and a client that refused them
// would break on an appliance upgrade rather than on a defect. Strict decoding
// must therefore refuse ambiguity WITHOUT refusing extension; this pins the
// distinction so a later tightening cannot quietly take unknown fields with it.
func TestAnUnknownFieldIsNotTreatedAsAmbiguity(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK,
			`{"session":{"valid":true,"totp":false,"sid":"`+sessionSID+
				`","csrf":null,"validity":1800,"future_field":{"a":[1,2]}},"took":0.1,"also_new":"x"}`)
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err != nil {
		t.Fatalf("an unknown field was treated as a defect: %v", err)
	}
}

// --- Destination confinement: the environment proxy ---------------------------
//
// An inherited HTTPS_PROXY would hand the connection — and the session id
// header on it — to whatever the environment names. The transport sets
// Proxy: nil deliberately; nothing asserted it, so nothing would have caught a
// later change to http.ProxyFromEnvironment.
func TestAnEnvironmentProxyCannotReceiveTheRequest(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, loginOKBody())
	}))
	// A closed port. If the transport consulted the environment, the dial
	// would go here and fail; the DialContext guard would also refuse it.
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"} {
		t.Setenv(k, "http://127.0.0.1:1")
	}
	t.Setenv("NO_PROXY", "")
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err != nil {
		t.Fatalf("the request did not reach the configured origin: %v", err)
	}
	got := f.recorded()
	if len(got) != 1 || got[0].Path != "/api/auth" {
		t.Fatalf("the configured origin did not receive exactly the one request: %+v", got)
	}
}

// The behavioural case above cannot distinguish "no proxy" from "a proxy that
// happened to be bypassed", so the decision is also asserted in the source.
func TestTheProxyDecisionIsExplicitInTheSource(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "ProxyFromEnvironment") {
		t.Error("the transport consults the environment for a proxy")
	}
	if !strings.Contains(string(src), "Proxy: nil") {
		t.Error("the transport does not state its proxy decision explicitly")
	}
}

// --- Destination confinement: a cross-host redirect ---------------------------
//
// TestCrossOriginRedirectIsRefused establishes that the client returns an
// error. It does not establish that the OTHER host received nothing, which is
// the property that matters when the redirected request is the one carrying
// the credential.
func TestACrossHostRedirectDeliversNothingToTheOtherHost(t *testing.T) {
	ca := newTestCA(t)
	other := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, loginOKBody())
	}), testHost, "elsewhere.invalid")
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/auth", http.StatusTemporaryRedirect)
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Login(context.Background(), config.NewSecretString(testPassword))
	if err == nil {
		t.Fatal("a cross-host redirect was followed")
	}
	if !errors.Is(err, pihole.ErrCrossOriginRedirect) && !errors.Is(err, pihole.ErrUnexpectedDial) {
		t.Errorf("refused for an unexpected reason: %v", err)
	}
	if got := other.recorded(); len(got) != 0 {
		t.Errorf("the other host received %d request(s): %+v", len(got), got)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Error("the credential reached the error")
	}
}

// --- Time bounds: teardown after the operation deadline has already expired ---
//
// Logout deliberately runs under a context detached from the caller's, so a
// cancelled or timed-out operation still gets a real opportunity to destroy
// its session. That is a deliberate exception to "one deadline for the whole
// operation", and the thing that makes it safe rather than unbounded is that
// the detached context carries LogoutTimeout. Nothing asserted the bound.
func TestTeardownIsBoundedEvenWhenTheOperationDeadlineHasExpired(t *testing.T) {
	ca := newTestCA(t)
	release := make(chan struct{})
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeJSON(w, http.StatusOK, loginOKBody())
		case http.MethodDelete:
			// Never answers. The teardown must give up on its own bound.
			<-release
		default:
			writeJSON(w, http.StatusOK, versionOKBody())
		}
	}))
	// Released BEFORE the server is closed: httptest.Server.Close waits for
	// outstanding handlers, and cleanups run last-registered-first.
	t.Cleanup(func() { close(release) })
	cfg := configFor(t, f, ca.path)
	cfg.Pihole.LogoutTimeout = config.Duration(250 * time.Millisecond)
	cfg.Pihole.RequestTimeout = config.Duration(250 * time.Millisecond)
	c, err := pihole.New(cfg, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	// An already-expired caller context: the strongest form of "the total
	// deadline is gone" the teardown can be asked to survive.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = c.Logout(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("a logout that was never answered reported success")
	}
	if c.SessionTeardown() != pihole.TeardownFailed {
		t.Errorf("teardown outcome = %v, want failed", c.SessionTeardown())
	}
	if c.SessionActive() {
		t.Error("the session id was retained after a failed teardown")
	}
	// Generous: the assertion is that it is BOUNDED, not that it is fast.
	if elapsed > 5*time.Second {
		t.Errorf("teardown took %v; it is not bounded by LogoutTimeout", elapsed)
	}
	// It must also have actually been attempted, rather than skipped because
	// the caller's context was already dead.
	var sawDelete bool
	for _, r := range f.recorded() {
		if r.Method == http.MethodDelete {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Error("no DELETE was attempted: a dead caller context suppressed the teardown entirely")
	}
}

// --- Session lifecycle: the claim must not be check-then-act ------------------
//
// WithSession refused a nested session by calling SessionActive and then
// Login, which is two separate acquisitions of the mutex with a gap between
// them. Two callers could both observe "no session", both authenticate, and
// the second would overwrite the first's session id — leaving a session that
// is valid on the appliance, occupies one of a finite number of seats, and
// that nothing holds an id for any more. That is precisely the leak the
// refusal exists to prevent.
func TestConcurrentWithSessionCallsCannotBothAuthenticate(t *testing.T) {
	// FINDING-78. This test used to create its race with `time.Sleep(50ms)` in
	// the handler and hope the competing callers arrived inside the window. A
	// sleep does not CREATE the condition under test, it only makes it likely;
	// on a loaded machine the window closes early and the test passes without
	// ever having tested anything. The condition is now constructed with
	// synchronisation: the first caller is held INSIDE its authentication
	// request, so it provably holds the claim while the competitors run.
	//
	// Timers appear below only as hang guards. None of them creates the
	// condition being tested; each turns a deadlock into a named failure.
	const guard = 10 * time.Second

	ca := newTestCA(t)
	firstAuthArrived := make(chan struct{})
	releaseFirstAuth := make(chan struct{})
	var authCount atomic.Int64

	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if authCount.Add(1) == 1 {
				close(firstAuthArrived)
				// Hold the first caller inside its authentication. Every
				// competing caller below runs while this one is here.
				select {
				case <-releaseFirstAuth:
				case <-time.After(guard):
				}
			}
			writeJSON(w, http.StatusOK, loginOKBody())
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, http.StatusOK, versionOKBody())
		}
	}))
	// Released BEFORE the server is closed: httptest.Server.Close waits for
	// outstanding handlers, and cleanups run last-registered-first.
	released := false
	t.Cleanup(func() {
		if !released {
			close(releaseFirstAuth)
		}
	})

	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	// --- the first caller, which will hold the claim ---------------------
	firstDone := make(chan error, 1)
	innerRan := make(chan struct{})
	go func() {
		firstDone <- c.WithSession(context.Background(), config.NewSecretString(testPassword),
			func(ctx context.Context) error {
				close(innerRan)
				return nil
			})
	}()

	select {
	case <-firstAuthArrived:
	case <-time.After(guard):
		t.Fatal("the first authentication never reached the server")
	}

	// The first caller is now blocked inside POST /api/auth. Under the fix it
	// took the claim BEFORE sending, so every competitor must be refused
	// without a request. Under the superseded check-then-act it had not yet
	// stored a session id, so competitors would sail past the check and block
	// in this same handler — which this test reports as a failure rather than
	// waiting for.
	const competitors = 8
	results := make(chan error, competitors)
	for range competitors {
		go func() {
			results <- c.WithSession(context.Background(), config.NewSecretString(testPassword),
				func(ctx context.Context) error { return nil })
		}()
	}
	for i := range competitors {
		select {
		case err := <-results:
			if !errors.Is(err, pihole.ErrSessionAlreadyActive) {
				t.Errorf("competitor %d: got %v, want ErrSessionAlreadyActive", i, err)
			}
		case <-time.After(guard):
			t.Fatalf("competitor %d never returned: it is blocked in its own authentication request, so the claim did not refuse it", i)
		}
	}

	// Exactly one authentication may have reached the server, and it is still
	// in flight. Asserted before the release, so a late competitor cannot be
	// counted as the first caller's own retry.
	if n := authCount.Load(); n != 1 {
		t.Errorf("%d authentications reached the server while one caller held the claim; exactly 1 may", n)
	}

	// --- release, and require the held operation to complete cleanly ------
	released = true
	close(releaseFirstAuth)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("the holding caller failed: %v", err)
		}
	case <-time.After(guard):
		t.Fatal("the holding caller never completed after its authentication was released")
	}
	select {
	case <-innerRan:
	default:
		t.Error("the holding caller's operation never ran")
	}

	if c.SessionActive() {
		t.Error("a session outlived every WithSession call")
	}
	if got := c.SessionTeardown(); got != pihole.TeardownAccepted {
		t.Errorf("teardown = %v, want accepted", got)
	}
	var logins, deletes int
	for _, r := range f.recorded() {
		switch r.Method {
		case http.MethodPost:
			logins++
		case http.MethodDelete:
			deletes++
		}
	}
	if logins != 1 {
		t.Errorf("%d authentications reached the server in total; exactly 1 may", logins)
	}
	if deletes != 1 {
		t.Errorf("%d session deletions reached the server; exactly 1 may", deletes)
	}
}

// --- Helpers used only by this file ------------------------------------------

// testPassword is generated per run rather than written as a literal, for the
// reason given over sessionSID in testserver_test.go: a credential-shaped
// literal is what the secret scanner exists to stop, and a fresh value cannot
// collide with something a log legitimately contains.
var testPassword = randomToken("password")

func testLogger(t testing.TB) *audit.Logger {
	t.Helper()
	var buf bytes.Buffer
	t.Cleanup(func() {
		if strings.Contains(buf.String(), testPassword) || strings.Contains(buf.String(), sessionSID) {
			t.Error("a credential reached the audit stream")
		}
	})
	return audit.New(&buf)
}

// versionOKBody is the documented version envelope, shared with
// versionHandler so the two cannot drift.
func versionOKBody() string {
	return `{"version":{
				"core":{"local":{"branch":"master","version":"v6.4.3","hash":"abc1234"},"remote":{"version":"v6.4.3","hash":"abc1234"}},
				"web":{"local":{"branch":"master","version":"v6.6","hash":"def5678"},"remote":{"version":"v6.6","hash":"def5678"}},
				"ftl":{"local":{"branch":"master","version":"v6.7","hash":"9999999","date":"2026-08-01"},"remote":{"version":"v6.7","hash":"9999999"}}
			},"took":0.002}`
}

// --- FINDING-77: the duplicate-key error reproduced the key ------------------
//
// The superseded error was:
//
//	fmt.Errorf("%w: the key %q appears twice in one object", ErrAmbiguousResponse, sanitizeMessage(key))
//
// and the comment above it argued that naming a key is safe because "a VALUE is
// never named". That reasoned about the wrong half of the pair. A JSON key is
// peer-authored, and by the time this decoder runs the peer has already
// received something worth echoing: during authentication it has the PASSWORD,
// and during an authenticated read it has the SESSION ID. Either can come back
// as a duplicated key name and land in the error verbatim.
//
// Nothing downstream removes it. Login scrubs only *APIError fields, and this
// is a plain wrapped error, so `errors.As` does not match and the scrub is
// skipped. The error then reaches stdout through `error: %v`.
//
// The fix omits the key entirely rather than sanitising it: no heuristic can
// distinguish a credential echoed as a key from a legitimate field name,
// because the peer chooses both.

func TestADuplicatedKeyNeverReachesTheErrorDuringAuthentication(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The peer has just received the password. It returns it as a
		// duplicated KEY name, which is entirely under its control.
		writeJSON(w, http.StatusOK,
			`{"session":{"valid":true,"`+testPassword+`":1,"`+testPassword+`":2,"sid":"x"},"took":0.1}`)
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Login(context.Background(), config.NewSecretString(testPassword))
	if err == nil {
		t.Fatal("an ambiguous response was accepted")
	}
	if !errors.Is(err, pihole.ErrAmbiguousResponse) {
		t.Errorf("classification lost: %v", err)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("the credential reached the error through a duplicated KEY name")
	}
	if c.SessionActive() {
		t.Error("a session was established from an ambiguous response")
	}
}

func TestADuplicatedKeyNeverReachesTheErrorDuringAnAuthenticatedRead(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeJSON(w, http.StatusOK, loginOKBody())
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			// The peer now holds the session id, having been sent it in the
			// X-FTL-SID header, and returns it as a duplicated key name.
			writeJSON(w, http.StatusOK,
				`{"version":{"`+sessionSID+`":1,"`+sessionSID+`":2}}`)
		}
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), config.NewSecretString(testPassword)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Logout(context.Background()) }()

	_, err = c.Version(context.Background())
	if err == nil {
		t.Fatal("an ambiguous response was accepted")
	}
	if !errors.Is(err, pihole.ErrAmbiguousResponse) {
		t.Errorf("classification lost: %v", err)
	}
	if strings.Contains(err.Error(), sessionSID) {
		t.Errorf("the session id reached the error through a duplicated KEY name")
	}
}

// PRE-FIX CONTROL. The superseded error shape is reconstructed exactly and
// applied to the same key, showing it exposes the value the cases above
// require to be absent. Without this the two tests prove only that the current
// error text happens not to contain the string.
func TestPreFixControlTheSupersededDuplicateKeyErrorExposedTheKey(t *testing.T) {
	// The superseded construction, verbatim from the commit it is replacing.
	superseded := fmt.Errorf("%w: the key %q appears twice in one object",
		pihole.ErrAmbiguousResponse, testPassword)
	if !strings.Contains(superseded.Error(), testPassword) {
		t.Fatal("PRE-FIX CONTROL: the superseded shape did not expose the key, so this control proves nothing")
	}
	t.Log("PRE-FIX CONTROL: the superseded error reproduced the peer-chosen key (the defect)")

	// And it is reachable: a plain wrapped error is NOT an *APIError, so
	// Login's scrub — which is `errors.As(err, &apiErr)` — never fires on it.
	var apiErr *pihole.APIError
	if errors.As(superseded, &apiErr) {
		t.Error("PRE-FIX CONTROL: the error matched *APIError, so Login's scrub would have applied and the leak would not reach a caller")
	}
}

// --- FINDING-79: teardown state survived into the next session attempt -------
//
// claimSession reserved the slot for a NEW operation but left c.teardown
// holding the previous operation's outcome. A Client that had completed one
// session cleanly, and then failed to authenticate for a second, reported
// TeardownAccepted — a true statement about an operation that had already
// finished, presented as the current one's result.
//
// It reaches an operator: reportTeardown prints "session logout ACCEPTED by
// Pi-hole" from exactly this value, and FINDING-75 has just made the failure
// path print it. So the stale value surfaces precisely where the accurate one
// was added.
//
// The reset belongs in the same critical section that takes the claim: a
// separate reset would reintroduce a window in which the slot is held and the
// outcome is the previous operation's.
func TestTeardownStateDoesNotSurviveIntoTheNextSessionAttempt(t *testing.T) {
	cases := []struct {
		name string
		// how the SECOND authentication fails, before any session exists
		second func(w http.ResponseWriter)
	}{
		{
			"rejected credential",
			func(w http.ResponseWriter) {
				writeJSON(w, http.StatusUnauthorized,
					`{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.1}`)
			},
		},
		{
			// The strict-decoding path added by FINDING-72/73: the response is
			// a 200 that cannot be resolved to one reading.
			"ambiguous authentication response",
			func(w http.ResponseWriter) {
				writeJSON(w, http.StatusOK, loginOKBody()+`{"session":{"valid":false}}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			var auths atomic.Int64
			f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPost:
					switch auths.Add(1) {
					case 1:
						writeJSON(w, http.StatusOK, loginOKBody())
					case 2:
						tc.second(w)
					default:
						writeJSON(w, http.StatusOK, loginOKBody())
					}
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default:
					writeJSON(w, http.StatusOK, versionOKBody())
				}
			}))
			c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
			if err != nil {
				t.Fatal(err)
			}

			// 1. One complete session, torn down cleanly.
			if err := c.WithSession(context.Background(), config.NewSecretString(testPassword),
				func(ctx context.Context) error { return nil }); err != nil {
				t.Fatalf("first session: %v", err)
			}
			if got := c.SessionTeardown(); got != pihole.TeardownAccepted {
				t.Fatalf("first session teardown = %v, want accepted", got)
			}

			// 2. A second attempt that fails BEFORE a session exists.
			err = c.WithSession(context.Background(), config.NewSecretString(testPassword),
				func(ctx context.Context) error {
					t.Error("the operation ran despite a failed authentication")
					return nil
				})
			if err == nil {
				t.Fatal("the second authentication was accepted")
			}
			if errors.Is(err, pihole.ErrSessionAlreadyActive) {
				t.Fatal("the claim from the first session was never released")
			}

			// 3. The reported outcome must be about THIS attempt, which never
			//    reached a teardown, not about the one before it.
			if got := c.SessionTeardown(); got != pihole.TeardownNotAttempted {
				t.Errorf("teardown = %v, want not attempted: the previous operation's outcome survived into an attempt that never established a session", got)
			}
			if c.SessionActive() {
				t.Error("a session is held after a failed authentication")
			}

			// 4. The slot is free, so a later valid operation still works.
			if err := c.WithSession(context.Background(), config.NewSecretString(testPassword),
				func(ctx context.Context) error { return nil }); err != nil {
				t.Errorf("a later valid operation was refused: %v", err)
			}
			if got := c.SessionTeardown(); got != pihole.TeardownAccepted {
				t.Errorf("third session teardown = %v, want accepted", got)
			}
		})
	}
}

// A refused claim must NOT reset the outcome: the refusal belongs to the
// caller that was turned away, and the holder's state is not theirs to clear.
func TestARefusedClaimDoesNotDisturbTheHolderSTeardownState(t *testing.T) {
	ca := newTestCA(t)
	f := newFakePihole(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeJSON(w, http.StatusOK, loginOKBody())
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, http.StatusOK, versionOKBody())
		}
	}))
	c, err := pihole.New(configFor(t, f, ca.path), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	// Inside the session, a nested attempt is refused. The outer session then
	// completes; its teardown must be recorded normally.
	err = c.WithSession(context.Background(), config.NewSecretString(testPassword),
		func(ctx context.Context) error {
			nested := c.WithSession(ctx, config.NewSecretString(testPassword),
				func(context.Context) error { return nil })
			if !errors.Is(nested, pihole.ErrSessionAlreadyActive) {
				t.Errorf("nested session: got %v, want ErrSessionAlreadyActive", nested)
			}
			return nil
		})
	if err != nil {
		t.Fatalf("outer session: %v", err)
	}
	if got := c.SessionTeardown(); got != pihole.TeardownAccepted {
		t.Errorf("teardown = %v, want accepted: a refused claim disturbed the holder's state", got)
	}
}
