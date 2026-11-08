// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// End-to-end tests: the real CLI, its real configuration loader, its real
// client, against a local HTTPS server that impersonates the parts of the
// Pi-hole API Phase 1 uses.
//
// WHAT THESE ESTABLISH AND WHAT THEY DO NOT
//
// They establish that the command surface behaves as documented: which network
// operations happen and in what order, what the exit status means, that a
// configuration error is reported before anything is authenticated, and that
// no credential reaches stdout, stderr or the audit log.
//
// They establish NOTHING about compatibility with a real Pi-hole. The server
// below is a fake written from docs/PIHOLE_API_CONTRACT.md; if the appliance
// diverges from that document, these tests pass and the deployment fails. That
// evidence needs a disposable real instance and is Phase 2 work-order item 1.

const e2eHost = "pi.hole"

// e2eCA is a throwaway certificate authority, generated per run. No trust
// material is committed, so nothing here can be reused against anything.
type e2eCA struct {
	path string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newE2ECA(t *testing.T, dir string) *e2eCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ScamWall E2E Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pihole-ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &e2eCA{path: path, cert: cert, key: key}
}

func (ca *e2eCA) leaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: e2eHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{e2eHost},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// e2eEnv is a complete, disposable deployment: a CA, a password file, a
// configuration, and a server.
type e2eEnv struct {
	dir        string
	ca         *e2eCA
	srv        *httptest.Server
	configPath string
	password   string
	sid        string

	mu       sync.Mutex
	requests []string
	// authStatus, when non-zero, is what POST /api/auth answers with.
	authStatus int
	// deleteStatus, when non-zero, is what DELETE /api/auth answers with. It
	// exists so a FAILED session teardown can be exercised: that path used to
	// print a success line and exit 0.
	deleteStatus int
	// versionFailures is how many times GET /api/info/version answers 503
	// before succeeding. It exists to pin the ACTUAL maximum request
	// behaviour of a status run, which is not three requests.
	versionFailures int
	// echoCredentialAsDuplicateKey makes the server return the value it has
	// just been given back as a DUPLICATED JSON KEY: the password on
	// POST /api/auth, the session id on GET /api/info/version. Both are
	// entirely peer-chosen, and both are what FINDING-77 was about.
	echoCredentialAsDuplicateKey bool
	// redirectLogoutTo, when non-empty, makes DELETE /api/auth answer 307 with
	// this Location. It exists for SW-P2-11: the Pi-hole API accepts a session
	// id as a `sid` QUERY parameter, the client refuses a redirect carrying a
	// query for exactly that reason, and the *url.Error describing the refusal
	// quotes the URL in full. That is the shortest real path from a credential
	// in a URL to a log line.
	redirectLogoutTo string
	// denyExact is the body GET /api/domains/deny/exact answers with. Set by
	// the shadow tests; an empty appliance otherwise.
	denyExact string
	// allowExact and allowRegex are the bodies the household's own allow
	// lists answer with. ORDER 8, C-18. Empty means the household has allowed
	// nothing, which is a different fact from the lists not being read --
	// shadow.AllowNotRead covers that one and is exercised by the unit tests.
	allowExact string
	allowRegex string
}

func (e *e2eEnv) record(method, path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests = append(e.requests, method+" "+path)
}

// sequence returns the exact ordered list of API calls the CLI made.
func (e *e2eEnv) sequence() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.requests))
	copy(out, e.requests)
	return out
}

func randomE2EToken(kind string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("test setup: no entropy: " + err.Error())
	}
	return "scamwall-e2e-" + kind + "-" + hex.EncodeToString(b)
}

// newE2EEnv builds the environment. mutate, if given, adjusts the
// configuration before it is written.
func newE2EEnv(t *testing.T, mutate func(*config.Config)) *e2eEnv {
	t.Helper()
	dir := t.TempDir()
	e := &e2eEnv{
		dir:      dir,
		ca:       newE2ECA(t, dir),
		password: randomE2EToken("password"),
		sid:      randomE2EToken("sid"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.record(r.Method, r.URL.Path)
		writeJSON := func(status int, body string) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth":
			if e.authStatus != 0 {
				writeJSON(e.authStatus, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}`)
				return
			}
			if e.echoCredentialAsDuplicateKey {
				// The peer has the password; it returns it as a key name twice.
				writeJSON(200, `{"session":{"valid":true,"`+e.password+`":1,"`+
					e.password+`":2,"sid":"`+e.sid+`"},"took":0.001}`)
				return
			}
			writeJSON(200, `{"session":{"valid":true,"totp":false,"sid":"`+e.sid+
				`","csrf":"`+randomE2EToken("csrf")+`","validity":1800,"message":null},"took":0.001}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/auth":
			writeJSON(http.StatusUnauthorized,
				`{"session":{"valid":false,"totp":false,"sid":null,"validity":-1,"message":"no SID provided"},"took":0.001}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/auth":
			if e.redirectLogoutTo != "" {
				w.Header().Set("Location", e.redirectLogoutTo)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			if e.deleteStatus != 0 {
				writeJSON(e.deleteStatus, `{"error":{"key":"server_error","message":"Internal Error","hint":null},"took":0.001}`)
				return
			}
			if r.Header.Get("X-FTL-SID") != e.sid {
				writeJSON(http.StatusUnauthorized, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}`)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/domains/deny/exact":
			if r.Header.Get("X-FTL-SID") != e.sid {
				writeJSON(http.StatusUnauthorized, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}`)
				return
			}
			body := e.denyExact
			if body == "" {
				body = `{"domains":[],"took":0.001}`
			}
			writeJSON(200, body)
		case r.Method == http.MethodGet && r.URL.Path == "/api/domains/allow/exact":
			if r.Header.Get("X-FTL-SID") != e.sid {
				writeJSON(http.StatusUnauthorized, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}`)
				return
			}
			body := e.allowExact
			if body == "" {
				body = `{"domains":[],"took":0.001}`
			}
			writeJSON(200, body)
		case r.Method == http.MethodGet && r.URL.Path == "/api/domains/allow/regex":
			if r.Header.Get("X-FTL-SID") != e.sid {
				writeJSON(http.StatusUnauthorized, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}`)
				return
			}
			body := e.allowRegex
			if body == "" {
				body = `{"domains":[],"took":0.001}`
			}
			writeJSON(200, body)
		case r.Method == http.MethodGet && r.URL.Path == "/api/info/version":
			if r.Header.Get("X-FTL-SID") != e.sid {
				writeJSON(http.StatusUnauthorized, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}`)
				return
			}
			e.mu.Lock()
			retryThis := e.versionFailures > 0
			if retryThis {
				e.versionFailures--
			}
			e.mu.Unlock()
			if retryThis {
				writeJSON(http.StatusServiceUnavailable,
					`{"error":{"key":"unavailable","message":"Temporarily unavailable","hint":null},"took":0.001}`)
				return
			}
			writeJSON(200, `{"version":{`+
				`"core":{"local":{"branch":"master","version":"v6.0.4","hash":"abc","date":null},"remote":{"version":"v6.0.4","hash":"abc"}},`+
				`"web":{"local":{"branch":"master","version":"v6.0.1","hash":"def","date":null},"remote":{"version":"v6.0.1","hash":"def"}},`+
				`"ftl":{"local":{"branch":"master","version":"v6.0.2","hash":"ghi","date":"2026-01-01"},"remote":{"version":"v6.0.2","hash":"ghi"}}},`+
				`"took":0.001}`)
		default:
			writeJSON(http.StatusNotFound, `{"error":{"key":"not_found","message":"Not Found","hint":null},"took":0.001}`)
		}
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{e.ca.leaf(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.srv = srv

	secretPath := filepath.Join(dir, "pihole_app_password")
	if err := os.WriteFile(secretPath, []byte(e.password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	// The name stays pi.hole so hostname verification is exercised exactly as
	// it is in production; only the dialled address is overridden, which is
	// the same mechanism the real deployment uses.
	cfg.Pihole.Host = e2eHost
	cfg.Pihole.Port = port
	cfg.Pihole.AddressOverride = srv.Listener.Addr().String()
	cfg.Pihole.CAPath = e.ca.path
	cfg.Pihole.SecretPath = secretPath
	cfg.Pihole.RequestTimeout = config.Duration(2 * time.Second)
	cfg.Pihole.TotalTimeout = config.Duration(5 * time.Second)
	cfg.Pihole.ConnectTimeout = config.Duration(2 * time.Second)
	cfg.Pihole.LogoutTimeout = config.Duration(2 * time.Second)
	cfg.Feed.Path = filepath.Join("..", "..", "testdata", "feed.json")
	cfg.Feed.TrustKeyID = "scamwall-test-key-1"
	cfg.Feed.TrustPublicKey = "ZZdzt8vw2UCXeoT95fcT9Fh0U80M7L0I1L/io4AeR7A="
	if mutate != nil {
		mutate(&cfg)
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(e.configPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

// assertNoCredentials fails if any captured stream mentions the password or
// the session id. Both are generated per run, so a match cannot be a
// coincidence.
func (e *e2eEnv) assertNoCredentials(t *testing.T, streams ...string) {
	t.Helper()
	for i, s := range streams {
		if strings.Contains(s, e.password) {
			t.Errorf("stream %d contains the application password", i)
		}
		if strings.Contains(s, e.sid) {
			t.Errorf("stream %d contains the session id", i)
		}
	}
}

// --- The approved read-only workflow ----------------------------------------

func TestStatusPerformsExactlyTheApprovedSequence(t *testing.T) {
	e := newE2EEnv(t, nil)
	code, stdout, stderr := capture(t, "status", "-config", e.configPath)

	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	want := []string{
		"POST /api/auth",
		"GET /api/info/version",
		"DELETE /api/auth",
	}
	got := e.sequence()
	if len(got) != len(want) {
		t.Fatalf("network sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("network sequence = %v, want %v", got, want)
		}
	}
	// The output must describe what actually happened.
	for _, s := range []string{"v6.0.4", "v6.0.1", "v6.0.2", "session logout ACCEPTED"} {
		if !strings.Contains(stdout, s) {
			t.Errorf("stdout does not report %q:\n%s", s, stdout)
		}
	}
	e.assertNoCredentials(t, stdout, stderr)
}

func TestSyncDryRunReportsThePlanAndSubmitsNothing(t *testing.T) {
	e := newE2EEnv(t, nil)
	code, stdout, stderr := capture(t, "sync", "--dry-run", "-config", e.configPath)

	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	got := e.sequence()
	for _, req := range got {
		if !strings.HasPrefix(req, "POST /api/auth") &&
			!strings.HasPrefix(req, "GET /api/info/version") &&
			!strings.HasPrefix(req, "DELETE /api/auth") {
			t.Fatalf("sync issued an operation outside the approved set: %q", req)
		}
	}
	if len(got) != 3 {
		t.Fatalf("network sequence = %v, want exactly three calls", got)
	}
	for _, s := range []string{"DRY RUN", "No blocking change was made", "proposed plan"} {
		if !strings.Contains(stdout, s) {
			t.Errorf("stdout does not state %q:\n%s", s, stdout)
		}
	}
	e.assertNoCredentials(t, stdout, stderr)
}

func TestDoctorProbesWithoutSendingACredential(t *testing.T) {
	e := newE2EEnv(t, nil)
	code, stdout, stderr := capture(t, "doctor", "-config", e.configPath)

	// The probe is answered 401, which doctor reads as "reachable, needs a
	// password" — a successful probe, so every check passes.
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	got := e.sequence()
	if len(got) != 1 || got[0] != "GET /api/auth" {
		t.Fatalf("doctor's network sequence = %v, want exactly [GET /api/auth]", got)
	}
	if !strings.Contains(stdout, "0 failed") {
		t.Errorf("doctor did not pass:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// --- Failure paths ----------------------------------------------------------

func TestInvalidConfigurationFailsBeforeAnythingIsAuthenticated(t *testing.T) {
	cases := map[string]func(*config.Config){
		"a port outside the legal range": func(c *config.Config) { c.Pihole.Port = 0 },
		"plaintext requested":            func(c *config.Config) { c.Pihole.Host = "" },
		"enforcement requested":          func(c *config.Config) { c.Runtime.DryRun = false },
		"a request timeout exceeding the total": func(c *config.Config) {
			c.Pihole.RequestTimeout = config.Duration(time.Hour)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newE2EEnv(t, mutate)
			code, stdout, stderr := capture(t, "status", "-config", e.configPath)
			if code == exitOK {
				t.Fatalf("an invalid configuration was accepted\nstdout: %s", stdout)
			}
			if seq := e.sequence(); len(seq) != 0 {
				t.Fatalf("the network was contacted despite an invalid configuration: %v", seq)
			}
			if !strings.Contains(stdout, "configuration") {
				t.Errorf("the failure does not name the configuration:\n%s", stdout)
			}
			e.assertNoCredentials(t, stdout, stderr)
		})
	}
}

func TestAMissingCredentialFileFailsBeforeAnyRequest(t *testing.T) {
	e := newE2EEnv(t, func(c *config.Config) {
		c.Pihole.SecretPath = filepath.Join(t.TempDir(), "absent")
	})
	code, stdout, stderr := capture(t, "status", "-config", e.configPath)
	if code == exitOK {
		t.Fatal("a missing credential was accepted")
	}
	if seq := e.sequence(); len(seq) != 0 {
		t.Fatalf("the network was contacted with no credential available: %v", seq)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

func TestFailedAuthenticationReturnsPromptlyAndLeavesNoSession(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.authStatus = http.StatusUnauthorized

	start := time.Now()
	code, stdout, stderr := capture(t, "status", "-config", e.configPath)
	elapsed := time.Since(start)

	if code != exitFailure {
		t.Fatalf("exit %d, want %d\nstdout: %s", code, exitFailure, stdout)
	}
	// Exactly one attempt: a rejected credential must not become a login storm
	// against a service that rate-limits authentication.
	got := e.sequence()
	if len(got) != 1 || got[0] != "POST /api/auth" {
		t.Fatalf("network sequence = %v, want exactly one POST /api/auth", got)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("a rejected credential took %v to report", elapsed)
	}
	if !strings.Contains(stdout, "401") {
		t.Errorf("the failure does not report the status:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

func TestEnforcementIsRefusedEvenWithAReachableServer(t *testing.T) {
	// The refusal must not depend on the network being unavailable.
	e := newE2EEnv(t, nil)
	code, stdout, stderr := capture(t, "sync", "--dry-run=false", "-config", e.configPath)

	if code != exitUsage {
		t.Fatalf("exit %d, want %d\nstdout: %s", code, exitUsage, stdout)
	}
	if seq := e.sequence(); len(seq) != 0 {
		t.Fatalf("an enforcement request contacted the network: %v", seq)
	}
	if !strings.Contains(stdout, "refusing to run") {
		t.Errorf("the refusal is not stated plainly:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

func TestAnUnreachableServerFailsWithoutClaimingSuccess(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.srv.Close()

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)
	if code != exitFailure {
		t.Fatalf("exit %d, want %d\nstdout: %s", code, exitFailure, stdout)
	}
	if strings.Contains(stdout, "ACCEPTED") || strings.Contains(stdout, "ALREADY ABSENT") {
		t.Errorf("the output claims a session was torn down:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// --- Truthful session teardown ----------------------------------------------

// TestAFailedLogoutIsNotReportedAsSuccess covers the defect directly.
//
// WithSession performs the logout in a deferred call and deliberately does not
// let a logout failure mask the caller's error, so a run whose DELETE failed
// still returned nil from WithSession. `status` printed "session closed" and
// exited 0 on exactly that path: a success line for a cleanup it had never
// observed succeed.
func TestAFailedLogoutIsNotReportedAsSuccess(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.deleteStatus = http.StatusInternalServerError

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)

	if code == exitOK {
		t.Errorf("exit %d: a failed session teardown was reported as success\nstdout: %s", code, stdout)
	}
	if strings.Contains(stdout, "ACCEPTED") {
		t.Errorf("stdout claims the logout was accepted:\n%s", stdout)
	}
	if !strings.Contains(stdout, "session logout FAILED") {
		t.Errorf("stdout does not state that the logout failed:\n%s", stdout)
	}
	// The version read DID succeed, and the output still reports it. The
	// failure is about cleanup, and saying so precisely is the point.
	if !strings.Contains(stdout, "v6.0.4") {
		t.Errorf("stdout dropped the result the command actually obtained:\n%s", stdout)
	}
	// DELETE was attempted, which is the distinction between "cleanup not
	// attempted" and "cleanup attempted and refused".
	if got := e.sequence(); len(got) != 3 || got[2] != "DELETE /api/auth" {
		t.Errorf("network sequence = %v, want the DELETE to have been attempted", got)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// TestALogoutAnswered404IsTheDesiredEndState distinguishes "already gone" from
// both "accepted" and "failed".
func TestALogoutAnswered404IsTheDesiredEndState(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.deleteStatus = http.StatusNotFound

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)

	if code != exitOK {
		t.Errorf("exit %d: an already-absent session is the desired end state\nstdout: %s", code, stdout)
	}
	if !strings.Contains(stdout, "ALREADY ABSENT") {
		t.Errorf("stdout does not distinguish an already-absent session:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// TestStatusIsNotLimitedToThreeRequests pins the ACTUAL maximum request
// behaviour of a status run.
//
// The operator procedure described `status` as "exactly three requests". It is
// three only when nothing is retried: GET /api/info/version is in the
// permitted set as RETRYABLE, so a Pi-hole answering 503 produces more. The
// bound that is real is the permitted SET, not a request count.
func TestStatusIsNotLimitedToThreeRequests(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.versionFailures = 2 // exhausts MaxRetries=2, then succeeds

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	got := e.sequence()
	want := []string{
		"POST /api/auth",
		"GET /api/info/version",
		"GET /api/info/version",
		"GET /api/info/version",
		"DELETE /api/auth",
	}
	if len(got) != len(want) {
		t.Fatalf("network sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("network sequence = %v, want %v", got, want)
		}
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// --- The credential-free probe ----------------------------------------------

// TestDoctorNoCredentialDoesNotOpenTheSecret is the proof the operator
// procedure's step B needs.
//
// The control is the second half: the SAME configuration, without the flag,
// must fail on the secret. If it did not, this test would pass for a doctor
// that reads the credential anyway.
func TestDoctorNoCredentialDoesNotOpenTheSecret(t *testing.T) {
	e := newE2EEnv(t, func(c *config.Config) {
		// A path that cannot be opened. Anything that reads it fails loudly.
		c.Pihole.SecretPath = filepath.Join(t.TempDir(), "absent", "pihole_app_password")
	})

	code, stdout, stderr := capture(t, "doctor", "--no-credential", "-config", e.configPath)
	if code != exitOK {
		t.Fatalf("doctor --no-credential exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "SKIP") || !strings.Contains(stdout, "NOT READ") {
		t.Errorf("the skipped credential check is not reported as skipped:\n%s", stdout)
	}
	if strings.Contains(stdout, "readable") {
		t.Errorf("stdout claims the credential is readable:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 skipped") {
		t.Errorf("the summary does not count the skipped check:\n%s", stdout)
	}
	// It is still a real connectivity probe: the unauthenticated GET happened.
	if got := e.sequence(); len(got) != 1 || got[0] != "GET /api/auth" {
		t.Errorf("network sequence = %v, want exactly [GET /api/auth]", got)
	}

	// Control: without the flag, the same configuration must fail.
	code, stdout, _ = capture(t, "doctor", "-config", e.configPath)
	if code == exitOK {
		t.Fatalf("control: doctor without --no-credential passed on an unreadable secret:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FAIL") || !strings.Contains(stdout, "application password") {
		t.Errorf("control: the failure is not attributed to the credential:\n%s", stdout)
	}
}

// TestDoctorOfflineStillReadsTheSecret records the fact the operator procedure
// depends on for step C, and which its step B contradicted.
//
// `doctor --offline` is not a credential-free command. It skips the network
// and reads the password; that combination is exactly what a secret-read test
// under a disabled network needs, and exactly what a connectivity probe
// claiming to read no password must not use.
func TestDoctorOfflineStillReadsTheSecret(t *testing.T) {
	e := newE2EEnv(t, func(c *config.Config) {
		c.Pihole.SecretPath = filepath.Join(t.TempDir(), "absent", "pihole_app_password")
	})

	code, stdout, stderr := capture(t, "doctor", "--offline", "-config", e.configPath)
	if code == exitOK {
		t.Fatalf("doctor --offline passed with an unreadable secret, so it did not read it:\n%s", stdout)
	}
	if !strings.Contains(stdout, "application password") {
		t.Errorf("stdout does not report the credential check:\n%s", stdout)
	}
	if n := len(e.sequence()); n != 0 {
		t.Errorf("doctor --offline made %d request(s); it must touch no network", n)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// TestDoctorNeverReportsTheCredentialLength closes the disclosure the
// procedure relied on. A length is a fact about a credential, and it diagnosed
// nothing: LoadSecretFile already refuses an empty one.
func TestDoctorNeverReportsTheCredentialLength(t *testing.T) {
	e := newE2EEnv(t, nil)
	code, stdout, stderr := capture(t, "doctor", "--offline", "-config", e.configPath)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "application password") {
		t.Fatalf("the credential check did not run:\n%s", stdout)
	}
	if strings.Contains(stdout, "bytes") {
		t.Errorf("stdout reports a credential length:\n%s", stdout)
	}

	// The bare decimal length must not appear either — a length printed with
	// no unit at all is still a length. But searching the WHOLE of stdout for
	// it is wrong, and was FINDING-60: stdout legitimately carries this test's
	// own t.TempDir() paths, Go embeds a ten-digit random component in those,
	// and the two-digit length collides with unrelated digits in it about 8%
	// of the time. Measured on this tree before the fix, this test failed 2
	// runs in 25. That is a false positive rather than a disclosure — no
	// length was printed in the failing runs — and a check that fails one run
	// in twelve for a reason unrelated to its property stops being read, which
	// is worse than not having it.
	//
	// So the ONE source of unrelated random digits is masked first: the
	// directory this test created, whose text the test knows verbatim. The
	// bare-integer search then runs over everything the program itself
	// composed. That is deliberately stricter than matching "<n> bytes"-shaped
	// phrases would be — it still catches a length emitted with no unit, in
	// any wording — and it narrows the haystack rather than the property.
	if e.dir == "" {
		t.Fatal("the environment has no directory recorded; masking it would blank stdout and hide a real disclosure")
	}
	composed := strings.ReplaceAll(stdout, e.dir, "<tmpdir>")
	if strings.Contains(composed, strconv.Itoa(len(e.password))) {
		t.Errorf("stdout contains the credential's length:\n%s", stdout)
	}

	// A guard on the guard. The length is 54 by construction — a fixed prefix
	// plus 32 hex characters — and the check above is only meaningful while it
	// stays long enough not to collide with the digits the program legitimately
	// prints, such as the "N checks, N failed, N skipped" summary. A future
	// change that shortened the token to a single digit would make this test
	// pass or fail on the check counts instead of on the credential, silently.
	if n := len(e.password); n < 10 {
		t.Fatalf("the e2e password is %d characters: a length below 10 collides with the counts in the summary line, which makes the check above unreliable rather than strict", n)
	}

	e.assertNoCredentials(t, stdout, stderr)
}

// TestCredentialsNeverReachAnyStream sweeps every command in one place, so a
// new command added without thought about disclosure fails here.
func TestCredentialsNeverReachAnyStream(t *testing.T) {
	commands := [][]string{
		{"status"},
		{"sync", "--dry-run"},
		{"doctor"},
		{"validate-feed"},
		{"plan"},
		{"version"},
	}
	for _, cmd := range commands {
		t.Run(strings.Join(cmd, " "), func(t *testing.T) {
			e := newE2EEnv(t, nil)
			args := append(append([]string{}, cmd...), "-config", e.configPath)
			_, stdout, stderr := capture(t, args...)
			e.assertNoCredentials(t, stdout, stderr)
		})
	}
}

// --- Phase 2 readiness review -------------------------------------------------

// FINDING-75. When the operation itself failed, `status` and `sync` printed the
// error and returned, and never reached reportTeardown — so a run whose read
// failed AND whose session teardown also failed told the operator only about
// the read. The exit status was 1 either way, which is why this was invisible:
// the verdict was right and the reason was incomplete. An operator following
// §6.5 step D needs to know a session may still be live on the appliance, and
// that is exactly the case where nothing said so.
func TestAFailedReadStillReportsWhatBecameOfTheSession(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.versionFailures = 99 // never succeeds; exhausts the retries
	e.deleteStatus = http.StatusInternalServerError

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)

	if code == exitOK {
		t.Errorf("exit %d: a failed read reported success", code)
	}
	// The primary failure is not hidden by the cleanup report.
	if !strings.Contains(stdout, "error:") {
		t.Errorf("stdout does not report the primary failure:\n%s", stdout)
	}
	// And the cleanup outcome is not hidden by the primary failure.
	if !strings.Contains(stdout, "session logout FAILED") {
		t.Errorf("stdout does not say what became of the session:\n%s", stdout)
	}
	if !strings.Contains(stdout, "may remain valid on the appliance") {
		t.Errorf("stdout does not state the consequence for the appliance:\n%s", stdout)
	}
	var sawDelete bool
	for _, r := range e.sequence() {
		if r == "DELETE /api/auth" {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Error("no teardown was attempted after the read failed")
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// The same property for the other command that opens a session.
func TestSyncDryRunAlsoReportsWhatBecameOfTheSessionOnFailure(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.versionFailures = 99
	e.deleteStatus = http.StatusInternalServerError

	code, stdout, stderr := capture(t, "sync", "--dry-run", "-config", e.configPath)

	if code == exitOK {
		t.Errorf("exit %d: a failed read reported success", code)
	}
	if !strings.Contains(stdout, "session logout FAILED") {
		t.Errorf("stdout does not say what became of the session:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// A read that fails while the teardown SUCCEEDS must still fail, and must say
// so without implying the command as a whole succeeded. Without this, the fix
// above could be satisfied by printing a reassuring cleanup line.
func TestAFailedReadWithACleanTeardownStillFails(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.versionFailures = 99

	code, stdout, _ := capture(t, "status", "-config", e.configPath)

	if code == exitOK {
		t.Errorf("exit %d: a failed read reported success\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "error:") {
		t.Errorf("stdout does not report the primary failure:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ACCEPTED") {
		t.Errorf("stdout does not record the successful teardown:\n%s", stdout)
	}
}

// FINDING-76. `doctor --offline` is the command the operator procedure relies
// on to be provably network-free, and it built a full HTTP client — Client,
// transport, dialler and redirect policy — before deciding not to use any of
// it. No socket was opened, so the weaker claim held; the stated requirement
// is that nothing capable of opening one is constructed, and the report said
// nothing either way.
//
// The CA still has to be validated offline, because that is a genuine offline
// check, and validating it still constructs a tls.Config — that construction
// IS the validation. FINDING-80 corrected an earlier version of this comment
// that listed the TLS configuration among what --offline avoids. What it
// avoids is the Client, the transport, the dialler and the redirect policy:
// the things that can reach the network. A tls.Config cannot.
//
// What this case can observe is the socket, not the constructor: it asserts
// the fake server recorded ZERO requests, and that the transcript states which
// path was taken. The transcript line is execution-path evidence, not a
// boundary — Docker's `--network none` is the boundary, and it is step C's
// job, not this test's.
func TestDoctorOfflineBuildsNoNetworkClient(t *testing.T) {
	e := newE2EEnv(t, nil)

	code, stdout, stderr := capture(t, "doctor", "--offline", "-config", e.configPath)

	if code != exitOK {
		t.Errorf("exit %d: offline doctor failed\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if got := e.sequence(); len(got) != 0 {
		t.Errorf("offline doctor contacted the server: %v", got)
	}
	// The CA check still happens, and still reports the path it validated.
	if !strings.Contains(stdout, "certificate authority") {
		t.Errorf("offline doctor dropped the CA check:\n%s", stdout)
	}
	if !strings.Contains(stdout, e.ca.path) {
		t.Errorf("the CA check does not name what it validated:\n%s", stdout)
	}
	// And it says, in its own output, that it built nothing that could reach
	// the network. A claim an operator relies on has to be in the transcript.
	if !strings.Contains(stdout, "no network client constructed") {
		t.Errorf("offline doctor does not state that it built no client:\n%s", stdout)
	}
	// A bad CA must still fail offline: the check is real, not a stub.
	e.assertNoCredentials(t, stdout, stderr)
}

// The offline CA check must actually reject a bad CA, or the line above is
// decoration.
func TestDoctorOfflineStillRejectsAnUnusableCA(t *testing.T) {
	e := newE2EEnv(t, func(c *config.Config) {})
	bad := filepath.Join(e.dir, "not-a-ca.crt")
	if err := os.WriteFile(bad, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e2 := newE2EEnv(t, func(c *config.Config) { c.Pihole.CAPath = bad })

	code, stdout, _ := capture(t, "doctor", "--offline", "-config", e2.configPath)

	if code == exitOK {
		t.Errorf("exit %d: an unusable CA passed the offline check\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "certificate authority") {
		t.Errorf("the failure is not attributed to the CA check:\n%s", stdout)
	}
}

// Online doctor still probes, and still does so without a credential. This is
// the positive control for the two cases above: the offline change must not
// have disabled the connectivity check.
func TestDoctorOnlineStillProbesWithoutACredential(t *testing.T) {
	e := newE2EEnv(t, nil)

	code, stdout, stderr := capture(t, "doctor", "--no-credential", "-config", e.configPath)

	if code != exitOK {
		t.Errorf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	got := e.sequence()
	if len(got) != 1 || got[0] != "GET /api/auth" {
		t.Errorf("network sequence = %v, want exactly one unauthenticated probe", got)
	}
	if strings.Contains(stdout, "no network client constructed") {
		t.Errorf("an online run claims it built no client:\n%s", stdout)
	}
	e.assertNoCredentials(t, stdout, stderr)
}

// --- FINDING-77 at the command surface ----------------------------------------
//
// The unit tests assert the ERROR is clean. This asserts the whole command is:
// stdout, stderr and the audit stream (which the CLI writes to stderr) all go
// through `error: %v`, and that is the path the superseded error reached.
//
// The fake returns the password it has just been given back as a DUPLICATED
// JSON KEY — a value entirely of the peer's choosing, which no sanitiser can
// distinguish from a legitimate field name.
func TestADuplicatedKeyCarryingTheCredentialReachesNoStream(t *testing.T) {
	e := newE2EEnv(t, nil)
	e.echoCredentialAsDuplicateKey = true

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)

	if code == exitOK {
		t.Errorf("exit %d: an ambiguous authentication response was accepted", code)
	}
	// The command must still say something useful about what went wrong.
	if !strings.Contains(stdout, "error:") {
		t.Errorf("stdout does not report the failure:\n%s", stdout)
	}
	// And it must say it without reproducing the peer's key.
	e.assertNoCredentials(t, stdout, stderr)
	// No session may survive an authentication that was refused.
	for _, r := range e.sequence() {
		if r == "GET /api/info/version" {
			t.Error("a read was performed after an ambiguous authentication response")
		}
	}
}

// The same command, with a well-formed response, must still succeed — so the
// case above cannot be satisfied by failing everything.
func TestAWellFormedAuthenticationStillSucceedsAtTheCommandSurface(t *testing.T) {
	e := newE2EEnv(t, nil)

	code, stdout, stderr := capture(t, "status", "-config", e.configPath)

	if code != exitOK {
		t.Errorf("exit %d: a documented response was refused\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	e.assertNoCredentials(t, stdout, stderr)
}
