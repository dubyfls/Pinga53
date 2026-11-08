// SPDX-License-Identifier: AGPL-3.0-only

package pihole_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"crypto/tls"

	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// The API hostname used throughout these tests. It matches the name ScamWall
// verifies in production, so the tests exercise the real code path rather than
// a relaxed one.
const testHost = "pi.hole"

// testCA is a throwaway certificate authority created per test run.
//
// Generating trust material in-process rather than committing it means no
// certificate or key ever enters the repository, and a leaked fixture cannot
// be reused against anything.
type testCA struct {
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	path    string
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ScamWall Test CA", Organization: []string{"ScamWall Tests"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	path := filepath.Join(t.TempDir(), "test-ca.crt")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &testCA{certPEM: certPEM, cert: cert, key: key, path: path}
}

// leafFor issues a server certificate for the given DNS names.
func (ca *testCA) leafFor(t testing.TB, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakePihole is an HTTPS server that impersonates the parts of the Pi-hole API
// ScamWall uses.
type fakePihole struct {
	*httptest.Server
	ca *testCA

	// requests records what the client actually sent, so tests can assert on
	// transport behaviour rather than only on responses.
	mu       chan struct{}
	Requests []recordedRequest
}

type recordedRequest struct {
	Method   string
	Path     string
	RawQuery string
	SID      string
	HasAuth  bool
}

func newFakePihole(t testing.TB, ca *testCA, handler http.Handler, certNames ...string) *fakePihole {
	t.Helper()
	if len(certNames) == 0 {
		certNames = []string{testHost}
	}
	f := &fakePihole{ca: ca, mu: make(chan struct{}, 1)}
	f.mu <- struct{}{}

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-f.mu
		f.Requests = append(f.Requests, recordedRequest{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			SID:      r.Header.Get("X-FTL-SID"),
			HasAuth:  r.Header.Get("X-FTL-SID") != "",
		})
		f.mu <- struct{}{}
		handler.ServeHTTP(w, r)
	})

	srv := httptest.NewUnstartedServer(wrapped)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leafFor(t, certNames...)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.Server = srv
	return f
}

// recorded returns a copy of the recorded requests.
func (f *fakePihole) recorded() []recordedRequest {
	<-f.mu
	defer func() { f.mu <- struct{}{} }()
	out := make([]recordedRequest, len(f.Requests))
	copy(out, f.Requests)
	return out
}

// Port returns the port the fake server is listening on.
func (f *fakePihole) Port(t testing.TB) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(f.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// configFor builds a client configuration pointed at the fake server.
//
// The host stays "pi.hole" so hostname verification is exercised exactly as it
// is in production; only the dialled address is overridden, which is the same
// mechanism used against the real deployment.
func configFor(t testing.TB, f *fakePihole, caPath string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Pihole.Host = testHost
	cfg.Pihole.Port = f.Port(t)
	cfg.Pihole.AddressOverride = f.Listener.Addr().String()
	cfg.Pihole.CAPath = caPath
	cfg.Pihole.RequestTimeout = config.Duration(2 * time.Second)
	cfg.Pihole.TotalTimeout = config.Duration(5 * time.Second)
	cfg.Pihole.ConnectTimeout = config.Duration(2 * time.Second)
	cfg.Pihole.LogoutTimeout = config.Duration(2 * time.Second)
	cfg.Pihole.MaxRetries = 0
	cfg.Pihole.RetryBaseDelay = config.Duration(time.Millisecond)
	return cfg
}

// writeJSON is a helper for handlers.
func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// Session values are generated per run rather than written as literals.
//
// Two reasons. A credential-shaped literal in a public repository is exactly
// what the secret scanner exists to stop, and a value that is fresh every run
// cannot accidentally collide with something a log legitimately contains,
// which would make the leak assertions quietly meaningless.
var (
	sessionSID  = randomToken("sid")
	sessionCSRF = randomToken("csrf")
)

// randomToken returns an unpredictable, clearly-synthetic test value.
func randomToken(kind string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("test setup: no entropy available: " + err.Error())
	}
	return "scamwall-test-" + kind + "-" + hex.EncodeToString(b)
}

func loginOKBody() string {
	return `{"session":{"valid":true,"totp":false,"sid":"` + sessionSID +
		`","csrf":"` + sessionCSRF + `","validity":1800,"message":null},"took":0.001}`
}
