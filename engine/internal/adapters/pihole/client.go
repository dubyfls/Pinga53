// SPDX-License-Identifier: AGPL-3.0-only

// Package pihole is a read-only client for the Pi-hole v6 HTTPS API.
//
// The package exposes no method that mutates Pi-hole state. The only non-GET
// requests it can issue are POST /api/auth and DELETE /api/auth, which create
// and destroy ScamWall's own session and change nothing else.
package pihole

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/audit"
	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// UserAgent identifies ScamWall to Pi-hole. It carries no host or user detail.
const UserAgent = "ScamWall/0.1 (+https://github.com/dubyfls/Pinga53/engine)"

// MaxCABytes bounds reads of the CA file.
const MaxCABytes = 512 * 1024

// maxRedirects caps same-origin redirect following.
const maxRedirects = 3

// maxRetryDelay caps every wait between attempts, including one a server
// asked for with Retry-After. A peer must not be able to park this process for
// an arbitrary time by naming a large number.
const maxRetryDelay = 5 * time.Second

// Endpoints used by this client. Declared as constants so that the complete
// set of reachable endpoints is visible in one place and can be asserted by a
// test.
const (
	epAuth    = "/api/auth"
	epVersion = "/api/info/version"
	// epDenyExact is the ONE state endpoint the shadow comparison reads.
	//
	// The fully-qualified form, not `/api/domains`. The allowlist is over
	// (method, path) pairs compared exactly, so naming the narrow path is
	// what keeps `GET /api/domains` — every list, allow and deny, exact and
	// regex — outside what this client can construct at all. ScamWall
	// proposes exact deny entries and nothing else, so it reads exact deny
	// entries and nothing else.
	epDenyExact = "/api/domains/deny/exact"

	// epAllowExact and epAllowRegex are the household's own allow entries.
	//
	// FINDING-132, ORDER 8 control C-18. The comment above used to end "so no
	// allowlist, regex list or group is fetched", and that narrowness was
	// deliberate: ScamWall proposes exact deny entries, so it read exact deny
	// entries. The reasoning is sound about what ScamWall WRITES and wrong
	// about what it must KNOW. `shadow` exists to state the exact change
	// ScamWall would request of the appliance, and an addition the household
	// has already allowed is a change Pi-hole will override the moment it
	// lands. A plan that cannot say which of its additions are inert claims
	// more than it knows.
	//
	// Still narrow, and still read-only: two more fully-qualified GET paths,
	// not `/api/domains`.
	epAllowExact = "/api/domains/allow/exact"
	epAllowRegex = "/api/domains/allow/regex"
)

// Operation is one permitted API call: a method and a path, together.
//
// The pair is what matters. "Read-only" is not the same as "GET only" — a
// session has to be created and destroyed, and both of those are non-GET
// requests — so a method-only rule would either forbid authentication or
// permit every POST. What makes this client read-only is that the ONLY non-GET
// requests it can construct act on ScamWall's own session and nothing else.
type Operation struct {
	Method string
	Path   string
	// Retryable records whether repeating this exact request is safe. It is a
	// property of the operation, not of whether it happens to read data:
	// POST /api/auth reads nothing that changes, and is still not retryable,
	// because Pi-hole rate-limits authentication and has a finite number of
	// session seats.
	Retryable bool
	// Why is the justification for including the operation at all. An entry
	// without one should not be here.
	Why string
}

// PermittedOperations is the complete set of requests this client may issue.
//
// It is enforced at run time, before any name resolution, connection or TLS
// handshake, and it is enforced again on every redirect. A test asserts that
// this table and the endpoints in docs/PIHOLE_API_CONTRACT.md agree.
var PermittedOperations = []Operation{
	{
		Method: http.MethodPost, Path: epAuth, Retryable: false,
		Why: "creates ScamWall's own session; changes no Pi-hole state. Never retried: Pi-hole rate-limits login and has a finite number of session seats, so a retry storm could lock out an operator during an incident.",
	},
	{
		Method: http.MethodDelete, Path: epAuth, Retryable: false,
		Why: "destroys ScamWall's own session; changes no Pi-hole state. Not retried: a second delete of an already-deleted session is answered 404, which the caller already treats as the desired end state.",
	},
	{
		Method: http.MethodGet, Path: epAuth, Retryable: true,
		Why: "reads session state without sending a credential; used by doctor to distinguish 'unreachable' from 'needs a password'.",
	},
	{
		Method: http.MethodGet, Path: epVersion, Retryable: true,
		Why: "reads component version numbers. Non-sensitive.",
	},
	{
		Method: http.MethodGet, Path: epDenyExact, Retryable: true,
		Why: "reads the exact deny entries the appliance currently holds. The shadow comparison needs the target's OWN state: a comparison against a remembered or assumed list is an offline proposal with the appliance's name on it. Read-only, and narrow — the path names deny/exact, so no group or list is fetched.",
	},
	{
		Method: http.MethodGet, Path: epAllowExact, Retryable: true,
		Why: "reads the household's exact allow entries. Without them a shadow plan states additions the appliance would override the moment they landed, and cannot say which. FINDING-132. Read-only and fully qualified.",
	},
	{
		Method: http.MethodGet, Path: epAllowRegex, Retryable: true,
		Why: "reads the household's allow regexes. A regex allow covers hosts no exact list names, so reading only the exact list would leave the same gap one shape over. FINDING-132. Read-only and fully qualified.",
	},
}

// lookupOperation returns the permitted operation for a method and path.
func lookupOperation(method, path string) (Operation, bool) {
	for _, op := range PermittedOperations {
		if op.Method == method && op.Path == path {
			return op, true
		}
	}
	return Operation{}, false
}

// Errors returned by the client.
var (
	ErrPlaintextRefused      = errors.New("plaintext HTTP is refused")
	ErrCrossOriginRedirect   = errors.New("refused redirect to a different origin")
	ErrTooManyRedirects      = errors.New("too many redirects")
	ErrResponseTooLarge      = errors.New("response exceeds maximum size")
	ErrUnexpectedContent     = errors.New("unexpected response content type")
	ErrNotAuthenticated      = errors.New("no active session")
	ErrNoSessionID           = errors.New("authentication succeeded but returned no session id")
	ErrUnexpectedDial        = errors.New("refused connection to an unexpected address")
	ErrCAInvalid             = errors.New("certificate authority file contains no usable certificate")
	ErrOperationNotPermitted = errors.New("operation is not in the permitted set")
	ErrSessionAlreadyActive  = errors.New("a session is already active")
)

// APIError is a redacted representation of a failed API response.
//
// It carries the status, the endpoint, and Pi-hole's own error key. It never
// carries a request body, a response body, a header, or a credential.
type APIError struct {
	Status   int
	Endpoint string
	Key      string
	Message  string
	// RetryAfter is the delay the server asked for, parsed from Retry-After
	// and clamped. Zero when the header was absent, unparseable, or in the
	// past. It is a duration, never the raw header value, so nothing
	// peer-supplied reaches a log through it.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	b := strings.Builder{}
	fmt.Fprintf(&b, "pi-hole api: %s returned %d", e.Endpoint, e.Status)
	if e.Key != "" {
		fmt.Fprintf(&b, " (%s)", e.Key)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	return b.String()
}

// Unauthorized reports whether the failure was an authentication failure.
func (e *APIError) Unauthorized() bool { return e.Status == http.StatusUnauthorized }

// Forbidden reports whether the failure was an authorisation failure.
func (e *APIError) Forbidden() bool { return e.Status == http.StatusForbidden }

// RateLimited reports whether Pi-hole asked us to slow down.
func (e *APIError) RateLimited() bool { return e.Status == http.StatusTooManyRequests }

// SessionState is the non-sensitive part of a Pi-hole session response.
//
// The session id and CSRF token are deliberately absent from this type. The
// session id is held privately by the Client and the CSRF token is discarded,
// so neither can reach a caller, a log, or a report.
type SessionState struct {
	Valid    bool
	TOTP     bool
	Validity int
	Message  string
}

// Teardown is what became of the session this client created.
//
// It exists because "the client attempted a logout", "Pi-hole accepted the
// logout" and "the session is gone from the appliance" are three different
// claims. A caller that prints a success line has to be able to say which of
// them it actually observed. Before this type existed, `status` printed
// "session closed" on a path where the logout had FAILED and the failure was
// visible only as a warning in the audit stream.
type Teardown int

const (
	// TeardownNotAttempted: no logout was performed, because no session was
	// ever established.
	TeardownNotAttempted Teardown = iota
	// TeardownAccepted: Pi-hole answered the DELETE successfully. This is the
	// strongest claim this client can make on its own, and it is still a claim
	// about a REQUEST — not independent confirmation that the session is
	// absent from the appliance's session table.
	TeardownAccepted
	// TeardownAlreadyAbsent: Pi-hole answered 404. There was no such session
	// to destroy, which is the desired end state.
	TeardownAlreadyAbsent
	// TeardownFailed: the DELETE could not be completed. The session id is
	// discarded locally regardless, so nothing can retry it, and the session
	// may remain valid on the appliance until it expires.
	TeardownFailed
)

// String renders the outcome for an operator-facing line.
func (t Teardown) String() string {
	switch t {
	case TeardownAccepted:
		return "accepted"
	case TeardownAlreadyAbsent:
		return "already absent"
	case TeardownFailed:
		return "failed"
	default:
		return "not attempted"
	}
}

// ComponentVersion is the local and remote version of one Pi-hole component.
type ComponentVersion struct {
	LocalBranch   string
	LocalVersion  string
	LocalHash     string
	LocalDate     string
	RemoteVersion string
	RemoteHash    string
}

// VersionInfo is the non-sensitive version report from /api/info/version.
type VersionInfo struct {
	Core ComponentVersion
	Web  ComponentVersion
	FTL  ComponentVersion
}

// Client is a read-only Pi-hole API client.
type Client struct {
	cfg  config.Config
	log  *audit.Logger
	http *http.Client

	mu sync.Mutex
	// claimed is the single session slot, held from BEFORE the authentication
	// request goes on the wire until the teardown has run. It is separate from
	// sid because the window that matters starts before any sid exists: a
	// check of sid alone is satisfied by every caller that looks during a
	// login that is still in flight.
	claimed  bool
	sid      config.Secret
	teardown Teardown

	// peerSubject and peerIssuer are the verified leaf certificate's names,
	// recorded by the TLS verification callback of every connection this
	// client makes.
	//
	// # WHY A REPORT NEEDS THEM AND A CONFIGURATION FILE IS NOT ENOUGH
	//
	// `target_host: pi.hole` in a configuration file says which name was
	// ASKED for. A shadow plan claims to describe a particular appliance, and
	// the only evidence of which one answered is the certificate that was
	// actually verified against the pinned CA. Recording the configured name
	// alone would let a plan name a host it never reached.
	//
	// Written from crypto/tls's verification callback, which runs on the
	// handshake goroutine, and read by the caller afterwards, so it is under
	// the same mutex as the session.
	peerSubject string
	peerIssuer  string
}

// claimSession reserves the single session slot, or reports that it is taken.
//
// FINDING-74. The test and the reservation happen in ONE critical section.
// They were two —
// WithSession called SessionActive and then Login — and between them every
// concurrent caller saw an idle client, authenticated, and overwrote the
// previous session id. The overwritten session stays valid on the appliance
// for the rest of its lifetime, occupying one of a finite number of seats,
// with nothing left holding an id that could destroy it. That is the exact
// leak the refusal exists to prevent, so the refusal cannot itself be racy.
func (c *Client) claimSession() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claimed || !c.sid.IsZero() {
		// FINDING-79. A REFUSED claim changes nothing. The outcome belongs to
		// the caller that holds the slot, and is not this one's to clear.
		return ErrSessionAlreadyActive
	}
	c.claimed = true
	// FINDING-79. The outcome is reset in the SAME critical section that takes
	// the claim, because the two are one fact: a new operation has begun and
	// has not yet torn anything down. Resetting it anywhere else would leave a
	// window in which the slot is held by this operation while SessionTeardown
	// still reports the PREVIOUS one's result.
	//
	// The stale value was not hypothetical: a Client that completed one
	// session cleanly and then failed to authenticate for a second reported
	// TeardownAccepted, and reportTeardown prints "session logout ACCEPTED by
	// Pi-hole" from exactly this field — on the failure path FINDING-75 had
	// just added, so the stale value surfaced precisely where the accurate one
	// was introduced.
	c.teardown = TeardownNotAttempted
	return nil
}

// releaseSession gives the slot back after an attempt that established nothing.
func (c *Client) releaseSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.claimed = false
}

// New builds a client with TLS pinned to the configured private CA.
func New(cfg config.Config, log *audit.Logger) (*Client, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	expected := net.JoinHostPort(cfg.Pihole.Host, itoa(cfg.Pihole.Port))
	dialAddr := cfg.DialAddress()
	dialer := &net.Dialer{Timeout: cfg.Pihole.ConnectTimeout.D()}

	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   cfg.Pihole.ConnectTimeout.D(),
		ResponseHeaderTimeout: cfg.Pihole.RequestTimeout.D(),
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     true,
		// Proxies are ignored. A proxy would terminate or observe the
		// connection to a service that is, by definition, on the local host.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Only the configured origin may be dialled. Combined with the
			// redirect policy, this means no response can steer the client at
			// another host.
			if addr != expected {
				return nil, fmt.Errorf("%w: %s", ErrUnexpectedDial, addr)
			}
			// Resolution is overridden here, and only here. Certificate and
			// hostname verification are unaffected: tls.Config.ServerName
			// still requires a certificate valid for the configured host.
			return dialer.DialContext(ctx, network, dialAddr)
		},
	}

	c := &Client{
		cfg: cfg,
		log: log,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Pihole.TotalTimeout.D(),
			// A redirect is a request the SERVER chose, so the same rules that
			// govern a request this client chose are applied again here. Same
			// origin is not sufficient on its own: a Pi-hole that answered
			// GET /api/info/version with a 302 to a DNS-control endpoint would be
			// redirecting us, within the approved origin, to something the
			// contract forbids. The literal path is not written here: a guard
			// test refuses any mention of a mutating endpoint in this package,
			// and a comment is not an exemption from it.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return ErrTooManyRedirects
				}
				origin := via[0].URL
				if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
					return fmt.Errorf("%w: %s -> %s", ErrCrossOriginRedirect, origin.Host, req.URL.Host)
				}
				// A redirect target carrying a query string is refused outright.
				// Pi-hole accepts the session id as a `sid` query parameter, and a
				// redirect is the one way a URL this client did not build could
				// acquire one.
				if req.URL.RawQuery != "" {
					return fmt.Errorf("%w: redirect target carries a query string", ErrOperationNotPermitted)
				}
				if _, ok := lookupOperation(req.Method, req.URL.Path); !ok {
					return fmt.Errorf("%w: redirected to %s %s", ErrOperationNotPermitted, req.Method, req.URL.Path)
				}
				return nil
			},
		},
	}

	// The verified peer identity is recorded as a SIDE EFFECT of the standard
	// verification, never in place of it.
	//
	// VerifyConnection runs AFTER the normal chain and hostname checks, which
	// are left entirely alone: InsecureSkipVerify is false, RootCAs is the
	// pinned pool and ServerName is the configured host, so this callback is
	// only ever reached by a connection that already verified. Returning nil
	// from it therefore weakens nothing — there is nothing left to weaken —
	// and a callback that decided anything would be the exact shape this
	// repository refuses.
	tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the peer presented no certificate")
		}
		leaf := cs.PeerCertificates[0]
		c.mu.Lock()
		c.peerSubject = leaf.Subject.String()
		c.peerIssuer = leaf.Issuer.String()
		c.mu.Unlock()
		return nil
	}
	return c, nil
}

// buildTLSConfig creates a TLS configuration trusting only the configured CA.
//
// The system trust store is not consulted. Pi-hole's certificate is issued by a
// private CA, so accepting any publicly-trusted issuer would widen the set of
// parties able to impersonate it to every CA on the internet.
func buildTLSConfig(cfg config.Config) (*tls.Config, error) {
	f, err := os.Open(cfg.Pihole.CAPath)
	if err != nil {
		return nil, fmt.Errorf("open CA: %w", err)
	}
	defer func() { _ = f.Close() }()

	pem, err := io.ReadAll(io.LimitReader(f, MaxCABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	if len(pem) > MaxCABytes {
		return nil, fmt.Errorf("CA file exceeds %d bytes", MaxCABytes)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: %s", ErrCAInvalid, cfg.Pihole.CAPath)
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: cfg.Pihole.Host,
		MinVersion: tls.VersionTLS12,
		// InsecureSkipVerify is intentionally left at its zero value (false).
		// There is no configuration path that can set it, and a test asserts
		// the identifier does not appear in this package.
	}, nil
}

// SessionActive reports whether a session id is held.
func (c *Client) SessionActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.sid.IsZero()
}

// SessionTeardown reports what became of the session, as this client observed
// it. It is meaningful only after Logout, or WithSession, has run.
func (c *Client) SessionTeardown() Teardown {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.teardown
}

// Login authenticates and stores the session id in memory.
//
// The session id is never written to disk, never placed in a URL, and never
// logged. The CSRF token returned alongside it is discarded: ScamWall
// authenticates with a header rather than a cookie, so CSRF does not apply.
func (c *Client) Login(ctx context.Context, secret config.Secret) (SessionState, error) {
	if secret.IsZero() {
		return SessionState{}, errors.New("cannot authenticate with an empty password")
	}

	// The slot is claimed here rather than in WithSession, so that the
	// property holds for every caller rather than for the ones that remember
	// to use the wrapper. Claimed BEFORE the request: a refusal that happened
	// after the round trip would already have spent a session seat.
	if err := c.claimSession(); err != nil {
		return SessionState{}, err
	}
	established := false
	defer func() {
		if !established {
			c.releaseSession()
		}
	}()

	// One of exactly two sanctioned Reveal call sites (the other sets the
	// X-FTL-SID header). Both are the moment a credential goes on the wire.
	body, err := json.Marshal(struct {
		Password string `json:"password"`
	}{Password: secret.Reveal()})
	if err != nil {
		return SessionState{}, errors.New("failed to encode authentication request")
	}
	// Best-effort reduction of the plaintext's lifetime in memory. Go strings
	// are immutable, so the copy created by Reveal cannot be wiped; this
	// narrows the window without eliminating it.
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()

	var resp authResponse
	// Authentication is never retried. Pi-hole rate-limits login and returns
	// 429 when its session table is full, so a retry storm could lock out a
	// legitimate operator during an incident.
	err = c.do(ctx, http.MethodPost, epAuth, body, &resp)
	if err != nil {
		// This is the one request that carries the password, so it is the one
		// place a peer could echo it back. Scrubbed before the error leaves
		// this function, so no caller and no log ever sees it.
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			apiErr.Key = secret.Scrub(apiErr.Key)
			apiErr.Message = secret.Scrub(apiErr.Message)
		}
		return SessionState{}, err
	}
	if resp.Session.SID == nil || *resp.Session.SID == "" {
		return SessionState{}, ErrNoSessionID
	}

	c.mu.Lock()
	c.sid = config.NewSecretString(*resp.Session.SID)
	c.mu.Unlock()
	established = true

	// Overwrite the decoded copies so the only retained instance is the
	// redacting Secret.
	*resp.Session.SID = ""
	resp.Session.SID = nil
	resp.Session.CSRF = nil

	state := resp.Session.state()
	c.log.Info("pihole.login", audit.F("valid", state.Valid), audit.F("validity_seconds", state.Validity), audit.F("totp_enabled", state.TOTP))
	return state, nil
}

// Logout destroys the session.
//
// It runs under its own bounded context derived from ctx but detached from its
// cancellation, so a cancelled or failed operation still gets a real
// opportunity to tear down the session. Leaving a session behind is not
// harmless: it stays valid for its remaining lifetime and consumes one of a
// finite number of session seats.
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	active := !c.sid.IsZero()
	c.mu.Unlock()
	if !active {
		return nil
	}

	logoutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.Pihole.LogoutTimeout.D())
	defer cancel()

	err := c.do(logoutCtx, http.MethodDelete, epAuth, nil, nil)

	// The session id is discarded regardless of the outcome. Retaining an id
	// that may already be invalid serves no purpose and only extends the time
	// a credential sits in memory.
	//
	// The observed outcome is recorded in the same critical section, so a
	// caller cannot read a teardown state that disagrees with whether a
	// session id is still held.
	outcome := TeardownAccepted
	var apiErr *APIError
	switch {
	// 404 means the session is already gone, which is the desired end state.
	case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
		outcome = TeardownAlreadyAbsent
	case err != nil:
		outcome = TeardownFailed
	}

	c.mu.Lock()
	c.sid.Destroy()
	c.teardown = outcome
	// The slot is released here and nowhere else on this path: a caller that
	// authenticated holds it until the teardown has run, successfully or not.
	c.claimed = false
	c.mu.Unlock()

	switch outcome {
	case TeardownAlreadyAbsent:
		c.log.Info("pihole.logout", audit.F("result", "no_session"))
		return nil
	case TeardownFailed:
		c.log.Error("pihole.logout_failed", err)
		return err
	default:
		c.log.Info("pihole.logout", audit.F("result", "ok"))
		return nil
	}
}

// ProbeAuth queries session state without sending a credential.
//
// Used by doctor to distinguish "cannot reach Pi-hole" from "can reach it but
// needs a password", without transmitting anything sensitive.
func (c *Client) ProbeAuth(ctx context.Context) (SessionState, error) {
	var resp authResponse
	err := c.do(ctx, http.MethodGet, epAuth, nil, &resp)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Unauthorized() {
			// 401 here is a successful probe: it proves the API is reachable,
			// speaks JSON, and requires authentication.
			return SessionState{Valid: false, Message: "authentication required"}, nil
		}
		return SessionState{}, err
	}
	resp.Session.SID = nil
	resp.Session.CSRF = nil
	return resp.Session.state(), nil
}

// Version reads Pi-hole component versions. Requires an active session.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	if !c.SessionActive() {
		return nil, ErrNotAuthenticated
	}
	var resp versionResponse
	if err := c.do(ctx, http.MethodGet, epVersion, nil, &resp); err != nil {
		return nil, err
	}
	v := resp.toVersionInfo()
	c.log.Info("pihole.version_read",
		audit.F("core", v.Core.LocalVersion),
		audit.F("web", v.Web.LocalVersion),
		audit.F("ftl", v.FTL.LocalVersion))
	return v, nil
}

// WithSession authenticates, runs fn, and always attempts logout.
//
// Callers should prefer this over calling Login and Logout directly, because
// it makes the logout unconditional rather than dependent on every return path
// remembering to perform it.
func (c *Client) WithSession(ctx context.Context, secret config.Secret, fn func(context.Context) error) error {
	// Refused rather than nested, and refused by Login itself. A second Login
	// would overwrite the session id held here, and the overwritten one would
	// stay valid on the server for the rest of its lifetime, occupying one of
	// a finite number of seats with no way left to destroy it. That is a leak,
	// so it is a programming error. The test and the claim are one critical
	// section inside Login; this function deliberately does not pre-check,
	// because a pre-check is what made the refusal racy.
	if _, err := c.Login(ctx, secret); err != nil {
		return err
	}
	defer func() {
		if err := c.Logout(ctx); err != nil {
			// Logout failure must not mask the caller's error, so it is logged
			// rather than returned. It is NOT thereby discarded: Logout has
			// recorded TeardownFailed, and SessionTeardown is what a caller
			// must consult before printing anything that claims the session
			// was closed. A warning in an audit stream is not a substitute for
			// a truthful exit status.
			c.log.Warn("pihole.logout_incomplete", audit.F("reason", "see previous error"))
		}
	}()
	return fn(ctx)
}

func itoa(n int) string { return strconv.Itoa(n) }

// sanitizeMessage bounds and cleans a server-supplied message before it is
// allowed into an error string.
//
// Pi-hole's messages are short and generic, but they originate outside this
// process, so they are treated as untrusted: control characters are stripped
// and the length is capped to keep them out of logs as anything other than a
// short diagnostic.
func sanitizeMessage(s string) string {
	const maxLen = 200
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len() >= maxLen {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// jitteredBackoff returns a bounded, randomised delay for attempt n.
//
// Jitter prevents several ScamWall instances, or repeated retries after a
// shared outage, from synchronising into a thundering herd against a service
// whose availability is load-bearing for the whole network.
func jitteredBackoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	d := base << attempt
	if d > maxRetryDelay {
		d = maxRetryDelay
	}
	// Full jitter: uniform in [0, d].
	return time.Duration(rand.Int64N(int64(d) + 1))
}

func mediaTypeIsJSON(ct string) bool {
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// ValidateCA checks that the configured CA file is present, bounded and
// parseable, without constructing a Client, an HTTP transport or a dialler.
//
// FINDING-80 — what this does and does not avoid, stated exactly, because the
// first version of this comment overstated it.
//
// It DOES construct a *tls.Config: validating the CA means building the
// certificate pool, and buildTLSConfig is what turns that pool into the
// configuration whose construction is the validation. A tls.Config is an
// inert value — it holds no socket, no connection and no dialler, and nothing
// here hands it to anything — but it is constructed, and saying otherwise
// would be false.
//
// It does NOT construct a pihole.Client, an http.Transport, a net.Dialer or a
// redirect policy, and it opens no socket. That is the difference from New(),
// which builds all of them before a caller can decide not to use them.
//
// The parse, the bound and the errors are identical to New()'s, because they
// are the same code.
func ValidateCA(cfg config.Config) error {
	_, err := buildTLSConfig(cfg)
	return err
}

// DomainEntry is one exact deny entry the appliance currently holds.
//
// # WHAT THIS TYPE DELIBERATELY DOES NOT CARRY
//
// There is no `owner` field, and no derivation of one. Pi-hole records no
// notion of which program added an entry; `comment` is free text that any
// person or program can write, so an entry whose comment happens to say
// "scamwall" establishes nothing. Ownership is a question for an ownership
// ledger this build does not have, and internal/shadow treats every observed
// entry as the household's until one is supplied.
type DomainEntry struct {
	Domain  string `json:"domain"`
	Unicode string `json:"unicode"`
	Type    string `json:"type"`
	Kind    string `json:"kind"`
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
	// ID and DateAdded are the appliance's own record identity. Read and
	// reported; never used to infer who put the entry there.
	ID        int   `json:"id"`
	DateAdded int64 `json:"date_added"`
}

// DenyExactDomains reads the appliance's exact deny entries.
//
// Requires an active session — Pi-hole answers 401 without one, and asking
// first turns that into a local error rather than a request that spends one
// of a finite number of attempts against a rate limiter.
//
// It is a READ, and the only one ScamWall makes of the appliance's blocking
// state. Nothing in this client can write to it: see PermittedOperations.
func (c *Client) DenyExactDomains(ctx context.Context) ([]DomainEntry, error) {
	return c.readDomains(ctx, epDenyExact, "pihole.deny_exact_read")
}

// PeerCertificateIdentity reports the subject and issuer of the certificate
// the target actually presented and this client verified.
//
// ok is false before any connection has been made. A caller that reports an
// identity must report ITS ABSENCE too: "the program did not record which
// appliance answered" and "the program reached the right one" are not the
// same statement, and an omitted field reads as the second.
func (c *Client) PeerCertificateIdentity() (subject, issuer string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peerSubject == "" && c.peerIssuer == "" {
		return "", "", false
	}
	return c.peerSubject, c.peerIssuer, true
}

// AllowExactDomains reads the household's exact allow entries.
//
// Requires an active session, for the same reason DenyExactDomains does.
//
// These entries are the household's own statement about what it wants
// reachable. ScamWall reads them and never writes them: nothing in this client
// can, see PermittedOperations. The count is logged; the names are not.
func (c *Client) AllowExactDomains(ctx context.Context) ([]DomainEntry, error) {
	return c.readDomains(ctx, epAllowExact, "pihole.allow_exact_read")
}

// AllowRegexDomains reads the household's allow regexes.
//
// A regex allow covers hosts no exact list names, so a build that read only
// the exact list would leave the same gap one shape over. Whether a given
// pattern can be evaluated faithfully is a separate question and not this
// package's: see internal/policy's allow-regex evaluation, which abstains
// rather than guessing.
func (c *Client) AllowRegexDomains(ctx context.Context) ([]DomainEntry, error) {
	return c.readDomains(ctx, epAllowRegex, "pihole.allow_regex_read")
}

// readDomains is the body DenyExactDomains and the two allow readers share.
//
// It exists because three copies of "check the session, GET one fully
// qualified path, copy, sort, log the count" is three chances for one of them
// to stop sorting or start logging the names.
func (c *Client) readDomains(ctx context.Context, endpoint, event string) ([]DomainEntry, error) {
	if !c.SessionActive() {
		return nil, ErrNotAuthenticated
	}
	var resp domainsResponse
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}
	// A COPY, sorted, with the count logged rather than the names.
	//
	// The domains are the household's own lists. They are returned to the
	// caller, which is the point; they do not go into an audit stream that an
	// operator may paste somewhere.
	out := append([]DomainEntry(nil), resp.Domains...)
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	c.log.Info(event, audit.F("entries", itoa(len(out))))
	return out, nil
}
