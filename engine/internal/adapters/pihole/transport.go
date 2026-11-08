// SPDX-License-Identifier: AGPL-3.0-only

package pihole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/audit"
)

// authResponse mirrors the documented session envelope.
//
// SID and CSRF are pointers so they can be cleared immediately after use.
type sessionEnvelope struct {
	Valid    bool    `json:"valid"`
	TOTP     bool    `json:"totp"`
	SID      *string `json:"sid"`
	CSRF     *string `json:"csrf"`
	Validity int     `json:"validity"`
	Message  *string `json:"message"`
}

func (s sessionEnvelope) state() SessionState {
	st := SessionState{Valid: s.Valid, TOTP: s.TOTP, Validity: s.Validity}
	if s.Message != nil {
		st.Message = sanitizeMessage(*s.Message)
	}
	return st
}

type authResponse struct {
	Session sessionEnvelope `json:"session"`
	Took    float64         `json:"took"`
}

// apiErrorEnvelope mirrors Pi-hole's error shape.
type apiErrorEnvelope struct {
	Error struct {
		Key     string  `json:"key"`
		Message string  `json:"message"`
		Hint    *string `json:"hint"`
	} `json:"error"`
	Took float64 `json:"took"`
}

type localRemote struct {
	Local struct {
		Branch  *string `json:"branch"`
		Version *string `json:"version"`
		Hash    *string `json:"hash"`
		Date    *string `json:"date"`
	} `json:"local"`
	Remote struct {
		Version *string `json:"version"`
		Hash    *string `json:"hash"`
	} `json:"remote"`
}

func (lr localRemote) component() ComponentVersion {
	return ComponentVersion{
		LocalBranch:   deref(lr.Local.Branch),
		LocalVersion:  deref(lr.Local.Version),
		LocalHash:     deref(lr.Local.Hash),
		LocalDate:     deref(lr.Local.Date),
		RemoteVersion: deref(lr.Remote.Version),
		RemoteHash:    deref(lr.Remote.Hash),
	}
}

type versionResponse struct {
	Version struct {
		Core localRemote `json:"core"`
		Web  localRemote `json:"web"`
		FTL  localRemote `json:"ftl"`
	} `json:"version"`
	Took float64 `json:"took"`
}

func (v versionResponse) toVersionInfo() *VersionInfo {
	return &VersionInfo{
		Core: v.Version.Core.component(),
		Web:  v.Version.Web.component(),
		FTL:  v.Version.FTL.component(),
	}
}

// deref returns the value of a nullable string field. Every version field in
// the Pi-hole schema is nullable, so this avoids a nil dereference on a
// perfectly valid response.
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return sanitizeMessage(*p)
}

// do performs one API call, with bounded retries when the operation permits.
//
// The permitted-operation table is consulted FIRST, before the endpoint is
// built and before anything is resolved, dialled or handshaken. A request
// outside the contract must fail as a programming error, not as a network
// error, and it must not put a packet on the wire on its way to failing.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	op, permitted := lookupOperation(method, path)
	if !permitted {
		// The method and path are this process's own constants, not peer data,
		// so naming them is safe and is the only useful thing to say.
		return fmt.Errorf("%w: %s %s", ErrOperationNotPermitted, method, path)
	}

	endpoint := c.cfg.BaseURL() + path

	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %s", path)
	}
	// Plaintext is refused here as well as in configuration. A single check is
	// a single place to get wrong.
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %s", ErrPlaintextRefused, u.Scheme)
	}
	// The session id must never appear in a URL: query strings are recorded by
	// proxies, access logs, and browser history. Pi-hole offers a `sid` query
	// parameter; ScamWall does not use it.
	if u.RawQuery != "" {
		return errors.New("query parameters are not used by this client")
	}

	// One deadline for the whole operation, retries and backoff included.
	//
	// Without this the total is attempts x RequestTimeout plus the delays
	// between them, which is not what TotalTimeout says and grows with
	// MaxRetries. http.Client.Timeout bounds a single request; it does not
	// bound a sequence of them.
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Pihole.TotalTimeout.D())
	defer cancel()

	attempts := 1
	if op.Retryable {
		attempts += c.cfg.Pihole.MaxRetries
	}

	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			delay := c.retryDelay(lastErr, attempt-1)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				// The deadline that expired may be this operation's own, so the
				// error names the endpoint rather than surfacing a bare
				// context error from an unidentified place.
				return redactTransportError(path, ctx.Err())
			case <-timer.C:
			}
		}

		err := c.attempt(ctx, method, u.String(), path, body, out)
		if err == nil {
			return nil
		}
		lastErr = err

		// Context errors are terminal: the caller asked us to stop, or the
		// operation deadline above has expired.
		if ctx.Err() != nil {
			return err
		}
		if !op.Retryable || !isRetryable(err) {
			return err
		}
		c.log.Warn("pihole.retry",
			audit.F("endpoint", path),
			audit.F("attempt", attempt+1),
			audit.F("of", attempts))
	}
	return lastErr
}

// retryDelay is how long to wait before attempt n+1, given what went wrong.
//
// A server that answered 429 with a Retry-After has stated how long it wants
// to be left alone, and ignoring that in favour of a shorter local backoff is
// how a client turns rate limiting into an outage. The stated value is honoured
// where it is longer than the local backoff, and capped either way: a hostile
// or broken peer must not be able to park this process for an arbitrary time
// by naming a large number.
func (c *Client) retryDelay(lastErr error, attempt int) time.Duration {
	delay := jitteredBackoff(c.cfg.Pihole.RetryBaseDelay.D(), attempt)
	var apiErr *APIError
	if errors.As(lastErr, &apiErr) && apiErr.RetryAfter > 0 {
		if apiErr.RetryAfter > delay {
			delay = apiErr.RetryAfter
		}
	}
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	return delay
}

// isRetryable reports whether an error is worth another attempt.
//
// Authentication and authorisation failures are never retried: they will not
// succeed on repetition, and repeating them can trip rate limits or lockouts.
func isRetryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}
	// A response that was too large, or of the wrong type, indicates the peer
	// is not behaving as documented. Retrying will not change that.
	if errors.Is(err, ErrResponseTooLarge) ||
		errors.Is(err, ErrUnexpectedContent) ||
		// Ambiguity is a property of what the peer sent, not of the link. A
		// second attempt would have to be resolved the same way.
		errors.Is(err, ErrAmbiguousResponse) ||
		errors.Is(err, ErrCrossOriginRedirect) ||
		errors.Is(err, ErrTooManyRedirects) ||
		errors.Is(err, ErrOperationNotPermitted) ||
		errors.Is(err, ErrUnexpectedDial) {
		return false
	}
	// Remaining failures are transport-level (dial, TLS, timeout). TLS
	// failures are not distinguished here because retrying a handshake against
	// a correctly-configured peer is harmless and a misconfigured peer fails
	// the same way every time.
	return true
}

func (c *Client) attempt(ctx context.Context, method, fullURL, path string, body []byte, out any) error {
	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Pihole.RequestTimeout.D())
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, fullURL, reader)
	if err != nil {
		return fmt.Errorf("build request for %s", path)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// The session id travels only in this header, and only when one is held.
	c.mu.Lock()
	if !c.sid.IsZero() {
		req.Header.Set("X-FTL-SID", c.sid.Reveal())
	}
	c.mu.Unlock()

	resp, err := c.http.Do(req)
	if err != nil {
		// net/url wraps transport errors in *url.Error, whose message contains
		// the full URL. That is safe here because the URL never carries
		// credentials, but the error is still rewritten so that nothing
		// unexpected from a lower layer reaches a log.
		return redactTransportError(path, err)
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	// 204 carries no body. This is the documented success response for logout.
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	ct := resp.Header.Get("Content-Type")
	if !mediaTypeIsJSON(ct) {
		// The received content type is reported because it is a protocol fact,
		// not user data, and it is the single most useful clue when something
		// other than Pi-hole answers on the port.
		return fmt.Errorf("%w: %s returned %q", ErrUnexpectedContent, path, sanitizeMessage(ct))
	}

	limit := c.cfg.Pihole.MaxResponseBytes
	payload, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read response from %s: %w", path, redactTransportError(path, err))
	}
	if int64(len(payload)) > limit {
		return fmt.Errorf("%w: %s exceeded %d bytes", ErrResponseTooLarge, path, limit)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The peer's own words are scrubbed of anything we sent it before
		// they are allowed into an error. A Pi-hole that quoted a session id
		// back at us in an error message would otherwise put it into a log
		// without ScamWall having printed it anywhere.
		return c.scrubAPIError(newAPIError(resp.StatusCode, path, resp.Header, payload))
	}

	if out == nil {
		return nil
	}
	// Strict: ambiguity is refused rather than resolved. See decode.go.
	if err := decodeResponse(payload, out); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	return nil
}

// scrubAPIError removes any live session id the peer echoed back at us.
//
// The password is scrubbed at its own call site rather than here, because this
// method is reached for every endpoint and only Login holds the credential.
func (c *Client) scrubAPIError(err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	c.mu.Lock()
	sid := c.sid
	c.mu.Unlock()
	apiErr.Key = sid.Scrub(apiErr.Key)
	apiErr.Message = sid.Scrub(apiErr.Message)
	return err
}

// newAPIError builds a redacted error from a failure response.
//
// This is the NON-2xx path, and it deliberately does not use decodeResponse:
// the strict duplicate-key and trailing-content rules govern successful bodies
// only. A best-effort parse is right here — a peer returning a malformed error
// body should still produce an error carrying the status and the endpoint,
// rather than having its status swallowed by a parse failure.
//
// What keeps that safe is that nothing peer-NAMED survives: only the two
// values below are taken, each is bounded by sanitizeMessage, and each is then
// scrubbed of the session id (scrubAPIError) and, on the authentication path,
// of the password (Login). Key names are never reproduced — which is exactly
// the mistake FINDING-77 fixed on the success path.
func newAPIError(status int, path string, hdr http.Header, payload []byte) error {
	e := &APIError{Status: status, Endpoint: path}
	var env apiErrorEnvelope
	if err := json.Unmarshal(payload, &env); err == nil {
		e.Key = sanitizeMessage(env.Error.Key)
		e.Message = sanitizeMessage(env.Error.Message)
	}
	e.RetryAfter = parseRetryAfter(hdr.Get("Retry-After"), time.Now())
	return e
}

// parseRetryAfter reads the two forms RFC 9110 allows and clamps the result.
//
// The header is peer-supplied, so it is treated as untrusted input: a
// negative, absurd, or unparseable value yields zero, and a large one is
// clamped by the caller rather than obeyed. The parsed value is a duration and
// the raw string is discarded, so nothing the peer wrote survives into a log.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		// Clamped BEFORE the multiplication. time.Duration is an int64 of
		// nanoseconds, so a large delta-seconds value overflows into a
		// NEGATIVE duration, which sails past a later `> maxRetryDelay` test
		// and turns a server asking us to wait into no wait at all. Found by
		// the overflow case in TestParseRetryAfter.
		const maxSeconds = int(maxRetryDelay / time.Second)
		if secs > maxSeconds {
			return maxRetryDelay
		}
		return time.Duration(secs) * time.Second
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0
	}
	d := t.Sub(now)
	if d <= 0 {
		return 0
	}
	if d > maxRetryDelay {
		return maxRetryDelay
	}
	return d
}

// redactTransportError rewrites a transport error so that only its class and
// the endpoint path survive.
func redactTransportError(path string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("request to %s timed out: %w", path, context.DeadlineExceeded)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("request to %s cancelled: %w", path, context.Canceled)
	case errors.Is(err, ErrCrossOriginRedirect):
		return fmt.Errorf("request to %s: %w", path, ErrCrossOriginRedirect)
	case errors.Is(err, ErrTooManyRedirects):
		return fmt.Errorf("request to %s: %w", path, ErrTooManyRedirects)
	case errors.Is(err, ErrUnexpectedDial):
		return fmt.Errorf("request to %s: %w", path, ErrUnexpectedDial)
	case errors.Is(err, ErrOperationNotPermitted):
		// Raised by CheckRedirect. The wrapped message names the method and
		// path the server tried to send us to, which is peer-influenced but
		// already bounded and sanitised where it was built.
		return fmt.Errorf("request to %s: %w", path, ErrOperationNotPermitted)
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:") || strings.Contains(msg, "certificate"):
		// The specific verification failure is preserved because it is exactly
		// what an operator needs, and it contains no credential. It is
		// sanitised and bounded like any other peer-influenced string.
		return fmt.Errorf("TLS verification failed for %s: %s", path, sanitizeMessage(stripURL(msg)))
	default:
		return fmt.Errorf("transport error for %s: %s", path, sanitizeMessage(stripURL(msg)))
	}
}

// stripURL removes the leading `Method "URL": ` prefix that *url.Error adds.
func stripURL(msg string) string {
	if i := strings.Index(msg, `": `); i >= 0 && strings.Contains(msg[:i], `"`) {
		return msg[i+3:]
	}
	return msg
}

// domainsResponse is the shape of GET /api/domains/deny/exact.
//
// Only the fields ScamWall reads are declared. decodeResponse refuses
// duplicate keys, so a document naming `domains` twice is refused rather than
// resolved to whichever copy encoding/json kept.
type domainsResponse struct {
	Domains []DomainEntry `json:"domains"`
}
