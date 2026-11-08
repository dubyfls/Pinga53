// SPDX-License-Identifier: AGPL-3.0-only

package acquire

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// # THE BOUND THAT IS ALMOST ALWAYS MISSING
//
// A read deadline is easy and covers the wrong thing. The dangerous server is
// the one that accepts the TCP connection and then says nothing at all:
// there is no response to read, so a response deadline never fires, and the
// fetch sits holding a file descriptor until something else gives up. The
// deadline here is therefore ONE deadline on the request context, covering
// resolution, connection, TLS handshake, headers and body together. See
// TestASilentServerFailsInsideTheDeadline.
//
// # THIS IS NOT REACHABLE FROM cmd/
//
// Deliberately. ORDER 8 declined to build a feed fetcher unattended on the
// grounds that a half-built network path is worse than none, and that
// judgement stands. What is built here is the BOUNDS, proven against local
// test servers, so that the component the next order wires up starts from a
// transport that has already been attacked in a test rather than from a bare
// http.Get. TestTheFetcherIsNotReachableFromTheCommand keeps it that way.

// Fetch errors. Each is distinguishable because the operator's next move
// differs: a scheme refusal is a configuration mistake, a deadline is a
// network or a hostile server, a ratio refusal is a hostile server outright.
var (
	ErrFetchLimitsUnset = errors.New("acquire: fetch limits are unset; an unset bound is not an unbounded one")
	ErrFetchScheme      = errors.New("acquire: a snapshot may only be fetched over https")
	ErrFetchDeadline    = errors.New("acquire: the fetch deadline was reached")
	ErrFetchTooLarge    = errors.New("acquire: the response exceeded the byte cap")
	ErrFetchGzipRatio   = errors.New("acquire: the response expanded past the compression ratio cap")
	ErrFetchRedirects   = errors.New("acquire: too many redirects")
	ErrFetchCrossHost   = errors.New("acquire: a redirect left the origin host")
	ErrFetchStatus      = errors.New("acquire: the server did not return 200")
)

// FetchLimits are the bounds one fetch runs under. Every field is required.
type FetchLimits struct {
	// MaxBytes caps the body, after decompression. A body over it is
	// REFUSED, not truncated: a truncated signed document is a document
	// nobody signed, and it would fail signature verification with a
	// misleading reason.
	MaxBytes int64
	// MaxRedirects caps the chain. Redirects must also stay on the origin
	// host and on https.
	MaxRedirects int
	// MaxGzipRatio caps decompressed bytes per compressed byte. Compression
	// is handled here rather than by net/http, because a transport that
	// gunzips transparently gives no place to measure the ratio.
	MaxGzipRatio float64
	// Deadline is the ONE whole-request deadline. See the package comment.
	Deadline time.Duration
	// RootCAs is the trust anchor set. Nil means the system roots.
	RootCAs *x509.CertPool
}

func (l FetchLimits) unset() bool {
	return l.MaxBytes <= 0 || l.MaxRedirects <= 0 || l.MaxGzipRatio <= 0 || l.Deadline <= 0
}

// Fetch retrieves one snapshot document under the given bounds.
//
// It returns bytes and nothing else. Whether those bytes are a feed anybody
// signed is internal/feed's question, and whether the snapshot they describe
// may be applied is Decide's; keeping the three apart is why none of them can
// be talked into the others' answers.
func Fetch(ctx context.Context, rawURL string, limits FetchLimits) ([]byte, error) {
	if limits.unset() {
		return nil, ErrFetchLimitsUnset
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		// The URL is not echoed. It is configuration and may carry a key.
		return nil, fmt.Errorf("%w: the source URL could not be parsed", ErrFetchScheme)
	}
	// Scheme is compared lowercased because url.Parse does not normalise it
	// for a scheme it does not know, and "HTTP://" must not slip through a
	// case-sensitive equality test.
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return nil, fmt.Errorf("%w: scheme %q", ErrFetchScheme, u.Scheme)
	}

	// ONE deadline, on the context, covering everything. http.Client.Timeout
	// is set to the same value as a second line rather than as the first: a
	// caller that passes an already-cancelled context must still be honoured.
	ctx, cancel := context.WithTimeout(ctx, limits.Deadline)
	defer cancel()

	origin := strings.ToLower(u.Host)
	client := &http.Client{
		Timeout: limits.Deadline,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: limits.RootCAs},
			TLSHandshakeTimeout:   limits.Deadline,
			ResponseHeaderTimeout: limits.Deadline,
			// Compression is NOT delegated. net/http would add
			// Accept-Encoding and gunzip transparently, which removes the
			// place the ratio can be measured.
			DisableCompression: true,
			// A proxy is another party's decision about where this request
			// goes, and the origin check below would be measuring the wrong
			// thing.
			Proxy:               nil,
			MaxIdleConns:        2,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= limits.MaxRedirects {
				return ErrFetchRedirects
			}
			// A redirect is a request the SERVER chose, so the rules that
			// governed the request this process chose are applied again.
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("%w: a redirect tried to downgrade to %q", ErrFetchScheme, req.URL.Scheme)
			}
			if !strings.EqualFold(req.URL.Host, origin) {
				return ErrFetchCrossHost
			}
			return nil
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("acquire: the request could not be built")
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		// Unwrap to the sentinels the redirect policy raised; url.Error
		// wraps them and also quotes the whole URL, which is why the message
		// is rebuilt rather than passed through.
		for _, s := range []error{ErrFetchRedirects, ErrFetchCrossHost, ErrFetchScheme} {
			if errors.Is(err, s) {
				return nil, s
			}
		}
		// A timeout is reported as one whatever layer noticed it. The
		// handshake timeout fires before the context does when both are the
		// same duration, and an operator reading "the fetch failed: TLS
		// handshake timeout" has to know net/http's internals to see that
		// the bound they configured is the thing that worked.
		var ne net.Error
		if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, fmt.Errorf("%w after %s", ErrFetchDeadline, limits.Deadline)
		}
		return nil, fmt.Errorf("acquire: the fetch failed: %s", Redact(err.Error()))
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// The status line is this protocol's own vocabulary; the body is the
		// server's prose and is not repeated.
		return nil, fmt.Errorf("%w: %d", ErrFetchStatus, resp.StatusCode)
	}

	return readBounded(resp, limits)
}

// readBounded reads the body under the byte cap, decompressing if the server
// said it was gzipped, and refuses a body that expands past the ratio cap.
func readBounded(resp *http.Response, limits FetchLimits) ([]byte, error) {
	gzipped := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip")
	if !gzipped {
		body, err := readCapped(resp.Body, limits.MaxBytes)
		if err != nil {
			return nil, err
		}
		return body, nil
	}

	// The COMPRESSED stream is capped too. Without this, a server can make
	// this process read forever at a ratio that never trips the cap.
	compressed, err := readCapped(resp.Body, limits.MaxBytes)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(strings.NewReader(string(compressed)))
	if err != nil {
		return nil, fmt.Errorf("acquire: the response claimed to be gzip and was not")
	}
	defer func() { _ = zr.Close() }()

	// The ratio cap is enforced by reading at most ratio x compressed bytes,
	// so the bomb is never held in memory in the first place. Checking the
	// ratio after decompressing would mean decompressing it.
	ratioCap := int64(float64(len(compressed)) * limits.MaxGzipRatio)
	if ratioCap > limits.MaxBytes {
		ratioCap = limits.MaxBytes
	}
	out, err := readCapped(zr, ratioCap)
	if err != nil {
		if errors.Is(err, ErrFetchTooLarge) && ratioCap < limits.MaxBytes {
			return nil, fmt.Errorf("%w: %d compressed bytes expanded past ×%.0f",
				ErrFetchGzipRatio, len(compressed), limits.MaxGzipRatio)
		}
		return nil, err
	}
	return out, nil
}

// readCapped reads at most max bytes and refuses anything longer.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("acquire: the response could not be read: %s", Redact(err.Error()))
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrFetchTooLarge, max)
	}
	return b, nil
}
