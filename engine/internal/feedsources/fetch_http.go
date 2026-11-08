// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/audit"
)

// productionHTTPClient is the default HTTPClient. It is a thin wrapper
// around a bounded net/http.Client — this duplicates some of acquire.Fetch's
// behaviour on purpose, because:
//
//   - A fetcher cares about response HEADERS (ETag, Last-Modified), which
//     acquire.Fetch deliberately does not expose.
//   - A fetcher wants to send REQUEST headers (Auth-Key, If-None-Match),
//     which acquire.Fetch deliberately does not accept.
//   - acquire.Fetch refuses redirects across hosts and requires https:
//     those are the same rules this client enforces.
//
// Redacting key material from an error message is delegated to
// internal/audit.RedactURLs, the one place that redaction lives.
type productionHTTPClient struct {
	client   *http.Client
	maxBytes int64
	ua       string
}

// NewHTTPClient builds a bounded https-only client with the given deadline
// and max-bytes cap. Use the Options.HTTPClient seam in tests; this is what
// a real `scamwall fetch` run uses.
func NewHTTPClient(deadline time.Duration, maxBytes int64, userAgent string) HTTPClient {
	if deadline <= 0 {
		deadline = 30 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = MaxBodyBytes
	}
	if userAgent == "" {
		userAgent = "scamwall-fetch/1 (+https://github.com/dubyfls/Pinga53/engine)"
	}
	return &productionHTTPClient{
		client: &http.Client{
			Timeout: deadline,
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout:   deadline,
				ResponseHeaderTimeout: deadline,
				DisableCompression:    true,
				Proxy:                 nil,
				ForceAttemptHTTP2:     true,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("feedsources: too many redirects")
				}
				if !strings.EqualFold(req.URL.Scheme, "https") {
					return fmt.Errorf("feedsources: a redirect tried to downgrade to %q", req.URL.Scheme)
				}
				if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
					return errors.New("feedsources: a redirect left the origin host")
				}
				return nil
			},
		},
		maxBytes: maxBytes,
		ua:       userAgent,
	}
}

func (p *productionHTTPClient) Get(ctx context.Context, rawURL string, reqHeaders map[string]string) ([]byte, map[string]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, errors.New("feedsources: URL could not be parsed")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return nil, nil, fmt.Errorf("feedsources: URL is not https: scheme=%q", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("feedsources: could not build request: %w", err)
	}
	req.Header.Set("User-Agent", p.ua)
	req.Header.Set("Accept-Encoding", "gzip")
	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("feedsources: fetch failed: %s", audit.RedactURLs(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	headers := map[string]string{}
	for _, k := range []string{"ETag", "Last-Modified", "Content-Type", "Date"} {
		if v := resp.Header.Get(k); v != "" {
			headers[k] = v
		}
	}
	// 304 is not-modified — return no body, no error, let the caller
	// fall back to the cached records.
	if resp.StatusCode == http.StatusNotModified {
		return nil, headers, ErrNotFresh
	}
	if resp.StatusCode != http.StatusOK {
		return nil, headers, fmt.Errorf("feedsources: HTTP %d", resp.StatusCode)
	}

	body, err := readBoundedBody(resp, p.maxBytes)
	if err != nil {
		return nil, headers, err
	}
	return body, headers, nil
}

func readBoundedBody(resp *http.Response, max int64) ([]byte, error) {
	gzipped := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip")
	if !gzipped {
		return readCapped(resp.Body, max)
	}
	compressed, err := readCapped(resp.Body, max)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, errors.New("feedsources: body claimed gzip but was not")
	}
	defer func() { _ = zr.Close() }()
	return readCapped(zr, max)
}

func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("feedsources: body read failed: %s", audit.RedactURLs(err.Error()))
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("feedsources: body exceeded %d bytes", max)
	}
	return b, nil
}

// --- cache -----------------------------------------------------------------

// cacheEntry is what a fetcher persists between runs so it can send
// If-None-Match and If-Modified-Since.
type cacheEntry struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// loadCache reads a per-source cache file. Missing or unreadable returns a
// zero entry, not an error: a cache miss is normal.
func loadCache(path string) cacheEntry {
	if path == "" {
		return cacheEntry{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cacheEntry{}
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return cacheEntry{}
	}
	return e
}

// saveCache writes a per-source cache file. Failures are diagnostic but not
// fatal: a run that could not update its cache is a run that will re-fetch
// unconditionally next time, which is noisy but correct.
func saveCache(path string, e cacheEntry) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("feedsources: marshal cache: %w", err)
	}
	// atomicfile would be better here but a stale cache is recoverable;
	// the fetcher is not willing to add a dependency just for this.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return fmt.Errorf("feedsources: write cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("feedsources: rename cache: %w", err)
	}
	return nil
}

// cacheHeaders builds the conditional-request headers for a cached URL.
// Only emits headers whose values the cache actually carries.
func cacheHeaders(e cacheEntry, forURL string) map[string]string {
	if e.URL != forURL {
		return nil
	}
	h := map[string]string{}
	if e.ETag != "" {
		h["If-None-Match"] = e.ETag
	}
	if e.LastModified != "" {
		h["If-Modified-Since"] = e.LastModified
	}
	return h
}

// retryBackoff returns the nth retry delay: 1 s, 3 s, 9 s (bounded to 30 s).
// Only three retries, so a stuck provider does not become a loop that
// consumes the whole systemd timer window.
//
// Overridden to zero in tests so a retry loop doesn't wait for seconds that
// prove nothing.
var retryBackoff = func(n int) time.Duration {
	switch n {
	case 0:
		return time.Second
	case 1:
		return 3 * time.Second
	case 2:
		return 9 * time.Second
	default:
		return 30 * time.Second
	}
}

// doWithRetry runs f up to `attempts` times with exponential backoff,
// returning the last error on persistent failure. ErrNotFresh is NOT
// retried — a 304 is a success for the caller.
//
// The body is intentionally short: fetcher authors should not need to
// read this to understand their own retries. The scamwall-fetch service
// itself retries at the timer level too — one missed cycle means the next
// cycle picks up.
func doWithRetry(ctx context.Context, attempts int, f func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = f()
		if err == nil || errors.Is(err, ErrNotFresh) {
			return err
		}
		if ctx.Err() != nil {
			return err
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-time.After(retryBackoff(i)):
		case <-ctx.Done():
			return err
		}
	}
	return err
}
