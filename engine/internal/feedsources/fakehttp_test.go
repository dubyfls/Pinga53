// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// fakeHTTP is the test seam for HTTPClient. It is keyed by URL and returns
// bytes-headers-error tuples. Key material supplied in request headers can
// be asserted via SawRequest.
type fakeHTTP struct {
	responses map[string]fakeResponse
	seen      []fakeRequest
}

type fakeResponse struct {
	body    []byte
	headers map[string]string
	err     error
}

type fakeRequest struct {
	url     string
	headers map[string]string
}

func newFakeHTTP() *fakeHTTP { return &fakeHTTP{responses: map[string]fakeResponse{}} }

func (f *fakeHTTP) set(url string, body []byte, headers map[string]string, err error) {
	f.responses[url] = fakeResponse{body: body, headers: headers, err: err}
}

func (f *fakeHTTP) Get(_ context.Context, url string, reqHeaders map[string]string) ([]byte, map[string]string, error) {
	// Copy headers so a later mutation by the caller is not visible.
	snap := map[string]string{}
	for k, v := range reqHeaders {
		snap[k] = v
	}
	f.seen = append(f.seen, fakeRequest{url: url, headers: snap})
	r, ok := f.responses[url]
	if !ok {
		return nil, nil, fmt.Errorf("fakeHTTP: no stub for %s", url)
	}
	return r.body, r.headers, r.err
}

// sawRequestWithHeader returns true if any request to url carried the given
// header key, with the given value (or any value when wantValue == "").
func (f *fakeHTTP) sawRequestWithHeader(url, key, wantValue string) bool {
	for _, r := range f.seen {
		if r.url != url {
			continue
		}
		got, ok := r.headers[key]
		if !ok {
			continue
		}
		if wantValue == "" || got == wantValue {
			return true
		}
	}
	return false
}

// sawRequestWithoutKeyInAnyField fails if a credential-looking value appears
// anywhere in the recorded requests. Used by the "keys never leak" tests.
func (f *fakeHTTP) sawString(needle string) bool {
	if needle == "" {
		return false
	}
	for _, r := range f.seen {
		if strings.Contains(r.url, needle) {
			return true
		}
		for _, v := range r.headers {
			if strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}

// urls returns the URLs the fake was asked about, in call order.
func (f *fakeHTTP) urls() []string {
	out := make([]string, 0, len(f.seen))
	for _, r := range f.seen {
		out = append(out, r.url)
	}
	return out
}

// sortedConfiguredURLs lists stubbed URLs for diagnostics.
func (f *fakeHTTP) sortedConfiguredURLs() []string {
	out := make([]string, 0, len(f.responses))
	for u := range f.responses {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// errNoSuchURL is what the fake returns when asked about a URL it has no
// stub for; mapped to a sentinel for test clarity.
var errNoSuchURL = errors.New("fakeHTTP: no stub")
