// SPDX-License-Identifier: AGPL-3.0-only

package acquire_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/acquire"
)

// C-13 — the bounds a fetch has to carry, and the one that is almost always
// missing.
//
// A read deadline is easy and covers the wrong thing. The dangerous server is
// the one that accepts the TCP connection and then says nothing at all: there
// is no response to read, so a response deadline never fires, and the fetch
// sits there holding a file descriptor until something else gives up. The
// deadline has to cover the handshake, which means it has to be on the
// request context rather than on the body read.

func testLimits() acquire.FetchLimits {
	return acquire.FetchLimits{
		MaxBytes:     1 << 20,
		MaxRedirects: 3,
		MaxGzipRatio: 20,
		Deadline:     2 * time.Second,
	}
}

func poolFor(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

// TestASilentServerFailsInsideTheDeadline is the case this control exists for.
// The listener accepts TCP and never speaks TLS.
func TestASilentServerFailsInsideTheDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold it open and say nothing. Closing it here would make this
			// test pass for the wrong reason.
			defer func() { _ = c.Close() }()
		}
	}()

	lim := testLimits()
	lim.Deadline = 400 * time.Millisecond

	start := time.Now()
	_, err = acquire.Fetch(context.Background(), "https://"+ln.Addr().String()+"/feed.json", lim)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("a server that never spoke TLS returned a snapshot")
	}
	// Generous, because a CI host is not a stopwatch — but far below the
	// minutes an unbounded handshake would take.
	if elapsed > 5*time.Second {
		t.Fatalf("the fetch took %s against a deadline of %s; the deadline does not cover the handshake",
			elapsed.Round(time.Millisecond), lim.Deadline)
	}
	if !errors.Is(err, acquire.ErrFetchDeadline) && !strings.Contains(err.Error(), "deadline") &&
		!strings.Contains(err.Error(), "context") {
		t.Errorf("error = %v; it should say the deadline was reached", err)
	}
}

func TestPlainHTTPIsRefusedWithoutATouchingTheNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("the fetcher connected to a plaintext server")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	_, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", testLimits())
	if !errors.Is(err, acquire.ErrFetchScheme) {
		t.Fatalf("err = %v, want %v", err, acquire.ErrFetchScheme)
	}
}

func TestOnlyHTTPSSchemesAreAccepted(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"ftp://feeds.example.com/list",
		"//feeds.example.com/list",
		"feeds.example.com/list",
		"HTTP://feeds.example.com/list",
	} {
		if _, err := acquire.Fetch(context.Background(), raw, testLimits()); !errors.Is(err, acquire.ErrFetchScheme) {
			t.Errorf("Fetch(%q) err = %v, want %v", raw, err, acquire.ErrFetchScheme)
		}
	}
}

func TestABodyOverTheCapIsRefusedRatherThanTruncated(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 100 {
			_, _ = w.Write(big)
		}
	}))
	defer srv.Close()

	lim := testLimits()
	lim.MaxBytes = 1000
	lim.RootCAs = poolFor(t, srv)

	body, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim)
	if !errors.Is(err, acquire.ErrFetchTooLarge) {
		t.Fatalf("err = %v, want %v", err, acquire.ErrFetchTooLarge)
	}
	// Truncation is the wrong answer: a truncated signed document is a
	// document nobody signed, and it would fail signature verification with a
	// misleading reason.
	if len(body) != 0 {
		t.Errorf("a refused fetch returned %d bytes", len(body))
	}
}

func TestAGzipBombIsRefusedOnItsRatio(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// 4 MiB of zeroes compresses to a few KiB — a ratio far past any real feed.
	if _, err := zw.Write(bytes.Repeat([]byte{0}, 4<<20)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	payload := buf.Bytes()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	lim := testLimits()
	lim.RootCAs = poolFor(t, srv)
	lim.MaxBytes = 8 << 20 // deliberately larger than the bomb, so only the ratio can refuse it
	lim.MaxGzipRatio = 20

	if _, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim); !errors.Is(err, acquire.ErrFetchGzipRatio) {
		t.Fatalf("err = %v, want %v: %d compressed bytes expanded past the ratio cap", err, acquire.ErrFetchGzipRatio, len(payload))
	}
}

func TestAnHonestGzipBodyIsAccepted(t *testing.T) {
	// The control on the control: the ratio cap must not refuse ordinary
	// compression, or nobody can serve a compressed feed.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`{"schema_version":2,"hosts":["a.example.com","b.example.com"]}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	_ = zw.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	lim := testLimits()
	lim.RootCAs = poolFor(t, srv)

	body, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim)
	if err != nil {
		t.Fatalf("an ordinary compressed body was refused: %v", err)
	}
	if !strings.Contains(string(body), "a.example.com") {
		t.Errorf("body = %q", body)
	}
}

func TestRedirectsAreBoundedAndSameHost(t *testing.T) {
	t.Run("a chain longer than the cap is refused", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, srv.URL+r.URL.Path+"x", http.StatusFound)
		}))
		defer srv.Close()

		lim := testLimits()
		lim.RootCAs = poolFor(t, srv)
		if _, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim); !errors.Is(err, acquire.ErrFetchRedirects) {
			t.Fatalf("err = %v, want %v", err, acquire.ErrFetchRedirects)
		}
	})

	t.Run("a redirect to another host is refused", func(t *testing.T) {
		other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Errorf("the fetcher followed a redirect to a second host")
			_, _ = w.Write([]byte("{}"))
		}))
		defer other.Close()

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/feed.json", http.StatusFound)
		}))
		defer srv.Close()

		pool := poolFor(t, srv)
		pool.AddCert(other.Certificate())
		lim := testLimits()
		lim.RootCAs = pool

		if _, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim); !errors.Is(err, acquire.ErrFetchCrossHost) {
			t.Fatalf("err = %v, want %v", err, acquire.ErrFetchCrossHost)
		}
	})

	t.Run("a redirect downgrading to http is refused", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host+"/feed.json", http.StatusFound)
		}))
		defer srv.Close()

		lim := testLimits()
		lim.RootCAs = poolFor(t, srv)
		if _, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim); !errors.Is(err, acquire.ErrFetchScheme) {
			t.Fatalf("err = %v, want %v", err, acquire.ErrFetchScheme)
		}
	})
}

func TestUnsetLimitsAreRefused(t *testing.T) {
	if _, err := acquire.Fetch(context.Background(), "https://feeds.example.com/x", acquire.FetchLimits{}); !errors.Is(err, acquire.ErrFetchLimitsUnset) {
		t.Fatalf("err = %v, want %v: an unset bound is not an unbounded one", err, acquire.ErrFetchLimitsUnset)
	}
}

func TestANonOKStatusIsNotASnapshot(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("something went wrong on our end"))
	}))
	defer srv.Close()

	lim := testLimits()
	lim.RootCAs = poolFor(t, srv)
	body, err := acquire.Fetch(context.Background(), srv.URL+"/feed.json", lim)
	if err == nil {
		t.Fatalf("a 500 was returned as a snapshot")
	}
	if len(body) != 0 {
		t.Errorf("a failed fetch returned %d bytes", len(body))
	}
	if strings.Contains(err.Error(), "something went wrong on our end") {
		t.Errorf("the error reproduces the server's body: %v", err)
	}
}
