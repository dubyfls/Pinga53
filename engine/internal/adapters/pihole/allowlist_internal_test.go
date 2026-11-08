// SPDX-License-Identifier: AGPL-3.0-only

// This file is in package pihole rather than pihole_test because the property
// under test is that an unsupported operation is refused BEFORE any network
// activity, and the only way to ask for one is to call the unexported
// transport directly. Driving it through an exported method could not
// distinguish "refused early" from "refused because no server was listening".
package pihole

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/audit"
	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// clientWithUnreachableOrigin builds a client pointed at an address that
// nothing is listening on.
//
// That is the discriminator. If the permitted-operation check runs first, a
// forbidden request fails with ErrOperationNotPermitted and the unreachable
// address is never contacted. If the check were moved after the request was
// issued — or removed — the same call would fail with a dial error instead, and
// every assertion below would notice.
func clientWithUnreachableOrigin(t *testing.T) *Client {
	t.Helper()
	// A real, throwaway CA. Generated rather than written as a literal: a
	// certificate literal in the tree is what the secret scanner exists to
	// catch, and a hand-written one that does not parse would make New fail
	// for a reason unrelated to what is being tested.
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ScamWall Allowlist Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Pihole.Host = "pi.hole"
	cfg.Pihole.Port = 1
	// 127.0.0.1:1 is reserved and refuses immediately, so a test that DID
	// reach the network would fail fast rather than hang.
	cfg.Pihole.AddressOverride = "127.0.0.1:1"
	cfg.Pihole.CAPath = caPath
	cfg.Pihole.ConnectTimeout = config.Duration(500 * time.Millisecond)
	cfg.Pihole.RequestTimeout = config.Duration(500 * time.Millisecond)
	cfg.Pihole.TotalTimeout = config.Duration(time.Second)

	c, err2 := New(cfg, audit.New(os.Stderr))
	if err2 != nil {
		t.Fatalf("New: %v", err2)
	}
	return c
}

func TestUnpermittedOperationsAreRefusedBeforeAnyNetworkActivity(t *testing.T) {
	c := clientWithUnreachableOrigin(t)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"a mutating method on an approved path", http.MethodPut, epAuth},
		{"a patch on an approved path", http.MethodPatch, epVersion},
		{"a delete on the version endpoint", http.MethodDelete, epVersion},
		{"a post to the version endpoint", http.MethodPost, epVersion},
		{"an unknown read endpoint", http.MethodGet, "/api/queries"},
		{"an unknown write endpoint", http.MethodPost, "/api/groups"},
		{"a path that merely starts with an approved one", http.MethodGet, epVersion + "/../config"},
		{"an empty path", http.MethodGet, ""},
		{"the API root", http.MethodGet, "/api"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.do(context.Background(), tc.method, tc.path, nil, nil)
			if !errors.Is(err, ErrOperationNotPermitted) {
				t.Fatalf("got %v, want ErrOperationNotPermitted", err)
			}
		})
	}
}

func TestEveryPermittedOperationIsReachable(t *testing.T) {
	// The complement of the test above: the allowlist must not have grown a
	// typo that silently forbids something the client actually issues.
	c := clientWithUnreachableOrigin(t)
	for _, op := range PermittedOperations {
		t.Run(op.Method+" "+op.Path, func(t *testing.T) {
			err := c.do(context.Background(), op.Method, op.Path, nil, nil)
			if errors.Is(err, ErrOperationNotPermitted) {
				t.Fatalf("a permitted operation was refused by the allowlist: %v", err)
			}
			// It must fail — nothing is listening — but for a transport reason.
			if err == nil {
				t.Fatal("expected a transport failure against an unreachable origin")
			}
		})
	}
}

func TestPermittedOperationsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range PermittedOperations {
		key := op.Method + " " + op.Path
		if seen[key] {
			t.Errorf("duplicate entry %q", key)
		}
		seen[key] = true
		if op.Why == "" {
			t.Errorf("%s has no justification recorded", key)
		}
		if op.Method != http.MethodGet && op.Retryable {
			t.Errorf("%s is a non-GET marked retryable; a non-GET is not automatically safe to repeat", key)
		}
		if op.Path != epAuth && op.Method != http.MethodGet {
			t.Errorf("%s is a non-GET outside the session endpoint, which the read-only contract forbids", key)
		}
	}

	// THE DOCUMENT IS COMPARED, NOT COUNTED.
	//
	// This was `len(PermittedOperations) != 4`, which caught a table growing
	// and said nothing about whether the prose described the SAME operations.
	// Two entries swapped, or one renamed, left the count right and the
	// contract wrong. Adding an operation now requires writing the row.
	doc, err := os.ReadFile(filepath.Join(repoRootFromHere(t), "docs", "PIHOLE_API_CONTRACT.md"))
	if err != nil {
		t.Fatalf("read the API contract: %v", err)
	}
	// THE SECTION-7 TABLE, NOT THE WHOLE DOCUMENT.
	//
	// The file carries other tables of observed responses — `GET /api/docs`
	// answering 301, for one — and those are records of what the appliance
	// DID, not statements about what this client may construct. Matching
	// every table row in the file made the second of them a false failure.
	// The table is located by its own header row and ends at the first blank
	// line, so a row added to it is compared and a row added elsewhere is not.
	const header = "| Operation | Retried | Why it is permitted |"
	i := strings.Index(string(doc), header)
	if i < 0 {
		t.Fatalf("docs/PIHOLE_API_CONTRACT.md no longer contains the permitted-operations table "+
			"header %q; this test cannot check what it cannot find", header)
	}
	table := string(doc)[i:]
	if j := strings.Index(table, "\n\n"); j >= 0 {
		table = table[:j]
	}
	row := regexp.MustCompile("(?m)^\\| `([A-Z]+) (/api/[^`]+)` \\|")
	described := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(table, -1) {
		described[m[1]+" "+m[2]] = true
	}
	for key := range seen {
		if !described[key] {
			t.Errorf("%s is permitted at run time and is not described in "+
				"docs/PIHOLE_API_CONTRACT.md section 7. Update both together.", key)
		}
	}
	for key := range described {
		if !seen[key] {
			t.Errorf("docs/PIHOLE_API_CONTRACT.md section 7 describes %s, which the run-time "+
				"allowlist does not permit. Update both together.", key)
		}
	}
}

// repoRootFromHere walks up to the module root. The internal test file cannot
// use the external suite's helper of the same purpose.
func repoRootFromHere(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the module root")
	return ""
}

func TestParseRetryAfter(t *testing.T) {
	base := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"absent", "", 0},
		{"delta seconds", "2", 2 * time.Second},
		{"zero", "0", 0},
		{"negative", "-5", 0},
		{"capped", "86400", maxRetryDelay},
		{"not a number", "soon", 0},
		{"an HTTP date in the future", base.Add(3 * time.Second).Format(http.TimeFormat), 3 * time.Second},
		{"an HTTP date in the past", base.Add(-time.Hour).Format(http.TimeFormat), 0},
		{"an HTTP date far in the future is capped", base.Add(24 * time.Hour).Format(http.TimeFormat), maxRetryDelay},
		{"whitespace only", "   ", 0},
		{"a value that would overflow", "9223372036854775807", maxRetryDelay},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.in, base); got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRetryDelayNeverExceedsTheCap(t *testing.T) {
	c := clientWithUnreachableOrigin(t)
	c.cfg.Pihole.RetryBaseDelay = config.Duration(time.Hour)
	for attempt := range 8 {
		if d := c.retryDelay(nil, attempt); d > maxRetryDelay {
			t.Fatalf("attempt %d: delay %v exceeds the cap %v", attempt, d, maxRetryDelay)
		}
	}
	// And with a server that asked for far longer than the cap.
	long := &APIError{Status: http.StatusTooManyRequests, RetryAfter: 24 * time.Hour}
	if d := c.retryDelay(long, 0); d > maxRetryDelay {
		t.Fatalf("a server-requested delay was not capped: %v", d)
	}
}
