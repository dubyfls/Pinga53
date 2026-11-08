// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestURLhausParseFixture(t *testing.T) {
	body := readTestdata(t, "urlhaus_sample.json")
	records, err := parseURLhaus(body, time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("parseURLhaus: %v", err)
	}
	// Expected after filtering/normalisation: 2 records (evil.example.com,
	// another.evil.example.com — the second after lowercasing), no IP, no
	// offline.
	gotValues := map[string]bool{}
	for _, r := range records {
		gotValues[r.Value] = true
		if r.Classification != "malicious" {
			t.Fatalf("classification: %+v", r)
		}
		if r.SourceID != URLhausSourceID {
			t.Fatalf("source_id: %+v", r)
		}
		if r.RawRetention != "none" {
			t.Fatalf("raw_retention: %+v", r)
		}
	}
	wantValues := []string{"evil.example.com", "another.evil.example.com"}
	for _, w := range wantValues {
		if !gotValues[w] {
			t.Fatalf("missing expected host %q; got %v", w, gotValues)
		}
	}
	for _, r := range records {
		if strings.Contains(r.Value, "192.0.2.5") {
			t.Fatalf("IP literal survived normalisation: %+v", r)
		}
	}
}

func TestURLhausParseMalformed(t *testing.T) {
	_, err := parseURLhaus([]byte("not json {"), time.Now())
	if err == nil {
		t.Fatal("expected parse error for malformed body")
	}
}

func TestURLhausParseEmpty(t *testing.T) {
	// query_status ok but zero URLs.
	body := []byte(`{"query_status":"ok","urls":[]}`)
	records, err := parseURLhaus(body, time.Now())
	if err != nil {
		t.Fatalf("parseURLhaus empty: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("empty: want 0, got %d", len(records))
	}
}

func TestURLhausFetchHappy(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "abusech.key")
	secret := "super-secret-abusech-key-xyz"
	if err := os.WriteFile(keyPath, []byte(secret+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	fake := newFakeHTTP()
	fake.set(URLhausURL, readTestdata(t, "urlhaus_sample.json"), map[string]string{"ETag": `"abc"`}, nil)
	u := NewURLhaus()
	records, err := u.Fetch(context.Background(), Options{
		KeyPath:    keyPath,
		HTTPClient: fake,
		Now:        time.Now(),
		Timeout:    time.Second,
		CachePath:  filepath.Join(dir, "cache.json"),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(records) < 2 {
		t.Fatalf("records: got %d, want >= 2", len(records))
	}
	// Auth-Key must have been sent.
	if !fake.sawRequestWithHeader(URLhausURL, "Auth-Key", secret) {
		t.Fatalf("Auth-Key header not sent to URLhaus")
	}
	// Cache must have been written.
	if _, err := os.Stat(filepath.Join(dir, "cache.json")); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
}

func TestURLhausFetchMissingKey(t *testing.T) {
	u := NewURLhaus()
	_, err := u.Fetch(context.Background(), Options{
		KeyPath:    "/tmp/does-not-exist-abcxyz.key",
		HTTPClient: newFakeHTTP(),
	})
	if err == nil {
		t.Fatalf("expected ErrKeyFileMissing")
	}
	if !strings.Contains(err.Error(), "credential file is missing") {
		t.Fatalf("got %v", err)
	}
}

func TestURLhausKeyNeverAppearsInError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "abusech.key")
	secret := "super-secret-abusech-key-SHOULD-NEVER-LEAK"
	if err := os.WriteFile(keyPath, []byte(secret+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Make the fake error out carrying the URL (which does NOT contain the
	// key — URLhaus uses a header — but a defensive check anyway).
	fake := newFakeHTTP()
	fake.set(URLhausURL, nil, nil, errWithKey(secret))
	u := NewURLhaus()
	_, err := u.Fetch(context.Background(), Options{
		KeyPath:    keyPath,
		HTTPClient: fake,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("key leaked in error: %v", err)
	}
}

// --- helpers ----

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

// errWithKey is a test-only error whose message contains the secret. It
// stands in for a production error path that might accidentally interpolate
// a request URL or header value.
type errWithKey string

func (e errWithKey) Error() string { return "boom secret=" + string(e) }
