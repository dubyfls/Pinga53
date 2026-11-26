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
	body := readTestdata(t, "urlhaus_sample.csv")
	records, err := parseURLhausCSV(body, time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("parseURLhausCSV: %v", err)
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

func TestURLhausParseLenient(t *testing.T) {
	// CSV parsing is deliberately lenient: junk yields zero records, not an
	// error, so one malformed dump never abandons a whole fetch cycle.
	recs, err := parseURLhausCSV([]byte("not a dump\n"), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("want 0 records from junk, got %d", len(recs))
	}
}

func TestURLhausParseEmpty(t *testing.T) {
	// Only comment lines, no rows.
	body := []byte("# id,dateadded,url,url_status\n")
	records, err := parseURLhausCSV(body, time.Now())
	if err != nil {
		t.Fatalf("parseURLhausCSV empty: %v", err)
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
	// The Auth-Key is now part of the export path.
	keyedURL := URLhausExportBase + secret + "/recent.csv"
	fake := newFakeHTTP()
	fake.set(keyedURL, readTestdata(t, "urlhaus_sample.csv"), map[string]string{"ETag": `"abc"`}, nil)
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
	// The key must have been placed in the request path (new API).
	if !fake.sawString(secret) {
		t.Fatalf("Auth-Key not present in the request URL path")
	}
	// Cache must have been written…
	cacheBytes, err := os.ReadFile(filepath.Join(dir, "cache.json"))
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	// …and must NOT contain the key (cache is keyed by a key-less id).
	if strings.Contains(string(cacheBytes), secret) {
		t.Fatalf("Auth-Key leaked into the cache file")
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
	// The key is now in the URL path, so an error carrying the URL would
	// carry the key — redactKey must strip it.
	keyedURL := URLhausExportBase + secret + "/recent.csv"
	fake := newFakeHTTP()
	fake.set(keyedURL, nil, nil, errWithKey(secret))
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
