// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"testing"
	"time"
)

func TestPhishingDBParseFixture(t *testing.T) {
	body := readTestdata(t, "phishingdb_sample.txt")
	records, err := parsePhishingDB(body, time.Now())
	if err != nil {
		t.Fatalf("parsePhishingDB: %v", err)
	}
	got := map[string]bool{}
	for _, r := range records {
		got[r.Value] = true
		if r.Classification != "malicious" {
			t.Fatalf("classification: %+v", r)
		}
	}
	want := []string{"brand-support-signin.net", "customersupport-login.example.net", "secure-update.example.org"}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("missing %q; got %v", w, got)
		}
	}
	if got["localhost"] {
		t.Fatal("localhost survived normalisation")
	}
	// Dedupe check.
	count := 0
	for _, r := range records {
		if r.Value == "brand-support-signin.net" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 dedup'd record, got %d", count)
	}
}

func TestPhishingDBFetchHappy(t *testing.T) {
	fake := newFakeHTTP()
	fake.set(PhishingDBURL, readTestdata(t, "phishingdb_sample.txt"), map[string]string{"ETag": `"xyz"`}, nil)
	p := NewPhishingDB()
	records, err := p.Fetch(context.Background(), Options{HTTPClient: fake, Now: time.Now()})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(records) < 3 {
		t.Fatalf("records: got %d", len(records))
	}
}

func TestPhishingDBParseEmpty(t *testing.T) {
	records, err := parsePhishingDB([]byte(""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d", len(records))
	}
}
