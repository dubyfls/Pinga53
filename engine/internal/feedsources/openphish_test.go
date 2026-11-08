// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"testing"
	"time"
)

func TestOpenPhishParseFixture(t *testing.T) {
	body := readTestdata(t, "openphish_sample.txt")
	records, err := parseOpenPhish(body, time.Now())
	if err != nil {
		t.Fatalf("parseOpenPhish: %v", err)
	}
	got := map[string]bool{}
	for _, r := range records {
		got[r.Value] = true
		if r.Classification != "malicious" {
			t.Fatalf("classification: %+v", r)
		}
		if r.SourceID != OpenPhishSourceID {
			t.Fatalf("source_id: %+v", r)
		}
	}
	want := []string{"phish1.example.com", "phish2.example.net", "phish3.example.org", "phish4.example.com"}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("missing %q; got %v", w, got)
		}
	}
	if got["192.0.2.5"] || got["not-a-url-at-all"] {
		t.Fatalf("bad entries survived: %v", got)
	}
	// Dedupe worked: phish1 appears twice in the fixture, once in records.
	count := 0
	for _, r := range records {
		if r.Value == "phish1.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 phish1 record after dedupe, got %d", count)
	}
}

func TestOpenPhishParseEmpty(t *testing.T) {
	records, err := parseOpenPhish([]byte(""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0, got %d", len(records))
	}
}

func TestOpenPhishFetchCachedNotFresh(t *testing.T) {
	fake := newFakeHTTP()
	fake.set(OpenPhishURL, nil, map[string]string{"ETag": `"abc"`}, ErrNotFresh)
	o := NewOpenPhish()
	_, err := o.Fetch(context.Background(), Options{HTTPClient: fake})
	if err != ErrNotFresh {
		t.Fatalf("expected ErrNotFresh, got %v", err)
	}
}
