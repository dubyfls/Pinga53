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

func TestThreatFoxParseFixture(t *testing.T) {
	body := readTestdata(t, "threatfox_sample.json")
	records, err := parseThreatFox(body, time.Now())
	if err != nil {
		t.Fatalf("parseThreatFox: %v", err)
	}
	// Expected: evil.example.net (domain) + phish.example.org (url → host).
	// IP:port and md5 are dropped.
	got := map[string]string{}
	for _, r := range records {
		got[r.Value] = r.Classification
	}
	if got["evil.example.net"] != "malicious" {
		t.Fatalf("expected evil.example.net malicious, got %q", got["evil.example.net"])
	}
	if got["phish.example.org"] != "suspicious" {
		t.Fatalf("expected phish.example.org suspicious (confidence 40), got %q", got["phish.example.org"])
	}
	if _, has := got["203.0.113.17"]; has {
		t.Fatalf("IP survived normalisation: %v", got)
	}
}

func TestThreatFoxParseMalformed(t *testing.T) {
	_, err := parseThreatFox([]byte("{"), time.Now())
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestThreatFoxParseEmpty(t *testing.T) {
	records, err := parseThreatFox([]byte(`{"query_status":"no_result","data":[]}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0, got %d", len(records))
	}
}

func TestThreatFoxFetchHappy(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "abusech.key")
	secret := "tf-secret-xyz"
	if err := os.WriteFile(keyPath, []byte(secret), 0o640); err != nil {
		t.Fatal(err)
	}
	fake := newFakeHTTP()
	tf := NewThreatFox()
	url := "https://threatfox-api.abuse.ch/api/v1/?get_iocs=3"
	fake.set(url, readTestdata(t, "threatfox_sample.json"), nil, nil)
	records, err := tf.Fetch(context.Background(), Options{
		KeyPath:    keyPath,
		HTTPClient: fake,
		Now:        time.Now(),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(records) < 2 {
		t.Fatalf("records: got %d", len(records))
	}
	if !fake.sawRequestWithHeader(url, "Auth-Key", secret) {
		t.Fatalf("Auth-Key not sent")
	}
}

func TestThreatFoxKeyNeverAppearsInError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "abusech.key")
	secret := "tf-secret-ABCDEF"
	if err := os.WriteFile(keyPath, []byte(secret), 0o640); err != nil {
		t.Fatal(err)
	}
	fake := newFakeHTTP()
	fake.set("https://threatfox-api.abuse.ch/api/v1/?get_iocs=3", nil, nil, errWithKey(secret))
	tf := NewThreatFox()
	_, err := tf.Fetch(context.Background(), Options{
		KeyPath:    keyPath,
		HTTPClient: fake,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("key leaked: %v", err)
	}
}
