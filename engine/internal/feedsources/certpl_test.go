// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"testing"
	"time"
)

func TestCERTPolskaParseText(t *testing.T) {
	body := readTestdata(t, "certpl_sample.txt")
	records, err := parseCERTPolska(body, time.Now())
	if err != nil {
		t.Fatalf("parseCERTPolska: %v", err)
	}
	got := map[string]bool{}
	for _, r := range records {
		got[r.Value] = true
	}
	want := []string{"scam1.example.pl", "scam2.example.pl", "scam3.example.pl"}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("missing %q; got %v", w, got)
		}
	}
	// '.example.pl' is a public-suffix-only shape; it must not survive.
	if got[".example.pl"] {
		t.Fatalf("public-suffix-only survived: %v", got)
	}
}

func TestCERTPolskaParseJSON(t *testing.T) {
	body := readTestdata(t, "certpl_sample.json")
	records, err := parseCERTPolska(body, time.Now())
	if err != nil {
		t.Fatalf("parseCERTPolska JSON: %v", err)
	}
	got := map[string]bool{}
	for _, r := range records {
		got[r.Value] = true
	}
	if !got["scam-json1.example.pl"] || !got["scam-json3.example.pl"] {
		t.Fatalf("missing active entries: %v", got)
	}
	if got["scam-json2.example.pl"] {
		t.Fatalf("deleted entry survived: %v", got)
	}
}

func TestCERTPolskaParseMalformed(t *testing.T) {
	_, err := parseCERTPolska([]byte("[not valid json"), time.Now())
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCERTPolskaParseEmpty(t *testing.T) {
	records, err := parseCERTPolska([]byte(""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d", len(records))
	}
}
