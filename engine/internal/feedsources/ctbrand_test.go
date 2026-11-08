// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCTBrandParseFixture(t *testing.T) {
	body := readTestdata(t, "ctbrand_sample.json")
	records, err := parseCTBrand(body, "brand", time.Now())
	if err != nil {
		t.Fatalf("parseCTBrand: %v", err)
	}
	got := map[string]string{}
	for _, r := range records {
		got[r.Value] = r.Classification
		if r.SourceID != CTBrandSourceID {
			t.Fatalf("source id: %+v", r)
		}
		if r.Category != "brand" {
			t.Fatalf("category: %+v", r)
		}
	}
	// brand.com itself must be excluded — it's the brand's own cert.
	if _, has := got["brand.com"]; has {
		t.Fatalf("brand.com (the brand itself) survived: %v", got)
	}
	// Related SANs must be present as `suspicious`.
	want := []string{"brand-support-signin.net", "www.brand-support-signin.net", "customerportal.brand.com", "secure-brand-login.org"}
	for _, w := range want {
		if got[w] != "suspicious" {
			t.Fatalf("expected %q suspicious, got %q (all %v)", w, got[w], got)
		}
	}
	// Unrelated names must be dropped.
	if _, has := got["unrelated.example.com"]; has {
		t.Fatalf("unrelated SAN survived: %v", got)
	}
}

func TestCTBrandEmptyBrandList(t *testing.T) {
	dir := t.TempDir()
	c := NewCTBrand()
	c.BrandsPath = filepath.Join(dir, "brands.txt")
	// Missing file.
	records, err := c.Fetch(context.Background(), Options{HTTPClient: newFakeHTTP()})
	if err != nil {
		t.Fatalf("Fetch missing brands: %v", err)
	}
	if records != nil {
		t.Fatalf("expected nil records for missing brands, got %d", len(records))
	}
	// Empty file.
	if err := os.WriteFile(c.BrandsPath, []byte("# just a comment\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	records, err = c.Fetch(context.Background(), Options{HTTPClient: newFakeHTTP()})
	if err != nil {
		t.Fatalf("Fetch empty brands: %v", err)
	}
	if records != nil {
		t.Fatalf("expected nil records for empty brands, got %d", len(records))
	}
}

func TestCTBrandFetchHappy(t *testing.T) {
	dir := t.TempDir()
	brandsPath := filepath.Join(dir, "brands.txt")
	if err := os.WriteFile(brandsPath, []byte("brand\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewCTBrand()
	c.BrandsPath = brandsPath
	q := fmt.Sprintf(c.Template, url.QueryEscape("%brand%"))
	fake := newFakeHTTP()
	fake.set(q, readTestdata(t, "ctbrand_sample.json"), nil, nil)
	records, err := c.Fetch(context.Background(), Options{HTTPClient: fake, Now: time.Now()})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(records) < 3 {
		t.Fatalf("records: got %d", len(records))
	}
	// Every record must be suspicious.
	for _, r := range records {
		if r.Classification != "suspicious" {
			t.Fatalf("expected suspicious: %+v", r)
		}
	}
}

func TestCTBrandParseMalformed(t *testing.T) {
	_, err := parseCTBrand([]byte("not json"), "brand", time.Now())
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCTBrandParseEmpty(t *testing.T) {
	records, err := parseCTBrand([]byte("[]"), "brand", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d", len(records))
	}
}
