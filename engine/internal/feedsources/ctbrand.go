// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// CTBrandSourceID is the registry id for S6.
const CTBrandSourceID = "ct-brand-watch"

// CTBrandSearchURL is the crt.sh JSON endpoint shape. One query per brand,
// `%<brand>%` pattern. It is a CT log reader, not a scam list itself: the
// output is a `suspicious` signal, never `harmful` on its own.
const CTBrandSearchURL = "https://crt.sh/?output=json&q=%s"

// CTBrand is S6. BrandsPath is a file of brand strings, one per line; empty
// or missing disables the source.
type CTBrand struct {
	Template   string
	Cadence_   time.Duration
	BrandsPath string
}

func NewCTBrand() *CTBrand {
	return &CTBrand{
		Template:   CTBrandSearchURL,
		Cadence_:   6 * time.Hour,
		BrandsPath: "/etc/pinga53/scamwall/brands.txt",
	}
}

func (c *CTBrand) ID() string             { return CTBrandSourceID }
func (c *CTBrand) Cadence() time.Duration { return c.Cadence_ }

type ctRecord struct {
	NameValue  string `json:"name_value"`
	EntryTS    string `json:"entry_timestamp"`
	CommonName string `json:"common_name"`
}

func (c *CTBrand) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	brands, err := readBrandList(c.BrandsPath)
	if err != nil {
		return nil, err
	}
	if len(brands) == 0 {
		// Empty brand list = source disabled by configuration. Not an
		// error: this is the documented default per ORDER 17 §2.
		return nil, nil
	}
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}
	var all []feed.EvidenceRecord
	for _, brand := range brands {
		recs, err := c.fetchOneBrand(ctx, client, opts, brand)
		if err != nil {
			// A single brand's failure must not fail the whole source.
			// Record it to stderr; the pipeline carries what we have.
			fmt.Fprintf(os.Stderr, "ct-brand-watch: brand %q failed: %v\n", brand, err)
			continue
		}
		all = append(all, recs...)
	}
	return Dedupe(SortRecords(all)), nil
}

func (c *CTBrand) fetchOneBrand(ctx context.Context, client HTTPClient, opts Options, brand string) ([]feed.EvidenceRecord, error) {
	q := fmt.Sprintf(c.Template, url.QueryEscape("%"+brand+"%"))
	var body []byte
	err := doWithRetry(ctx, 3, func() error {
		var inner error
		body, _, inner = client.Get(ctx, q, nil)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ct-brand-watch: brand %q: %w", brand, err)
	}
	return parseCTBrand(body, brand, opts.Now)
}

func parseCTBrand(body []byte, brand string, now time.Time) ([]feed.EvidenceRecord, error) {
	var arr []ctRecord
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, fmt.Errorf("ct-brand-watch: parse: %w", err)
	}
	out := make([]feed.EvidenceRecord, 0, len(arr))
	for _, r := range arr {
		// name_value can be a newline-separated list of SANs.
		for _, raw := range strings.Split(r.NameValue, "\n") {
			raw = strings.TrimPrefix(strings.TrimSpace(raw), "*.")
			host, err := NormaliseHost(raw)
			if err != nil {
				continue
			}
			// Drop the brand's own apex cert: brand.com's own certificate is
			// not evidence of impersonation. Any host with exactly two labels
			// whose first label equals the brand (and the `www.` variant) is
			// the brand itself; drop it. Subdomains are kept — a lookalike
			// subdomain (customerportal.brand.com, when the brand runs only
			// brand.com) is exactly what this source exists to surface.
			labels := strings.Split(host, ".")
			if len(labels) == 2 && labels[0] == brand {
				continue
			}
			if len(labels) == 3 && labels[0] == "www" && labels[1] == brand {
				continue
			}
			if !containsBrandLikeToken(host, brand) {
				// Must contain the brand substring; crt.sh %b% catches many
				// unrelated names via SAN entries.
				continue
			}
			rec := feed.EvidenceRecord{
				Type:                   "domain",
				Value:                  host,
				SourceID:               CTBrandSourceID,
				SourceRecordID:         r.CommonName,
				ProviderClassification: "ct-brand-match",
				Classification:         "suspicious",
				State:                  "active",
				Category:               brand,
				RawRetention:           "none",
			}
			if t, err := time.Parse("2006-01-02T15:04:05.000000", r.EntryTS); err == nil {
				tt := t.UTC()
				rec.FirstSeen = &tt
			}
			_ = now
			out = append(out, rec)
		}
	}
	return Dedupe(SortRecords(out)), nil
}

func containsBrandLikeToken(host, brand string) bool {
	host = strings.ToLower(host)
	brand = strings.ToLower(brand)
	return strings.Contains(host, brand)
}

// readBrandList returns the non-empty, non-comment lines of brandsPath.
// Missing path returns nil, nil — a missing file means "no brands", which
// is the documented default.
func readBrandList(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("ct-brand-watch: read brands file: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
