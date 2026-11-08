// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// CERTPolskaSourceID is the registry id for S5.
const CERTPolskaSourceID = "cert-polska-warning-list"

// CERTPolskaURL is CERT Polska's warning list. The published endpoint
// returns a plain-text file, one domain per line (the JSON API is also
// available; the text file is simpler and has no auth).
const CERTPolskaURL = "https://hole.cert.pl/domains/v2/domains.txt"

// CERTPolska is S5.
type CERTPolska struct {
	URL      string
	Cadence_ time.Duration
}

func NewCERTPolska() *CERTPolska {
	return &CERTPolska{URL: CERTPolskaURL, Cadence_: 60 * time.Minute}
}

func (c *CERTPolska) ID() string             { return CERTPolskaSourceID }
func (c *CERTPolska) Cadence() time.Duration { return c.Cadence_ }

func (c *CERTPolska) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}
	cacheEntryVal := loadCache(opts.CachePath)
	reqHeaders := cacheHeaders(cacheEntryVal, c.URL)

	var body []byte
	var respHeaders map[string]string
	err := doWithRetry(ctx, 3, func() error {
		var inner error
		body, respHeaders, inner = client.Get(ctx, c.URL, reqHeaders)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, ErrNotFresh
	}
	if err != nil {
		return nil, fmt.Errorf("cert-polska fetch: %w", err)
	}
	records, err := parseCERTPolska(body, opts.Now)
	if err != nil {
		return nil, err
	}
	_ = saveCache(opts.CachePath, cacheEntry{
		URL:          c.URL,
		ETag:         respHeaders["ETag"],
		LastModified: respHeaders["Last-Modified"],
		FetchedAt:    opts.Now.UTC(),
	})
	return records, nil
}

// parseCERTPolska accepts either the plain-text list (one domain per line)
// or a JSON array of objects. The warning list is historically shipped as
// both; the fetcher is agnostic.
func parseCERTPolska(body []byte, now time.Time) ([]feed.EvidenceRecord, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		return parseCERTPolskaJSON([]byte(trimmed), now)
	}
	out := make([]feed.EvidenceRecord, 0, 1024)
	for _, line := range strings.Split(trimmed, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		host, err := NormaliseHost(s)
		if err != nil {
			continue
		}
		rec := feed.EvidenceRecord{
			Type:                   "domain",
			Value:                  host,
			SourceID:               CERTPolskaSourceID,
			ProviderClassification: "scam",
			Classification:         "malicious",
			State:                  "active",
			RawRetention:           "none",
		}
		if !now.IsZero() {
			t := now.UTC()
			rec.FirstSeen = &t
		}
		out = append(out, rec)
	}
	return Dedupe(SortRecords(out)), nil
}

type certplRecord struct {
	Domain     string `json:"Domain"`
	InsertDate string `json:"InsertDate"`
	DeleteDate string `json:"DeleteDate"`
}

func parseCERTPolskaJSON(body []byte, now time.Time) ([]feed.EvidenceRecord, error) {
	var arr []certplRecord
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, fmt.Errorf("cert-polska: parse JSON: %w", err)
	}
	out := make([]feed.EvidenceRecord, 0, len(arr))
	for _, r := range arr {
		// If deleted, skip.
		if strings.TrimSpace(r.DeleteDate) != "" {
			continue
		}
		host, err := NormaliseHost(r.Domain)
		if err != nil {
			continue
		}
		rec := feed.EvidenceRecord{
			Type:                   "domain",
			Value:                  host,
			SourceID:               CERTPolskaSourceID,
			ProviderClassification: "scam",
			Classification:         "malicious",
			State:                  "active",
			RawRetention:           "none",
		}
		if t, err := time.Parse(time.RFC3339, r.InsertDate); err == nil {
			tt := t.UTC()
			rec.FirstSeen = &tt
		}
		out = append(out, rec)
	}
	_ = now
	return Dedupe(SortRecords(out)), nil
}
