// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// PhishingDBSourceID is the registry id for S4.
const PhishingDBSourceID = "phishing-database"

// PhishingDBURL is the active phishing domains file in the
// Phishing.Database repo (mitchellkrogza). The file is a plain-text list of
// hostnames, one per line, updated hourly.
const PhishingDBURL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"

// PhishingDB is S4.
type PhishingDB struct {
	URL      string
	Cadence_ time.Duration
}

func NewPhishingDB() *PhishingDB {
	return &PhishingDB{URL: PhishingDBURL, Cadence_: 60 * time.Minute}
}

func (p *PhishingDB) ID() string             { return PhishingDBSourceID }
func (p *PhishingDB) Cadence() time.Duration { return p.Cadence_ }

func (p *PhishingDB) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}
	cacheEntryVal := loadCache(opts.CachePath)
	reqHeaders := cacheHeaders(cacheEntryVal, p.URL)

	var body []byte
	var respHeaders map[string]string
	err := doWithRetry(ctx, 3, func() error {
		var inner error
		body, respHeaders, inner = client.Get(ctx, p.URL, reqHeaders)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, ErrNotFresh
	}
	if err != nil {
		return nil, fmt.Errorf("phishing-database fetch: %w", err)
	}
	records, err := parsePhishingDB(body, opts.Now)
	if err != nil {
		return nil, err
	}
	_ = saveCache(opts.CachePath, cacheEntry{
		URL:          p.URL,
		ETag:         respHeaders["ETag"],
		LastModified: respHeaders["Last-Modified"],
		FetchedAt:    opts.Now.UTC(),
	})
	return records, nil
}

func parsePhishingDB(body []byte, now time.Time) ([]feed.EvidenceRecord, error) {
	out := make([]feed.EvidenceRecord, 0, 1024)
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	count := 0
	for sc.Scan() {
		if count >= MaxRecordsPerSource {
			break
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		host, err := NormaliseHost(string(line))
		if err != nil {
			continue
		}
		rec := feed.EvidenceRecord{
			Type:                   "domain",
			Value:                  host,
			SourceID:               PhishingDBSourceID,
			ProviderClassification: "phishing",
			Classification:         "malicious",
			State:                  "active",
			RawRetention:           "none",
		}
		if !now.IsZero() {
			t := now.UTC()
			rec.FirstSeen = &t
		}
		out = append(out, rec)
		count++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("phishing-database: scan: %w", err)
	}
	return Dedupe(SortRecords(out)), nil
}
