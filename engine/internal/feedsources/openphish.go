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

// OpenPhishSourceID is the registry id for S3.
const OpenPhishSourceID = "openphish-community"

// OpenPhishURL is the community feed (unauthenticated plain text, one URL per
// line). The commercial product is a separate source; this one is the free
// "community" feed.
const OpenPhishURL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

// OpenPhish is S3.
type OpenPhish struct {
	URL      string
	Cadence_ time.Duration
}

func NewOpenPhish() *OpenPhish {
	return &OpenPhish{URL: OpenPhishURL, Cadence_: 60 * time.Minute}
}

func (o *OpenPhish) ID() string             { return OpenPhishSourceID }
func (o *OpenPhish) Cadence() time.Duration { return o.Cadence_ }

func (o *OpenPhish) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}
	cacheEntryVal := loadCache(opts.CachePath)
	reqHeaders := cacheHeaders(cacheEntryVal, o.URL)

	var body []byte
	var respHeaders map[string]string
	err := doWithRetry(ctx, 3, func() error {
		var inner error
		body, respHeaders, inner = client.Get(ctx, o.URL, reqHeaders)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, ErrNotFresh
	}
	if err != nil {
		return nil, fmt.Errorf("openphish fetch: %w", err)
	}
	records, err := parseOpenPhish(body, opts.Now)
	if err != nil {
		return nil, err
	}
	_ = saveCache(opts.CachePath, cacheEntry{
		URL:          o.URL,
		ETag:         respHeaders["ETag"],
		LastModified: respHeaders["Last-Modified"],
		FetchedAt:    opts.Now.UTC(),
	})
	return records, nil
}

func parseOpenPhish(body []byte, now time.Time) ([]feed.EvidenceRecord, error) {
	out := make([]feed.EvidenceRecord, 0, 1024)
	sc := bufio.NewScanner(bytes.NewReader(body))
	// A single pathological line could exceed bufio's default 64 KiB; raise
	// but still cap so an adversary cannot make us read gigabytes per line.
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
			SourceID:               OpenPhishSourceID,
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
		return nil, fmt.Errorf("openphish: scan body: %w", err)
	}
	return Dedupe(SortRecords(out)), nil
}
