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

// URLhausSourceID is the registry id for S1.
const URLhausSourceID = "urlhaus"

// URLhausURL is the recent-URLs JSON endpoint. The provider's /api/
// documentation page (cited in the registry) describes it.
//
// This endpoint returns an object like:
//
//	{
//	  "query_status": "ok",
//	  "urls": [
//	    { "id": "...", "url": "http://...", "host": "evil.example.com",
//	      "url_status": "online", "threat": "malware_download",
//	      "tags": [...], "date_added": "2026-11-07 12:00:00 UTC" },
//	    ...
//	  ]
//	}
//
// Only "online" URLs become records. Hosts that are IP literals, localhost,
// or public suffixes are dropped by NormaliseHost. The URLhaus id is carried
// as source_record_id so a later correction can be attached.
const URLhausURL = "https://urlhaus.abuse.ch/downloads/json_recent/"

// URLhaus is S1 — abuse.ch's URL feed, projected to hosts.
type URLhaus struct {
	URL      string
	Cadence_ time.Duration
}

// NewURLhaus returns S1 with defaults.
func NewURLhaus() *URLhaus {
	return &URLhaus{URL: URLhausURL, Cadence_: 30 * time.Minute}
}

func (u *URLhaus) ID() string             { return URLhausSourceID }
func (u *URLhaus) Cadence() time.Duration { return u.Cadence_ }

type urlhausPayload struct {
	QueryStatus string                     `json:"query_status"`
	URLs        map[string][]urlhausRecord `json:"urls"`
}

// urlhausRecord is one entry.
//
// The json_recent variant keys the "urls" field as an array; some other
// variants key it as a map of id → [{..}, {..}]. Handle both.
type urlhausRecord struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Host      string   `json:"host"`
	URLStatus string   `json:"url_status"`
	Threat    string   `json:"threat"`
	Tags      []string `json:"tags"`
	DateAdded string   `json:"date_added"`
}

// urlhausRecentArray is the shape json_recent returns as of ORDER 17:
//
//	{ "query_status": "ok", "urls": [ { ... }, ... ] }
//
// Decoded in parallel with the map shape; whichever matches first wins.
type urlhausRecentArray struct {
	QueryStatus string          `json:"query_status"`
	URLs        []urlhausRecord `json:"urls"`
}

func (u *URLhaus) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	key, err := ReadKeyFile(opts.KeyPath)
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}

	// Cache. URLhaus publishes ETag headers; use them.
	cacheEntryVal := loadCache(opts.CachePath)
	reqHeaders := cacheHeaders(cacheEntryVal, u.URL)
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}
	// abuse.ch asks for Auth-Key in the request headers.
	reqHeaders["Auth-Key"] = key

	var body []byte
	var respHeaders map[string]string
	err = doWithRetry(ctx, 3, func() error {
		var inner error
		body, respHeaders, inner = client.Get(ctx, u.URL, reqHeaders)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, ErrNotFresh
	}
	if err != nil {
		// Scrub the key from any error diagnostic before returning.
		return nil, fmt.Errorf("urlhaus fetch: %s", redactKey(err.Error(), key))
	}

	records, err := parseURLhaus(body, opts.Now)
	if err != nil {
		return nil, err
	}

	// Cache update, best-effort.
	_ = saveCache(opts.CachePath, cacheEntry{
		URL:          u.URL,
		ETag:         respHeaders["ETag"],
		LastModified: respHeaders["Last-Modified"],
		FetchedAt:    opts.Now.UTC(),
	})
	return records, nil
}

// parseURLhaus decodes either shape and projects to EvidenceRecords.
func parseURLhaus(body []byte, now time.Time) ([]feed.EvidenceRecord, error) {
	// Try the array shape first.
	var arr urlhausRecentArray
	if err := json.Unmarshal(body, &arr); err == nil {
		return urlhausRecordsFromSlice(arr.URLs, now), nil
	}
	// Fall back to the map shape.
	var mp urlhausPayload
	if err := json.Unmarshal(body, &mp); err != nil {
		return nil, fmt.Errorf("urlhaus: parse body: %w", err)
	}
	all := make([]urlhausRecord, 0, len(mp.URLs))
	for _, group := range mp.URLs {
		all = append(all, group...)
	}
	return urlhausRecordsFromSlice(all, now), nil
}

func urlhausRecordsFromSlice(in []urlhausRecord, now time.Time) []feed.EvidenceRecord {
	out := make([]feed.EvidenceRecord, 0, len(in))
	if len(in) > MaxRecordsPerSource {
		in = in[:MaxRecordsPerSource]
	}
	for _, r := range in {
		if !strings.EqualFold(r.URLStatus, "online") {
			continue
		}
		host := r.Host
		if host == "" {
			host = r.URL
		}
		canon, err := NormaliseHost(host)
		if err != nil {
			continue
		}
		rec := feed.EvidenceRecord{
			Type:                   "domain",
			Value:                  canon,
			SourceID:               URLhausSourceID,
			SourceRecordID:         r.ID,
			ProviderClassification: r.Threat,
			Classification:         "malicious",
			State:                  "active",
			Category:               strings.Join(r.Tags, ","),
			RawRetention:           "none",
		}
		if t, err := time.Parse("2006-01-02 15:04:05 MST", r.DateAdded); err == nil {
			tt := t.UTC()
			rec.FirstSeen = &tt
		}
		_ = now // kept for possible future freshness checks; records default to the provider's own times
		out = append(out, rec)
	}
	return Dedupe(SortRecords(out))
}

// redactKey removes the raw key from an error message, so a diagnostic
// never carries it. internal/audit.RedactURLs strips URL-embedded
// credentials; a key sent in a header needs its own filter.
func redactKey(msg, key string) string {
	if key == "" {
		return msg
	}
	return strings.ReplaceAll(msg, key, "[REDACTED]")
}
