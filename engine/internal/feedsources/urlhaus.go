// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// URLhausSourceID is the registry id for S1.
const URLhausSourceID = "urlhaus"

// URLhausExportBase is abuse.ch's v2 export base. The Auth-Key is part of the
// path (not a header) in the current API; the old downloads/json_recent/ JSON
// endpoint was retired (returns HTTP 410) in the 2025 Spamhaus migration.
//
// The full URL is:
//
//	https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv
//
// and it returns a CSV dump (regenerated every 5 minutes) whose columns are:
//
//	# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
//
// Only "online" URLs become records. Hosts that are IP literals, localhost,
// or public suffixes are dropped by NormaliseHost. The URLhaus id is carried
// as source_record_id so a later correction can be attached.
const URLhausExportBase = "https://urlhaus-api.abuse.ch/v2/files/exports/"

// urlhausCacheKey keys the per-source ETag cache WITHOUT the Auth-Key, so the
// key is never written to the cache file.
const urlhausCacheKey = "urlhaus:recent.csv"

// URLhaus is S1 — abuse.ch's URL feed, projected to hosts.
type URLhaus struct {
	// ExportBase is the path prefix; the Auth-Key and "recent.csv" are
	// appended at fetch time. Overridable for tests.
	ExportBase string
	Cadence_   time.Duration
}

// NewURLhaus returns S1 with defaults.
func NewURLhaus() *URLhaus {
	return &URLhaus{ExportBase: URLhausExportBase, Cadence_: 30 * time.Minute}
}

func (u *URLhaus) ID() string             { return URLhausSourceID }
func (u *URLhaus) Cadence() time.Duration { return u.Cadence_ }

func (u *URLhaus) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	key, err := ReadKeyFile(opts.KeyPath)
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}

	// The Auth-Key lives in the path now; build it here and keep it out of
	// the cache file (cache is keyed by a stable, key-less identifier).
	fetchURL := u.ExportBase + key + "/recent.csv"

	cacheEntryVal := loadCache(opts.CachePath)
	reqHeaders := map[string]string{}
	if cacheEntryVal.URL == urlhausCacheKey {
		if cacheEntryVal.ETag != "" {
			reqHeaders["If-None-Match"] = cacheEntryVal.ETag
		}
		if cacheEntryVal.LastModified != "" {
			reqHeaders["If-Modified-Since"] = cacheEntryVal.LastModified
		}
	}

	var body []byte
	var respHeaders map[string]string
	err = doWithRetry(ctx, 3, func() error {
		var inner error
		body, respHeaders, inner = client.Get(ctx, fetchURL, reqHeaders)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, ErrNotFresh
	}
	if err != nil {
		// Scrub the key from any diagnostic (it is in the URL now).
		return nil, fmt.Errorf("urlhaus fetch: %s", redactKey(err.Error(), key))
	}

	records, err := parseURLhausCSV(body, opts.Now)
	if err != nil {
		return nil, err
	}

	_ = saveCache(opts.CachePath, cacheEntry{
		URL:          urlhausCacheKey,
		ETag:         respHeaders["ETag"],
		LastModified: respHeaders["Last-Modified"],
		FetchedAt:    opts.Now.UTC(),
	})
	return records, nil
}

// parseURLhausCSV reads the recent.csv export and projects online URLs to
// host EvidenceRecords. Comment lines (starting with '#', including the
// header row abuse.ch emits as a comment) are skipped; malformed rows are
// dropped, not fatal.
func parseURLhausCSV(body []byte, now time.Time) ([]feed.EvidenceRecord, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = true

	out := make([]feed.EvidenceRecord, 0, 1024)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip a malformed row rather than abandoning the dump
		}
		// columns: 0 id, 1 dateadded, 2 url, 3 url_status, 4 last_online,
		//          5 threat, 6 tags, 7 urlhaus_link, 8 reporter
		if len(row) < 4 {
			continue
		}
		id := strings.TrimSpace(row[0])
		dateAdded := strings.TrimSpace(row[1])
		rawURL := strings.TrimSpace(row[2])
		status := strings.TrimSpace(row[3])
		var threat, tags string
		if len(row) > 5 {
			threat = strings.TrimSpace(row[5])
		}
		if len(row) > 6 {
			tags = strings.TrimSpace(row[6])
		}
		if !strings.EqualFold(status, "online") {
			continue
		}
		canon, err := NormaliseHost(rawURL)
		if err != nil {
			continue
		}
		rec := feed.EvidenceRecord{
			Type:                   "domain",
			Value:                  canon,
			SourceID:               URLhausSourceID,
			SourceRecordID:         id,
			ProviderClassification: threat,
			Classification:         "malicious",
			State:                  "active",
			Category:               tags,
			RawRetention:           "none",
		}
		// CSV dates are "2026-11-07 12:00:05" (UTC), sometimes with a
		// trailing " UTC". Try both.
		if t, err := time.Parse("2006-01-02 15:04:05", dateAdded); err == nil {
			tt := t.UTC()
			rec.FirstSeen = &tt
		} else if t, err := time.Parse("2006-01-02 15:04:05 MST", dateAdded); err == nil {
			tt := t.UTC()
			rec.FirstSeen = &tt
		}
		out = append(out, rec)
		if len(out) >= MaxRecordsPerSource {
			break
		}
	}
	_ = now
	return Dedupe(SortRecords(out)), nil
}

// redactKey removes the raw key from an error message, so a diagnostic
// never carries it. internal/audit.RedactURLs strips URL-embedded
// credentials of the user:pass@ form; an Auth-Key placed in a path segment
// (URLhaus) or a header (ThreatFox) needs its own filter.
func redactKey(msg, key string) string {
	if key == "" {
		return msg
	}
	return strings.ReplaceAll(msg, key, "[REDACTED]")
}
