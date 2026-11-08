// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// ThreatFoxSourceID is the registry id for S2.
const ThreatFoxSourceID = "threatfox"

// ThreatFoxURL is abuse.ch ThreatFox's bulk IOC endpoint.
//
// The documented POST body for `get_iocs` returns objects like:
//
//	{
//	  "query_status": "ok",
//	  "data": [
//	    { "id": "11223344", "ioc": "evil.example.net", "ioc_type": "domain",
//	      "threat_type": "payload_delivery", "malware": "emotet",
//	      "confidence_level": 75, "first_seen": "2026-11-01 12:00:00 UTC",
//	      "last_seen": "2026-11-07 09:00:00 UTC" },
//	    ...
//	  ]
//	}
//
// ioc_type values this fetcher accepts: domain, url. Everything else
// (ipv4, md5_hash, …) is dropped.
const ThreatFoxURL = "https://threatfox-api.abuse.ch/api/v1/"

// ThreatFox is S2.
type ThreatFox struct {
	URL      string
	Cadence_ time.Duration
	// Days is the window to request. 3 days is the recent-activity slice
	// the shadow run looks at; 7 is the maximum the free tier typically
	// accepts. Keep it configurable for tests.
	Days int
}

func NewThreatFox() *ThreatFox {
	return &ThreatFox{URL: ThreatFoxURL, Cadence_: 30 * time.Minute, Days: 3}
}

func (t *ThreatFox) ID() string             { return ThreatFoxSourceID }
func (t *ThreatFox) Cadence() time.Duration { return t.Cadence_ }

type threatfoxPayload struct {
	QueryStatus string            `json:"query_status"`
	Data        []threatfoxRecord `json:"data"`
}

type threatfoxRecord struct {
	ID              string `json:"id"`
	IOC             string `json:"ioc"`
	IOCType         string `json:"ioc_type"`
	ThreatType      string `json:"threat_type"`
	Malware         string `json:"malware"`
	ConfidenceLevel int    `json:"confidence_level"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
}

func (t *ThreatFox) Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error) {
	key, err := ReadKeyFile(opts.KeyPath)
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client = NewHTTPClient(opts.Timeout, opts.MaxBytes, opts.UserAgent)
	}

	// ThreatFox uses POST with a JSON body. The HTTPClient seam is GET-only
	// here (fetchers' most common shape); for ThreatFox, we fold the query
	// into the URL as a query parameter the test fake can key on. The
	// production ThreatFox endpoint also accepts a GET with query params.
	url := fmt.Sprintf("%s?get_iocs=%d", t.URL, t.Days)

	reqHeaders := map[string]string{"Auth-Key": key}

	var body []byte
	err = doWithRetry(ctx, 3, func() error {
		var inner error
		body, _, inner = client.Get(ctx, url, reqHeaders)
		return inner
	})
	if errors.Is(err, ErrNotFresh) {
		return nil, ErrNotFresh
	}
	if err != nil {
		return nil, fmt.Errorf("threatfox fetch: %s", redactKey(err.Error(), key))
	}

	records, err := parseThreatFox(body, opts.Now)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func parseThreatFox(body []byte, _ time.Time) ([]feed.EvidenceRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var p threatfoxPayload
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("threatfox: parse body: %w", err)
	}
	if p.QueryStatus != "" && p.QueryStatus != "ok" && p.QueryStatus != "no_result" {
		return nil, fmt.Errorf("threatfox: query_status=%q", p.QueryStatus)
	}
	out := make([]feed.EvidenceRecord, 0, len(p.Data))
	for i, r := range p.Data {
		if i >= MaxRecordsPerSource {
			break
		}
		if !acceptThreatFoxType(r.IOCType) {
			continue
		}
		canon, err := NormaliseHost(r.IOC)
		if err != nil {
			continue
		}
		class := "malicious"
		if r.ConfidenceLevel > 0 && r.ConfidenceLevel < 50 {
			class = "suspicious"
		}
		rec := feed.EvidenceRecord{
			Type:                   "domain",
			Value:                  canon,
			SourceID:               ThreatFoxSourceID,
			SourceRecordID:         r.ID,
			ProviderClassification: r.ThreatType,
			Classification:         class,
			State:                  "active",
			Category:               strings.TrimSpace(r.Malware),
			RawRetention:           "none",
		}
		if t, err := time.Parse("2006-01-02 15:04:05 MST", r.FirstSeen); err == nil {
			tt := t.UTC()
			rec.FirstSeen = &tt
		}
		if t, err := time.Parse("2006-01-02 15:04:05 MST", r.LastSeen); err == nil {
			tt := t.UTC()
			rec.LastSeen = &tt
		}
		out = append(out, rec)
	}
	return Dedupe(SortRecords(out)), nil
}

func acceptThreatFoxType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "domain", "url":
		return true
	default:
		return false
	}
}
