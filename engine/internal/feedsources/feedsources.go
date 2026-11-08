// SPDX-License-Identifier: AGPL-3.0-only

// Package feedsources turns one provider's response into evidence records.
//
// # WHY A SEPARATE PACKAGE
//
// internal/acquire is a decision engine. Its Fetch is a bounded HTTPS
// transport that returns raw bytes; its Decide applies the seven gates; its
// Run drives the two across a slice of sources. Nothing in acquire knows a
// URLhaus "online_url" JSON field from an OpenPhish text line, and it must
// not learn: once a decision engine accrues provider knowledge, a bug in a
// decoder is a bug in the gate.
//
// This package is where provider-specific decoding and normalisation live.
// A Source knows how to ask its one provider, how to read the provider's
// response, and how to project that response into feed.EvidenceRecord values.
// It does not sign anything, it does not write a signed envelope, and it
// does not decide anything about independence — a records file is one
// source's unsigned, pre-admission statement, and scamwall-run.sh's
// `acquire` phase is where signing happens.
//
// # WHAT A SOURCE PROMISES
//
//  1. It fetches under a deadline.
//  2. It drops indicators it cannot normalise rather than aborting.
//  3. It never writes a credential to a log, an error, or a record.
//  4. It never includes household data — no query strings, no client IPs,
//     no allow-list contents. Records are the PROVIDER's statements.
//  5. Its output is deterministic for a given input: a records file written
//     twice from the same bytes has the same records in the same order.
package feedsources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/atomicfile"
	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// MaxBodyBytes bounds ONE provider response, after decompression. 64 MiB is
// well above the free URLhaus daily dump (a few MiB) and well below what
// would stress the Pinga53 VM.
const MaxBodyBytes = 64 << 20

// MaxRecordsPerSource bounds one records file. A provider shipping more
// indicators than this is a provider whose output has either grown out of
// ScamWall's scope or is misbehaving; either way, downstream `acquire` gates
// are the right place to refuse, not this fetcher's RAM.
const MaxRecordsPerSource = 500_000

// Errors.
var (
	// ErrKeyFileMissing is a provider that needs a credential and has none.
	// The fetcher returns this rather than attempting an unauthenticated
	// request: a public-looking URL hit without a key can leak the fact
	// that this host is trying to reach the provider, which is itself
	// information.
	ErrKeyFileMissing = errors.New("feedsources: credential file is missing")

	// ErrEmptyResponse is a response that parsed and carried no indicators.
	// Not an error of the fetcher — empty is a valid state — but a caller
	// may want to distinguish it from a non-empty result.
	ErrEmptyResponse = errors.New("feedsources: response carried no indicators")

	// ErrNotFresh is a cache hit where the provider says nothing has changed.
	// The fetcher returns the previously-stored records when the provider
	// honours If-Modified-Since / If-None-Match, so a records file written
	// twice from a 304 is the same records file.
	ErrNotFresh = errors.New("feedsources: provider reports no change since last fetch")
)

// Options bound a single fetch.
type Options struct {
	// Timeout is the ONE whole-request deadline, resolution + TLS + body.
	// Zero means a per-source default.
	Timeout time.Duration
	// MaxBytes caps the body after decompression. Zero means MaxBodyBytes.
	MaxBytes int64
	// KeyPath is the credential file. Empty means the source has no
	// authentication; fetchers that require one return ErrKeyFileMissing.
	KeyPath string
	// CachePath, when non-empty, is a file this fetcher reads and writes
	// to persist ETag / Last-Modified between runs.
	CachePath string
	// Now is the instant this run believes it is; passed through to records
	// as a fallback FirstSeen, and used for cache-staleness arithmetic.
	Now time.Time
	// HTTPClient is a seam for tests. Nil means the production client.
	HTTPClient HTTPClient
	// UserAgent is the User-Agent string. Empty means a default.
	UserAgent string
}

// HTTPClient is the small surface fetchers need. The production
// implementation is one wrapping acquire.Fetch; the test implementation is a
// handwritten fake with a response map keyed by URL. See fetch_http.go.
type HTTPClient interface {
	// Get performs one bounded HTTPS GET. Headers are both input (extra
	// request headers, e.g. Auth-Key) and output (response headers the
	// caller wants to read, e.g. ETag).
	//
	// A non-2xx response is an error, not a returned status: fetchers do
	// not want to think about 403 or 500.
	Get(ctx context.Context, url string, reqHeaders map[string]string) (body []byte, respHeaders map[string]string, err error)
}

// Source is one provider's fetcher plus its normaliser.
type Source interface {
	// ID is the registry source id — matches `source_id` in the registry.
	ID() string
	// Cadence is how often the provider updates. The scamwall-run shim
	// rejects a records file older than 2 × Cadence.
	Cadence() time.Duration
	// Fetch asks the provider, decodes the response, normalises each
	// indicator into zero or one EvidenceRecords, drops what cannot be
	// normalised, and returns the set.
	Fetch(ctx context.Context, opts Options) ([]feed.EvidenceRecord, error)
}

// RecordsFile is what one source writes to /var/lib/scamwall/records/<id>.json.
//
// A thin header plus the records. The header carries the issue time (the
// instant the fetcher completed), the source id, the fetcher's cadence, and
// the record count. scamwall-run.sh reads the header to know whether the
// file is still fresh.
type RecordsFile struct {
	SchemaVersion int                   `json:"schema_version"`
	SourceID      string                `json:"source_id"`
	WrittenAt     time.Time             `json:"written_at"`
	CadenceHours  float64               `json:"cadence_hours"`
	RecordCount   int                   `json:"record_count"`
	Records       []feed.EvidenceRecord `json:"records"`
}

// RecordsFileSchema is the on-disk schema version. v1 is this shape.
const RecordsFileSchema = 1

// WriteRecordsFile serialises the records plus a thin header and replaces
// the destination atomically. Mode 0640 — the fetcher writes as scamwall,
// the shim reads as scamwall too, and other accounts have no business
// reading a provider's raw indicator list.
func WriteRecordsFile(path string, sourceID string, cadence time.Duration, now time.Time, records []feed.EvidenceRecord) error {
	rf := RecordsFile{
		SchemaVersion: RecordsFileSchema,
		SourceID:      sourceID,
		WrittenAt:     now.UTC(),
		CadenceHours:  cadence.Hours(),
		RecordCount:   len(records),
		Records:       records,
	}
	b, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return fmt.Errorf("feedsources: marshal records: %w", err)
	}
	b = append(b, '\n')
	return atomicfile.Write(path, b, 0o640)
}

// ReadRecordsFile returns the thin header and the records.
//
// Rejects a schema version this build does not understand. A records file
// written by a future version of the fetcher is not guaranteed to decode
// here, and `acquire`'s gates are safer catching that via MinEntries /
// Integrity than the consumer going silently empty.
func ReadRecordsFile(path string) (*RecordsFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("feedsources: read records file: %w", err)
	}
	var rf RecordsFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("feedsources: parse records file: %w", err)
	}
	if rf.SchemaVersion != RecordsFileSchema {
		return nil, fmt.Errorf("feedsources: records file %s has schema %d, want %d", path, rf.SchemaVersion, RecordsFileSchema)
	}
	return &rf, nil
}

// NormaliseHost takes a provider-written host-or-URL and returns a canonical
// host suitable for an EvidenceRecord.Value.
//
// Steps:
//  1. If it looks like a URL, extract the host.
//  2. Strip :port, strip a trailing dot, lowercase.
//  3. IDNA to ACE (punycode).
//  4. Reject if domain.Normalize refuses it: single-label names, IP literals,
//     localhost, link-local TLDs, public-suffix-only names, syntactically
//     invalid names.
//
// Normalisation that succeeds does NOT imply the host is a thing to block —
// that is the policy engine's job. It implies only that the provider wrote
// something that has a canonical form and is not obviously an internal name.
func NormaliseHost(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty host")
	}
	// Strip a scheme if the provider wrote a URL.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip userinfo (very unusual in a feed but accept for safety).
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Strip path/query/fragment.
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	// Strip port.
	if i := strings.LastIndex(s, ":"); i >= 0 {
		// Don't strip inside an IPv6 literal; those are refused below anyway.
		if !strings.Contains(s, "[") {
			s = s[:i]
		}
	}
	// Strip trailing dot.
	s = strings.TrimSuffix(s, ".")
	// Lowercase AFTER everything else, so that a mixed-case URL in a
	// provider's feed does not survive to the records file.
	s = strings.ToLower(s)
	if s == "" {
		return "", errors.New("host is empty after cleanup")
	}
	d, err := domain.Normalize(s)
	if err != nil {
		return "", err
	}
	return string(d), nil
}

// DropProtected removes hosts whose canonical form is covered by a suffix in
// protected.txt. The decision engine still applies the allow-list and
// protected.txt in its own right — this is a local-first drop so that a
// fetcher's records file never carries a host the writer would refuse.
//
// Case-insensitive whole-label suffix match: `example.com` covers
// `example.com` and `anything.example.com`, NOT `notexample.com`.
func DropProtected(records []feed.EvidenceRecord, protected []string) []feed.EvidenceRecord {
	if len(protected) == 0 {
		return records
	}
	suffixes := make([]string, 0, len(protected))
	for _, p := range protected {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		suffixes = append(suffixes, p)
	}
	if len(suffixes) == 0 {
		return records
	}
	out := records[:0]
	for _, r := range records {
		host := strings.ToLower(r.Value)
		drop := false
		for _, suf := range suffixes {
			if host == suf || strings.HasSuffix(host, "."+suf) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, r)
		}
	}
	return out
}

// Dedupe collapses records with the same (Type, Value, SourceID) tuple,
// keeping the first and preserving document order.
func Dedupe(records []feed.EvidenceRecord) []feed.EvidenceRecord {
	seen := make(map[string]struct{}, len(records))
	out := make([]feed.EvidenceRecord, 0, len(records))
	for _, r := range records {
		key := r.Type + "\x00" + r.Value + "\x00" + r.SourceID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

// SortRecords returns a records slice ordered by (Type, Value) for
// determinism. The acquire gates are over SETS; ordering only matters for
// the records file to byte-compare across runs that saw the same input.
func SortRecords(records []feed.EvidenceRecord) []feed.EvidenceRecord {
	out := append([]feed.EvidenceRecord(nil), records...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// ReadKeyFile reads a credential file, refuses one that is world-readable,
// trims a trailing newline, and refuses an empty value.
//
// Keys live under /etc/pinga53/scamwall/secrets/<source>.key, mode 0640,
// owned root:scamwall (operator step, see the handoff). A key the whole
// box can read is not a key, so world-readable is refused rather than
// trusted.
func ReadKeyFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrKeyFileMissing, path)
		}
		return "", fmt.Errorf("feedsources: open key file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("feedsources: stat key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("feedsources: key file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o004 != 0 {
		return "", fmt.Errorf("feedsources: key file %s has mode %#o and is world-readable; a key every process on this host can read is not a key",
			path, info.Mode().Perm())
	}
	// Bound the read: a credential file is small, and reading a larger
	// one points at a mis-used path (log file, core dump).
	b := make([]byte, 4096)
	n, err := f.Read(b)
	if err != nil && n == 0 {
		return "", fmt.Errorf("feedsources: read key file: %w", err)
	}
	k := strings.TrimRight(string(b[:n]), "\r\n \t")
	if k == "" {
		return "", fmt.Errorf("feedsources: key file %s is empty", path)
	}
	return k, nil
}
