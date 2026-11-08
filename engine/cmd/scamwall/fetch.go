// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/feedsources"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT THE FETCH VERB DOES
//
// scamwall fetch reads the deployed source registry, picks every source that
// is both `enabled: true` AND whose id is one of the recognised fetcher ids,
// runs its fetcher, and writes
//
//	<out-dir>/<source_id>.json
//
// atomically. One file per source. A fetch that errors (missing key file,
// HTTP failure, provider returned something unparseable) is reported on
// stderr and does NOT affect the other sources: the scamwall-fetch.service
// timer runs every 30 min and one bad provider must not starve the good ones.
//
// The command returns 0 if ALL enabled fetchers succeeded, 1 if any failed.
// The records files written by the successful ones stay on disk for the
// shim (scamwall-run.sh) to pick up on its next cycle.
//
// Rights are enforced: for every source enabled in the registry, retrieval
// must be `permitted` (directly or via a satisfied conditional). A source
// enabled whose retrieval grant is not satisfied is reported and skipped.

// sourceRegistry picks the fetcher for a known id.
var fetcherFactories = map[string]func() feedsources.Source{
	feedsources.URLhausSourceID:    func() feedsources.Source { return feedsources.NewURLhaus() },
	feedsources.ThreatFoxSourceID:  func() feedsources.Source { return feedsources.NewThreatFox() },
	feedsources.OpenPhishSourceID:  func() feedsources.Source { return feedsources.NewOpenPhish() },
	feedsources.PhishingDBSourceID: func() feedsources.Source { return feedsources.NewPhishingDB() },
	feedsources.CERTPolskaSourceID: func() feedsources.Source { return feedsources.NewCERTPolska() },
	feedsources.CTBrandSourceID:    func() feedsources.Source { return feedsources.NewCTBrand() },
}

func cmdFetch(w *os.File, args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(w)
	registryPath := fs.String("registry", "", "path to the source registry (required)")
	outDir := fs.String("out-dir", "/var/lib/scamwall/records", "directory to write per-source records files to")
	secretsDir := fs.String("secrets-dir", "/etc/pinga53/scamwall/secrets", "directory holding per-source credential files")
	cacheDir := fs.String("cache-dir", "/var/lib/scamwall/cache", "directory to persist per-source ETag/Last-Modified")
	timeout := fs.Duration("timeout", 30*time.Second, "per-fetch deadline")
	only := fs.String("only", "", "comma-separated subset of source ids to run; empty means every enabled source")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *registryPath == "" {
		fmt.Fprintln(w, "fetch: --registry is required")
		return exitUsage
	}

	reg, problems, err := sourceregistry.Load(*registryPath)
	if err != nil {
		return fail(w, fmt.Errorf("load registry: %w", err))
	}
	if ps := reg.Validate(time.Now().UTC()); len(ps) > 0 {
		for _, p := range ps {
			fmt.Fprintf(w, "registry: %s\n", p.String())
		}
		return fail(w, errors.New("registry validation failed"))
	}
	for _, p := range problems {
		fmt.Fprintf(w, "registry warning: %s\n", p.String())
	}

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fail(w, fmt.Errorf("mkdir out-dir: %w", err))
	}
	if err := os.MkdirAll(*cacheDir, 0o750); err != nil {
		return fail(w, fmt.Errorf("mkdir cache-dir: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*20)
	defer cancel()

	client := feedsources.NewHTTPClient(*timeout, 0, "")
	now := time.Now().UTC()

	wanted := parseCSV(*only)
	anyRan := 0
	failed := 0

	for i := range reg.Sources {
		s := &reg.Sources[i]
		if !s.Enabled {
			continue
		}
		if len(wanted) > 0 {
			if _, ok := wanted[s.SourceID]; !ok {
				continue
			}
		}
		factory, known := fetcherFactories[s.SourceID]
		if !known {
			fmt.Fprintf(w, "fetch: no fetcher for enabled source %q (not one of this build's known fetchers)\n", s.SourceID)
			continue
		}
		if ok, why := s.Authorizes(sourceregistry.OpRetrieval); !ok {
			fmt.Fprintf(w, "fetch: refusing to retrieve %s: %s\n", s.SourceID, why)
			continue
		}
		anyRan++
		src := factory()
		keyPath := filepath.Join(*secretsDir, keyFileFor(s.SourceID))
		cachePath := filepath.Join(*cacheDir, s.SourceID+".cache.json")
		recs, err := src.Fetch(ctx, feedsources.Options{
			Timeout:    *timeout,
			KeyPath:    keyPath,
			CachePath:  cachePath,
			Now:        now,
			HTTPClient: client,
		})
		if errors.Is(err, feedsources.ErrNotFresh) {
			// 304 — keep the previous records file in place.
			fmt.Fprintf(w, "fetch: %s: not modified, previous records kept\n", s.SourceID)
			continue
		}
		if errors.Is(err, feedsources.ErrKeyFileMissing) {
			// ORDER 17B §1: an enabled abuse.ch source with no key file
			// SKIPS with a health message, not a failure. The deploy
			// cannot place the operator's Auth-Key, so a fresh install
			// must be allowed to run with URLhaus + ThreatFox skipping
			// until the operator places /etc/pinga53/scamwall/secrets/
			// abusech.key.
			fmt.Fprintf(w, "fetch: %s: skipped (credential file missing; operator step)\n", s.SourceID)
			continue
		}
		if err != nil {
			fmt.Fprintf(w, "fetch: %s: ERROR: %v\n", s.SourceID, err)
			failed++
			continue
		}
		outPath := filepath.Join(*outDir, s.SourceID+".json")
		if err := feedsources.WriteRecordsFile(outPath, s.SourceID, src.Cadence(), now, recs); err != nil {
			fmt.Fprintf(w, "fetch: %s: write %s: %v\n", s.SourceID, outPath, err)
			failed++
			continue
		}
		fmt.Fprintf(w, "fetch: %s: %d record(s) -> %s\n", s.SourceID, len(recs), outPath)
	}

	fmt.Fprintf(w, "\n%d enabled fetcher(s) ran, %d failed\n", anyRan, failed)
	if failed > 0 {
		return exitFailure
	}
	return exitOK
}

func parseCSV(s string) map[string]struct{} {
	out := map[string]struct{}{}
	if s == "" {
		return out
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := s[start:i]
			if tok != "" {
				out[tok] = struct{}{}
			}
			start = i + 1
		}
	}
	return out
}

// keyFileFor names the per-source credential file. abuse.ch (URLhaus and
// ThreatFox) share one Auth-Key per account, so the file name is deliberately
// shared: one file, one secret, two fetchers reading it.
func keyFileFor(sourceID string) string {
	switch sourceID {
	case feedsources.URLhausSourceID, feedsources.ThreatFoxSourceID:
		return "abusech.key"
	default:
		return sourceID + ".key"
	}
}

// --- test shim: the records-file reader for scamwall-run.sh ---

// cmdMergeRecords is not a subcommand but a helper used by scamwall-run.sh.
// It walks a directory of per-source records files, keeps the ones newer
// than 2 × their declared cadence, concatenates the records, and prints a
// single JSON array to stdout.
//
// Kept in this file so the fetch + merge logic lives in one place.
func cmdMergeRecords(w *os.File, args []string) int {
	fs := flag.NewFlagSet("merge-records", flag.ContinueOnError)
	fs.SetOutput(w)
	dir := fs.String("dir", "/var/lib/scamwall/records", "directory holding per-source records files")
	now := fs.String("now", "", "RFC 3339 instant to use as 'now' for freshness (default: real now)")
	minSources := fs.Int("min-sources", 1, "keep only indicators listed by at least this many distinct source ids")
	maxRecords := fs.Int("max-records", 0, "refuse (exit non-zero) when more than this many records remain; 0 = no cap")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	nowT := time.Now().UTC()
	if *now != "" {
		t, err := time.Parse(time.RFC3339, *now)
		if err != nil {
			fmt.Fprintf(w, "merge-records: bad --now: %v\n", err)
			return exitUsage
		}
		nowT = t.UTC()
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Empty directory == no records, exit 0 with []. The shim
			// treats an empty records array by falling back to the
			// sentinel.
			fmt.Fprintln(w, "[]")
			return exitOK
		}
		return fail(w, fmt.Errorf("read dir: %w", err))
	}
	var all []feed.EvidenceRecord
	kept := 0
	stale := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		rf, err := feedsources.ReadRecordsFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "merge-records: skip %s: %v\n", path, err)
			continue
		}
		cadence := time.Duration(rf.CadenceHours * float64(time.Hour))
		ageLimit := 2 * cadence
		if ageLimit <= 0 {
			ageLimit = 2 * time.Hour
		}
		age := nowT.Sub(rf.WrittenAt.UTC())
		if age > ageLimit {
			stale++
			fmt.Fprintf(os.Stderr, "merge-records: skip %s: age %s > 2*cadence (%s)\n", path, age.Round(time.Second), ageLimit)
			continue
		}
		all = append(all, rf.Records...)
		kept++
	}
	// Dedup across sources; two feeds listing the same host are two records
	// here (same Value, different SourceID), and the proposal engine counts
	// them per source. The dedup in feedsources.Dedupe is (type,value,src).
	all = feedsources.Dedupe(all)
	// Corroboration prefilter. Full feed snapshots run to hundreds of
	// thousands of hosts; with the policy requiring two independent sources,
	// an indicator only one source id lists can never qualify, so carrying it
	// into the signed evidence only costs size. Counting distinct source ids
	// is a superset of counting independent voices (lineage may still merge
	// two ids into one), so the decision engine's own rule is unchanged.
	if *minSources > 1 {
		seen := map[string]map[string]struct{}{}
		for _, r := range all {
			k := r.Type + "\x00" + r.Value
			if seen[k] == nil {
				seen[k] = map[string]struct{}{}
			}
			seen[k][r.SourceID] = struct{}{}
		}
		kept := all[:0]
		for _, r := range all {
			if len(seen[r.Type+"\x00"+r.Value]) >= *minSources {
				kept = append(kept, r)
			}
		}
		fmt.Fprintf(os.Stderr, "merge-records: min-sources %d: %d of %d record(s) kept\n", *minSources, len(kept), len(all))
		all = kept
	}
	if *maxRecords > 0 && len(all) > *maxRecords {
		return fail(w, fmt.Errorf("merge-records: %d records exceed --max-records %d; refusing rather than truncating", len(all), *maxRecords))
	}
	all = feedsources.SortRecords(all)
	b, err := jsonMarshalArray(all)
	if err != nil {
		return fail(w, err)
	}
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
	fmt.Fprintf(os.Stderr, "merge-records: %d file(s) kept, %d stale, %d merged record(s)\n", kept, stale, len(all))
	return exitOK
}

func jsonMarshalArray(all []feed.EvidenceRecord) ([]byte, error) {
	if all == nil {
		return []byte("[]"), nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(all); err != nil {
		return nil, fmt.Errorf("merge-records: marshal: %w", err)
	}
	return buf.Bytes(), nil
}
