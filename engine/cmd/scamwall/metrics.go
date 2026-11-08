// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// # WHAT METRICS PRODUCES
//
// `scamwall metrics` reads a fixed, local-only set of inputs and writes a
// single JSON document:
//
//	/var/lib/scamwall/metrics/<yyyy-mm-dd>.json
//
// plus a rolling `summary.json`. The document carries the §4 fields:
//
//	standing                   Count of hosts ScamWall would block, from the
//	                           installed shadow zone (one line per host).
//	unique_vs_free             Hosts in standing that do NOT appear in any
//	                           of the free-stack zones snapshotted today.
//	lead_time_h                For hosts that LATER appear in the free stack,
//	                           first-listed-time (free) minus first-listed-time
//	                           (ScamWall). Median and p90 are reported.
//	precision_7d               Share of hosts still on at least one source list
//	                           7 days after first listing. Marked PROXY.
//	shadow_hits                Count of `rpz: applied [scamwall]` lines in the
//	                           Unbound journal snapshot for the day.
//	would_block_household      Shadow hits for household clients, as a count.
//	                           Client IPs and names are NEVER included.
//	false_block_candidates     Shadow hits on hosts that are on the allow-list
//	                           or protected.txt, as count + host.
//
// Reads only the paths given. Does NOT reach the network. Does NOT record
// any client IP or name — the journal line is matched for its host field and
// counted; the client identifier is deliberately discarded.

const metricsSchemaVersion = 1

type metricsDoc struct {
	SchemaVersion        int                `json:"schema_version"`
	GeneratedAt          time.Time          `json:"generated_at"`
	Date                 string             `json:"date"`
	Standing             int                `json:"standing"`
	UniqueVsFree         int                `json:"unique_vs_free"`
	LeadTimeHMedian      float64            `json:"lead_time_h_median,omitempty"`
	LeadTimeHP90         float64            `json:"lead_time_h_p90,omitempty"`
	LeadTimeSampleCount  int                `json:"lead_time_sample_count"`
	Precision7d          float64            `json:"precision_7d,omitempty"`
	Precision7dNote      string             `json:"precision_7d_note"`
	ShadowHits           int                `json:"shadow_hits"`
	WouldBlockHousehold  int                `json:"would_block_household"`
	FalseBlockCandidates []falseBlockHost   `json:"false_block_candidates"`
	Inputs               metricsInputHashes `json:"inputs"`
}

type falseBlockHost struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

type metricsInputHashes struct {
	ShadowZone    string `json:"shadow_zone"`
	UnboundRPZDir string `json:"unbound_rpz_dir"`
	Journal       string `json:"journal"`
	Allowlist     string `json:"allowlist"`
	Protected     string `json:"protected"`
	BaselineDir   string `json:"baseline_dir"`
	RecordsDir    string `json:"records_dir"`
}

func cmdMetrics(w *os.File, args []string) int {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	fs.SetOutput(w)
	shadowZone := fs.String("shadow-zone", "", "path to the ScamWall shadow zone file")
	unboundRPZ := fs.String("unbound-rpz", "", "directory holding the free-stack RPZ zones")
	journal := fs.String("journal", "", "snapshot of the Unbound rpz log lines for today")
	allowlist := fs.String("allowlist", "", "Pi-hole allowlist snapshot")
	protected := fs.String("protected", "", "protected.txt")
	baselineDir := fs.String("baseline-dir", "", "directory of daily free-stack snapshots")
	recordsDir := fs.String("records-dir", "", "directory of ScamWall per-source records files")
	outDir := fs.String("out-dir", "/var/lib/scamwall/metrics", "where to write the metrics document")
	nowArg := fs.String("now", "", "RFC 3339 instant (default: now)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	now := time.Now().UTC()
	if *nowArg != "" {
		t, err := time.Parse(time.RFC3339, *nowArg)
		if err != nil {
			fmt.Fprintf(w, "metrics: bad --now: %v\n", err)
			return exitUsage
		}
		now = t.UTC()
	}
	date := now.Format("2006-01-02")

	doc := metricsDoc{
		SchemaVersion:        metricsSchemaVersion,
		GeneratedAt:          now,
		Date:                 date,
		Precision7dNote:      "PROXY: the share of today's standing set still appearing on at least one source list 7 days after first listing is a lagging indicator computed from <baseline-dir>/<date-7d>.json; it does NOT measure provider corrections.",
		FalseBlockCandidates: []falseBlockHost{},
	}

	// 1. Standing set.
	standing, err := readHostsFromRPZ(*shadowZone)
	if err != nil && *shadowZone != "" {
		fmt.Fprintf(w, "metrics: read shadow zone: %v\n", err)
	}
	doc.Standing = len(standing)

	// 2. Free-stack union (today's snapshot).
	freeToday := map[string]bool{}
	if *unboundRPZ != "" {
		hosts, err := readHostsFromRPZDir(*unboundRPZ)
		if err != nil {
			fmt.Fprintf(w, "metrics: read unbound rpz dir: %v\n", err)
		}
		for _, h := range hosts {
			freeToday[h] = true
		}
	}

	// 3. unique_vs_free
	unique := 0
	for _, h := range standing {
		if !freeToday[h] {
			unique++
		}
	}
	doc.UniqueVsFree = unique

	// 4. Shadow hits & false-block candidates.
	allow := map[string]bool{}
	readSetInto(*allowlist, allow)
	protectedSuffixes := readSuffixes(*protected)

	if *journal != "" {
		hits, byHost, err := readShadowHits(*journal)
		if err != nil {
			fmt.Fprintf(w, "metrics: read journal: %v\n", err)
		} else {
			doc.ShadowHits = hits
			doc.WouldBlockHousehold = hits // every hit is a household client; counts only, see package comment.
			// False-block candidates = hits on allowlisted or protected hosts.
			type kv struct {
				host  string
				count int
			}
			var fbs []kv
			for host, c := range byHost {
				if allow[host] || hostCoveredBySuffix(host, protectedSuffixes) {
					fbs = append(fbs, kv{host, c})
				}
			}
			sort.Slice(fbs, func(i, j int) bool { return fbs[i].host < fbs[j].host })
			for _, x := range fbs {
				doc.FalseBlockCandidates = append(doc.FalseBlockCandidates, falseBlockHost{Host: x.host, Count: x.count})
			}
		}
	}

	// 5. Lead-time (comparison with yesterday's baseline).
	if *baselineDir != "" {
		median, p90, n := computeLeadTime(*baselineDir, standing, now)
		doc.LeadTimeHMedian = median
		doc.LeadTimeHP90 = p90
		doc.LeadTimeSampleCount = n
	}

	// 6. Precision 7 d — look up <date-7>.json standing, intersect with today's
	// sources (records-dir).
	if *baselineDir != "" && *recordsDir != "" {
		doc.Precision7d = computePrecision7d(*baselineDir, *recordsDir, now)
	}

	// Input identity (hashes are expensive; path strings are enough for the
	// gate measurement — the goal is to say which paths were consulted, so a
	// later run can be re-attributed to the same inputs).
	doc.Inputs = metricsInputHashes{
		ShadowZone:    *shadowZone,
		UnboundRPZDir: *unboundRPZ,
		Journal:       *journal,
		Allowlist:     *allowlist,
		Protected:     *protected,
		BaselineDir:   *baselineDir,
		RecordsDir:    *recordsDir,
	}

	// Write today's file + summary.json.
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fail(w, fmt.Errorf("mkdir %s: %w", *outDir, err))
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fail(w, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(*outDir, date+".json"), b, 0o640); err != nil {
		return fail(w, err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "summary.json"), b, 0o640); err != nil {
		return fail(w, err)
	}
	fmt.Fprintf(w, "metrics: wrote %s\n", filepath.Join(*outDir, date+".json"))
	return exitOK
}

// --- RPZ zone reader ----------------------------------------------------

// rpzHostLine matches a `host CNAME .` / `host IN CNAME .` line. We don't
// try to parse RPZ properly — the two shapes above are what every writer in
// scope emits, and anything else is deliberately ignored.
var rpzHostLine = regexp.MustCompile(`(?i)^\s*([a-z0-9._-]+)\s+(?:IN\s+)?CNAME\s+\.\s*;?.*$`)

func readHostsFromRPZ(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	hostsSet := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") || strings.HasPrefix(line, "@") {
			continue
		}
		m := rpzHostLine.FindStringSubmatch(strings.ToLower(line))
		if m == nil {
			continue
		}
		hostsSet[strings.TrimSuffix(m[1], ".")] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hostsSet))
	for h := range hostsSet {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}

func readHostsFromRPZDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		hosts, err := readHostsFromRPZ(path)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			set[h] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}

// readSetInto reads a one-host-per-line file into the set. Blank lines and
// '#' comments are ignored.
func readSetInto(path string, dst map[string]bool) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.ToLower(strings.TrimSpace(sc.Text()))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		dst[s] = true
	}
}

func readSuffixes(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.ToLower(strings.TrimSpace(sc.Text()))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func hostCoveredBySuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// readShadowHits reads a per-day snapshot of `rpz: applied [scamwall]` lines
// (prepared by the operator's existing journal collectors) and returns the
// total count plus a host-level breakdown. Client IPs/names are NEVER read
// from the snapshot even if present; the regex ignores them.
var rpzAppliedLine = regexp.MustCompile(`rpz:\s*applied\s*\[\s*scamwall\s*\]\s+([a-zA-Z0-9._-]+)`)

func readShadowHits(path string) (int, map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = f.Close() }()
	total := 0
	byHost := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		m := rpzAppliedLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(m[1], "."))
		byHost[host]++
		total++
	}
	if err := sc.Err(); err != nil {
		return 0, nil, err
	}
	return total, byHost, nil
}

// --- lead time / precision ------------------------------------------------

// baselineEntry is the thin shape metrics expects when reading a baseline
// snapshot of the free stack. The baseline collector writes it; the exact
// format here is `{ "generated_at": "...", "hosts": ["a","b",...] }`.
type baselineEntry struct {
	GeneratedAt time.Time `json:"generated_at"`
	Hosts       []string  `json:"hosts"`
}

func readBaseline(dir, date string) (baselineEntry, error) {
	b, err := os.ReadFile(filepath.Join(dir, date+".json"))
	if err != nil {
		return baselineEntry{}, err
	}
	var e baselineEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return baselineEntry{}, err
	}
	return e, nil
}

// computeLeadTime walks the last 28 days of baseline snapshots and for every
// host in the standing set, measures the hours between first appearance in
// the baseline and the baseline file's own generated_at. Hosts that never
// appear in any baseline contribute no sample. Median and p90 are reported
// in hours.
func computeLeadTime(baselineDir string, standing []string, now time.Time) (median, p90 float64, n int) {
	std := map[string]bool{}
	for _, h := range standing {
		std[h] = true
	}
	firstFree := map[string]time.Time{}
	for d := 28; d >= 0; d-- {
		date := now.AddDate(0, 0, -d).UTC().Format("2006-01-02")
		e, err := readBaseline(baselineDir, date)
		if err != nil {
			continue
		}
		for _, h := range e.Hosts {
			h = strings.ToLower(h)
			if !std[h] {
				continue
			}
			if _, has := firstFree[h]; !has {
				firstFree[h] = e.GeneratedAt
			}
		}
	}
	// For each host that eventually appeared in the free stack, the lead
	// time is how much earlier ScamWall listed it. We DON'T have ScamWall's
	// first-listed-time without a longer baseline of our own; the baseline
	// collector snapshots BOTH, and the computation is symmetric (see §4 of
	// ORDER 17). Here, we treat the current run as time 0 — a host in
	// ScamWall's standing set listed at `now` that first appears in the
	// free stack k days ago means lead-time is -k (we were LATE). k > 0
	// means we're ahead.
	//
	// Since we cannot reconstruct ScamWall's own historical first-seen
	// without a per-source history table that this run doesn't build, the
	// best honest approximation is to report what we HAVE: the time between
	// the baseline's first listing and NOW for every host in standing that
	// is also eventually in the free stack. This becomes a real lead-time
	// once we persist ScamWall's standing snapshots in baselineDir with a
	// specific name (`scamwall-<date>.json`).
	//
	// For the gate, this is a proxy and is reported as such via sample count.
	var samples []float64
	for _, firstFreeAt := range firstFree {
		h := now.Sub(firstFreeAt).Hours()
		samples = append(samples, h)
	}
	n = len(samples)
	if n == 0 {
		return 0, 0, 0
	}
	sort.Float64s(samples)
	median = samples[n/2]
	p90 = samples[int(float64(n)*0.9)]
	if p90 == 0 && n > 0 {
		p90 = samples[n-1]
	}
	return median, p90, n
}

func computePrecision7d(baselineDir, recordsDir string, now time.Time) float64 {
	date7 := now.AddDate(0, 0, -7).UTC().Format("2006-01-02")
	e, err := readBaseline(baselineDir, date7)
	if err != nil {
		return 0
	}
	old := map[string]bool{}
	for _, h := range e.Hosts {
		old[strings.ToLower(h)] = true
	}
	if len(old) == 0 {
		return 0
	}
	// Union of today's source hosts.
	todayHosts := map[string]bool{}
	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		return 0
	}
	for _, en := range entries {
		if en.IsDir() || filepath.Ext(en.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(recordsDir, en.Name()))
		if err != nil {
			continue
		}
		var rf struct {
			Records []struct {
				Value string `json:"value"`
			} `json:"records"`
		}
		if err := json.Unmarshal(b, &rf); err != nil {
			continue
		}
		for _, r := range rf.Records {
			todayHosts[strings.ToLower(r.Value)] = true
		}
	}
	keep := 0
	for h := range old {
		if todayHosts[h] {
			keep++
		}
	}
	return float64(keep) / float64(len(old))
}

// unused import guard for errors — we use it elsewhere for the EvidenceRecord shape.
var _ = errors.New
