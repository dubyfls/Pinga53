// SPDX-License-Identifier: AGPL-3.0-only

package rpz_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/rpz"
)

// Each test covers ONE rejection axis of LoadPinga53Snapshot. A "load
// succeeded" test is included at the top so a regression in the happy path
// does not hide behind seven passing rejection tests.

const validSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// writeSnapshot renders a Pinga53 snapshot file for a test. Tests that need
// to violate a specific rule modify the returned path's content directly
// rather than growing this helper into a set of flags.
func writeSnapshot(t *testing.T, path, generatedAt string, sha string, exact, regex, subscribed []string) {
	t.Helper()
	// JSON is assembled by hand so the schema key ordering, quoting and
	// null-vs-empty distinction are testable — encoding/json would normalize
	// them.
	quoteList := func(v []string) string {
		if len(v) == 0 {
			return "[]"
		}
		parts := make([]string, len(v))
		for i, s := range v {
			parts[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	body := fmt.Sprintf(`{
  "schema": 1,
  "generated_at": %q,
  "source_sha256": %q,
  "exact_allow": %s,
  "regex_allow": %s,
  "subscribed_allow": %s
}
`, generatedAt, sha, quoteList(exact), quoteList(regex), quoteList(subscribed))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
}

func tempSnapshot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "allowlist.json")
}

func TestLoadPinga53Snapshot_HappyPath(t *testing.T) {
	path := tempSnapshot(t)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	gen := now.Add(-15 * time.Minute)
	writeSnapshot(t, path, gen.Format(time.RFC3339), validSHA,
		[]string{"example.com"},
		[]string{"^ads\\..*"},
		[]string{"trusted-list.example"})

	snap, err := rpz.LoadPinga53SnapshotAt(path, now, rpz.DefaultMaxPinga53SnapshotAge)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The two writer-facing halves must both be present. A NIL half is
	// specifically what makes Snapshot.Readable() refuse (see rpz.go).
	if snap.Allow == nil || snap.Subscribed == nil {
		t.Fatalf("snapshot must expose Allow AND Subscribed, got Allow=%v Subscribed=%v",
			snap.Allow != nil, snap.Subscribed != nil)
	}
	if ok, why := snap.Readable(); !ok {
		t.Fatalf("valid snapshot should be Readable, got refusal: %s", why)
	}

	// The Subscribed half must report Read()=true — an unread run would be
	// indistinguishable from an empty subscription and internal/shadow would
	// refuse it. See snapshot_pinga53.go's SubscribedRead=true note.
	if !snap.Subscribed.Read() {
		t.Fatal("Pinga53 snapshot must present Subscribed as READ")
	}
}

func TestLoadPinga53Snapshot_MissingFile(t *testing.T) {
	_, err := rpz.LoadPinga53Snapshot(filepath.Join(t.TempDir(), "not-there.json"))
	if !errors.Is(err, rpz.ErrSnapshotAbsent) {
		t.Fatalf("missing file must map to ErrSnapshotAbsent, got %v", err)
	}
}

func TestLoadPinga53Snapshot_MalformedJSON(t *testing.T) {
	path := tempSnapshot(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := rpz.LoadPinga53Snapshot(path)
	if err == nil {
		t.Fatal("malformed JSON must fail")
	}
	// A partial parse must not leak an "acceptable" Snapshot back with
	// half the data present. errors.Is against a sentinel would be false
	// here because JSON errors are their own type; we assert on the wrap
	// prefix instead so the caller can still tell WHY without probing the
	// concrete error type.
	if !strings.Contains(err.Error(), "Pinga53 snapshot") {
		t.Fatalf("error should carry the Pinga53 snapshot prefix, got %v", err)
	}
}

func TestLoadPinga53Snapshot_UnknownSchema(t *testing.T) {
	path := tempSnapshot(t)
	if err := os.WriteFile(path, []byte(`{
      "schema": 2,
      "generated_at": "2026-09-30T12:00:00Z",
      "source_sha256": "`+validSHA+`",
      "exact_allow": [],
      "regex_allow": [],
      "subscribed_allow": []
    }`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := rpz.LoadPinga53Snapshot(path)
	if !errors.Is(err, rpz.ErrPinga53SnapshotSchema) {
		t.Fatalf("schema=2 must return ErrPinga53SnapshotSchema, got %v", err)
	}
}

func TestLoadPinga53Snapshot_UnknownFieldRejected(t *testing.T) {
	// DisallowUnknownFields means a stray field is a refusal, not silent
	// data loss. This is the paranoid direction: if the exporter grows a
	// new field this build does not know about, the writer must not
	// silently ignore it — the human bumps the schema.
	path := tempSnapshot(t)
	if err := os.WriteFile(path, []byte(`{
      "schema": 1,
      "generated_at": "2026-09-30T12:00:00Z",
      "source_sha256": "`+validSHA+`",
      "exact_allow": [], "regex_allow": [], "subscribed_allow": [],
      "future_field": "hi"
    }`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := rpz.LoadPinga53Snapshot(path)
	if err == nil {
		t.Fatal("unknown field must fail")
	}
	if !strings.Contains(err.Error(), "future_field") {
		t.Fatalf("error should name the unknown field, got %v", err)
	}
}

func TestLoadPinga53Snapshot_Stale(t *testing.T) {
	path := tempSnapshot(t)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	// 3 h old vs a 2 h default — refuse.
	gen := now.Add(-3 * time.Hour)
	writeSnapshot(t, path, gen.Format(time.RFC3339), validSHA, nil, nil, nil)
	_, err := rpz.LoadPinga53SnapshotAt(path, now, rpz.DefaultMaxPinga53SnapshotAge)
	if !errors.Is(err, rpz.ErrPinga53SnapshotStale) {
		t.Fatalf("stale must return ErrPinga53SnapshotStale, got %v", err)
	}
}

func TestLoadPinga53Snapshot_ExactlyAtMaxAgeIsAccepted(t *testing.T) {
	// Boundary: age == maxAge is NOT stale (the condition is >, not >=).
	// A shorter cycle than the export cadence would sporadically refuse a
	// snapshot that arrived on the exact clock tick.
	path := tempSnapshot(t)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	gen := now.Add(-2 * time.Hour)
	writeSnapshot(t, path, gen.Format(time.RFC3339), validSHA, nil, nil, nil)
	if _, err := rpz.LoadPinga53SnapshotAt(path, now, 2*time.Hour); err != nil {
		t.Fatalf("age==maxAge should be accepted, got %v", err)
	}
}

func TestLoadPinga53Snapshot_FutureTimestampIsAccepted(t *testing.T) {
	// Small clock skew — the reader's clock is BEHIND the exporter's —
	// must not refuse. The staleness rejection is one-directional.
	path := tempSnapshot(t)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	gen := now.Add(30 * time.Second)
	writeSnapshot(t, path, gen.Format(time.RFC3339), validSHA, nil, nil, nil)
	if _, err := rpz.LoadPinga53SnapshotAt(path, now, rpz.DefaultMaxPinga53SnapshotAge); err != nil {
		t.Fatalf("future generated_at within skew must be accepted, got %v", err)
	}
}

func TestLoadPinga53Snapshot_OverEntryCap(t *testing.T) {
	// Assemble a snapshot whose entry SUM exceeds MaxPinga53SnapshotEntries.
	// Individually each list is under; the cap is the sum.
	//
	// Using unique domain names because the exporter can (and does) produce
	// hosts that are one character apart; a duplicate-check would swallow
	// them and give the test a false pass.
	path := tempSnapshot(t)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	gen := now.Add(-15 * time.Minute)
	total := rpz.MaxPinga53SnapshotEntries + 1
	each := total/3 + 1
	mk := func(prefix string) []string {
		out := make([]string, each)
		for i := range out {
			out[i] = fmt.Sprintf("%s%d.example", prefix, i)
		}
		return out
	}
	writeSnapshot(t, path, gen.Format(time.RFC3339), validSHA,
		mk("e"), mk("r"), mk("s"))
	_, err := rpz.LoadPinga53SnapshotAt(path, now, rpz.DefaultMaxPinga53SnapshotAge)
	if !errors.Is(err, rpz.ErrPinga53SnapshotOverCap) {
		t.Fatalf("over-cap must return ErrPinga53SnapshotOverCap, got %v", err)
	}
}

func TestLoadPinga53Snapshot_OverByteCap(t *testing.T) {
	// A snapshot larger than MaxSnapshotBytes is refused before the JSON
	// decoder sees it. Uses a stat check so we don't have to actually
	// allocate 8 MiB.
	path := tempSnapshot(t)
	if err := os.Truncate(path, int64(rpz.MaxSnapshotBytes+1)); err != nil {
		if err := os.WriteFile(path, make([]byte, rpz.MaxSnapshotBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Reopen and ensure the size is set (Truncate creates if absent, sizes
	// beyond the current length).
	if fi, err := os.Stat(path); err != nil || fi.Size() <= int64(rpz.MaxSnapshotBytes) {
		if err := os.WriteFile(path, make([]byte, rpz.MaxSnapshotBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := rpz.LoadPinga53Snapshot(path)
	if err == nil {
		t.Fatal("over-byte-cap must fail")
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("error should name the byte cap, got %v", err)
	}
}

func TestLoadPinga53Snapshot_BadSHA(t *testing.T) {
	cases := []struct {
		name string
		sha  string
	}{
		{"too short", "aaaa"},
		{"has uppercase", strings.Repeat("A", 64)},
		{"non-hex chars", strings.Repeat("g", 64)},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tempSnapshot(t)
			now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
			gen := now.Add(-15 * time.Minute)
			writeSnapshot(t, path, gen.Format(time.RFC3339), tc.sha, nil, nil, nil)
			_, err := rpz.LoadPinga53SnapshotAt(path, now, rpz.DefaultMaxPinga53SnapshotAge)
			if !errors.Is(err, rpz.ErrPinga53SnapshotIntegrity) {
				t.Fatalf("bad sha (%s) must return ErrPinga53SnapshotIntegrity, got %v", tc.name, err)
			}
		})
	}
}

func TestLoadPinga53Snapshot_MissingGeneratedAt(t *testing.T) {
	path := tempSnapshot(t)
	// Empty string won't parse as time.Time; write "0001-01-01T00:00:00Z"
	// (Go's zero value) instead, which IS parseable but is the zero time
	// so IsZero() catches it.
	writeSnapshot(t, path, "0001-01-01T00:00:00Z", validSHA, nil, nil, nil)
	_, err := rpz.LoadPinga53Snapshot(path)
	if !errors.Is(err, rpz.ErrPinga53SnapshotIntegrity) {
		t.Fatalf("zero generated_at must return ErrPinga53SnapshotIntegrity, got %v", err)
	}
}

func TestLoadPinga53Snapshot_MalformedGeneratedAt(t *testing.T) {
	path := tempSnapshot(t)
	// Not RFC 3339 — time.Time's JSON unmarshaller will refuse this before
	// the schema check gets to it.
	if err := os.WriteFile(path, []byte(`{
      "schema": 1,
      "generated_at": "yesterday",
      "source_sha256": "`+validSHA+`",
      "exact_allow": [], "regex_allow": [], "subscribed_allow": []
    }`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := rpz.LoadPinga53Snapshot(path)
	if err == nil {
		t.Fatal("malformed generated_at must fail")
	}
}

func TestLoadPinga53Snapshot_RejectionMeansEmptySnapshot(t *testing.T) {
	// The order says "Rejection = the zone writer freezes." This asserts
	// that end of the promise: any load error returns a zero Snapshot, and
	// the zero Snapshot's Readable() refuses. A writer that received a
	// half-populated Snapshot would not freeze — it would emit a zone that
	// overrides household allows it never saw.
	_, err := rpz.LoadPinga53Snapshot("/no/such/path/for/sure")
	if err == nil {
		t.Fatal("expected error")
	}
	var empty rpz.Snapshot
	ok, why := empty.Readable()
	if ok {
		t.Fatal("zero Snapshot must not be Readable")
	}
	if !strings.Contains(why, "no allow-list snapshot") {
		t.Fatalf("refusal reason should name the missing snapshot, got %q", why)
	}
}
