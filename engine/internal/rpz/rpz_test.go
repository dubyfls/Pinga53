// SPDX-License-Identifier: AGPL-3.0-only

package rpz_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/enforce"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/rpz"
	"github.com/dubyfls/Pinga53/engine/internal/shadow"
)

// # ORDER 11 QUEUE ITEM 8 — THE RPZ ZONE WRITER
//
// Every test here is offline and touches nothing but a temporary directory.
// The zone this package produces is the first artefact in the tree that a
// resolver would act on, so the tests are weighted towards what must NEVER
// appear in it rather than towards what should.

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

// readAllow is an allow snapshot that was read and covers exactly what it is
// told to. The three kinds are separate maps because C-25 reports WHICH kind
// decided, and a test that cannot tell them apart cannot check that.
type readAllow struct {
	exact       map[string]bool
	regex       map[string]bool
	unevaluable int
}

func (a readAllow) Cover(d string) (bool, bool) { return a.exact[d], a.regex[d] }
func (a readAllow) Allowed(d string) bool       { return a.exact[d] || a.regex[d] }
func (a readAllow) Unevaluable() int            { return a.unevaluable }
func (a readAllow) Counts() (int, int)          { return len(a.exact), len(a.regex) }
func (a readAllow) Read() bool                  { return true }
func (a readAllow) Source() string              { return "in-process fake, read" }

// readSubscribed is a subscribed-list snapshot that was read.
type readSubscribed struct{ allow map[string]bool }

func (s readSubscribed) Membership(d string) (shadow.Tristate, shadow.Tristate) {
	if s.allow[d] {
		return shadow.Yes, shadow.No
	}
	return shadow.No, shadow.No
}
func (s readSubscribed) Read() bool     { return true }
func (s readSubscribed) Source() string { return "in-process fake, read" }

func snapshot() rpz.Snapshot {
	return rpz.Snapshot{
		Allow:      readAllow{exact: map[string]bool{}, regex: map[string]bool{}},
		Subscribed: readSubscribed{allow: map[string]bool{}},
	}
}

// policyWith builds a real policy, because Exception.canonical is filled by
// the parser and a struct literal would carry an empty canonical form — which
// matches nothing, so a hand-built policy would make the protected-domain
// tests pass for the wrong reason.
func policyWith(t *testing.T, exceptions string) *proposal.Policy {
	t.Helper()
	doc := fmt.Sprintf(`{"schema_version":1,"min_independent_sources":2,
		"proposal_scope":"subdomains","exceptions":[%s]}`, exceptions)
	p, err := proposal.ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("the fixture policy is not a policy: %v", err)
	}
	return p
}

// standing derives each digest FROM THE NAME rather than from the position in
// the slice, so that the same state supplied in a different order is the same
// state. A positional digest would make the determinism test pass for two
// inputs that were never equal.
func standing(names ...string) []enforce.StandingEntry {
	out := make([]enforce.StandingEntry, 0, len(names))
	for _, n := range names {
		out = append(out, enforce.StandingEntry{
			Canonical: n,
			Digest:    fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(n))),
		})
	}
	return out
}

func fixtureWriter(t *testing.T, path string) *rpz.Writer {
	t.Helper()
	return &rpz.Writer{
		Path:     path,
		Now:      time.Date(2026, 9, 25, 11, 0, 0, 0, time.UTC),
		Snapshot: snapshot(),
		Policy:   policyWith(t, ""),
	}
}

func mustEnforce(t *testing.T, w *rpz.Writer, p enforce.Plan) enforce.Result {
	t.Helper()
	r, err := w.Enforce(p)
	if err != nil {
		t.Fatalf("Enforce returned an error: %v", err)
	}
	return r
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// ---------------------------------------------------------------------------
// §4.4 golden zone
// ---------------------------------------------------------------------------

func TestTheZoneForAFixtureStateIsExactlyTheGolden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scamwall.zone")
	w := fixtureWriter(t, path)
	r := mustEnforce(t, w, enforce.Plan{
		Standing: standing("evil.example.com", "alpha.example.net", "bravo.example.net"),
	})
	if r.Outcome != enforce.OutcomeApplied {
		t.Fatalf("outcome %q, want applied: %s", r.Outcome, r.Reason)
	}

	got := readFile(t, path)
	goldenPath := filepath.Join("testdata", "fixture.zone")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want := readFile(t, goldenPath)
	if !bytes.Equal(got, want) {
		t.Errorf("the zone is not the golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestTwoRunsOverTheSameStateProduceTheSameBytes(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "one.zone")
	two := filepath.Join(dir, "two.zone")
	plan := enforce.Plan{Standing: standing("b.example.net", "a.example.net", "c.example.net")}

	mustEnforce(t, fixtureWriter(t, one), plan)
	// The same state in a different order must still be the same file: the
	// zone is an input to a resolver reload, and a file that differs run to
	// run for no reason makes every real change unreadable.
	shuffled := enforce.Plan{Standing: standing("c.example.net", "a.example.net", "b.example.net")}
	mustEnforce(t, fixtureWriter(t, two), shuffled)

	if !bytes.Equal(readFile(t, one), readFile(t, two)) {
		t.Errorf("the same state produced two different zones")
	}
}

// ---------------------------------------------------------------------------
// §4.4 protected domains
// ---------------------------------------------------------------------------

func TestAProtectedDomainAndEverySubdomainOfItAreNeverWritten(t *testing.T) {
	// Two exceptions, because ScopeSubdomains deliberately does not cover the
	// apex: see ORDER 8's C-17 note.
	pol := policyWith(t,
		`{"value":"bank.example.com","scope":"exact"},`+
			`{"value":"bank.example.com","scope":"subdomains"}`)

	rnd := rand.New(rand.NewSource(11))
	labels := []string{"a", "pay", "login", "www", "secure", "m", "api", "x1"}

	for i := 0; i < 200; i++ {
		var host string
		switch rnd.Intn(3) {
		case 0:
			host = "bank.example.com"
		case 1:
			host = labels[rnd.Intn(len(labels))] + ".bank.example.com"
		default:
			host = labels[rnd.Intn(len(labels))] + "." +
				labels[rnd.Intn(len(labels))] + ".bank.example.com"
		}

		path := filepath.Join(t.TempDir(), "z")
		w := fixtureWriter(t, path)
		w.Policy = pol
		w.AllowEmpty = true
		r := mustEnforce(t, w, enforce.Plan{Standing: standing(host)})

		if _, err := os.Stat(path); err == nil {
			if bytes.Contains(readFile(t, path), []byte(host)) {
				t.Fatalf("a protected host was written into the zone: %q", host)
			}
		}
		if len(r.Review) != 1 || r.Review[0].Canonical != host {
			t.Fatalf("protected host %q was not routed to review: %+v", host, r.Review)
		}
	}
}

func TestProtectionDoesNotLeakOntoALookalike(t *testing.T) {
	// A protection that reaches bank.example.com.evil.org protects the
	// attacker. internal/proposal.Covers is the label comparison that makes
	// this hold; this test is here so the writer cannot grow its own
	// suffix test beside it.
	pol := policyWith(t,
		`{"value":"bank.example.com","scope":"exact"},`+
			`{"value":"bank.example.com","scope":"subdomains"}`)

	for _, host := range []string{"bank.example.com.evil.org", "notbank.example.com", "xbank.example.com"} {
		path := filepath.Join(t.TempDir(), "z")
		w := fixtureWriter(t, path)
		w.Policy = pol
		r := mustEnforce(t, w, enforce.Plan{Standing: standing(host)})
		if r.Outcome != enforce.OutcomeApplied {
			t.Fatalf("%s: outcome %q, want applied — the protection leaked: %s", host, r.Outcome, r.Reason)
		}
		if !bytes.Contains(readFile(t, path), []byte(host)) {
			t.Errorf("%s was not written; the household's protection reached a name it does not own", host)
		}
	}
}

// ---------------------------------------------------------------------------
// §4.4 allowlist precedence — all three kinds
// ---------------------------------------------------------------------------

func TestAHostTheHouseholdAllowsIsExcludedAndSentToReviewWhicheverKindAllowsIt(t *testing.T) {
	const host = "allowed.example.com"
	for _, tc := range []struct {
		kind string
		snap func() rpz.Snapshot
	}{
		{"exact allow", func() rpz.Snapshot {
			s := snapshot()
			s.Allow = readAllow{exact: map[string]bool{host: true}, regex: map[string]bool{}}
			return s
		}},
		{"regex allow", func() rpz.Snapshot {
			s := snapshot()
			s.Allow = readAllow{exact: map[string]bool{}, regex: map[string]bool{host: true}}
			return s
		}},
		{"subscribed allowlist", func() rpz.Snapshot {
			s := snapshot()
			s.Subscribed = readSubscribed{allow: map[string]bool{host: true}}
			return s
		}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "z")
			w := fixtureWriter(t, path)
			w.Snapshot = tc.snap()
			r := mustEnforce(t, w, enforce.Plan{Standing: standing(host, "blocked.example.com")})

			if bytes.Contains(readFile(t, path), []byte(host)) {
				t.Errorf("an allowed host was written; on Pinga53 the RPZ entry would override "+
					"the household's own allow (%s)", tc.kind)
			}
			if len(r.Review) != 1 || r.Review[0].Canonical != host {
				t.Fatalf("the allowed host was not routed to review: %+v", r.Review)
			}
			if !strings.Contains(r.Review[0].Reason, "allow") {
				t.Errorf("the review reason does not say which kind allowed it: %q", r.Review[0].Reason)
			}
		})
	}
}

func TestAnUnevaluableAllowPatternFreezesRatherThanBlocking(t *testing.T) {
	// C-25: with a pattern the run could not read, "not allowed" means "no
	// pattern I could read matched", which does not license a block — and a
	// zone entry is a block.
	dir := t.TempDir()
	path := filepath.Join(dir, "z")
	if err := os.WriteFile(path, []byte("; previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := fixtureWriter(t, path)
	w.Snapshot.Allow = readAllow{exact: map[string]bool{}, regex: map[string]bool{}, unevaluable: 1}
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("evil.example.com")})

	if r.Outcome != enforce.OutcomeFrozen {
		t.Errorf("outcome %q, want frozen", r.Outcome)
	}
	if got := string(readFile(t, path)); got != "; previous\n" {
		t.Errorf("the previous zone was changed: %q", got)
	}
}

// ---------------------------------------------------------------------------
// §4.4 freeze
// ---------------------------------------------------------------------------

func TestAMissingSnapshotLeavesTheOldZoneAloneAndFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		snap rpz.Snapshot
	}{
		{"no snapshot at all", rpz.Snapshot{}},
		{"allow list not read", rpz.Snapshot{Allow: shadow.AllowNotRead{}, Subscribed: readSubscribed{}}},
		{"gravity not read", rpz.Snapshot{Allow: readAllow{}, Subscribed: shadow.SubscribedNotRead{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "z")
			if err := os.WriteFile(path, []byte("; previous\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			w := fixtureWriter(t, path)
			w.Snapshot = tc.snap
			r := mustEnforce(t, w, enforce.Plan{Standing: standing("evil.example.com")})

			if r.Outcome != enforce.OutcomeFrozen {
				t.Errorf("outcome %q, want frozen", r.Outcome)
			}
			if r.Reason == "" {
				t.Error("a freeze with no reason is a silent failure with a status code")
			}
			if got := string(readFile(t, path)); got != "; previous\n" {
				t.Errorf("the previous zone was changed: %q", got)
			}
			if r.Outcome.Changed() {
				t.Error("a freeze reported itself as a change")
			}
		})
	}
}

func TestAStaleAcquisitionLeavesTheOldZoneAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	if err := os.WriteFile(path, []byte("; previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := fixtureWriter(t, path)
	w.Stale, w.StaleReason = true, "the last acquisition is 40h old"
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("evil.example.com")})

	if r.Outcome != enforce.OutcomeFrozen {
		t.Errorf("outcome %q, want frozen", r.Outcome)
	}
	if !strings.Contains(r.Reason, "40h") {
		t.Errorf("the freeze did not carry the caller's reason: %q", r.Reason)
	}
	if got := string(readFile(t, path)); got != "; previous\n" {
		t.Errorf("the previous zone was changed: %q", got)
	}
}

// ---------------------------------------------------------------------------
// §4.4 empty and size
// ---------------------------------------------------------------------------

func TestAnEmptyResultIsRefusedUnlessSomebodyAskedForOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	if err := os.WriteFile(path, []byte("; previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := fixtureWriter(t, path)
	r := mustEnforce(t, w, enforce.Plan{})
	if r.Outcome != enforce.OutcomeRefused {
		t.Fatalf("outcome %q, want refused", r.Outcome)
	}
	if got := string(readFile(t, path)); got != "; previous\n" {
		t.Errorf("an empty zone replaced a populated one: %q", got)
	}

	w2 := fixtureWriter(t, filepath.Join(t.TempDir(), "z"))
	w2.AllowEmpty = true
	if r := mustEnforce(t, w2, enforce.Plan{}); r.Outcome != enforce.OutcomeApplied {
		t.Errorf("with --allow-empty the outcome is %q, want applied: %s", r.Outcome, r.Reason)
	}
}

func TestAZoneOverTheSizeCapIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	w.MaxEntries = 2
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net", "b.example.net", "c.example.net")})
	if r.Outcome != enforce.OutcomeRefused {
		t.Fatalf("outcome %q, want refused", r.Outcome)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a zone over the size cap was written anyway")
	}
}

// ---------------------------------------------------------------------------
// §4.4 the diff gate
// ---------------------------------------------------------------------------

func TestARunRemovingAnAbnormalShareWritesNothingAndRoutesToReview(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "z")

	// Eight standing entries, then a run that keeps only two: six removals
	// against eight owned is 75%, far above AbnormalRemovalFraction.
	var all []string
	for i := 0; i < 8; i++ {
		all = append(all, fmt.Sprintf("h%d.example.net", i))
	}
	first := mustEnforce(t, fixtureWriter(t, path), enforce.Plan{Standing: standing(all...)})
	if first.Outcome != enforce.OutcomeApplied {
		t.Fatalf("the setup run did not write: %s", first.Reason)
	}
	before := readFile(t, path)

	w := fixtureWriter(t, path)
	w.PrevSerial = first.Serial
	r := mustEnforce(t, w, enforce.Plan{Standing: standing(all[0], all[1])})

	if r.Outcome != enforce.OutcomeReview {
		t.Fatalf("outcome %q, want routed_to_review: %s", r.Outcome, r.Reason)
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("an abnormal-removal run rewrote the zone")
	}
	if r.Adds != 0 || r.Removals != 0 {
		t.Errorf("a run that wrote nothing reported %d adds and %d removals", r.Adds, r.Removals)
	}
}

func TestARunOverTheAdditionCapWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	w.MaxAddsPerRun = 2
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net", "b.example.net", "c.example.net")})
	if r.Outcome != enforce.OutcomeReview {
		t.Fatalf("outcome %q, want routed_to_review: %s", r.Outcome, r.Reason)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a run over the per-run addition cap wrote a zone")
	}
}

func TestAZoneThatAlreadyAgreesWithThePlanIsNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	plan := enforce.Plan{Standing: standing("a.example.net", "b.example.net")}
	first := mustEnforce(t, fixtureWriter(t, path), plan)
	before := readFile(t, path)

	w := fixtureWriter(t, path)
	w.PrevSerial = first.Serial
	r := mustEnforce(t, w, plan)

	if r.Outcome != enforce.OutcomeNoChange {
		t.Fatalf("outcome %q, want no_change", r.Outcome)
	}
	if r.Outcome.Changed() {
		t.Error("no_change reported itself as a change")
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("a run with nothing to do rewrote the zone, and so bumped the serial for nothing")
	}
}

// ---------------------------------------------------------------------------
// §4.4 serial
// ---------------------------------------------------------------------------

func TestTheSerialStrictlyIncreasesAcrossRunsIncludingWithinOneDay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "z")
	at := time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC)

	var last uint64
	prev := ""
	for i := 0; i < 5; i++ {
		w := fixtureWriter(t, path)
		w.Now = at.Add(time.Duration(i) * time.Hour)
		w.PrevSerial = prev
		// The set GROWS. A run that swapped one host for another would be a
		// 100% removal against a one-entry zone, which the abnormal-removal
		// gate holds — correctly, and not what this test is measuring.
		var names []string
		for j := 0; j <= i; j++ {
			names = append(names, fmt.Sprintf("h%d.example.net", j))
		}
		r := mustEnforce(t, w, enforce.Plan{Standing: standing(names...)})
		if r.Outcome != enforce.OutcomeApplied {
			t.Fatalf("run %d: outcome %q: %s", i, r.Outcome, r.Reason)
		}
		n, err := strconv.ParseUint(r.Serial, 10, 64)
		if err != nil {
			t.Fatalf("run %d: serial %q is not a number: %v", i, r.Serial, err)
		}
		if n <= last {
			t.Fatalf("run %d: serial %d did not increase past %d", i, n, last)
		}
		last, prev = n, r.Serial
	}
}

func TestARestoredOlderStateStillProducesAHigherSerial(t *testing.T) {
	// The zone on disk is the other half of the state. A ledger rolled back
	// to an older serial must not be able to re-issue one a resolver has
	// already seen: a lower serial is a zone a secondary will ignore.
	dir := t.TempDir()
	path := filepath.Join(dir, "z")

	w := fixtureWriter(t, path)
	w.PrevSerial = "2026092540"
	first := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net")})

	restored := fixtureWriter(t, path)
	restored.PrevSerial = "2026092502" // an older state, restored from backup
	second := mustEnforce(t, restored, enforce.Plan{Standing: standing("a.example.net", "b.example.net")})

	if second.Serial <= first.Serial {
		t.Fatalf("after restoring an older state the serial went backwards: %s then %s",
			first.Serial, second.Serial)
	}
}

func TestTheSerialIsTodaysDateWhenNothingPrecedesIt(t *testing.T) {
	w := fixtureWriter(t, filepath.Join(t.TempDir(), "z"))
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net")})
	if !strings.HasPrefix(r.Serial, "20260925") || len(r.Serial) != 10 {
		t.Errorf("serial %q is not YYYYMMDDnn for 2026-09-25", r.Serial)
	}
}

// ---------------------------------------------------------------------------
// §4.3 atomic replace and .prev
// ---------------------------------------------------------------------------

func TestThePreviousZoneIsKeptBesideTheNewOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "z")
	first := mustEnforce(t, fixtureWriter(t, path), enforce.Plan{Standing: standing("a.example.net")})
	before := readFile(t, path)

	w := fixtureWriter(t, path)
	w.PrevSerial = first.Serial
	mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net", "b.example.net")})

	if got := readFile(t, path+".prev"); !bytes.Equal(got, before) {
		t.Errorf(".prev is not the zone that was there before:\n%s", got)
	}
	if bytes.Equal(readFile(t, path), before) {
		t.Error("the new zone was not written")
	}
}

func TestAFailureBeforeTheRenameLeavesTheOldZoneIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory would not stop the write")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "z")
	first := mustEnforce(t, fixtureWriter(t, path), enforce.Plan{Standing: standing("a.example.net")})
	before := readFile(t, path)

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	w := fixtureWriter(t, path)
	w.PrevSerial = first.Serial
	if _, err := w.Enforce(enforce.Plan{Standing: standing("a.example.net", "b.example.net")}); err == nil {
		t.Fatal("a write into a read-only directory reported success")
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("the old zone was damaged by a write that could not complete")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temp file was left behind: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// §4.1 / §4.2 what must never appear in the file
// ---------------------------------------------------------------------------

func TestTheZoneNamesNoSourceNoURLAndNoEvidenceText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	mustEnforce(t, w, enforce.Plan{
		Standing: []enforce.StandingEntry{{
			Canonical: "evil.example.com",
			Digest:    "sha256:" + strings.Repeat("ab", 32),
		}},
		Review: []enforce.ReviewItem{{
			Canonical:   "other.example.com",
			Reason:      "reported by phishtank at https://phishtank.example/x",
			Explanation: "the evidence says it is a bank clone",
		}},
	})

	zone := string(readFile(t, path))
	for _, forbidden := range []string{
		"http://", "https://", "phishtank", "evidence", "bank clone", "feed", "source",
	} {
		if strings.Contains(strings.ToLower(zone), forbidden) {
			t.Errorf("the zone contains %q:\n%s", forbidden, zone)
		}
	}
}

func TestEveryEntryCarriesADigestPrefixAndNoWildcard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	mustEnforce(t, fixtureWriter(t, path), enforce.Plan{Standing: standing("a.example.net", "b.example.net")})

	for _, line := range strings.Split(string(readFile(t, path)), "\n") {
		if !strings.Contains(line, "CNAME") {
			continue
		}
		if strings.Contains(line, "*") {
			t.Errorf("a wildcard entry was written; subdomain coverage is an owner decision: %q", line)
		}
		if !strings.Contains(line, "; d=") {
			t.Errorf("an entry carries no decision digest: %q", line)
		}
	}
}

func TestAHostThatIsNotAValidNameIsReportedAndNotWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	r := mustEnforce(t, w, enforce.Plan{
		Standing: append(standing("good.example.net"), enforce.StandingEntry{Canonical: "not a host!"}),
	})
	if strings.Contains(string(readFile(t, path)), "not a host") {
		t.Error("an invalid host reached the zone")
	}
	var reported bool
	for _, rv := range r.Review {
		if rv.Canonical == "not a host!" {
			reported = true
		}
	}
	if !reported {
		t.Errorf("an invalid host was dropped silently: %+v", r.Review)
	}
}

func TestAWithheldHostIsNeverWritten(t *testing.T) {
	// C-09: a host the report may not name has no canonical form here, and an
	// opaque identifier is not a name a resolver can be asked about.
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	w.AllowEmpty = true
	r := mustEnforce(t, w, enforce.Plan{
		Standing: []enforce.StandingEntry{{Canonical: "", Digest: "sha256:aa"}},
	})
	if got := readFile(t, path); bytes.Contains(got, []byte("CNAME")) {
		t.Errorf("a nameless entry was written:\n%s", got)
	}
	if len(r.Review) != 1 {
		t.Errorf("the withheld entry was not reported: %+v", r.Review)
	}
}

// ---------------------------------------------------------------------------
// §4.4 zone syntax
// ---------------------------------------------------------------------------

func TestTheZoneParsesUnderAStrictChecker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	mustEnforce(t, fixtureWriter(t, path), enforce.Plan{
		Standing: standing("evil.example.com", "a.example.net", "xn--bcher-kva.example.net"),
	})
	if err := checkZone(t, readFile(t, path)); err != nil {
		t.Errorf("the zone this package wrote is not a well-formed zone file: %v", err)
	}
	checkWithExternalTool(t, path)
}

// checkWithExternalTool runs a real zone parser if the host happens to have
// one. ORDER 11 section 4.4 makes this check OPTIONAL and requires the absence
// of the tool to be recorded rather than skipped silently, because a check that
// quietly does not run is indistinguishable from one that passed.
func checkWithExternalTool(t *testing.T, path string) {
	t.Helper()
	for _, tool := range []struct {
		name string
		args []string
	}{
		{"named-checkzone", []string{"scamwall.rpz", path}},
		{"unbound-checkconf", nil},
	} {
		bin, err := exec.LookPath(tool.name)
		if err != nil || tool.args == nil {
			continue
		}
		if out, err := exec.Command(bin, tool.args...).CombinedOutput(); err != nil {
			t.Errorf("%s refused the zone: %v\n%s", tool.name, err, out)
		}
		return
	}
	t.Log("BLOCKED (tool absent): neither named-checkzone nor unbound-checkconf is installed " +
		"on this host, so the optional external validation of the zone did not run. The strict " +
		"checker above is not a substitute for it and does not claim to be")
}

func TestTheStrictCheckerRejectsAMalformedZone(t *testing.T) {
	// A checker that passes everything proves nothing about the zone above.
	for _, bad := range []string{
		"",
		"$ORIGIN scamwall.rpz.\nnothing here\n",
		"$ORIGIN scamwall.rpz.\n@ IN NS localhost.\nx IN CNAME .\n",           // no SOA
		"$ORIGIN scamwall.rpz.\n@ IN SOA a. b. ( 1 2 3 4 5 )\nx IN CNAME .\n", // no NS
	} {
		if err := checkZone(t, []byte(bad)); err == nil {
			t.Errorf("the checker accepted a malformed zone:\n%s", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// §4.3 the sealed record
// ---------------------------------------------------------------------------

func TestEveryWriteProducesASealedRecordThatNamesTheZone(t *testing.T) {
	key, err := mac.NewKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	w.Key = key
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net", "b.example.net")})

	var rec rpz.Record
	if err := json.Unmarshal(readFile(t, rpz.RecordPath(path)), &rec); err != nil {
		t.Fatalf("the record is not readable: %v", err)
	}
	if rec.Digest != r.Digest || rec.Serial != r.Serial || rec.Entries != 2 {
		t.Errorf("the record does not describe the run: %+v against %+v", rec, r)
	}
	if rec.Tag == "" {
		t.Fatal("the record carries no tag; an unsealed record is not a sealed one")
	}
	if err := rpz.VerifyRecord(rec, key); err != nil {
		t.Errorf("the record does not verify under the key that made it: %v", err)
	}

	// C-24: a changed record must not verify.
	tampered := rec
	tampered.Entries = 99
	if err := rpz.VerifyRecord(tampered, key); err == nil {
		t.Error("a record whose entry count was rewritten still verified")
	}
	other, err := mac.NewKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := rpz.VerifyRecord(rec, other); err == nil {
		t.Error("the record verified under a key that did not make it")
	}
}

func TestARunWithNoKeySaysSoRatherThanWritingAnUnkeyedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net")})
	if r.Outcome != enforce.OutcomeApplied {
		t.Fatalf("outcome %q: %s", r.Outcome, r.Reason)
	}
	var rec rpz.Record
	if err := json.Unmarshal(readFile(t, rpz.RecordPath(path)), &rec); err != nil {
		t.Fatalf("the record is not readable: %v", err)
	}
	if rec.Tag != "" {
		t.Error("a build with no key produced something that looks like a tag")
	}
	if err := rpz.VerifyRecord(rec, nil); err == nil {
		t.Error("an unkeyed record verified; an unchecked tag is not a passed one")
	}
}

// ---------------------------------------------------------------------------
// §4.5 dry run
// ---------------------------------------------------------------------------

func TestADryRunWritesNothingAndStillSaysWhatWouldHappen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "z")
	w := fixtureWriter(t, path)
	w.DryRun = true
	r := mustEnforce(t, w, enforce.Plan{Standing: standing("a.example.net", "b.example.net")})

	if r.Outcome.Changed() {
		t.Error("a dry run reported a change")
	}
	if r.Adds != 2 {
		t.Errorf("a dry run reported %d additions, want 2", r.Adds)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a dry run wrote a zone")
	}
	if _, err := os.Stat(rpz.RecordPath(path)); err == nil {
		t.Error("a dry run wrote a record")
	}
}

// ---------------------------------------------------------------------------
// the strict zone checker (§4.4), stdlib only
// ---------------------------------------------------------------------------

// checkZone is a deliberately strict reader for the one zone shape this
// package emits. It is not a general zone parser: a general one would accept
// things this writer must never produce, which is the wrong direction for a
// check. If unbound-checkconf or named-checkzone is installed the test that
// calls this also runs it; neither is present on this host, and that optional
// check is recorded BLOCKED (tool absent) rather than skipped silently.
func checkZone(t *testing.T, b []byte) error {
	t.Helper()
	var sawSOA, sawNS, sawOrigin bool
	seen := map[string]bool{}

	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		// An entry comment is the only trailing comment this writer emits.
		if j := strings.Index(line, ";"); j >= 0 {
			if !strings.HasPrefix(strings.TrimSpace(line[j:]), "; d=") {
				return fmt.Errorf("line %d: unexpected trailing comment: %q", i+1, line)
			}
			line = strings.TrimSpace(line[:j])
		}
		fields := strings.Fields(line)
		switch {
		case fields[0] == "$ORIGIN":
			if len(fields) != 2 || !strings.HasSuffix(fields[1], ".") {
				return fmt.Errorf("line %d: $ORIGIN must be one absolute name: %q", i+1, line)
			}
			sawOrigin = true
		case fields[0] == "$TTL":
			if len(fields) != 2 {
				return fmt.Errorf("line %d: $TTL takes one value: %q", i+1, line)
			}
			if _, err := strconv.Atoi(fields[1]); err != nil {
				return fmt.Errorf("line %d: $TTL is not a number: %q", i+1, line)
			}
		case len(fields) >= 3 && fields[1] == "IN" && fields[2] == "SOA":
			// @ IN SOA mname rname ( serial refresh retry expire minimum )
			if sawSOA {
				return fmt.Errorf("line %d: a second SOA", i+1)
			}
			nums := numbersIn(fields)
			if len(nums) != 5 {
				return fmt.Errorf("line %d: SOA carries %d numbers, want 5: %q", i+1, len(nums), line)
			}
			if len(nums[0]) != 10 {
				return fmt.Errorf("line %d: the serial %q is not YYYYMMDDnn", i+1, nums[0])
			}
			sawSOA = true
		case len(fields) >= 3 && fields[1] == "IN" && fields[2] == "NS":
			if len(fields) != 4 || !strings.HasSuffix(fields[3], ".") {
				return fmt.Errorf("line %d: NS needs one absolute target: %q", i+1, line)
			}
			sawNS = true
		case len(fields) == 4 && fields[1] == "IN" && fields[2] == "CNAME":
			if fields[3] != "." {
				return fmt.Errorf("line %d: an RPZ NXDOMAIN entry must target '.': %q", i+1, line)
			}
			owner := fields[0]
			if strings.Contains(owner, "*") {
				return fmt.Errorf("line %d: wildcard owner: %q", i+1, owner)
			}
			if strings.HasSuffix(owner, ".") {
				return fmt.Errorf("line %d: entry owners are relative to $ORIGIN: %q", i+1, owner)
			}
			if seen[owner] {
				return fmt.Errorf("line %d: duplicate owner %q", i+1, owner)
			}
			seen[owner] = true
			for _, label := range strings.Split(owner, ".") {
				if label == "" || len(label) > 63 {
					return fmt.Errorf("line %d: bad label in %q", i+1, owner)
				}
				for _, r := range label {
					if !(r == '-' || r == '_' || (r >= '0' && r <= '9') ||
						(r >= 'a' && r <= 'z')) {
						return fmt.Errorf("line %d: %q is not a canonical LDH name", i+1, owner)
					}
				}
			}
		default:
			return fmt.Errorf("line %d: unrecognised record: %q", i+1, line)
		}
	}
	switch {
	case !sawOrigin:
		return fmt.Errorf("no $ORIGIN")
	case !sawSOA:
		return fmt.Errorf("no SOA")
	case !sawNS:
		return fmt.Errorf("no NS")
	}
	return nil
}

func numbersIn(fields []string) []string {
	var out []string
	for _, f := range fields {
		if _, err := strconv.Atoi(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}
