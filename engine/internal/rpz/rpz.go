// SPDX-License-Identifier: AGPL-3.0-only

// Package rpz writes the decided plan as an RPZ zone file, and nothing else.
//
// # WHAT MAKES THIS DIFFERENT FROM EVERY OTHER OUTPUT IN THIS TREE
//
// It is the first artefact ScamWall produces that a RESOLVER WILL ACT ON.
// `propose`, `decide` and `shadow` all produce documents a person reads; a
// zone file is loaded by Unbound and changes what the household can reach.
// Everything below is shaped by that one difference: the failure that matters
// is not a wrong report, it is a household that cannot reach its bank.
//
// So the package refuses far more readily than it writes. A degraded input is
// a freeze, not a smaller zone. A cap exceeded is a refusal of the WHOLE run,
// not a partial write — internal/enforce's Adapter contract says an adapter
// that half-applies a plan is worse than one that refuses late, and half a
// zone is exactly that: the hosts that did not fit are unblocked, silently.
//
// # THE ALLOWLIST INVERSION, WHICH IS THE NEW HARM HERE
//
// On Pinga53, Pi-hole FTL forwards ALLOWED queries onward to Unbound. An RPZ
// entry in Unbound therefore sits BELOW the household's own allow entries in
// the query path and overrides them: a host the household explicitly allowed
// would be NXDOMAIN anyway, and the allow entry that was supposed to fix it
// would have no effect at all. On the Pi-hole shadow path an allowed host is
// merely an inert addition; here it is an override of the household. That is
// why the snapshot is mandatory, why an unreadable one freezes the run, and
// why a covered host is excluded and sent to a person rather than written.
//
// # WHAT THIS PACKAGE CANNOT DO
//
// Reach a network, reload a resolver, or read a real allow list. It takes the
// snapshot through internal/shadow's interfaces and, in this order, the only
// implementations it is given are offline. Loading the zone into Unbound is a
// separate operator-run order.
package rpz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/atomicfile"
	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/enforce"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/safetext"
	"github.com/dubyfls/Pinga53/engine/internal/shadow"
)

const (
	// DefaultOrigin is the zone the entries hang under. Configurable because
	// an operator with an existing rpz: block may already use another name,
	// and a second zone with the same origin would be ambiguous.
	DefaultOrigin = "scamwall.rpz."
	// DefaultMaxEntries bounds one zone. Above it the run refuses: a zone two
	// orders of magnitude larger than the household's ledger is a data
	// problem, and loading it would be the mass-blocking mirror of §1 harm 1.
	DefaultMaxEntries = 50000
	// zoneTTL is short on purpose. An entry withdrawn by the next run should
	// stop being served in a minute, not in a day.
	zoneTTL = 60
	// digestPrefixLen is how much of a decision digest an entry comment
	// carries. Enough to find the decision, far too little to be a hash of
	// the hostname somebody could grind.
	digestPrefixLen = 12
	// maxName is the longest owner name a zone entry may have, leaving room
	// for the separator and the origin.
	maxName = 255
)

// ErrNoName is a standing entry with no canonical name.
var ErrNoName = errors.New("rpz: the entry has no canonical name")

// Review reasons. Closed, and each names the rule that fired rather than the
// outcome, so an operator reading one knows which entry to go and look at.
const (
	ReasonProtected        = "protected_by_household_exception"
	ReasonExactAllow       = "overridden_by_household_exact_allow"
	ReasonRegexAllow       = "overridden_by_household_regex_allow"
	ReasonSubscribedAllow  = "overridden_by_subscribed_allowlist"
	ReasonAllowNotKnown    = "subscribed_allowlist_membership_unknown"
	ReasonInvalidHost      = "not_a_canonical_host"
	ReasonIdentityWithheld = "identity_withheld"
)

// Snapshot is the household's allow answer, read at ENFORCEMENT time.
//
// Not at decision time. The decider's view of the allow lists can be minutes
// or hours old, and an allow entry added in between is exactly the case this
// is here to catch: somebody unblocking their bank while an unattended run is
// in flight.
//
// Both halves are internal/shadow's interfaces rather than new ones. C-25
// already models the three kinds — exact allow, regex allow, subscribed
// allowlist — and a second model of the same thing would be a second place
// for the POSIX-versus-RE2 question to be answered differently.
type Snapshot struct {
	// Allow answers the exact and regex kinds.
	Allow shadow.AllowList
	// Subscribed answers the third: lists the household subscribed to.
	Subscribed shadow.SubscribedLists
}

// Readable reports whether the snapshot may be acted on, and why not.
//
// A NIL interface, an UNREAD list and a PARTIALLY EVALUABLE one are all
// refusals. The third is the one that looks safe and is not: C-25's rule is
// that with a pattern this build could not read, "not allowed" means "no
// pattern I could read matched", which is a weaker statement and does not
// license a block. A zone entry IS a block, and there is no way to tell WHICH
// hosts an unreadable pattern would have covered — so the whole run freezes
// rather than a subset being held.
func (s Snapshot) Readable() (bool, string) {
	switch {
	case s.Allow == nil:
		return false, "no allow-list snapshot was supplied. On Pinga53 an RPZ entry overrides the " +
			"household's own allow entries, so a zone written without one could unblockably block " +
			"something the household asked for"
	case s.Subscribed == nil:
		return false, "no subscribed-list snapshot was supplied, so a host the household's own " +
			"subscribed allowlists cover cannot be recognised"
	case !s.Allow.Read():
		return false, "the household's allow entries were not read by this run: " + s.Allow.Source()
	case !s.Subscribed.Read():
		return false, "the household's subscribed lists were not read by this run: " + s.Subscribed.Source()
	case s.Allow.Unevaluable() > 0:
		return false, fmt.Sprintf("%d of the household's allow patterns could not be evaluated "+
			"faithfully, so 'not allowed' means only 'no pattern this build could read matched'. "+
			"That does not license a block, and there is no way to say which hosts the unreadable "+
			"patterns cover", s.Allow.Unevaluable())
	}
	return true, ""
}

// covers reports whether the snapshot allows a host, and which kind said so.
func (s Snapshot) covers(host string) (string, bool) {
	if exact, regex := s.Allow.Cover(host); exact {
		return ReasonExactAllow, true
	} else if regex {
		return ReasonRegexAllow, true
	}
	if s.Allow.Allowed(host) {
		// Covered by an entry whose kind the caller did not report. Excluded
		// anyway: the answer that matters is "the household allowed it".
		return ReasonExactAllow, true
	}
	switch allow, _ := s.Subscribed.Membership(host); allow {
	case shadow.Yes:
		return ReasonSubscribedAllow, true
	case shadow.Unknown:
		// Unknown is not No. A host this run could not look up is one it
		// cannot say the household did not allow.
		return ReasonAllowNotKnown, true
	}
	return "", false
}

// Writer is the RPZ enforcement adapter. It satisfies enforce.Adapter.
type Writer struct {
	// Path is where the zone goes. The previous zone is kept beside it as
	// Path+".prev" and the sealed record as RecordPath(Path).
	Path string
	// Origin defaults to DefaultOrigin.
	Origin string
	// Now is the instant the serial is derived from. Supplied rather than
	// read, so that two runs over one fixture produce one zone.
	Now time.Time
	// Snapshot is the household's allow answer. Mandatory; see Readable.
	Snapshot Snapshot
	// Policy carries the household's exceptions, which are this tree's
	// protected domains: ORDER 8 C-17 records why there is no separate
	// protected_domains field. A nil Policy protects nothing, which is a
	// state the caller must not reach silently — cmdRPZ requires -policy.
	Policy *proposal.Policy
	// PrevSerial is the last serial the caller has on record, from the
	// ownership ledger. The zone on disk is consulted as well: see nextSerial.
	PrevSerial string
	// MaxEntries defaults to DefaultMaxEntries.
	MaxEntries int
	// AllowEmpty permits a zone with no entries. Off by default: an empty
	// zone is what a broken run produces, and it unblocks everything.
	AllowEmpty bool
	// DryRun computes everything and writes nothing.
	DryRun bool
	// Stale is the caller's acquisition verdict. True freezes the run.
	Stale bool
	// StaleReason is carried into the freeze, verbatim.
	StaleReason string
	// MaxAddsPerRun and MaxRemovalsPerRun are C-20's caps, applied here a
	// second time against the ZONE rather than against the ledger: the two
	// can drift, and the gate that matters is the one in front of the file a
	// resolver reads. Zero is "no cap configured", not "a cap of zero".
	MaxAddsPerRun     int
	MaxRemovalsPerRun int
	// Key seals the record. A nil key writes an unsealed record that says it
	// is unsealed; see mac.Key.Tag.
	Key *mac.Key
}

// Name is the adapter's name.
func (w *Writer) Name() string { return "rpz" }

func (w *Writer) origin() string {
	if w.Origin == "" {
		return DefaultOrigin
	}
	return w.Origin
}

func (w *Writer) maxEntries() int {
	if w.MaxEntries <= 0 {
		return DefaultMaxEntries
	}
	return w.MaxEntries
}

// Enforce produces the zone, or refuses and says why.
//
// # ORDER OF OPERATIONS, AND WHY IT IS THIS ONE
//
// Freeze, then classify, then diff, then gate, then write once. Every refusal
// is discovered before anything on disk is touched, so there is no state in
// which half a decision has been applied. The single write at the end is the
// only line in this package that changes the household's protection.
func (w *Writer) Enforce(p enforce.Plan) (enforce.Result, error) {
	r := enforce.Result{Adapter: w.Name()}

	// 1. Freezes. Both keep the existing zone exactly as it is.
	if w.Stale {
		r.Outcome, r.Reason = enforce.OutcomeFrozen, "the evidence supply is degraded, so this run "+
			"is not in a position to withdraw a block: "+safetext.Clip(w.StaleReason, 300)
		return r, nil
	}
	if ok, why := w.Snapshot.Readable(); !ok {
		r.Outcome, r.Reason = enforce.OutcomeFrozen, "the allow-list snapshot is unusable: "+why
		return r, nil
	}

	// 2. Classify the standing set. Every exclusion is recorded, because a
	//    host silently absent from a zone is a block silently withdrawn.
	desired, review := w.classify(p.Standing)
	r.Review = review

	// 3. Read what is there now. An absent zone is not an empty one: the
	//    difference decides whether "nothing changed" is true.
	current, zoneSerial, exists, err := w.readCurrent()
	if err != nil {
		return r, err
	}

	adds, removals := diff(current, keys(desired))

	// 4. Gates, in the order C-20 puts them: abnormality on what the run
	//    WANTED, then the caps, then the zone's own limits.
	if code, reason := w.gate(adds, removals, len(current)); code != "" {
		r.Outcome, r.Reason = code, reason
		return r, nil
	}
	if len(desired) == 0 && !w.AllowEmpty {
		r.Outcome, r.Reason = enforce.OutcomeRefused, "this run would write a zone with no entries, "+
			"which withdraws every block ScamWall is holding. Pass --allow-empty if that is "+
			"genuinely what the household wants"
		return r, nil
	}
	if len(desired) > w.maxEntries() {
		r.Outcome, r.Reason = enforce.OutcomeRefused, fmt.Sprintf(
			"the zone would hold %d entries and the cap is %d", len(desired), w.maxEntries())
		return r, nil
	}

	r.Entries = len(desired)
	r.Adds, r.Removals = len(adds), len(removals)

	// 5. Nothing to do is a SUCCESS and is not a change. Writing anyway would
	//    bump the serial for no reason, and a serial that moves without the
	//    zone moving trains an operator to ignore it.
	if exists && len(adds) == 0 && len(removals) == 0 {
		r.Outcome = enforce.OutcomeNoChange
		r.Artifact, r.Serial = w.Path, zoneSerial
		r.Reason = "the zone already says exactly this; it was left alone and its serial did not move"
		return r, nil
	}

	serial, err := nextSerial(w.Now, w.PrevSerial, zoneSerial)
	if err != nil {
		return r, err
	}
	zone := w.render(desired, serial)
	sum := sha256.Sum256(zone)
	r.Serial, r.Digest = serial, "sha256:"+hex.EncodeToString(sum[:])

	if w.DryRun {
		// OutcomeReported, not OutcomeApplied: a dry run changed nothing, and
		// the one outcome in the vocabulary meaning "described rather than
		// did" is the honest one. It is deliberately NOT OutcomeNoChange,
		// which claims the zone and the plan already agree.
		r.Outcome = enforce.OutcomeReported
		r.Reason = fmt.Sprintf("--dry-run: %d addition(s) and %d removal(s) would be written to %s "+
			"at serial %s. Nothing was written", len(adds), len(removals), w.Path, serial)
		return r, nil
	}

	if err := w.write(zone, exists); err != nil {
		return r, err
	}
	rec := Record{
		Purpose: string(mac.PurposeRPZZone), Origin: w.origin(), Serial: serial,
		Digest: r.Digest, Entries: len(desired), Adds: len(adds), Removals: len(removals),
		WrittenAt: w.Now.UTC(),
	}
	rec = rec.sealed(w.Key)
	if err := writeRecord(w.Path, rec); err != nil {
		return r, err
	}

	r.Outcome, r.Artifact = enforce.OutcomeApplied, w.Path
	if w.Key == nil {
		r.Reason = "written. The record beside it is UNSEALED: this run held no MAC key, and a " +
			"digest anybody can recompute is not a statement about who produced the zone"
	}
	return r, nil
}

// classify turns the standing set into the entries that may be written and
// the ones a person has to look at.
func (w *Writer) classify(standing []enforce.StandingEntry) (map[string]string, []enforce.ReviewItem) {
	desired := make(map[string]string, len(standing))
	var review []enforce.ReviewItem
	held := func(name, reason, explanation string) {
		review = append(review, enforce.ReviewItem{
			Canonical: name, Reason: reason, Explanation: safetext.Clip(explanation, 300),
		})
	}

	for _, e := range standing {
		if e.Canonical == "" {
			held("", ReasonIdentityWithheld, "this decision's host is withheld under C-09. An "+
				"opaque identifier is not a name, and writing one into a zone would ask a "+
				"resolver about a host that does not exist")
			continue
		}
		canonical, err := domain.Normalize(e.Canonical)
		if err != nil {
			held(e.Canonical, ReasonInvalidHost, "this name does not canonicalise: "+err.Error())
			continue
		}
		host := canonical.String()
		if len(host)+1+len(w.origin()) > maxName {
			held(host, ReasonInvalidHost, fmt.Sprintf(
				"the name is %d bytes and would exceed the %d-byte limit under origin %q",
				len(host), maxName, w.origin()))
			continue
		}
		if w.Policy != nil {
			if m, ok := w.Policy.MatchException(host); ok {
				held(host, ReasonProtected, fmt.Sprintf(
					"the household excepted %q at scope %q; a protected name is never written",
					m.Exception.Canonical(), m.Exception.Scope))
				continue
			}
		}
		if reason, covered := w.Snapshot.covers(host); covered {
			held(host, reason, "the household's own allow entries cover this host. An RPZ entry "+
				"sits below them in the query path and would override the household, so it is "+
				"excluded and left for a person")
			continue
		}
		desired[host] = digestPrefix(e.Digest)
	}

	sort.Slice(review, func(i, j int) bool {
		if review[i].Canonical != review[j].Canonical {
			return review[i].Canonical < review[j].Canonical
		}
		return review[i].Reason < review[j].Reason
	})
	return desired, review
}

// gate applies C-20 to the difference between the plan and the zone.
//
// # WHY A CAP HERE REFUSES THE WHOLE RUN RATHER THAN TRIMMING
//
// For the appliance adapter, a cap is a ration: apply what fits, carry the
// rest. For a FILE, applying what fits means writing a zone missing the
// entries that did not, which withdraws those blocks. Rationing and
// withdrawing are the same act on a whole-state artefact, so the cap becomes
// a review gate instead. The entries stay where they are until a person looks.
func (w *Writer) gate(adds, removals []string, owned int) (enforce.Outcome, string) {
	if w.MaxAddsPerRun > 0 && len(adds) > w.MaxAddsPerRun {
		return enforce.OutcomeReview, fmt.Sprintf(
			"this run would add %d entries and automatic.max_additions_per_run is %d. A batch far "+
				"larger than usual means something changed upstream, and writing the first %d of "+
				"it vets none of it: the zone is left as it is",
			len(adds), w.MaxAddsPerRun, w.MaxAddsPerRun)
	}
	if len(removals) == 0 {
		return "", ""
	}

	// MaxPerRun and MaxPerDay are set to the run's own size where no cap is
	// configured, so that an unconfigured cap does not read as a cap of zero
	// — which would defer every removal — while the abnormal-run rule, which
	// is not a cap and is never optional, still runs.
	perRun, perDay := w.MaxRemovalsPerRun, w.MaxRemovalsPerRun
	if perRun <= 0 {
		perRun, perDay = len(removals), len(removals)
	}
	d := proposal.AssessRemovals(proposal.RemovalInput{
		Proposed: removals, OwnedCount: owned, MaxPerRun: perRun, MaxPerDay: perDay,
	})
	switch {
	case d.Held:
		return enforce.OutcomeReview, string(d.Reason) + ": " + d.Explanation
	case len(d.Deferred) > 0:
		return enforce.OutcomeReview, fmt.Sprintf(
			"%d of this run's %d removals do not fit inside the removal caps. A zone is written "+
				"whole, so writing the ones that fit would withdraw the ones that do not: nothing "+
				"is written and the difference is left for a person",
			len(d.Deferred), len(removals))
	}
	return "", ""
}

// readCurrent reads the zone that is there now.
//
// A MISSING FILE IS NOT AN ERROR AND NOT AN EMPTY ZONE. The third return says
// which, because "the zone already agrees with the plan" is true of an empty
// plan against an empty zone and false against no zone at all — and the
// second of those has to be written.
func (w *Writer) readCurrent() (hosts []string, serial string, exists bool, err error) {
	b, err := os.ReadFile(w.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("rpz: read the current zone: %w", err)
	}
	hosts, serial = ParseZone(b)
	return hosts, serial, true, nil
}

// ParseZone reads back the owners and the serial of a zone this package wrote.
//
// Deliberately forgiving about everything else. It is not a validator — the
// tests carry a strict one — and its only job is to answer "what is already
// blocked" without a hand-edited comment making a run fail.
func ParseZone(b []byte) (hosts []string, serial string) {
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") {
			continue
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "IN" {
			continue
		}
		switch f[2] {
		case "SOA":
			for _, tok := range f[3:] {
				if len(tok) == 10 {
					if _, err := strconv.ParseUint(tok, 10, 64); err == nil {
						serial = tok
						break
					}
				}
			}
		case "CNAME":
			if len(f) == 4 && f[3] == "." {
				hosts = append(hosts, f[0])
			}
		}
	}
	sort.Strings(hosts)
	return hosts, serial
}

// render produces the zone bytes. Sorted, fixed-width, no clock in it but the
// serial: two runs over one state produce one file.
func (w *Writer) render(entries map[string]string, serial string) []byte {
	var b strings.Builder
	b.WriteString("; ScamWall RPZ zone - generated, do not edit by hand.\n")
	b.WriteString("; Exact hosts only; no wildcards. Whether a block should reach subdomains is\n")
	b.WriteString("; an owner decision and this build does not take it.\n")
	b.WriteString("; Each entry carries a short decision-digest prefix and nothing else.\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", w.origin())
	fmt.Fprintf(&b, "$TTL %d\n", zoneTTL)
	fmt.Fprintf(&b, "@ IN SOA localhost. hostmaster.%s ( %s 3600 600 604800 %d )\n",
		w.origin(), serial, zoneTTL)
	b.WriteString("@ IN NS localhost.\n")
	for _, host := range keys(entries) {
		fmt.Fprintf(&b, "%s IN CNAME . ; d=%s\n", host, entries[host])
	}
	return []byte(b.String())
}

// write replaces the zone, keeping the previous one beside it.
//
// The .prev copy goes first. If it fails, nothing else has happened; if the
// zone write fails, atomicfile has left the old zone untouched and .prev is a
// duplicate of it, which is harmless. The other order would leave a run able
// to replace the zone and lose the copy of what it replaced.
func (w *Writer) write(zone []byte, exists bool) error {
	if exists {
		old, err := os.ReadFile(w.Path)
		if err != nil {
			return fmt.Errorf("rpz: read the zone being replaced: %w", err)
		}
		if err := atomicfile.Write(w.Path+".prev", old, 0o644); err != nil {
			return fmt.Errorf("rpz: keep the previous zone: %w", err)
		}
	}
	if err := atomicfile.Write(w.Path, zone, 0o644); err != nil {
		return fmt.Errorf("rpz: write the zone: %w", err)
	}
	return nil
}

// nextSerial is the next YYYYMMDDnn, strictly greater than every serial this
// run can see.
//
// # WHY IT CONSULTS THE ZONE AS WELL AS THE CALLER'S STATE
//
// A serial that goes backwards is a zone a secondary ignores, and the state
// file is the half of this that can be restored from a backup. The zone on
// disk cannot: it is the thing the resolver actually loaded. Taking the
// maximum of both means a restored older ledger cannot re-issue a serial that
// has already been served.
func nextSerial(now time.Time, prev ...string) (string, error) {
	t := now.UTC()
	next := uint64(t.Year())*1000000 + uint64(t.Month())*10000 + uint64(t.Day())*100 + 1
	for _, p := range prev {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64)
		if err != nil {
			continue // not a serial this build wrote; it constrains nothing
		}
		if n >= next {
			next = n + 1
		}
	}
	// A DNS serial is 32 bits. Above that it wraps, and a wrapped serial is a
	// zone that looks older than the one before it.
	if next > 4294967295 {
		return "", fmt.Errorf("rpz: the next serial %d does not fit in 32 bits; the zone's serial "+
			"sequence has to be reset by an operator", next)
	}
	return strconv.FormatUint(next, 10), nil
}

// digestPrefix is the part of a decision digest an entry comment carries.
//
// Hex only, and truncated. A comment is the one place in a generated file
// where arbitrary text tends to end up, and this one is reduced to characters
// that cannot terminate a line, open a record, or say anything about where
// the decision came from.
func digestPrefix(d string) string {
	d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "sha256:")
	var b strings.Builder
	for _, r := range d {
		if b.Len() == digestPrefixLen {
			break
		}
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// diff is what the zone gains and loses. Both inputs are sorted.
func diff(current, desired []string) (adds, removals []string) {
	have := make(map[string]bool, len(current))
	for _, h := range current {
		have[h] = true
	}
	want := make(map[string]bool, len(desired))
	for _, h := range desired {
		want[h] = true
		if !have[h] {
			adds = append(adds, h)
		}
	}
	for _, h := range current {
		if !want[h] {
			removals = append(removals, h)
		}
	}
	sort.Strings(adds)
	sort.Strings(removals)
	return adds, removals
}
