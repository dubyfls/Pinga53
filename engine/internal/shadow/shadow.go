// SPDX-License-Identifier: AGPL-3.0-only

// Package shadow reports the exact change ScamWall would request of a Pi-hole
// it has actually read.
//
// # WHAT MAKES THIS DIFFERENT FROM A PROPOSAL REPORT
//
// internal/proposal answers "which domains meet the policy". That answer is
// the same whether the household's appliance already blocks every one of them
// or none. A shadow comparison answers "what would ScamWall ask this
// appliance to do", and it cannot be produced without the appliance's own
// state: a comparison against a remembered, cached or assumed list is an
// offline proposal with the appliance's name in the heading.
//
// So Compare takes the observed entries as an argument and binds what it was
// told about where they came from. An Observation with no target identity is
// reported as having none — see Observation.Unestablished.
//
// # IT CANNOT WRITE, STRUCTURALLY
//
// This package imports no HTTP client, no Pi-hole adapter and no
// configuration. The observed state arrives as a slice of values. There is
// nothing here that could construct a request, so there is nothing here that
// could construct a mutating one, and the caller that does the reading is
// bounded by pihole.PermittedOperations — a (method, path) allowlist checked
// before name resolution and again on every redirect.
//
// The behavioural half of that claim is measured against a fake server that
// records every request it receives; see the package tests.
package shadow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Entry is one deny entry observed on the target.
//
// A COPY of what was read, not a handle onto it. Comment is carried because
// an operator looking at a conflict wants to see what the household wrote
// beside the entry; it is never consulted to decide anything. See Ownership.
type Entry struct {
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`
}

// Ownership answers whether one observed entry is a block ScamWall itself
// placed.
//
// # WHY THIS IS AN ARGUMENT AND NOT A HEURISTIC
//
// Pi-hole records nothing about which program added an entry. The only
// candidate signals are the domain itself and the free-text comment, and both
// are wrong in the direction that costs the household something:
//
//   - A DOMAIN cannot establish ownership. "It is a scam domain and ScamWall
//     blocks scam domains" would make ScamWall claim, and later remove, an
//     entry a person added deliberately — including one they added for a
//     reason ScamWall's evidence does not know about.
//   - A COMMENT is free text. Anyone and anything can write "scamwall" into
//     it, and a program that treats its own name in a field it does not
//     control as proof of ownership can be made to delete whatever an
//     attacker labels.
//
// So ownership comes from an ownership LEDGER that records what ScamWall
// actually did, and this build has none: the enforcement milestone builds it.
// Until then NoOwnership is the only implementation, every observed entry is
// the household's, and the removal list is empty for the honest reason rather
// than by accident.
type Ownership interface {
	// OwnedByScamWall reports whether the ledger records this exact domain as
	// a block ScamWall placed.
	OwnedByScamWall(domain string) bool
	// Source describes where the answer came from, for the report. A reader
	// must be able to tell "the ledger says no" from "there is no ledger".
	Source() string
}

// NoOwnership is the ownership record this build has: none.
type NoOwnership struct{}

// OwnedByScamWall is false for every domain. See Ownership.
func (NoOwnership) OwnedByScamWall(string) bool { return false }

// Source says so out loud.
func (NoOwnership) Source() string {
	return "none: this build keeps no ownership ledger, so every observed entry is treated as " +
		"the household's and nothing is proposed for removal"
}

// LedgerOwnership is an explicit set of domains a caller states ScamWall owns.
//
// Not a ledger — it is the SHAPE a ledger will fill, and it exists so the
// removal, conflict and correction paths can be tested now rather than
// written blind alongside the enforcement milestone. A caller that has no
// ledger must pass NoOwnership and not an empty LedgerOwnership: the two
// answer every domain identically and describe themselves differently, and
// the description is what a reader acts on.
type LedgerOwnership struct {
	// Domains are the canonical names the ledger records.
	Domains map[string]bool
	// Origin is where the caller got them. Reported verbatim.
	Origin string
}

// OwnedByScamWall consults the set.
func (l LedgerOwnership) OwnedByScamWall(domain string) bool { return l.Domains[domain] }

// Source reports the caller's stated origin.
func (l LedgerOwnership) Source() string {
	if strings.TrimSpace(l.Origin) == "" {
		return "an ownership set was supplied with no stated origin"
	}
	return l.Origin
}

// Observation is the appliance state one shadow run compared against, and
// everything known about where it came from.
type Observation struct {
	// Entries are the exact deny entries read from the target.
	Entries []Entry
	// ReadAt is when the read completed.
	ReadAt time.Time
	// TargetHost is the name whose certificate was verified, as the client
	// was configured. Empty means the caller did not state one.
	TargetHost string
	// TargetAddress is the address actually dialled. Empty means unstated.
	// It is NOT the same fact as TargetHost: a name verified in a
	// certificate says who answered, an address says where.
	TargetAddress string
	// TLSSubject and TLSIssuer identify the certificate the target presented,
	// where the caller recorded them.
	TLSSubject string
	TLSIssuer  string
	// SessionTeardown is what became of the session the read was made under,
	// in the caller's own vocabulary. Empty when the caller did not say.
	SessionTeardown string
	// Complete is whether the read finished. A partial read is NOT a smaller
	// appliance: an interrupted list makes every entry it did not reach look
	// absent, which turns into a proposed addition of something already
	// blocked and — with a ledger — a proposed removal of something still
	// there. A run over an incomplete observation refuses.
	Complete bool
}

// Unestablished names the identities this observation does not carry.
//
// Reported in every plan, including a complete one, because "the program did
// not record which host it read" and "the program read the right host" are
// not distinguishable from a plan that simply omits the field.
func (o Observation) Unestablished() []string {
	var out []string
	for _, f := range []struct {
		name  string
		value string
		why   string
	}{
		{"target_host", o.TargetHost, "the name whose certificate was verified"},
		{"target_address", o.TargetAddress, "the address actually dialled"},
		{"tls_subject", o.TLSSubject, "the subject of the certificate the target presented"},
		{"tls_issuer", o.TLSIssuer, "the issuer of that certificate"},
	} {
		if strings.TrimSpace(f.value) == "" {
			out = append(out, f.name+": "+f.why+" was not recorded by the caller")
		}
	}
	return out
}

// Kind is what ScamWall would do about one domain.
type Kind string

// The change vocabulary. Closed.
const (
	// KindAdd — ScamWall would ask the appliance to block it, and the
	// appliance does not block it now.
	KindAdd Kind = "add"
	// KindAlreadyPresent — it qualifies and the appliance already holds it,
	// under ScamWall's own ownership. Nothing would be requested.
	KindAlreadyPresent Kind = "already_present"
	// KindConflict — it qualifies and the appliance already holds an entry
	// for it that ScamWall does not own. Nothing would be requested, and the
	// entry is reported: an unattended system must not adopt, re-comment or
	// re-create a person's entry, and must not quietly count it as its own.
	KindConflict Kind = "conflict_user_managed"
	// KindRemove — the appliance holds an entry ScamWall's ledger records as
	// its own, and it no longer qualifies. A correction.
	KindRemove Kind = "remove"
	// KindHouseholdAllowed — it qualifies, the appliance holds no deny entry
	// for it, and the household's OWN allow list covers it. Nothing would be
	// requested: the appliance resolves allow against deny in the allow's
	// favour, so the addition would be inert, and a plan that listed it as an
	// addition would be claiming work it will not do. ORDER 8 C-18.
	KindHouseholdAllowed Kind = "household_allowed"
	// KindAllowNotEvaluable — it qualifies, the appliance holds no deny entry
	// for it, and at least one household allow pattern could not be evaluated
	// faithfully. ScamWall withholds rather than guessing: "no pattern I could
	// read matched" is a weaker statement than "no pattern matched", and only
	// the second licenses a block.
	KindAllowNotEvaluable Kind = "allow_not_evaluable"
	// KindDisabledEntry — it qualifies, an entry exists, and the entry is
	// DISABLED. Reported separately from already-present: a disabled deny
	// entry blocks nothing, so treating it as satisfied would report the
	// household as protected when they are not.
	KindDisabledEntry Kind = "present_but_disabled"
	// KindReview — it qualifies, nothing above ScamWall's exact deny in the
	// appliance's documented order covers it, and the addition would beat
	// something BELOW it that belongs to the household: a list they
	// subscribed to. Nothing would be requested. C-25, and see
	// LabelAdd for the order.
	//
	// Also the answer when subscribed membership could not be read at all:
	// "I could not check whether I would be overriding the household" is not
	// a reason to go ahead.
	KindReview Kind = "review_overrides_household_subscription"
)

// Change is one line of the shadow plan.
type Change struct {
	Kind Kind `json:"kind"`
	// Precedence is where this domain sits in the appliance's documented
	// decision order, for a domain ScamWall would add. Empty on kinds that
	// propose no addition. See LabelAdd.
	Precedence AddLabel `json:"precedence,omitempty"`
	// Domain is the name. Present on every kind: nothing in this package is
	// reached for a value the proposal report withheld — see Compare.
	Domain string `json:"domain"`
	// ObservedComment is the free text beside an existing entry, clipped.
	// Reported so an operator can see what the household wrote; never
	// consulted to decide anything.
	ObservedComment string `json:"observed_comment,omitempty"`
	// Explanation is why this line reads the way it does.
	Explanation string `json:"explanation"`
}

// maxComment bounds an observed comment as it is printed. The appliance's
// database is a place a person — or a program — can put arbitrary text.
const maxComment = 200

// Plan is one shadow comparison, whole.
type Plan struct {
	// Binding is the identity of everything this plan was computed from.
	Binding Binding `json:"binding"`
	// Changes are every line, sorted by kind then domain.
	Changes []Change `json:"changes"`
	// Unestablished names identities the program could not establish.
	Unestablished []string `json:"unestablished"`
	// Limitations is what this plan does not establish. Travels inside the
	// document, as internal/proposal's does, so quoting a count without it
	// takes effort.
	Limitations []string `json:"limitations"`
}

// Binding is the complete identity of one shadow comparison's inputs.
type Binding struct {
	// EvidenceDigest and PolicyDigest are copied from the proposal report, so
	// a shadow plan and the report it came from can be compared.
	EvidenceDigest string `json:"evidence_digest"`
	PolicyDigest   string `json:"policy_digest"`
	// ReportEvaluatedAt is the instant the evidence was judged against.
	ReportEvaluatedAt string `json:"report_evaluated_at"`
	// ObservedStateDigest is over the appliance state this plan compared
	// against. Two plans over the same appliance at two instants are
	// different plans, and this is what says so.
	ObservedStateDigest string `json:"observed_state_digest"`
	// ObservedEntries is how many entries were read.
	ObservedEntries int `json:"observed_entries"`
	// TargetHost, TargetAddress, TLSSubject, TLSIssuer are what the caller
	// established about who answered. Empty fields are ALSO listed in
	// Plan.Unestablished, so absence is a statement.
	TargetHost    string `json:"target_host,omitempty"`
	TargetAddress string `json:"target_address,omitempty"`
	TLSSubject    string `json:"tls_subject,omitempty"`
	TLSIssuer     string `json:"tls_issuer,omitempty"`
	// ObservedAt is when the read completed; ComparedAt is when this
	// comparison ran. Two fields, because the gap between them is exactly
	// the window in which the appliance can have moved.
	ObservedAt string `json:"observed_at"`
	ComparedAt string `json:"compared_at"`
	// SessionTeardown is what became of the session that produced this read.
	//
	// IN the document, and not printed after it. A machine-readable plan
	// followed by a paragraph of prose is not a machine-readable plan; and a
	// plan whose session outcome was only ever a line on a terminal could be
	// filed as evidence with no record of whether ScamWall left a session
	// standing on the household's appliance.
	//
	// The vocabulary is the adapter's, carried as a string so this package
	// does not import it.
	SessionTeardown string `json:"session_teardown"`
	// OwnershipSource is where the ownership answers came from.
	OwnershipSource string `json:"ownership_source"`
	// BuildIdentity is the code that produced this plan, when the caller
	// supplied one, with BuildIdentityState saying which. Same position
	// internal/proposal takes: a plausible wrong answer is worse than an
	// absent one.
	BuildIdentity      string `json:"build_identity,omitempty"`
	BuildIdentityState string `json:"build_identity_state"`
	// SemanticsVersion is THIS package's comparison rules.
	SemanticsVersion int `json:"semantics_version"`
}

// SemanticsVersion is the version of the comparison rules in this package.
//
// History:
//
//	1  the rules as ORDER 7 first built them.
const SemanticsVersion = 1

// timeLayout is the one spelling of an instant. A binding is compared as a
// string, so one moment must have one spelling.
const timeLayout = time.RFC3339

// Input is one shadow comparison.
type Input struct {
	// Qualifying are the canonical names an unattended run would block, from
	// proposal.AutoPlan.Blocks. A name the proposal report was not permitted
	// to print is ABSENT from that list, which is why this package never
	// needs to decide whether it may name something.
	Qualifying []string
	// Allow is the household's allow lists as this run read them, or
	// AllowNotRead. Nil is refused: a nil AllowList and an empty one answer
	// every domain the same way and mean different things.
	Allow AllowList
	// Subscribed answers whether the household's subscribed lists cover a
	// host, or SubscribedNotRead. Nil is refused for AllowList's reason.
	Subscribed SubscribedLists
	// Observed is the appliance state, and where it came from.
	Observed Observation
	// Owned answers which observed entries ScamWall placed. Required: a nil
	// value would be indistinguishable from "nothing is owned" and this
	// package refuses to guess which was meant.
	Owned Ownership
	// EvidenceDigest, PolicyDigest and ReportEvaluatedAt are copied from the
	// proposal report's binding.
	EvidenceDigest    string
	PolicyDigest      string
	ReportEvaluatedAt string
	// ComparedAt is when this comparison runs. Required and explicit, for
	// the reason proposal.Input.At is.
	ComparedAt time.Time
	// BuildIdentity is the code identity, where the caller has one.
	BuildIdentity string
	// EvidenceStale is the caller's statement that the evidence behind
	// Qualifying is past its usable life. A stale run still produces a plan
	// — the plan is the useful artefact — and every addition in it is
	// suppressed, because acting on evidence nobody would act on is the
	// failure this whole repository is about.
	EvidenceStale bool
	// StaleReason is why, reported verbatim.
	StaleReason string
}

// Errors this package returns.
var (
	// ErrIncompleteInput is a comparison that cannot be attempted.
	ErrIncompleteInput = errIncomplete{}
)

type errIncomplete struct{}

func (errIncomplete) Error() string { return "a shadow comparison is missing a required input" }

// Compare reports the exact change ScamWall would request of the target.
//
// # IT REQUESTS NOTHING
//
// The return value is a description. This package has no client, so a caller
// that wanted to act on it would have to write the code that does, and that
// code does not exist in this repository: policy.EnforcementCompiledIn is
// false and policy.Apply returns an error.
func Compare(in Input) (*Plan, error) {
	switch {
	case in.Owned == nil:
		return nil, fmt.Errorf("%w: no ownership answer. A nil Ownership and an empty ledger "+
			"answer every domain the same way and mean different things; pass NoOwnership "+
			"explicitly to say this build has no ledger", ErrIncompleteInput)
	case in.Allow == nil:
		return nil, fmt.Errorf("%w: no allow-list answer. A nil AllowList and an empty one "+
			"answer every domain the same way and mean different things; pass AllowNotRead "+
			"explicitly to say this run did not read them", ErrIncompleteInput)
	case in.Subscribed == nil:
		return nil, fmt.Errorf("%w: no subscribed-list answer. A nil SubscribedLists and one that "+
			"found nothing answer every domain the same way and mean different things; pass "+
			"SubscribedNotRead explicitly to say this run could not read gravity", ErrIncompleteInput)
	case in.ComparedAt.IsZero():
		return nil, fmt.Errorf("%w: no comparison instant", ErrIncompleteInput)
	case !in.Observed.Complete:
		// THE INTERRUPTED READ.
		//
		// A partial list is not a smaller appliance. Every entry the read did
		// not reach looks absent, which becomes a proposed addition of
		// something already blocked and — once a ledger exists — a proposed
		// removal of something still there. There is no safe way to compare
		// against a list that does not know how long it should have been.
		return nil, fmt.Errorf("%w: the read of the target did not complete, so the observed "+
			"state is a prefix of the appliance's list and not the list. Every entry the read "+
			"did not reach would look absent", ErrIncompleteInput)
	}

	present := make(map[string]Entry, len(in.Observed.Entries))
	for _, e := range in.Observed.Entries {
		// FIRST OCCURRENCE WINS, AND A REPEAT IS NOT MERGED.
		//
		// Pi-hole's schema makes a duplicate exact deny entry unlikely; a
		// hostile or corrupted response can still carry one. Taking the last
		// would let a second entry for the same domain, with `enabled: true`,
		// mask a first that is disabled.
		if _, seen := present[e.Domain]; !seen {
			present[e.Domain] = e
		}
	}

	qualifying := make(map[string]bool, len(in.Qualifying))
	var changes []Change
	for _, d := range in.Qualifying {
		if qualifying[d] {
			continue // the same name twice is one request
		}
		qualifying[d] = true
		changes = append(changes, compareOne(d, present, in))
	}

	// REMOVALS, over the observed entries this build is told it owns.
	//
	// Driven from the OBSERVED list rather than from a remembered one: a
	// removal is a request to change something that is there, so the thing
	// has to have been seen.
	for _, e := range in.Observed.Entries {
		if qualifying[e.Domain] || !in.Owned.OwnedByScamWall(e.Domain) {
			continue
		}
		changes = append(changes, Change{
			Kind: KindRemove, Domain: e.Domain, ObservedComment: clip(e.Comment),
			Explanation: "the ownership record says ScamWall placed this block and the current " +
				"evidence and policy no longer qualify it",
		})
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].Domain < changes[j].Domain
	})

	return &Plan{
		Binding: Binding{
			EvidenceDigest:      in.EvidenceDigest,
			PolicyDigest:        in.PolicyDigest,
			ReportEvaluatedAt:   in.ReportEvaluatedAt,
			ObservedStateDigest: observedDigest(in.Observed),
			ObservedEntries:     len(in.Observed.Entries),
			TargetHost:          in.Observed.TargetHost,
			TargetAddress:       in.Observed.TargetAddress,
			TLSSubject:          in.Observed.TLSSubject,
			TLSIssuer:           in.Observed.TLSIssuer,
			ObservedAt:          in.Observed.ReadAt.UTC().Format(timeLayout),
			ComparedAt:          in.ComparedAt.UTC().Format(timeLayout),
			SessionTeardown:     in.Observed.SessionTeardown,
			OwnershipSource:     in.Owned.Source(),
			BuildIdentity:       in.BuildIdentity,
			BuildIdentityState:  buildIdentityState(in.BuildIdentity),
			SemanticsVersion:    SemanticsVersion,
		},
		Changes:       changes,
		Unestablished: in.Observed.Unestablished(),
		Limitations:   limitations(in),
	}, nil
}

// compareOne decides the line for one qualifying domain.
//
// The four `!exists` branches are the appliance's documented order, read from
// the top: C-18 answers levels 1 and 2, C-25 answers levels 3 and 4, and the
// label on every one of them says which level decided.
func compareOne(d string, present map[string]Entry, in Input) Change {
	e, exists := present[d]

	// The state this run could read, in the order's own terms. Computed once
	// so that every branch below labels itself from the same answer.
	exactAllow, regexAllow := in.Allow.Cover(d)
	subAllow, subDeny := in.Subscribed.Membership(d)
	label := LabelAdd(HostState{
		ExactAllow: exactAllow, RegexAllow: regexAllow,
		SubscribedAllow: subAllow, SubscribedDeny: subDeny,
	})

	switch {
	case !exists && in.EvidenceStale:
		// A stale run still SHOWS the addition it would have made, under a
		// kind that requests nothing. Hiding it would make a stale run and a
		// run with nothing to do produce the same document.
		return Change{Kind: KindConflict, Domain: d, Precedence: label,
			Explanation: "would be added, and is NOT requested: the evidence behind it is stale. " +
				clip(in.StaleReason)}
	case !exists && in.Allow.Allowed(d):
		// THE HOUSEHOLD ALREADY SAID YES.
		//
		// Levels 1 and 2 of the documented order. The addition would be
		// inert, and reporting it as an addition would be claiming work that
		// will not happen — the accuracy defect FINDING-132 actually is.
		return Change{Kind: KindHouseholdAllowed, Domain: d, Precedence: label,
			Explanation: "qualifies under the policy, and the household's own allow list covers " +
				"it. Nothing would be requested: an exact or regex allow outranks an exact deny in " +
				"the appliance's documented order, so the entry would be inert"}
	case !exists && in.Allow.Unevaluable() > 0:
		// THE HOUSEHOLD MAY HAVE SAID YES AND SCAMWALL CANNOT READ IT.
		//
		// Ordered after the match above so a host the readable patterns DO
		// cover is reported as allowed rather than as unreadable. What is left
		// here is the genuinely undecidable case.
		return Change{Kind: KindAllowNotEvaluable, Domain: d, Precedence: label,
			Explanation: fmt.Sprintf("qualifies under the policy, and %d of the household's allow "+
				"patterns could not be evaluated faithfully. Nothing would be requested: no pattern "+
				"ScamWall could read covers this name, which is a weaker statement than no pattern "+
				"covering it, and only the second would license a block", in.Allow.Unevaluable())}
	case !exists && label.Review():
		// LEVEL 4: THE HOUSEHOLD'S SUBSCRIBED LISTS.
		//
		// ScamWall's exact deny sits ABOVE them, so this addition would win —
		// against something the household chose. That is not a request an
		// unattended system may make quietly, and "I could not check" is not a
		// reason to go ahead either.
		return Change{Kind: KindReview, Domain: d, Precedence: label,
			Explanation: reviewExplanation(label, in)}
	case !exists && !in.Allow.Read():
		// The allow lists were never read. The addition still stands — this
		// is the behaviour every build before ORDER 8 had — but it is stated
		// as unchecked rather than presented as verified.
		return Change{Kind: KindAdd, Domain: d, Precedence: label,
			Explanation: "qualifies under the policy and the appliance holds no exact deny entry " +
				"for it. NOT checked against the household's allow lists, which this run did not read"}
	case !exists:
		return Change{Kind: KindAdd, Domain: d, Precedence: label,
			Explanation: "qualifies under the policy, the appliance holds no exact deny entry for " +
				"it, no household allow entry covers it, and no subscribed allowlist does either"}
	case !e.Enabled:
		return Change{Kind: KindDisabledEntry, Domain: d, ObservedComment: clip(e.Comment),
			Explanation: "an exact deny entry exists and is DISABLED, so it blocks nothing. " +
				"ScamWall would not enable somebody else's entry, and does not count this as protection"}
	case in.Owned.OwnedByScamWall(d):
		return Change{Kind: KindAlreadyPresent, Domain: d, ObservedComment: clip(e.Comment),
			Explanation: "already blocked, and the ownership record says ScamWall placed it; " +
				"nothing would be requested"}
	default:
		return Change{Kind: KindConflict, Domain: d, ObservedComment: clip(e.Comment),
			Explanation: "already blocked by an entry ScamWall does not own. Nothing would be " +
				"requested: an unattended system must not adopt, re-comment or re-create a " +
				"person's entry, nor count it as its own"}
	}
}

// reviewExplanation says which of the two review cases this is.
//
// They are different facts and an operator acts differently on them: one is
// "ScamWall would override a list you subscribed to", the other is "ScamWall
// cannot tell whether it would".
func reviewExplanation(label AddLabel, in Input) string {
	if label == LabelOverridesSubscribedAllowlist {
		return "qualifies under the policy, and a list the household SUBSCRIBED TO permits it. " +
			"An exact deny outranks a subscribed allowlist in the appliance's documented order, so " +
			"this addition would override the household's own choice. Held for review; nothing is requested"
	}
	return "qualifies under the policy, and this run could not read the household's subscribed " +
		"lists, so it cannot say whether the addition would override one. " + clip(in.Subscribed.Source()) +
		" Held for review; nothing is requested"
}

// Counts totals one plan by kind.
func (p *Plan) Counts() map[Kind]int {
	out := map[Kind]int{}
	for _, c := range p.Changes {
		out[c.Kind]++
	}
	return out
}

// Requests reports whether this plan would ask the appliance for anything.
func (p *Plan) Requests() bool {
	for _, c := range p.Changes {
		if c.Kind == KindAdd || c.Kind == KindRemove {
			return true
		}
	}
	return false
}

// limitations is what one plan does not establish.
func limitations(in Input) []string {
	out := []string{
		"This is a description of a change, not a request for one. This package imports no HTTP client and no Pi-hole adapter; nothing in this build can apply a line of it.",
		"The comparison is only as good as the read it was given. A plan carries the digest of the state it compared against, and the appliance can have changed between the read and now: the two instants in the binding are that window.",
		"Ownership is what the ownership record said, not what the appliance knows. Pi-hole records nothing about which program added an entry, and neither a domain nor a comment establishes one. " + in.Owned.Source(),
		"An entry ScamWall does not own is left ALONE, whatever it says. A conflict line is a report, never a step towards taking the entry over.",
	}
	if in.EvidenceStale {
		out = append(out, "THE EVIDENCE BEHIND THIS PLAN IS STALE and every addition is suppressed: "+clip(in.StaleReason))
	}
	return out
}

// observedDigest is over the observed state, canonically.
//
// Over the VALUES and not the response bytes: two reads that returned the same
// entries in a different order observed the same appliance, and a digest that
// said otherwise would make every run look like a change.
func observedDigest(o Observation) string {
	entries := append([]Entry(nil), o.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Domain != entries[j].Domain {
			return entries[i].Domain < entries[j].Domain
		}
		return entries[i].Comment < entries[j].Comment
	})
	b, err := json.Marshal(struct {
		Label   string  `json:"label"`
		Entries []Entry `json:"entries"`
	}{"pihole-deny-exact", entries})
	if err != nil {
		// Entry holds two strings and a bool. Marshal cannot fail on it, and
		// a digest that silently became the empty string would be worse than
		// a panic a test would catch.
		panic("shadow: observed state could not be encoded: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

const (
	buildIdentityAbsent  = "absent"
	buildIdentityPresent = "present"
)

func buildIdentityState(id string) string {
	if strings.TrimSpace(id) == "" {
		return buildIdentityAbsent
	}
	return buildIdentityPresent
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		// Control characters out of anything that reaches a terminal. The
		// appliance's comment field is somewhere a person — or a program —
		// can put arbitrary bytes.
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) <= maxComment {
		return s
	}
	return s[:maxComment] + "…"
}

// JSON writes the machine-readable plan.
func (p *Plan) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// Text writes the operator-readable plan.
func (p *Plan) Text(w io.Writer) {
	fmt.Fprintln(w, "scamwall shadow comparison (read-only, against state read from the target)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "bindings")
	fmt.Fprintf(w, "  evidence        %s\n", p.Binding.EvidenceDigest)
	fmt.Fprintf(w, "  policy          %s\n", p.Binding.PolicyDigest)
	fmt.Fprintf(w, "  evidence judged %s\n", p.Binding.ReportEvaluatedAt)
	fmt.Fprintf(w, "  target host     %s\n", orNone(p.Binding.TargetHost))
	fmt.Fprintf(w, "  target address  %s\n", orNone(p.Binding.TargetAddress))
	fmt.Fprintf(w, "  tls subject     %s\n", orNone(p.Binding.TLSSubject))
	fmt.Fprintf(w, "  tls issuer      %s\n", orNone(p.Binding.TLSIssuer))
	fmt.Fprintf(w, "  observed state  %s  (%d entr%s)\n", p.Binding.ObservedStateDigest,
		p.Binding.ObservedEntries, plural(p.Binding.ObservedEntries))
	fmt.Fprintf(w, "  observed at     %s\n", p.Binding.ObservedAt)
	fmt.Fprintf(w, "  compared at     %s\n", p.Binding.ComparedAt)
	fmt.Fprintf(w, "  session         %s\n", orNone(p.Binding.SessionTeardown))
	fmt.Fprintf(w, "  ownership       %s\n", p.Binding.OwnershipSource)
	fmt.Fprintf(w, "  semantics       v%d  (a RULE version, not a build stamp)\n", p.Binding.SemanticsVersion)
	if p.Binding.BuildIdentityState == buildIdentityPresent {
		fmt.Fprintf(w, "  built by        %s\n", p.Binding.BuildIdentity)
	} else {
		fmt.Fprintln(w, "  built by        NOT SUPPLIED — this plan does not identify the code")
		fmt.Fprintln(w, "                  that produced it.")
	}

	if len(p.Unestablished) > 0 {
		fmt.Fprintln(w, "\nidentities this program could NOT establish:")
		for _, u := range p.Unestablished {
			fmt.Fprintf(w, "  - %s\n", u)
		}
	}

	c := p.Counts()
	fmt.Fprintf(w, "\n%d change line(s): %d add, %d held for review, %d already present, "+
		"%d present but disabled, %d conflict, %d remove, %d household-allowed, %d allow-not-evaluable\n",
		len(p.Changes), c[KindAdd], c[KindReview], c[KindAlreadyPresent],
		c[KindDisabledEntry], c[KindConflict], c[KindRemove],
		c[KindHouseholdAllowed], c[KindAllowNotEvaluable])
	if !p.Requests() {
		fmt.Fprintln(w, "ScamWall would request no change of this appliance.")
	}

	// EVERY kind is rendered. A count line that names a category the body
	// never prints sends its reader looking for lines that are not there;
	// KindReview, KindHouseholdAllowed and KindAllowNotEvaluable are the ones
	// this build actually produces most of the time.
	for _, kind := range []Kind{
		KindAdd, KindReview, KindRemove, KindConflict, KindDisabledEntry,
		KindAlreadyPresent, KindHouseholdAllowed, KindAllowNotEvaluable,
	} {
		var sel []Change
		for _, ch := range p.Changes {
			if ch.Kind == kind {
				sel = append(sel, ch)
			}
		}
		if len(sel) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", kind)
		for _, ch := range sel {
			fmt.Fprintf(w, "  %s\n", ch.Domain)
			if ch.Precedence != "" {
				fmt.Fprintf(w, "      precedence: %s\n", ch.Precedence)
			}
			fmt.Fprintf(w, "      %s\n", ch.Explanation)
			if ch.ObservedComment != "" {
				fmt.Fprintf(w, "      the entry's comment reads: %q\n", ch.ObservedComment)
			}
		}
	}

	fmt.Fprintln(w, "\nwhat this plan does not establish")
	for _, l := range p.Limitations {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}

func orNone(s string) string {
	if s == "" {
		return "NOT ESTABLISHED"
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
