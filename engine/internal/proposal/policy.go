// SPDX-License-Identifier: AGPL-3.0-only

// Package proposal turns authenticated, attributed evidence into domain
// proposals with explicit matching rules, exceptions and reasons.
//
// # WHAT A PROPOSAL IS, AND WHAT IT IS NOT
//
// A proposal is a statement that, under one named policy, over one bound set
// of evidence, at one recorded instant, a domain met the stated conditions.
//
// It is NOT permission to enforce anything. `policy.EnforcementCompiledIn` is
// false in every build of this repository, `policy.Apply` returns an error,
// and this package imports neither the Pi-hole adapter nor the configuration
// package. Producing a proposal and applying one are separate acts, separated
// here by the absence of any code that could perform the second.
//
// # THREE OUTCOMES, NOT TWO
//
// Propose, abstain, refuse — and they answer different questions. Abstaining
// says the evidence was read and did not meet the policy. Refusing says the
// evidence was not admissible at all: nobody could vouch for the source, the
// signer had no authority to speak for it, the rights position forbids the
// operation. Folding a refusal into an abstention would report an
// authorisation failure as a policy outcome, and an operator would tune the
// policy to fix something the policy cannot fix.
package proposal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/safetext"
	"github.com/dubyfls/Pinga53/engine/internal/strictjson"
)

// PolicySchemaVersion is the version of the operator's proposal policy
// document.
const PolicySchemaVersion = 1

// Bounds on the operator's policy document.
const (
	// MaxPolicyBytes bounds the file.
	MaxPolicyBytes = 4 << 20
	// MaxExceptions bounds how many exceptions one policy may carry.
	MaxExceptions = 10000
	// MaxNoteBytes bounds one operator note as it is PRINTED.
	MaxNoteBytes = 200
)

// Errors raised by the policy path.
var (
	// ErrPolicySchema is a document that is not a policy of a version this
	// build reads.
	ErrPolicySchema = errors.New("proposal policy is not a document this build reads")
	// ErrPolicyInvalid is a policy that parses and is still not usable.
	ErrPolicyInvalid = errors.New("proposal policy is invalid")
	// ErrPolicyTooLarge is a policy above the bound.
	ErrPolicyTooLarge = errors.New("proposal policy exceeds the maximum accepted size")
)

// Scope is how far a rule or an exception reaches.
//
// # WHY SCOPE IS WRITTEN DOWN AND NEVER INFERRED
//
// "Block example.com" is ambiguous in the way that matters: it may mean that
// one name, or everything under it. Inferring which is meant from the shape of
// the name — counting labels, guessing at a registrable domain — produces a
// rule whose reach depends on a heuristic the operator never saw. So the scope
// is a field, it has no default, and a document that omits it is refused.
type Scope string

// The scope vocabulary. Closed, and both members are spelled out in the
// document rather than implied by the other's absence.
const (
	// ScopeExact covers the name itself and nothing else.
	ScopeExact Scope = "exact"
	// ScopeSubdomains covers every name strictly beneath it, and NOT the name
	// itself.
	//
	// # THE APEX DECISION, STATED WHERE IT IS IMPLEMENTED
	//
	// Whether `subdomains` should also cover the apex is a product choice and
	// this is the one taken: it does not. The two scopes are separate and
	// compose, so an operator who wants both writes both, and an operator who
	// wants only the children can say so. Under the other reading —
	// subdomains-includes-apex — "children but not the apex" becomes
	// unsayable, and an operator who needs it has no spelling at all.
	//
	// It is revisable without a silent change of meaning, because the scope is
	// explicit in every document that uses it: a future version that changed
	// the rule would be a schema version, not a re-reading.
	//
	// # THE DANGEROUS CASE, AND WHERE IT IS ALREADY REFUSED
	//
	// `subdomains` on `com` would reach every name under `com` — one line of
	// an operator's file proposing, or excepting, the whole internet. This
	// package was designed with a guard against that and then did not need
	// one: internal/domain.Normalize ALREADY refuses a public suffix and a
	// single label outright, using the same compiled list
	// (golang.org/x/net/publicsuffix, already a requirement of this module),
	// so `com`, `co.uk` and `github.io` never become canonical names at all
	// and no scope can be written against them.
	//
	// The guard was deleted rather than kept as defence in depth. A second
	// copy of one rule is a second behaviour as soon as one of them is
	// corrected, and this one would have been the copy that nobody
	// maintained. What is kept is the test: TestASubdomainRuleOnAPublicSuffix
	// IsRefused asserts the property at THIS package's surface, so the
	// requirement is measured here whatever internal/domain does later.
	//
	// The limitation, stated: the list is a snapshot compiled into
	// golang.org/x/net, not a live one. A name that becomes a public suffix
	// after this build was compiled is not refused.
	ScopeSubdomains Scope = "subdomains"
)

// Valid reports whether s is one of the two scopes.
func (s Scope) Valid() bool { return s == ScopeExact || s == ScopeSubdomains }

// ValidScopes is the closed vocabulary, for diagnostics.
var ValidScopes = []Scope{ScopeExact, ScopeSubdomains}

// Exception is one name the operator will not have proposed.
//
// # WHY AN EXCEPTION IS NOT A NEGATIVE PROPOSAL
//
// It is the household's own statement, and it outranks every source. A bank
// the household uses, a school portal, an employer's VPN endpoint: the cost of
// proposing one of those is not symmetric with the cost of missing a scam
// site, and no amount of corroboration from strangers should be able to
// override the person whose network it is.
type Exception struct {
	// Value is the name, as the operator wrote it. Canonicalised on load.
	Value string `json:"value"`
	// Scope is how far the exception reaches. Required.
	Scope Scope `json:"scope"`
	// Note is the operator's own record of why. Printed, bounded, escaped.
	Note string `json:"note,omitempty"`

	// canonical is Value in canonical form, filled by LoadPolicy.
	canonical string
}

// Canonical is the exception's canonical form.
func (e Exception) Canonical() string { return e.canonical }

// Policy is the operator's whole statement about how evidence becomes a
// proposal.
type Policy struct {
	SchemaVersion int    `json:"schema_version"`
	Note          string `json:"note,omitempty"`

	// MinIndependentSources is how many established-independent sources must
	// assert an indicator adversely before it is proposed.
	//
	// A POINTER, and required. There is no default, because any default would
	// be a recommendation this project is in no position to make: the right
	// number depends on which sources are enabled, what their lineage is, and
	// what the household's tolerance for a false proposal is. A policy that
	// omits it is refused rather than given a number somebody would later
	// quote as ScamWall's advice.
	MinIndependentSources *int `json:"min_independent_sources"`

	// ProposalScope is the scope every proposal this policy produces carries.
	// Required, for the reason Scope documents.
	ProposalScope Scope `json:"proposal_scope"`

	// AcceptUnestablishedIndependence counts sources whose independence the
	// registry cannot establish. Defaults to false, which is the fail-closed
	// direction: an unknown upstream is not demonstrated independence.
	AcceptUnestablishedIndependence bool `json:"accept_unestablished_independence"`

	// AcceptAuthoritativeAlone lets ONE source holding the registry's
	// `authoritative` tier satisfy the threshold by itself.
	//
	// Defaults to false, and the default is the point. The tier is a claim
	// the registry author makes about a provider; acting on one source is a
	// decision about the household's own risk, and a registry must not be
	// able to grant itself permission to take it. Only primary lineage may
	// hold the tier — see sourceregistry.validateTiers — so this switch
	// cannot be a route back to counting a republished corpus twice.
	AcceptAuthoritativeAlone bool `json:"accept_authoritative_alone"`

	// HouseholdLocalUse states that this run's decisions only protect the
	// household's own network: the zone is loaded by the household's own
	// resolver and nothing derived is shown to, or published for, anyone
	// else. Then the rights a decision needs are the LOCAL ones (retrieval,
	// local_storage, enrichment) and `derived_output` is not asked, because
	// no derived result leaves the house. Publishing stays gated exactly as
	// before: every outcome still carries ExportWithheld from
	// Indicator.Exportable, and `scamwall publish` requires derived_output +
	// redistribution (plus commercial_use for the paid feed).
	//
	// Defaults to false, which keeps the stricter gate.
	HouseholdLocalUse bool `json:"household_local_use,omitempty"`

	// Exceptions are the household's own refusals.
	Exceptions []Exception `json:"exceptions"`

	// Automatic is the household's unattended-blocking contract. ABSENT means
	// the household has not started stating it, which is a different thing
	// from an incomplete one and is reported differently. See automatic.go.
	Automatic *Automatic `json:"automatic,omitempty"`

	// exceptionsPresent records whether the document carried the key at all.
	//
	// An absent `exceptions` and an empty one decode identically into a nil
	// slice, and they are not the same statement: one household has decided
	// they have no exceptions, the other has not been asked. That difference
	// is invisible in the decoded value and matters for unattended blocking,
	// so the presence is taken from the raw document and kept.
	exceptionsPresent bool
}

// ExceptionsStated reports whether the policy document carried an
// `exceptions` key, empty or not.
//
// See Policy.exceptionsPresent: the decoded value cannot tell "we have none"
// apart from "we have not been asked", and the automatic contract needs to.
func (p *Policy) ExceptionsStated() bool { return p.exceptionsPresent }

// LoadPolicy reads and validates a policy document.
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path) //nolint:gosec // an operator path given on the command line
	if err != nil {
		return nil, fmt.Errorf("open proposal policy: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err == nil && info.Size() > MaxPolicyBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrPolicyTooLarge, info.Size(), MaxPolicyBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read proposal policy: %w", err)
	}
	if int64(len(b)) > MaxPolicyBytes {
		return nil, fmt.Errorf("%w: max %d", ErrPolicyTooLarge, MaxPolicyBytes)
	}
	return ParsePolicy(b)
}

// ParsePolicy validates a policy held in memory.
// policyNames is this document's closed set of field names, for the
// duplicate-key diagnostic.
var policyNames = sync.OnceValue(func() map[string]bool {
	return strictjson.FieldNames(Policy{})
})

func ParsePolicy(b []byte) (*Policy, error) {
	// AMBIGUITY IS CHECKED BEFORE THE DECODE, over the raw tokens.
	//
	// Measured against 9dcb191 through the real command, a policy naming
	// min_independent_sources twice — 1 then 99 — was accepted and the run
	// used 99. A reviewer reading that file sees 1 (FINDING-127). After the
	// decode there is nothing left to check: encoding/json keeps the last
	// value and reports nothing.
	if err := strictjson.CheckDuplicates(b, policyNames()); err != nil {
		return nil, fmt.Errorf("parse proposal policy: %w", err)
	}
	var p Policy
	if err := strictUnmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse proposal policy: %w", err)
	}
	if p.SchemaVersion != PolicySchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrPolicySchema, p.SchemaVersion, PolicySchemaVersion)
	}
	if p.MinIndependentSources == nil {
		return nil, fmt.Errorf("%w: min_independent_sources is required and has no default; "+
			"the right number depends on which sources are enabled and what their lineage is, "+
			"and this build is in no position to choose one", ErrPolicyInvalid)
	}
	if *p.MinIndependentSources < 1 {
		return nil, fmt.Errorf("%w: min_independent_sources is %d; a threshold of zero proposes "+
			"everything any source mentions, which is not a policy", ErrPolicyInvalid, *p.MinIndependentSources)
	}
	if !p.ProposalScope.Valid() {
		return nil, fmt.Errorf("%w: proposal_scope is %q; it must be one of %s",
			ErrPolicyInvalid, safetext.Clip(string(p.ProposalScope), 32), joinScopes())
	}
	if len(p.Exceptions) > MaxExceptions {
		return nil, fmt.Errorf("%w: %d exceptions (max %d)", ErrPolicyInvalid, len(p.Exceptions), MaxExceptions)
	}

	// A PRESENT-AND-MALFORMED automatic value is an error; an ABSENT one is
	// not. See Automatic: the whole point of the contract is that a value the
	// household has not chosen stays visibly unchosen, so a policy with an
	// incomplete block loads and reports itself as unresolved. A value they
	// DID write and got wrong is refused, because this build cannot guess
	// what a negative limit meant.
	if err := validateAutomatic(p.Automatic); err != nil {
		return nil, err
	}

	// The presence of `exceptions`, taken from the raw document.
	//
	// json.Unmarshal into map[string]json.RawMessage rather than a second
	// full decode: it is one shallow pass over bytes that strictUnmarshal has
	// already proved to be a well-formed object with no unknown fields and no
	// duplicate keys, so nothing here can disagree with the decoded value.
	var present map[string]json.RawMessage
	if err := json.Unmarshal(b, &present); err != nil {
		return nil, fmt.Errorf("parse proposal policy: %w", err)
	}
	_, p.exceptionsPresent = present["exceptions"]

	seen := make(map[string]bool, len(p.Exceptions))
	for i := range p.Exceptions {
		e := &p.Exceptions[i]
		if !e.Scope.Valid() {
			return nil, fmt.Errorf("%w: exception %d has scope %q; it must be one of %s",
				ErrPolicyInvalid, i, safetext.Clip(string(e.Scope), 32), joinScopes())
		}
		// Assess, not Normalize: an exception is a name the OPERATOR wrote,
		// and a syntax error in it is an error in the policy rather than a
		// suspicious name. The signals are not consulted here — an exception
		// is the household's own statement and is not second-guessed by a
		// property of the spelling.
		canonical, err := domain.Normalize(e.Value)
		if err != nil {
			return nil, fmt.Errorf("%w: exception %d (%q) is not a valid domain: %v",
				ErrPolicyInvalid, i, domain.Clip(e.Value), err)
		}
		e.canonical = canonical.String()

		// Two exceptions with the same canonical name and scope are refused
		// rather than deduplicated: the operator wrote the same rule twice and
		// probably meant two different things by the second one.
		k := e.canonical + "/" + string(e.Scope)
		if seen[k] {
			return nil, fmt.Errorf("%w: %s is excepted twice at scope %s",
				ErrPolicyInvalid, e.canonical, e.Scope)
		}
		seen[k] = true
	}
	return &p, nil
}

func joinScopes() string {
	out := make([]string, 0, len(ValidScopes))
	for _, s := range ValidScopes {
		out = append(out, string(s))
	}
	return strings.Join(out, ", ")
}

// Covers reports whether a rule on base, at this scope, reaches query.
//
// # WHY THIS IS LABEL COMPARISON AND NOT strings.HasSuffix
//
// Both arguments are canonical forms from internal/domain, which means
// lowercase, punycode, one trailing root dot removed, IDNA-mapped. A naive
// suffix test over such strings is still wrong in the direction that matters:
//
//	HasSuffix("notbad.example.com", "bad.example.com") == true
//
// and `notbad.example.com` is somebody else's domain. Requiring the separator
// to be part of the match is what makes the comparison be about LABELS rather
// than about characters — the boundary is the dot, and demanding it is present
// is demanding that the match ends where a label ends.
//
// Substring matching is not used anywhere in this package for the same reason,
// one step worse: `example.com.attacker.net` contains `example.com`.
func Covers(base string, scope Scope, query string) bool {
	switch scope {
	case ScopeExact:
		return query == base
	case ScopeSubdomains:
		// Strictly beneath: the apex is a different rule. See ScopeSubdomains.
		return query != base && strings.HasSuffix(query, "."+base)
	default:
		// An unknown scope reaches nothing. A scope this build does not
		// understand must not be read as the more permissive of the two it
		// does.
		return false
	}
}

// ExceptionMatch is the exception that shadowed a proposal, and why it won.
type ExceptionMatch struct {
	Exception Exception
	// Specificity is the number of canonical labels the exception names. It is
	// what decides between two matching exceptions.
	Specificity int
}

// MatchException finds the exception that applies to a canonical name.
//
// # PRECEDENCE, AND WHY IT IS THIS ONE
//
// More than one exception can match: `example.com` at `subdomains` and
// `pay.example.com` at `exact` both reach `pay.example.com`. The winner is the
// most specific — the one naming more labels — and `exact` beats `subdomains`
// at equal specificity.
//
// This is the only rule under which adding a NARROWER exception cannot change
// the decision about any name the narrower one does not itself reach. Under
// "first match wins" the answer depends on file order; under "broadest wins" a
// household that excepts one subdomain would silently widen an existing rule.
// Both of those make an operator's edit have effects away from where they made
// it.
//
// The order is total: specificity, then exact-before-subdomains, then the
// canonical name. Two exceptions cannot tie, because ParsePolicy refuses a
// repeated (name, scope) pair.
func (p *Policy) MatchException(canonical string) (ExceptionMatch, bool) {
	var best ExceptionMatch
	found := false
	for _, e := range p.Exceptions {
		if !Covers(e.canonical, e.Scope, canonical) {
			continue
		}
		m := ExceptionMatch{Exception: e, Specificity: labelCount(e.canonical)}
		if !found || moreSpecific(m, best) {
			best, found = m, true
		}
	}
	return best, found
}

// moreSpecific implements the total order MatchException documents.
func moreSpecific(a, b ExceptionMatch) bool {
	if a.Specificity != b.Specificity {
		return a.Specificity > b.Specificity
	}
	if a.Exception.Scope != b.Exception.Scope {
		return a.Exception.Scope == ScopeExact
	}
	return a.Exception.canonical < b.Exception.canonical
}

func labelCount(canonical string) int {
	if canonical == "" {
		return 0
	}
	return strings.Count(canonical, ".") + 1
}

// Digest is the policy's identity, over its canonical contents.
//
// Over the VALUE, not the file bytes: reformatting the operator's file must
// not read as a change of policy, while adding an exception must. Exceptions
// are sorted, because the order two of them appear in changes nothing — the
// precedence rule above is by specificity and not by position.
//
// # IT IDENTIFIES THE FULL REPORTED POLICY, NOT ONLY THE DECIDING RULES
//
// The NOTES are in it, both the policy's own and each exception's, and that is
// a decision rather than an oversight in either direction.
//
// An exception's note is QUOTED IN THE REPORT — Outcome.Exception carries it,
// bounded and escaped. So two policies whose notes differ produce two
// different reports. A digest that ignored them would let a reader compare
// two reports, find the same policy digest, and conclude they were computed
// under the same policy while one of them says something the other does not
// (FINDING-123).
//
// The cost is that editing a comment changes the digest. That is correct for
// what this digest IS: a citation of the document the report quotes, not a
// comparability key for two measurements. internal/evaluation has the other
// kind and keeps them apart deliberately.
func (p *Policy) Digest() string {
	type canonicalException struct {
		Canonical string `json:"canonical"`
		Scope     Scope  `json:"scope"`
		// Note is IN the digest. See below.
		Note string `json:"note"`
	}
	ex := make([]canonicalException, 0, len(p.Exceptions))
	for _, e := range p.Exceptions {
		ex = append(ex, canonicalException{e.canonical, e.Scope, e.Note})
	}
	sort.Slice(ex, func(i, j int) bool {
		if ex[i].Canonical != ex[j].Canonical {
			return ex[i].Canonical < ex[j].Canonical
		}
		if ex[i].Scope != ex[j].Scope {
			return ex[i].Scope < ex[j].Scope
		}
		return ex[i].Note < ex[j].Note
	})
	return digestJSON("proposal-policy", struct {
		SchemaVersion int    `json:"schema_version"`
		Note          string `json:"note"`
		MinIndep      int    `json:"min_independent_sources"`
		ProposalScope Scope  `json:"proposal_scope"`
		AcceptUnest   bool   `json:"accept_unestablished_independence"`
		// AcceptAuthAlone changes whether one source can block on its own,
		// so two policies differing only in it decide differently and the
		// digest has to separate them.
		AcceptAuthAlone   bool                 `json:"accept_authoritative_alone"`
		HouseholdLocalUse bool                 `json:"household_local_use,omitempty"`
		Exceptions        []canonicalException `json:"exceptions"`
		// ExceptionsStated is in the digest because it is a DIFFERENT policy
		// from the one with no key at all, and nothing else in this structure
		// distinguishes them: both produce an empty exception list.
		ExceptionsStated bool `json:"exceptions_stated"`
		// Automatic is in the digest, whole and INCLUDING its unset fields.
		//
		// A report cites the policy it was decided under, and the automatic
		// contract decides whether an indicator would be blocked without
		// anybody being asked. Two policies that differ only in
		// `max_additions_per_run` produce different unattended behaviour, and
		// a digest that ignored the block would let a reader conclude two
		// runs were governed by the same terms when they were not. The
		// pointers are carried as pointers, so filling a value in changes
		// this digest exactly as much as changing one does — which is the
		// point: unresolved is a state of the policy, not an absence of one.
		Automatic *Automatic `json:"automatic"`
	}{p.SchemaVersion, p.Note, *p.MinIndependentSources, p.ProposalScope,
		p.AcceptUnestablishedIndependence, p.AcceptAuthoritativeAlone, p.HouseholdLocalUse, ex, p.exceptionsPresent, p.Automatic})
}
