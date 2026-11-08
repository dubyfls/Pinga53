// SPDX-License-Identifier: AGPL-3.0-only

package shadow

import "fmt"

// AllowList is the household's own statement about what it wants reachable.
//
// ORDER 8 control C-18, FINDING-132.
//
// # WHY THIS IS AN INTERFACE AND NOT A SLICE OF PATTERNS
//
// For the same reason Ownership is. This package has no ScamWall dependencies
// and keeps none: deciding whether a Pi-hole allow regex covers a host means
// knowing where POSIX ERE and RE2 disagree, which is internal/policy's job and
// is tested there. What Compare needs is the answer, plus an honest account of
// how much of the question could be answered at all.
//
// # WHY "NOT READ" IS NOT "EMPTY"
//
// A run that never read the allow lists and a household with no allow entries
// produce the same empty slice and mean opposite things. This package already
// refuses that confusion once — Observation.Complete, where a partial read is
// explicitly not a smaller appliance — and AllowNotRead is the same refusal.
// A plan built without the allow lists says so on every addition rather than
// quietly asserting the household allowed nothing.
type AllowList interface {
	// Cover reports WHICH kind of entry covers this domain: an exact allow,
	// a regex allow, or neither. Two booleans rather than one, because the
	// appliance's documented order puts them at different levels and C-25
	// reports which one decided — an operator fixing an inert addition needs
	// to know which entry to go and look at.
	Cover(domain string) (exact, regex bool)
	// Allowed reports whether the household's entries cover this domain.
	Allowed(domain string) bool
	// Unevaluable is how many allow patterns could not be evaluated
	// faithfully. Any number above zero means Allowed's `false` is "no
	// pattern I could read matched", which is a weaker statement than "no
	// pattern matched" and does not license a block.
	Unevaluable() int
	// Counts is how many exact entries and how many regexes were considered.
	Counts() (exact, regex int)
	// Read reports whether the allow lists were read at all.
	Read() bool
	// Source describes where the answer came from, for the plan.
	Source() string
}

// AllowNotRead is the answer from a run that did not read the allow lists.
//
// It allows nothing, reports nothing readable, and says so. Every addition in
// a plan built on it carries the caveat, because an addition the household has
// already allowed is one the appliance overrides the moment it lands, and a
// plan that cannot say which of its additions are inert claims more than it
// knows.
type AllowNotRead struct{}

// Allowed is false for every domain: not an assertion that nothing is allowed,
// but the absence of an answer. Compare reads Read() before trusting it.
func (AllowNotRead) Allowed(string) bool { return false }

// Cover is false and false, for the same reason: no answer, not a negative one.
func (AllowNotRead) Cover(string) (bool, bool) { return false, false }

// Unevaluable is zero: nothing was read, so nothing failed to be read.
func (AllowNotRead) Unevaluable() int { return 0 }

// Counts is zero and zero.
func (AllowNotRead) Counts() (int, int) { return 0, 0 }

// Read is false. This is the field that matters.
func (AllowNotRead) Read() bool { return false }

// Source says plainly that the question was not asked.
func (AllowNotRead) Source() string {
	return "the household's allow lists were not read by this run, so no addition below has been checked against them"
}

// ObservedAllowList is an allow answer computed from entries actually read.
//
// Covers is supplied by the caller — in practice internal/policy's CoverAllow,
// which is where the POSIX-versus-RE2 question is answered.
type ObservedAllowList struct {
	// CoverKind reports WHICH kind of entry covers a domain. See Cover.
	CoverKind func(domain string) (exact, regex bool)
	// Covers reports whether the household's entries cover a domain.
	Covers func(domain string) bool
	// Exact and Regex are how many entries of each kind were read.
	Exact, Regex int
	// NotEvaluable is how many regexes could not be read faithfully.
	NotEvaluable int
	// Origin describes where the entries came from.
	Origin string
}

// Allowed consults the caller's coverage function.
func (o ObservedAllowList) Allowed(domain string) bool {
	if o.Covers == nil {
		return false
	}
	return o.Covers(domain)
}

// Unevaluable is how many patterns could not be read.
func (o ObservedAllowList) Unevaluable() int { return o.NotEvaluable }

// Counts is the entries read, by kind.
func (o ObservedAllowList) Counts() (int, int) { return o.Exact, o.Regex }

// Read is true: this answer came from entries the run actually fetched.
func (o ObservedAllowList) Read() bool { return true }

// Source describes the read.
func (o ObservedAllowList) Source() string {
	if o.Origin != "" {
		return o.Origin
	}
	return fmt.Sprintf("read from the appliance: %d exact allow entries and %d allow regexes, of which %d could not be evaluated",
		o.Exact, o.Regex, o.NotEvaluable)
}

// Cover reports which kind of entry matched.
//
// CoverKind is supplied by the caller alongside Covers, for the same reason:
// the POSIX-versus-RE2 question is internal/policy's and stays there. A caller
// that supplies Covers and not CoverKind gets "neither", which makes every
// addition read as effective at levels 1 and 2 — so Compare treats a nil
// CoverKind as an unread allow list rather than as an empty one.
func (o ObservedAllowList) Cover(domain string) (bool, bool) {
	if o.CoverKind == nil {
		return false, false
	}
	return o.CoverKind(domain)
}
