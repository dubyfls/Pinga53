// SPDX-License-Identifier: AGPL-3.0-only

package shadow

// # PI-HOLE'S DECISION ORDER, ENCODED ONCE
//
// Source: docs.pi-hole.net/database/domain-database, section "Priorities".
// The appliance resolves a name against its lists in this order, and the
// FIRST match decides:
//
//	1. exact allow
//	2. regex allow
//	3. exact deny            <- what ScamWall proposes
//	4. subscribed allowlists
//	5. subscribed denylists
//	6. regex deny
//
// ORDER 8 left "does the appliance resolve allow over deny?" as its first
// owner question and lowered FINDING-132's severity on the assumption that it
// does. The documented answer is longer than one bit, and the interesting part
// is that ScamWall's exact deny sits in the MIDDLE: two of the four levels
// below it are the household's own choices.
//
// Above it, an add is inert — FINDING-132's case, and an accuracy defect
// rather than an exposure, which is why the corrected severity stands.
//
// Below it, an add WINS, and one of the things it wins against is a list the
// household deliberately subscribed to. That is household intent being
// overridden, and it is not something an unattended system may do quietly.
//
// This is the only place the order is written. A second copy is a second
// behaviour the first time one of them is corrected.

// Precedence is a level in the order above. Lower wins.
type Precedence int

// The six levels, in the documented order.
const (
	PrecExactAllow Precedence = iota + 1
	PrecRegexAllow
	PrecExactDeny
	PrecSubscribedAllow
	PrecSubscribedDeny
	PrecRegexDeny
)

// Tristate is an answer that may not be known.
//
// Unknown is not No. A host this build could not look up in the subscribed
// lists is not a host that is absent from them, and the difference decides
// whether an addition is reported as effective or sent to a person.
type Tristate int

// The three answers.
const (
	Unknown Tristate = iota
	Yes
	No
)

// AddLabel is what the order says would happen to a proposed exact deny.
type AddLabel string

// The labels.
const (
	// LabelEffective — nothing above the add matches, so it would take
	// effect, and nothing below it belongs to the household.
	LabelEffective AddLabel = "effective"
	// LabelOverriddenByExactAllow — level 1 matches. The add would have no
	// effect at all. FINDING-132's case, now stated rather than assumed.
	LabelOverriddenByExactAllow AddLabel = "overridden_by_exact_allow"
	// LabelOverriddenByRegexAllow — level 2 matches. Same outcome, different
	// entry to go and look at.
	LabelOverriddenByRegexAllow AddLabel = "overridden_by_regex_allow"
	// LabelOverridesSubscribedAllowlist — level 4 matches and the add, at
	// level 3, would beat it. The household subscribed to a list that permits
	// this host and ScamWall would override them. Review, never an automatic
	// add.
	LabelOverridesSubscribedAllowlist AddLabel = "overrides_subscribed_allowlist"
	// LabelUnknownSubscribedAllowlist — level 4 could not be read. Treated as
	// the case above, because "I could not check whether I would be
	// overriding the household" is not a reason to go ahead.
	LabelUnknownSubscribedAllowlist AddLabel = "unknown_subscribed_allowlist"
)

// Review reports whether a label requires a person before anything is asked
// of the appliance.
func (l AddLabel) Review() bool {
	return l == LabelOverridesSubscribedAllowlist || l == LabelUnknownSubscribedAllowlist
}

// HostState is what the appliance holds for one host, as far as this run
// could read it.
type HostState struct {
	ExactAllow bool
	RegexAllow bool
	// SubscribedAllow is whether a subscribed ALLOWLIST covers the host.
	// Unknown unless gravity was read.
	SubscribedAllow Tristate
	// SubscribedDeny is whether a subscribed DENYLIST covers it. Recorded
	// because the order names it; it changes no label, because a subscribed
	// denylist sits BELOW ScamWall's exact deny and agrees with it.
	SubscribedDeny Tristate
}

// LabelAdd applies the documented order to one proposed exact-deny addition.
//
// The order is an order: a host covered at two levels reports the HIGHER one,
// so two runs over the same appliance say the same thing and an operator
// fixing it knows which entry to look at.
func LabelAdd(s HostState) AddLabel {
	switch {
	case s.ExactAllow:
		return LabelOverriddenByExactAllow
	case s.RegexAllow:
		return LabelOverriddenByRegexAllow
	case s.SubscribedAllow == Yes:
		return LabelOverridesSubscribedAllowlist
	case s.SubscribedAllow == Unknown:
		return LabelUnknownSubscribedAllowlist
	default:
		return LabelEffective
	}
}

// SubscribedLists answers whether the household's subscribed lists cover a
// host.
//
// An interface for the same reason AllowList and Ownership are: this package
// depends on nothing else in the tree, and reading gravity is the adapter's
// problem.
type SubscribedLists interface {
	// Membership reports whether a subscribed allowlist and a subscribed
	// denylist cover the host.
	Membership(domain string) (allow, deny Tristate)
	// Read reports whether the lists were consulted at all.
	Read() bool
	// Source describes where the answer came from.
	Source() string
}

// SubscribedNotRead is the answer from a run that could not read gravity.
//
// It is the only implementation this build has, and the reason is recorded
// rather than hidden: the Pi-hole endpoint that answers "which lists contain
// this host" takes the host in the URL PATH. The client's whole safety model
// is an allowlist of exact (method, path) pairs — "the allowlist is over exact
// (method, path) pairs, so the broad path stays unconstructible" — and
// admitting a path template would change the control that makes the client
// safe. It would also put a household hostname into a URL, which is where
// C-14 spends its whole effort keeping things out of.
//
// So membership is Unknown, every addition is labelled
// unknown_subscribed_allowlist, and every addition goes to review. See
// ORDER_9_PROGRESS.md: C-25 is PARTIAL and this is the part that remains.
type SubscribedNotRead struct{}

// Membership is Unknown for both. Not No: see Tristate.
func (SubscribedNotRead) Membership(string) (Tristate, Tristate) { return Unknown, Unknown }

// Read is false.
func (SubscribedNotRead) Read() bool { return false }

// Source says plainly that the question was not asked.
func (SubscribedNotRead) Source() string {
	return "the household's subscribed lists were not read by this run, so no addition below is " +
		"known to leave them alone; each is held for review rather than requested"
}
