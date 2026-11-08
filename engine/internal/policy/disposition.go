// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// Disposition is what a plan does with one validated indicator.
//
// Three outcomes, not two. A binary propose/exclude forces every uncertain
// case into one of two wrong answers: propose it, and a suspicious-looking but
// possibly legitimate name gets blocked on a signal rather than on evidence;
// exclude it, and the fact that it was ever seen disappears from the report.
// Review keeps the entry visible without acting on it, which is the honest
// outcome when the input is a signal and the requirement is evidence.
type Disposition string

// The dispositions a plan can assign.
const (
	// DispositionPropose: the entry is eligible to be proposed for blocking.
	DispositionPropose Disposition = "propose"
	// DispositionReview: the entry is eligible on the feed's own terms, and
	// something about the NAME warrants a human look before it is acted on.
	// Not proposed, and not hidden.
	DispositionReview Disposition = "review"
	// DispositionExclude: the entry is not eligible at all.
	DispositionExclude Disposition = "exclude"
)

// Reason is a stable machine-readable code explaining a disposition.
//
// These strings appear in plans and in operator reports and are covered by the
// plan digest, so changing one is a change to the plan format, not a rename.
type Reason string

// The reasons a disposition can carry.
const (
	// ReasonEligible: nothing stood in the way.
	ReasonEligible Reason = "eligible"
	// ReasonNotBlockAction: the feed asked for something other than a block.
	ReasonNotBlockAction Reason = "not_block_action"
	// ReasonBelowConfidence: the publisher did not state high confidence.
	ReasonBelowConfidence Reason = "below_confidence"
	// ReasonMixedScript: the name combines scripts in a way that is not a known
	// legitimate combination. This is a property of the NAME and says nothing
	// about whether the name is malicious, which is why it produces review
	// rather than a proposal or an exclusion.
	ReasonMixedScript Reason = "mixed_script_requires_review"
	// ReasonInvisibleCharacter: the written form of the name contained
	// characters that canonicalisation removed, so the canonical form does not
	// show what the publisher wrote. Like ReasonMixedScript this is a property
	// of the NAME, and it produces review for the same reason.
	ReasonInvisibleCharacter Reason = "invisible_character_requires_review"
)

// Decide assigns a disposition and a reason to one indicator.
//
// The order is deliberate and is the documented policy:
//
//  1. What the FEED asked for. An allow record is not a blocking candidate at
//     all, and a record the publisher is not confident about is not one either.
//     These are exclusions, because the feed itself has said so.
//  2. What the NAME looks like. A mixed-script name that the feed does assert
//     with high confidence is not excluded and not proposed: it goes to review.
//     Downgrading rather than excluding matters, because a signal is not
//     evidence and excluding on a signal silently withdraws protection from
//     entries the publisher was confident about.
//
// What this function will not do, in either direction:
//
//   - It will not treat Unicode, a non-Latin script, or punycode as evidence of
//     anything. Those signals exist, they are carried in the plan, and they
//     change no disposition. Most of the internationalised internet is
//     ordinary, and a policy that flagged it would be useless and unjust.
//   - It will not let a mixed-script name reach a proposal merely because the
//     old whole-feed rejection was removed. Removing a rejection without
//     putting the signal somewhere would make every such entry eligible, which
//     is the opposite half of the same defect.
func Decide(ind feed.Indicator) (Disposition, Reason) {
	if ind.Action != feed.ActionBlock {
		return DispositionExclude, ReasonNotBlockAction
	}
	if ind.Confidence != feed.ConfidenceHigh {
		return DispositionExclude, ReasonBelowConfidence
	}
	// Fixed precedence, so that an entry carrying both signals always reports
	// the same reason. Invisible characters come first because they are the
	// stronger statement: a mixed-script name at least LOOKS like what it is,
	// whereas a name whose written form contained removed characters does not.
	for _, s := range ind.Signals {
		if s == domain.SignalInvisibleCharacter {
			return DispositionReview, ReasonInvisibleCharacter
		}
	}
	for _, s := range ind.Signals {
		if s == domain.SignalMixedScript {
			return DispositionReview, ReasonMixedScript
		}
	}
	return DispositionPropose, ReasonEligible
}
