// SPDX-License-Identifier: AGPL-3.0-only

// Package policy turns a validated feed into a proposed blocking plan.
//
// A plan is a pure function of its inputs. This package does not import the
// Pi-hole adapter, and nothing here can reach the network. That is the
// structural reason a Phase 1 plan cannot be submitted: there is no wiring
// through which it could travel.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/domain"
	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// PlanFormatVersion identifies the canonical serialisation used for the
// digest. Changing the serialisation must change this value, otherwise two
// incompatible plans could share a digest.
//
// v2 adds the review section. Every digest computed by v1 differs from the v2
// digest of the same feed, deliberately and unavoidably: a plan that withholds
// entries pending review is not the same plan as one that never saw them, and
// a digest that could not tell them apart would be worthless for review. No
// recorded digest in this repository is invalidated, because none was ever
// committed as a fixture.
const PlanFormatVersion = "scamwall-plan-v2"

// Entry is a single proposed blocking action.
type Entry struct {
	Domain     domain.Domain   `json:"domain"`
	Category   string          `json:"category,omitempty"`
	Confidence feed.Confidence `json:"confidence"`
}

// Exclusions records why candidate indicators did not reach the plan.
//
// Reporting exclusions matters: a plan that silently drops most of its input
// looks identical to a plan whose input was small, and an operator needs to
// tell those apart.
type Exclusions struct {
	NotBlockAction  int `json:"not_block_action"`
	BelowConfidence int `json:"below_confidence"`
	ExpiredInFeed   int `json:"expired_in_feed"`
}

// Total returns the number of excluded indicators.
//
// Entries held for review are NOT counted here. They were not excluded — they
// are eligible on the feed's own terms and are waiting on a human — and
// folding them into the exclusion total would hide them in exactly the way
// this plan format exists to prevent.
func (e Exclusions) Total() int { return e.NotBlockAction + e.BelowConfidence + e.ExpiredInFeed }

// ReviewEntry is a candidate withheld from the plan pending a human decision.
//
// It carries the same fields as a proposed entry plus the reason it is here,
// so that a reviewer can act on it without re-deriving anything.
type ReviewEntry struct {
	Domain     domain.Domain   `json:"domain"`
	Category   string          `json:"category,omitempty"`
	Confidence feed.Confidence `json:"confidence"`
	Reason     Reason          `json:"reason"`
	// Signals are what was observed about the name, verbatim from the domain
	// package. Reported so the reviewer sees the input to the decision rather
	// than only its output.
	Signals []domain.Signal `json:"signals,omitempty"`
}

// Plan is a proposed set of blocking actions.
//
// In Phase 1 a Plan is a report, not an instruction. Nothing consumes it other
// than the terminal.
type Plan struct {
	FormatVersion   string    `json:"format_version"`
	FeedID          string    `json:"feed_id"`
	ManifestVersion string    `json:"manifest_version"`
	FeedExpiresAt   time.Time `json:"feed_expires_at"`
	Entries         []Entry   `json:"entries"`
	// Review holds candidates that the feed asserts with high confidence and
	// that something about the NAME says a human should look at first. They
	// are not proposed and not excluded.
	Review     []ReviewEntry `json:"review"`
	Exclusions Exclusions    `json:"exclusions"`
	// Digest is a SHA-256 over the canonical serialisation. Two runs over the
	// same feed produce the same digest, which is what makes operator review
	// meaningful: the plan that was reviewed is provably the plan in hand.
	Digest string `json:"digest"`
	// DryRun is always true in Phase 1 and is recorded in the plan so that a
	// captured plan document states its own mode.
	DryRun bool `json:"dry_run"`
}

// Count returns the number of proposed entries.
func (p *Plan) Count() int { return len(p.Entries) }

// ReviewCount returns the number of entries held for review.
func (p *Plan) ReviewCount() int { return len(p.Review) }

// IsEmpty reports whether the plan proposes nothing.
func (p *Plan) IsEmpty() bool { return len(p.Entries) == 0 }

// Compute builds a plan from a validated feed.
//
// Only high-confidence block records are eligible. Anything less certain is
// reported but not proposed: the cost of wrongly blocking a bank, a hospital,
// or a delivery tracker is far higher than the cost of missing one scam
// domain, so the default posture is to under-block.
func Compute(v *feed.Validated) *Plan {
	p := &Plan{
		FormatVersion:   PlanFormatVersion,
		FeedID:          v.FeedID,
		ManifestVersion: v.ManifestVersion,
		FeedExpiresAt:   v.ExpiresAt.UTC(),
		Entries:         make([]Entry, 0, len(v.Indicators)),
		Exclusions:      Exclusions{ExpiredInFeed: v.ExpiredCount},
		DryRun:          true,
	}

	for _, ind := range v.Indicators {
		// One decision function, so that "what reaches a plan" is a single
		// reviewable rule rather than a chain of conditions spread through a
		// loop. See Decide for the policy and for what it deliberately will
		// not do.
		switch disp, reason := Decide(ind); disp {
		case DispositionPropose:
			p.Entries = append(p.Entries, Entry{
				Domain:     ind.Domain,
				Category:   ind.Category,
				Confidence: ind.Confidence,
			})
		case DispositionReview:
			p.Review = append(p.Review, ReviewEntry{
				Domain:     ind.Domain,
				Category:   ind.Category,
				Confidence: ind.Confidence,
				Reason:     reason,
				Signals:    ind.Signals,
			})
		case DispositionExclude:
			switch reason {
			case ReasonNotBlockAction:
				p.Exclusions.NotBlockAction++
			case ReasonBelowConfidence:
				p.Exclusions.BelowConfidence++
			}
		}
	}

	// Sort by canonical domain. Domains are unique after feed validation, so
	// this is a total order and the result is fully deterministic. Both
	// sections are sorted, because both are covered by the digest.
	sort.Slice(p.Entries, func(i, j int) bool {
		return p.Entries[i].Domain < p.Entries[j].Domain
	})
	sort.Slice(p.Review, func(i, j int) bool {
		return p.Review[i].Domain < p.Review[j].Domain
	})

	p.Digest = digest(p)
	return p
}

// canonical renders the plan in the exact form covered by the digest.
//
// Only fields that change the meaning of the plan are included. Timestamps
// that vary between runs over the same feed are deliberately excluded, because
// a digest that changes without the plan changing would be useless for review.
func canonical(p *Plan) string {
	var b strings.Builder
	b.WriteString(PlanFormatVersion)
	b.WriteByte('\n')
	b.WriteString("feed_id:" + p.FeedID + "\n")
	b.WriteString("manifest_version:" + p.ManifestVersion + "\n")
	fmt.Fprintf(&b, "entries:%d\n", len(p.Entries))
	for _, e := range p.Entries {
		b.WriteString(string(e.Domain))
		b.WriteByte('\t')
		b.WriteString(string(e.Confidence))
		b.WriteByte('\n')
	}
	// The review section is inside the digest. A plan that withheld an entry
	// and one that never saw it are different plans, and an operator who
	// approved one must not be shown the other under the same identity.
	fmt.Fprintf(&b, "review:%d\n", len(p.Review))
	for _, r := range p.Review {
		b.WriteString(string(r.Domain))
		b.WriteByte('\t')
		b.WriteString(string(r.Confidence))
		b.WriteByte('\t')
		b.WriteString(string(r.Reason))
		b.WriteByte('\n')
	}
	return b.String()
}

func digest(p *Plan) string {
	sum := sha256.Sum256([]byte(canonical(p)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Canonical exposes the digest input, so tests can assert determinism against
// the serialisation rather than only against the hash.
func Canonical(p *Plan) string { return canonical(p) }
