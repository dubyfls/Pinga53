// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"net/url"
	"strings"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHY FEED HOSTS ARE A CHECK, NOT A DERIVED SET
//
// Every ScamWall run reaches a set of hosts to fetch feeds and threat data
// from. Two of those hosts happen to live on .2 as well: the resolver
// ScamWall queries is Unbound on this host, and any misconfiguration that
// lets the writer emit an RPZ entry for a feed host would starve the next
// run of the feed that would have proven the block wrong.
//
// The order asks us to enforce this as an INVARIANT rather than a fix-up:
// scamwall check fails until every registered source URL's host is covered
// by protected_domains. Making it a check keeps the resolver adapter and
// the source registry loosely coupled — a new source added to the
// registry is a new check failure until the owner acknowledges it, rather
// than an automatic addition to a set the owner did not review.
//
// # WHAT "COVERED" MEANS
//
// Whole-label suffix match. `urlhaus.abuse.ch` is covered by
// `abuse.ch`; it is NOT covered by `use.ch` (a plausibly-adjacent
// TLD-shaped string that shares tail characters). This matches the RPZ
// writer's own protected-domain semantics — a subdomain of a protected
// suffix is protected, but an unrelated host with a coincidentally
// similar tail is not.

// FeedHost is one URL host extracted from a source registry record.
//
// The URL is kept alongside the host so a check failure can name the
// source that introduced the requirement — an operator adding a new
// source and forgetting to update protected_domains gets a message that
// points at the exact source_id and URL.
type FeedHost struct {
	Host     string // lowercased, without port
	SourceID string // sourceregistry.Source.SourceID
	URL      string // the URL the host was taken from
}

// FeedHosts returns every URL host in the registry, dedup'd across
// sources by lowercased hostname. The first source that named the host
// wins the citation slot — subsequent duplicates are dropped rather than
// producing repeated check-failure lines for the same missing suffix.
//
// Only OfficialDocumentation is walked. If a future field carries feed
// URLs directly (RegistryDocumentation, DataURL, etc.) it must be added
// here in the same commit that adds it to the source registry schema —
// otherwise the check silently narrows.
//
// Unparseable URLs and the literal string "unknown" are dropped. Both are
// already refused earlier by sourceregistry.Load's own validation; the
// belt-and-braces skips here are for the "future edit lands a malformed
// URL past the loader" case, which should error but should not crash the
// invariant check.
func FeedHosts(reg *sourceregistry.Registry) []FeedHost {
	if reg == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []FeedHost
	for _, s := range reg.Sources {
		u := strings.TrimSpace(s.OfficialDocumentation)
		if u == "" || u == "unknown" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, FeedHost{Host: host, SourceID: s.SourceID, URL: u})
	}
	return out
}

// CoverAllowSuffix returns true when host is exactly one of the protected
// suffixes OR ends with `.<suffix>` for one of them. Whole-label match.
//
// Both sides are lowercased once. A trimmed-empty suffix in the list is
// ignored — the file format the caller reads supports blank lines and
// comment lines explicitly.
func CoverAllowSuffix(host string, protected []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, p := range protected {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if host == p {
			return true
		}
		if strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

// UncoveredFeedHosts returns the feed hosts NOT covered by any entry in
// protected. Order is the same as FeedHosts's output, so the check's
// failure list is deterministic across runs.
func UncoveredFeedHosts(reg *sourceregistry.Registry, protected []string) []FeedHost {
	if reg == nil {
		return nil
	}
	var out []FeedHost
	for _, h := range FeedHosts(reg) {
		if !CoverAllowSuffix(h.Host, protected) {
			out = append(out, h)
		}
	}
	return out
}
