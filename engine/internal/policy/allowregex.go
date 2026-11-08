// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// The household's allow entries, and what ScamWall may conclude from them.
//
// ORDER 8 control C-18, FINDING-132.
//
// # WHY THIS IS NOT JUST regexp.MatchString
//
// Pi-hole evaluates these patterns as POSIX ERE, in C, on the appliance. This
// process has Go's regexp, which is RE2. The two overlap in the common case
// and differ in ways that do not announce themselves: a construct RE2 rejects
// may be meaningful to the appliance, and a construct both accept may not mean
// the same thing in each.
//
// Where they might differ, ScamWall does not guess. It withdraws its own
// opinion and abstains, leaving the household's entry to mean whatever the
// appliance says it means. The alternative — assuming a pattern ScamWall
// cannot read does not cover the host — resolves every ambiguity against the
// household, which is the one direction this project will not take.
//
// The cost is stated rather than hidden. Enough unevaluable patterns and
// ScamWall has an opinion about nothing, so the counts travel with the answer:
// see Coverage.Unevaluable and MustAbstain.

// unevaluableConstructs are the patterns whose presence means "do not guess".
//
// Each is either something RE2 cannot express, or something it expresses
// DIFFERENTLY from POSIX ERE. `[[:alnum:]]` is the instructive case: Go's
// regexp accepts it, so a naive implementation compiles it happily and gets a
// subtly different language than the appliance ran. Accepting it because it
// compiles would be exactly the silent disagreement this file exists to avoid.
var unevaluableConstructs = []struct {
	needle string
	why    string
}{
	{"[[:", "a POSIX character class; Go's regexp accepts the spelling but the appliance's POSIX ERE need not agree on its membership"},
	{`\<`, "a GNU word-boundary operator, which RE2 does not have"},
	{`\>`, "a GNU word-boundary operator, which RE2 does not have"},
	{"(?", "an inline group flag or a lookaround; RE2 supports neither in the form POSIX ERE callers expect"},
}

// backReference is `\1` … `\9` outside a character class.
var backReference = regexp.MustCompile(`\\[1-9]`)

// AllowRegex is one household allow pattern and what can be said about it.
//
// The zero value is not evaluable and matches nothing, so a caller that forgets
// to check Evaluable fails safe in the direction of having no opinion.
type AllowRegex struct {
	// Raw is the entry exactly as the appliance holds it, options included.
	Raw string
	// Pattern is what remains after the options this build understands are
	// removed.
	Pattern string
	// Evaluable reports whether this process can decide what the pattern
	// covers with the same answer the appliance would give.
	Evaluable bool
	// Why states what made it unevaluable. Empty when it is evaluable.
	Why string

	re *regexp.Regexp
}

// ParseAllowRegex reads one allow entry.
//
// Options are separated by `;`. Two are understood:
//
//   - `querytype=…` narrows which query types the rule applies to. It does not
//     change what the PATTERN covers, so it is stripped and the rest is
//     evaluated. C-18 names this case specifically.
//   - `invert` reverses the rule's sense. That changes what the entry MEANS,
//     not merely when it applies, so the entry is not evaluated at all.
//
// Any other option is unrecognised, and an unrecognised option could be either
// kind, so it is refused rather than assumed harmless.
func ParseAllowRegex(raw string) AllowRegex {
	a := AllowRegex{Raw: raw}

	parts := strings.Split(raw, ";")
	a.Pattern = parts[0]
	for _, opt := range parts[1:] {
		switch {
		case strings.HasPrefix(opt, "querytype="):
			// Understood and irrelevant to coverage.
		case opt == "invert":
			a.Why = "carries the `invert` option, which reverses what the entry means rather than when it applies"
			return a
		case opt == "":
			// A trailing `;` names no option.
		default:
			a.Why = fmt.Sprintf("carries an option this build does not recognise (%d characters); an unrecognised option may change what the entry means", len(opt))
			return a
		}
	}

	for _, c := range unevaluableConstructs {
		if strings.Contains(a.Pattern, c.needle) {
			a.Why = "contains " + c.why
			return a
		}
	}
	if backReference.MatchString(a.Pattern) {
		a.Why = "contains a back-reference, which RE2 does not have"
		return a
	}

	re, err := regexp.Compile(a.Pattern)
	if err != nil {
		// Reported without the message, which quotes the pattern back.
		a.Why = "is not a pattern this process can compile"
		return a
	}
	a.Evaluable = true
	a.re = re
	return a
}

// Matches reports whether the pattern covers host.
//
// An unevaluable pattern matches NOTHING — it answers neither yes nor no, and
// a caller must consult MustAbstain rather than reading a false here as "not
// covered". That is why Coverage exists and why this method is not the whole
// interface.
func (a AllowRegex) Matches(host string) bool {
	if !a.Evaluable || a.re == nil {
		return false
	}
	return a.re.MatchString(host)
}

// Coverage is what the household's allow lists say about one host.
type Coverage struct {
	// ExactMatch: an exact allow entry names this host.
	ExactMatch bool
	// RegexMatch: an evaluable allow regex covers this host.
	RegexMatch bool
	// Unevaluable counts the allow regexes this process could not evaluate.
	// Reported whether or not the host matched anything, because it is the
	// measure of how much of the household's statement ScamWall could read.
	Unevaluable int
	// Total is how many allow regexes were considered.
	Total int
}

// Allowed reports whether the household has said this host is wanted.
func (c Coverage) Allowed() bool { return c.ExactMatch || c.RegexMatch }

// MustAbstain reports whether ScamWall has to withhold its opinion.
//
// True when the household allows the host outright, and true when ScamWall
// could not read some of what the household said — because "no pattern I could
// read matched" is not the same statement as "no pattern matched", and only
// the second one licenses a block.
func (c Coverage) MustAbstain() bool { return c.Allowed() || c.Unevaluable > 0 }

// CoverAllow evaluates one host against the household's allow entries.
//
// exact and regexes are the appliance's own rows. Hosts and exact entries are
// compared after lowercasing and dropping a trailing root dot, which is how
// the appliance treats them; the regexes are matched against the host as
// given, because a pattern may be anchored on either.
func CoverAllow(host string, exact, regexes []string) Coverage {
	h := canonicalHost(host)
	c := Coverage{Total: len(regexes)}

	for _, e := range exact {
		if canonicalHost(e) == h {
			c.ExactMatch = true
			break
		}
	}
	for _, r := range regexes {
		a := ParseAllowRegex(r)
		if !a.Evaluable {
			c.Unevaluable++
			continue
		}
		if a.Matches(h) {
			c.RegexMatch = true
		}
	}
	return c
}

// canonicalHost lowercases and drops a trailing root dot.
func canonicalHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
