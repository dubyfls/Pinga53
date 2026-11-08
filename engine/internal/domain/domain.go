// SPDX-License-Identifier: AGPL-3.0-only

// Package domain provides a canonical domain type with strict validation, and
// a separate, non-judgemental report of what is notable about a name.
//
// # Four questions, kept apart
//
// This package answers the first two and refuses to answer the last two:
//
//  1. Is this a syntactically valid domain, and what is its canonical form?
//     That is Normalize. Its errors are about SYNTAX.
//  2. Is there anything about this name a reviewer would want to know — that
//     it is internationalised, that a label mixes scripts, that the publisher
//     wrote punycode rather than the readable form, that the canonical form
//     does not show what was written? That is Assess, and what it returns are
//     SIGNALS, not verdicts.
//  3. Is this domain malicious? Nothing here can answer that. A signal is not
//     evidence, and evidence is not a signal.
//  4. Should this domain be blocked? That is policy, and it lives in
//     internal/policy, where the feed's own claims are also in scope.
//
// The distinction is not academic. Until this separation existed, a
// syntactically valid mixed-script name made Normalize return an error, and a
// caller validating a signed feed could not tell "this entry is suspicious"
// apart from "this file is corrupt" — so one suspicious entry invalidated the
// whole feed, including every unrelated indicator in it. Removing that
// rejection without putting the signal somewhere would have been the opposite
// mistake: every such name would silently have become eligible for blocking.
// Both failures are the same confusion, in opposite directions.
//
// This package intentionally has no ScamWall dependencies, so its guarantees
// hold regardless of the caller.
package domain

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Length limits from RFC 1035, in the presentation form used here (no trailing
// root dot, so 253 rather than 255).
const (
	MaxLength      = 253
	MaxLabelLength = 63
	MinLabels      = 2

	// MaxInputLength bounds the RAW input, before any conversion.
	//
	// MaxLength bounds the CANONICAL form, and it is checked after IDNA
	// conversion — which is far too late to be the only bound. Until this
	// existed, a multi-megabyte string from a feed record was mapped,
	// punycoded and then echoed, in full, into an error message that an
	// operator reads and an audit stream may retain. The cost of the
	// conversion and the size of the message were both set by the input.
	//
	// 1024 is derived rather than picked. A canonical name is at most 253
	// ASCII bytes across at most 127 labels; an A-label of 63 bytes decodes
	// to at most 59 code points, each at most 4 UTF-8 bytes, so the Unicode
	// source of a maximal name cannot exceed roughly 950 bytes. Anything
	// longer than 1024 cannot become a valid domain, so rejecting it early
	// discards nothing a later check would have accepted.
	MaxInputLength = 1024
)

// maxEchoLength bounds how much of a value may appear in an error message.
//
// Errors from this package are read by operators and are wrapped by callers
// that add the offending value again — internal/feed does exactly that — so an
// unbounded echo is multiplied, not merely large.
const maxEchoLength = 64

// Clip bounds a value for inclusion in an error message or a report.
//
// It truncates on a rune boundary and states the original length, so that a
// reader can tell a clipped value from a short one and can still see enough of
// the beginning to recognise the record. It is exported because callers that
// wrap these errors have the same obligation and should not each reinvent it.
func Clip(s string) string {
	if len(s) <= maxEchoLength {
		return s
	}
	cut := maxEchoLength
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s\u2026(%d bytes)", s[:cut], len(s))
}

// Validation errors. Each rejected class has a distinct error so that a caller
// can report precisely why a feed record was refused.
//
// Every one of these is a statement about SYNTAX. None of them means a name is
// suspicious, and none of them may be used to mean that.
var (
	ErrEmpty            = errors.New("domain is empty")
	ErrTooLong          = errors.New("domain exceeds maximum length")
	ErrLabelTooLong     = errors.New("domain label exceeds maximum length")
	ErrEmptyLabel       = errors.New("domain contains an empty label")
	ErrSingleLabel      = errors.New("domain is a single label")
	ErrIPLiteral        = errors.New("domain is an IP address literal")
	ErrLocalhost        = errors.New("domain is localhost")
	ErrLocalTLD         = errors.New("domain uses a link-local or internal TLD")
	ErrWildcard         = errors.New("domain contains a wildcard")
	ErrMalformedIDN     = errors.New("domain is not a valid internationalised name")
	ErrPublicSuffix     = errors.New("domain is a public suffix")
	ErrSharedPlatform   = errors.New("domain is a shared hosting platform")
	ErrInvalidCharacter = errors.New("domain contains an invalid character")
	ErrNumericTLD       = errors.New("domain has an all-numeric top-level label")
	ErrInputTooLong     = errors.New("domain input exceeds the maximum accepted length")
)

// Signal is something notable about a syntactically valid name.
//
// A signal is an OBSERVATION. It carries no judgement, no score and no
// implication that anything is wrong: most internationalised domains in the
// world are entirely legitimate, and a great many of them are not written in
// Latin script. What a signal is for is letting a policy that has other
// evidence — a signed feed's own claims, a publisher's stated confidence —
// decide what to do about a name it would otherwise treat as ordinary.
//
// Values are stable strings so they can appear in a plan, a report, or a
// regression fixture without changing when the code is refactored.
type Signal string

// The signals this package can raise.
const (
	// SignalNonASCII: the input contained characters outside ASCII, so the
	// canonical form is punycode. On its own this describes most of the
	// internationalised internet and means nothing at all.
	SignalNonASCII Signal = "non_ascii"

	// SignalPunycodeInput: the input was ALREADY in punycode. Distinct from
	// SignalNonASCII because it is a fact about the publisher rather than
	// about the name: a feed that writes "xn--80ak6aa92e" instead of the
	// readable form has given a reviewer no way to see what the name looks
	// like. Not suspicious by itself; useful when reading a plan.
	SignalPunycodeInput Signal = "punycode_input"

	// SignalSingleNonLatinScript: a label is written wholly in one script that
	// is not Latin. Explicitly NOT a risk signal — it is recorded so that a
	// policy which wants to say "leave ordinary internationalised names alone"
	// can distinguish them from mixed-script ones without re-deriving it.
	SignalSingleNonLatinScript Signal = "single_non_latin_script"

	// SignalMixedScript: one label combines scripts in a way that is not a
	// known legitimate combination. This is the classic homograph
	// construction — a Cyrillic character inside an otherwise Latin word — and
	// it is the one signal here a policy is expected to act on. It still is
	// not evidence of anything: a name can mix scripts for entirely ordinary
	// reasons, which is why the disposition it drives is review rather than
	// exclusion.
	SignalMixedScript Signal = "mixed_script"

	// SignalInvisibleCharacter: the input contained one or more characters
	// with no visible rendering — a format character, a default-ignorable code
	// point, or a variation selector — which IDNA mapping REMOVED, so the
	// canonical form does not show what the publisher wrote.
	//
	// This is the one signal here that is about canonicalisation destroying
	// evidence rather than about the name itself, and it is why it exists.
	// IDNA deletes U+00AD, U+200B, U+2060, U+FEFF and U+FE0F silently, so
	// "ex\u200bample.com" canonicalises to exactly "example.com" — the
	// legitimate name, byte for byte. Before this signal existed, such an
	// entry carried only SignalNonASCII, which this package documents as
	// meaning nothing at all and which internal/policy deliberately ignores,
	// so it reached a blocking proposal against the legitimate domain with
	// nothing anywhere to tell a reviewer that the written form differed.
	//
	// It is NOT a validity failure. The name is syntactically fine and its
	// canonical form is correct; what is notable is that the two do not look
	// alike. Like SignalMixedScript it drives review, not exclusion, because a
	// publisher may equally have copied an invisible character in by accident.
	SignalInvisibleCharacter Signal = "invisible_character"
)

// invisibleClasses are the Unicode properties that mark a code point with no
// visible rendering of its own.
//
// These are the maintained Unicode tables from the standard library, not a
// hand-written list of characters: Cf covers the format characters (U+00AD,
// U+200B, U+2060, U+FEFF), Variation_Selector covers U+FE00..U+FE0F, and
// Other_Default_Ignorable_Code_Point covers the remainder of the derived
// Default_Ignorable_Code_Point property. Membership is a conservative
// SUPERSET: it is intersected with what the canonical form actually lost
// before anything is reported, so a character the profile kept is never
// described as removed.
var invisibleClasses = []*unicode.RangeTable{
	unicode.Cf,
	unicode.Variation_Selector,
	unicode.Other_Default_Ignorable_Code_Point,
}

// Observation is one signal, with enough context to act on or report.
type Observation struct {
	// Signal is what was observed.
	Signal Signal
	// Label is the label the observation is about, in its ASCII (punycode)
	// form. The ASCII form is deliberate: reporting the Unicode form would
	// print the confusable characters into a terminal, an issue tracker or a
	// log, where they look like whatever they were chosen to look like.
	Label string
	// Detail is a short, bounded description — for a mixed-script observation,
	// the script names involved, joined and sorted. Never peer-supplied text.
	Detail string
}

// Assessment is the canonical form of a name together with what was observed
// about it.
type Assessment struct {
	// Domain is the canonical form. Always valid: an Assessment is only
	// returned when normalisation succeeded.
	Domain Domain
	// Observations are sorted by (Signal, Label) so that two runs over the
	// same input produce byte-identical output.
	Observations []Observation
}

// Has reports whether the assessment carries the given signal.
func (a Assessment) Has(s Signal) bool {
	for _, o := range a.Observations {
		if o.Signal == s {
			return true
		}
	}
	return false
}

// Signals returns the distinct signals, sorted and deduplicated.
func (a Assessment) Signals() []Signal {
	seen := make(map[Signal]bool, len(a.Observations))
	out := make([]Signal, 0, len(a.Observations))
	for _, o := range a.Observations {
		if seen[o.Signal] {
			continue
		}
		seen[o.Signal] = true
		out = append(out, o.Signal)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Domain is a validated, canonical, lowercase, ASCII (punycode) domain name
// with no trailing root dot.
type Domain string

// String returns the canonical form.
func (d Domain) String() string { return string(d) }

// idnaProfile is the lookup profile used for normalisation.
//
// VerifyDNSLength enforces the length limits during conversion. BidiRule
// applies the RFC 5893 rules for right-to-left names. ValidateLabels keeps the
// leading- and trailing-hyphen rules and the A-label checks.
//
// # WHY StrictDomainName IS OFF, AND WHAT REPLACES IT
//
// StrictDomainName(true) restricts labels to letters, digits and hyphen. That
// excluded underscore, on the reasoning that resolvers treat it
// inconsistently — which is sound advice about names one might CREATE.
// ScamWall creates no names. It decides about names that already exist and are
// already resolving, and hosted phishing tenants use underscore. A host this
// package cannot normalise is a host that can never be blocked, so the
// exclusion was not a conservative choice; it was a hole with a
// conservative-sounding reason. FINDING-133, ORDER 8 control C-16.
//
// Turning the flag off is not by itself the fix. Measured directly, the
// relaxed profile also admits `sp ace`, `slash/x`, `at@sign`, `per%cent`,
// `quote"x`, `back\slash`, `bad!char`, `dollar$` and `semi;colon` — and a name
// carrying any of those reaches a Pi-hole API call, a log line and a blocklist
// file. So the LDH rule is not removed, it is MOVED: labelCharset below
// enforces letters, digits, hyphen and underscore on the canonical form, which
// is the same rule plus exactly one character.
//
// Punycode output is always LDH, so internationalised names are unaffected.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

// labelCharset reports whether every label of an already-canonical ASCII name
// is letters, digits, hyphen or underscore.
//
// This runs on the CANONICAL form, after IDNA conversion, so a label is either
// ASCII to begin with or is an `xn--` A-label, and both are covered by one
// rule. Leading and trailing hyphens are left to ValidateLabels, which already
// refuses them and says which label was wrong.
func labelCharset(ascii string) (bad rune, ok bool) {
	for _, r := range ascii {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return r, false
		}
	}
	return 0, true
}

// internalTLDs are top-level labels that never denote a public internet name.
// Blocking them is meaningless at best, and at worst would interfere with
// local service discovery.
var internalTLDs = map[string]struct{}{
	"local":       {},
	"localhost":   {},
	"localdomain": {},
	"internal":    {},
	"onion":       {},
	"invalid":     {},
	"test":        {},
	"example":     {},
	"home":        {},
	"lan":         {},
	"arpa":        {},
}

// Normalize validates raw and returns its canonical form.
//
// It answers exactly one question: is this a syntactically valid domain, and
// what is its canonical spelling? It does not judge the name. A mixed-script
// name, a punycode name and an ordinary ASCII name are all equally valid here,
// and Assess is where the difference between them is recorded.
func Normalize(raw string) (Domain, error) {
	a, err := Assess(raw)
	if err != nil {
		return "", err
	}
	return a.Domain, nil
}

// Assess validates raw and reports what is notable about it.
//
// The order of checks is deliberate. Structural rejections (wildcards, IP
// literals, stray URL syntax) happen before IDNA conversion, because feeding
// such input to a normaliser produces confusing errors and, in the worst case,
// a name that converts "successfully" into something unintended.
func Assess(raw string) (Assessment, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Assessment{}, ErrEmpty
	}

	// Bounded before anything expensive touches it, and before any error
	// message can quote it. See MaxInputLength.
	if len(s) > MaxInputLength {
		return Assessment{}, fmt.Errorf("%w: %d bytes (max %d)", ErrInputTooLong, len(s), MaxInputLength)
	}

	// Invalid UTF-8 is rejected before anything else looks at the bytes.
	//
	// A domain arriving from a JSON feed is a UTF-8 string by definition, so
	// this is malformed input rather than an exotic name. It matters more
	// than it looks: the IDNA mapper replaces an invalid byte with U+FFFD and
	// encodes THAT, producing an ACE label which the same profile then
	// refuses on the way back in. The canonical form would not be
	// canonicalisable, and deduplication is only sound if it is. Found by
	// FuzzAssess on the input "0.\\xd00" within a second of the target
	// existing.
	if !utf8.ValidString(s) {
		return Assessment{}, fmt.Errorf("%w: input is not valid UTF-8", ErrInvalidCharacter)
	}

	// Control characters and embedded whitespace are always malformed and are
	// a common way to smuggle a different name past a naive parser.
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return Assessment{}, fmt.Errorf("%w: control or whitespace character", ErrInvalidCharacter)
		}
	}

	// Wildcards are rejected outright. ScamWall blocks exact domains only, so
	// a wildcard is never a narrowing of scope, only a widening of it.
	if strings.ContainsAny(s, "*?") {
		return Assessment{}, ErrWildcard
	}

	// Strip surrounding brackets so that "[::1]" is recognised as an address
	// rather than as a name containing punctuation.
	unbracketed := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if net.ParseIP(unbracketed) != nil {
		return Assessment{}, ErrIPLiteral
	}

	// Remove exactly one trailing root dot. More than one is malformed.
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Assessment{}, ErrEmpty
	}
	if strings.HasSuffix(s, ".") {
		return Assessment{}, fmt.Errorf("%w: repeated trailing dot", ErrEmptyLabel)
	}
	// Re-check: "192.0.2.1." is an address once the root dot is removed.
	if net.ParseIP(s) != nil {
		return Assessment{}, ErrIPLiteral
	}

	// Reject URL syntax rather than silently extracting a host from it. A feed
	// is expected to contain bare domains; anything else is a schema violation
	// and should be visible as one.
	if i := strings.IndexAny(s, "/\\@:?#%,;\"'<>()[]{}|^`"); i >= 0 {
		return Assessment{}, fmt.Errorf("%w: %q", ErrInvalidCharacter, s[i:i+1])
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return Assessment{}, ErrEmptyLabel
	}

	// Recorded before conversion, because after it the distinction is gone.
	inputWasNonASCII := !isASCII(s)
	inputWasPunycode := strings.Contains(strings.ToLower(s), acePrefix)

	ascii, err := idnaProfile.ToASCII(s)
	if err != nil {
		return Assessment{}, fmt.Errorf("%w: %s", ErrMalformedIDN, Clip(err.Error()))
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" {
		return Assessment{}, ErrEmpty
	}

	// The LDH rule, moved out of the IDNA profile and widened by exactly one
	// character. See idnaProfile. Checked here rather than after the
	// round-trip so that a bad character reports itself instead of the generic
	// "does not normalise to itself".
	if bad, ok := labelCharset(ascii); !ok {
		return Assessment{}, fmt.Errorf("%w: %q", ErrInvalidCharacter, bad)
	}

	// The canonical form must itself be canonical.
	//
	// Rejecting invalid UTF-8 above removes the one input known to break this,
	// but the property is asserted here rather than assumed, because it is the
	// property callers actually depend on: feed deduplication, plan digests
	// and the whole idea of "the same domain" are unsound the moment two
	// spellings of one name can produce forms that do not converge. A future
	// change in the IDNA tables cannot reintroduce the defect silently.
	if round, rerr := idnaProfile.ToASCII(ascii); rerr != nil || !strings.EqualFold(round, ascii) {
		return Assessment{}, fmt.Errorf("%w: the canonical form does not normalise to itself", ErrMalformedIDN)
	}

	if len(ascii) > MaxLength {
		return Assessment{}, fmt.Errorf("%w: %d > %d", ErrTooLong, len(ascii), MaxLength)
	}

	// Checked before the label-count rule so that the bare name reports the
	// specific reason rather than the generic "single label".
	if ascii == "localhost" || strings.HasSuffix(ascii, ".localhost") {
		return Assessment{}, ErrLocalhost
	}

	labels := strings.Split(ascii, ".")
	if len(labels) < MinLabels {
		return Assessment{}, ErrSingleLabel
	}
	for _, l := range labels {
		if l == "" {
			return Assessment{}, ErrEmptyLabel
		}
		if len(l) > MaxLabelLength {
			return Assessment{}, fmt.Errorf("%w: %q is %d > %d", ErrLabelTooLong, l, len(l), MaxLabelLength)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return Assessment{}, fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrInvalidCharacter, l)
		}
	}

	tld := labels[len(labels)-1]
	if _, bad := internalTLDs[tld]; bad {
		if tld == "localhost" {
			return Assessment{}, ErrLocalhost
		}
		return Assessment{}, fmt.Errorf("%w: .%s", ErrLocalTLD, tld)
	}
	if isAllDigits(tld) {
		return Assessment{}, ErrNumericTLD
	}

	// A public suffix is a registry boundary, not a site. Blocking "com" or
	// "co.uk" would take out an enormous portion of the internet, so an entry
	// that *is* a public suffix is refused rather than trusted.
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return Assessment{}, fmt.Errorf("%w: %q", ErrPublicSuffix, ascii)
	}

	// A shared hosting platform is the same category error one list further
	// out: the apex is a platform, not a site. See sharedPlatforms. Reported
	// under its own code, because a reviewer asking why a name was not
	// blocked needs to know WHICH list it was on -- one is a compiled
	// snapshot of the PSL, the other is this repository's own judgement.
	if _, isPlatform := sharedPlatforms[ascii]; isPlatform {
		return Assessment{}, fmt.Errorf("%w: %q", ErrSharedPlatform, ascii)
	}

	// --- Syntax is settled. Everything below is observation, never rejection.
	a := Assessment{Domain: Domain(ascii)}
	if inputWasNonASCII {
		a.Observations = append(a.Observations, Observation{Signal: SignalNonASCII, Label: ascii})
	}
	if inputWasPunycode {
		a.Observations = append(a.Observations, Observation{Signal: SignalPunycodeInput, Label: ascii})
	}
	a.Observations = append(a.Observations, invisibleObservations(s, ascii)...)
	a.Observations = append(a.Observations, scriptObservations(labels)...)

	sort.Slice(a.Observations, func(i, j int) bool {
		if a.Observations[i].Signal != a.Observations[j].Signal {
			return a.Observations[i].Signal < a.Observations[j].Signal
		}
		if a.Observations[i].Label != a.Observations[j].Label {
			return a.Observations[i].Label < a.Observations[j].Label
		}
		return a.Observations[i].Detail < a.Observations[j].Detail
	})
	return a, nil
}

// acePrefix marks a punycode-encoded label.
const acePrefix = "xn--"

// isAllDigits reports whether s consists only of ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// allowedScriptGroups are sets of scripts that legitimately co-occur inside a
// single label. Japanese mixes Han with the two kana scripts, Chinese mixes Han
// with Bopomofo, and Korean mixes Han with Hangul. Treating those as notable
// would flag a large part of the legitimate internet.
var allowedScriptGroups = []map[string]bool{
	{"Han": true, "Hiragana": true, "Katakana": true}, // Japanese
	{"Han": true, "Bopomofo": true},                   // Chinese
	{"Han": true, "Hangul": true},                     // Korean
}

// scriptObservations reports script composition for each label, working from
// the CANONICAL form rather than from the input.
//
// Decoding each ACE label back to Unicode, rather than analysing the input
// before conversion, means the observation is a property of the name that was
// accepted — so two spellings of the same name produce the same observations,
// and the label reported alongside is the ASCII one that is safe to print.
//
// The rule follows the shape of UTS #39's moderately restrictive profile:
// Latin may accompany the CJK script groups, but a label mixing Latin with
// Cyrillic or Greek — the pairs that supply nearly all confusable characters —
// is notable. A label written wholly in one non-Latin script is ordinary, and
// is reported as such rather than not at all.
//
// It is not a complete UTS #39 implementation. Whole-script confusables, where
// a name is written entirely in one script that resembles another, are not
// detected. That limitation is stated rather than papered over.
func scriptObservations(asciiLabels []string) []Observation {
	var out []Observation
	for _, alabel := range asciiLabels {
		if !strings.HasPrefix(alabel, acePrefix) {
			// A label with no ACE prefix is pure ASCII, hence Latin-only by
			// construction, and carries no script observation at all.
			continue
		}
		u, err := idna.Punycode.ToUnicode(alabel)
		if err != nil {
			// Unreachable for a label the profile above already converted, and
			// treated as "nothing observable" rather than as an error: this
			// function is not allowed to reject anything.
			continue
		}
		scripts := scriptsIn(u)
		if len(scripts) == 0 {
			continue
		}
		hasLatin := scripts["Latin"]
		rest := make(map[string]bool, len(scripts))
		for name := range scripts {
			if name != "Latin" {
				rest[name] = true
			}
		}
		switch {
		case len(rest) == 0:
			// Latin written in an ACE label: unusual, but not a mixture.
		case len(rest) == 1 && !hasLatin:
			out = append(out, Observation{
				Signal: SignalSingleNonLatinScript,
				Label:  alabel,
				Detail: joinScripts(rest),
			})
		case scriptGroupAllowed(rest):
			// A known legitimate combination. Reported as an ordinary
			// internationalised name, not as a mixture.
			out = append(out, Observation{
				Signal: SignalSingleNonLatinScript,
				Label:  alabel,
				Detail: joinScripts(rest),
			})
		default:
			out = append(out, Observation{
				Signal: SignalMixedScript,
				Label:  alabel,
				Detail: joinScripts(scripts),
			})
		}
	}
	return out
}

func scriptGroupAllowed(rest map[string]bool) bool {
	for _, group := range allowedScriptGroups {
		if subsetOf(rest, group) {
			return true
		}
	}
	return false
}

// isASCII reports whether s contains only ASCII.
func isASCII(s string) bool {
	for _, r := range s {
		if r >= 0x80 {
			return false
		}
	}
	return true
}

// scriptsIn returns the set of Unicode scripts present in a label.
//
// Letters are what carry script identity; digits, hyphens and other
// script-neutral characters are ignored so that "web3" is not treated as
// mixing anything.
func scriptsIn(label string) map[string]bool {
	found := map[string]bool{}
	for _, r := range label {
		if !unicode.IsLetter(r) {
			continue
		}
		if name := scriptOf(r); name != "" {
			found[name] = true
		}
	}
	return found
}

func subsetOf(sub, super map[string]bool) bool {
	for k := range sub {
		if !super[k] {
			return false
		}
	}
	return true
}

// joinScripts renders a script set deterministically.
func joinScripts(scripts map[string]bool) string {
	names := make([]string, 0, len(scripts))
	for k := range scripts {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, "+")
}

// scriptOf returns the name of the Unicode script r belongs to, ignoring
// script-neutral categories.
func scriptOf(r rune) string {
	for name, table := range unicode.Scripts {
		switch name {
		case "Common", "Inherited":
			continue
		}
		if unicode.Is(table, r) {
			return name
		}
	}
	return ""
}

// invisibleObservations reports characters in the input that have no visible
// rendering and that the canonical form does not carry.
//
// The check is an intersection of two facts, and needs both. Membership of an
// invisible Unicode class says the character cannot be seen; absence from the
// canonical form says this particular normalisation actually removed it. A
// character that is invisible but survived into the canonical form is not
// reported, because the canonical form then does show what was written.
//
// The observation is about the NAME rather than about one label. The code
// points are rendered as U+XXXX and never as themselves: printing an invisible
// character into a terminal or an issue tracker reproduces exactly the problem
// the signal exists to report.
func invisibleObservations(input, ascii string) []Observation {
	carried := make(map[rune]bool, len(ascii))
	for _, alabel := range strings.Split(ascii, ".") {
		u := alabel
		if strings.HasPrefix(alabel, acePrefix) {
			if decoded, err := idna.Punycode.ToUnicode(alabel); err == nil {
				u = decoded
			}
		}
		for _, r := range u {
			carried[r] = true
		}
	}

	seen := map[rune]bool{}
	var removed []rune
	for _, r := range input {
		if seen[r] || carried[r] || !unicode.In(r, invisibleClasses...) {
			continue
		}
		seen[r] = true
		removed = append(removed, r)
	}
	if len(removed) == 0 {
		return nil
	}

	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	points := make([]string, len(removed))
	for i, r := range removed {
		points[i] = fmt.Sprintf("U+%04X", r)
	}
	return []Observation{{
		Signal: SignalInvisibleCharacter,
		Label:  ascii,
		Detail: strings.Join(points, "+"),
	}}
}

// sharedPlatforms are multi-tenant hosting domains whose APEX is a platform
// rather than a site. ORDER 8 control C-17.
//
// # WHY THIS EXISTS BESIDE THE PUBLIC SUFFIX LIST
//
// A public suffix is a registry boundary and Normalize already refuses one. A
// shared hosting platform is the same shape — thousands of unrelated tenants
// beneath one name — and is NOT in the PSL, because the PSL records where
// registration boundaries are, not where trust boundaries are. `github.io` and
// `pages.dev` happen to be in it; `godaddysites.com` is not.
//
// Nothing stopped a feed naming the apex, and a single block on it takes the
// household off every tenant on the platform at once — sites it never had
// anything to do with. That is the first harm ORDER 8 §1 names, arriving from
// a feed rather than from a mistake.
//
// # WHAT THIS LIST IS AND IS NOT
//
// It is not policy and it is not a feed. It is a correctness list in the same
// sense the PSL is: naming the apex is a category error whatever the
// household's preferences are. It can only ever REFUSE, so it can cost a
// block; it cannot cause one. That asymmetry is why it ships with entries
// rather than empty.
//
// It is necessarily incomplete and maintained by hand. A platform missing from
// it is not refused — see the owner question in ORDER_8_PROGRESS.md about
// whether this should become a reviewed, versioned list of its own.
//
// Tenants are unaffected: only an exact match on the apex is refused.
var sharedPlatforms = map[string]struct{}{
	// The three the control names.
	"godaddysites.com":  {},
	"weeblysite.com":    {},
	"000webhostapp.com": {},
}
