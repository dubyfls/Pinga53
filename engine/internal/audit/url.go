// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"net/url"
	"strings"
)

// # WHY A URL IS REDACTED INSIDE ITS VALUE RATHER THAN BY ITS KEY
//
// A feed's URL is configuration, and configuration is where an API key
// legitimately lives: `https://feeds.example.com/list?api_key=…` is how
// several providers authenticate. The key is then inside a value that looks
// like an address, under a field name that looks harmless, and very often
// inside an error message this process did not compose — Go's own network
// errors quote the whole URL.
//
// deniedKeys cannot catch that. The field is called `url`, and redacting
// every `url` field outright would remove the host and path, which are the
// only part of it an operator needs in order to tell one source from another.
// So the redaction happens inside the value, and it happens here rather than
// at call sites, for the reason this package's own comment already gives: a
// call-site discipline fails silently the first time somebody forgets, and
// the failure mode is a credential in a log file.

// URLPlaceholder marks where a URL's credential-bearing parts were.
const URLPlaceholder = "[redacted]"

// RedactURLs removes credential-bearing parts of every http(s) URL in s.
//
// What survives is scheme, host and path. Userinfo, query and fragment are
// dropped, and their absence is marked rather than silent — a reader must be
// able to tell a URL that had no query from one whose query was removed.
//
// Text containing no URL is returned unchanged.
func RedactURLs(s string) string {
	if !strings.Contains(s, "http://") && !strings.Contains(s, "https://") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		j := indexScheme(s[i:])
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+j])
		rest := s[i+j:]
		end := len(rest)
		for k, r := range rest {
			// A URL in a message ends at the first character that cannot
			// appear unescaped in one.
			if r == ' ' || r == '"' || r == '\'' || r == '`' || r == '\n' ||
				r == '\t' || r == '<' || r == '>' || r == '\\' {
				end = k
				break
			}
		}
		b.WriteString(redactOne(rest[:end]))
		i += j + end
	}
	return b.String()
}

// indexScheme returns the offset of the first http:// or https:// in s, or -1.
func indexScheme(s string) int {
	a := strings.Index(s, "https://")
	b := strings.Index(s, "http://")
	switch {
	case a < 0:
		return b
	case b < 0:
		return a
	default:
		return min(a, b)
	}
}

func redactOne(raw string) string {
	// A trailing delimiter is punctuation in the sentence, not part of the
	// URL. Peel it off and put it back, so `…/list?k=v:` does not become an
	// unparseable URL and get left alone — which is the failure that leaks.
	trailer := ""
	for len(raw) > 0 && strings.ContainsRune(":;,.)]}", rune(raw[len(raw)-1])) {
		trailer = raw[len(raw)-1:] + trailer
		raw = raw[:len(raw)-1]
	}

	u, err := url.Parse(raw)
	if err != nil {
		// It looked like a URL and would not parse. Drop all of it rather
		// than guess which half was the secret.
		return URLPlaceholder + trailer
	}
	had := u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != ""
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	out := u.String()
	if had {
		out += "?" + URLPlaceholder
	}
	return out + trailer
}
