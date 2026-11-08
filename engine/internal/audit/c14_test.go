// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/audit"
)

// C-14 — a credential carried in a source URL must not reach a log line.
//
// A feed's URL is configuration, and configuration is where an API key
// legitimately lives: `https://feeds.example.com/list?token=…` is how
// several real providers authenticate. The key is then in a value that looks
// like an address, under a field name that looks harmless, inside an error
// message this process did not compose — Go's own network errors quote the
// whole URL.
//
// The denied-key list cannot catch that: the field is called `url`, and
// redacting every `url` field outright would remove the host and path, which
// are the only part of it an operator needs. So the redaction has to happen
// inside the VALUE, and it has to happen in the logger, for the reason the
// package comment already gives — a call-site discipline fails silently the
// first time somebody forgets.

// The marker is deliberately not credential-SHAPED, and the query parameter
// below is deliberately not spelled the way a real provider spells it. This
// repository's own scripts/secret-scan.sh refuses a literal assignment of a
// credential-shaped key to a quoted value, in any file, tests included — so a
// test ABOUT credential leakage cannot itself contain something that looks
// like one. The gate working on this file is worth recording.
const marker = "MARKER-THAT-MUST-NEVER-BE-LOGGED"

func lines(t *testing.T, f func(l *audit.Logger)) string {
	t.Helper()
	var b strings.Builder
	f(audit.New(&b))
	return b.String()
}

func TestACredentialInAURLDoesNotReachTheLog(t *testing.T) {
	url := "https://feeds.example.com/v1/list?token=" + marker

	cases := map[string]func(l *audit.Logger){
		"a plain string field": func(l *audit.Logger) {
			l.Info("fetch", audit.F("url", url))
		},
		"a field with a harmless name": func(l *audit.Logger) {
			l.Info("fetch", audit.F("source", url))
		},
		"an error the standard library composed": func(l *audit.Logger) {
			l.Error("fetch", errors.New(`Get "`+url+`": dial tcp 192.0.2.1:443: connect: refused`))
		},
		"a value nested in a map": func(l *audit.Logger) {
			l.Info("fetch", audit.F("detail", map[string]any{"endpoint": url}))
		},
		"a value in a slice": func(l *audit.Logger) {
			l.Info("fetch", audit.F("detail", []any{url}))
		},
	}

	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			got := lines(t, f)
			if strings.Contains(got, marker) {
				t.Errorf("the credential reached the log:\n%s", got)
			}
			// ...and the part an operator needs survives.
			if !strings.Contains(got, "feeds.example.com") {
				t.Errorf("the host was removed along with the credential:\n%s", got)
			}
		})
	}
}

func TestUserinfoAndFragmentAreRemovedToo(t *testing.T) {
	for _, u := range []string{
		"https://scamwall:" + marker + "@feeds.example.com/v1/list",
		"https://feeds.example.com/v1/list#token=" + marker,
		"http://feeds.example.com/v1/list?key=" + marker,
	} {
		got := lines(t, func(l *audit.Logger) { l.Info("fetch", audit.F("url", u)) })
		if strings.Contains(got, marker) {
			t.Errorf("%q leaked:\n%s", u, got)
		}
	}
}

func TestAnOrdinaryURLIsLeftAlone(t *testing.T) {
	// The control on the control. A URL with nothing sensitive in it must come
	// through readable, or this redaction makes every diagnostic useless.
	got := lines(t, func(l *audit.Logger) {
		l.Info("fetch", audit.F("url", "https://feeds.example.com/v1/list.json"))
	})
	if !strings.Contains(got, "https://feeds.example.com/v1/list.json") {
		t.Errorf("an ordinary URL was mangled:\n%s", got)
	}
	if strings.Contains(got, "[redacted]") {
		t.Errorf("an ordinary URL was marked redacted:\n%s", got)
	}
}

func TestOrdinaryProseIsUntouched(t *testing.T) {
	msg := "the appliance refused the session; check the app password"
	got := lines(t, func(l *audit.Logger) { l.Warn("session", audit.F("detail", msg)) })
	if !strings.Contains(got, msg) {
		t.Errorf("prose containing no URL was altered:\n%s", got)
	}
}
