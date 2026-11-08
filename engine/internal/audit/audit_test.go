// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/audit"
)

// fakeSecret implements audit.Redactor the same way config.Secret does, so
// this package can be tested without importing config.
type fakeSecret struct{ plaintext string }

func (f fakeSecret) Redacted() string { return audit.Placeholder }
func (f fakeSecret) String() string   { return audit.Placeholder }

func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestDeniedKeysAreRedacted(t *testing.T) {
	// Spelling variants must all be caught: the denylist is normalised, so a
	// header logged as "X-FTL-SID" and a field logged as "x_ftl_sid" are the
	// same key as far as redaction is concerned.
	keys := []string{
		"password", "Password", "PASSWORD", "passwd",
		"sid", "SID", "session_id", "sessionId",
		"csrf", "csrf_token", "CSRF-Token",
		"authorization", "Authorization",
		"x-ftl-sid", "X-FTL-SID", "x_ftl_sid",
		"token", "api_key", "secret", "cookie",
		"body", "request_body", "headers",
	}
	for _, k := range keys {
		if !audit.IsDeniedKey(k) {
			t.Errorf("key %q should be denied", k)
		}
	}
	for _, k := range []string{"endpoint", "status", "attempt", "domain", "feed_id", "valid"} {
		if audit.IsDeniedKey(k) {
			t.Errorf("key %q should not be denied", k)
		}
	}
}

func TestLoggerRedactsDeniedKeys(t *testing.T) {
	var buf bytes.Buffer
	log := audit.NewWithClock(&buf, fixedClock())

	log.Info("test.event",
		audit.F("password", "hunter2-actual-password"),
		audit.F("sid", "abcdef0123456789"),
		audit.F("csrf", "csrf-token-value"),
		audit.F("endpoint", "/api/auth"),
	)

	out := buf.String()
	for _, leak := range []string{"hunter2-actual-password", "abcdef0123456789", "csrf-token-value"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "/api/auth") {
		t.Errorf("non-sensitive field was dropped: %s", out)
	}
	if strings.Count(out, audit.Placeholder) != 3 {
		t.Errorf("expected 3 redactions, got: %s", out)
	}
}

func TestLoggerRedactsRedactorValuesUnderAnyKey(t *testing.T) {
	// The realistic leak is a secret logged under an innocuous key. Structural
	// recognition is what saves us there, not the denylist.
	var buf bytes.Buffer
	log := audit.NewWithClock(&buf, fixedClock())

	log.Info("test.event", audit.F("harmless_looking_name", fakeSecret{plaintext: "TOP-SECRET-VALUE"}))

	if strings.Contains(buf.String(), "TOP-SECRET-VALUE") {
		t.Fatalf("secret leaked under a non-denied key: %s", buf.String())
	}
	if !strings.Contains(buf.String(), audit.Placeholder) {
		t.Fatalf("expected redaction placeholder: %s", buf.String())
	}
}

func TestLoggerRedactsNestedMaps(t *testing.T) {
	var buf bytes.Buffer
	log := audit.NewWithClock(&buf, fixedClock())
	log.Info("test.event", audit.F("detail", map[string]any{
		"endpoint": "/api/info/version",
		"sid":      "leaked-session-id",
	}))
	if strings.Contains(buf.String(), "leaked-session-id") {
		t.Fatalf("nested secret leaked: %s", buf.String())
	}
}

func TestLoggerReservedKeysCannotBeOverwritten(t *testing.T) {
	var buf bytes.Buffer
	log := audit.NewWithClock(&buf, fixedClock())
	log.Info("real.event", audit.F("event", "spoofed.event"), audit.F("level", "info"))

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if rec["event"] != "real.event" {
		t.Errorf("event was overwritten: %v", rec["event"])
	}
}

func TestLoggerOutputIsValidJSONLine(t *testing.T) {
	var buf bytes.Buffer
	log := audit.NewWithClock(&buf, fixedClock())
	log.Warn("a.b", audit.F("n", 1))
	log.Error("c.d", errors.New("boom"))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for _, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", l, err)
		}
		for _, k := range []string{"ts", "level", "event"} {
			if _, ok := rec[k]; !ok {
				t.Errorf("missing %q in %q", k, l)
			}
		}
	}
}

func TestRedactHandlesNilAndScalars(t *testing.T) {
	if audit.Redact(nil) != nil {
		t.Error("nil should stay nil")
	}
	if audit.Redact(42) != 42 {
		t.Error("int should pass through")
	}
	if audit.Redact("plain") != "plain" {
		t.Error("string should pass through")
	}
	if audit.Redact(fakeSecret{"x"}) != audit.Placeholder {
		t.Error("Redactor should be redacted")
	}
}

func TestConcurrentLoggingIsSafe(t *testing.T) {
	var buf bytes.Buffer
	log := audit.NewWithClock(&buf, fixedClock())
	done := make(chan struct{})
	for i := range 8 {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for range 50 {
				log.Info("concurrent", audit.F("worker", n))
			}
		}(i)
	}
	for range 8 {
		<-done
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 400 {
		t.Fatalf("expected 400 lines, got %d (interleaved writes?)", len(lines))
	}
	for _, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("corrupted line under concurrency: %q", l)
		}
	}
}
