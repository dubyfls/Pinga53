// SPDX-License-Identifier: AGPL-3.0-only

// Package audit provides structured logging with mandatory redaction.
//
// Redaction is performed by the logger rather than by call sites. A
// call-site-only discipline fails silently the first time someone forgets, and
// the failure mode is a credential in a log file — so the guarantee is placed
// where it cannot be forgotten.
//
// This package deliberately has no dependency on any other ScamWall package.
// Values that carry secrets are recognised through the Redactor interface, so
// the logger never needs to import the types it protects.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Placeholder replaces any value considered sensitive.
const Placeholder = "[REDACTED]"

// Redactor is implemented by values that must never be logged in the clear.
//
// Recognising secrets structurally means a secret stays redacted even when it
// is logged under a harmless-looking key.
type Redactor interface {
	Redacted() string
}

// Level is a log severity.
type Level string

// Supported severities.
const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// deniedKeys are field names whose values are always replaced, regardless of
// the value's type. Keys are normalised (lowercased, separators removed)
// before lookup, so "X-FTL-SID", "x_ftl_sid" and "xftlsid" all match.
var deniedKeys = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"secret":        {},
	"sid":           {},
	"sessionid":     {},
	"csrf":          {},
	"csrftoken":     {},
	"xftlsid":       {},
	"authorization": {},
	"auth":          {},
	"cookie":        {},
	"setcookie":     {},
	"token":         {},
	"apikey":        {},
	"accesstoken":   {},
	"credential":    {},
	"credentials":   {},
	"key":           {},
	"privatekey":    {},
	// Bodies and headers are never logged at any level. Naming them here means
	// an accidental attempt produces a redacted placeholder rather than a leak.
	"body":         {},
	"requestbody":  {},
	"responsebody": {},
	"headers":      {},
	"header":       {},
	"payload":      {},
}

var keyReplacer = strings.NewReplacer("-", "", "_", "", ".", "", " ", "")

func normaliseKey(k string) string {
	return keyReplacer.Replace(strings.ToLower(k))
}

// IsDeniedKey reports whether a field name is always redacted. Exported so
// tests can assert the denylist rather than restating it.
func IsDeniedKey(k string) bool {
	_, ok := deniedKeys[normaliseKey(k)]
	return ok
}

// Field is a single structured log field.
type Field struct {
	Key   string
	Value any
}

// F builds a Field.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Logger writes redacted JSON log lines.
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

// New returns a Logger writing JSON lines to w.
func New(w io.Writer) *Logger {
	return &Logger{w: w, now: time.Now}
}

// NewWithClock returns a Logger with a fixed clock, for deterministic tests.
func NewWithClock(w io.Writer, now func() time.Time) *Logger {
	return &Logger{w: w, now: now}
}

// Info logs at info severity.
func (l *Logger) Info(event string, fields ...Field) { l.log(LevelInfo, event, nil, fields) }

// Warn logs at warn severity.
func (l *Logger) Warn(event string, fields ...Field) { l.log(LevelWarn, event, nil, fields) }

// Error logs at error severity. The error's message is included; callers are
// responsible for constructing errors that are already redacted, and the
// logger redacts again as a second line of defence.
func (l *Logger) Error(event string, err error, fields ...Field) {
	l.log(LevelError, event, err, fields)
}

func (l *Logger) log(level Level, event string, err error, fields []Field) {
	rec := map[string]any{
		"ts":    l.now().UTC().Format(time.RFC3339Nano),
		"level": string(level),
		"event": event,
	}
	if err != nil {
		rec["error"] = redactValue(err.Error())
	}
	for _, f := range fields {
		if f.Key == "" {
			continue
		}
		// Reserved keys cannot be overwritten by a caller-supplied field.
		switch normaliseKey(f.Key) {
		case "ts", "level", "event":
			continue
		}
		if IsDeniedKey(f.Key) {
			rec[f.Key] = Placeholder
			continue
		}
		rec[f.Key] = Redact(f.Value)
	}

	// json.Marshal sorts map keys, so output is deterministic.
	b, mErr := json.Marshal(rec)
	if mErr != nil {
		// Never emit the offending value: it is exactly the sort of thing that
		// failed to marshal because it was unusual, and unusual values are
		// where secrets hide.
		b, _ = json.Marshal(map[string]any{
			"ts":    l.now().UTC().Format(time.RFC3339Nano),
			"level": string(LevelError),
			"event": "audit.marshal_failed",
		})
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

// Redact returns a loggable form of v, replacing anything sensitive.
func Redact(v any) any { return redactValue(v) }

func redactValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case Redactor:
		return t.Redacted()
	case error:
		return redactValue(t.Error())
	case string:
		// Every string goes through the URL redaction. A credential in a
		// source URL is the one secret that arrives inside a value that looks
		// like an address, under a field name that looks harmless; see url.go.
		return RedactURLs(t)
	case bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, time.Duration, time.Time:
		return t
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = RedactURLs(s)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if IsDeniedKey(k) {
				out[k] = Placeholder
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, redactValue(val))
		}
		return out
	default:
		// Unknown types are rendered with %v, which routes through any
		// fmt.Formatter the type implements. Secret types redact themselves on
		// that path, so an unrecognised wrapper still cannot leak.
		return RedactURLs(fmt.Sprintf("%v", t))
	}
}

// SortedKeys returns the keys of m in a stable order. Used by tests and by
// deterministic report rendering.
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
