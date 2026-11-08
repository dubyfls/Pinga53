// SPDX-License-Identifier: AGPL-3.0-only

// Package strictjson refuses a JSON document that says two different things
// about the same field.
//
// # WHY A DECODER IS NOT ENOUGH
//
// encoding/json accepts duplicate keys and silently keeps the LAST one. That
// is not a parse error, it is a choice, and for a document of record it is the
// worst available one:
//
//	{"min_independent_sources": 1, ..., "min_independent_sources": 99}
//
// A reviewer reading that file sees a threshold of 1. The program ran with 99.
// Both are reading the same bytes and nothing anywhere says so. Measured
// against `9dcb191` through the real command, that document produced a report
// whose every abstention said "of 99 required" (FINDING-127).
//
// There is no correct way to resolve the ambiguity, so it is not resolved. It
// is refused.
//
// # WHY THIS IS A PACKAGE
//
// Because it was already two packages. `internal/evaluation` grew this walk
// for fixture sets and `internal/sourceregistry` grew its own for the registry
// — near-identical, and they have already diverged: the corrections made to
// the first in ORDER 6 (FINDING-112, FINDING-113, FINDING-114) were never made
// to the second. A security-relevant parser control with two copies has two
// behaviours the first time one of them is fixed.
//
// This is the corrected walk, carrying those fixes, and it is what the
// evidence, signer-authority and proposal-policy documents use. The two
// existing copies are NOT migrated here by this change — they belong to
// packages whose evidence is bound to commits of their own — and the fact that
// one of them is uncorrected is recorded rather than quietly inherited.
//
// # THE PATH IS BUILT FROM THIS PACKAGE'S OWN BYTES
//
// A diagnostic must not echo bytes an attacker chose. The schema path a
// duplicate is reported at is assembled from KNOWN field names and a fixed
// placeholder, sanitised WHERE THE KEY ARRIVES rather than where the path is
// rendered — the separators `.` and `[` can both occur inside a key, so a
// render-time clean cannot tell a segment the walk produced from one the
// document supplied.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// MaxNestingDepth bounds how deeply the walk will descend.
//
// The walk is recursive, so an input nested a million levels deep would
// exhaust the stack before any validation ran — a crash reached through a
// parser. No document this package guards nests beyond a handful of levels.
const MaxNestingDepth = 32

// The bounds on a diagnostic.
//
// A document full of duplicates is caller-controlled in its COUNT even when
// every individual problem is short and safe. MaxCollected bounds what is
// built in memory; MaxReported bounds what is printed. The number omitted is
// always stated, so a bound never reads as a clean bill of health.
const (
	MaxCollected = 1000
	MaxReported  = 50
)

// UnrecognisedSegment stands in for any key that is not one of the caller's
// own schema names. It is deliberately not the key.
const UnrecognisedSegment = "<unrecognised>"

// Errors returned by this package.
var (
	// ErrAmbiguous is a document that names one key twice.
	ErrAmbiguous = errors.New("document is ambiguous: it says two different things about the same field")
	// ErrTooDeep is an input nested past MaxNestingDepth.
	ErrTooDeep = errors.New("document is nested too deeply")
)

// errStopWalk ends the walk without reporting anything.
//
// # WHY THIS IS NOT A nil RETURN
//
// The walk stops quietly when the decoder can read no more, because malformed
// JSON is reported by the decode that follows and saying it twice in two
// vocabularies buries it. Returning nil to mean "stopped" is a DEFECT rather
// than a style choice: the array loop below is `for dec.More()`, a decoder in
// an error state keeps answering true, and a recursive call that returned nil
// without consuming anything leaves the loop spinning forever. Malformed JSON
// inside any array hangs the parser — a denial of service reachable from an
// input file.
var errStopWalk = errors.New("the walk can read no more")

// Duplicate is one ambiguity, located by a schema path built from known names.
//
// Every field is this package's own bytes or the caller's schema vocabulary.
// Nothing the document chose reaches any of them.
type Duplicate struct {
	// Path locates the offending key, e.g. `sources[0].source_id`. An
	// unrecognised key is rendered as UnrecognisedSegment, never as the key.
	Path string
	// Parent locates the object that names the key twice.
	Parent string
	// Key is a safe rendering of the key for prose: the quoted name when the
	// schema defines it, a fixed phrase otherwise.
	Key string
}

// Duplicates walks b and returns every object that names one key twice.
//
// # WHY THIS IS EXPORTED SEPARATELY FROM CheckDuplicates
//
// It is the single walk this repository has for the job. CheckDuplicates
// renders its result as one error; internal/sourceregistry maps it onto that
// package's own Problem type, which collects every validation failure rather
// than stopping at the first. Both call sites are tested. Before ORDER 8 they
// were two implementations and had already diverged — the ORDER 6 corrections
// reached one and not the other, which is FINDING-128.
//
// The returned slice is bounded by MaxCollected. total is the true count and
// is always greater than or equal to len(found), so a bound never reads as a
// clean bill of health.
//
// known is the caller's closed set of schema field names; a key outside it is
// located by position and never reproduced. Pass nil to name no key at all.
func Duplicates(b []byte, known map[string]bool) (found []Duplicate, total int, err error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	p := &problems{known: known}
	if err := walk(dec, "", 0, p); err != nil && !errors.Is(err, errStopWalk) {
		return nil, 0, err
	}
	return p.list, p.total, nil
}

// CheckDuplicates refuses any object in b that names the same key twice, at
// every nesting level.
//
// known is the caller's closed set of schema field names; a key outside it is
// located by position and never reproduced. Pass nil to name no key at all.
func CheckDuplicates(b []byte, known map[string]bool) error {
	found, total, err := Duplicates(b, known)
	if err != nil {
		return err
	}
	if total == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAmbiguous, Render(found, total))
}

// Render turns findings into one bounded sentence, naming what it omitted.
func Render(found []Duplicate, total int) string {
	shown := found
	if len(shown) > MaxReported {
		shown = shown[:MaxReported]
	}
	parts := make([]string, 0, len(shown))
	for _, d := range shown {
		parts = append(parts, fmt.Sprintf(
			"%s names %s twice, so the document states two different things about it",
			describe(d.Parent), d.Key))
	}
	out := strings.Join(parts, "; ")
	if omitted := total - len(shown); omitted > 0 {
		out += fmt.Sprintf("; and %d further ambiguities not listed", omitted)
	}
	return out
}

// problems collects the findings under both bounds.
type problems struct {
	known map[string]bool
	list  []Duplicate
	total int
}

func (p *problems) add(d Duplicate) {
	p.total++
	if len(p.list) < MaxCollected {
		p.list = append(p.list, d)
	}
}

// safeName renders a key for a diagnostic without ever reproducing input.
func (p *problems) safeName(key string) string {
	if p.known[key] {
		return fmt.Sprintf("%q", key)
	}
	return "a key this schema does not define"
}

// appendSegment extends a schema path with one key, sanitising it HERE.
func (p *problems) appendSegment(path, key string) string {
	name := UnrecognisedSegment
	if p.known[key] {
		name = key
	}
	if path == "" {
		return name
	}
	return path + "." + name
}

// describe renders the path to the offending object. Nothing is cleaned here:
// appendSegment already guarantees every segment is the caller's own bytes.
func describe(path string) string {
	if path == "" {
		return "the top-level object"
	}
	return "the object at " + path
}

// walk consumes exactly one JSON value from dec.
func walk(dec *json.Decoder, path string, depth int, p *problems) error {
	if depth > MaxNestingDepth {
		return fmt.Errorf("%w: more than %d levels", ErrTooDeep, MaxNestingDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return errStopWalk
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil // a scalar has nothing nested
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errStopWalk
			}
			key, ok := keyTok.(string)
			if !ok {
				return errStopWalk
			}
			here := p.appendSegment(path, key)
			if seen[key] {
				p.add(Duplicate{Path: here, Parent: path, Key: p.safeName(key)})
			}
			seen[key] = true
			if err := walk(dec, here, depth+1, p); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return errStopWalk
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walk(dec, fmt.Sprintf("%s[%d]", path, i), depth+1, p); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return errStopWalk
		}
	}
	return nil
}

// FieldNames collects the JSON field names a struct type declares, so a caller
// can pass its own closed vocabulary without writing it out twice.
//
// Only the caller's own bytes end up in `known`: the names come from struct
// tags in the caller's source and never from the document.
func FieldNames(t any) map[string]bool {
	out := map[string]bool{}
	collect(reflectTypeOf(t), out, 0)
	return out
}

// collect walks a struct type and records every exported field's JSON name.
func collect(t reflect.Type, into map[string]bool, depth int) {
	if depth > 8 {
		return
	}
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue // time.Time's internals are not part of any schema
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			name = f.Name
		}
		into[name] = true
		collect(f.Type, into, depth+1)
	}
}

func reflectTypeOf(v any) reflect.Type { return reflect.TypeOf(v) }
