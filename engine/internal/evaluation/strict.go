// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// maxNestingDepth bounds how deeply the duplicate-key walk will descend.
//
// The walk is recursive, so an input nested a million levels deep would exhaust
// the stack before any validation ran — a crash reached through the parser,
// which is the same class of defect as accepting the document would be. The
// deepest legitimate fixture nests four levels (set, cases, observations,
// object), so 32 leaves ample room and still refuses an attack.
const maxNestingDepth = 32

// Errors raised by the strict decode.
var (
	// ErrAmbiguousDocument is a document that says two different things about
	// the same field. It is REFUSED rather than resolved: see checkDuplicates.
	ErrAmbiguousDocument = errors.New("fixture set is ambiguous")
	// ErrTrailingContent is a file holding more than one document.
	ErrTrailingContent = errors.New("fixture set has content after the document")
	// ErrTooDeep is an input nested past maxNestingDepth.
	ErrTooDeep = errors.New("fixture set is nested too deeply")
)

// knownFieldNames is the closed set of JSON names this schema defines.
//
// # WHY THE SET EXISTS AT ALL
//
// A diagnostic must not echo bytes an attacker chose. A fixture set can arrive
// from outside the repository, its key names are entirely caller-controlled,
// and an error that quotes them verbatim will carry whatever was put there —
// terminal escape sequences, a forged second log line, a megabyte of padding —
// into logs, CI output and this project's own reports.
//
// Refusing to name ANY key would make a genuine typo very hard to find, so the
// rule is narrower and gives up nothing: a key is named only when it is one of
// OUR OWN schema names. Those bytes come from the struct definitions in this
// package, never from the input. Anything else is reported by position.
var knownFieldNames = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	collectJSONNames(reflect.TypeOf(FixtureSet{}), out, 0)
	return out
})

func collectJSONNames(t reflect.Type, into map[string]bool, depth int) {
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
			continue // time.Time's internals are not part of this schema
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			name = f.Name
		}
		into[name] = true
		collectJSONNames(f.Type, into, depth+1)
	}
}

// safeKeyName renders a key for a diagnostic without ever reproducing input.
func safeKeyName(key string) string {
	if knownFieldNames()[key] {
		return fmt.Sprintf("%q", key)
	}
	return "a key this schema does not define"
}

// checkDuplicates refuses any object that names the same key twice, at every
// nesting level.
//
// # WHY THE DECODER CANNOT BE TRUSTED WITH THIS
//
// encoding/json accepts duplicate keys and silently keeps the LAST one. For a
// fixture set — a document whose entire purpose is to state ground truth — that
// is the worst available behaviour. Demonstrated against the superseded
// implementation, every one of these was accepted:
//
//	"label": "legitimate", ... "label": "malicious"      -> malicious
//	"fixture_set_id": "demo", ... "fixture_set_id": "X"  -> X
//	"source_id": "s1", ... "source_id": "s2"             -> s2
//	"action": "block", ... "action": "allow"             -> allow
//
// A reviewer reading the file sees the first value; the harness measures
// against the second; both are reading the same bytes. The first case flips the
// ground truth a precision figure is computed from, and the second changes
// which fixture set a result claims to be about. There is no correct way to
// resolve that ambiguity, so it is not resolved — it is refused.
//
// The walk is over TOKENS, not over a decoded value: by the time a value
// exists, the duplicate has already been discarded and is unrecoverable.
func checkDuplicates(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var problems dupProblems
	if err := walkDuplicates(dec, "", 0, &problems); err != nil && !errors.Is(err, errStopWalk) {
		return err
	}
	if problems.total == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAmbiguousDocument, problems.render())
}

// dupProblems collects the duplicate-key findings under the same two bounds
// fixture.go applies to validation problems.
//
// # WHY THIS PATH NEEDED ITS OWN BOUND
//
// FINDING-111 bounded Validate and left this walk alone, on the reading that
// strict decoding "refuses a hostile KEY without echoing it" and so had
// nothing caller-controlled left to bound. The COUNT was caller-controlled
// anyway. Measured against the unbounded implementation, a 1,760,001-byte
// document of repeated duplicate objects produced a 6,159,921-byte error —
// 3.5x the input, and roughly 28 MB extrapolated to MaxSetBytes
// (FINDING-114). Every individual problem in it was short and safe; there
// were simply 20,000 of them.
//
// The order kept is the DOCUMENT's. Validate sorts before cutting because its
// walk order is not the file's; this walk's is, and the file's order is also
// the order an author reads it in.
type dupProblems struct {
	list  []string
	total int
}

// add records one problem, keeping at most maxCollectedProblems of them in
// memory. total counts every one, so the omission can be stated rather than
// looking like a clean bill of health.
func (p *dupProblems) add(s string) {
	p.total++
	if len(p.list) < maxCollectedProblems {
		p.list = append(p.list, s)
	}
}

// render joins what is reported and states what is not.
func (p *dupProblems) render() string {
	shown := p.list
	if len(shown) > maxReportedProblems {
		shown = shown[:maxReportedProblems]
	}
	out := strings.Join(shown, "; ")
	if omitted := p.total - len(shown); omitted > 0 {
		out += fmt.Sprintf("; and %d further ambiguities not listed", omitted)
	}
	return out
}

// errStopWalk ends the walk without reporting anything.
//
// # WHY THIS IS NOT A nil RETURN
//
// The walk stops quietly when the decoder can read no more, because malformed
// JSON is reported by the decode that follows and saying it twice in two
// vocabularies buries it. Returning nil to mean "stopped" was a DEFECT, not a
// style choice: the array loop below is `for dec.More()`, a decoder in an
// error state keeps answering true, and a recursive call that returned nil
// without consuming anything left the loop spinning forever. Malformed JSON
// inside any array hung the parser — a denial of service reachable from an
// input file. A distinct sentinel makes "stopped" propagate out of the loop.
var errStopWalk = errors.New("the walk can read no more")

// walkDuplicates consumes exactly one JSON value from dec.
func walkDuplicates(dec *json.Decoder, path string, depth int, problems *dupProblems) error {
	if depth > maxNestingDepth {
		return fmt.Errorf("%w: more than %d levels", ErrTooDeep, maxNestingDepth)
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
			here := appendSegment(path, key)
			if seen[key] {
				problems.add(fmt.Sprintf(
					"%s names %s twice, so the document states two different things about it",
					describeLocation(path), safeKeyName(key)))
			}
			seen[key] = true
			if err := walkDuplicates(dec, here, depth+1, problems); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return errStopWalk
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkDuplicates(dec, fmt.Sprintf("%s[%d]", path, i), depth+1, problems); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return errStopWalk
		}
	}
	return nil
}

// appendSegment extends a schema path with one key, sanitising the key HERE
// rather than when the path is rendered.
//
// # WHY SANITISING AT RENDER TIME WAS WRONG
//
// The superseded code appended the raw key and left describeLocation to clean
// the path up afterwards by splitting it on "." and on "[". Both separators
// can appear INSIDE a key, so the render could not tell a segment the walk
// produced from one the document supplied. Measured against it:
//
//	key "cases[\x1b[2J\aforged"  the bracket suffix was emitted VERBATIM,
//	                             putting a raw ESC and a raw BEL into the
//	                             error string, into any log carrying it and
//	                             into any report that quoted it (FINDING-112);
//
//	key "cases.label"            split into two segments, both of them schema
//	                             names, rendering as the path `cases.label` —
//	                             a location the parser never generated, naming
//	                             an object that does not exist in the document
//	                             (FINDING-113).
//
// A segment is safe only if it was never caller-controlled. Every segment this
// produces is either one of THIS package's own schema names or the fixed
// string below, so the assembled path carries no input bytes at all and the
// render has nothing left to clean. Array indices are formatted from an int by
// the walk itself and are safe for the same reason.
func appendSegment(path, key string) string {
	name := unrecognisedSegment
	if knownFieldNames()[key] {
		name = key
	}
	if path == "" {
		return name
	}
	return path + "." + name
}

// unrecognisedSegment stands in for a key that is not one of this schema's own
// names. It is deliberately not the key.
const unrecognisedSegment = "<unrecognised>"

// describeLocation renders the path to the offending object.
//
// Nothing is cleaned here: appendSegment already guarantees that every segment
// is made of this package's own bytes.
func describeLocation(path string) string {
	if path == "" {
		return "the top-level object"
	}
	return "the object at " + path
}

// decodeExactlyOne decodes a single JSON document from b into v and proves
// nothing follows it.
//
// # WHY A SECOND DECODE AND NOT dec.More()
//
// More() answers "is another element coming", derived from a peek that
// SWALLOWS the read error it may encounter. A second Decode that is required
// to return io.EOF answers the question actually being asked — "is this file
// exactly one document" — and distinguishes the three outcomes that matter:
// clean end (io.EOF), another document, and input that is not JSON at all.
//
// HONEST NOTE ON DISCRIMINATION. The superseded implementation used More(),
// and against every trailing-content case in this package's tests it already
// returned the correct verdict. The tests below therefore do NOT discriminate
// between the two implementations; they are recorded as regression cover for
// behaviour that was already right, not as evidence of a defect repaired.
func decodeExactlyOne(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return sanitizeDecodeError(err)
	}
	var rest json.RawMessage
	switch err := dec.Decode(&rest); {
	case errors.Is(err, io.EOF):
		return nil
	case err == nil:
		return fmt.Errorf("%w: a second document follows; a fixture file holds exactly one", ErrTrailingContent)
	default:
		return fmt.Errorf("%w: the bytes after the document are not a document either", ErrTrailingContent)
	}
}

// unknownFieldPrefix is the fixed prefix encoding/json puts on the one error
// whose text embeds a caller-controlled key.
const unknownFieldPrefix = `json: unknown field `

// sanitizeDecodeError strips caller-controlled bytes out of a decode error.
//
// encoding/json reports an unrecognised key as: json: unknown field "<key>".
// The key is quoted straight from the input, so the superseded implementation
// emitted, verbatim, whatever the document put there — demonstrated with
// `json: unknown field "<script>alert(1)</script>"`. That string reaches logs
// and reports. This replaces it with a positionless, schema-vocabulary-only
// form, and names the key only when the key is one of ours.
func sanitizeDecodeError(err error) error {
	msg := err.Error()
	idx := strings.Index(msg, unknownFieldPrefix)
	if idx < 0 {
		return err
	}
	raw := strings.TrimSpace(msg[idx+len(unknownFieldPrefix):])
	var key string
	if uq, uerr := strconv.Unquote(raw); uerr == nil {
		key = uq
	}
	return fmt.Errorf("the document carries %s; a fixture set is a claim about "+
		"ground truth, and a field this build does not understand may qualify that claim",
		safeKeyName(key))
}
