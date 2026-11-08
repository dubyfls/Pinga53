// SPDX-License-Identifier: AGPL-3.0-only

// Command elfcheck asserts, by parsing the ELF structure itself, that an
// executable has no dynamic interpreter and no dynamic linking structures.
//
// It replaces `! ldd BINARY | grep -q "=>"`, which proved nothing:
//
//   - `ldd` on a static binary prints "not a dynamic executable" and exits 1,
//     and on a non-ELF file it fails too, so a MISSING or CORRUPT binary
//     produced the same "no => lines" result as a correctly static one;
//   - if `ldd` was absent the shell reported command-not-found, which the
//     negated pipeline also read as success;
//   - `ldd` may execute the object it is asked about, which is the wrong
//     operation to perform on a build artifact.
//
// Scope of what this proves — deliberately narrow:
//
//	PROVES     the file parses as an ELF object of an executable type, declares
//	           no PT_INTERP / .interp, has no PT_DYNAMIC / SHT_DYNAMIC section,
//	           and names no DT_NEEDED shared library.
//	DOES NOT   prove the binary is safe, that it was built from this source,
//	PROVE      that it contains no embedded secret, or that it will run.
//
// A file that cannot be opened, cannot be parsed, or is not an executable
// object is a FAILURE, never a pass.
//
// Usage: elfcheck <path>
// Exit status: 0 only when every required property was actually observed.
package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
)

// property is one observed structural fact and whether it satisfies the
// requirement. Every property is reported, so a failure says which one failed.
type property struct {
	name     string
	ok       bool
	observed string
}

type report struct {
	path       string
	class      string
	machine    string
	objectType string
	properties []property
}

func (r *report) add(name string, ok bool, observed string) {
	r.properties = append(r.properties, property{name: name, ok: ok, observed: observed})
}

func (r *report) failed() bool {
	for _, p := range r.properties {
		if !p.ok {
			return true
		}
	}
	return false
}

// inspect opens path and records every required structural property.
//
// It returns an error only when no observation could be made at all — a
// missing file, a non-regular file, an empty file, or something that is not an
// ELF object. Those are failures of the check, not passes.
func inspect(path string) (*report, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (mode %s)", path, info.Mode())
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}

	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s is not a parseable ELF object: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	r := &report{
		path:       path,
		class:      f.Class.String(),
		machine:    f.Machine.String(),
		objectType: f.Type.String(),
	}

	// An executable object. A relocatable or core file is not what was built.
	r.add("object type is executable",
		f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN, f.Type.String())

	// A dynamic interpreter, in either representation. PT_INTERP is what the
	// kernel acts on; .interp is the section that carries it. A stripped
	// binary can retain one without the other, so both are checked.
	interp := ""
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			interp = "PT_INTERP present"
			break
		}
	}
	r.add("no PT_INTERP segment", interp == "", orNone(interp))

	sectionInterp := ""
	if s := f.Section(".interp"); s != nil {
		sectionInterp = ".interp section present"
	}
	r.add("no .interp section", sectionInterp == "", orNone(sectionInterp))

	// Dynamic linking structures. A CGO_ENABLED=0 Go build has neither a
	// PT_DYNAMIC segment nor an SHT_DYNAMIC section. Their presence means the
	// binary carries a runtime linking apparatus, which the scratch final
	// stage cannot serve.
	dynSeg := ""
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			dynSeg = "PT_DYNAMIC present"
			break
		}
	}
	r.add("no PT_DYNAMIC segment", dynSeg == "", orNone(dynSeg))

	dynSec := ""
	for _, s := range f.Sections {
		if s.Type == elf.SHT_DYNAMIC {
			dynSec = "section " + s.Name + " of type SHT_DYNAMIC"
			break
		}
	}
	r.add("no SHT_DYNAMIC section", dynSec == "", orNone(dynSec))

	// Named shared library dependencies. DynString reads the .dynamic section;
	// when there is none it reports no entries and no error, which on its own
	// would be indistinguishable from "the section was stripped". That is why
	// the two structural checks above are required as well — this one is the
	// direct statement of the property, not the whole proof of it.
	needed, err := f.DynString(elf.DT_NEEDED)
	switch {
	case err != nil && !errors.Is(err, elf.ErrNoSymbols):
		r.add("no DT_NEEDED entries", false, "dynamic section could not be read: "+err.Error())
	case len(needed) > 0:
		r.add("no DT_NEEDED entries", false, fmt.Sprintf("%v", needed))
	default:
		r.add("no DT_NEEDED entries", true, "none")
	}

	libs, err := f.ImportedLibraries()
	switch {
	case err != nil && !errors.Is(err, elf.ErrNoSymbols):
		r.add("no imported libraries", false, "imported libraries could not be read: "+err.Error())
	case len(libs) > 0:
		r.add("no imported libraries", false, fmt.Sprintf("%v", libs))
	default:
		r.add("no imported libraries", true, "none")
	}

	return r, nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func main() {
	if len(os.Args) != 2 || os.Args[1] == "" {
		fmt.Fprintf(os.Stderr, "usage: elfcheck <path>\n")
		os.Exit(2)
	}

	r, err := inspect(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "elfcheck: FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("elfcheck: %s (%s, %s, %s)\n", r.path, r.class, r.machine, r.objectType)
	for _, p := range r.properties {
		status := "ok  "
		if !p.ok {
			status = "FAIL"
		}
		fmt.Printf("  %s %-28s observed: %s\n", status, p.name, p.observed)
	}
	if r.failed() {
		fmt.Fprintf(os.Stderr, "elfcheck: FAILED: %s does not have the required static properties\n", r.path)
		os.Exit(1)
	}
	fmt.Printf("elfcheck: %s has no dynamic interpreter and no dynamic dependencies\n", r.path)
}
