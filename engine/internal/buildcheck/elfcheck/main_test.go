// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The controls below are deliberately paired. A checker that always passed
// would be caught by the negative controls; a checker that always failed would
// be caught by the positive one. Neither alone is evidence.

// buildStatic compiles a trivial stdlib-only program with CGO disabled, which
// is how container/Dockerfile builds the shipped binary. If the toolchain
// cannot produce it the test FAILS rather than skipping: an unrunnable control
// proves nothing.
func buildStatic(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module elfcheckcontrol\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	out := filepath.Join(dir, "control")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the static control failed: %v\n%s", err, combined)
	}
	return out
}

func TestStaticBinaryPasses(t *testing.T) {
	r, err := inspect(buildStatic(t))
	if err != nil {
		t.Fatalf("inspect returned an error for a static binary: %v", err)
	}
	if r.failed() {
		for _, p := range r.properties {
			t.Logf("%v %s: %s", p.ok, p.name, p.observed)
		}
		t.Fatalf("a CGO_ENABLED=0 binary was reported as not static")
	}
}

// elfWithSegment builds a minimal, structurally valid ELF64 executable whose
// single program header has the given type. It is the negative control for the
// interpreter and dynamic-section checks: nothing else about the file differs
// from the positive control's shape.
func elfWithSegment(t *testing.T, ptype elf.ProgType) string {
	t.Helper()

	const ehSize = 64
	const phSize = 56
	payload := []byte("/lib64/ld-linux-x86-64.so.2\x00")

	var buf bytes.Buffer
	// e_ident
	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(byte(elf.ELFCLASS64))
	buf.WriteByte(byte(elf.ELFDATA2LSB))
	buf.WriteByte(byte(elf.EV_CURRENT))
	buf.WriteByte(byte(elf.ELFOSABI_NONE))
	buf.Write(make([]byte, 8)) // ABI version + padding

	w := func(v any) {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatalf("encode ELF header: %v", err)
		}
	}
	w(uint16(elf.ET_EXEC))    // e_type
	w(uint16(elf.EM_X86_64))  // e_machine
	w(uint32(elf.EV_CURRENT)) // e_version
	w(uint64(0x400000))       // e_entry
	w(uint64(ehSize))         // e_phoff
	w(uint64(0))              // e_shoff — no section headers
	w(uint32(0))              // e_flags
	w(uint16(ehSize))         // e_ehsize
	w(uint16(phSize))         // e_phentsize
	w(uint16(1))              // e_phnum
	w(uint16(0))              // e_shentsize
	w(uint16(0))              // e_shnum
	w(uint16(0))              // e_shstrndx

	w(uint32(ptype))           // p_type
	w(uint32(elf.PF_R))        // p_flags
	w(uint64(ehSize + phSize)) // p_offset
	w(uint64(0x400000))        // p_vaddr
	w(uint64(0x400000))        // p_paddr
	w(uint64(len(payload)))    // p_filesz
	w(uint64(len(payload)))    // p_memsz
	w(uint64(1))               // p_align
	buf.Write(payload)

	path := filepath.Join(t.TempDir(), "control.elf")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write control: %v", err)
	}
	// The control must be parseable, or it is testing nothing.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("the hand-built control is not a parseable ELF: %v", err)
	}
	_ = f.Close()
	return path
}

func TestDynamicInterpreterFails(t *testing.T) {
	r, err := inspect(elfWithSegment(t, elf.PT_INTERP))
	if err != nil {
		t.Fatalf("inspect returned an error instead of a report: %v", err)
	}
	if !r.failed() {
		t.Fatalf("a binary declaring PT_INTERP was accepted as static")
	}
	if !propertyFailed(r, "no PT_INTERP segment") {
		t.Fatalf("the interpreter property was not the one reported as failed: %+v", r.properties)
	}
}

func TestDynamicSegmentFails(t *testing.T) {
	r, err := inspect(elfWithSegment(t, elf.PT_DYNAMIC))
	if err != nil {
		t.Fatalf("inspect returned an error instead of a report: %v", err)
	}
	if !r.failed() {
		t.Fatalf("a binary carrying PT_DYNAMIC was accepted as static")
	}
	if !propertyFailed(r, "no PT_DYNAMIC segment") {
		t.Fatalf("the dynamic-segment property was not the one reported as failed: %+v", r.properties)
	}
}

// A dynamically linked system binary, when one is present, is the realistic
// negative control. It is additive: the hand-built controls above already
// cover the property without depending on the host.
func TestHostDynamicBinaryFailsWhenAvailable(t *testing.T) {
	candidates := []string{"/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/env"}
	for _, c := range candidates {
		f, err := elf.Open(c)
		if err != nil {
			continue
		}
		hasInterp := false
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				hasInterp = true
			}
		}
		_ = f.Close()
		if !hasInterp {
			continue
		}
		r, err := inspect(c)
		if err != nil {
			t.Fatalf("inspect(%s): %v", c, err)
		}
		if !r.failed() {
			t.Fatalf("the dynamically linked %s was accepted as static", c)
		}
		return
	}
	t.Log("no dynamically linked system binary found; the hand-built controls carry this case")
}

func TestMalformedInputsFail(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, bytes.Repeat([]byte{0xAB}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated")
	if err := os.WriteFile(truncated, []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(dir, "does-not-exist")},
		{"empty file", empty},
		{"non-ELF content", garbage},
		{"truncated ELF header", truncated},
		{"directory", dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := inspect(tc.path)
			if err == nil && (r == nil || !r.failed()) {
				t.Fatalf("%s was accepted; a check that could not run must fail", tc.name)
			}
		})
	}
}

func propertyFailed(r *report, name string) bool {
	for _, p := range r.properties {
		if p.name == name && !p.ok {
			return true
		}
	}
	return false
}
