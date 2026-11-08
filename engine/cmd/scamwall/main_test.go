// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/config"
	"github.com/dubyfls/Pinga53/engine/internal/policy"
)

// The Phase 1 boundary lives at the command surface as much as in the
// packages beneath it. Until this file existed, `cmd/scamwall` had no tests at
// all, so "no subcommand can modify Pi-hole" rested entirely on reading the
// code. These tests make the boundary observable.
//
// run() writes to *os.File, so the tests hand it real temporary files rather
// than changing the signature of working code to suit a test.

// capture runs the CLI and returns (exit code, stdout, stderr).
func capture(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()

	out, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	defer func() { _ = out.Close() }()

	errf, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("create stderr: %v", err)
	}
	defer func() { _ = errf.Close() }()

	code := run(args, out, errf)

	so, err := os.ReadFile(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	se, err := os.ReadFile(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return code, string(so), string(se)
}

// writeConfig writes a configuration pointing at the repository's signed test
// feed, so the offline commands have something real to work on.
func writeConfig(t *testing.T, mutate func(*config.Config)) string {
	t.Helper()
	cfg := config.Default()
	cfg.Feed.Path = filepath.Join("..", "..", "testdata", "feed.json")
	cfg.Feed.TrustKeyID = "scamwall-test-key-1"
	cfg.Feed.TrustPublicKey = "ZZdzt8vw2UCXeoT95fcT9Fh0U80M7L0I1L/io4AeR7A="
	if mutate != nil {
		mutate(&cfg)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// --- The enforcement boundary -------------------------------------------------

// The single most important assertion in this package: an operator who
// explicitly asks for enforcement must be refused, loudly, and must not be
// able to mistake the refusal for a successful no-op.
func TestSyncRefusesDryRunFalse(t *testing.T) {
	code, stdout, _ := capture(t, "sync", "--dry-run=false")

	if code != exitUsage {
		t.Errorf("exit code = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(stdout, "refusing to run") {
		t.Errorf("refusal not reported: %q", stdout)
	}
	if !strings.Contains(stdout, "read-only") {
		t.Errorf("output does not state the read-only posture: %q", stdout)
	}
	// A refusal that mentions success in any form is a refusal someone will
	// misread in a scrollback.
	for _, forbidden := range []string{"applied", "submitted", "blocked ", "success"} {
		if strings.Contains(strings.ToLower(stdout), forbidden) {
			t.Errorf("refusal output contains %q, which reads like an action was taken: %q", forbidden, stdout)
		}
	}
}

// --dry-run=false must be refused before anything else happens. If the refusal
// came after configuration loading, a broken configuration would mask it — and
// worse, a *valid* configuration would mean the credential had already been
// read from disk.
func TestSyncRefusesBeforeTouchingConfiguration(t *testing.T) {
	code, stdout, _ := capture(t, "sync", "--dry-run=false", "-config", "/nonexistent/definitely/not/here.json")

	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stdout, "refusing to run") {
		t.Errorf("expected the refusal, got: %q", stdout)
	}
	if strings.Contains(stdout, "configuration") {
		t.Errorf("configuration was consulted before the refusal: %q", stdout)
	}
}

func TestEnforcementIsNotCompiledIn(t *testing.T) {
	if policy.EnforcementCompiledIn {
		t.Fatal("EnforcementCompiledIn is true; Phase 1 forbids an enforcing build")
	}
	if err := policy.Apply(nil); err == nil {
		t.Fatal("policy.Apply returned nil; it must always refuse in this build")
	}
}

// --- version ------------------------------------------------------------------

func TestVersionReportsReadOnlyPosture(t *testing.T) {
	code, stdout, _ := capture(t, "version")
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0", code)
	}
	for _, want := range []string{"scamwall", "enforcement compiled in", "false", "read-only, dry-run"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output missing %q: %q", want, stdout)
		}
	}
}

// --- usage --------------------------------------------------------------------

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"unknown command", []string{"definitely-not-a-command"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := capture(t, tc.args...)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr, "Phase 1 is read-only") {
				t.Errorf("usage does not state the phase posture: %q", stderr)
			}
		})
	}
}

func TestHelpSucceeds(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, stdout, _ := capture(t, arg)
		if code != exitOK {
			t.Errorf("%s: exit code = %d, want 0", arg, code)
		}
		if !strings.Contains(stdout, "sync --dry-run") {
			t.Errorf("%s: help does not document sync: %q", arg, stdout)
		}
	}
}

// The advertised command list and the dispatch table must not drift apart. A
// command reachable but undocumented is how an unreviewed surface appears.
func TestEveryDocumentedCommandIsDispatched(t *testing.T) {
	_, help, _ := capture(t, "help")
	for _, cmd := range []string{"version", "doctor", "status", "validate-feed", "plan", "sync"} {
		if !strings.Contains(help, cmd) {
			t.Errorf("command %q is dispatched but not documented in usage", cmd)
		}
	}
	// And nothing that mutates is advertised.
	for _, forbidden := range []string{"apply", "enforce", "block", "add", "remove", "delete"} {
		if strings.Contains(help, "\n  "+forbidden) {
			t.Errorf("usage advertises a mutating command %q", forbidden)
		}
	}
}

// --- offline commands -----------------------------------------------------------

// plan and validate-feed must work with no network, no credential, and no CA.
// The configuration below points ca_path and secret_path at paths that do not
// exist: if either command touched them, it would fail.
func TestOfflineCommandsNeedNoCredentialOrCA(t *testing.T) {
	cfgPath := writeConfig(t, func(c *config.Config) {
		c.Pihole.CAPath = "/nonexistent/ca.crt"
		c.Pihole.SecretPath = "/nonexistent/password"
	})

	for _, cmd := range []string{"validate-feed", "plan"} {
		t.Run(cmd, func(t *testing.T) {
			code, stdout, _ := capture(t, cmd, "-config", cfgPath)
			if code != exitOK {
				t.Fatalf("%s: exit code = %d, want 0. Output: %q", cmd, code, stdout)
			}
			if strings.Contains(stdout, "/nonexistent") {
				t.Errorf("%s: touched the CA or secret path: %q", cmd, stdout)
			}
		})
	}
}

// The plan digest is what makes operator review meaningful: the plan that was
// reviewed must be provably the plan in hand. Two runs over the same feed must
// therefore produce byte-identical output.
func TestPlanIsDeterministic(t *testing.T) {
	cfgPath := writeConfig(t, nil)

	code, first, _ := capture(t, "plan", "-config", cfgPath)
	if code != exitOK {
		t.Fatalf("first plan failed with %d: %q", code, first)
	}
	code, second, _ := capture(t, "plan", "-config", cfgPath)
	if code != exitOK {
		t.Fatalf("second plan failed with %d: %q", code, second)
	}
	if first != second {
		t.Errorf("plan output is not deterministic:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if !strings.Contains(first, "sha256:") {
		t.Errorf("plan does not report a digest: %q", first)
	}
}

// sync in its default (dry-run) mode reports the plan and states plainly that
// nothing was submitted. It needs a reachable Pi-hole, which no test has, so
// this asserts the failure is a clean error rather than a silent success.
func TestSyncDryRunDefaultDoesNotClaimSuccessWithoutPihole(t *testing.T) {
	cfgPath := writeConfig(t, func(c *config.Config) {
		c.Pihole.CAPath = "/nonexistent/ca.crt"
		c.Pihole.SecretPath = "/nonexistent/password"
	})

	code, stdout, _ := capture(t, "sync", "-config", cfgPath)
	if code == exitOK {
		t.Fatalf("sync reported success with no Pi-hole reachable: %q", stdout)
	}
	if !strings.Contains(stdout, "error:") {
		t.Errorf("failure was not reported as an error: %q", stdout)
	}
}

// --- doctor ---------------------------------------------------------------------

// doctor must report a per-check verdict and a nonzero exit when any check
// fails. A diagnostic tool that exits 0 while printing failures teaches people
// to ignore its exit status.
func TestDoctorFailsWhenChecksFail(t *testing.T) {
	cfgPath := writeConfig(t, func(c *config.Config) {
		c.Pihole.CAPath = "/nonexistent/ca.crt"
		c.Pihole.SecretPath = "/nonexistent/password"
	})

	code, stdout, _ := capture(t, "doctor", "-config", cfgPath, "-offline")
	if code == exitOK {
		t.Fatalf("doctor exited 0 despite unreadable trust material: %q", stdout)
	}
	if !strings.Contains(stdout, "FAIL") {
		t.Errorf("doctor did not mark any check as failed: %q", stdout)
	}
	if !strings.Contains(stdout, "checks,") || !strings.Contains(stdout, "failed") {
		t.Errorf("doctor did not print a summary: %q", stdout)
	}
	// The enforcement check must be present and passing.
	if !strings.Contains(stdout, "enforcement absent") {
		t.Errorf("doctor does not check for absent enforcement: %q", stdout)
	}
}

// doctor -offline must not attempt any connection. With a config whose CA is
// unreadable the client cannot even be built, so the connectivity check must be
// absent rather than reported either way.
func TestDoctorOfflineSkipsConnectivity(t *testing.T) {
	cfgPath := writeConfig(t, nil)
	_, stdout, _ := capture(t, "doctor", "-config", cfgPath, "-offline")
	if strings.Contains(stdout, "pi-hole connectivity") {
		t.Errorf("-offline still ran the connectivity check: %q", stdout)
	}
}

// --- flag handling ---------------------------------------------------------------

// An unparseable flag must be a usage error. Silently ignoring it would mean a
// mistyped security-relevant flag looks like it was honoured.
func TestUnknownFlagIsAUsageError(t *testing.T) {
	for _, cmd := range []string{"version", "doctor", "status", "validate-feed", "plan", "sync"} {
		code, _, _ := capture(t, cmd, "--no-such-flag")
		if code != exitUsage {
			t.Errorf("%s --no-such-flag: exit code = %d, want %d", cmd, code, exitUsage)
		}
	}
}

// --- the source-level guard --------------------------------------------------

// The offline commands must not be able to reach the network even by accident.
// This is asserted structurally, the same way internal/adapters/pihole's guard
// tests work: the command bodies must not mention the Pi-hole adapter.
func TestOfflineCommandsDoNotReferenceThePiholeAdapter(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)

	for _, fn := range []string{"func cmdPlan(", "func cmdValidateFeed(", "func printPlan("} {
		start := strings.Index(text, fn)
		if start < 0 {
			t.Fatalf("%s not found in main.go; this guard is looking at the wrong thing", fn)
		}
		end := strings.Index(text[start:], "\n}\n")
		if end < 0 {
			t.Fatalf("could not delimit %s", fn)
		}
		body := text[start : start+end]
		if strings.Contains(body, "pihole.") {
			t.Errorf("%s references the Pi-hole adapter; it must stay offline:\n%s", fn, body)
		}
	}
}

// A build tag is the only thing standing between this binary and an enforcing
// one. Assert that no counterpart file supplying EnforcementCompiledIn = true
// has appeared: "disabled" is weaker than "absent", and this project chose
// absent deliberately.
func TestNoEnforceTaggedFileExists(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "internal", "policy"))
	if err != nil {
		t.Fatalf("read policy package: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "policy", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(b), "EnforcementCompiledIn = true") {
			t.Errorf("%s declares EnforcementCompiledIn = true", e.Name())
		}
		if strings.Contains(string(b), "//go:build enforce") {
			t.Errorf("%s is an enforce-tagged file; Phase 1 forbids one existing at all", e.Name())
		}
	}
}
