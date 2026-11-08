// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/proposal"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # EVERYTHING HERE IS SYNTHETIC
//
// The signing key comes from a fixed seed inside the test binary, every domain
// is under a documentation-reserved name from RFC 2606, and every source
// record is invented. docs/source-registry.json is not read, no record in it
// is enabled, and nothing is fetched.

// proposeAt is the instant every fixture below is judged against. Explicit, so
// that two runs of the command produce byte-identical output.
const proposeAt = "2026-06-01T00:00:00Z"

// proposeEnv is a complete set of input files on disk, as an operator would
// have them.
type proposeEnv struct {
	dir          string
	evidencePath string
	signersPath  string
	registryPath string
	policyPath   string
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func writeFixture(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// proposeGrant is a permitted grant with the citation the registry requires.
func proposeGrant() sourceregistry.Grant {
	return sourceregistry.Grant{
		Status: sourceregistry.GrantPermitted,
		Evidence: sourceregistry.Evidence{
			ProviderTerms: []sourceregistry.Citation{{
				URL:       "https://example.com/terms",
				CheckedOn: "2026-01-01",
				Quote:     "synthetic terms written for this test suite",
			}},
		},
	}
}

func proposeSource(id string) sourceregistry.Source {
	perms := map[sourceregistry.Operation]sourceregistry.Grant{}
	for _, op := range sourceregistry.AllOperations {
		perms[op] = proposeGrant()
	}
	return sourceregistry.Source{
		SourceID: id, CatalogRef: "none", RequestedPriority: "unknown",
		OfficialName: "synthetic source " + id, OfficialDocumentation: "unknown",
		VerifiedOn: "unknown", Kind: "bulk feed", IndicatorTypes: []string{"domain"},
		ClassificationMeaning:       "invented for this test suite",
		Authentication:              "none",
		Quotas:                      "unknown",
		UpdateCadence:               "unknown",
		Retention:                   "unknown",
		WithdrawalBehaviour:         "unknown",
		AttributionRequired:         "unknown",
		DerivedDataRestrictions:     "unknown",
		UpstreamSources:             []string{},
		UpstreamSourcesCompleteness: sourceregistry.UpstreamDocumentedComplete,
		AggregationDependencies:     []string{},
		IntendedOperations:          []string{},
		AccessStatus:                "unresolved",
		DispositionReason:           "synthetic record; there is nothing to look at",
		PrivacyImplications:         "unknown",
		IntendedPermittedUse:        "unknown",
		CoverageLimitations:         "unknown",
		OperationalCost:             "unknown",
		Permissions:                 perms,
	}
}

// newProposeEnv writes the four input files. mutate, when given, may change
// the evidence records before they are signed.
func newProposeEnv(t *testing.T, mutate func(*[]feed.EvidenceRecord)) *proposeEnv {
	t.Helper()
	dir := t.TempDir()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x41
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	records := []feed.EvidenceRecord{
		// Two DIRECT assertions: two voices, and the threshold of two is met.
		{Type: "domain", Value: "bad.example.com", SourceID: "src-a", SourceRecordID: "a1",
			Classification: "malicious", State: "active"},
		{Type: "domain", Value: "bad.example.com", SourceID: "src-c", SourceRecordID: "c1",
			Classification: "malicious", State: "active"},
		// One direct and one REPUBLISHED: the aggregated claim is evidence and
		// is not a second voice, so the threshold is not met. FINDING-122, at
		// the public surface rather than in a unit test.
		{Type: "domain", Value: "relayed.example.org", SourceID: "src-a", SourceRecordID: "a4",
			Classification: "malicious", State: "active"},
		{Type: "domain", Value: "relayed.example.org", SourceID: "src-b", SourceRecordID: "b4",
			Classification: "malicious", State: "active"},
		{Type: "domain", Value: "lonely.example.net", SourceID: "src-a", SourceRecordID: "a2",
			Classification: "suspicious", State: "active"},
		{Type: "domain", Value: "bank.example.com", SourceID: "src-a", SourceRecordID: "a3",
			Classification: "malicious", State: "active"},
		{Type: "domain", Value: "bank.example.com", SourceID: "src-c", SourceRecordID: "c3",
			Classification: "malicious", State: "active"},
	}
	if mutate != nil {
		mutate(&records)
	}

	at, err := time.Parse(time.RFC3339, proposeAt)
	if err != nil {
		t.Fatal(err)
	}
	payload := mustJSON(t, feed.EvidenceManifest{
		ManifestVersion: feed.SupportedEvidenceManifestVersion,
		FeedID:          "synthetic-evidence",
		IssuedAt:        at.Add(-time.Hour),
		ExpiresAt:       at.Add(24 * time.Hour),
		Records:         records,
	})
	doc := mustJSON(t, struct {
		SchemaVersion int               `json:"schema_version"`
		Signature     map[string]string `json:"signature"`
		Payload       json.RawMessage   `json:"payload"`
	}{feed.EvidenceSchemaVersion, map[string]string{
		"algorithm": feed.SignatureAlgorithm,
		"key_id":    "synthetic-key-1",
		"value":     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}, payload})

	return &proposeEnv{
		dir:          dir,
		evidencePath: writeFixture(t, dir, "evidence.json", doc),
		signersPath: writeFixture(t, dir, "signers.json", mustJSON(t, feed.SignerAuthority{
			SchemaVersion: feed.SignerAuthoritySchemaVersion,
			Signers: []feed.Signer{{
				KeyID: "synthetic-key-1", PublicKey: pub,
				AssertsSourceIDs: []string{"src-a", "src-c"},
				AggregatorFor:    []string{"src-b"},
				Note:             "synthetic authority written for this test suite",
			}},
		})),
		registryPath: writeFixture(t, dir, "registry.json", mustJSON(t, sourceregistry.Registry{
			SchemaVersion:    sourceregistry.SchemaVersion,
			Note:             "synthetic registry written for this test suite; nothing is enabled",
			RetiredSourceIDs: []string{},
			Sources:          []sourceregistry.Source{proposeSource("src-a"), proposeSource("src-b"), proposeSource("src-c")},
		})),
		policyPath: writeFixture(t, dir, "policy.json", []byte(`{
  "schema_version": 1,
  "note": "synthetic policy written for this test suite",
  "min_independent_sources": 2,
  "proposal_scope": "exact",
  "accept_unestablished_independence": false,
  "exceptions": [{"value":"bank.example.com","scope":"exact","note":"the household's bank"}]
}`)),
	}
}

func (e *proposeEnv) args(extra ...string) []string {
	return append([]string{
		"propose",
		"-evidence", e.evidencePath,
		"-signers", e.signersPath,
		"-registry", e.registryPath,
		"-policy", e.policyPath,
		"-at", proposeAt,
	}, extra...)
}

// --- the command's answers ----------------------------------------------

func TestProposeAnswersEachIndicatorWithAReason(t *testing.T) {
	e := newProposeEnv(t, nil)
	code, stdout, stderr := capture(t, e.args()...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	for _, want := range []string{
		"bad.example.com", "corroborated", "scope=exact",
		"lonely.example.net", "insufficient_independent_support",
		"bank.example.com", "user_exception",
		"7 record(s): 7 admitted, 0 refused",
		"4 indicator(s): 1 proposed, 2 abstained, 1 refused",
		// FINDING-122 at the public surface: one direct claim and one
		// republished one do not make two voices.
		"relayed.example.org", "aggregated_claims_are_not_independent_confirmation",
		"aggregated (NOT counted as independent): src-b",
		"not permission to enforce",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report does not say %q:\n%s", want, stdout)
		}
	}
	// Every binding is present and is a digest, not a name.
	for _, want := range []string{
		"evidence         sha256:",
		"signer authority sha256:", "signer grant     sha256:",
		"source registry  sha256:", "policy           sha256:",
		"evaluated at     " + proposeAt,
		// A RULE version, and the report must not let it read as a build
		// stamp. The build identity is a separate, explicitly-supplied line.
		"semantics        v1  (a RULE version, not a build stamp)",
		"built by         scamwall ",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report does not bind %q:\n%s", want, stdout)
		}
	}
}

func TestProposeOutputIsDeterministic(t *testing.T) {
	e := newProposeEnv(t, nil)
	_, first, _ := capture(t, e.args()...)
	_, second, _ := capture(t, e.args()...)
	if first != second {
		t.Error("two runs over the same inputs produced different output")
	}
	_, firstJSON, _ := capture(t, e.args("-json")...)
	_, secondJSON, _ := capture(t, e.args("-json")...)
	if firstJSON != secondJSON {
		t.Error("two JSON runs over the same inputs produced different output")
	}
}

// TestChangingAnInputChangesTheBindingThatNamesIt.
//
// A report that did not move when its inputs did would be citing a
// configuration it was not computed from.
func TestChangingAnInputChangesTheBindingThatNamesIt(t *testing.T) {
	e := newProposeEnv(t, nil)
	_, base, _ := capture(t, e.args("-json")...)
	baseBinding := decodeBinding(t, base)

	t.Run("a different policy", func(t *testing.T) {
		writeFixture(t, e.dir, "policy.json", []byte(
			`{"schema_version":1,"min_independent_sources":1,"proposal_scope":"subdomains"}`))
		_, out, _ := capture(t, e.args("-json")...)
		b := decodeBinding(t, out)
		if b.PolicyDigest == baseBinding.PolicyDigest {
			t.Error("the policy changed and the policy binding did not")
		}
		if b.EvidenceDigest != baseBinding.EvidenceDigest {
			t.Error("changing the policy moved the evidence binding")
		}
	})

	t.Run("a different registry", func(t *testing.T) {
		e2 := newProposeEnv(t, nil)
		writeFixture(t, e2.dir, "registry.json", mustJSON(t, sourceregistry.Registry{
			SchemaVersion:    sourceregistry.SchemaVersion,
			RetiredSourceIDs: []string{},
			Sources: []sourceregistry.Source{
				proposeSource("src-a"), proposeSource("src-b"), proposeSource("src-c"),
			},
		}))
		_, out, _ := capture(t, e2.args("-json")...)
		if decodeBinding(t, out).RegistryDigest == baseBinding.RegistryDigest {
			t.Error("the registry changed and the registry binding did not")
		}
	})

	t.Run("a different evidence document", func(t *testing.T) {
		e2 := newProposeEnv(t, func(r *[]feed.EvidenceRecord) {
			(*r)[0].Value = "other.example.com"
		})
		_, out, _ := capture(t, e2.args("-json")...)
		if decodeBinding(t, out).EvidenceDigest == baseBinding.EvidenceDigest {
			t.Error("the evidence changed and the evidence binding did not")
		}
	})

	t.Run("a different evaluation instant", func(t *testing.T) {
		code, out, _ := capture(t, "propose",
			"-evidence", e.evidencePath, "-signers", e.signersPath,
			"-registry", e.registryPath, "-policy", e.policyPath,
			"-at", "2026-06-01T06:00:00Z", "-json")
		if code != exitOK {
			t.Fatalf("exit %d: %s", code, out)
		}
		if decodeBinding(t, out).EvaluatedAt == baseBinding.EvaluatedAt {
			t.Error("the evaluation instant changed and the binding did not")
		}
	})
}

func decodeBinding(t *testing.T, out string) proposal.Binding {
	t.Helper()
	var doc struct {
		Binding proposal.Binding `json:"binding"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, out)
	}
	return doc.Binding
}

// --- exit codes ----------------------------------------------------------

func TestProposeExitCodesSayWhichOfThreeThingsHappened(t *testing.T) {
	t.Run("0: every record admitted", func(t *testing.T) {
		e := newProposeEnv(t, nil)
		if code, out, _ := capture(t, e.args()...); code != exitOK {
			t.Fatalf("exit %d, want %d\n%s", code, exitOK, out)
		}
	})

	t.Run("3: the run completed and a record was refused", func(t *testing.T) {
		e := newProposeEnv(t, func(r *[]feed.EvidenceRecord) {
			*r = append(*r, feed.EvidenceRecord{
				Type: "domain", Value: "x.example.com", SourceID: "src-nobody",
				Classification: "malicious", State: "active",
			})
		})
		code, out, _ := capture(t, e.args()...)
		if code != exitPartial {
			t.Fatalf("exit %d, want %d\n%s", code, exitPartial, out)
		}
		// The report is COMPLETE; a refusal is an outcome, not a failure.
		if !strings.Contains(out, "records not admitted as evidence") {
			t.Errorf("the refusal is not reported:\n%s", out)
		}
		if !strings.Contains(out, "signer_not_authorised_for_source") {
			t.Errorf("the refusal carries no reason code:\n%s", out)
		}
	})

	t.Run("1: the run did not complete", func(t *testing.T) {
		e := newProposeEnv(t, nil)
		writeFixture(t, e.dir, "evidence.json", []byte(`{"schema_version":2,"signature":{}}`))
		if code, _, _ := capture(t, e.args()...); code != exitFailure {
			t.Fatalf("exit %d, want %d", code, exitFailure)
		}
	})

	t.Run("2: a usage error", func(t *testing.T) {
		e := newProposeEnv(t, nil)
		for _, args := range [][]string{
			{"propose"},
			{"propose", "-evidence", e.evidencePath},
			{"propose", "-evidence", e.evidencePath, "-signers", e.signersPath},
			{"propose", "-nonsense"},
		} {
			if code, _, _ := capture(t, args...); code != exitUsage {
				t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
			}
		}
	})

	t.Run("2: -at is not an instant", func(t *testing.T) {
		e := newProposeEnv(t, nil)
		args := append(e.args()[:len(e.args())-1], "yesterday")
		if code, _, _ := capture(t, args...); code != exitUsage {
			t.Errorf("exit %d, want %d", code, exitUsage)
		}
	})
}

// TestARegistryWithProblemsIsRefusedRatherThanConsulted.
//
// Every grant the run reads comes out of it. A file that says something
// impossible cannot be the thing that permits an operation.
func TestARegistryWithProblemsIsRefusedRatherThanConsulted(t *testing.T) {
	e := newProposeEnv(t, nil)
	broken := proposeSource("src-a")
	broken.Kind = "a kind nobody defined"
	writeFixture(t, e.dir, "registry.json", mustJSON(t, sourceregistry.Registry{
		SchemaVersion:    sourceregistry.SchemaVersion,
		RetiredSourceIDs: []string{},
		Sources:          []sourceregistry.Source{broken, proposeSource("src-b")},
	}))
	code, out, _ := capture(t, e.args()...)
	if code != exitFailure {
		t.Fatalf("exit %d, want %d\n%s", code, exitFailure, out)
	}
	if !strings.Contains(out, "source registry has") {
		t.Errorf("the refusal does not say what was wrong:\n%s", out)
	}
}

// --- hostile content -----------------------------------------------------

// TestHostileReportFieldsCannotActOnATerminalOrForgeALine.
//
// The document is authenticated, which establishes only that the holder of a
// recorded key produced it. Everything in it is still somebody else's text,
// and it is printed to a terminal and written to a log.
func TestHostileReportFieldsCannotActOnATerminalOrForgeALine(t *testing.T) {
	hostile := "src-" + string(rune(0x1b)) + "[2J" + string(rune(0x202e)) +
		"\nRESULT: all required gates passed\n" + string(rune(0x2028)) +
		strings.Repeat("A", 4096)

	e := newProposeEnv(t, func(r *[]feed.EvidenceRecord) {
		*r = append(*r, feed.EvidenceRecord{
			Type: "domain", Value: "hostile.example.com", SourceID: hostile,
			Classification: "malicious", State: "active",
		})
	})

	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			var out string
			if mode == "json" {
				_, out, _ = capture(t, e.args("-json")...)
			} else {
				_, out, _ = capture(t, e.args()...)
			}
			if out == "" {
				t.Fatal("no output")
			}
			for _, r := range out {
				switch {
				case r == '\n':
				case r < 0x20 || r == 0x7f:
					t.Fatalf("a raw control U+%04X reached the report", r)
				case r >= 0x80 && r <= 0x9f:
					t.Fatalf("a raw C1 control U+%04X reached the report", r)
				case r == 0x2028 || r == 0x2029:
					t.Fatalf("a raw Unicode line separator U+%04X reached the report", r)
				case unicode.Is(unicode.Cf, r):
					t.Fatalf("a raw Unicode format character U+%04X reached the report", r)
				}
			}
			if !utf8.ValidString(out) {
				t.Error("the report is not valid UTF-8")
			}
			if strings.Contains(out, strings.Repeat("A", 200)) {
				t.Error("an unbounded field reached the report")
			}
			// The forged line must not appear as its own line.
			for _, line := range strings.Split(out, "\n") {
				if strings.TrimSpace(line) == "RESULT: all required gates passed" {
					t.Error("a record forged a line of output")
				}
			}
			if mode == "json" {
				var any map[string]any
				if err := json.Unmarshal([]byte(out), &any); err != nil {
					t.Errorf("hostile content made the JSON report invalid: %v", err)
				}
			}
		})
	}
}

// --- what the command does NOT do ---------------------------------------

// TestProposeNeedsNoConfigurationCredentialOrCA.
//
// It takes no -config flag at all, so there is no path from it to the
// deployment's Pi-hole host, CA, or application password.
func TestProposeNeedsNoConfigurationCredentialOrCA(t *testing.T) {
	e := newProposeEnv(t, nil)

	// A -config flag must not even be accepted: accepting and ignoring one
	// would let an operator believe the command had read it.
	if code, _, _ := capture(t, e.args("-config", "/nonexistent/config.json")...); code != exitUsage {
		t.Errorf("propose accepted a -config flag; exit %d", code)
	}

	code, stdout, stderr := capture(t, e.args()...)
	if code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, forbidden := range []string{"pi.hole", "secret", "password", "X-FTL-SID", "/etc/scamwall"} {
		if strings.Contains(strings.ToLower(stdout+stderr), strings.ToLower(forbidden)) {
			t.Errorf("the output mentions %q", forbidden)
		}
	}
}

// TestProposeDoesNotReferenceTheAdapterOrTheConfiguration is the source-level
// guard, in the same shape as TestOfflineCommandsDoNotReferenceThePiholeAdapter.
func TestProposeDoesNotReferenceTheAdapterOrTheConfiguration(t *testing.T) {
	src, err := os.ReadFile("propose.go")
	if err != nil {
		t.Fatalf("read propose.go: %v", err)
	}
	// Comment lines are skipped. The file's own documentation NAMES config.Load
	// and config.LoadSecretFile, to say that it does not call them, and a guard
	// that fired on that would be reading the explanation as the offence.
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, forbidden := range []string{"pihole.", "config.", "http.", "net.", "url."} {
			if strings.Contains(line, forbidden) {
				t.Errorf("propose.go:%d references %q; this command reaches no network "+
					"and no credential:\n%s", i+1, forbidden, line)
			}
		}
	}
}

// TestTheProposalPathDoesNotDependOnTheAdapterAtAll is the stronger, whole
// import-graph version: not "this file does not mention it" but "no package
// this path pulls in can reach it".
func TestTheProposalPathDoesNotDependOnTheAdapterAtAll(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	out, err := exec.Command("go", "list", "-deps",
		"github.com/dubyfls/Pinga53/engine/internal/proposal").CombinedOutput()
	if err != nil {
		t.Skipf("go list: %v\n%s", err, out)
	}
	// net/http is deliberately NOT on this list, and the reason is worth
	// writing down rather than discovering later. golang.org/x/net/publicsuffix
	// implements net/http/cookiejar.PublicSuffixList and therefore imports
	// net/http; internal/domain has used publicsuffix since before this order,
	// so net/http has always been in this graph and in the executable. Linking
	// a package is not calling it, and asserting otherwise here would be a
	// guard that fails for a reason unrelated to what it claims to measure.
	// What the absence of a network call rests on is the source guard above and
	// the namespace run below.
	forbidden := []string{
		"github.com/dubyfls/Pinga53/engine/internal/adapters/pihole",
		"github.com/dubyfls/Pinga53/engine/internal/config",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if dep == f {
				t.Errorf("internal/proposal transitively depends on %s", f)
			}
		}
	}
}

// TestTheRealProcessProducesTheSameAnswerWithNoNetworkAtAll.
//
// # WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT
//
// It builds the actual binary and runs the actual process twice: once
// normally, and once inside an unprivileged network namespace created with
// `unshare -rn`, which has no interface but a DOWN loopback. Identical output
// and an exit of 0 in both establishes that the command completes no network
// operation — nothing it needs is reachable there.
//
// The POSITIVE CONTROL is what makes that mean anything: `status`, which does
// need the network, is run in the same namespace and must fail. Without it,
// "it worked in the namespace" would be consistent with the namespace doing
// nothing at all.
//
// It does NOT establish that no socket was opened. A connect() that failed and
// was ignored would look exactly like this. That needs a syscall-level trace
// or a runtime with no network device, and neither is available here; the
// exact missing operator evidence is recorded in docs/VERIFICATION.md.
func TestTheRealProcessProducesTheSameAnswerWithNoNetworkAtAll(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not available; runtime isolation evidence is BLOCKED here")
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skipf("unprivileged network namespaces are unavailable: %v", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}

	bin := filepath.Join(t.TempDir(), "scamwall")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	e := newProposeEnv(t, nil)
	args := e.args()

	plain, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("the ordinary run failed: %v", err)
	}
	isolated, err := exec.Command("unshare", append([]string{"-rn", bin}, args...)...).Output()
	if err != nil {
		t.Fatalf("the run in an empty network namespace failed: %v", err)
	}
	if string(plain) != string(isolated) {
		t.Error("the command answered differently with and without a network")
	}

	// The control: a command that DOES need the network must fail there, or
	// the namespace is proving nothing.
	cfgPath := writeConfig(t, nil)
	control := exec.Command("unshare", "-rn", bin, "status", "-config", cfgPath)
	if err := control.Run(); err == nil {
		t.Error("`status` SUCCEEDED inside an empty network namespace; the namespace is " +
			"not isolating anything and the result above establishes nothing")
	}
}

// --- writing a report ----------------------------------------------------

func TestProposeWritesOnlyTheReportItWasAskedFor(t *testing.T) {
	e := newProposeEnv(t, nil)
	out := filepath.Join(e.dir, "report.json")

	code, stdout, _ := capture(t, e.args("-json", "-out", out)...)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stdout)
	}
	if !strings.Contains(stdout, "report written to") {
		t.Errorf("the command did not say where it wrote: %q", stdout)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the written report is not valid JSON: %v", err)
	}
	for _, key := range []string{"binding", "counts", "limitations", "records", "outcomes"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("the written report has no %q", key)
		}
	}

	t.Run("it refuses to overwrite", func(t *testing.T) {
		code, stdout, _ := capture(t, e.args("-json", "-out", out)...)
		if code != exitFailure {
			t.Errorf("exit %d; the command overwrote an existing report", code)
		}
		if !strings.Contains(stdout, "does not overwrite") {
			t.Errorf("the refusal does not say why: %q", stdout)
		}
	})

	t.Run("nothing else appeared in the directory", func(t *testing.T) {
		entries, err := os.ReadDir(e.dir)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{
			"evidence.json": true, "signers.json": true,
			"registry.json": true, "policy.json": true, "report.json": true,
		}
		for _, entry := range entries {
			if !want[entry.Name()] {
				t.Errorf("the command left %q behind", entry.Name())
			}
		}
	})
}

// TestProposeIsDocumentedAndAdvertisesNothingThatMutates.
func TestProposeIsDocumentedAndAdvertisesNothingThatMutates(t *testing.T) {
	_, help, _ := capture(t, "help")
	if !strings.Contains(help, "propose") {
		t.Error("propose is dispatched but not documented in usage")
	}
	for _, forbidden := range []string{"\n  apply", "\n  enforce", "\n  push"} {
		if strings.Contains(help, forbidden) {
			t.Errorf("usage advertises %q", strings.TrimSpace(forbidden))
		}
	}
	if !strings.Contains(strings.Join(strings.Fields(help), " "), "not permission to enforce it") {
		t.Error("usage does not say that producing a proposal is not permission to enforce it")
	}
}

// TestAFailedWriteLeavesNoPartialReport.
//
// # FINDING-129, FOUND BY DRIVING THE REAL PROCESS
//
// The superseded implementation opened -out directly and, when the write
// failed, closed it and returned an error — leaving the truncated bytes on
// disk under exactly the name the operator asked for. Measured against
// 9dcb191 under `ulimit -f 4`: a 4,096-byte file, not valid JSON, ending
// mid-record, sitting where a completed report belongs.
//
// A script globbing *.json would take it for evidence, and a truncated TEXT
// report is worse still: it is readable prose all the way to where it stops.
//
// The failure is produced with RLIMIT_FSIZE rather than a mock, because the
// thing under test is what the real process leaves on a real filesystem.
func TestAFailedWriteLeavesNoPartialReport(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	bin := filepath.Join(t.TempDir(), "scamwall")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	for _, mode := range []struct{ name, flag, ext string }{
		{"json", "-json", ".json"},
		{"text", "", ".txt"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			e := newProposeEnv(t, nil)
			out := filepath.Join(e.dir, "report"+mode.ext)

			args := append(e.args("-out", out), mode.flag)
			if mode.flag == "" {
				args = e.args("-out", out)
			}
			// 4 * 512 = 2048 bytes, well under a complete report.
			cmd := exec.Command("sh", "-c",
				"ulimit -f 4; exec \"$@\"", "sh", bin)
			cmd.Args = append(cmd.Args, args...)
			combined, _ := cmd.CombinedOutput()

			if _, err := os.Stat(out); err == nil {
				b, _ := os.ReadFile(out)
				t.Errorf("a failed write left %d bytes under the operator's name:\n%s",
					len(b), string(b[:min(len(b), 200)]))
			} else if !os.IsNotExist(err) {
				t.Fatalf("stat: %v", err)
			}
			if _, err := os.Stat(out + ".partial"); err == nil {
				t.Errorf("the temporary file survived a failed write")
			}
			if !strings.Contains(string(combined), "file too large") {
				t.Fatalf("premise broken: the write did not fail:\n%s", combined)
			}
		})
	}
}

// TestASuccessfulWriteLeavesExactlyOneFile is the positive control: a fix
// that removed the report on every path would satisfy the test above.
func TestASuccessfulWriteLeavesExactlyOneFile(t *testing.T) {
	e := newProposeEnv(t, nil)
	out := filepath.Join(e.dir, "report.json")

	if code, stdout, _ := capture(t, e.args("-json", "-out", out)...); code != exitOK {
		t.Fatalf("exit %d: %s", code, stdout)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the report was not written: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the written report is not valid JSON: %v", err)
	}
	if _, err := os.Stat(out + ".partial"); err == nil {
		t.Error("the temporary file survived a successful write")
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".partial") {
			t.Errorf("the command left %q behind", entry.Name())
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestProposeRefusesAnUnrecognisedAudience.
//
// An unrecognised value falls through to the EXPORT rendering inside
// ForAudience, which is the safe direction. It is still refused here: a typo
// that silently produced a redacted report would be read as "nothing
// qualified", which is a wrong answer delivered confidently.
func TestProposeRefusesAnUnrecognisedAudience(t *testing.T) {
	code, out, errOut := capture(t, "propose", "-audience", "locel",
		"-evidence", "/nonexistent", "-signers", "/nonexistent",
		"-registry", "/nonexistent", "-policy", "/nonexistent")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\n%s%s", code, exitUsage, out, errOut)
	}
	if !strings.Contains(out+errOut, "-audience") {
		t.Errorf("the message does not name the flag:\n%s%s", out, errOut)
	}
}
