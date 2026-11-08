# ScamWall Architecture (Phase 1)

ScamWall is a local-first fraud-domain protection engine. Phase 1 delivers a
**read-only, dry-run vertical slice**: it can authenticate to a native Pi-hole
v6 instance, read non-sensitive version and status information, validate a
signed threat feed, and compute a proposed blocking plan — but it has no code
path capable of changing Pi-hole in any way.

---

## 1. Design position

ScamWall is a **separate, unprivileged consumer** of the Pi-hole HTTPS API. It
is not a Pi-hole plugin, patch, fork, or sidecar with special access.

```
┌───────────────────────────────── host ─────────────────────────────────┐
│                                                                        │
│   Pi-hole v6 (native, untouched)          ScamWall (Docker, hardened)  │
│   ┌───────────────────────────┐           ┌─────────────────────────┐  │
│   │ FTL + embedded webserver  │           │ non-root, read-only fs  │  │
│   │ :53 DNS   :443 HTTPS API  │◀──TLS─────│ cap_drop ALL            │  │
│   │ private CA, CN=pi.hole    │  GET only │ no ports, no socket     │  │
│   └───────────────────────────┘           └─────────────────────────┘  │
│            ▲                                        │                  │
│            │ read-only, authenticated               │ read-only mounts │
│            │ POST /api/auth → X-FTL-SID             ▼                  │
│            │ GET  /api/info/version         CA cert, secret, config    │
│            └ DELETE /api/auth (always)                                 │
└────────────────────────────────────────────────────────────────────────┘
```

The blast radius is deliberately asymmetric: ScamWall can be fully compromised
without gaining the ability to modify Pi-hole, because in Phase 1 it holds no
credential capable of mutation *and no code capable of issuing one*.

---

## 2. Package layout

| Package | Responsibility | Depends on |
| --- | --- | --- |
| `cmd/scamwall` | CLI surface, flag parsing, exit codes, wiring | all internal |
| `internal/config` | Load + validate configuration, redacted rendering | domain |
| `internal/domain` | Canonical domain type, IDNA normalisation, validation | — |
| `internal/feed` | Manifest schema, Ed25519 verification, bounds, expiry; and the signed **evidence** document and its signer authority | domain |
| `internal/policy` | Deterministic plan computation, confidence gating | domain, feed |
| `internal/observation` | Provenance-bearing observations, deduplication, corroboration, rights binding | domain, sourceregistry |
| `internal/sourceregistry` | Per-operation rights, lineage, retirement, and the 85 source records | — |
| `internal/proposal` | Matching, exceptions, precedence, reason codes, bound proposal reports, and the household's **automatic contract**: the terms on which a domain may be blocked with nobody asked | domain, feed, observation, safetext, sourceregistry, strictjson |
| `internal/shadow` | The change ScamWall would request of a Pi-hole it has **read**: additions, entries already present, conflicts with user-managed entries, removals of entries an ownership record says are its own. Imports no HTTP client, no adapter and no configuration, so it cannot construct a request of any kind | — |
| `internal/safetext` | Escaping and bounding of caller-controlled text on its way into any report | — |
| `internal/strictjson` | Refusal of a JSON document that says two different things about one field, with a bounded diagnostic that echoes no key | — |
| `internal/audit` | Structured logging with mandatory redaction | — |
| `internal/adapters/pihole` | HTTPS client, session lifecycle, read-only reads | audit, config |

The table above is the **executable**.

**What changed at ORDER 6, and what it means.** `internal/observation` and
`internal/sourceregistry` were previously listed below this line as *not
reachable from `cmd/scamwall`*, and `docs/REQUIREMENTS_MATRIX.md` recorded that
as the reason SW-P3-06 was MISSING: the provenance model existed and nothing
the command could read carried a source. `scamwall propose` closes that.
They are now in the executable, by way of `internal/proposal` and the
`schema_version 2` evidence document.

Two further packages exist in the repository and are **not reachable from
`cmd/scamwall`**:

| Package | Responsibility | Depends on |
| --- | --- | --- |
| `internal/evaluation` | Baseline-versus-candidate measurement over versioned fixtures | domain, feed, observation, policy, proposal, safetext, sourceregistry |
| `internal/repotext` | The repository's own text-integrity control: no tracked text file may carry mojibake or invalid UTF-8 | — |

`go list -deps ./cmd/scamwall` names neither. `internal/evaluation` is a
harness: it measures the rules the executable runs — `internal/policy.Decide`
through `PolicyDetector`, and `internal/proposal.DecideIndicator` through
`ProposalRule` — and calls them rather than restating them, so what it reports
is the shipped rule and not a copy of it. Wiring the harness itself into a
command is a separate, deliberate step that has not been taken.

`internal/repotext` is a different kind of thing and will never be wired in: it
is a GATE, whose only caller is `go test` and therefore `scripts/check.sh`. It
asserts a property of this repository's tracked text and nothing whatever about
the running system. It exists because FINDING-89 destroyed 682 runs of
characters in an authoritative document and every gate the repository had was
blind to it: the damage was still well-formed UTF-8, still valid Markdown, and
in a file no compiler reads.

Dependencies point inward. `internal/domain` has no dependencies on any other
ScamWall package, so its guarantees hold no matter who calls it.
`internal/safetext` likewise: it is the one copy of the escaping and bounding
that `internal/evaluation` and `internal/proposal` both need, and a security
control with two copies has two behaviours the first time one is corrected.

Critically, **`internal/policy` does not import `internal/adapters/pihole`,**
and neither does `internal/proposal`. A plan is a pure function of the feed and
configuration; a proposal is a pure function of four local files. There is no
wiring through which either can reach the Pi-hole client, which is the
structural reason Phase 1 cannot submit one.

`internal/proposal` also does not import `internal/config`. That is deliberate
and is asserted by a test: the configuration file names the Pi-hole host, the
CA and the path to the application password, and opening it is how a command
with no business near a credential acquires a reason to.

**One honest note on the import graph.** `net/http` IS reachable from
`internal/domain`, and therefore from `internal/proposal` and from the
executable — `golang.org/x/net/publicsuffix` implements
`net/http/cookiejar.PublicSuffixList` and so imports it. That has been true
since before ORDER 6. Linking a package is not calling it; what the absence of
a network call rests on is the source-level guard on `cmd/scamwall/propose.go`
and the namespace run recorded in `docs/VERIFICATION.md`, not the import graph.

---

## 3. Command surface

| Command | Network | Purpose |
| --- | --- | --- |
| `scamwall version` | none | Build identity; prints enforcement compile state |
| `scamwall doctor` | TLS handshake + `GET /api/auth` | Preflight: config, CA, secret, DNS pinning, TLS, reachability |
| `scamwall status` | full session | Authenticate, read `/api/info/version`, log out |
| `scamwall validate-feed` | none | Parse, verify signature, enforce bounds, report |
| `scamwall plan` | none | Compute the proposed blocking plan; print it |
| `scamwall propose` | none | Turn a signed evidence document into domain proposals, abstentions and refusals, each with a reason |
| `scamwall sync --dry-run` | full session | Plan + live read + explicit statement that nothing was submitted |

`doctor` deliberately uses the credential-free `GET /api/auth` probe so that
connectivity can be diagnosed without transmitting a password.

### 3.1 `propose`, and why it takes no `-config`

```
scamwall propose --evidence E --signers S --registry R --policy P
                 [--at RFC3339] [--json] [--out FILE]
                 [--max-bytes N] [--max-records N]
```

Every other subcommand begins with `loadConfig`, because every other
subcommand either talks to Pi-hole or reads the feed the deployment is
configured with. This one does neither, so it takes four explicit paths and
**refuses a `-config` flag** rather than accepting and ignoring one — accepting
it would let an operator believe the command had read it.

The consequence is that `propose` runs on a machine with no deployment at all,
which is what makes it reviewable.

**Exit codes**, because two cannot say what happened:

| code | meaning |
| --- | --- |
| 0 | the run completed and every record was admitted as evidence |
| 3 | the run COMPLETED and at least one record was refused. The report is whole; a refusal is an outcome, not a failure |
| 1 | the run did not complete |
| 2 | usage |

`--out` refuses to overwrite an existing file.

**Producing a proposal is not permission to enforce it.** The usage text says
so, and §4 is why it is true rather than merely stated.

---

## 4. Enforcement is absent, not merely disabled

Three independent mechanisms, any one of which is sufficient:

1. **Compile-time.** Enforcement lives behind the `enforce` build tag. The
   default build compiles `enforce_disabled.go`, which sets
   `EnforcementCompiledIn = false` and provides a submitter that returns an
   error. No enforcing implementation exists in the tree at all in Phase 1.
2. **Structural.** `internal/policy` cannot reach `internal/adapters/pihole`.
   The Pi-hole client exposes no exported method that performs a write.
3. **Runtime.** `--dry-run` defaults to `true`. Passing `--dry-run=false` is
   rejected with a diagnostic, not honoured.

Defence in depth matters here because a single forgotten flag default is a
plausible mistake; three failures at once is not.

---

## 5. Data flow

### 5.1 Feed validation (`validate-feed`, offline)

```
feed.json ──▶ size gate ──▶ JSON decode ──▶ manifest version check
    │                                            │
    │                                            ▼
    │                                   Ed25519 verify over
    │                                   canonical payload bytes
    │                                            │
    ▼                                            ▼
record-count gate                        manifest expiry check
    │                                            │
    └──────────────────┬─────────────────────────┘
                       ▼
        per-record: IDNA normalise → canonical form →
        reject IP literal / localhost / .local / single label /
        wildcard / public suffix / malformed IDN / over-length →
        dedupe + conflict detection → per-record expiry
                       ▼
              validated indicator set
```

Signature verification happens **before** any record is interpreted, and the
signature covers the exact canonical bytes that are later parsed. Verifying a
re-serialised structure would leave room for a parser-differential attack.

### 5.2 Plan computation (`plan`, offline)

Validated indicators are filtered to `action == "block"` **and**
`confidence == "high"`, then sorted into a canonical order. The plan carries a
content digest so two runs over the same feed are provably identical.

Determinism is a security property, not a convenience: an operator must be able
to review a plan and know the reviewed plan is what would be applied.

### 5.3 Live read (`status`, `sync --dry-run`)

```
load CA ──▶ build TLS config (private CA only, ServerName=pi.hole)
   │
   ▼
read secret from /run/secrets/pihole_app_password
   │
   ▼
POST /api/auth ──▶ SID held in memory only
   │                    │
   │                    ▼
   │            GET /api/info/version  (bounded, typed, redacted)
   │                    │
   └────────────────────┴──▶ DELETE /api/auth   ← always, incl. error/cancel
```

The logout is registered immediately after a successful authentication and runs
from a deferred path with its own bounded context, so a cancelled or failed read
still tears the session down rather than leaving it to expire.

---

### 5.4 Proposal computation (`propose`, offline)

```
signers.json ─▶ size gate ─▶ strict decode ─▶ schema v1 ─▶ per-signer:
                                                 key id unique, ed25519 key
                                                 well-formed, at least one
                                                 grant, no wildcard
                                                      │
registry.json ─▶ parse ─▶ Validate(at) ─▶ ANY problem refuses the run ──┤
                                                      │
policy.json  ─▶ size gate ─▶ strict decode ─▶ schema v1 ─▶ threshold present,
                                                 scope stated, every exception
                                                 canonicalised and unique ─────┤
                                                      │
evidence.json ─▶ size gate ─▶ strict decode envelope ─▶ schema v2
                     │
                     ▼
            resolve the key id IN THE AUTHORITY  ← no fallback key
                     │
                     ▼
            Ed25519 verify over the payload bytes
                     │
   ══════════════ everything below is AUTHENTICATED, none of it is TRUSTED ══
                     │
                     ▼
            manifest version, issued/expires, clock skew, record count
                     │
                     ▼
   per record, in this order, and the order is part of the answer:
     1. indicator type known?           → indicator_type_unknown
        indicator type supported?       → indicator_type_unsupported
     2. may this SIGNER assert this SOURCE?
                                        → signer_not_authorised_for_source
        (asked BEFORE the registry, so a refusal cannot reveal whether the
         operator's registry holds that source)
     3. registry: present? retired?     → source_not_in_registry
                                          source_retired
     4. domain.Assess → canonical form  → record_value_invalid  (SYNTAX only)
     5. rights: local_storage           → source_rights_refuse_local_storage
     6. raw retention                   → dropped and REPORTED, or
                                          record_invalid for an invented value
     7. observation.Store.Add           → new | correction | duplicate
                     │
                     ▼
   per indicator, in this order:
     1. rights: enrichment, derived_output   → REFUSE
     2. the household's exception            → REFUSE (user_exception)
     3. anything live at `at`?                → PASS-equivalent abstentions:
                                                 expired_only, withdrawn_only,
                                                 no_live_evidence
     4. sources conflict?                     → ABSTAIN (sources_conflict)
     5. invisible_character / mixed_script    → ABSTAIN (name_requires_review)
     6. adverse independent sources ≥ policy  → PROPOSE, at the policy's scope
                                                else insufficient_independent_support
                     │
                     ▼
            report, binding: evidence bytes, signer grant, registry,
            policy, evaluation instant, semantics version
```

Nothing above has a code path to a network client, a credential or a Pi-hole
session, and every input is a path the operator named. **What is measured is
that the command completes no network operation** — byte-identical output
inside an empty network namespace, with `scamwall status` failing there as the
control. **That no socket was ATTEMPTED is not established**; a `connect()`
that failed and was ignored would look identical. `docs/VERIFICATION.md`
§4.41.6 lists the three commands that would settle it, none of which is
available on the machine this was measured on.

**A refused record is REPORTED, never dropped.** A document quietly losing half
its records is the failure mode the third exit code and the refusal list exist
to make visible.

**Matching is over labels.** Both sides of every comparison are canonical forms
from `internal/domain`, and the separator is required to be part of the match:
`strings.HasSuffix("notbad.example.com", "bad.example.com")` is true and
`notbad.example.com` is somebody else's domain. `scope: subdomains` reaches
every name strictly beneath a name and NOT the name itself, so the two scopes
compose and an operator who wants both writes both.

---

## 6. The Pi-hole client

Hardening properties, all enforced in `internal/adapters/pihole`:

| Property | Mechanism |
| --- | --- |
| HTTPS only | Scheme checked before dial; `http` rejected |
| Private CA only | `tls.Config.RootCAs` set to a pool containing only the configured CA; system roots never loaded |
| Hostname verified | `ServerName` fixed to the configured API host, independent of dialled address |
| No verification bypass | `InsecureSkipVerify` never set; asserted by a unit test that greps the package |
| Address pinning | Custom `DialContext` maps the API host to a configured address — resolution override only, never a verification change |
| Bounded bodies | `io.LimitReader` with a hard cap; overflow is an error, not a truncation |
| Content-type gate | `application/json` required before decode |
| Strict timeouts | Per-request deadline plus overall client timeout |
| Context cancellation | Every request carries a context; cancellation is honoured |
| Bounded retries | Only for idempotent reads; capped attempts, exponential backoff with jitter; never for `POST /api/auth` |
| Redirect policy | Cross-origin redirects refused |
| Redacted errors | Errors carry status and endpoint, never bodies, headers, or credentials |

Retrying authentication would be actively harmful: the API rate-limits login
and returns `429 no_seats` when the session table is full, so a retry storm
could lock out legitimate operators.

---

## 7. Secret handling

The application password is read **only** from
`/run/secrets/pihole_app_password`, mounted read-only into the container.

* It is never placed in configuration files, environment variables, or flags.
* It is held in a `Secret` type whose `String()`, `GoString()`, `Format()`, and
  `MarshalJSON()` all return `"[REDACTED]"`, so it cannot be leaked by an
  accidental `%v` or a JSON dump.
* Its plaintext is reachable only through an explicit `Reveal()` call, which
  appears in exactly two places, both of them the point at which a credential
  is placed on the wire: the auth request body and the `X-FTL-SID` header. A
  test enforces that count.
* It is zeroed after the authentication request is constructed.

The session ID receives the same `Secret` treatment.

---

## 8. Audit logging

`internal/audit` emits structured JSON to stdout. Redaction is applied by the
logger itself rather than trusted to call sites, because a call-site-only
discipline fails silently the first time someone forgets.

Denylisted keys (`password`, `sid`, `csrf`, `authorization`, `x-ftl-sid`,
`token`, `secret`, …) are replaced with `[REDACTED]` regardless of value, and
values carrying the `Secret` type are redacted structurally. Request and
response bodies are never logged at any level.

---

## 9. Container model

Single static binary in a minimal final stage. No shell, no package manager, no
interpreter. Runs as a fixed non-root UID/GID with a read-only root filesystem,
all capabilities dropped, `no-new-privileges`, `tmpfs` on `/tmp` with
`noexec,nosuid,nodev`, bounded memory/PID/CPU/log size, no published ports, no
host networking, and no Docker socket.

`pi.hole` is pinned via `extra_hosts` because DNS in this environment resolves
that name to a different device. See `docs/SECURITY_BOUNDARIES.md`.

---

## 10. Phase 1 non-goals

Explicitly out of scope: any Pi-hole mutation, third-party feed downloads,
enforcement, rollback, scheduling, persistent state, metrics export, telemetry,
and multi-instance orchestration.
