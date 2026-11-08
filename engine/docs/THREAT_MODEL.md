# ScamWall Threat Model (Phase 1)

Scope: the Phase 1 read-only, dry-run vertical slice. Enforcement, third-party
feed ingestion, and persistent state are out of scope and are modelled in
Phase 2.

---

## 1. Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Pi-hole application password | Grants full API access, including mutation | `/etc/scamwall/secrets/...` on host; `/run/secrets/...` read-only in container; process memory |
| Pi-hole session ID (SID) | Bearer credential for the session lifetime | Process memory only |
| Pi-hole private CA | Trust anchor for the API connection | `/etc/scamwall/certs/pihole-ca.crt`, read-only |
| Feed trust public key | Determines which feeds are accepted | Configuration; committed |
| DNS availability | Losing it breaks the whole network | Pi-hole, which ScamWall must never disturb |
| Pi-hole blocklist integrity | Wrongly blocking a bank or hospital domain is a real harm | Pi-hole database, untouched in Phase 1 |
| Operator trust in the plan | Enforcement decisions rest on reviewed plans | Plan output |

The last asset is easy to overlook. If a plan is not reproducible, review is
theatre — so plan determinism is treated as a security control.

---

## 2. Trust boundaries

```
   Internet ─────────────╳──────────  (no ScamWall egress in Phase 1)

   ┌──────────── host ────────────────────────────────────────────┐
   │                                                              │
   │  root ──── B1 ────▶ /etc/scamwall/{certs,secrets}            │
   │                            │ read-only bind                  │
   │                            ▼                                 │
   │  ┌─────── container (uid≠0, ro rootfs, cap_drop ALL) ──────┐  │
   │  │  ScamWall process                                       │  │
   │  └─────────────────────────────────────────────────────────┘  │
   │                            │ B2: TLS, private CA, SAN pi.hole │
   │                            ▼                                  │
   │  Pi-hole FTL :443 ◀── B3: authenticated API surface           │
   └───────────────────────────────────────────────────────────────┘
                                ▲
                                │ B4: LAN — other devices, incl. the
                                     appliance that answers DNS "pi.hole"
```

* **B1 — host filesystem &rarr; container.** Crossed only by three read-only
  mounts: CA, secret, config. Anything else is a boundary violation.
* **B2 — container &rarr; Pi-hole over TLS.** The only network crossing. Trust is
  the private CA alone; system roots are not consulted.
* **B3 — API authorisation.** Pi-hole, not ScamWall, is the authority. ScamWall's
  self-restriction to reads is defence in depth, not the control.
* **B4 — the LAN.** Untrusted. Notably, DNS for `pi.hole` here answers with a
  different device (see `SECURITY_BOUNDARIES.md` §4).
* **B5 — a signed EVIDENCE document, and the operator files that admit it.**
  Added at ORDER 6, and it does not cross the diagram above at all: every one
  of its four inputs is a local path the operator names, nothing is fetched,
  and `scamwall propose` constructs no Pi-hole client and opens no
  configuration file. See §4.6.

---

## 2.1 Authenticated is not trusted (B5)

A verified signature establishes that the holder of a key the operator
recorded produced the bytes. That is the whole of what it establishes, and the
three mistakes available at this boundary are all forms of forgetting it.

| the claim | why it is not believed |
| --- | --- |
| `source_id` — who observed this | A signature over a source id is not authority over that source. The id is a field INSIDE the signed payload, so a signer free to write any id could assert one indicator under three source ids and collect three independent votes for it. Authority is the OPERATOR's statement, in `signers.json`, enforced per record, with no wildcard spelling |
| `classification`, `state`, `provider_confidence`, `category` | The provider's opinion, carried verbatim, mapped into a closed vocabulary, never fused into a ScamWall score. There is no ScamWall confidence, by design |
| `expires_at`, `first_seen`, `last_seen` | The provider's own window. Impossible orderings are refused; a plausible ordering is still only a claim |
| `source_record_id` | Load-bearing for corrections, and therefore exactly the field an adversary would use to withdraw somebody else's evidence. Scoped to `(source_id, source_record_id)` and never to the record id alone |

Everything above is attacker-controlled **unconditionally** before the
signature is checked — the file's length, its nesting, its key names, its
envelope fields — and attacker-controlled **if the signing key is compromised**
afterwards. Bounds and escaping therefore apply to both halves, not only to the
first.

---

## 3. Adversaries

| Adversary | Capability | Motivation |
| --- | --- | --- |
| A1 — Malicious/compromised feed publisher | Controls feed contents; may hold a signing key | Block a competitor, cause a DoS, poison the plan |
| A2 — Network attacker on the LAN | Spoof DNS/ARP, impersonate `pi.hole`, MITM | Harvest the application password |
| A3 — Compromised ScamWall container | Arbitrary code execution as the container user | Escalate to host or to Pi-hole mutation |
| A4 — Malicious dependency | Code execution at build or run time | Supply-chain compromise |
| A5 — Local unprivileged host user | Read world-readable files, inspect processes | Harvest credentials |
| A6 — Careless operator (non-malicious) | Misconfiguration, copy-paste of unsafe commands | — |

A6 is included deliberately. Most real incidents in a homelab are
self-inflicted, and a design that only resists malice is fragile.

---

## 4. Threats and mitigations

### 4.1 A2 — Impersonating Pi-hole to steal the password

**This is the highest-severity network threat**, and this environment is already
in the precondition state: the name `pi.hole` resolves to a device that is not
Pi-hole.

| Attack | Mitigation |
| --- | --- |
| DNS spoofing / rogue responder for `pi.hole` | `extra_hosts` pins the name to a fixed address; DNS is not consulted |
| Presenting any publicly-trusted certificate | Trust pool contains **only** the Pi-hole private CA; system roots never loaded |
| Presenting a cert for another name | `ServerName` fixed to `pi.hole`; SAN must match |
| Downgrade to plaintext | `http` refused before dialling; TLS 1.2 floor |
| Redirect to an attacker origin | Cross-origin redirects refused |
| Operator "fixes" a TLS error with `-k` | Documented as prohibited; no bypass flag exists in the binary; asserted by test |

The last row is the one that actually bites in practice. A TLS error is a
finding, not an obstacle — the design deliberately offers no escape hatch,
because an escape hatch that exists will eventually be used.

### 4.2 A1 — Malicious or compromised feed

| Attack | Mitigation |
| --- | --- |
| Unsigned or altered feed | Ed25519 signature verified over canonical bytes before parsing |
| Signature over re-serialised data (parser differential) | Signature covers the exact on-disk payload bytes |
| Replay of an old feed | Manifest `issued_at`/`expires_at`; expired manifests rejected |
| Stale indicators inside a fresh manifest | Per-record expiry enforced independently |
| Feed bloat &rarr; memory exhaustion | Hard caps on file size and record count, enforced before decode |
| Blocking a public suffix (`com`, `co.uk`) | Public-suffix entries rejected |
| Wildcards to over-block | Wildcard entries rejected; exact domains only |
| IDN homograph confusion | IDNA normalisation to a single canonical lowercase form |
| Duplicate/conflicting records | Rejected, not silently resolved |
| Low-confidence noise reaching a plan | Only `high` confidence + `block` action enter a plan |
| Blocking critical infrastructure | Plans are reviewable, deterministic, and never auto-applied in Phase 1 |

A signed feed is still an *untrusted* feed. Signing proves origin, not
correctness — so bounds and sanity rules apply to signed feeds too.

### 4.3 A3 — Compromised container

| Goal | Mitigation |
| --- | --- |
| Escape to host | No privileged mode, no host networking, no Docker socket, all capabilities dropped |
| Gain privileges | `no-new-privileges:true`; non-root UID; no setuid binaries in the image |
| Persist | Read-only root filesystem; `/tmp` is `tmpfs` with `noexec,nosuid,nodev` |
| Read host files | Only three read-only mounts; `/etc/pihole` never mounted |
| Pivot to other hosts | No published ports; egress limited to the Pi-hole API |
| **Mutate Pi-hole with the stolen password** | **Not mitigated — see §6** |

### 4.4 A4 — Supply chain

| Attack | Mitigation |
| --- | --- |
| Malicious module | Minimal dependency surface; `go.sum` pinning; `govulncheck` |
| Base-image substitution | Base images pinned by digest, not tag |
| Build-time secret capture | Secrets never enter the build context; `.dockerignore` excludes them |
| Secrets baked into layers | Multi-stage build; final stage carries only the binary and CA trust files |

### 4.5 A5 / A6 — Local users and operator error

| Attack | Mitigation |
| --- | --- |
| Reading the secret file | `0640` with a dedicated group; never world-readable |
| Secret in `ps` output | Never passed as an argument or environment variable |
| Secret in logs | `Secret` type redacts on every formatting path; logger denylists keys |
| Secret committed to a **public** repo | Deny-by-default `.gitignore`; pre-commit secret scan |
| Accidental enforcement | Dry-run is the immutable default; enforcement not compiled |
| Operating on the wrong directory | Binary refuses to run outside its expected root |

---

### 4.6 A1 (extended) — a signed evidence document

Same adversary as §4.2, a different document, and one new capability: the
ability to attribute what it says to somebody else.

| Attack | Mitigation |
| --- | --- |
| Assert one indicator under three source ids and collect three independent votes for it | The OPERATOR records which source ids a signer may assert (`asserts_source_ids`) or aggregate (`aggregator_for`). No wildcard spelling exists, and a record outside its signer's authority is refused and reported |
| Hold `aggregator_for` over several sources and satisfy `min_independent_sources` single-handed | A claim that reached this build only by republication is evidence and is NOT independent confirmation: it is reported and does not count towards the threshold. One signer republishing two upstreams in one document is one attestation (FINDING-122). `accept_unestablished_independence` does not open this door either |
| Sign with a key the operator has not recorded | The key to verify with comes from the authority document and nowhere else. There is no fallback key |
| Substitute a different key while keeping a recorded key id | The recorded key is the one used; the signature fails |
| Tamper with the payload after signing | Ed25519 over the payload bytes as they appear in the file |
| Append a second document after the signed one | Refused; a strict decode requires exactly one value |
| Rewrite a record after verification, in a caller that holds the validated value | A digest over the records and the signer's grant is taken the instant validation finishes and re-checked by the consumer (FINDING-119). The report would otherwise bind the original bytes while reporting something they do not say |
| Attribute a record to a source that does not exist, or to one deliberately retired | Refused, with **different** reason codes: "no such source" and "a source that was taken out of service" lead somewhere different |
| Probe the operator's registry through the difference between two refusals | Signer authority is checked BEFORE the registry, so a signer with no authority over a source cannot learn whether that source is in the registry |
| Claim an indicator type this build cannot act on | Refused; known-but-unsupported and unknown are separate codes |
| Destroy a whole document with one malformed record | Only integrity, signature and structural failures refuse the document. A malformed VALUE refuses that record — the defect at `7e11419`, kept fixed in a new path |
| Smuggle one source id past the authority check as another | Whole-string comparison. Trailing space, NUL, case, zero-width space, an embedded newline and path traversal were all measured and all resolve to authority `none` |
| Ship the provider's raw response and have it retained without a grant | `raw_retention` defaults to `none`; raw sent anyway is dropped and the drop reported. `retained` is honoured only when the source's registry record authorises `local_storage` |
| Launder one source's prohibition through a derived result | Unanimity over live contributors: one contributing source's refusal of `enrichment` or `derived_output` refuses the whole indicator |
| Terminal escapes, bidi overrides, forged log lines, invalid UTF-8 in any reported field | `internal/safetext` escapes and bounds every caller-controlled field on the way into text and JSON alike |
| Inflate a report with volume | The file, the record count, every individual explanation and every echoed identifier are bounded. A refused record is still REPORTED, because a document quietly losing half its records is the failure this is meant to make visible |
| Reach the network or a credential through the new command | It takes no `-config` flag and refuses one, and imports neither `internal/config` nor the Pi-hole adapter. It is measured to COMPLETE no network operation; that it opens no socket is **not** established. See §6 residual risk 7 for exactly what the evidence supports |

**What none of this establishes.** That any claim in an admitted document is
true. A verified signature is authenticity only; source attribution is what
the document CLAIMS, admitted because the operator granted that signer
authority over that source id. It is not independent confirmation that the
named source observed anything, and no part of ScamWall treats it as one.

---
## 5. Explicitly out of scope

Physical access; a compromised Pi-hole host (it is the trust anchor —
if it is compromised, ScamWall's guarantees are moot); a malicious Go toolchain
or kernel; and denial of service against Pi-hole itself.

---

## 6. Residual risks

Stated plainly, because unstated residual risk is the dangerous kind.

1. **Credential theft grants mutation.** ScamWall cannot mutate Pi-hole, but an
   attacker who steals the application password from ScamWall's memory or mount
   can call mutating endpoints directly. ScamWall's read-only design constrains
   *ScamWall*, not an attacker holding its credential. Mitigate by scoping the
   application password as narrowly as Pi-hole permits and rotating it on any
   suspicion of compromise. **This is the top residual risk of Phase 1.**

2. **The CA is a self-signed root with a short validity window**
   (2026-09-05 &rarr; 2026-10-22). Expiry causes a hard, correct failure. The
   operational hazard is that renewal pressure invites someone to disable
   verification. Rotation must be a documented procedure before Phase 2.

3. **`pi.hole` resolves to a foreign device on this network.** ScamWall is
   insulated by address pinning, but every *other* consumer of that name on this
   network is not. This warrants independent investigation.

4. **No feed revocation.** A feed signing key cannot be revoked in Phase 1;
   trust is a static configured key. Compromise requires manual reconfiguration.

5. **Session seats are finite.** Repeated crashes between authentication and
   logout could exhaust Pi-hole session seats (`429 no_seats`). Mitigated by
   always-attempted bounded logout, but not eliminated.

6. **Unverified live authentication.** The authenticated path has been proven
   only against a fake server, because the secret is not yet readable. Until it
   runs live, a divergence in the authenticated surface remains possible —
   assessed as low risk, since the unauthenticated surface matched the
   specification exactly.

7. **"No network" is asserted by construction, not observed at the syscall
   level.** `scamwall propose` takes no configuration, imports neither
   `internal/config` nor the Pi-hole adapter, and completes with byte-identical
   output inside an empty network namespace (`unshare -rn`) — with `status`, in
   the same namespace, failing as the positive control that makes the namespace
   mean anything. That does NOT establish that no socket was opened: a
   `connect()` that failed and was ignored would look exactly the same. A
   syscall trace or a runtime with no network device would settle it; `strace`,
   `ltrace`, `bwrap` and `firejail` are absent on the machine this was measured
   on and Docker is operator-executed. The exact missing evidence is recorded in
   `docs/VERIFICATION.md` rather than approximated.

   Note also that `net/http` IS linked into the executable — it always has been:
   `golang.org/x/net/publicsuffix` implements `net/http/cookiejar.PublicSuffixList`
   and `internal/domain` uses the suffix list. Linking a package is not calling
   it, and the import graph is therefore not the control.
