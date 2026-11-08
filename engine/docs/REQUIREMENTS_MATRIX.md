# ScamWall Requirements Matrix

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

This is the single source of truth for **what ScamWall must do** and **whether
that has been proven**. `docs/IMPLEMENTATION_PLAN.md` says how and in what
order; `docs/VERIFICATION.md` records the evidence each row points at.

Where an earlier document already states a fact in detail — the API contract,
the threat model, the security boundaries — this matrix links to it rather than
restating it. Restating creates two truths that drift.

---

## 1. How to read this document

### 1.1 Requirement IDs

`SW-P<phase>-<nn>`. IDs are **stable**: once assigned they are never reused,
renumbered, or recycled. A requirement that is dropped is marked `WITHDRAWN`
and kept, so that evidence referencing it stays resolvable.

### 1.2 Status vocabulary

Exactly one of:

| Status | Meaning |
| --- | --- |
| `VERIFIED` | Implemented **and** the required evidence has been produced and recorded in `docs/VERIFICATION.md`, tied to a specific commit. |
| `IMPLEMENTED-UNVERIFIED` | The code exists and is believed correct, but the required evidence has not been produced, or was produced against a superseded commit. |
| `MISSING` | Not implemented. |
| `BLOCKED` | Cannot be verified from this account or in this environment. The blocker and the exact operator command are recorded. |
| `WITHDRAWN` | Deliberately dropped. Retained for ID stability. |

`IMPLEMENTED-UNVERIFIED` is not a soft `VERIFIED`. A requirement whose evidence
predates a change to the code, dependencies, configuration, or artifacts it
covers is **demoted back** to `IMPLEMENTED-UNVERIFIED` until the evidence is
renewed. See §5.

### 1.3 What "evidence" means here

Evidence is a reproducible observation tied to an identity:

* the **source commit** the observation was made against;
* the **tool versions** that made it;
* where a container is involved, the **image ID** (not the tag);
* where configuration is involved, the **configuration identity**.

A conversational claim that something worked is *history*, not evidence. Rows
that rest on such claims are marked `IMPLEMENTED-UNVERIFIED` and say so.

---

## 2. Baseline

| Item | Value |
| --- | --- |
| Branch | `feat/phase-1-core` |
| Session baseline | `2edb95a` — *fix(verify): rebuild runtime verification around checked operations* (tree `546ad23`) |
| Evidence commit | `aa49797` — *fix(ci): supply the deployment's fixtures, and check the mount sources*. The last commit that changes a gate input |
| **Verified image** | source `c35b1e601f2543cb666d34888c61b08406446106`, image `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`, built by the operator on the deployment's host in `docs/VERIFICATION.md` §6.5 step A: build exit 0 with both in-build assertions executed **uncached**, the binary reporting the expected commit and enforcement absent, verifier 95 passed / 0 failed / 0 blocked / 0 cleanup problems, and a clean close-out. Evidence: `docs/VERIFICATION.md` §3.22. It carries **SW-P1-05 and SW-P1-20**. It is a deployable artifact for this household — built from this deployment's configuration — but deploying it is not authorised by that record |
| Previous verified image | source `b6b1769151501d89d7f8550d2c8f3378d0e73c3d`, image `sha256:b95cc07ca564b115f8bf2d49d642efafc99ae8ff4ae7746caaa7d2ff5e00516b`, build exit 0 with both in-build assertions executed, verifier 90 passed / 0 failed / 0 blocked / 0 cleanup problems, `VERIFY exit=0`. Evidence: `docs/VERIFICATION.md` §3.7. **Lapsed at `aa49797`**, and superseded at `c35b1e6`. Retained as an identity on record and as the evidence §3.7 describes |
| **CI-built image** | source `72bc84c13f4e6914bfb015e87d46a5234e8f5234`, image `sha256:d7c44949d56d4f609b3f184464521a2d95c6b34e628f69fd5b145ad6104bba07`, built on the runner in the passing run 34047025567: build exit 0 with both in-build assertions executed, and `container runtime verification` PASSED against CI's own fixtures. Evidence: `docs/VERIFICATION.md` §3.12. It **carried SW-P1-20** between `72bc84c` and `7e11419`, that row being about the executable; it never carried SW-P1-05, which is about this deployment's settings. Both rows are now bound to the operator-built image above, and §3.12 keeps its own evidence intact for the artifact it names. Not a deployable artifact for this household: it was built from a clean checkout with no `.env` |
| Previous evidence commit | `b6b1769` — *fix(verify): check list processing, name scope, mounts, numbers and fields*. `ef40156`/`aa49797` changed `scripts/*.sh`, `compose.yaml` and the workflow, which demotes the rows §5 names; the script-bound rows were re-run and renewed at `aa49797`, the image-bound ones were not and cannot be from the service account |
| Superseded evidence commit | `0b083cb` — *fix(verify): attribute resources and complete the runtime assertions*. `b6b1769` changed `scripts/*.sh`, which demotes the rows §5 names; those were re-run and renewed |
| Superseded candidate image | source `b469c592ca756b82bc2eb18ee4cdcb42b9458a0c`, image `sha256:d3c4ed2c91250448044e1f1eb4e8d0d04591ba10237b3c56e5effc55f7e2251f`, build exit 0. **No verifier was ever run against this image**, and it predates all seventeen findings in `docs/VERIFICATION.md` §4.7 and §4.8. Retained as an identity on record for ID stability; it is not evidence and must not be deployed |
| Previous working candidate | `7e1141997cc1f7484144f07c1fb05cde5d39e280`. Implementation and local verification only: not pushed, not built, not deployed. It changes Go source, `scripts/*.sh` and `.github/workflows/gates.yml`, so §5 demotes the rows named in §3 below. `docs/VERIFICATION.md` §3.14 |
| Previous working candidate | `9ebb98c590fe96628c486d83b66a3b9c87608b85`. Correction and local verification only: not pushed, not built, not deployed. It changes Go source (`cmd/scamwall/main.go`, `internal/adapters/pihole/client.go`), `scripts/check.sh`, `scripts/container-runtime-verify.sh`, a new `scripts/lib/docker-resources.sh`, a new `scripts/operator-handoff.sh` and a comment in `container/Dockerfile`. `docs/VERIFICATION.md` §3.15 |
| Previous working candidate | `5af270d8ae36b1f60832f4edf26b71df2eee4945`. Defect correction and local verification only: not pushed, not built, not deployed. It changes `scripts/check.sh`, `scripts/gate-diagnostics.sh`, `scripts/operator-handoff.sh`, the **tracked file mode** of `scripts/container-runtime-verify.sh`, two test files, and adds `scripts/tests/entrypoint-mode-test.sh`, so §5 demotes the script-bound rows again. It changes **no Go source**, so the Go-path rows established at `9ebb98c` and `7e11419` stand. It does **not** change `.github/workflows/gates.yml`. `docs/VERIFICATION.md` §3.16, §4.14 |
| Previous working candidate | `76f3bfd3ebc647ba21dd281fc2b5a3c48435b8d7`. ORDER 1: defect correction and local verification only — not pushed, not built, not deployed. It changes `scripts/operator-handoff.sh` and `scripts/tests/operator-handoff-test.sh` and nothing else, so §5 demotes the script-bound rows again; the suite was re-run on the clean committed tree to renew them. It changes **no Go source**, no Dockerfile, no Compose definition and no workflow, so the Go-path rows established at `9ebb98c` and `7e11419` stand. `docs/VERIFICATION.md` §3.17, §4.15 |
| Previous working candidate | `04e7ea4e8e85c39cf60d6786021ce3cc7562e904`. ORDER 1 review response: defect correction and local verification only — not pushed, not built, not deployed. It changes `scripts/operator-handoff.sh` and `scripts/tests/operator-handoff-test.sh` and nothing else, so §5 demotes the script-bound rows again; the suite was re-run on the clean committed tree to renew them. It changes **no Go source**, no Dockerfile, no Compose definition and no workflow, so the Go-path rows established at `9ebb98c` and `7e11419` stand. One gate does **not** pass on this tree: `go test -race ./...` fails about 8% of runs on a pre-existing coincidence in `cmd/scamwall/e2e_test.go` that this session did not introduce and deliberately did not fix at the time; it was fixed afterwards at `ff2e734` on the reviewer's instruction — FINDING-60. `docs/VERIFICATION.md` §3.18, §3.19, §4.16 |
| Previous working candidate | `ff2e7349ad49005d9ec889d9ee276e2b358a7660`. FINDING-60: defect correction and local verification only — not pushed, not built, not deployed. It changes `cmd/scamwall/e2e_test.go` and nothing else. That is Go source under `cmd/`, so §5 applies — but it is a `_test.go` file, so it is not compiled into any binary, the executable is byte-identical to the one at `222e903`, and **no image-bound row moves**. No row's Source field lists that file, so the demotion the rule produces is SW-P1-13 alone, renewed by the gate run recorded in `docs/VERIFICATION.md` §3.19. With this the gate suite has **no failing gate** on the tree. `docs/VERIFICATION.md` §3.19, §4.16 |
| Previous working candidate | `6bb33bfe78374d41738416af78c76db131e6151d`. ORDER 2, architecture half: local implementation and verification only — not pushed, not built, not deployed. It adds `internal/sourceregistry` (new Go package, 80 cases) and `docs/source-registry.json`, and revises `docs/SOURCE_REGISTRY.md`. That is Go source under `internal/`, so §5 applies; no existing row's Source field lists the new file, so the demotion is SW-P1-13 alone, renewed by the gate run in `docs/VERIFICATION.md` §3.20. It is **not** on the critical Go path — nothing in `cmd/` or the credential, network or enforcement paths references it — so SW-P1-10 is untouched. No Dockerfile, Compose definition or workflow changed, and no image-bound row moves. Gate suite: 26 passed, 0 failed, 2 BLOCKED. **ORDER 2 is not accepted**: the 85-entry catalog is absent from this repository, so no source has been researched and the registry holds zero records. `docs/VERIFICATION.md` §3.20, §4.17 |
| Previous working candidate | `e8f86834de2d9f696b37e8c4a9479d751bbe9c89`. ORDER 2 §3, the registry safety model: local implementation and verification only — not pushed, not built, not deployed. It changes `internal/sourceregistry` (five source files, two test files, 105 cases) and `docs/`, and adds `docs/EVALUATION_PROTOCOL.md`. Go source under `internal/`, so §5 applies; no existing row's Source field lists these files, so the demotion is SW-P1-13 alone, renewed by the gate run in `docs/VERIFICATION.md` §3.21. **Not on the critical Go path** — nothing in `cmd/` or the credential, network or enforcement paths references it — so SW-P1-10 is untouched. No Dockerfile, Compose definition or workflow changed; no image-bound row moves. Gate suite: 26 passed, 0 failed, 2 BLOCKED, CHECK exit=1. **ORDER 2 is not accepted**: acceptance needs all 85 catalog entries to carry a disposition and **zero do**, the catalog being absent from this repository. `docs/VERIFICATION.md` §3.21, §4.18 |
| Previous working candidate | `c35b1e601f2543cb666d34888c61b08406446106`. Documentation only: it changes `docs/` and nothing else, so it changes no gate input and the suites of `docs/VERIFICATION.md` §3.21 are this tree's. **Not pushed. Built and verified by the operator, and not deployed** — `docs/VERIFICATION.md` §6.5 preflight, step A and close-out were run against it, producing image `sha256:0efff150…` and closing SW-P1-05 and SW-P1-20 (`docs/VERIFICATION.md` §3.22). Steps B, C and D were not run; no credential was opened and no request reached the household appliance. ORDER 2 remains not accepted, for the reason in the row above |
| Previous working candidate | `9bbf284` — *feat(registry): put the catalog in the repository, and qualify all 85 entries* — plus the documentation commit that records it. Local implementation and research only: **not pushed, not built, not deployed.** It adds `docs/SOURCE_CATALOG.md`, takes `docs/source-registry.json` from 0 records to 85, and changes `internal/sourceregistry` (`registry.go` and `registry_test.go`). Go source under `internal/`, so §5 applies; **no existing row's Source field names those files**, so the demotion is SW-P1-13 alone, renewed by the gate run in `docs/VERIFICATION.md` §3.24. `go list -deps ./cmd/scamwall` does **not** contain `sourceregistry`, so the executable is byte-identical, **SW-P1-10 is untouched, and no image-bound row moves** — SW-P1-05 and SW-P1-20 stay VERIFIED on image `sha256:0efff150…`. No `scripts/*.sh`, Dockerfile, Compose definition or workflow changed. **ORDER 2's catalog blocker is discharged**: all 85 entries carry a record with a disposition and a research basis, 11 of them naming a specific access blocker. Nothing is enabled and no record claims `verified-available` |
| **Working candidate** | `87bdfafcb9f1690b567f966b677afe965c08af48` — *fix(test): stop the handoff suite asserting one household's deployment values*. **Pushed, with the operator's approval, and verified by two hosted runs.** It changes `scripts/tests/operator-handoff-test.sh` and nothing else: no Go source, no Dockerfile, no Compose definition, no workflow. §5 demotes the script-bound rows, renewed by the local gate run at this commit (26 passed, 0 failed, 2 BLOCKED) and by hosted run 34394790484 (**28 passed, 0 failed, 0 BLOCKED**). **SW-P1-12 closes here** — `docs/VERIFICATION.md` §3.25. Whether SW-P1-05 is also demoted was contested and is now **settled: it is not**, because the change touches no input that row's evidence was produced from — §5.1, and the analysis at `docs/VERIFICATION.md` §3.28. Not built by the operator, not deployed; the CI-built image `sha256:3143d699…` is the runner's and is not a deployable artifact for this household |
| **ORDER 5 candidate** | `9cf5f106af5e712cac5e058910565eabda1f7710` — the indicator core. Local implementation and verification only: **not pushed, not built, not deployed.** Five commits: `18d7e0f` (normalisation — FINDING-82, FINDING-83), `0fcc2d9` (`internal/observation`), `2797da8` (`internal/evaluation`), `cd370a0` (the adversarial pass — FINDING-85, 86, 87), `9cf5f10` (FINDING-88). It changes `internal/domain`, `internal/feed`, `internal/policy` and `internal/sourceregistry`, and adds `internal/observation` and `internal/evaluation`. **`internal/domain`, `internal/feed` and `internal/policy` are on `go list -deps ./cmd/scamwall`, so the executable differs and SW-P1-05 and SW-P1-20 are demoted** — §5, and the trace at `docs/VERIFICATION.md` §3.37. The historical evidence for image `sha256:0efff150…` at source `c35b1e6` remains valid **for that artifact** and is not withdrawn. No `scripts/*.sh`, Dockerfile, Compose definition or workflow changed, and all seven shell suites pass at identical case counts, so no script-bound row moves. Go test cases 557 → 702. Gate suite: 26 passed, 0 failed, 2 BLOCKED, CHECK exit=1. **Nothing was enabled, no source disposition changed, no provider was contacted and no external data was fetched.** `docs/VERIFICATION.md` §3.35–§3.37, §4.35, §4.36 |
| **ORDER 5 REVIEW CORRECTIONS candidate** | `0ff221c3d1a2f535e52275b9967c03ad9af725f1` — the review corrections. Local correction and verification only: **not pushed, not built, not deployed.** Eleven commits from `3152485`: `8c9dc4a` (FINDING-89, the document encoding and the gate that sees it), `fafa405` (FINDING-90, 91), `a013380` (FINDING-92), `c4afba9` (FINDING-93, 94), `52d99a5` (FINDING-95, 96), `cdc5e31` (FINDING-97 … 101), `ae77ba4` (FINDING-102), `1f300c8` (FINDING-103), `748ba98` (FINDING-104), `288addb` (FINDING-105, 106, 107), `0ff221c` (staticcheck in this pass's own tests). It repairs `docs/REQUIREMENTS_MATRIX.md`, changes `internal/evaluation`, `internal/observation` and `internal/sourceregistry`, adds `internal/repotext`, and changes one test file in `internal/domain`. **No compiled input of `./cmd/scamwall` changed: built with `-buildvcs=false` the executable is byte-identical to the one at `3152485`, SHA-256 `15fabb9e…`** — `docs/VERIFICATION.md` §3.38. **SW-P1-05, SW-P1-12 and SW-P1-20 therefore do not move and stay IMPLEMENTED-UNVERIFIED**; they were demoted at `9cf5f10` and only §6.5 step A and an approved push renew them. No `scripts/*.sh`, Dockerfile, Compose definition or workflow changed, and all seven shell suites pass at identical case counts, so no script-bound row moves. Go test cases 702 → 879. Gate suite: 26 passed, 0 failed, 2 BLOCKED, CHECK exit=1. **Nothing was enabled, no source disposition changed, no provider was contacted and no external data was fetched.** `docs/VERIFICATION.md` §3.38, §4.37 |
| **ORDER 7 candidate** | see `docs/VERIFICATION.md` §3.41 — correcting the offline proposal boundary. Local correction and verification only: **not pushed, not built, not deployed.** Ten findings in the surface ORDER 6 built (FINDING-120 … FINDING-129), **nine corrected and FINDING-128 left OPEN**. It changes `internal/proposal`, `internal/feed`, `cmd/scamwall` and adds `internal/strictjson`. **No row is promoted**; SW-P1-10's evidence is renewed with **three of its dispositions revised**, and SW-P1-13 and SW-P1-15 are renewed on this tree. The compiled input of `./cmd/scamwall` changed again, so the image-bound rows are further from the verified image than before. No `scripts/*.sh`, Dockerfile, Compose definition or workflow changed. **Nothing was enabled, no trust key changed, no provider contacted, no Docker access widened, and no operator rebuild is recommended.** `docs/VERIFICATION.md` §3.41, §4.42, §5.13; matrix §5.6 |
| **ORDER 6 candidate** | `7163a2e9013727bf4d09fb1db5db30acfa161c20` — an offline provenance-to-proposal path. Local implementation and verification only: **not pushed, not built, not deployed.** It corrects seven findings in `internal/evaluation` (FINDING-112 … FINDING-118) and one in `internal/feed` (FINDING-119); adds `internal/safetext`, `internal/feed/evidence.go`, `internal/proposal`, `cmd/scamwall/propose.go` and a `propose` subcommand. **The compiled input of `./cmd/scamwall` CHANGED** — built `-trimpath -buildvcs=false CGO_ENABLED=0` the executable is `228e10a8…` against `15fabb9e…` at `005e06d` — so the image-bound rows are demoted with a demonstrated gap rather than an incidental one. **SW-P3-06 moves MISSING → IMPLEMENTED-UNVERIFIED**, the only status promotion; **SW-P1-10 and SW-P1-15 are demoted from VERIFIED**. No `scripts/*.sh`, Dockerfile, Compose definition or workflow changed. **Nothing was enabled, no source disposition changed, no trust key was changed, no provider was contacted and no external data was fetched.** `docs/VERIFICATION.md` §3.40, §4.41, §5.12; matrix §5.5 |
| **ORDER 5 CORRECTIONS candidate** | `49fab8a67137eff515cb6a317c03af7e57ecebc7` — evidence binding and diagnostic trust. Local correction and verification only: **not pushed, not built, not deployed.** Three commits from `80e4707`: `161d34c` (FINDING-108, 109, 110), `b33bf22` (FINDING-111), `49fab8a` (the test a red-team mutation survived). It changes `internal/evaluation` only — `binding.go`, `fixture.go`, `report.go`, `metrics.go`, `binding_test.go`, and two new test files. **No compiled input of `./cmd/scamwall` changed: built `-trimpath -buildvcs=false` with `CGO_ENABLED=0` the executable is byte-identical to the one at `80e4707`, SHA-256 `15fabb9e…`** — `docs/VERIFICATION.md` §3.39. **SW-P1-05, SW-P1-12 and SW-P1-20 do not move and stay IMPLEMENTED-UNVERIFIED.** SW-P1-13 is renewed on this tree's transcript under an unchanged status; the status itself does not transition. No `scripts/*.sh`, Dockerfile, Compose definition or workflow changed, and all seven shell suites pass at identical case counts — 963 cases, 0 failed. Go test cases 879 → 957. Gate suite: 26 passed, 0 failed, 2 BLOCKED, CHECK exit=1. **Nothing was enabled, no source disposition changed, no provider was contacted and no external data was fetched.** `docs/VERIFICATION.md` §3.39, §4.38 |
| Published commit | `518af51a714747105faec35a9abb639295a7d0d4` — the tip of `origin/feat/phase-1-core`, and the commit hosted run **34396978547** tested: 28 passed, 0 failed, 0 BLOCKED. `docs/VERIFICATION.md` §3.27 |
| Documentation tip | `cc8a568`, `e5f5a64` and the commit carrying this reconciliation. **Not pushed**, documentation only, no gate input changed. The gate results of record are §3.26's local run and the hosted runs above. **The current reconciliation is the ORDER 5 REVIEW CORRECTIONS commit**, whose gate results of record are `docs/VERIFICATION.md` §3.38 |
| Licence | AGPL-3.0-only |
| Current phase | Phase 1 — **accepted**, within the evidence boundaries in §3 and qualified by one pending criterion (`docs/IMPLEMENTATION_PLAN.md` §3.3, `docs/VERIFICATION.md` §3.30). Phase 2 not entered |
| Enforcement | Not compiled in (`policy.EnforcementCompiledIn == false`; no `enforce` build-tag file exists) |

Full baseline detail, including tool versions and the gate transcript, is in
`docs/VERIFICATION.md` §2.

---

## 3. Phase 1 — Trustworthy verification

**Objective.** Establish checks that cannot lie, and an auditable baseline.

The governing rule for this phase: *a check that could not run has proven
nothing.* Every requirement below is written so that the absence of evidence is
visible rather than silently absent.

**Read this before the table: the statuses below are for THIS tree, and Phase 1
is not accepted on it.** Phase 1 *is* accepted, at commit
`c35b1e601f2543cb666d34888c61b08406446106` and image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`,
qualified by §3.3 of `docs/IMPLEMENTATION_PLAN.md`'s pending preservation
criterion. That acceptance is untouched, still names those identities, and is
not relabelled to `HEAD` by anything below.

This candidate changed the runtime verifier's emitted output, the Pi-hole
client's and CLI's compiled Go, and the operator handoff driver. By §5 those
are evidence-producing inputs for the two image-bound rows, so **SW-P1-05 and
SW-P1-20 are open here** and an operator rebuild — `docs/VERIFICATION.md` §6.5
step A — is what renews them. SW-P1-12 is open for the separate reason that no
hosted run has executed this tree. `docs/VERIFICATION.md` §3.31 states each
row, the input that demoted it, and what renews it.

| ID | Requirement | Status at this candidate |
| --- | --- | --- |
| SW-P1-01 | Container runtime verification is built from checked operations | VERIFIED |
| SW-P1-02 | Repository verification and operator Docker verification are separate programs | VERIFIED |
| SW-P1-03 | Every command, search and parse failure is checked explicitly | VERIFIED |
| SW-P1-04 | Assertions read only successfully captured structured output | VERIFIED |
| SW-P1-05 | Exact image identity and deployment settings are verified against a real image | **IMPLEMENTED-UNVERIFIED** — image-bound; the verifier and the compiled binary both changed. §6.5 step A renews it |
| SW-P1-06 | Inspection resources are isolated; only this invocation's resources are removed | VERIFIED |
| SW-P1-07 | Regression tests cover the enumerated false-pass classes | VERIFIED |
| SW-P1-08 | Shell scripts pass ShellCheck as a required gate | VERIFIED |
| SW-P1-09 | An independent secret detector runs alongside the project-specific scanner | VERIFIED |
| SW-P1-10 | Critical Go paths are reviewed and the review is recorded | VERIFIED |
| SW-P1-11 | govulncheck results are handled by content, not by exit status alone | VERIFIED |
| SW-P1-12 | CI is reproducible, least-privilege, and records tool versions | **IMPLEMENTED-UNVERIFIED** — no hosted run has executed this tree. An approved push, then a hosted run |
| SW-P1-13 | Pre-existing functional, security, race, and offline-plan tests are preserved and rerun | VERIFIED |
| SW-P1-14 | The gate suite is deterministic: no gate passes or fails at random | VERIFIED |
| SW-P1-15 | The CLI's read-only guarantee is covered by a test | VERIFIED |
| SW-P1-16 | Cleanup is part of the verdict: it completes first, it is idempotent, and its failure is nonzero | VERIFIED |
| SW-P1-17 | Every resource is attributed to this invocation before it is deleted; pre-existing resources are preserved | VERIFIED |
| SW-P1-18 | One resolved Compose configuration drives creation, listing and expectation | VERIFIED |
| SW-P1-19 | The deployment's mounts are asserted exactly: presence, type, source, mode, no extras | VERIFIED |
| SW-P1-20 | Static linkage is proven by checked ELF inspection of the built artifact | **IMPLEMENTED-UNVERIFIED** — the Go source changed, so the executable this row is about is not the one the verified image contains. §6.5 step A renews it |

**Nineteen of twenty are VERIFIED at `c35b1e6`. The phase does not close.**
SW-P1-05 and SW-P1-20 were the two image-bound rows, and the operator's run of
`docs/VERIFICATION.md` §6.5 — preflight, step A and close-out, against
`c35b1e601f2543cb666d34888c61b08406446106`, producing image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06` —
closes both. `docs/VERIFICATION.md` §3.22.

**At `c35b1e6` all twenty rows read VERIFIED, and Phase 1 was ACCEPTED there —
within the evidence boundaries stated below, and qualified by one pending
criterion.** Three of the twenty have since lapsed on the current candidate;
the paragraph immediately above the table says which and why, and
`docs/VERIFICATION.md` §3.31 states each one. The
pending one is at the phase level rather than in any row: *existing deployment
resources survive checker execution* is established of the program by tests that
check it directly, and has never been observed against this deployment's own
resource inventory. `docs/IMPLEMENTATION_PLAN.md` §3.3 reconciles every
criterion; `docs/VERIFICATION.md` §3.30 records the gap and what would close it. The question that held it open was the
renewal rule's, not any row's: whether commits made after the operator's build
demoted SW-P1-05. The operator has settled the rule — renewal follows a row's
affected evidence-producing inputs — and the analysis it requires has been
carried out and recorded: `docs/VERIFICATION.md` §3.28, §5.1 below. No
evidence-producing input of either image-bound row changed, so no rebuild is
required and no row moves.

**The evidence boundaries, which travel with the acceptance.**

| | |
| --- | --- |
| Image-bound rows (SW-P1-05, SW-P1-20) | Commit `c35b1e601f2543cb666d34888c61b08406446106`, image `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06` — the operator's own build and run, `docs/VERIFICATION.md` §3.22. **Not** relabelled to `HEAD`, and not evidence about any other artifact |
| Hosted-CI row (SW-P1-12) | Commit `87bdfaf`, run 34394790484, 28 passed / 0 failed / 0 BLOCKED — §3.25; confirmed at `518af51` by run 34396978547 — §3.27 |
| Every other row | The local suite on a clean committed tree, most recently §3.26; each row names its own evidence section |
| The tree these carry to | `HEAD`. Every commit since `87bdfaf` is documentation-only, and the two non-documentation commits since `c35b1e6` touch no input either image-bound row's evidence was produced from — §3.28 |

**What acceptance of this phase is not.** It is acceptance of the *verification
apparatus and its evidence*, and nothing beyond it. The execution boundary is
specific rather than blanket, and `docs/VERIFICATION.md` §3.22 states it:
the in-build assertions executed, and the isolated `scamwall version` probe ran
in a container with no network, no mounts and no credential; the **deployment
inspection container was created and never started**; and **no live Pi-hole
operation was performed** — no credential opened, no authenticated request, no
feed or indicator fetched, nothing detected or blocked. So the application has
never run *as deployed*, and nothing here says it can authenticate or read its
mounted secret. Phase 2 and every broader product validation remain **pending**,
SW-P2-04 stays **BLOCKED**. FINDING-68 was **closed at `e2b740b`**, and closing
it is one of the reasons Phase 1's acceptance does not travel to the current
candidate: it is a change to the verifier, which is an evidence-producing input
for the image-bound rows. `docs/VERIFICATION.md` §4.19, §3.31. Read the next paragraphs
before reading the table above as anything wider.

**SW-P1-12 closed at `87bdfaf`**, on hosted run 34394790484: **28 passed, 0
failed, 0 BLOCKED**, `RESULT: all required gates passed`, executing
`scripts/check.sh` itself so the gate list is the local suite's by construction.
It had been the one open row since `7e11419`. The push that made it possible was
approved by the operator; the run before it, 34392469729, **failed** — and what
it found is FINDING-71, a regression suite that asserted this household's own
deployment values and could therefore only pass on one machine. Both runs are
recorded in `docs/VERIFICATION.md` §3.25. A failed run that is quietly re-run
until green is not evidence.

**SW-P1-05 is VERIFIED, and its renewal state is no longer contested.** The
evidence — the 358-case suite against the scripted fake, and the operator's
verifier run against image `sha256:0efff150…` built from `c35b1e6` — is
untouched by anything committed since, and that is now a finding rather than an
assertion: `docs/VERIFICATION.md` §3.28 enumerates the row's evidence-producing
inputs, runs `git diff` and `go list -deps` across every commit from `c35b1e6`
to `HEAD`, and finds none of them changed. `87bdfaf` changes
`scripts/tests/operator-handoff-test.sh`, which is the control for a driver that
did not change; `9bbf284` changes a package the shipped binary does not import.
The row keeps its own identities — that commit and that image — and this
document does not describe the run as having happened anywhere else. §5.1.

**What "all twenty VERIFIED" still does not mean.** Not that the application
runs *as deployed*, authenticates, or reads its mounted secret — the deployment
container has never been started, the only executions on record are the
in-build assertions and an isolated `version` probe with no network, no mounts
and no credential (`docs/VERIFICATION.md` §3.22), and steps B, C and D of §6.5
remain unexecuted.
Not that the workflow handles fork pull requests safely; a branch push cannot
show that, and the property stays in Phase 2. Not that ScamWall detects
anything. Phase 2 rows are untouched and SW-P2-04 stays BLOCKED.

**What this closure is not.** It is not evidence that the application runs,
authenticates, or reads its mounted secret — the verifier deliberately never
starts the container, which is what makes the check safe to run against a host
carrying a live deployment. Steps B, C and D of §6.5 were not run, no credential
was opened, and no request reached the household Pi-hole. Phase 2's rows are
untouched, and SW-P2-04 stays BLOCKED.

**Phase 1 was not complete at `7e11419`, and there it was further from complete
than it had been at `72bc84c`** — retained in the past tense it belongs in, now
that the phase is accepted at the identities §3 names above. That was the
renewal rule working, not a regression. Nineteen
of twenty requirements were verified at `72bc84c`; the working candidate changes
Go source, `scripts/*.sh` and the workflow, so §5 demotes three rows rather than
one. Restoring them needs an operator build and a hosted run — in that order,
and neither can be performed from this account.

| Row | State at `7e11419` | Next step |
| --- | --- | --- |
| SW-P1-12 | **IMPLEMENTED-UNVERIFIED** | Demoted by §5: `.github/workflows/gates.yml` changed at `bc5ad77` (fixture ownership) and `scripts/check.sh` at `66199c8`/`3cc7c5e`. The gate list is now **26**, not the 24 run 34047025567 executed, so that run cannot be read as covering this tree. It also needs the property-by-property re-review §5 requires for a workflow change — begun, and partly mechanised: `scripts/workflow-policy-check.sh` now asserts seven of the properties on every run (`docs/VERIFICATION.md` FINDING-30). Renewal: an approved push, then a hosted run |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Demoted by §5 on both halves. The commit half lapsed because the Go source changed, so the executable this row is about is not the one image `sha256:d7c44949…` contains; the image half lapses with it. The controls (§3.6) are untouched and pass. Renewal: the assertion must be observed inside a real `docker build` of this source — `docs/VERIFICATION.md` §6.5 step A produces exactly that, or a hosted run does |
| SW-P1-05 | IMPLEMENTED-UNVERIFIED | Still open, and its renewal now has **wider scope**: `bc5ad77` adds assertions relating the supplementary group to the password file's ownership, the container identity's ability to read it, and the daemon's user-namespace posture. None has ever been evaluated against this deployment. Renewal is an operator action: `docs/VERIFICATION.md` §6.5 step A |

**Do not relabel run 34047025567 as covering `7e11419`.** It covers `72bc84c`:
24 gates, a different workflow file, and different Go source. The new candidate
needs its own hosted run after a subsequently approved push, and until then the
honest statement is that these three rows are implemented and unverified.

**And do not relabel it as covering `9ebb98c` either.**
That session changes Go source and three scripts and adds two more, so §5
demotes the same rows a second time. Its local suite was re-run on the final
clean committed tree and those rows rest on *that* transcript
(`docs/VERIFICATION.md` §3.15); nothing about it was renewed by any earlier run.

| Row | State at `9ebb98c` | Next step |
| --- | --- | --- |
| SW-P1-12 | **IMPLEMENTED-UNVERIFIED** | Still demoted. `.github/workflows/gates.yml` is unchanged by this session, so the property-by-property workflow re-review is not re-triggered — but `scripts/check.sh` gained a gate, so the gate list this tree runs is again not the list any hosted run has executed. Renewal: an approved push, then a hosted run |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Still demoted on both halves: the Go source changed again, so the executable this row is about is not the one in image `sha256:d7c44949…`. The controls (§3.6) are untouched and pass. Renewal: the assertion observed inside a real `docker build` of this source — `docs/VERIFICATION.md` §6.5 step A, or a hosted run |
| SW-P1-05 | IMPLEMENTED-UNVERIFIED | Still open. Its renewal procedure was **rewritten and tested** this session — `§6.5` step A now passes explicit build metadata, checks the in-build assertions per step, runs the built binary to confirm the commit it embeds, and pins the runtime verifier to the resolved image ID. That is a better renewal, not a renewal. It has not been executed |
| SW-P1-15 | **IMPLEMENTED-UNVERIFIED** | Demoted by §5 on the Go change, and renewed on the local transcript: `go test -race -count=1 ./...` passes with six new CLI cases covering the credential-free doctor mode, the credential-length removal, and the three session-teardown outcomes. `docs/VERIFICATION.md` §3.15 |

**Where the rows stood at `72bc84c`, retained because a row that was closed and
then demoted is a different thing from one that was never closed.** Nineteen of
twenty requirements were verified at
`72bc84c`. No requirement is BLOCKED any more — SW-P1-12 closed on a passing
hosted run, and SW-P1-20 closed on the build inside it — and one remains
demoted, awaiting an operator action this account cannot perform:

| Row | State | Next step |
| --- | --- | --- |
| SW-P1-12 | **VERIFIED** | Closed at `72bc84c` by run 34047025567: 24 passed, 0 failed, 0 BLOCKED, gate list identical to the local suite's. It took three runs — the first could not be diagnosed at all (FINDING-23), the second diagnosed itself and found FINDING-27 — and the acceptance criterion was never relaxed. `docs/VERIFICATION.md` §3.12 |
| SW-P1-20 | **VERIFIED** | Closed at `72bc84c`, bound to image `sha256:d7c44949…`. Its acceptance is "the controls pass, AND the assertion is observed to run inside a real `docker build`"; the controls are untouched and were re-run at `b6e70f4`, and the assertion is a `RUN` step in a build that exited 0 on an uncached runner. An earlier revision held this row open because CI's *deployment* differs from the operator's — an over-application, since the ELF assertion reads no deployment. `docs/VERIFICATION.md` §3.12 |
| SW-P1-05 | IMPLEMENTED-UNVERIFIED | Demoted by §5: `aa49797` changes `deploy/compose/compose.yaml` **and** `scripts/container-runtime-verify.sh`, and the verifier now makes assertions the `b6b1769` run never evaluated. The CI run at `72bc84c` passed the same verifier against image `sha256:d7c44949…` and **does not close this**: it resolved a different deployment, so four assertions remain unevaluated against the operator's configuration. Renewal is an operator action: `docs/VERIFICATION.md` §6.1 |


#### SW-P1-05 and SW-P1-20 reconciled against their acceptance criteria at `c35b1e6`

The evidence is the operator's run of `docs/VERIFICATION.md` §6.5 — preflight,
step A and close-out — against `c35b1e601f2543cb666d34888c61b08406446106`,
producing image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`.
Preflight 9 passed, step A 22 passed, the runtime verifier 95 passed / 0 failed
/ 0 blocked / 0 cleanup problems, close-out 7 passed; every step reported zero
failures, zero blocks and zero cleanup problems, with a direct exit status of 0.
`docs/VERIFICATION.md` §3.22.

Each row is reconciled against **the criterion as written**, not against a
paraphrase of it.

| SW-P1-05, criterion as written | Met by | Verdict |
| --- | --- | --- |
| Artifact (1) — the regression suite against the scripted fake passes | `scripts/tests/runtime-verify-test.sh`, **358 cases, 0 failed**, at `e8f8683`. `c35b1e6` is documentation-only and changes no gate input, so §5's converse carries it forward to this tree — `docs/VERIFICATION.md` §3.21 | **Met** |
| Artifact (2) — a real run against a real built image | The verifier run inside step A, against an image built by `docker build` on the operator's host in the same step: **95 passed, 0 failed, 0 blocked, 0 cleanup problems** | **Met** |
| Artifact (2) **records the image ID** it ran against | `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`, resolved once from the tag by step A and passed to the verifier as both `SCAMWALL_IMAGE` and `SCAMWALL_EXPECTED_IMAGE_ID`, so the verifier's own identity assertion had to agree with the build's output | **Met** |
| `0 blocked` weighs as much as `0 failed` — the row says so explicitly | 0 blocked at every step. No assertion went unrun | **Met** |
| The four assertions that had never been evaluated **against this deployment** — the prohibited-path rule over the secret source, the host-side regular-file check on each approved mount, the password file's world-reachability, and the supplementary group resolving to the deployment's value rather than the default | The run resolved the deployment's own configuration on the deployment's own host, and reported no failed and no blocked check. The preflight refuses to proceed if any `SCAMWALL_*` or `PIHOLE_HOST_IP` variable is exported, which is the route by which a bind source could have been redirected to a fixture; it passed | **Met**, by counts rather than by a per-assertion listing — see the qualification below |

| SW-P1-20, criterion as written | Met by | Verdict |
| --- | --- | --- |
| The controls pass | `internal/buildcheck/elfcheck/main_test.go` — positive, negative and malformed-input controls — passing under `go test -race -count=1 ./...` at `e8f8683`, carried forward to `c35b1e6` for the same reason as above. `docs/VERIFICATION.md` §3.6, §3.21 | **Met** |
| The assertion is **observed to run inside a real `docker build`** | The ELF linkage assertion executed in the step-A build, **uncached**. Step A locates the step by its header line and examines that step's own output, so a log that merely contains the assertion's text does not satisfy it, and a `CACHED` step fails it | **Met** |
| Both, and neither part suffices alone | Both, on one commit and one artifact — the first time since `b6b1769` that the two halves of this row rest on the same image | **Met** |

**The qualification on SW-P1-05's last row, stated rather than buried.** The
evidence returned is step and verifier **counts**, not a per-assertion listing.
What is established directly is that no check failed and no check went unrun, on
the operator's resolved configuration; that the four named assertions are among
the checks that ran follows from their being unconditional assertions in the
verifier this run executed, not from having been read individually in a
transcript. The row's acceptance criterion is written in terms of the two
artifacts and the image ID, and it is met on its own terms. A transcript would
be the stronger form, and `docs/VERIFICATION.md` §3.22 says where it lives.

**What the count moved from, and what that does not prove.** 95 passed against
90 at `b6b1769` (§3.7). The assertions added since — `aa49797`'s three and the
FINDING-29 readability judgement with its user-namespace check — are an increase
of that order, and the correspondence is recorded as consistent rather than
asserted item by item.

**Neither row is closed by this run for any other artifact.** Both are bound to
this image ID *and* this commit. **A rebuild requires fresh verification**: the
image it produces must be identified and verified in its own right before either
row can be claimed for it. That is a statement about what has been verified, and
it is deliberately kept apart from any claim about digests — this record does
**not** assert that a rebuild yields a different image ID, nor that it yields the
same one. Reproducibility here has been neither demonstrated nor refuted, and
nothing depends on which way it would go.

**A contradiction in the verifier's own output, recorded and not fixed here.**
The transcript step A requires contains both the FINDING-29 verdict — an
inspection of the password file's owner, group and mode — and a note telling the
operator those are things "this program does not inspect and does not claim".
The note is stale prose from before FINDING-29 was fixed. It is a **pending
wording correction**, recorded as FINDING-68 in `docs/VERIFICATION.md` §4.19,
and the tested code is deliberately unchanged: the note is emitted text asserted
against by a 358-case suite, and the verifier that prints it is an
evidence-producing input for SW-P1-05 and SW-P1-16 … SW-P1-19, so editing it
demotes the rows this run has just renewed and costs another operator build.
**It remains open on those terms** — §5.1 confirms the reasoning rather than
overturning it, and `docs/VERIFICATION.md` §4.19 scopes the change. No
assertion's verdict depends on it, and it qualifies neither row above.

**Still pending, and not touched by this run.** SW-P1-12 — no hosted run has
seen any commit since `72bc84c`, and the gate list has moved from 24 to 26. All
of Phase 2 — steps B, C and D of §6.5 were not executed, no credential was
opened, no request reached the household appliance, and SW-P2-04 stays BLOCKED.

| Row | State at `c35b1e6` | Next step |
| --- | --- | --- |
| SW-P1-05 | **VERIFIED**, bound to image `sha256:0efff150…` and commit `c35b1e6` | None for the row. It re-opens on a change to any input its evidence was produced from — `container/Dockerfile`; `deploy/compose/compose.yaml` **or the deployment's resolved configuration**; `scripts/container-runtime-verify.sh` **or `scripts/lib/docker-resources.sh`**; `scripts/operator-handoff.sh`; **any compiled input of `./cmd/scamwall`**; `scripts/tests/runtime-verify-test.sh`; or a rebuild. §5, and the worked analysis at `docs/VERIFICATION.md` §3.28 |
| SW-P1-20 | **VERIFIED**, bound to the same image and commit | None for the row. It re-opens on a change to any compiled input of `./cmd/scamwall` (the packages `go list -deps` names, `go.mod`, `go.sum`, the toolchain), to `container/Dockerfile`, or on a rebuild; §5 |
| SW-P1-12 | **VERIFIED** at `87bdfaf` on hosted run 34394790484 — 28 passed, 0 failed, 0 BLOCKED | None. It re-opens on any change to `.github/workflows/gates.yml` or to the gate list `scripts/check.sh` defines |

#### SW-P1-20 reconciled across the complete history since `72bc84c`

This row has been closed once and demoted twice, and the two facts are easy to
collapse into a wrong one. They are kept apart here.

| | |
| --- | --- |
| **Old evidence, and what it still covers** | Run 34047025567 at source `72bc84c13f4e6914bfb015e87d46a5234e8f5234`, image `sha256:d7c44949d56d4f609b3f184464521a2d95c6b34e628f69fd5b145ad6104bba07`. The ELF linkage assertion executed as a `RUN` step inside an uncached `docker build` that exited 0. **That evidence is not withdrawn and is not weakened.** It remains valid for the artifact it names, and `docs/VERIFICATION.md` §3.12 keeps it |
| **What it does not cover** | Any other source tree, and any other image. It is bound to an image ID, which is the digest of that image's content |
| **Drift since** | Five commits changed Go source — `0d620de`, `ee09fff`, `2a0af8f`, `7e11419`, `42477f1` — and `container/Dockerfile` changed with them. Cumulatively **+3440 / −229 across 22 files** (`git diff --stat 72bc84c..HEAD -- '*.go' go.mod go.sum container/Dockerfile`). The executable this tree produces is not the executable inside `sha256:d7c44949…` |
| **Current status** | **IMPLEMENTED-UNVERIFIED**, and has been continuously since `7e11419` |
| **Current renewal requirement** | The ELF linkage assertion must be observed executing inside a real `docker build` **of this source**, not of any earlier one. Two paths produce it: `docs/VERIFICATION.md` §6.5 **step A**, run by the operator; or a hosted run after an approved push. Either is sufficient on its own for this row. The static controls (`docs/VERIFICATION.md` §3.6) are untouched and pass, and they are the *other* half of the acceptance — they are not a substitute for the build half |

**The error this table exists to prevent.** "This patch changed no Go source"
is a statement about one patch. It is not a statement about the distance
between the current tree and the tree some earlier evidence was produced
against, and it must never be read as one. The renewal rule in §5 is
cumulative: evidence lapses when the source it describes moves, and it does not
un-lapse because a later commit happened to leave that source alone.

The same reading applies to **SW-P1-12**, for the same reason and by a
different route: the gate list this tree runs is **26**, and run 34047025567
executed **24**. That row is also IMPLEMENTED-UNVERIFIED and also needs its own
hosted run.

Demoting rows that were green is the rule working, not a regression. The
alternative — leaving them VERIFIED because the change "should not affect them"
— is precisely the assumption §5 exists to forbid. Restoring one of them on
evidence that genuinely covers it is the same rule working in the other
direction, and is not a relaxation: SW-P1-20's criterion was met, not amended.

An unverified required item means the phase does not close, however many of the
others are green — and "the CI badge is green" is the most tempting reason to
forget that. Nineteen-twentieths is not nineteen-twentieths of a closed phase;
it is an open phase. The one open row is the one that ties the work to a real
image *and a real deployment*, which is precisely the half a passing CI run
cannot supply: CI verified a container built on the runner, mounting throwaway
fixtures, with `group_add: 65532` rather than the deployment's `989`
(`docs/VERIFICATION.md` §3.12).

**What was missing for SW-P1-05, precisely** — four assertions, not the row as a
whole. `docs/VERIFICATION.md` §6.1 lists them: the prohibited-path rule over the
secret source, the host-side regular-file check on every approved mount, the
password file's world-reachability, and the supplementary group resolving to the
deployment's value rather than the runner's default. Everything else the row
asserted had run against a real image in CI. **All four are now evaluated** — the
operator's run at `c35b1e6` reported 0 failed and 0 blocked against the
deployment's own resolved configuration; see the reconciliation earlier in this
section and `docs/VERIFICATION.md` §3.22. The paragraph above and the tables
below are retained as the state at `72bc84c` … `e8f8683`, which is what they
describe.

**The history of these two rows**, retained rather than rewritten, because a
row that was closed, demoted and closed again on different evidence is a
different thing from one that was never in doubt. Both were first closed by the
operator's run at `b6b1769` against image `sha256:b95cc07c…`
(`docs/VERIFICATION.md` §3.7):

| Was blocked | Closed by | Acceptance criterion met | State now |
| --- | --- | --- | --- |
| SW-P1-05 | the verifier run against a real built image: 90 passed, 0 failed, 0 blocked, 0 cleanup problems, `VERIFY exit=0`, image identity confirmed against the pin, container created and never started | both artifacts required by the row — the regression suite against the fake, and a real run recording the image ID | **Demoted** at `aa49797`, and **VERIFIED again at `c35b1e6`** on artifact (2) produced by §6.5 step A: 95 passed, 0 failed, 0 blocked, 0 cleanup problems against `sha256:0efff150…` |
| SW-P1-20 | the ELF linkage assertion executing inside a `docker build` that exited 0 | both parts — the controls pass (§3.6) *and* the assertion ran in a real build | **VERIFIED again** at `72bc84c` on the CI build, demoted at `7e11419` with the Go source, and **VERIFIED again at `c35b1e6`** on the operator's uncached build. Bound to `sha256:0efff150…`, having passed through `sha256:b95cc07c…` and `sha256:d7c44949…` |

**Reconciliation of everything else claimed for Phase 1**, so that nothing is
carried on assumption:

| Item | State |
| --- | --- |
| `check.sh` exit status, requested directly rather than inferred from the printed verdict | **Obtained** at `aa49797` and again at `b6e70f4`: `CHECK exit=1`, with 22 passed, 0 failed, 2 BLOCKED. Run directly, not through a wrapper, a monitor, `tee` or a background task, so the status is the script's own. The status and the printed verdict agree. `docs/VERIFICATION.md` §3.0, §3.13 |
| Evidence renewal after `ef40156`/`aa49797` changed `scripts/*.sh`, `compose.yaml` and the workflow | **Done, except for one row.** §5 demotes SW-P1-01 … SW-P1-04, SW-P1-06 … SW-P1-09, SW-P1-11 and SW-P1-14 on any `scripts/*.sh` change; the suite was re-run at `aa49797`, and again at `b6e70f4`, and those rows rest on that transcript. SW-P1-20 was renewed by the CI build at `72bc84c`. SW-P1-05 needs an image built on the operator's host against the operator's deployment and cannot be renewed from the service account; it is demoted rather than carried, `docs/VERIFICATION.md` §6.1 |
| The six defects fixed in `b6b1769` | **Recorded** as FINDING-17 … FINDING-22, `docs/VERIFICATION.md` §4.8, with the pre-fix comparison in §3.5 — the `0b083cb` verifier fails 50 of the 319 cases |
| Determinism (SW-P1-14) at the new suite size | **Partly renewed.** 30 consecutive runs of the 319-case suite at `b6b1769`, 0 failures — against 500 runs for the 237-case suite at `0b083cb`. Shorter by design and stated as such, not merged into one figure. `docs/VERIFICATION.md` §3.3 |
| Hosted CI execution | **Done, and it failed.** Run 34036997074 at `2a18874`. What it established: the workflow runs, its recorded tool versions match §2.2 exactly, its gate list matches the local suite's, and `docker build` passes on an independent host. What it did not: a passing run. `docs/VERIFICATION.md` §3.8 |
| Diagnosability of a failed CI gate | **Fixed at `ef40156`, and demonstrated locally.** A failing gate now reports its reason, verdict and cleanup result before any length limit, states any truncation, and preserves the omitted material in a sanitized artifact CI uploads. 62 regression cases, three PRE-FIX CONTROLS, and an end-to-end demonstration through `check.sh` with an injected failing gate — `docs/VERIFICATION.md` §4.9 and §3.10. **Not yet observed on a runner**: the `::group::` markers and the artifact upload have never been exercised by GitHub |
| Why the `2a18874` CI run failed | **Not established, and unrecoverable from that run.** It has no artifacts and its log holds exactly the twenty-five lines the old `head -25` kept. The *precondition* for the predicted cause is now established by resolving the real definition under runner conditions (`docs/VERIFICATION.md` §3.9), but a precondition is not a mechanism |
| CI's ability to run the container gates at all | **Addressed at `aa49797`, unobserved.** The workflow now creates disposable fixtures under `RUNNER_TEMP`, outside the build context, 0700/0600, and removes them in a step that fails the job if the removal did not take. No CI-specific assertion was weakened or skipped. `docs/VERIFICATION.md` §3.4 and §6.3 |
| Fork-pull-request secret handling | **Not demonstrated**, and not demonstrable by a branch push. Reviewed in `docs/VERIFICATION.md` §3.4, and since `66199c8` also asserted *lexically* on every gate run by `scripts/workflow-policy-check.sh` — which establishes what the workflow says, not what GitHub does. Registered in `docs/VERIFICATION.md` §6.4 item 10 so it is not lost when SW-P1-12 closes again |
| Evidence renewal at `7e11419` | **Local half done; hosted and image halves outstanding.** §5 demotes SW-P1-01 … SW-P1-04, SW-P1-06 … SW-P1-09, SW-P1-11, SW-P1-14 and SW-P1-19 on any `scripts/*.sh` change, and every Go-source row plus SW-P1-13 on a Go change. The whole local suite was re-run on the final clean committed tree — 24 passed, 0 failed, 2 BLOCKED, `CHECK exit=1` — and those rows rest on that transcript (`docs/VERIFICATION.md` §3.14). SW-P1-12 and SW-P1-20 cannot be renewed from this account and are demoted rather than carried |
| The API contract, enforced rather than described | **New at `0d620de`, locally evidenced.** A permitted-operation table is checked before any network activity and again on every redirect; the total deadline, `Retry-After` handling, session nesting and credential scrubbing are covered by tests against a local fake. `docs/PIHOLE_API_CONTRACT.md` §7 states the permitted set and, in its own subsection, that none of this is evidence about a real Pi-hole |
| Runtime password access, live authentication, destination connectivity and TLS verification through the `pi.hole` pin | **Not established, and out of Phase 1 scope.** Phase 2 — SW-P2-02 and SW-P2-04. `docs/VERIFICATION.md` §6.2 |
| The operator procedure that renews SW-P1-05 | **Rewritten and tested; still unexecuted.** It was a documentation code block that nothing ran, and it carried nine defects — including a hardcoded HEAD that refused its own documented checkout, a build passing no source metadata, a step claiming to read no password beside output showing it reading one, and steps B–D executing whatever the mutable tag pointed at. It is now `scripts/operator-handoff.sh` with 141 regression cases against a scripted fake Docker and git. `docs/VERIFICATION.md` §4.13 and §6.5. **Testing the procedure is not performing it**: SW-P1-05 closes when the operator runs step A and returns its result |
| Evidence renewal at `76f3bfd` (ORDER 1) | **Local half done; hosted and image halves outstanding, as before.** §5 demotes SW-P1-01 … SW-P1-04, SW-P1-06 … SW-P1-09, SW-P1-11, SW-P1-14 and SW-P1-19 on the `scripts/*.sh` change. The whole local suite was re-run on the final clean committed tree and those rows rest on that transcript (`docs/VERIFICATION.md` §3.17). SW-P1-12, SW-P1-20 and SW-P1-05 cannot be renewed from this account and are demoted rather than carried. **This patch changing no Go source does not renew any Go-bound row** — see the row below |
| SW-P1-20 reconciled across the whole history since `72bc84c` | **IMPLEMENTED-UNVERIFIED, and this patch does not change that in either direction.** A correction is recorded here rather than left implied: "no Go source changed in this patch" says something about `0cdec6c…76f3bfd` and **nothing** about whether the current Go source matches the tree CI built at `72bc84c`. It does not. Five commits since have changed Go source — `0d620de`, `ee09fff`, `2a0af8f`, `7e11419`, `42477f1` — together with `container/Dockerfile`, for a cumulative **+3440 / −229 across 22 files**. The image the old evidence is bound to therefore contains a **different executable** from the one this tree builds. See §5 and the reconciliation table below |
| The operator procedure's own defects, second pass | **Six found and fixed at `76f3bfd`; the procedure is still unexecuted.** FINDING-51 to FINDING-56: a failed isolation assertion did not prevent `docker start`, a step published its identities before it had a verdict, `--authorise-authenticated-read` was accepted as proof that steps A, B and C had passed, the work directory's advertised "sanitized logs" were the raw captures, step Z's leftover check could not return anything and therefore passed every time, and the privileged work directory and state file were not validated for symlinks, ownership, mode or ancestor writability. `docs/VERIFICATION.md` §4.15. The suite is 308 cases. **Testing the procedure is still not performing it**: SW-P1-05 closes when the operator runs step A and returns its result |
| The "pending operator testing" row, examined as a category | **Reclassified.** Across two review passes that row has now been found to contain **eight** defects that needed no Docker daemon — FINDING-49 and FINDING-50 at `5af270d`, FINDING-51 … FINDING-56 at `76f3bfd`. It must not be read as a queue of questions only a daemon can settle. What genuinely remains behind it is narrow, and `docs/VERIFICATION.md` §7 states it as such |
| Evidence renewal at `9ebb98c` | **Local half done; hosted and image halves outstanding, as before.** §5 demotes SW-P1-01 … SW-P1-04, SW-P1-06 … SW-P1-09, SW-P1-11, SW-P1-14 and SW-P1-19 on the `scripts/*.sh` change, and every Go-source row plus SW-P1-13 and SW-P1-15 on the Go change. The whole local suite was re-run on the final clean committed tree and those rows rest on that transcript (`docs/VERIFICATION.md` §3.15). SW-P1-12, SW-P1-20 and SW-P1-05 cannot be renewed from this account and are demoted rather than carried |
| **The operator procedure that renews SW-P1-05, performed** | **Done.** The operator ran `docs/VERIFICATION.md` §6.5 preflight, step A and close-out against `c35b1e6`: 9 / 22 / 7 step checks passed, the runtime verifier 95 passed / 0 failed / 0 blocked / 0 cleanup problems, every step exit 0, producing image `sha256:0efff150…`. Four review passes had found twenty defects in this procedure without a daemon — nine at `6a737f3`, two at `5af270d`, six at `76f3bfd`, three at `04e7ea4`. This is the first time it has been run rather than reviewed, and it ran clean. `docs/VERIFICATION.md` §3.22 |
| Evidence renewal at `c35b1e6` | **Image half done. Hosted half outstanding.** `c35b1e6` changes documentation only, so §5 demotes nothing and the `e8f8683` transcript carries forward (`docs/VERIFICATION.md` §3.21). SW-P1-05 and SW-P1-20 are renewed by the operator run and are VERIFIED at this commit and image. **SW-P1-12 is not renewed and cannot be from this account**: no hosted run has seen any commit since `72bc84c`, and the gate list has moved from 24 to 26 |
| The live-appliance evidence | **Still absent, and not sought.** Steps B, C and D of `docs/VERIFICATION.md` §6.5 were not run. No credential was opened at any point — the close-out compared the secret's owner, group, mode, size and mtime against a baseline and did not read it, and `--verify-secret-integrity` was not used. No request reached the household Pi-hole. SW-P2-04 stays BLOCKED and every Phase 2 row still lacks evidence against anything real |
| FINDING-68, raised by reading this run's own output | **Recorded, not fixed.** The verifier prints a note telling the operator it "does not inspect and does not claim" the password file's owner, group and mode, in the same transcript as the FINDING-29 verdict that inspects exactly those and that step A requires before it will pass. A pending **wording** correction, still **open**; the tested code is deliberately unchanged, because the verifier that prints the note is an evidence-producing input for the rows this run has just renewed, and the note is output its 358-case control asserts against. Scoped as its own change, rebuild included: `docs/VERIFICATION.md` §4.19. **Superseded: closed at `e2b740b`**, and the rebuild it names is now due — §3.31 |
| The ORDER 2 catalog blocker | **Discharged at `9bbf284`.** `docs/SOURCE_CATALOG.md` holds all 85 entries in the repository, so the research scope no longer lives only in a conversation. `docs/source-registry.json` holds 85 records — one per entry — each with a disposition, a research basis or a named blocker, and citations read from the provider's own pages on 2026-09-09. Dispositions: 21 `commercial-approval-required`, 14 `credentials-required`, 6 `historical`, 3 `unavailable`, 41 `unresolved`. **Nothing is enabled**, no record claims `verified-available`, and no record declares an intended operation |
| What the research did **not** establish | **Access, for any source.** Fetching the indicators is outside the order this was done under, so every record's access is documented rather than confirmed — which is why `verified-available` is at zero and why 41 records sit at `unresolved`, several of them with every rights question answered. `docs/SOURCE_REGISTRY.md` §3.1 states the strain this puts on the disposition vocabulary and declines to redesign it |
| The first-wave proposal | **Four sources proposed, in prose only.** `docs/IMPLEMENTATION_PLAN.md` §5.4. Each states the exact operation, the unresolved conditions, the adapter input, the typed output, provenance and expiry handling, correction behaviour, expected overlap, and the evidence still needed. Two of the four cannot claim independence; one is blocked on a rights answer nobody has asked for; the expected incremental value is stated as probably small. §5.5 specifies the adapter for the best-supported of them, and specifies no network code and no threat score |
| The evaluation protocol | **Amended where it was silent, not rewritten.** `docs/EVALUATION_PROTOCOL.md` gains a named baseline (§2.1), duplicate and campaign leakage controls (§4.3), precision/recall/coverage definitions with sample-size rules (§5.1), a fixed false-positive operating point (§5.2), task-level usability and recovery measurement (§6.1), feed-outage, staleness, rollback and correction-propagation tests (§6.2), cost per deployment-year (§7.1), an approval-ownership table (§8.1), and an explicit rule that a DNS pilot result may not be reported as evidence about email, phone, wallet or message detection (§9.1) |
| FINDING-69 and FINDING-70 | **69 fixed, 70 fixed.** 69: `kind` and `authentication` could not express `unknown`, though §2 says every field may. Found by writing records for eleven providers whose documentation could not be read. 70: `docs/source-registry.json`'s `note` had carried the string `"mutation test"` since `e8f8683` — a test fixture committed over the file's own account of itself, which every gate passed because `note` has no rule attached to it. `docs/VERIFICATION.md` §4.20, §4.21 |

### SW-P1-01 — Runtime verification is built from checked operations

**Intended behavior.** `scripts/container-runtime-verify.sh` treats every
Docker operation as fallible. A failed operation produces `FAIL` or `BLOCKED`
and a nonzero exit; it is never indistinguishable from a satisfied assertion.

**Source.** `scripts/container-runtime-verify.sh`
**Tests.** `scripts/tests/runtime-verify-test.sh` — the *absence versus search failure*, *incomplete and malformed inspection data* and *daemon availability* case groups
**Evidence required.** The regression suite passes, and each deliberate failure
injection yields a nonzero verifier exit.
**Dependencies.** None.
**Acceptance.** Every failure injection in the suite produces nonzero exit and
a report naming the failed operation.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

### SW-P1-02 — Repository and operator verification are separate

**Intended behavior.** Repository-content checks use git and run as the
unprivileged service account. Docker checks talk to the daemon, are executed by
the operator, and **never invoke git** — so the operator needs no
`safe.directory` exception in a `scamwall`-owned tree, and the service account
needs no Docker group membership.

**Source.** `scripts/container-security-check.sh` (repository, uses git);
`scripts/container-runtime-verify.sh` (daemon, derives the repository root from
`BASH_SOURCE` and confirms it by required files)
**Tests.** `scripts/tests/runtime-verify-test.sh` — *no git dependency*: the verifier is run with
a `git` on `PATH` that refuses every invocation, and must still succeed; a
static check asserts no git command appears outside comments.
**Evidence required.** Both assertions pass.
**Dependencies.** None.
**Acceptance.** Verification succeeds with a hostile `git`; `git` is never
executed.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

### SW-P1-03 — Command and parse failures are checked explicitly

**Intended behavior.** `docker inspect`, `docker history`, `docker export`,
`docker create`, `docker compose create`, `docker compose ps`, and every `jq`
parse are checked. A `jq` failure is reported as a parse failure, never as
"the property is absent". Error text on a stream can never satisfy a pattern,
because assertions run over captured JSON rather than over command output.

**Source.** `scripts/container-runtime-verify.sh` — `assert_eq`, `assert_true`,
`assert_empty_list`, and the guarded capture sites.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *absence versus search failure* (failed operations and failed searches), *incomplete and malformed inspection data*
(unparseable and empty JSON).
**Evidence required.** Each injected failure yields nonzero exit and a report
that names the operation, and no assertion is claimed as passed.
**Dependencies.** SW-P1-01.
**Acceptance.** As above, for inspect, history, export, create, and both
malformed and empty JSON.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

### SW-P1-04 — Only captured structured output is evaluated

**Intended behavior.** Inspection output is captured to a file and its exit
status verified *before* any assertion reads it. Container inspection must be a
single-element JSON array before any field is read.

**Source.** `scripts/container-runtime-verify.sh` — `CJSON`/`IMAGE_JSON`
capture and the `jq -e 'type == "array" and length == 1'` gate.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *incomplete and malformed inspection data*.
**Evidence required.** `[]` and non-JSON both produce nonzero exit.
**Dependencies.** SW-P1-03.
**Acceptance.** As above.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

### SW-P1-05 — Exact image identity and deployment settings

**Intended behavior.** The requested image is resolved ONCE to its immutable
image ID; that ID — never the tag — is used for image history and for creating
the filesystem-enumeration container; the inspected deployment container's
`.Image` must equal it; and when `SCAMWALL_EXPECTED_IMAGE_ID` is set the
resolved ID must equal it. Deployment settings — user, supplementary group,
capabilities, `no-new-privileges`, seccomp/AppArmor, init, read-only rootfs,
the exact mount set, tmpfs options, hostname pinning, network mode, port
bindings, log bounds and resource limits — are asserted against that container,
against values derived from the resolved configuration.

Compose creates from the tag written in the compose file, so the container's
recorded image is what detects a tag repointed between resolution and creation.
A difference is not assumed to be a mismatch: Docker's image stores do not all
record the same identifier for the same image, so the container's identifier is
re-resolved through the daemon and compared. Equivalence is accepted with both
identifiers reported; anything else fails. What each field means — `.Id` the
local image identifier, `.RepoDigests` registry manifest digests, a manifest
list a different identifier entirely — is printed rather than assumed.

**Source.** `scripts/container-runtime-verify.sh` — "image identity" and
"deployment container" sections.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *image identity* (mismatch,
tag movement, equivalent identifier, malformed and non-digest identifiers, and
a log assertion that no image operation uses the mutable tag), *mounts*,
*tmpfs bounds*, *logging bounds*, *API hostname pinning*, *supplementary
group*, *hardening regressions*.
**Evidence required.** Two distinct artifacts:
1. the regression suite against the scripted fake; and
2. **a real run against a real built image, recording the image ID** — this is
   what makes the assertions statements about a deployable artifact rather than
   about a fixture.
**Dependencies.** Docker daemon access.
**Acceptance.** (1) and (2) both pass, and (2) records the image ID it ran
against.
**Status.** **VERIFIED** at `c35b1e601f2543cb666d34888c61b08406446106`, bound to
image `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`.
Both artifacts hold, on the same tree:

| Artifact | Result | At `c35b1e6` |
| --- | --- | --- |
| (1) regression suite against the scripted fake | **358 cases, 0 failed**, at `e8f8683`. The cases discriminate: the `0b083cb` verifier fails 50 of the 319 it shares — `docs/VERIFICATION.md` §3.5 | **Valid.** `c35b1e6` is documentation-only and changes no gate input, so §5's converse carries the transcript forward — `docs/VERIFICATION.md` §3.21 |
| (2) operator run against image `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`, built from `c35b1e6` on the deployment's host | **95 passed, 0 failed, 0 blocked, 0 cleanup problems**; step exit 0; the resolved image ID pinned through both `SCAMWALL_IMAGE` and `SCAMWALL_EXPECTED_IMAGE_ID`; the container created and never started; cleanup and close-out clean — `docs/VERIFICATION.md` §3.22 | **Produced.** This is the artifact the row had been missing since `aa49797`, and it records the image ID it ran against |

**The four assertions that were unevaluated against this deployment are now
evaluated.** They are unconditional assertions in the verifier this run
executed, the run reported **0 failed and 0 blocked**, and the configuration it
resolved was the deployment's — the preflight refuses to proceed while any
`SCAMWALL_*` or `PIHOLE_HOST_IP` variable is exported, which is the only route by
which a bind source could have been redirected to a fixture. What was missing:

1. `no prohibited path appears in the configured mounts or in the secret source`
   — added at `aa49797`; CI evaluated it against fixture paths under `RUNNER_TEMP`.
2. `every approved mount resolves to an existing regular file on this host`
   — added at `aa49797`; "this host" was the runner.
3. `the application password file is not world-readable through its path`
   — added at `aa49797`; the runner's was a 0600 fixture in a fresh directory,
   not the deployment's secrets path.
4. the supplementary group — CI resolved `65532` from the default, because
   `deploy/compose/.env` is gitignored and a fresh clone has none. The
   deployment resolves its own value.

**Stated at the strength the evidence supports.** The returned evidence is step
and verifier **counts**, not a per-assertion transcript. "No check failed and no
check went unrun, on the deployment's resolved configuration" is established
directly; that these four are among the checks that ran follows from their being
unconditional in the verifier, not from having been read line by line. The
acceptance criterion is written in terms of the two artifacts and the image ID,
and it is met on its own terms. Before this run the position was "expected to
pass", and §5 exists precisely because expected is not observed; it is now
observed.

**A stale note in the verifier's own output, recorded and not fixed.** The
transcript contains both the FINDING-29 verdict — which inspects the password
file's owner, group and mode — and a note asserting that the program "does not
inspect and does not claim" them. FINDING-68, `docs/VERIFICATION.md` §4.19: a
pending wording correction, with the tested code left unchanged because editing
emitted text is a `scripts/*.sh` change that would demote this row again. No
assertion's verdict depends on the note.

`0 blocked` carries as much weight here as `0 failed`. This verifier reports
"could not run" separately from "failed", and a run with no failures but
several unrun checks would satisfy the letter of the acceptance criterion while
proving much less than it appears to.

**Scope of the closure.** This row is about the container's *configuration as
built and created*. It is not evidence that the application runs as deployed,
authenticates, or reads its mounted secret — the verifier never starts the
deployment container, deliberately, which is what makes the check safe to run on
a host carrying a live deployment. The binary did execute in the run that closed
this row, in the build's own assertions and in an isolated `version` probe with
no network, no mounts and no credential (`docs/VERIFICATION.md` §3.22); neither
touches the deployment's state, and neither is evidence for the rows below.
Those are SW-P2-01 and SW-P2-04, both still open.

**Renewal.** Tied to image `sha256:0efff150…` and commit `c35b1e6`. Any rebuild
— including one from this same commit — calls for **fresh verification** of the
image it produces, resolved to an ID and run against that ID; §5 applies. Whether
that image's digest would match `sha256:0efff150…` is a separate question this
record does not answer in either direction. The procedure is
`docs/VERIFICATION.md` §6.5 step A, which has now been executed once and is
therefore a tested and *performed* procedure rather than only a tested one. §6.1
is its superseded ancestor and must not be run.

*Note on the earlier candidate.* The operator's build of `b469c592` produced
image `sha256:d3c4ed2c…`. No verifier was ever run against it and it predates
all seventeen findings in `docs/VERIFICATION.md` §4.7 and §4.8. It remains an
identity on record, is superseded — by `sha256:b95cc07c…` and now by
`sha256:0efff150…` — and must not be deployed or cited as evidence for this row.

### SW-P1-06 — Attributable inspection resources and scoped cleanup

**Intended behavior.** Every resource this invocation creates is attributable
to it before it is deleted, and nothing else is touched.

* The invocation identifier is UNPREDICTABLE (128 bits from `/dev/urandom`),
  not `$$`. A PID is small, reused and guessable, so a stale resource could
  carry a colliding project name.
* Created resource IDs are recorded as they are created, and a per-invocation
  ownership label is applied through a Compose override, so a resource left by
  a partially completed creation is still attributable.
* A snapshot is taken BEFORE anything is created. Any resource already carrying
  the invocation's labels is a collision: nothing is created and nothing is
  deleted, and the ambiguity is reported.
* Removal is by exact ID after re-verifying the label. There is no
  `compose down -p <project>`: project-wide deletion trusts a name.
* Configuration features that escape project isolation — `container_name`,
  externally named networks, volumes or secrets, additional services — block
  the run before anything is created.
* A resource whose ownership cannot be established is PRESERVED and reported.

**Source.** `scripts/container-runtime-verify.sh` — `INVOCATION`,
`VERIFY_PROJECT`, the ownership override, `snapshot_kind`, `label_query`,
`owned_by_this_invocation`, `remove_owned`, `sweep`, `run_cleanup`.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *resource ownership*
(container and network collisions, unrelated-resource preservation, partial
creation, a pre-existing container never adopted), *consistent Compose
configuration* (isolation-escaping features), *cleanup as a verdict*.
**Evidence required.** The fake daemon's command log shows removal of exactly
the resources this run created, every listing filtered by a label unique to
this invocation, no `compose down`, and no reference to any other resource.
**Dependencies.** SW-P1-01.
**Acceptance.** As above, plus: a collision blocks creation, and an
unattributable resource is preserved rather than removed.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1, on cases that construct the
situation rather than infer it: `unrelated-preserved`, `create-fail-existing`,
`named-network-preexisting` and `partial-create` plant resources this invocation
did not create and assert, from the fake daemon's command log, that no
unfiltered listing occurs, that the deployment project is never targeted, and
that none of them is adopted or removed. Behaviour against a real daemon rode on
SW-P1-05, which is closed again at `c35b1e6`: the operator's run reported 0
cleanup problems and cleanup completion against a real daemon, and the close-out
found no resource attributable to the recorded build invocation —
`docs/VERIFICATION.md` §3.22, and §3.7 for the same result at `b6b1769`. **This
row previously added that "the host's existing deployment was left untouched",
which outran the evidence**: no inventory of the deployment's own resources was
taken before and after the run, and the absence of *this run's* leftovers cannot
stand in for one. This row's acceptance is unaffected; the phase-level criterion
it was being read into is **pending** — `docs/VERIFICATION.md` §3.30.

### SW-P1-07 — Regression tests for the false-pass classes

**Intended behavior.** Each historical false pass is reproduced deliberately
and asserted to produce a nonzero result. Required classes: forbidden paths
with and without a leading `./`; failed cleanup and interrupted cleanup;
resource-name collision and unrelated-resource preservation; partial Compose
creation; consistent `.env` handling and interpolation; missing, additional,
duplicated, writable and incorrect mounts; missing inspection fields and
malformed JSON; image tag movement and identity mismatch; failed history search
and other search errors; missing or incorrect hostname pinning; missing,
invalid or unbounded logging settings; invalid tmpfs bounds; static and
dynamically linked ELF controls; and the absence of any application-start
operation in the inspection workflow.

A passing suite proves only that the code agrees with itself unless the tests
DISCRIMINATE. Two mechanisms provide that:

* **Pre-fix controls in the suite.** Where a fix changed an expression, the
  superseded expression is applied to the same fixture and asserted to exhibit
  the defect — the `^\./?` path anchor missing `bin/sh`, an unperformed grep
  looking like a clean result, empty `.Mounts` satisfying the old read-only and
  prohibited-mount assertions.
* **The whole suite run against the pre-fix implementation.** Recorded in
  `docs/VERIFICATION.md` §3.5.

**Source / Tests.** `scripts/tests/runtime-verify-test.sh` (319 cases at `b6b1769`); the ELF
controls are `internal/buildcheck/elfcheck/main_test.go`. Both are wired into
`scripts/check.sh` as required gates that need no daemon.
**Evidence required.** All cases present and passing; the suite is a required
gate; and each targeted case is shown to fail against the pre-fix
implementation.
**Dependencies.** SW-P1-01 … SW-P1-06, SW-P1-16 … SW-P1-20.
**Acceptance.** Every listed class has at least one case; the suite runs on
every gate run as the service account; the pre-fix comparison is recorded.
**Status.** VERIFIED at `b6b1769` — `docs/VERIFICATION.md` §3.1. Coverage map in
`docs/VERIFICATION.md` §3.2; pre-fix comparisons in §3.5, which record both the
`b469c59` comparison (112 failures once its own baseline is unmasked) and the
`0b083cb` one (50 of 319 cases). Six classes were added at `b6b1769` for
FINDING-17 … FINDING-22; they are listed at the end of §3.2.

**Classes added at `76f3bfd` for the operator handoff (ORDER 1).** These belong
to `scripts/tests/operator-handoff-test.sh` rather than to the verifier's suite,
and each is a false-pass or a forbidden-action class the earlier list did not
name:

* an isolation assertion that failed, or that could not be evaluated, must
  prevent the container from being started at all — asserted against the fake
  daemon's own command log, not against the program's output;
* a step that did not pass must publish no identity, and a later step must
  refuse rather than run off one;
* a cleanup failure must make the step's recorded state `failed`, not `passed`;
* an authorisation flag must not stand in for a prerequisite's recorded result;
* a prerequisite that passed against a different image or a different resolved
  configuration must be refused as STALE;
* a rebuild must invalidate downstream acceptance **before** it runs, so a
  failed rebuild leaves nothing usable;
* the shareable evidence copy must retain no credential-shaped value the
  sanitizer catches, while the raw capture must retain it;
* a close-out check that cannot return anything is not a pass, and an empty
  invocation register is UNPROVEN;
* a privileged program must not follow a symlink, adopt a state file it does
  not own, or write into a directory an unprivileged account could substitute.

The discrimination mechanism for these is the **reversion experiment** recorded
in `docs/VERIFICATION.md` §3.17: each fix was reverted on its own and the suite
re-run. In-suite pre-fix controls were not used here because five of the six
defects are the *absence* of a control-flow gate rather than a changed
expression, and a reverted gate is the faithful reproduction of that.

### SW-P1-08 — ShellCheck as a required gate

**Intended behavior.** Every shell script in the repository is analysed by
ShellCheck. Findings are either fixed or suppressed inline with a written
justification. ShellCheck's absence is `BLOCKED`, never a silent skip.

**Source.** `scripts/check.sh` (gate), `scripts/*.sh`, `scripts/tests/*.sh`
**Tests.** The gate is its own test.
**Evidence required.** A clean ShellCheck run at a recorded severity and
version, and a demonstration that the gate fails when a script is broken.
**Dependencies.** None.
**Acceptance.** Gate present, passing, and failing on a deliberately broken
script.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1. Clean over all 10 tracked
scripts at `--severity=style`. Two informational findings were false positives
(a function reached only through `trap`; a deliberately single-quoted regex) and
carry inline `disable=` directives with a written reason on the line above.

### SW-P1-09 — An independent secret detector

**Intended behavior.** A third-party secret scanner runs *alongside*
`scripts/secret-scan.sh`, not instead of it. The project scanner encodes
ScamWall-specific rules (forbidden paths, the Pi-hole password, private CA
material); the independent detector covers the generic credential shapes a
hand-written scanner will miss. Both are required gates.

The independent detector must cover **what would be published**: the commit
history, and the tracked/staged tree — not the operator's untracked local
material, which is governed by `.gitignore` and by the project scanner's path
denial.

**Source.** New: `scripts/independent-secret-scan.sh`, `.gitleaks.toml`
**Tests.** A positive-control case: a planted synthetic credential must be
detected.
**Evidence required.** A clean run over history and the publishable tree, with
tool version recorded; every allowlist entry justified in-file; and the
positive control detected.
**Dependencies.** None.
**Acceptance.** As above.
**Status.** VERIFIED — `docs/VERIFICATION.md` §4.2. gitleaks 8.30.0 over full
history and the `git archive` tree: clean. Positive control fires. Both
exploratory hits are dispositioned, one by a narrowly scoped and justified
allowlist entry.

### SW-P1-10 — Critical Go path review

**Intended behavior.** The following are reviewed, and the review is recorded
with a finding-by-finding disposition: credential handling; TLS configuration
and trust; destination pinning; redirect policy; proxy behavior; deadlines and
cancellation; response size limits; domain normalization; feed verification.

**Source.** `internal/config/secret.go`, `internal/config/config.go`,
`internal/adapters/pihole/client.go`, `internal/adapters/pihole/transport.go`,
`internal/domain/domain.go`, `internal/feed/feed.go`, `internal/audit/audit.go`
**Tests.** `internal/**/**_test.go` (109 test functions at the baseline);
notably `internal/adapters/pihole/guard_test.go` for the structural guards.
**Evidence required.** A written review in `docs/VERIFICATION.md` §5 naming
each area, what was checked, and the outcome — including areas found adequate.
**Dependencies.** None.
**Acceptance.** Every listed area has a recorded disposition; anything found
deficient has either a fix or an explicitly accepted finding.
**Status.** IMPLEMENTED-UNVERIFIED at the ORDER 6 candidate — **demoted from
VERIFIED**. The consolidated review at `docs/VERIFICATION.md` §5 covers all
nine areas for the surface that existed when it was written. This candidate
adds a second signed-document verifier (`internal/feed/evidence.go`) and a
second decision path (`internal/proposal`), both reachable from the command
and neither covered by that review. §5.12 there is the extension, written in
this pass; the row returns to VERIFIED when a reviewer accepts it. Matrix §5.5.

### SW-P1-11 — govulncheck result handling

**Intended behavior.** The vulnerability gate decides from **result content**,
not from exit status alone. This matters because `govulncheck`'s JSON and SARIF
output modes exit `0` whether or not findings exist; a gate that trusts the
exit status in those modes reports a vulnerable dependency set as clean.

**Source.** `scripts/check.sh`
**Tests.** A case that feeds the gate a known-findings result and asserts the
gate fails.
**Evidence required.** The gate's decision procedure is documented, and the
"findings present but exit status 0" case is demonstrated to fail the gate.
**Dependencies.** None.
**Acceptance.** As above.
**Status.** VERIFIED — `docs/VERIFICATION.md` §4.3. `scripts/govulncheck-gate.sh`
decides from `finding` records, distinguishes them from the `osv` database
entries a clean scan also emits, and treats an unparseable stream as UNPROVEN.
Measured on this host: a module with 58 findings exits 3 in text mode and **0**
in JSON mode; the gate fails it either way.

### SW-P1-12 — Reproducible CI with constrained permissions

**Intended behavior.** CI runs the same gates as the local suite, with:
pinned action versions; an explicitly minimal `permissions:` block; recorded
tool versions in the run log; and **no secret exposure to untrusted
contributions** — meaning fork pull requests get no repository secrets and no
elevated token.

**Source.** `.github/workflows/gates.yml`
**Tests.** None can substitute for running it. Three different things are often
conflated here, and this row keeps them apart:

| Level | Meaning | State |
| --- | --- | --- |
| Implementation review | the workflow file was read property by property against the requirement | DONE — `docs/VERIFICATION.md` §3.4, re-done at `aa49797` for the three new steps |
| Local simulation | the same gate list was executed locally, as the service account | DONE — `bash scripts/check.sh`, §3.0. This exercises the GATES, not the workflow: it says nothing about `permissions:`, action pinning, runner image, or fork-PR secret handling. `scripts/tests/compose-fixture-test.sh` narrows the gap slightly by resolving the deployment under the runner's conditions (§3.9), and narrows it only slightly: it still runs here |
| Hosted CI run | the workflow itself executed on GitHub, with a run URL and log | **DONE, AND PASSING** — 34047025567 at `72bc84c`, 24 passed / 0 failed / 0 BLOCKED (§3.12). Two earlier runs failed and are retained: 34036997074 (§3.8) and 34045148578 (§3.11) |

**Evidence required.** A hosted run: workflow file at a named commit, a run
URL, the recorded tool versions from that run's log, and the outcome of each
gate in it.
**Dependencies.** SW-P1-08, SW-P1-09, SW-P1-11.
**Acceptance.** The hosted run exists and passes, and its gate list matches the
local suite's. **This criterion is unchanged**, and was deliberately not
amended: option B in `docs/VERIFICATION.md` §6.3 proposed relaxing it to "every
gate that could run passed", which would have permanently exempted the container
gates from the only independent host available. Making CI able to satisfy the
criterion was chosen over making the criterion able to accept CI.
**Status at `87bdfaf`.** **VERIFIED**, on hosted run 34394790484 — 28 passed, 0
failed, 0 BLOCKED, `RESULT: all required gates passed`, at
`87bdfafcb9f1690b567f966b677afe965c08af48`, runner Ubuntu 24.04.5 LTS, go
1.26.8, staticcheck 2026.2.1, govulncheck v1.7.0, shellcheck 0.11.0, gitleaks
8.30.0. Both halves of the acceptance criterion hold: the run exists and passes,
and CI executes `scripts/check.sh` itself rather than maintaining a second list,
so the gate list is the local suite's by construction — 28 entries in both
places. `docs/VERIFICATION.md` §3.25.

**It took two runs, and the first is part of the record.** Run 34392469729 at
`a348967` failed — 27 passed, 1 failed — on three cases of the operator-handoff
suite that asserted this household's own deployment values as literals and could
therefore pass on exactly one machine (FINDING-71, `docs/VERIFICATION.md`
§4.22). CI was correct and the test was wrong. That defect had survived 33
commits precisely because no runner had ever executed that suite, which is the
best available argument for why this row is a requirement rather than a
courtesy.

**Status at `7e11419`.** **IMPLEMENTED-UNVERIFIED.** Demoted by §5: the
workflow file and `scripts/check.sh` both changed, and the gate list is now 26
rather than the 24 run 34047025567 executed. Renewal is a hosted run of *this*
tree after an approved push. `docs/VERIFICATION.md` §3.14.

**A mismatch inside this row, recorded rather than resolved by moving the
requirement.** Its *Intended behavior* says "no secret exposure to untrusted
contributions — meaning fork pull requests get no repository secrets and no
elevated token". Its *Acceptance* says only that a hosted run exists, passes,
and matches the local gate list. Those are not the same thing, and the second
does not entail the first: run 34047025567 satisfied the acceptance criterion
in full while demonstrating nothing whatever about fork pull requests.

The disposition, stated explicitly because the tempting move is the wrong one:

* The acceptance criterion **is not reopened**. It was met on its own terms at
  `72bc84c`, and it was met without being relaxed — `docs/VERIFICATION.md` §6.3
  records that a proposal to weaken it was rejected. Reopening a criterion that
  was satisfied would make the record less trustworthy, not more.
* The fork-PR property **stays assigned to Phase 2** (`docs/VERIFICATION.md`
  §6.4 item 10), where it was assigned before this session. It is not being
  moved to a later phase in order to close Phase 1: it was already there, and
  it cannot be demonstrated without a pull request from a fork — which is not
  an artefact of scheduling but of what GitHub will and will not do for a
  branch push.
* What *was* closable was closed now. `scripts/workflow-policy-check.sh`
  (`docs/VERIFICATION.md` FINDING-30) turns seven properties from "reviewed"
  into "asserted on every gate run", including one review had not covered:
  that no attacker-chosen context reaches a `run:` block. That removes the risk
  of the declaration being silently changed. It does not, and cannot, establish
  what GitHub does at run time.

**Superseded status, retained.**
 **VERIFIED** at `72bc84c` — run 34047025567, 24 passed / 0 failed /
0 BLOCKED, `RESULT: all required gates passed`, gate list identical to the local
suite's in content and order. `docs/VERIFICATION.md` §3.12.

| Acceptance component | State |
| --- | --- |
| A hosted run exists, with a run URL and log | **Met.** <(a hosted CI run in the original repository)>, commit `72bc84c` |
| The run records its tool versions | **Met.** Reproduced in full at `docs/VERIFICATION.md` §3.12; every version matches the local set except Compose, which differs and is now recorded on both sides — that difference is FINDING-27 |
| Its gate list matches the local suite's | **Met.** 24 gates, identical and in identical order; `check.sh` is the single definition and CI keeps no second list. The only difference in outcome is the two container gates, BLOCKED locally and PASS in CI |
| The run passes | **Met.** 24 passed, 0 failed, 0 BLOCKED, `RESULT: all required gates passed` |

**A by-product worth recording separately:** `docker build` PASSED on the
runner, executing the ELF linkage and enforcement-absent assertions on Ubuntu
24.04.4 with Docker 28.0.4. SW-P1-20 was already closed by §3.7 against the
operator's host; this is independent corroboration from a second one.

**The blocking sequence**, which is now more specific than "run CI":

1. ~~**Fix FINDING-23**~~ — **DONE at `ef40156`.** A failing gate now reports its
   reason, verdict and cleanup result before any length limit, states any
   truncation, and preserves the omitted material in a sanitized artifact the
   workflow uploads. 62 regression cases plus an end-to-end demonstration
   through `check.sh` itself — `docs/VERIFICATION.md` §4.9 and §3.10.
2. ~~**Then decide the fixture question**~~ — **DONE at `aa49797`: option A.**
   The workflow generates disposable fixtures on the runner rather than
   exempting CI from the container gates. The reasoning for deciding it without
   the old run's cause in hand — including why option B was rejected on its
   merits — is `docs/VERIFICATION.md` §6.3.
3. ~~**Then a passing run**~~ — **DONE at `72bc84c`.** Run 34047025567: 24
   passed, 0 failed, 0 BLOCKED. §3.12. The sequence took three runs and each
   one earned its place: the first produced the run URL and FINDING-23, the
   second produced FINDING-27 and FINDING-28 by diagnosing itself, and the
   third passed.

**All three steps have been observed on a runner.** The `::group::` markers, the
artifact upload, the fixture step (0600 files in a 0700 directory) and its
cleanup behaved as designed, and the container gates executed and passed. The
caveat that stood here — that all of it was a hypothesis about GitHub's
behaviour until a run exercised it — was well placed: run 34045148578 found
FINDING-27, an assertion added by this session that read a Compose field not
every Compose version renders. It was fixed rather than accommodated, and run
34047025567 then passed.

**Two things this row will still not cover when it closes.** Both are recorded
now, because the moment a green run exists they become easy to forget:

* **Fork-pull-request secret handling.** The workflow's strongest security
  property — that a fork PR gets no repository secret and a read-only token —
  cannot be demonstrated by pushing a branch in this repository. It needs a pull
  request from a fork. Until then that property is reviewed, not observed.
* **Agreement with the runtime evidence.** The hosted runner has a Docker
  daemon, so `docker build` and the runtime verification will attempt to run
  there rather than report `BLOCKED`. If either fails on a *hardening
  assertion*, that is not a CI defect to be worked around: it is a disagreement
  with `docs/VERIFICATION.md` §3.7 about builds of the same commit, and it takes
  precedence over closing this row.

**Why the acceptance criterion is probably not satisfiable as written.** This was
set out before the push and the run is consistent with it, but it is a
hypothesis and is labelled as one. `deploy/compose/compose.yaml` binds
`/etc/scamwall/certs/pihole-ca.crt` — a literal absolute path with no
environment override — and a secret file defaulting to
`/etc/scamwall/secrets/pihole_app_password`. Neither can exist on a fresh hosted
runner, so `compose create` should fail there. `docker compose config` does not
catch it: tested against a nonexistent secret path, it exits 0.

**The run neither confirmed nor refuted this.** It failed at the right gate, and
FINDING-23 means the log does not say why. A prediction that matches an outcome
has not thereby been shown to match the mechanism, and this row will not record
that it has until a log shows the verifier's own verdict. `docs/VERIFICATION.md`
§3.8 and §6.3.

Recording the requirement as unsatisfiable and leaving it that way would be the
one unacceptable outcome, so it is written down here rather than left to be
rediscovered on each red run.

**Resolved, and the resolution is narrower than "the problem is fixed".** The
acceptance criterion turned out to be satisfiable after all — run 34047025567
passed at `72bc84c` — and the reasoning below is retained because it is why.
 Two of the three statements above have since been tested rather than
reasoned about, by resolving the real definition under runner conditions with no
`.env` and no operator paths (`docs/VERIFICATION.md` §3.9):

| Statement | Now |
| --- | --- |
| The CA source is a literal absolute path with **no** environment override | **No longer true.** `${SCAMWALL_CA_FILE}` was added at `aa49797`, defaulting to the operator path. Adding it is what makes the row satisfiable without amending it |
| Neither source can exist on a fresh runner | **Established by resolution**, not merely read off the file: with nothing set, both resolve under `/etc/scamwall/` |
| `docker compose config` does not catch it | **Established.** Exits 0 with every bind source absent |
| Therefore the `2a18874` run failed for this reason | **Still not established**, and unrecoverable from that run — it kept no artifact and its log holds only the twenty-five lines `head -25` allowed |

The acceptance criterion **is** satisfiable, and has been satisfied: CI creates
the two fixtures it needs, the verifier makes the same assertions in both
environments, and run 34047025567 passed all 24 gates. The heading of this
paragraph — "probably not satisfiable as written" — was wrong, and is left
standing rather than rewritten, because a prediction edited after the outcome is
not a prediction. What made it wrong was adding one environment override and a
fixture step, neither of which existed when it was written.

### SW-P1-13 — Pre-existing tests preserved and rerun

**Intended behavior.** The functional, security, race, and offline-plan tests
that existed before this work continue to exist and to pass. Any intentional
behavior change is explained.

**Source / Tests.** All `internal/**/*_test.go`; `go test -race ./...`
**Evidence required.** A full `go test -race -count=1 ./...` transcript at the
current commit, plus `go vet`, `gofmt`, and `staticcheck`.
**Dependencies.** None.
**Acceptance.** All pass; no test deleted or weakened without an explanation.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

Demoted and renewed again at `ff2e734`, which changes `cmd/scamwall/e2e_test.go`.
A test was **modified**, and this row's acceptance clause allows that only with
an explanation, so here it is: the credential-length assertion had its haystack
narrowed and its property left intact, demonstrated by mutating the program to
disclose the length both with and without a unit and confirming the check fires
in both cases. The weaker rewrite — matching `"<n> bytes"`-shaped phrases
instead of a bare integer — was considered and rejected, and the mutation that
tells the two apart is recorded. `docs/VERIFICATION.md` §3.19, §4.16.

### SW-P1-14 — The gate suite is deterministic

**Intended behavior.** A gate reports the same result for the same inputs. A
gate that fails at random is not a weaker gate — it is an untrustworthy one,
because the same nondeterminism that produces a spurious failure can produce a
spurious pass, and because a team that learns to re-run a red gate has stopped
reading it.

**Source.** `scripts/check.sh`, `scripts/tests/runtime-verify-test.sh`
**Tests.** Repeated execution of the full suite.
**Evidence required.** A recorded run count with zero unexplained variation,
and a root-cause record for any nondeterminism found and removed.
**Dependencies.** SW-P1-07.
**Acceptance.** No unexplained variation over a recorded number of runs.
**Status.** VERIFIED — root cause found, fixed, and guarded.
`docs/VERIFICATION.md` §4.1 records the whole chain: a `pipefail` +
short-circuiting `grep -q` race that inverted matches. It was a false FAIL here
and a false PASS elsewhere, including a 100% false-clean in the secret scanner
for files above the pipe buffer.
`scripts/tests/pipefail-sigpipe-test.sh` now fails the build if the construction
returns.

**Run counts, stated separately rather than merged**, because the suite changed
size between them and a single figure would imply a measurement that was not
made — `docs/VERIFICATION.md` §3.3:

| Suite | Consecutive runs | Failures |
| --- | --- | --- |
| 237 cases, at `0b083cb` | 500 | 0 |
| 319 cases, at `b6b1769` | 30 | 0 |

The `b6b1769` measurement is shorter: each run of the larger suite takes about
75 seconds, so 500 of them is roughly ten hours. The root cause behind the
original nondeterminism is fixed and independently guarded by
`scripts/tests/pipefail-sigpipe-test.sh`, which is why a shorter repeat is
treated as sufficient to renew rather than as re-establishing the property from
nothing. The shortfall is recorded in `docs/VERIFICATION.md` §7 so it is visible
rather than rounded away.

**Those counts are of the SHELL suites, and this row's claim is wider than
that.** `go test -race ./...` is a required gate in the same suite and has
never been in any of them. It carried an 8% nondeterminism — a two-digit
constant colliding with the ten-digit random component of a `t.TempDir()` path
in `cmd/scamwall/e2e_test.go` — from the moment that assertion was written
until `ff2e734` removed it. FINDING-60. None of that falsifies the
measurements that were taken: it means this row is **under-evidenced** rather
than wrong, and recording it here is the alternative to adjusting the status
quietly. Closing the gap needs a recorded repeat count of the Go gate, which
has not been taken — the standing instruction against determinism campaigns
was not revisited for it. The status is left as it stands, for a reviewer to
decide on. `docs/VERIFICATION.md` §3.19, §4.16.

### SW-P1-15 — The CLI read-only guarantee is tested

**Intended behavior.** The Phase 1 boundary is enforced at the command surface:
`sync --dry-run=false` is refused, `plan` performs no network access, and no
subcommand can mutate Pi-hole. At the baseline `cmd/scamwall` had no test file
at all, so this boundary rested on inspection alone.

**Source.** `cmd/scamwall/main.go`
**Tests.** New: `cmd/scamwall/main_test.go`
**Evidence required.** Tests covering the `--dry-run=false` refusal, the exit
codes, and the absence of an enforcement path.
**Dependencies.** None.
**Acceptance.** Tests present and passing.
**Status.** IMPLEMENTED-UNVERIFIED at the ORDER 6 candidate — **demoted from
VERIFIED**. `cmd/scamwall/main.go` changed and the command surface this row
asserts over gained `propose`. The tests are present and passing —
`main_test.go` unchanged, plus `cmd/scamwall/propose_test.go` covering the new
command's exit codes, its refusal of a `-config` flag, its import graph, its
hostile-field handling and a run of the real process in an empty network
namespace — but a row that asserts a GUARANTEE over the command surface is
renewed by a reviewer accepting that the new command is inside it, not by the
tests passing. `docs/VERIFICATION.md` §4.4, §4.41, §5.12; matrix §5.5.


### SW-P1-16 — Cleanup is part of the verdict

**Intended behavior.** Required cleanup completes BEFORE success is reported;
its failures count towards the verdict; a failed required cleanup makes the
exit status nonzero and names every remaining resource by identifier, without
printing configuration, environment or credential content; the handler runs on
EXIT, INT and TERM without repeating a destructive operation; and it is
idempotent — a resource already removed is not an error, and at most one
removal is attempted per resource however many handlers fire.

At the baseline the success summary was printed first and every cleanup error
was discarded, so a run that left containers behind reported success.

**Source.** `scripts/container-runtime-verify.sh` — `run_cleanup`, `on_exit`,
`on_signal`, `remove_owned`, `HANDLED_RESOURCES`, `summary_and_exit`.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *cleanup as a verdict*:
ordering (the cleanup section precedes the verdict line), a failed container
removal, a failed network removal, a TERM delivered mid-run, a mid-run
verification failure, and a run whose inspections fail so ownership cannot be
established.
**Evidence required.** Each case produces a nonzero exit; the fake daemon's log
shows exactly one removal attempt per resource; leftovers are named.
**Dependencies.** SW-P1-17.
**Acceptance.** As above.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

### SW-P1-17 — Resource ownership is established before deletion

Requirement text and evidence: see SW-P1-06, which this row makes explicit as
its own acceptance item so that a future change to the cleanup path cannot
quietly weaken it. The properties held separately here are:

* the invocation identifier is unpredictable, not derived from the PID;
* every created resource ID is recorded, and a per-invocation ownership label
  is applied;
* pre-existing resources are preserved, including any that coincidentally
  carry a matching label, and their presence blocks creation;
* deletion is by exact ID after re-verifying ownership, never project-wide;
* partial creation is cleaned up by attribution, and unattributable resources
  are preserved and reported.

**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1, on the same four cases cited
under SW-P1-06, which assert preservation of pre-existing resources directly.
Behaviour against a real daemon rode on SW-P1-05, which is closed again at
`c35b1e6`: the operator's run reported 0 cleanup problems and cleanup completion
against a real daemon, and the close-out found no resource attributable to the
recorded build invocation — `docs/VERIFICATION.md` §3.22, and §3.7 for the same
result at `b6b1769`. **The claim that "the host's existing deployment was left
untouched" is withdrawn here too**, for the reason §3.30 gives: no before/after
inventory of the deployment's resources exists, and this run's own clean
leftover enumeration is not one.

### SW-P1-18 — One resolved Compose configuration

**Intended behavior.** A single argument set — private project name, explicit
`--env-file`, the compose file, and the ownership override — resolves the
configuration, creates the container and lists it. Configuration resolution and
parsing failures are checked explicitly and block the run. Expected
interpolated settings are derived from `docker compose config`, Compose's own
interpolation, and then validated separately against the security requirements;
they are never re-derived by grepping `.env` and stripping quotes by hand. The
rendered configuration is kept in a mode-700 temporary directory and is never
printed.

At the baseline creation passed `--env-file` and cleanup did not, so the two
commands could describe different deployments; and the expected supplementary
group came from a hand-rolled `.env` parse that reimplements — and gets wrong —
Compose's precedence rules.

**Source.** `scripts/container-runtime-verify.sh` — `COMPOSE_ARGS`,
`CONFIG_JSON`, `cfg`, the derived-settings section.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *consistent Compose
configuration*: every Compose operation carries the same `--env-file` and
project name; a `.env` value deliberately DIFFERENT from the resolved value
must not be used; resolution failure and unparseable output block the run.
**Evidence required.** As above, plus the mode-700 directory assertion in the
verifier's own output.
**Dependencies.** SW-P1-03.
**Acceptance.** As above.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1.

### SW-P1-19 — The mount set is asserted exactly

**Intended behavior.** `.Mounts` must be a non-empty array before any statement
is made about mounts. The observed set must EQUAL the set derived from the
resolved configuration — mount type, expected resolved source, destination and
read-only status — with nothing missing, nothing extra, and no duplicated
destination. The one runtime-managed exception, the scratch tmpfs at `/tmp`, is
named explicitly and validated separately from `HostConfig.Tmpfs`, where Docker
records its options. Prohibited sources and destinations are rejected.

At the baseline an absent or empty `.Mounts` satisfied both "every mount is
read-only" and "no prohibited mounts" without a single mount being examined,
and nothing checked that the configuration, feed, CA and password mounts were
present at all.

**Scope.** A read-only mount at `/run/secrets/pihole_app_password` does not
prove the container identity can READ it; that depends on the host file's
owner, group and mode. The verifier prints this, and no row here claims it.

**Source.** `scripts/container-runtime-verify.sh` — `EXPECTED_MOUNTS`,
`OBSERVED_MOUNTS`, the mount comparison and tmpfs validation.
**Tests.** `scripts/tests/runtime-verify-test.sh` — *mounts*: empty, absent,
missing configuration mount, missing password mount, extra, duplicated,
writable, wrong source, wrong type, `docker.sock`, `/etc/pihole`, a tmpfs
somewhere other than `/tmp`; plus a pre-fix control showing empty `.Mounts`
satisfied the superseded assertions. And — added at `aa49797` — *mount sources
on the host*: a source that does not exist, a source that is a directory where a
file is required, an absent password file, a world-reachable password file, a
secret source taken from a prohibited path, and a pre-fix control showing the
superseded prohibited-path expression exempted the secret source entirely.
`scripts/tests/compose-fixture-test.sh` additionally resolves the real
definition under hosted-runner conditions and checks the result against this
row's own approved mount set.
**Evidence required.** Each case produces a nonzero exit and names the mount.
**Dependencies.** SW-P1-18.
**Acceptance.** As above.
**Status.** VERIFIED — `docs/VERIFICATION.md` §3.1. Against a real container:
SW-P1-05, which is VERIFIED at `c35b1e6` — the operator's run reported 0 failed
and 0 blocked against a real container built from this source, so the host-side
mount-source assertions this row describes were evaluated against the
deployment's own paths (`docs/VERIFICATION.md` §3.22).

**What `aa49797` added, and why it belongs in this row rather than a new one.**
Every assertion here was about the container's mount TABLE. Docker's default for
a bind whose source does not exist is to create an empty directory and mount
that — so a deployment with no CA and no password file produces a mount table
that satisfies every assertion above, over nothing. That is a false pass in this
row's own subject matter, and it is closed two ways: `bind.create_host_path:
false` in the definition, and a host-side check that each approved source is an
existing regular file. `docs/VERIFICATION.md` §4.10, FINDING-25.

### SW-P1-20 — Static linkage proven by ELF inspection

**Intended behavior.** The build asserts the intended executable properties of
the artifact it produced by parsing its ELF structure: an executable object
type, no `PT_INTERP` and no `.interp` section, no `PT_DYNAMIC` and no
`SHT_DYNAMIC` section, and no `DT_NEEDED` shared library. A missing inspection
tool, an unreadable file, an empty file or a malformed executable is a FAILURE.

At the baseline the assertion was `! ldd BIN 2>/dev/null | grep -q "=>"`, which
passed for a static binary, a missing binary, a corrupt binary and a missing
`ldd` alike.

**Scope.** This proves the binary carries no dynamic linking apparatus. It does
not prove the binary is safe, secret-free, or built from this source.

**Source.** `internal/buildcheck/elfcheck/main.go`; invoked by
`container/Dockerfile` in the build stage.
**Tests.** `internal/buildcheck/elfcheck/main_test.go` — positive control (a
`CGO_ENABLED=0` build compiled by the test), negative controls (hand-built ELF
objects carrying `PT_INTERP` and `PT_DYNAMIC`, a dynamically linked system
binary where one is present), and malformed inputs (missing, empty, non-ELF,
truncated header, a directory). `scripts/container-security-check.sh` asserts
the Dockerfile still invokes it and that no `ldd`-based assertion returns.
**Evidence required.** The controls pass, AND the assertion is observed to run
inside a real `docker build`.
**Dependencies.** Docker daemon access for the second part.
**Acceptance.** Both.
**Status.** **VERIFIED** at `c35b1e601f2543cb666d34888c61b08406446106`, bound to
image `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`.
It was VERIFIED at `b6b1769`, demoted at `aa49797`, re-established at `72bc84c`
on the CI-built image, demoted again at `7e11419` when the Go source moved, and
is now closed on an operator-built image of the current tree:

| Part | Result | At `c35b1e6` |
| --- | --- | --- |
| The controls | 5 test functions — positive, negative and malformed inputs — all passing, `docs/VERIFICATION.md` §3.6, re-run under `go test -race -count=1 ./...` at `e8f8683` (`docs/VERIFICATION.md` §3.21) | **Valid.** `c35b1e6` is documentation-only, so the transcript carries forward |
| The assertion inside a real build | Executed during the operator's `docker build` of `b6b1769` (§3.7); in CI at `2a18874` (§3.8); in the **passing** run 34047025567 at `72bc84c` (§3.12); and now in the operator's `--no-cache` build of `c35b1e6`, which produced `sha256:0efff150…` (§3.22) | **Valid, on this source.** Step A checks the assertion **per build step** — a `CACHED` step fails it, as does one that never reported `DONE` — so "the assertion executed" is established rather than inferred from the log containing its text |

**Both halves rest on one commit and one artifact**, for the first time since
`b6b1769`. Between `72bc84c` and this run they did not: the controls described
the current source while the build half described an image containing a
different executable, which is why the row was IMPLEMENTED-UNVERIFIED
throughout that stretch even though nothing about the checker had changed.

**The same build also asked the artifact directly.** A container created from
the resolved image ID — no network, no mounts, no credential — ran `scamwall
version` and reported the expected commit and `enforcement compiled in false`.
That is not part of this row's acceptance criteria. It corroborates the
`Enforcement` row of §2 against the built executable rather than against the
source, and — together with the preflight's `HEAD`-equals-expected check on a
clean tree — it is what ties the image to a commit at all: the value passed as
`--build-arg COMMIT` is shown to have reached the executable, which is the gap
FINDING-39 named.

**Why the CI run closes this row when it does not close SW-P1-05.** The two
rows were demoted together and are easily assumed to renew together. They do
not. SW-P1-05 asserts *deployment settings* — the supplementary group, the CA
and password sources, the mount set — and CI resolves a different deployment,
so its run does not speak to the operator's. This row asserts a property of the
*executable*, established in the build stage before any deployment exists: the
assertion opens the binary, parses its ELF structure and exits. It reads no
password, no CA, no mount and no group. A difference in those cannot bear on
it, and treating it as though it could was an over-application of the renewal
rule rather than an application of it — `docs/VERIFICATION.md` §3.12.

The assertion is a `RUN` step, so a build exit of 0 does not merely coexist with
it having passed: the build could not have reached that status otherwise. The
same build also executed the enforcement-absent assertion — the binary must
report `enforcement compiled in false` — which is recorded alongside it and
corroborates the `Enforcement` row in §2 against the built artifact rather than
against the source alone.

Neither part closes this row alone. Passing controls prove the checker works;
a green build without them proves an assertion ran but not that it can fail.

**Scope of the closure.** This row is closed for the artifact the assertion ran
against — `sha256:0efff150…` — and for no other image. The extension this
paragraph used to anticipate has happened: `docs/VERIFICATION.md` §6.5 step A
re-executed the assertion during the operator's own build and recorded the
result against that image ID. It was never a precondition for closing the row,
because a requirement is met by the evidence its acceptance names and this one
names a real build rather than a particular host; it is now simply the evidence
in hand.

**Renewal.** Tied to an image. A rebuild re-executes the assertion, and its
result is recorded against the ID the rebuilt image resolves to; §5. A `CACHED` build step is not a
re-execution, which is why §6.5 step A refuses one — by examining the build
step's own lines rather than searching the log for the assertion's text.

---

## 4. Phases 2–6 — forward requirements

These are registered now so that Phase 1 evidence can be linked forward, and so
that the scope of later phases is fixed before implementation begins. All are
`MISSING` until their phase opens. Each will be expanded to the same level of
detail as §3 when its phase is entered; the acceptance criteria below are
binding on that expansion.

### 4.1 Phase 2 — Verified read-only Pi-hole integration

*Entry:* Phase 1 verification accepted for the relevant source and artifacts.

| ID | Requirement | Status |
| --- | --- | --- |
| SW-P2-01 | The permitted API method/path set is defined and enforced, including authentication and session cleanup | IMPLEMENTED-UNVERIFIED |
| SW-P2-02 | TLS verification, destination pinning, redirect restriction, deadlines, bounded responses, and controlled proxy behavior are enforced | IMPLEMENTED-UNVERIFIED |
| SW-P2-03 | Bounded retries, cancellation, rate-limit handling, and credential-safe diagnostics | IMPLEMENTED-UNVERIFIED |
| SW-P2-04 | Secret permissions and access are verified **under the actual container identity** | BLOCKED — see the note below; the blocker is no longer daemon access |
| SW-P2-05 | A disposable Pi-hole integration environment exists, with a documented compatibility scope | MISSING |
| SW-P2-06 | Failure-path tests: correct and rejected credentials, invalid CA, wrong hostname, unavailable server, malformed responses, rate limits, interrupted execution | IMPLEMENTED-UNVERIFIED |
| SW-P2-07 | Operator commands for one controlled live read-only test, not started automatically | IMPLEMENTED-UNVERIFIED |

*Acceptance.* Read-only integration succeeds against the test environment;
approved live evidence is captured **without credentials or session tokens**;
no blocking-state mutation occurs; failure paths terminate within defined
limits; session cleanup is verified including its failure cases; permission and
compatibility assumptions are documented.


#### Phase 2 traceability, reconciled before any further Phase 2 coding

Built by reading every Phase 2 row and acceptance criterion against the code
that exists, rather than by assuming the rows describe it. It exists so that a
later change can be checked against a requirement instead of against a memory,
and so that the **level** of each row's evidence is visible rather than
inferred.

**Four evidence levels, and a lower one never stands in for a higher one:**

| L | Level | What it can establish |
| --- | --- | --- |
| **1** | Static / code review | that the source says what it should. Not that it behaves that way |
| **2** | Unit or fake-server test | that the behaviour is right **against a fake written from `docs/PIHOLE_API_CONTRACT.md`**. If the appliance diverges from that document, level 2 passes and the deployment fails |
| **3** | Disposable-container integration | that it behaves that way against a real Pi-hole that is not the household's |
| **4** | Live-appliance observation | that it behaves that way against the deployment in question |

**Nothing in this repository is above level 2 for any Phase 2 row.** Level 3
needs SW-P2-05's disposable instance, which does not exist; level 4 needs §6.5
steps B, C and D, which have not been run.

| ID | Intended behaviour | Implementation | Existing test | Missing evidence | Real daemon? | Production credential? | Contacts Pi-hole? | Can change Pi-hole state? | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **SW-P2-01** | The permitted method/path set is defined and enforced, authentication and session cleanup included | `pihole/client.go` — `PermittedOperations`, `lookupOperation`, `CheckRedirect`; `transport.go` — `do` consults the table first | `allowlist_internal_test.go` (4); `client_test.go` login/logout/redirect/nesting; `hardening_test.go` concurrency and cross-host; `e2e_test.go` exact ordered sequence | that the appliance answers these four at these paths at all — level 4 | no | no | no | no | **IMPLEMENTED-UNVERIFIED** (L2). FINDING-74 fixed this pass |
| **SW-P2-02** | TLS verification, destination pinning, redirect restriction, deadlines, bounded responses, controlled proxy behaviour | `client.go` — `buildTLSConfig`, `DialContext`, `Proxy: nil`, `CheckRedirect`, `MaxResponseBytes` | wrong CA, hostname mismatch, plaintext, cross-origin, same-origin-unapproved-path, redirect-with-query, oversized, wrong content type; **new**: proxy behavioural + source guard, cross-host delivers nothing | that the household certificate actually chains to the mounted CA and is valid for `pi.hole` — level 4, §6.5 step B | no | no | no | no | **IMPLEMENTED-UNVERIFIED** (L2) |
| **SW-P2-03** | Bounded retries, cancellation, rate-limit handling, credential-safe diagnostics | `transport.go` — `do`, `retryDelay`, `isRetryable`, `parseRetryAfter`, `redactTransportError`, `scrubAPIError` | `TestParseRetryAfter`, `TestRetryDelayNeverExceedsTheCap`, total-timeout, cancellation, rate-limit, credential/SID echo; **new**: teardown bounded past a dead caller context | behaviour against a real rate limiter — level 3 | no | no | no | no | **IMPLEMENTED-UNVERIFIED** (L2) |
| **SW-P2-04** | Secret permissions and access verified **under the actual container identity** | `container-runtime-verify.sh` judges host metadata; `doctor --offline` performs the read | verifier suite (378) for the judgement; `config/secret_test.go` for the read path | **the read itself, by a started container, against the real mounted secret.** §6.5 step C | **yes** | **yes** | no | no | **BLOCKED** (L1/L2 only). The blocker is not daemon access: the verifier deliberately never starts the application, so a passing run is *absent* evidence here, not weak evidence |
| **SW-P2-05** | A disposable Pi-hole integration environment, with a documented compatibility scope | none | none | the whole row | yes | no | to the disposable instance only | to the disposable instance only | **MISSING**. §6.6 is prepared and unexecuted |
| **SW-P2-06** | Failure-path tests: rejected credentials, invalid CA, wrong hostname, unavailable server, malformed responses, rate limits, interruption | `pihole/client_test.go`, `fuzz_test.go`, `cmd/scamwall/e2e_test.go` | all of the above; **new**: trailing content, duplicate keys, unknown-field tolerance, teardown reporting on the failure path | the same failures produced by a real appliance rather than by a fake — level 3 | no | no | no | no | **IMPLEMENTED-UNVERIFIED** (L2). FINDING-72, FINDING-73, FINDING-75 fixed this pass |
| **SW-P2-07** | Operator commands for one controlled live read-only test, not started automatically | `scripts/operator-handoff.sh` steps B, C, D, Z; §6.5 | `operator-handoff-test.sh`, **400 cases**, scripted fake Docker/git/Compose | that the steps behave the same against a real daemon and a real appliance — levels 3 and 4 | no (suite); **yes** (the steps themselves) | no (suite); **yes** for C and D | no (suite); **yes** for B and D | only ScamWall's own session, in D | **IMPLEMENTED-UNVERIFIED** (L2). FINDING-76 tightened step C this pass |

**Reviewed, and four further findings fixed before any push.** FINDING-77 …
FINDING-80, `docs/VERIFICATION.md` §4.30 … §4.33, all in code this same pass
added. One is a security defect: the duplicate-key error introduced by the
FINDING-73 fix **reproduced a peer-chosen key**, and a peer that echoed the
password or the session id as a duplicated key name had it printed to stdout by
`error: %v` with no scrub in the path. Demonstrated reaching stdout against the
superseded code in an isolated copy, then fixed by omitting the key entirely.
The other three: a regression that created its race with a sleep instead of
synchronisation, teardown state surviving into the next session attempt, and a
comment claiming `doctor --offline` constructs no TLS configuration when it
does.

**Validating those four produced FINDING-81** (`docs/VERIFICATION.md` §4.34), an
evidence defect rather than a code defect: the regression cited for "a refused
claim resets nothing" does not discriminate that property — the forbidden reset
passes the entire `-race` suite, because `Logout` clears the session id, the
outcome and the claim in one critical section. The code is unchanged; the
refused-branch constraint is recorded as **ASSERTED-BY-REVIEW** and is not
counted among the discriminated corrections.

**Their effect on the rows above is none.** SW-P2-01 … SW-P2-03, SW-P2-06 and
SW-P2-07 were already IMPLEMENTED-UNVERIFIED at evidence level 2 and stay
there; SW-P2-04 stays BLOCKED; SW-P2-05 stays MISSING. What changed is the
quality of the level-2 evidence, not its level.

**Every change this pass made maps to a row above or to a demonstrated
finding**, and none of it is Phase 2 *acceptance*. The order that produced it
authorised implementation and local testing and nothing else: no live step was
run, no credential was opened, and no request reached the appliance. The live
gaps in the "Missing evidence" column stay **explicitly pending** and are not
narrowed by anything here.


*Notes.* SW-P2-01 through SW-P2-03 and SW-P2-06 are largely implemented at the
baseline (`internal/adapters/pihole/`) and tested against a fake HTTPS server;
what is missing is evidence against anything real.

*Implementation advanced at `7e11419`, without acceptance.* `0d620de` closes
four gaps these rows depend on and that no test previously covered: the
permitted set of API operations is enforced in code before any network activity
and again on every redirect target (FINDING-31); one deadline bounds a retried
operation rather than each attempt separately (FINDING-32); `Retry-After` is
honoured and capped (FINDING-33); and a session cannot be nested, which
previously leaked a seat on the appliance (FINDING-36). `2a0af8f` adds
end-to-end coverage of the CLI against a local fake, asserting the exact ordered
network sequence, that an invalid configuration fails with zero network calls,
and that no credential reaches any stream.

**None of that is acceptance, and SW-P1-05 closing does not supply it.** That
row was the Phase 1 blocker on this phase's entry, and it closed at `c35b1e6`;
every row here still needs evidence against something real, and none has any.
`docs/VERIFICATION.md` §6.5 steps B, C and D are the procedures that would
produce it. They were **not** run: the operator executed the preflight, step A
and the close-out only. They remain pending operator review, and SW-P1-12 is
still open besides.

*Carried into this phase from the `b6b1769` runtime verification.* The verified
run resolved the API destination through the compose default mapping,
`pi.hole:host-gateway`, with `PIHOLE_HOST_IP` unset. What that established is
narrow and worth stating exactly: the pin is applied as configured — a single
`extra_hosts` entry, agreeing between the resolved configuration and the created
container, with no second or conflicting entry. It is a fact about the
container's name resolution and about nothing beyond it.

Three consequences follow, and all three are Phase 2 work rather than Phase 1
gaps:

| Question | Requirement | State |
| --- | --- | --- |
| Is the address behind the mapping reachable, and is it a Pi-hole? | SW-P2-05, SW-P2-07 | **Not attempted.** The deployment container was never started, and the isolated `version` probe that did run had no network; nothing was sent |
| Does TLS verification succeed against it — correct CA, correct hostname, no downgrade or fallback? | SW-P2-02 | **Not attempted against anything real.** Evidenced only against a fake HTTPS server |
| Can the container identity read the mounted password at runtime, and does authentication succeed? | SW-P2-04, SW-P2-01 | **Unverified.** No process has read the file; no session has been established |

SW-P2-04 remains BLOCKED, and the reason has changed. It is no longer blocked
on Docker daemon access — that is resolved. It is blocked because the runtime
verifier deliberately never starts the application, so a passing run says
nothing whatever about credential access. Verifying it requires a *started*
container under the actual container identity, which is a Phase 2 activity,
operator-initiated and never automatic. Passing runtime verification must not be
read as partial evidence for it: it is not weak evidence, it is absent evidence.

Destination connectivity and TLS verification through the mapping are recorded
here as Phase 2 scope so that neither is mistaken for something Phase 1 closed.

### 4.2 Phase 3 — Trusted feeds, policy, and durable state

*Entry:* Earlier applicable gates pass.

| ID | Requirement | Status |
| --- | --- | --- |
| SW-P3-01 | Strict, versioned configuration and feed schemas | IMPLEMENTED-UNVERIFIED |
| SW-P3-02 | Key provisioning, rotation, revocation, sequence/freshness, expiry, and replay protection | MISSING |
| SW-P3-03 | An established signed-update design (e.g. TUF) is evaluated before any custom lifecycle protocol; the decision and its scope are recorded | MISSING |
| SW-P3-04 | Publisher provenance, review, withdrawal, and signing-key separation | MISSING |
| SW-P3-05 | Domain **validity** is separated from **maliciousness** classification; mixed scripts or Unicode alone never establish maliciousness | IMPLEMENTED-UNVERIFIED |
| SW-P3-06 | Exact-domain/subdomain semantics, duplicates, source conflicts, confidence rules, expiry, user exceptions, reason codes | IMPLEMENTED-UNVERIFIED |
| SW-P3-07 | Defined behavior for unavailable, stale, revoked, or invalid feeds, including effect on existing state | MISSING |
| SW-P3-08 | Bounded input processing; fuzzing of critical parsers and normalization | MISSING |
| SW-P3-09 | Atomic state updates, locking, corruption handling, schema migration, storage limits | MISSING |
| SW-P3-10 | Plans are versioned and deterministic, bound to feed, policy/configuration identity, destination identity, creation/expiry, actions, exclusions, and application preconditions | IMPLEMENTED-UNVERIFIED |
| SW-P3-11 | Tests for clock anomalies, interrupted writes, concurrent runs, oversized input, and recovery | MISSING |

*Acceptance.* Tampered, stale, replayed, malformed, and oversized inputs have
tested outcomes; trust changes and withdrawals have tested procedures; policy
precedence is explicit and deterministic; state survives tested interruption
without silently accepting corruption; documentation states that signing
establishes **authenticity only** and never implies detection accuracy.

*Known gap, and its resolution at `7e11419`.* Until that commit,
`internal/domain/domain.go` rejected mixed-script labels inside `Normalize`,
and a rejected record made the whole feed fail to load. That conflated "this
name is not a valid domain" with "this name is suspicious", which SW-P3-05
forbids — and the blast radius was the sharper half of the defect: one
suspicious-looking entry destroyed every unrelated indicator in a signed feed.

The conflation is removed, in both directions:

| Question | Where it is answered now |
| --- | --- |
| Is this a syntactically valid domain, and what is its canonical form? | `domain.Normalize`. Its errors are about syntax only; `ErrMixedScript` no longer exists |
| Is there anything notable about the name? | `domain.Assess` returns observations — `non_ascii`, `punycode_input`, `single_non_latin_script`, `mixed_script` — carrying no judgement |
| Is the domain malicious? | Nothing in the domain package answers this, and its package comment says so |
| Is it eligible for a proposed block? | `policy.Decide`, from the feed's own claims first and the name's signals second |

The disposition is three-valued, not two. A mixed-script name the feed asserts
with high confidence is **neither proposed nor excluded**: it is held for
review, visible, with the signals that put it there and a stable reason code.
Excluding on a signal would silently withdraw protection from entries the
publisher was confident about; proposing it would treat a signal as evidence.
Unicode, a non-Latin script and punycode alone change no disposition, and a
test asserts each of them individually.

Plan format `scamwall-plan-v1` becomes `v2`: the review section is inside the
digest, because a plan that withheld an entry and one that never saw it are
different plans and an operator approving the first must not thereby authorise
the second. Every digest changes, deliberately. **No signing fixture was
regenerated** — none needed to be, and none may be regenerated to make a test
pass.

**SW-P3-05 is `IMPLEMENTED-UNVERIFIED`, not VERIFIED.** The code exists and is
covered by regressions for Cyrillic and Greek lookalikes in four positions,
legitimate Japanese Han+kana combinations, ordinary IDNs in five scripts,
invalid encodings and disallowed input, duplicate and conflicting canonical
forms through the feed validator, stable signal and reason codes, and
determinism over repeated runs. Its **acceptance** is a Phase 3 activity and
Phase 3 has not begun; implementing a requirement early does not accelerate the
phase that accepts it. `docs/VERIFICATION.md` §3.14.


*What ORDER 5 added at `9cf5f10`, and why the row does not move.* The
separation above held in the two directions it was built for. ORDER 5's audit
found a third nobody had looked at: **canonicalisation destroying the evidence
for a signal.** IDNA *deletes* U+00AD, U+200B, U+2060, U+FE0F and U+FEFF
rather than rejecting them, so `ex<ZWSP>ample.com` canonicalised to exactly
`example.com` and — carrying only `non_ascii`, which `policy.Decide` ignores
by design — reached a blocking proposal against the legitimate name. That is
FINDING-82. `invisible_character` now records it and drives review, on the
same reasoning as `mixed_script`. FINDING-83 bounded the raw input, which was
unbounded through IDNA conversion and through the error message.

The row stays **`IMPLEMENTED-UNVERIFIED`** for the reason it always has:
acceptance is a Phase 3 activity and Phase 3 has not begun. Two more defects
found in the same code does not change which phase accepts it.
`docs/VERIFICATION.md` §3.36, §4.35.

*Duplicates, source conflicts, confidence and expiry (SW-P3-06).* ORDER 5
built `internal/observation`, which represents multiple provenance-bearing
observations per indicator, retains conflicting classifications rather than
resolving them, keeps expired and withdrawn evidence in history while removing
it from the live set, and refuses four distinct ways an independent-source
count inflates. The row stays **MISSING**, and the distinction is not
pedantry: SW-P3-06 is about **exact-domain and subdomain semantics, user
exceptions and reason codes in the shipped decision path**, and the package is
not reachable from `cmd/scamwall`. It is a foundation for that requirement,
not that requirement. `docs/VERIFICATION.md` §3.36.

*What ORDER 6 changed, and why the row moves to `IMPLEMENTED-UNVERIFIED`.*
The objection above was precise and is now answered: `scamwall propose` puts
`internal/observation`, `internal/sourceregistry`, `internal/proposal` and
`internal/safetext` on `go list -deps ./cmd/scamwall`, and the semantics the
row names — exact-domain and subdomain matching over canonical DNS labels, an
explicit apex decision, duplicates, retained source conflicts, expiry against a
bound instant, operator exceptions with deterministic precedence, and a closed
reason vocabulary — are implemented there and exercised through the actual
command. §5.5 maps every clause to its implementation and its discriminating
test.

The row is **not** VERIFIED, for two independent reasons. Acceptance of a
Phase 3 row is a Phase 3 activity and Phase 3 has not begun; and every input
that exercises it is synthetic, written by this project for the purpose. No
catalog source is enabled, no provider was contacted, and no real evidence
document exists. `docs/VERIFICATION.md` §4.41, `docs/EVIDENCE_SCHEMA.md`.

*Bounded parsing and fuzzing (SW-P3-08).* Four native fuzz targets now exist —
domain normalisation, configuration decoding, feed decoding, and the
authentication response — and their first runs found two real defects
(`docs/VERIFICATION.md` FINDING-34, FINDING-35). The row stays **MISSING**: it
requires fuzzing of *critical parsers and normalisation* as an accepted,
sustained practice with recorded corpora and durations, and four bounded
campaigns on one afternoon is a start, not that.

*Plan binding gap.* `policy.Plan` at the baseline binds format version, feed
ID, manifest version, entries, and exclusions. SW-P3-10 additionally requires
binding to policy/configuration identity, destination identity, and creation
and expiry times, and requires application preconditions. Those fields do not
exist yet.

### 4.3 Phase 4 — Independent effectiveness evaluation

*Entry:* Feed and policy behavior stable enough for meaningful evaluation.

| ID | Requirement | Status |
| --- | --- | --- |
| SW-P4-01 | A versioned evaluation runner | MISSING |
| SW-P4-02 | Lawful data sourcing and redistribution constraints, documented | MISSING |
| SW-P4-03 | Evaluation labels independent of the feed under evaluation | MISSING |
| SW-P4-04 | Development data separated from held-out data; leakage controls and time boundaries documented | MISSING |
| SW-P4-05 | Dataset includes malicious, legitimate, uncertain, and internationalized domains | MISSING |
| SW-P4-06 | Precision, recall on the dataset, false-positive rate, feed delay, withdrawal delay, resource use | MISSING |
| SW-P4-07 | Sample sizes, uncertainty, label limitations, category-level results reported | MISSING |
| SW-P4-08 | Numerical acceptance thresholds proposed **and recorded** before the acceptance run and before final held-out results are inspected | MISSING |
| SW-P4-09 | Uncertain labels treated explicitly, never folded into a favorable category | MISSING |

*Acceptance.* Reproducible from recorded inputs; predeclared thresholds
assessed honestly; failures lead to remediation and a **fresh** evaluation
procedure; synthetic fixtures are never presented as real-world accuracy
evidence.


*What ORDER 5 built at `9cf5f10`, and why every row stays MISSING.*
`internal/evaluation` is a deterministic, local-only harness implementing
`docs/EVALUATION_PROTOCOL.md` §5.1's definitions exactly: precision over
*additional* labelled proposals, recall over labelled-malicious cases actually
seen, coverage bounding both, Wilson 95% intervals on every proportion, and no
rate at all below ten labelled observations. It reports per indicator type and
per scam category as well as pooled, counts abstentions, unsupported types and
parse failures each as their own number, and emits machine-readable JSON and an
operator report. It can demonstrate improvement **and** regression, and two
controls prove it can fail a rule: `always-propose` scores precision 0.326 at a
0.879 false-positive rate, and `always-abstain` gets recall 0.000, no reportable
precision, and a false negative for every labelled scam.

**None of that moves a row, and the reason is the whole point of Phase 4.**

| Row | Why it is still MISSING |
| --- | --- |
| SW-P4-01 | the runner is versioned and exists, but Phase 4 has not begun and a runner is not an evaluation |
| SW-P4-02 | the rights model exists in `internal/observation` and the registry; the **documented** lawful-sourcing position for an actual evaluation does not |
| SW-P4-03 | the labels were written by this project alongside the rule under test — the exact tautology §3 forbids |
| SW-P4-04 | the partition field exists and the shipped set is `development`; nothing has been held out, because nothing has been evaluated |
| SW-P4-05 | the fixture set has all four classes, but it is 68 **synthetic** cases, not a dataset |
| SW-P4-06 | computed over synthetic fixtures; feed delay, withdrawal delay and resource use are not measured at all |
| SW-P4-07 | reported, over synthetic fixtures |
| SW-P4-08 | no threshold has been proposed, because there is nothing to accept |
| SW-P4-09 | `unknown` is first-class and never redistributed — the one criterion the harness genuinely satisfies, over data that cannot support the claim |

Every `Result` the harness emits carries `NotProtocolConformant` listing these
reasons, and the operator report prints them **above** the numbers. The
harness is a regression instrument for decision rules. It is not an
evaluation, and no number it produces may be cited as evidence of real-world
effectiveness. `docs/VERIFICATION.md` §3.36.

*Standing constraint.* `testdata/feed.json` is a synthetic fixture. It is
evidence about parsing and signature verification. It is not, and must never be
cited as, evidence about detection accuracy.

### 4.4 Phase 5 — Operational read-only pilot

*Entry:* Earlier gates pass and evaluation supports proceeding.

| ID | Requirement | Status |
| --- | --- | --- |
| SW-P5-01 | Pilot scope, observation period, stop conditions, and operator responsibilities defined **before** launch | MISSING |
| SW-P5-02 | Scheduling with overlap prevention, bounded retries, and cancellation | MISSING |
| SW-P5-03 | Healthy, stale, degraded, authentication-failed, and disabled states are distinguished | MISSING |
| SW-P5-04 | Bounded logs and storage; sensitive fields redacted; retention documented | IMPLEMENTED-UNVERIFIED |
| SW-P5-05 | DNS query history is not collected by default | MISSING |
| SW-P5-06 | Tests for restart, power interruption, clock issues, feed outages, credential rotation, and application upgrades | MISSING |
| SW-P5-07 | Dependency/licence inventory and a release-evidence process tied to source and image | MISSING |
| SW-P5-08 | Safe installation, update, diagnostics, and recovery instructions | MISSING |

*Acceptance.* The agreed observation period and review volume are completed;
failures and incorrect proposals are measured and either resolved or explicitly
accepted; no Pi-hole blocking-state changes occur; operational resource and
privacy requirements hold.

### 4.5 Phase 6 — Controlled enforcement

*Entry:* Phases 1–5 pass. **Household enforcement remains disabled pending a
separate review of concrete results.**

| ID | Requirement | Status |
| --- | --- | --- |
| SW-P6-01 | Enforcement is implemented and tested first against disposable Pi-hole instances | MISSING |
| SW-P6-02 | ScamWall-owned entries are tracked without assuming exclusive ownership of pre-existing user entries | MISSING |
| SW-P6-03 | Plan expiry, target identity, policy/feed identity, and observed-state preconditions are rechecked immediately before applying | MISSING |
| SW-P6-04 | Absolute and proportional change limits are enforced | MISSING |
| SW-P6-05 | Operations are journaled and partial success is reconciled | MISSING |
| SW-P6-06 | Repeated application is idempotent | MISSING |
| SW-P6-07 | Concurrent user changes are detected | MISSING |
| SW-P6-08 | Conditional rollback preserves later user changes and reports conflicts | MISSING |
| SW-P6-09 | Interruption between every meaningful mutation step is tested | MISSING |
| SW-P6-10 | Disable, uninstall, and recovery remove **only** attributable changes | MISSING |
| SW-P6-11 | Stale-feed behavior for previously applied entries is defined | MISSING |
| SW-P6-12 | A limited deployment proposal with exact changes, limits, monitoring, and rollback commands | MISSING |
| SW-P6-13 | The structural guards are widened to cover every package that can reach the network | MISSING |

*Acceptance.* Mutation and recovery tests pass in isolated environments; no
user-managed change is overwritten or removed improperly; partial failures
leave understandable, recoverable state; all earlier applicable gates pass
against the enforcement candidate; the operator reviews the concrete deployment
proposal before any live enforcement.

*Structural note.* The Phase 1 design deliberately makes enforcement
*absent* rather than *disabled*: there is no `enforce`-tagged file, so
`go build -tags enforce` fails rather than producing an enforcing binary.
Phase 6 must introduce that file, and doing so is itself a change that demotes
every Phase 1 and Phase 2 row to `IMPLEMENTED-UNVERIFIED` until re-run.

*Guard-scope note (SW-P6-13).* `TestNoMutatingEndpoints` scans only
`internal/adapters/pihole/`, which is correct today because that package is the
only one able to make an HTTP request. Phase 6 changes that. The guard must be
widened in the same change that grants any other package network access — not
afterwards. See `docs/VERIFICATION.md` §5.11.

---

## 5. Evidence renewal rule

An earlier phase's evidence is **not** permanent. A row returns to
`IMPLEMENTED-UNVERIFIED` when any of the following changes in a way that
touches it:

| Change | Rows demoted |
| --- | --- |
| Go source under `internal/` or `cmd/` | Every row whose Source lists that file, plus SW-P1-13 |
| `go.mod` / `go.sum` / toolchain | SW-P1-10, SW-P1-11, SW-P1-13, SW-P5-07 |
| `container/Dockerfile` or `deploy/compose/compose.yaml` | SW-P1-05, SW-P1-06, SW-P1-18, SW-P1-19, and every container row |
| Any `scripts/*.sh` — including `scripts/tests/*.sh` and any script added later | SW-P1-01 … SW-P1-04, SW-P1-06 … SW-P1-09, SW-P1-11, SW-P1-14, **SW-P1-05**, SW-P1-16, SW-P1-17, SW-P1-18, SW-P1-19. That is the **union across all scripts**, not the effect of any one change: which of these rows a given change demotes is decided by §5.1's dependency question. SW-P1-05 belongs here because `scripts/container-runtime-verify.sh` is its verifier; a change to a script that neither produced nor controls a row's evidence demotes that row not at all |
| `.github/workflows/*.yml` | SW-P1-12, and its implementation-review evidence specifically: the file must be re-reviewed property by property, not merely re-run |
| A rebuild (the resulting image must be verified in its own right, whatever ID it resolves to) | SW-P1-05, SW-P1-20, SW-P2-04 |
| Feed schema or trust key | SW-P3-01 … SW-P3-04, SW-P3-07 |
| Detection behavior | Every Phase 4 row |

Applied to `7e11419`, that table demotes SW-P1-12 (workflow and `check.sh`
changed), SW-P1-20 (Go source changed, so the executable the row is about is
not the one the verified image contains), and every Go-source row plus
SW-P1-13 — the last of which the local re-run then renews. SW-P1-05 was already
demoted and its renewal scope has widened. §3 above states each one and its
next step.

#### A correction to the table above, and what it was contradicting

The `scripts/*.sh` row used to enumerate eleven rows and omit four:
**SW-P1-05, SW-P1-16, SW-P1-17 and SW-P1-18**. All four name
`scripts/container-runtime-verify.sh` in their own **Source** field, so all four
were always demoted by a change to **that file**. The enumeration was
incomplete, not the rule.

Three of the four — SW-P1-16, SW-P1-17, SW-P1-18 — were added to the row above
first. **SW-P1-05 was held out while §5.1's question was open, and it is now in
the row with the others**, for the reason the original correction gave: the
verifier is its Source. What was wrong about the first attempt was not adding
the row but what the row was taken to mean — a filename index read as a
dependency boundary. §5.1 records the rule that replaced that reading, and the
row above now says what it is: a union across all scripts, resolved per change
by analysis.

The omission mattered most for SW-P1-05, and the document contradicted itself
about it in three places rather than one:

* §3 demotes SW-P1-05 at `aa49797` and gives the reason as `compose.yaml` **and**
  `scripts/container-runtime-verify.sh` changing — a `scripts/*.sh` demotion, by
  a rule whose table did not list the row.
* `docs/VERIFICATION.md` §3.22 states the renewal condition for both image-bound
  rows as "any change to Go source, `container/Dockerfile`, the compose
  definition or `scripts/*.sh`".
* The reason FINDING-68 is recorded and **not fixed** is that editing the
  verifier's emitted text is a `scripts/*.sh` change that would demote the rows
  the operator's run has just renewed. That argument only holds if a
  `scripts/*.sh` change demotes SW-P1-05 — which the table denied.

So the table is corrected to state the rule and then enumerate it, rather than
enumerating a subset and leaving the rule implied. **Nothing about acceptance
moves.** No row's criterion changed, no new test is required, and no row's
status changes as a result: SW-P1-16, SW-P1-17 and SW-P1-18 ride on the same
`scripts/tests/runtime-verify-test.sh` transcript that renews SW-P1-01 … SW-P1-04,
so every gate run that renewed those renewed these in the same breath. What
changes is that a reader can now derive the demotion set from the table instead
of having to notice that an enumeration is incomplete.

**The general form, as the operator settled it.** A change demotes every row
whose **affected evidence-producing inputs** it touches: the files that produced
the row's evidence, their **transitive dependencies**, the **configuration** the
evidence was resolved against, and the **test controls** that make the evidence
discriminating rather than merely agreeable.

The **Source / Tests** columns and the rows-per-change table above are an
**index** over that rule — a fast lookup, and not the dependency boundary. Two
consequences follow, and both matter:

* A file named in **neither** column can still demote a row, if the row's
  evidence depends on it. A package the shipped binary imports, a library the
  verifier sources, or the resolved Compose configuration are all inputs whether
  or not a Source field lists them.
* A file named in the table demotes **only** the rows whose evidence it actually
  feeds. `scripts/*.sh` is one line in an index, not a claim that every script
  produces every script-bound row's evidence.

Where the index and the dependency analysis disagree, **the analysis wins, and
it is written down** — as an entry in `docs/VERIFICATION.md` naming what was
compared and by which command. An analysis that is not recorded is an opinion,
and this rule does not run on opinions. `docs/VERIFICATION.md` §3.28 is the
first one carried out under this rule and is the worked example.

### 5.1 The question this rule left open, and the operator's answer

**The situation, as it stood.** `87bdfaf` changes
`scripts/tests/operator-handoff-test.sh` and nothing else. Does that demote
**SW-P1-05**, which is VERIFIED on the operator's build of image
`sha256:0efff150…`? The session that raised the question declined to settle it,
on the ground that it was the session the convenient answer would benefit.

**The two readings it was put between, kept because the answer supersedes them
rather than agreeing with either.**

| Reading | Says | Its evidence in this repository |
| --- | --- | --- |
| **Broad** — any script change demotes every script-bound row | SW-P1-05 is demoted, and renewal is another operator build | The practice at `76f3bfd` and `04e7ea4`, each of which changed only `scripts/operator-handoff.sh` and its suite and is recorded as demoting "the script-bound rows again". SW-P1-05 was already open at both, so the question never bit |
| **Per-file** — a row is demoted by a change to a file its own Source names | SW-P1-05 is untouched | The row's own re-opening conditions, written earlier in this document and quoted verbatim: it "re-opens on any change to `container/Dockerfile`, `deploy/compose/compose.yaml`, `scripts/container-runtime-verify.sh` or a rebuild". `scripts/tests/operator-handoff-test.sh` is none of those. The Go row in the table above is already per-file, in those words |

**The answer: neither. Renewal follows the affected evidence-producing inputs.**
The broad reading demotes rows whose evidence a change cannot have touched; the
per-file reading exempts changes that a row's evidence genuinely depends on
merely because no Source field happens to name them. Both are proxies for the
question that actually decides the matter — *did this change touch anything the
row's evidence was produced from?* — and that question is answered by analysis,
against the transitive dependencies, the configuration and the test controls, not
by matching filenames. §5 above now states the rule in those terms, and the
analysis must be recorded where the evidence is.

**Applied to `87bdfaf`, and to every other commit since `c35b1e6`.** The
analysis is `docs/VERIFICATION.md` §3.28, with the commands it ran. Its result:
no evidence-producing input of SW-P1-05 or SW-P1-20 changed. The Dockerfile, the
compose definition, `scripts/container-runtime-verify.sh`, its library,
`scripts/operator-handoff.sh`, the compiled inputs of `./cmd/scamwall` and the
358-case control are all untouched; the one package that did change,
`internal/sourceregistry`, is absent from `go list -deps ./cmd/scamwall`; and
`scripts/tests/operator-handoff-test.sh` is the control for a driver that did not
change. **SW-P1-05 stands at commit `c35b1e6` and image `sha256:0efff150…`, and
no operator rebuild is required for these changes.**

**What that answer does not license.** It does not move the run to `HEAD`: the
row's identities are the commit and the image the operator actually built, and
this document names those wherever the row is stated. It makes **no claim about
digest identity in either direction** — not that a rebuild would reproduce
`sha256:0efff150…`, and not that it would fail to. What it does say is separate
and unconditional: **an image produced by a rebuild has not been verified, and
verification is bound to an identified artifact**, so a rebuild calls for a
fresh run against the ID it resolves to. The earlier claim that a demotion here
"would demand a rebuild that could only produce the same evidence again" is
**withdrawn** for the same reason — it asserted an outcome for a run nobody has
made. It does not exempt `deploy/compose/.env`, which is untracked and therefore
invisible to every command in the analysis.

**And the same answer settles FINDING-68 in the other direction.** The stale note
is printed by `scripts/container-runtime-verify.sh`, which *is* an
evidence-producing input for SW-P1-05 and for SW-P1-16 … SW-P1-19, and the note
is output that the 358-case control asserts against. Under this rule the wording
fix demotes those rows on the merits, so it stays a separately scoped change with
an operator rebuild attached — `docs/VERIFICATION.md` §4.19. A rule that let the
convenient answer through in both places would not have been a rule.

The `scripts/*.sh` row is written to include test scripts and future ones on
purpose. `ef40156` added `scripts/gate-diagnostics.sh` and
`scripts/tests/gate-diagnostics-test.sh`; `aa49797` added
`scripts/tests/compose-fixture-test.sh`. A rule that enumerated the scripts that
existed when it was written would have silently exempted all three, and
`shellcheck (all scripts)` already had exactly that defect once — it read only
the git index, so an unstaged script was "clean" by never having been staged
(`docs/VERIFICATION.md` §4.5).

Renewal means re-running the gate and recording a **new** entry in
`docs/VERIFICATION.md` against the new commit or image ID. Editing the old
entry's commit hash is not renewal.

The converse also needs saying, or the rule becomes unusable: **evidence is
tied to the last commit that changed a gate input.** A documentation-only
commit changes none, so the record carries forward rather than requiring a
re-run — otherwise writing down the evidence would itself invalidate it.

**Image-bound rows carry a second identity.** SW-P1-05 and SW-P1-20 are tied to
an image ID *and* to a commit. Both must hold. At `b6e70f4`:

| Row | Bound to | Holds? |
| --- | --- | --- |
| SW-P1-20 | image `sha256:d7c44949…`, commit `72bc84c` | **Yes.** `b6e70f4` changes documentation only, so the commit half is intact; the image half is the artifact the assertion ran against |
| SW-P1-05 | image `sha256:b95cc07c…`, commit `b6b1769` | **No.** The commit half lapsed at `aa49797`, which changed the verifier and `compose.yaml` — so the row is `IMPLEMENTED-UNVERIFIED` in §3 rather than carried forward on the image alone |

At `7e11419` neither holds. SW-P1-20's commit half lapsed when the Go source
changed, and no image had been built from this source on any host, so both
identities were absent rather than merely stale. A rebuild was the only route,
and `docs/VERIFICATION.md` §6.5 step A is that rebuild.

**At `c35b1e6` both hold, on the same identities.** The operator ran step A and
returned its result (`docs/VERIFICATION.md` §3.22):

| Row | Bound to | Holds? |
| --- | --- | --- |
| SW-P1-05 | image `sha256:0efff150…`, commit `c35b1e6` | **Yes.** The image was built from that commit on the deployment's host, and the verifier ran against the resolved image ID with the deployment's own configuration |
| SW-P1-20 | image `sha256:0efff150…`, commit `c35b1e6` | **Yes.** The controls pass on this source and the assertion executed, uncached, inside the build that produced this image |

This is the first commit at which both rows are bound to a single artifact since
`b6b1769`. That is worth stating because the two rows have been closed on
*different* images before — SW-P1-20 on the CI build, SW-P1-05 on nothing — and
a reader scanning for "VERIFIED" would not otherwise see the difference.

A rebuild from the same commit produces an image that **has not been verified**,
however confident one is that it is equivalent: verification is bound to an
identified artifact, and the artifact a rebuild produces has not been through
it. That is the whole of the requirement, and it holds without any claim about
whether the digest would differ. Rebuild, then re-run `docs/VERIFICATION.md`
§6.1 and record the ID it resolves to.

**A row bound to a CI-built image is not thereby a weaker row.** What matters is
whether the artifact the evidence names is the artifact the requirement is
about. SW-P1-20 is about an executable's linkage, and CI built a real one.
SW-P1-05 is about a deployment's settings, and CI resolved a different
deployment. The distinction is the requirement's, not the runner's.

---

### 5.2 Applied at `9cf5f10` — ORDER 5

| Row | State at `9cf5f10` | Why, and what renews it |
| --- | --- | --- |
| SW-P1-05 | **IMPLEMENTED-UNVERIFIED** | Demoted. `internal/domain`, `internal/feed` and `internal/policy` are on `go list -deps ./cmd/scamwall`, so the executable differs from the one in image `sha256:0efff150…`. Renewal: `docs/VERIFICATION.md` §6.5 step A, against the final commit |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Demoted on the commit half for the same reason. The ELF controls (§3.6) are untouched and pass locally. Renewal: the assertion observed inside a real `docker build` of this source |
| SW-P1-13 | **IMPLEMENTED-UNVERIFIED** | Demoted by the Go change, and renewed on this tree's own transcript: `docs/VERIFICATION.md` §3.35 |
| SW-P1-10 | **unchanged** | The critical-path review covers credential handling, the network client, the enforcement boundary and the decision path. `internal/domain`, `internal/feed` and `internal/policy` changed, and `docs/VERIFICATION.md` §5.9 and §5.11 review domain normalisation and the decision path — so this row IS touched. Its transcript is §3.35, the findings at §4.35, and the review entries themselves, updated at this commit. The credential and network paths are byte-identical |
| SW-P1-12 | **unchanged** | `.github/workflows/gates.yml` is not changed and `scripts/check.sh` gained no gate. The gate list this tree runs is the 28 a hosted run executes. It remains demoted for the reason it already was |
| every script-bound row | **unchanged** | No `scripts/*.sh` changed. All seven shell suites pass at identical case counts — 963 cases, 0 failed |
| every container row | **unchanged** | No Dockerfile and no Compose definition changed |

**The two new packages move nothing.** `internal/observation` and
`internal/evaluation` are not on `go list -deps ./cmd/scamwall`, so the
executable does not carry them and no image-bound row is affected by their
existence. They are in the same position `internal/sourceregistry` has been in
since `9bbf284`, and are demoted-by-nothing for the same reason: SW-P1-13 is
the only row whose Source could name them, and it is renewed on this tree.

The demotion of SW-P1-05 and SW-P1-20 here is **not contested** and needs no
§5.1-style analysis. §5.1 settled the case where a change touches no input a
row's evidence came from; this is the opposite case, where the change is to
the executable the evidence is about. `docs/VERIFICATION.md` §3.37 is the
trace.


---

### 5.3 Applied at `0ff221c` — ORDER 5 REVIEW CORRECTIONS

| Row | State at `0ff221c` | Why, and what renews it |
| --- | --- | --- |
| SW-P1-05 | **IMPLEMENTED-UNVERIFIED** | **Unchanged, and not renewed here.** It was demoted at `9cf5f10` and stays demoted. This pass changed no compiled input of `./cmd/scamwall`: the executable is byte-identical to the one at `3152485` (§3.38), which is already not the one in image `sha256:0efff150…`. Renewal: `docs/VERIFICATION.md` §6.5 step A, against the final commit |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Unchanged, for the same reason. The ELF controls are untouched and pass locally; the row is about the executable inside a real image, and no image was built |
| SW-P1-12 | **IMPLEMENTED-UNVERIFIED** | Unchanged. `.github/workflows/gates.yml` is not changed and `scripts/check.sh` gained no gate. It remains demoted because no hosted run has executed this tree, and nothing was pushed |
| SW-P1-13 | **IMPLEMENTED-UNVERIFIED** | Demoted by the Go change, and renewed on this tree's own transcript: `docs/VERIFICATION.md` §3.38. Go test cases 702 → 879, 0 failed, 0 skipped |
| SW-P1-10 | **unchanged** | The critical-path review covers credential handling, the network client, the enforcement boundary and the decision path. None of those files changed: `internal/domain` changed only `bounds_test.go`, and `internal/adapters/pihole`, `internal/config` and `internal/audit` are untouched |
| every script-bound row | **unchanged** | No `scripts/*.sh` changed. All seven shell suites pass at identical case counts to §3.35 |
| every container row | **unchanged** | No Dockerfile and no Compose definition changed |

**The three non-consumed packages still move nothing, and a fourth joins them.**
`internal/observation`, `internal/evaluation`, `internal/sourceregistry` and the
new `internal/repotext` are **none of them on `go list -deps ./cmd/scamwall`**,
so the executable does not carry them and no image-bound row is affected by
their existence or their correction. That list is checked in §3.38 rather than
asserted.

**`internal/observation` and `internal/evaluation` have no production
consumer.** That was true at `9cf5f10` and is still true here. Correcting
nineteen defects in them does not give them one, and none of the corrections
should be read as moving either package toward the shipped decision path. A
package reached only by its own tests is a foundation, not a delivered
capability.

**`internal/repotext` also has no production consumer, by design.** It is a
repository control: its only caller is `go test`, which `scripts/check.sh`
runs. It asserts a property of the tracked text and nothing about the running
system, and it is not a requirement's Source.

**No phase advances.** Phase 3 and Phase 4 requirements are exactly where
`9cf5f10` left them. FINDING-92 through FINDING-103 correct an evaluation
harness and an observation model that remain Phase 3 *foundations*; SW-P3-06 in
particular stays **MISSING**, because it is about exact-domain and subdomain
semantics, user exceptions and reason codes **in the shipped decision path**,
and nothing in this pass puts either package on that path.

**Historical evidence is preserved.** The record for image
`sha256:0efff150…` at source `c35b1e6`, and the hosted runs 34047025567,
34394790484 and 34396978547, are evidence about those artifacts and those runs.
They still exist and are still what they were. Nothing here withdraws, restates
or re-dates them; they are simply not evidence about this tree.

---

### 5.4 Applied at `49fab8a` — ORDER 5 CORRECTIONS, evidence binding and diagnostic trust

| Row | State at `49fab8a` | Why, and what renews it |
| --- | --- | --- |
| SW-P1-05 | **IMPLEMENTED-UNVERIFIED** | **Unchanged, and not renewed here.** Demoted at `9cf5f10` and still demoted. This pass changed no compiled input of `./cmd/scamwall`: built `-trimpath -buildvcs=false CGO_ENABLED=0` the executable is byte-identical at `80e4707` and `49fab8a`, SHA-256 `15fabb9e…`. Only `docs/VERIFICATION.md` §6.5 step A renews it |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Unchanged, same reason. The ELF controls are untouched and pass locally; the row is about the executable inside a real image, and no image was built |
| SW-P1-12 | **IMPLEMENTED-UNVERIFIED** | Unchanged. `.github/workflows/gates.yml` is not changed and `scripts/check.sh` gained no gate. No hosted run has executed this tree and nothing was pushed |
| SW-P1-13 | **IMPLEMENTED-UNVERIFIED** | **Demoted by the Go change and renewed on this tree's own transcript.** The STATUS does not transition — it was IMPLEMENTED-UNVERIFIED at `80e4707` and is IMPLEMENTED-UNVERIFIED here. What is new is the evidence: Go test cases 879 → 957, 0 failed, 0 skipped. `docs/VERIFICATION.md` §3.39 |
| SW-P1-10 | **unchanged** | The critical-path review covers credential handling, the network client, the enforcement boundary and the decision path. None of those files changed: every change is in `internal/evaluation`, which is on none of those paths |
| every script-bound row | **unchanged** | No `scripts/*.sh` changed. All seven shell suites pass at identical case counts to §3.38 — 963 cases, 0 failed |
| every container row | **unchanged** | No Dockerfile and no Compose definition changed |

**A status transition and new evidence are different things, and the previous
account conflated them.** The record for `0ff221c` headed itself *"No row
moved. No phase advanced. Nothing was renewed"* and then carried a table headed
*"Rows that did move"* listing SW-P1-13 as renewed. Both sentences cannot be
true. The accurate account, which holds for that pass and for this one:

* **No row changed state.** SW-P1-13 was IMPLEMENTED-UNVERIFIED before and
  after. A Go change demotes it and the local re-run renews it in the same
  pass, so the state a reader sees never differs.
* **One row's evidence was renewed.** SW-P1-13 now rests on this tree's
  transcript rather than on the previous one. That is a new citation under an
  unchanged status, not a promotion.
* **Nothing was promoted.** No row went from IMPLEMENTED-UNVERIFIED to
  VERIFIED, and no phase advanced.

"No row moved" is therefore correct and "Nothing was renewed" is wrong; the
heading *"Rows that did move"* named a renewal rather than a transition.

**`internal/evaluation` still has no production consumer.** It is not on
`go list -deps ./cmd/scamwall`, which names `internal/audit`,
`internal/config`, `internal/adapters/pihole`, `internal/domain`,
`internal/feed` and `internal/policy` and nothing else. That list is run in
§3.39 rather than asserted. Four more defects corrected in a package the binary
does not carry give it no consumer and move it no closer to the shipped
decision path.

**The rebuild obligation is unchanged, and is not measured from this order's
baseline.** It is owed from the current candidate back to the operator-tested
commit `c35b1e601f2543cb666d34888c61b08406446106` and image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`.
Establishing that *this* pass added no further executable drift does not
discharge drift that already existed before `80e4707`. The byte-identical
binary narrows nothing.

**Nothing in this pass is an operator step.** No rebuild was performed or
authorised, nothing was pushed, no Docker daemon was contacted, no Pi-hole was
contacted, no credential was accessed, no feed was fetched, no provider was
contacted, and no source or enforcement was enabled.

### 5.5 Applied at the ORDER 6 candidate — an offline provenance-to-proposal path

**This pass differs from §5.2, §5.3 and §5.4 in one way that matters: the
compiled input of `./cmd/scamwall` CHANGED.** Every previous ORDER 5 pass
touched `internal/evaluation`, which the binary does not carry, and each one
could and did say the executable was byte-identical. This one adds a
subcommand.

Built `-trimpath -buildvcs=false` with `CGO_ENABLED=0`:

| tree | SHA-256 of `./cmd/scamwall` |
| --- | --- |
| `005e06d` (baseline) | `15fabb9e9c2d305b6af33f9ac704008009388afea30fb7d7292517eb402f93d2` |
| this candidate | `228e10a87a2cd8ac6c837099834a50808a288d7279f0cf5f2ede1a7765b70092` |

| Row | State | Why, and what renews it |
| --- | --- | --- |
| SW-P1-05 | **IMPLEMENTED-UNVERIFIED** | Demoted since `9cf5f10` and **the gap has widened**: the executable is no longer the one the verified image contains, and now demonstrably so rather than incidentally. Only a rebuild and `docs/VERIFICATION.md` §6.5 step A renew it |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Same, and specifically: the ELF controls pass locally on the new binary, and the row is about the executable inside a real image. No image was built |
| SW-P2-04 | **BLOCKED** | Unchanged and unchanged in reason. It needs a *started* container under the real container identity, which is operator-initiated |
| SW-P1-10 | **IMPLEMENTED-UNVERIFIED** | **Demoted, and this is a transition.** The row's areas include feed verification and the decision path, and this pass adds a second signed-document verifier (`internal/feed/evidence.go`) and a second decision path (`internal/proposal`) reachable from the command. The recorded review in `docs/VERIFICATION.md` §5 does not cover either. Renewed by extending that review to the new surface — see §5.12 there, written in this pass, which is the review and not a promise of one |
| SW-P1-13 | **IMPLEMENTED-UNVERIFIED** | Demoted by the Go change and renewed on this tree's own transcript. **The status does not transition**; the evidence does. Go test cases counted at both commits, 0 failed, 0 skipped |
| SW-P1-15 | **IMPLEMENTED-UNVERIFIED** | **Demoted, and this is a transition from VERIFIED.** Its Source is `cmd/scamwall/main.go`, which changed, and the command surface it asserts over gained a subcommand. Renewed by `cmd/scamwall/propose_test.go` plus the existing `main_test.go` on this tree; the row returns to VERIFIED only when a reviewer accepts that the new command is inside the read-only guarantee, which is a review and not a test run |
| SW-P1-12 | **IMPLEMENTED-UNVERIFIED** | Unchanged. No workflow changed and `scripts/check.sh` gained no gate. No hosted run has executed this tree and nothing was pushed |
| every script-bound row | **unchanged** | No `scripts/*.sh` changed |
| every container row | **unchanged** | No Dockerfile and no Compose definition changed |
| SW-P3-01 | **IMPLEMENTED-UNVERIFIED** | Unchanged in status. A second document type is added under an explicit new schema version; the v1 feed schema and trust key are untouched, and each loader refuses the other's version |
| SW-P3-05 | **IMPLEMENTED-UNVERIFIED** | Unchanged in status, with new evidence. The separation is now asserted at a second surface: `TestASignalIsNotEvidence` measures Unicode, punycode, a single non-Latin script and legitimate Japanese as proposing normally, and mixed-script and invisible-character names as preventing a proposal without ever establishing maliciousness. Acceptance is still a Phase 3 activity |
| SW-P3-06 | **MISSING → IMPLEMENTED-UNVERIFIED** | **The one status transition this pass earns.** See below |
| SW-P3-08 | **MISSING** | Unchanged. The new loader carries file, record-count, field and diagnostic bounds, and the row wants sustained fuzzing as a practice with recorded corpora and durations. Bounds are not that |
| SW-P3-09 | **MISSING** | Unchanged and untouched. `propose` persists nothing; there is no durable state to update atomically |
| SW-P3-10 | **MISSING** | Unchanged and untouched. `propose` emits proposals, not a plan, and does not modify `policy.Plan` |
| every Phase 4 row | **MISSING** | Unchanged. Stage G's numbers are synthetic development results over fixtures this project wrote, which is the tautology EVALUATION_PROTOCOL.md §3 forbids counting. A new fixture set and a new control do not make a synthetic result held-out |

#### SW-P3-06, and exactly what the transition rests on

The row was MISSING, and §4.2 recorded a precise reason: `internal/observation`
is "a foundation for that requirement, not that requirement", because SW-P3-06
is about those semantics **in the shipped decision path** and the package "is
not reachable from `cmd/scamwall`".

That objection is now answered. `go list -deps ./cmd/scamwall` names
`internal/observation`, `internal/sourceregistry`, `internal/proposal` and
`internal/safetext`, and `scamwall propose` exercises all four.

Clause by clause:

| clause | where it is implemented | where it is measured |
| --- | --- | --- |
| exact-domain semantics | `proposal.Covers`, `ScopeExact` | `TestMatchingIsOverLabelsAndNotOverCharacters` |
| subdomain semantics, apex documented | `ScopeSubdomains`, and its doc comment states the apex decision and why | same, plus `TestTheHouseholdOutranksEverySource/a subdomain exception reaches a child and not the apex` |
| duplicates | `observation.Store.Add` | `TestOneSourceSayingSomethingThreeTimesIsOneSource`, `TestTheSameRecordTwiceIsNotTwoObservations` |
| source conflicts | `Indicator.Conflicted`, reported and never resolved | `TestSourcesThatDisagreeAreReportedRatherThanResolved` |
| confidence rules | provider confidence carried, never fused; `min_independent_sources` required with no default | `TestAPolicyIsRefusedRatherThanDefaulted` |
| expiry | `Indicator.Current(at)`, instant bound into the report | `TestWithdrawnAndExpiredEvidenceAreNamedSeparately`, `TestLivenessIsDecidedAgainstTheRecordedInstantAndNothingElse` |
| user exceptions | `Policy.MatchException`, precedence by specificity | `TestExceptionPrecedenceIsBySpecificity`, `TestTheHouseholdOutranksEverySource` |
| reason codes | `proposal.AllReasons`, closed and enumerated by a test | `TestEveryReasonThisPackageCanEmitIsInTheVocabulary` |

**Why IMPLEMENTED-UNVERIFIED and not VERIFIED.** Two reasons, and either alone
is sufficient:

1. **Acceptance of a Phase 3 row is a Phase 3 activity, and Phase 3 has not
   begun.** Implementing a requirement early does not accelerate the phase that
   accepts it. This is the same reason SW-P3-05 has stood at
   IMPLEMENTED-UNVERIFIED since `7e11419`.
2. **Every input that exercises it here is synthetic.** No catalog source is
   enabled, no provider was contacted, and no real evidence document exists.
   The semantics are demonstrated over documents this project wrote for the
   purpose.

**What the transition does not carry with it.** No phase advances. SW-P3-02,
SW-P3-03, SW-P3-04, SW-P3-07, SW-P3-08, SW-P3-09, SW-P3-10 and SW-P3-11 are
untouched, and Phase 3 acceptance requires all of them.

#### The rebuild obligation, unchanged in nature and larger in size

It is owed from the current candidate back to the operator-tested commit
`c35b1e601f2543cb666d34888c61b08406446106` and image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`.
Previous passes could at least say they added no executable drift. This one
adds some, deliberately, and says so.

#### Nothing in this pass is an operator step

No rebuild was performed or authorised, nothing was pushed, no Docker daemon
was contacted, no Pi-hole was contacted, no credential was accessed, no feed
was fetched, no provider was contacted, no trust key was changed, and no source
or enforcement was enabled.

### 5.6 Applied at the ORDER 7 candidate — correcting the offline proposal boundary

Ten findings in the surface ORDER 6 built, nine corrected and one open. That
is the fact this section is mostly about: **a pass that finds ten defects in a
path is a reason for less confidence in that path, not more**, and no row is
promoted here.

Built `-trimpath -buildvcs=false` with `CGO_ENABLED=0`:

| tree | SHA-256 of `./cmd/scamwall` |
| --- | --- |
| `005e06d` (ORDER 6 baseline) | `15fabb9e9c2d305b6af33f9ac704008009388afea30fb7d7292517eb402f93d2` |
| `dd38a72` (ORDER 6 ending) | `228e10a87a2cd8ac6c837099834a50808a288d7279f0cf5f2ede1a7765b70092` |
| this candidate | see §3.41 |

| Row | State | Why, and what renews it |
| --- | --- | --- |
| SW-P1-05 | **IMPLEMENTED-UNVERIFIED** | Unchanged and still demoted. The compiled input changed again, so the gap between the executable and the verified image `sha256:0efff150…` is wider still. Only a rebuild and §6.5 step A renew it |
| SW-P1-20 | **IMPLEMENTED-UNVERIFIED** | Same |
| SW-P2-04 | **BLOCKED** | Unchanged in state and in reason |
| SW-P1-10 | **IMPLEMENTED-UNVERIFIED** | Unchanged in state — demoted at ORDER 6 and still demoted. The evidence is renewed and **three of its dispositions are revised**: output hygiene, mutation after authentication, and bounds were each recorded "adequate" and each had a defect. §5.13 |
| SW-P1-13 | **IMPLEMENTED-UNVERIFIED** | Demoted by the Go change and renewed on this tree's own transcript. The STATUS does not transition; the evidence does |
| SW-P1-15 | **IMPLEMENTED-UNVERIFIED** | Unchanged in state. `cmd/scamwall/propose.go` and its tests changed, so the evidence is renewed on this tree. It returns to VERIFIED when a reviewer accepts that the command is inside the read-only guarantee, which is a review and not a test run |
| SW-P1-12 | **IMPLEMENTED-UNVERIFIED** | Unchanged. No workflow changed and `scripts/check.sh` gained no gate. Nothing was pushed |
| every script-bound row | **unchanged** | No `scripts/*.sh` changed |
| every container row | **unchanged** | No Dockerfile and no Compose definition changed |
| SW-P3-01 | **IMPLEMENTED-UNVERIFIED** | Unchanged in state. The evidence and authority schemas gain a duplicate-key refusal — a strictness the row is about — and the report's binding gains three fields. No schema version changed |
| SW-P3-05 | **IMPLEMENTED-UNVERIFIED** | Unchanged and untouched. The separation is unaffected by every finding here |
| SW-P3-06 | **IMPLEMENTED-UNVERIFIED** | **Unchanged in state, and the evidence behind it is materially better.** ORDER 6 moved it here; ORDER 7 found that its rights refusals disclosed what they refused, its aggregator grants inflated corroboration, and two of its bindings cited the wrong thing. It is not promoted, and the reasons ORDER 6 gave for not promoting it — Phase 3 acceptance is a Phase 3 activity, and every input is synthetic — are both unchanged |
| SW-P3-08 | **MISSING** | Unchanged. `internal/strictjson` adds an ambiguity refusal and the row still wants sustained fuzzing as a practice |
| every Phase 4 row | **MISSING** | Unchanged. No evaluation number moved |

#### No row is promoted, and one new gap is recorded

FINDING-128 is **OPEN**: `internal/sourceregistry` carries an uncorrected copy
of the duplicate-key walk and echoes an attacker-chosen key in a decode
diagnostic. It is on the critical path, because `scamwall propose` reads the
registry. §4.42.7 records what is demonstrated and what is present-but-masked,
at those two different strengths.

#### The boundaries these findings do not move

* **ORDER 6's gate run remains what it was**: 26 passed, 0 failed, 2 Docker
  BLOCKED, direct exit 1, at `650434d` and repeated at `4d22168`. A
  historical INCOMPLETE run, bound to those commits.
* **The operator evidence at `c35b1e601f2543cb666d34888c61b08406446106`,
  image `sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`,
  remains evidence for that artifact only.** It is further from this candidate
  than it was.
* **Local synthetic tests establish no real-provider accuracy, no passing
  Docker gate, no hosted run and no product effectiveness.** Nothing in this
  pass touches any of them.

#### Nothing in this pass is an operator step

No rebuild was performed or authorised, nothing was pushed, no Docker daemon
was contacted, no Pi-hole was contacted, no credential was accessed, no feed
was fetched, no provider was contacted, no trust key was changed, and no
source or enforcement was enabled. **No operator rebuild is recommended**: the
order withholds that recommendation until the rights, authenticated-identity
and aggregator-counting questions have passing controls and an independent
reviewable diff, and the diff is what this candidate produces for review.

## 6. Requirements deliberately not held here

Two things belong elsewhere and are linked rather than duplicated:

* **API behavior and divergence** — `docs/PIHOLE_API_CONTRACT.md`. That
  document is the contract; this matrix only records whether the client obeys
  it.
* **Threats and residual risk** — `docs/THREAT_MODEL.md` and
  `docs/SECURITY_BOUNDARIES.md`. A threat is not a requirement; the control
  answering it is.

---

## 5.7 ORDER 7 second pass — renewal at `d104949`

Evidence for this pass is `docs/VERIFICATION.md` §4.43. The rule applied is
§5.6's: a row whose evidence depends on an input that changed is **renewed on
this tree or it is not claimed**, and a row bound to an image is bound to that
image and moves only when a new one is verified.

### 5.7.1 No row is promoted

Nothing in this pass promotes a requirement. Two new capabilities were added
and both arrive **IMPLEMENTED-UNVERIFIED**, for the same reason: their claims
are about a real appliance and a real household, and this pass established
neither.

| row | state | why |
| --- | --- | --- |
| **SW-P1-10** (proposal boundary) | renewed on this tree, **not promoted** | `internal/proposal` changed: a policy schema addition, a new decision layer, a wider policy digest. Every §4.42 control still passes and `-race` is clean, so the evidence is renewed at `d104949`. It is not stronger than it was |
| **SW-P1-13**, **SW-P1-15** | renewed on this tree | the gate suite ran at this commit: 26/0/2-BLOCKED, direct exit 1 |
| **SW-P1-05**, **SW-P1-20** and every other image-bound row | **unchanged, and further away** | bound to `sha256:0efff150…` at `c35b1e6`. The compiled input changed again. No image was built; both Docker gates are BLOCKED |
| **SW-P2-04** (live Pi-hole read) | **PARTLY ESTABLISHED for the first time, and NOT claimed complete** | see §5.7.2 |
| **SW-P3-06** | stays IMPLEMENTED-UNVERIFIED | untouched by this pass |

### 5.7.2 SW-P2-04 — the first real contact, stated at its actual strength

The row has read "**Not established.** Only a fake HTTPS server has been
exercised" since it was written. That is no longer accurate, and the accurate
replacement is narrower than it looks.

**Established, at `d104949`, against the Pi-hole installed on this host:**

* the client resolves, dials and completes a TLS handshake against the real
  appliance under `ServerName: pi.hole`, with the pinned private CA and the
  system trust store not consulted;
* the certificate presented verifies against `/etc/scamwall/certs/pihole-ca.crt`
  — checked twice, by the client and independently by `openssl verify`;
* `GET /api/auth` completes and the appliance answers `401`, which `doctor`
  reports as `reachable over TLS; authentication required`;
* a name that resolves to a different machine is **refused**, not completed —
  measured against a real mismatched peer, which §3.7 had only asserted
  (`docs/VERIFICATION.md` §4.43.4.1; FINDING-130 was raised on this and
  WITHDRAWN, §4.43.4.2).

**Not established, and the row stays open:**

* **authentication.** `POST /api/auth` has never been sent to a real appliance.
  The credential is unreadable by the executing account and permissions were
  not widened;
* **any state read.** `GET /api/domains/deny/exact` has never reached a real
  appliance;
* **session teardown against a real appliance.** No session was ever created,
  so none was destroyed;
* **`shadow` end to end.** It stops at the credential, before any request.

The row therefore moves from **Not established** to **PARTLY ESTABLISHED —
unauthenticated reachability and TLS identity only**. It does not become
VERIFIED and must not be cited as evidence that ScamWall can operate against a
Pi-hole.

### 5.7.3 Two new rows

| id | requirement | state | evidence |
| --- | --- | --- | --- |
| **SW-P2-10** | The household states the terms of unattended blocking before any of it happens, and a value they have not chosen is visibly unresolved rather than defaulted | **IMPLEMENTED-UNVERIFIED** | `internal/proposal/automatic.go`; 20 boundary tests in `automatic_test.go`, all through the real signed-document path. **Unverified because no household has filled one in.** The format exists; whether it asks for the right nine things is a product question this repository cannot answer alone |
| **SW-P2-11** | ScamWall can state the exact change it would request of a Pi-hole it has read, bound to what it actually saw, without being able to request it | **IMPLEMENTED-UNVERIFIED** | `internal/shadow`; 16 unit tests; `cmd/scamwall/shadow_test.go` drives the real command against a request-recording server. **Unverified against a real appliance**: the command has never completed one, for the credential reason in §5.7.2 |

### 5.7.4 The boundaries, restated where a reader will hit them

* **ORDER 6's `26 passed, 0 failed, 2 BLOCKED, exit 1` is bound to `650434d`
  and `4d22168`.** This candidate produced a run of the same shape at
  `d104949`. They are different runs over different trees.
* **The operator evidence at `c35b1e6` / `sha256:0efff150…` remains evidence
  for that artifact only**, and this tree is further from it.
* **A passing local fake, a Docker image build and a read from the installed
  Pi-hole establish three different things.** One of the three happened.
  §4.43.8 keeps them apart.
* **Local synthetic tests establish no real-provider accuracy and no product
  effectiveness.** Nothing in this pass touches either.

### 5.7.5 What was and was not done to the deployment

A Pi-hole **was** contacted, for the first time, and exactly one method was
used: `GET /api/auth`, which carries no credential. **No configuration
mutation occurred and none could**: the client's permitted set contains no
mutating operation, the check runs before name resolution and again on every
redirect, and a gate now requires every Pi-hole path in the adapter's source
to be one the allowlist carries.

Nothing was pushed. No Docker daemon was contacted. No credential was
accessed, and no permission was widened to try. No feed was enabled, no
provider was contacted, no trust key was changed, and enforcement remains
absent from the build — `scamwall version` at this commit reports
`enforcement compiled in  false`.

## 5.8 ORDER 8 — control crosswalk and four defect corrections

**No row is promoted.** This pass produced synthetic and fake-server evidence
only. No Pi-hole was contacted, nothing was pushed, no Docker access was
widened, no credential was opened, no feed was enabled and no trust key
changed. `scamwall version` at this commit still reports
`enforcement compiled in  false`.

Real-appliance evidence remains §4.43.3 alone, at its own commit. Nothing here
renews or extends it, and the two must not be read as one row.

### 5.8.1 What changed in the compiled input

`internal/sourceregistry`, `internal/strictjson`, `internal/observation`,
`internal/domain`, `internal/policy`, `internal/shadow`,
`internal/adapters/pihole` and `cmd/scamwall`. The compiled input of
`./cmd/scamwall` changed again, so the image-bound rows are further from the
verified image than they were at `d104949`. No `scripts/*.sh`, Dockerfile,
Compose definition or workflow changed. **No operator rebuild is recommended.**

### 5.8.2 FINDING-128 closed, three findings opened and closed

| # | Row affected | Disposition |
| --- | --- | --- |
| FINDING-128 | SW-P1-13 (strict decoding), SW-P1-15 | **CLOSED.** Both duplicate-key walks are now one, in `internal/strictjson`. Evidence §4.44.3 |
| FINDING-131 | same rows | **CLOSED.** The unknown-field diagnostic echoed the document's key — FINDING-128 one function away |
| FINDING-132 | SW-P2-04 (Pi-hole integration), and the shadow rows | **CLOSED.** The client reads the household's allow lists and the plan states what it checked. Severity corrected mid-run to accuracy rather than exposure — §4.44.6 |
| FINDING-133 | SW-P1-10 (domain normalisation) | **CLOSED.** Underscore labels are normalisable; the LDH rule moved out of the IDNA profile and was widened by exactly one character |
| FINDING-134 | SW-P1 provenance rows | **CLOSED.** Independence claimability is inherited along the lineage chain |

### 5.8.3 Two new rows

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| SW-P2-07 | The household's own allow entries are read from the appliance, and a shadow plan states which of its additions were checked against them. An allow pattern that cannot be evaluated faithfully withholds ScamWall's opinion rather than resolving the ambiguity against the household | **VERIFIED against the fake server only** | `internal/policy/allowregex_test.go`, `internal/shadow/allow_test.go`, `cmd/scamwall/shadow_test.go`; §4.44.6 |
| SW-P2-08 | Independence is a property of the whole declared lineage chain, not of one record's own field | **VERIFIED (synthetic)** | `internal/observation/c05_test.go`; §4.44.4 |

Neither row may be read as a claim about the installed appliance. SW-P2-07 in
particular rests on an **unmeasured assumption** about Pi-hole's allow/deny
precedence — see §4.44.6 and the owner questions.

### 5.8.4 The controls crosswalk

`docs/orders/ORDER_8_CROSSWALK.md` records C-01…C-24 against this tree: 3
`PRESENT`, 8 `PARTIAL`, 2 `DIFFERENT`, 11 `ABSENT`. It is a survey, not a
promotion: no row in this matrix changes status because a control was found
present, only because a defect was corrected and tested.

Five of the eleven absences are one missing component — this tree has no feed
acquisition layer at all — rather than five missing controls.

## 5.9 ORDER 9 — the controls port finished

**No row is promoted.** This pass produced synthetic and fake-server evidence
only. No Pi-hole was contacted, nothing was pushed, no Docker access was
widened, no credential was opened, no feed was enabled and no trust key
changed. `scamwall version` at this commit still reports
`enforcement compiled in  false`.

Real-appliance evidence remains §4.43.3 alone, at its own commit. Nothing here
renews or extends it, and the two must not be read as one row.

### 5.9.1 What changed in the compiled input

Three new packages — `internal/acquire`, `internal/mac`, `internal/journal` —
plus `internal/audit`, `internal/proposal`, `internal/sourceregistry`,
`internal/shadow`, `internal/observation` and `cmd/scamwall`. The compiled
input of `./cmd/scamwall` changed again, so the image-bound rows are further
from the verified image than they were at ORDER 8's end. No `scripts/*.sh`,
Dockerfile, Compose definition or workflow changed. **No operator rebuild is
recommended.**

`internal/acquire` contains this repository's second network client and the
first one aimed outside the household. **It is not reachable from `cmd/`**, and
`TestTheFetcherIsNotReachableFromTheCommand` holds it there over the whole
import graph.

### 5.9.2 One finding opened and closed

| # | Row affected | Disposition |
| --- | --- | --- |
| FINDING-135 | SW-P1-06 (no secret reaches a log), SW-P2-04 | **CLOSED.** `internal/audit` returned every string unchanged, so a credential in a source URL's query string reached the log verbatim — including inside a `url.Error` the standard library composed. Medium, and reachable today through the Pi-hole client's own error logging. Evidence §4.45.4 |

### 5.9.3 Six new rows

Kept apart from §5.8's rows deliberately: these are **synthetic** and
fake-server evidence, and none of them has met a real appliance, a real feed
server or a real ownership ledger.

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| SW-P2-09 | A feed snapshot is applied only when every acquisition gate passes; a refusal quarantines and **never withdraws** what is already in effect. A source that shipped a refused snapshot stays unhealthy however many later attempts merely failed to reach it | **VERIFIED (synthetic)** | `internal/acquire/c10_test.go`, `c11_test.go`, `c12_test.go`; §4.45.3 |
| SW-P2-10 | A fetch is bounded by ONE deadline covering resolution, connection, TLS handshake, headers and body; https only at the request and at every redirect; same-host redirects capped; a body over the cap refused rather than truncated; a compressed body capped on its expansion ratio | **VERIFIED against local test servers only** | `internal/acquire/c13_test.go`; §4.45.3. **Never pointed at a publisher, and not reachable from `cmd/`** |
| SW-P2-11 | A credential carried in a source URL reaches neither a stored row, nor an error, nor a log line, whoever composed the message | **VERIFIED (synthetic)** | `internal/audit/c14_test.go`, `internal/acquire/c14_test.go`; §4.45.4 |
| SW-P2-12 | The independent-source threshold counts **origin groups**, not feeds: the largest family of adverse sources whose origins are pairwise disjoint. An `authoritative` tier may satisfy it alone, only for primary lineage and only when the household's policy permits | **VERIFIED (synthetic)** | `internal/proposal/c01_test.go`, `c07_test.go`, `internal/sourceregistry/c04_test.go`; §4.45.3. **Inert against the shipped registry**, which declares no `upstream_labels` and no tiers |
| SW-P2-13 | A report has an audience. The export rendering withholds every host whose evidence may be used here and not republished — across propose, abstain and refuse, records, plan items and deferred samples — and a withheld host carries a **keyed** identifier under its own MAC purpose, never an unkeyed digest | **VERIFIED (synthetic)** | `internal/proposal/c08_test.go`, `c09_test.go`, `internal/mac/*_test.go`; §4.45.3 |
| SW-P2-14 | A journal records only substantive change, never forgets a host it has recorded, keeps the last-block time, and **refuses to record anything at all** when the run did not read the appliance. A report seal and a store seal are never interchangeable, and report verification checks every item by host, digest and MAC | **VERIFIED (synthetic)** | `internal/journal/c22_test.go`, `c23_test.go`, `c24_test.go`, `internal/proposal/c24_test.go`; §4.45.3 |

### 5.9.4 Two rows that have no caller

Recorded as requirements rather than as verified behaviour of the shipped
command, because nothing in this build reaches them:

| ID | Requirement | Status |
| --- | --- | --- |
| SW-P2-15 | Owned-entry retention: a household exception and an upstream withdrawal both end a block **through** a source-outage freeze; only lifetime expiry is held by one. Removals beyond 25% of what ScamWall owns are an abnormal run and are held whole | **RULE VERIFIED (synthetic), NO CALLER.** `internal/proposal/c21_test.go`, `c20_test.go`. This build keeps no ownership ledger, so it proposes no removals and the rule is never invoked |
| SW-P2-16 | `shadow` labels every proposed addition with its place in Pi-hole's documented decision order, and an addition that would override a list the household subscribed to goes to **review**, never an automatic add | **PARTIAL.** `internal/shadow/c25_test.go`. Gravity cannot be read by this build, so every addition is labelled `unknown_subscribed_allowlist` and held for review — `shadow` requests nothing at all. §4.45.6 |

**ORDER 11 note (2026-09-25):** both rows above have moved. SW-P2-15 now has a
caller (`scamwall decide --ledger`) and SW-P2-16 is still PARTIAL but is now
load-bearing for the RPZ path as well. §5.10 is the operative statement; this
subsection is left as ORDER 9 wrote it, because history is the value.

### 5.9.5 The ORDER 8 owner question about precedence

§5.8's closing note said SW-P2-07 rests on an **unmeasured assumption** about
Pi-hole's allow/deny precedence. That assumption is now replaced by the
appliance's own documented order, recorded in §4.45.6 and encoded in one
function. FINDING-132's corrected severity — accuracy, not exposure — **stands**.

What remains unmeasured is the same thing it always was: whether the
household's actual version behaves as its documentation says. One `dig` against
a name on both lists settles it, and it is the operator's optional step.

### 5.9.6 What the shipped command actually reaches

Added by the re-verification pass recorded in `docs/VERIFICATION.md` §4.46,
which found this stated for one package and not for another that is in the same
position. Produced by `go list -deps ./cmd/...`:

| package | ORDER 9 rows it carries | reached by the shipped command |
| --- | --- | --- |
| `internal/acquire` | SW-P2-09, SW-P2-10, SW-P2-11 | **no** — imported by nothing outside its own tests |
| `internal/journal` | SW-P2-14, journal half | **no** — imported by nothing outside its own tests |
| `internal/mac` | SW-P2-13, SW-P2-14 report-seal half | yes, via `internal/proposal` → `cmd/scamwall/propose.go` |
| `internal/shadow` | SW-P2-16 | yes |

Three consequences for the rows above, none of which changes a status:

1. **SW-P2-09 and SW-P2-11 carry SW-P2-10's qualifier.** All three are
   `internal/acquire`. SW-P2-10 said "not reachable from `cmd/`" and the other
   two did not; the three stand or fall together.
2. **SW-P2-14 is two halves on different footings.** Its journal clauses —
   substantive change, never forgetting a host, the last-block time, and C-23's
   total refusal — are **RULE VERIFIED (synthetic), NO CALLER**, exactly like
   SW-P2-15. Its seal clauses run in the shipped `propose`.
3. **§5.9.4's title undercounts.** Read it as *the rules this build never
   invokes*, which is SW-P2-15, SW-P2-16, the whole of the `internal/acquire`
   group, and SW-P2-14's journal half.

None of this is a regression and none of it was introduced by ORDER 9. A
control ported before its caller exists is the order working as written; a
record that says so for one package and stays silent for another is the defect,
and it is what this subsection closes.

**ORDER 11 note (2026-09-25):** note 1 was wrong about SW-P2-11 and note 2 is
superseded. `internal/audit` IS reached by `cmd/` — `run()` builds
`audit.New(stderr)` before it dispatches — so SW-P2-11 does not share
SW-P2-09's gate; only SW-P2-09 and SW-P2-10 do. `internal/journal` is reached
now, via `shadow --journal`. §5.10 carries the current statuses.

---

## 5.10 ORDER 11 — the controls get callers, and the owned resolver gets an output

Added by ORDER 11 (`docs/orders/ORDER_11_PROGRESS.md`, `docs/VERIFICATION.md`
§4.47). Branch `feat/scamwall-o11`, `14bddf6` → `f5f881e`, local only.

§5.9.4 and §5.9.6 recorded a set of rows as **RULE VERIFIED (synthetic), NO
CALLER**. That status is the honest one and it is also the one that protects
nobody: a rule the shipped command never executes is a rule the household does
not have. ORDER 11 gave five of them a caller and left one gated on purpose.

### 5.10.1 The rows that moved

| ID | was | now | driven from |
| --- | --- | --- | --- |
| SW-P2-15 | RULE VERIFIED (synthetic), NO CALLER | **VERIFIED (synthetic), REACHABLE FROM `cmd/`** | `scamwall decide --ledger`, plus `--source-outage` / `--max-acquisition-age`. `cmd/scamwall/decide_test.go`, `inventory_test.go` |
| SW-P2-14 journal half | RULE VERIFIED (synthetic), NO CALLER | **VERIFIED (synthetic), REACHABLE FROM `cmd/`** | `scamwall shadow --journal`. A run that did not read the appliance records nothing, for any host, and is reported incomplete. `cmd/scamwall/journal_test.go` |
| SW-P2-11 | not reachable from `cmd/` (§5.9.6 note 1) | **VERIFIED (synthetic), REACHABLE FROM `cmd/`** | `run()` builds `audit.New(stderr)` before it dispatches; ORDER 11 item 6 found §5.9.6 wrong about this one |
| SW-P2-09 | not reachable from `cmd/` | **BLOCKED**, and the block is a gate | `internal/acquire/reachability_test.go` REQUIRES `cmd/` never to reach the fetcher, and ORDER 11 §0 forbids weakening a gate. Now asserted from the command side as well |
| SW-P2-16 | PARTIAL | **PARTIAL**, unchanged, and now more consequential | gravity is still unread; see 5.10.3 |

SW-P2-10 is unchanged: it is `internal/acquire` and shares SW-P2-09's gate.

### 5.10.2 Two new rows

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| SW-P2-17 | There is **one boundary** between deciding and enforcing. An adapter receives a plan that retention and the caps have already settled, and its only remaining freedom is to REFUSE — never to do more than the plan says. The read-only shadow path satisfies the boundary **without acquiring the power to write**, and says so in its outcome | **VERIFIED (synthetic)** | `internal/enforce/enforce_test.go`; `TestTheShadowAdapterReportsAndCannotApply`, `TestEveryShadowKindIsSayableInThePlanVocabulary`. §4.47 |
| SW-P2-18 | ScamWall can produce an enforcement artefact for the **owned** resolver: an RPZ zone of exact hosts answering NXDOMAIN, deterministic and golden-tested, written atomically with the previous zone kept beside it and a **sealed** decision record under its own MAC purpose. A host the household allows — by exact entry, by regex, or through a subscribed allowlist — is excluded and routed to review, never written. A protected name and every subdomain of one are never written. A missing or unreadable allow snapshot, or a degraded evidence supply, leaves the existing zone **unchanged** and exits non-zero. Adds and removals against the zone are subject to C-20's caps and abnormal-removal rule, and a run over either writes nothing | **VERIFIED (synthetic)** | `internal/rpz/rpz_test.go` (27), `cmd/scamwall/rpz_test.go` (15), golden `internal/rpz/testdata/fixture.zone` sha256 `dc8945ca…a50a`. §4.47 |

Both rows are **synthetic**. Nothing in either was measured against a real
resolver, a real allow list or a real feed, and neither renews §4.43.3, which
remains the only real-appliance evidence this repository holds.

### 5.10.3 What SW-P2-18 does NOT establish

Listed separately because the gap between "the zone is correct" and "the
household is protected" is the whole of ORDER 12:

* **No zone has been loaded into a resolver.** Nothing in this build reloads
  Unbound, and no flag does. The zone has never been served.
* **No real allow list has been read.** `--allowlist` takes an operator's
  offline export. The live read is ORDER 12's, and until it exists a real
  `scamwall rpz` run either uses an export or freezes.
* **The zone was not validated by a real zone parser.** Neither
  `named-checkzone` nor `unbound-checkconf` is installed on the build host;
  that optional check is **BLOCKED (tool absent)** and the test logs it rather
  than skipping silently. A strict stdlib checker written for the tests is not
  a substitute and does not claim to be.
* **SW-P2-16 (C-25) still gates it.** With gravity unread the only real
  subscribed-list implementation in the tree reports *not read*, which freezes
  the writer. That is correct, and it means the PARTIAL row now has a harder
  consequence than it did when only `shadow` depended on it.
* **Nothing populates `ledger.Owned.Digest` or `ledger.Serial`**, because
  nothing in this tree writes an ownership ledger at all. Every standing
  entry's zone comment therefore renders `; d=-`, and the serial's only
  persistence is the zone's own SOA. Recorded as an ORDER 11 owner question.
