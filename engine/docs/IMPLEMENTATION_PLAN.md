# ScamWall Implementation Plan

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

This document describes **how** ScamWall is built and **in what order**.
`docs/REQUIREMENTS_MATRIX.md` holds the numbered requirements and their status;
`docs/VERIFICATION.md` holds the evidence. Where those documents already say
something, this one links instead of repeating.

---

## 1. The rule that shapes everything below

> **Writing the code does not complete a phase. Producing its evidence does.**

Two consequences follow, and they are the reason this plan is structured the
way it is.

**A check that could not run has proven nothing.** It is reported as `BLOCKED`
and it fails the gate. It is never a skip, never an "N/A", never a green tick
with a footnote. The failure mode this prevents is specific and common: a
suite that reports green while quietly omitting the half of itself that needed
a daemon, a network, or a credential.

**Evidence expires.** Every phase revalidates the applicable guarantees of
every earlier phase before it can pass. A Phase 1 gate result recorded against
commit `A` says nothing about commit `B`. The demotion rules are in
`docs/REQUIREMENTS_MATRIX.md` §5, and they are mechanical: if the source moved,
the evidence is stale, regardless of how confident anyone is that the change was
harmless.

---

## 2. Sequencing

```
Phase 1  Trustworthy verification          <- current
   |     establish gates that cannot lie
   v
Phase 2  Verified read-only integration
   |     prove the Pi-hole client against something real
   v
Phase 3  Trusted feeds, policy, durable state
   |     make the inputs and the stored state defensible
   v
Phase 4  Independent effectiveness evaluation
   |     find out whether it actually works
   v
Phase 5  Operational read-only pilot
   |     run it for real, changing nothing
   v
Phase 6  Controlled enforcement            <- household enforcement stays
         (separate operator review)           disabled pending its own review
```

The order is not arbitrary. Verification comes first because every later claim
is expressed through it: if the gates can produce a false pass, no subsequent
result means anything. Effectiveness evaluation comes *before* the pilot and
well before enforcement, because the cost of being wrong rises steeply along
that axis — a false positive in Phase 4 is a number in a report, and the same
false positive in Phase 6 blocks a household's bank.

### 2.1 Working while blocked

Some evidence needs the Docker daemon, and the service account does not have
it (`docs/SECURITY_BOUNDARIES.md` §5.2). That is a deliberate choice, not an
oversight: `docker` group membership is root-equivalent on this host.

Work therefore proceeds on independent tasks while a gate is blocked. What does
**not** proceed is the completion decision: a phase with a blocked required
gate is not complete, and dependent phases do not open. Blocked items carry the
exact operator command needed to unblock them, in `docs/VERIFICATION.md` §6.

### 2.2 Crosswalk to the consolidated phase orders (ORDERS 1–10)

The consolidated phase orders restate the programme as ten orders. They
**extend** this plan; they do not replace it. Requirement IDs are unchanged and
remain `SW-P<phase>-<nn>`, historical evidence keeps its scope, and no
acceptance criterion below is silently altered by the renumbering. Where an
order asks for something this plan did not, that is new work and is marked as
such.

| Order | Subject | Maps onto | Relationship |
| --- | --- | --- | --- |
| **1** | Finish the operator safety foundation | Phase 1, §3 — specifically SW-P1-05, SW-P1-07, SW-P1-16, SW-P1-17 | **Narrows and adds.** It directs the correction of six defects in `scripts/operator-handoff.sh` and the introduction of an explicit step lifecycle. The Phase 1 acceptance criteria are unchanged; the handoff is the procedure that renews SW-P1-05, so this hardens the renewal rather than the requirement |
| **2** | Validate the source catalog and architecture | **New.** Nearest existing text is Phase 3, §5 ("trusted feeds") | **Adds a gate before Phase 3.** Source qualification — rights, access, provenance, independence — was not previously a separate step; feeds were treated as an input to Phase 3 rather than as something requiring its own disposition per source. Phase 3 does not open for a source that has no disposition. Its **structure** is prepared in `docs/SOURCE_REGISTRY.md`, the catalog is in the repository at `docs/SOURCE_CATALOG.md`, and **all 85 entries are researched and carry a disposition** — `docs/source-registry.json`. Nothing is enabled. The clause this row used to carry, that the catalog "does not need re-supplying" because it was present in the order text, was true only of a session with that text in front of it; §3.3 records how it became a blocker and how it was discharged |
| **3** | Typed evidence model and storage | Phase 3, §5 | **Widens.** The plan's "durable state" is one indicator type and a policy decision. The order requires observations, indicators and decisions to be distinct entities, with provenance, lineage, retraction and usage rights preserved per type |
| **4** | Bounded acquisition and quarantine | Phase 3, §5 | **Adds.** Acquisition infrastructure — endpoint allow-listing, size and decompression limits, schema-drift detection, quarantine, atomic batch acceptance — is required *before* adapters multiply, rather than per adapter |
| **5** | Implement the first qualified sources | Phase 3, §5 | **Narrows.** Deliberately a small set, chosen on verified rights and independence, not the whole first wave |
| **6** | Fusion, relationships, and policy | Phase 3, §5 and Phase 4, §6 | **Widens.** Adds explicit policy for contradiction, correlation, retraction, shared infrastructure and human review, and forbids broadening a URL decision to its hostname without a documented host-level policy |
| **7** | Signed distribution and recovery | Phase 3, §5 (feed trust) | **Widens.** The existing feed-signature work becomes one part of a full update lifecycle: trust bootstrap, rotation, revocation, rollback and replay protection, last-known-good, signed withdrawals |
| **8** | Private identity and message analysis | **New.** Touches Phase 4, §6 | **Adds.** Non-domain indicator types and message corpora, with their own product surfaces. Explicitly *not* reachable through Pi-hole |
| **9** | Independent effectiveness evaluation | Phase 4, §6 | **Direct match, widened.** Adds per-type and per-source measurement, lineage-aware deduplication, temporal holdouts, and predeclared thresholds |
| **10** | Read-only pilot and controlled enforcement | Phase 5, §7 **and** Phase 6, §8 | **Merges two phases into one order, and does not merge their gates.** The order preserves the separation: the pilot must be accepted before enforcement is implemented, enforcement is implemented only in disposable environments, and live household enforcement still needs its own approval of a concrete deployment and rollback plan |

**What the crosswalk does not do.** It does not renumber a requirement, reopen
a closed row, or move an item's evidence. When this was written, `SW-P1-20` was
`VERIFIED` at `72bc84c` and `SW-P1-05` was `IMPLEMENTED-UNVERIFIED` pending an
operator run of §6.5 step A. That run has since happened: both rows are now
`VERIFIED` at `c35b1e6`, bound to image `sha256:0efff150…`
(`docs/VERIFICATION.md` §3.22). The point stands unchanged — a row moves on
evidence, not on a crosswalk. An order that widens a phase widens what that
phase must eventually prove; it does not retroactively invalidate what an
earlier commit's evidence established about a narrower claim.

**Phase 2 is untouched by the renumbering.** Order 1 finishes Phase 1's
operator foundation and Order 10 returns to the pilot; the verified read-only
integration in §4 remains the gate between them, and the orders' rule that
"every phase must revalidate the applicable requirements of all previous
phases" is the same rule as §1's *Evidence expires*.

---

## 3. Phase 1 — Trustworthy verification

**Objective.** Establish checks that cannot lie, and an auditable baseline.

**Status at the baseline commit `2edb95a`.** Eight of fifteen requirements were
verified. The container verifier had already been rebuilt around checked
operations and was covered by 61 regression cases. Missing was the tooling layer
around it — ShellCheck, an independent secret detector, content-based
vulnerability handling, CI — plus the findings this session's own inspection
raised.

**Status at `b6e70f4`, retained for the history.** Nineteen of twenty verified — the requirement set
grew from fifteen to twenty as the work exposed classes that had no requirement
covering them. `docs/REQUIREMENTS_MATRIX.md` §3 is authoritative; this paragraph
is a summary and defers to it wherever the two differ.

**Status now: twenty of twenty verified, and Phase 1 is accepted — qualified by
one pending criterion** (resource preservation observed against this deployment,
§3.3 and `docs/VERIFICATION.md` §3.30), within the evidence boundaries §3.3 and
`docs/REQUIREMENTS_MATRIX.md` §3 state, and with Phase 2 and all product
validation still pending. The two paragraphs below are
the steps that got there, kept in the order they happened rather than collapsed
into the outcome.

**Status at `c35b1e6`, when the operator's build landed. Nineteen of twenty
verified; the phase did not close there.** The operator ran
`docs/VERIFICATION.md` §6.5 — preflight, step A and
close-out — against `c35b1e601f2543cb666d34888c61b08406446106`, producing image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`.
Preflight 9 passed, step A 22 passed, the runtime verifier 95 passed / 0 failed
/ 0 blocked / 0 cleanup problems, close-out 7 passed; every step exit 0.
**SW-P1-05 and SW-P1-20 are both VERIFIED at that commit and that image**, and
for the first time since `b6b1769` they rest on the same artifact.
`docs/VERIFICATION.md` §3.22; `docs/REQUIREMENTS_MATRIX.md` §3 is authoritative.

**The open row was SW-P1-12, and it is now closed.** The paragraph that stood
here said it was the only open row, that no hosted run had seen any commit since
`72bc84c`, and that renewal was an approved push followed by a hosted run. That
is exactly what happened. The operator approved a push; run 34394790484 at
`87bdfaf` reported **28 passed, 0 failed, 0 BLOCKED**, executing
`scripts/check.sh` itself so the gate list is the local suite's by construction.
SW-P1-12 is **VERIFIED** — `docs/VERIFICATION.md` §3.25.

**The run before it failed, and that is the part worth carrying forward.** Run
34392469729 found three cases of `scripts/tests/operator-handoff-test.sh`
asserting this household's own deployment values as literals, so they could only
pass on one machine — FINDING-71, `docs/VERIFICATION.md` §4.22. The defect had
survived 33 commits because no runner had ever executed that suite. "One open
required row is an open phase" has not moved as a principle; what has moved is
that the principle now rests on a single unresolved question rather than on a
missing run — §3.3.

**What closing these two rows does not mean.** The verifier never starts the
deployment container, so nothing here says the application runs *as deployed*,
authenticates, or reads its mounted secret. The binary did execute in that run —
the two in-build assertions, and an isolated `scamwall version` probe with no
network, no mounts and no credential — which is how the commit metadata was read
back out of the image; neither execution touches the deployment's state
(`docs/VERIFICATION.md` §3.22). Steps B, C and D of §6.5 were not run. No credential was
opened — the close-out compared the deployment secret's owner, group, mode, size
and modification time against a baseline recorded before the handoff began, and
`--verify-secret-integrity` was not used — and no request reached the household
Pi-hole. Phase 2 is unchanged and SW-P2-04 stays BLOCKED.

**A defect the run's own output exposed.** The verifier prints a note stating
that the password file's owner, group and mode are things it "does not inspect
and does not claim", in the same transcript as the FINDING-29 verdict that
inspects exactly those — and which step A requires before it will report a pass.
It is a wording defect, recorded as FINDING-68 with the tested code deliberately
unchanged: the verifier that prints the note is an evidence-producing input for
the rows this run has just renewed, and the note is output its 358-case control
asserts against, so the fix carries an operator rebuild. **It stayed open
through that pass and was closed at `e2b740b`**, which is where the rebuild it
names falls due. `docs/VERIFICATION.md` §4.19 and §3.31.

**SW-P1-05 and SW-P1-20 were closed and re-opened together; only SW-P1-20 has
closed again.** Both closed on the operator's run at `b6b1769` against image
`sha256:b95cc07c…`: build exit 0 with the ELF and enforcement-absent assertions
executed inside it, verifier 90 passed / 0 failed / 0 blocked / 0 cleanup
problems, `VERIFY exit=0` (`docs/VERIFICATION.md` §3.7). `ef40156` and
`aa49797` then changed the verifier and the compose definition, which
`docs/REQUIREMENTS_MATRIX.md` §5 demotes both rows on.

**SW-P1-20 is VERIFIED again at `72bc84c`**, bound to the CI-built image
`sha256:d7c44949…`. Its acceptance is that the ELF controls pass and that the
assertion is observed to run inside a real `docker build`; the passing run's
build did that on an uncached runner. An earlier revision of this plan said a
passing CI run renewed neither row. That was an over-application of the renewal
rule: CI's deployment differs from the operator's, but the ELF assertion runs in
the build stage and reads no password, CA, mount or group, so no deployment
difference can bear on it (`docs/VERIFICATION.md` §3.12).

**SW-P1-05 remained `IMPLEMENTED-UNVERIFIED` at `b6e70f4`** — closed since, at
`c35b1e6`; see the block above. What was missing was nameable:
four assertions that depend on the operator's own configuration — the
prohibited-path rule over the secret source, the host-side regular-file check on
each approved mount, the password file's world-reachability, and the
supplementary group resolving to `989` rather than to the default `65532`. Every
other assertion in that row ran against a real image in CI. Renewal is an
operator action — `docs/VERIFICATION.md` §6.1 — and is expected to pass;
expected is not observed.

**SW-P1-12 is now VERIFIED.** Three hosted runs were executed, each with
operator approval for its specific push, and the third passed: run 34047025567
at `72bc84c`, **24 passed, 0 failed, 0 BLOCKED**, gate list identical to the
local suite's (`docs/VERIFICATION.md` §3.12). The acceptance criterion was
never relaxed; CI was made able to meet it.

Each run earned its place. The first (§3.8) produced the run URL and tool
versions — and FINDING-23, because its failure could not be diagnosed from its
own log. The second (§3.11) ran the container gates on the runner for the first
time and they passed, and it diagnosed its own single failure, which turned out
to be FINDING-27 and FINDING-28 — both defects in this session's work. The third
passed.

**The phase did not close at `b6e70f4`, and does not close at `c35b1e6` either —
for a different reason each time.** At `b6e70f4` SW-P1-05 was
`IMPLEMENTED-UNVERIFIED`; at `c35b1e6` it is VERIFIED and SW-P1-12 is the open
row. The paragraph below is the `b6e70f4` reasoning, retained because it is why
the operator run was needed at all. SW-P1-05 was `IMPLEMENTED-UNVERIFIED`, and a
passing CI run does not renew it: CI verified a container built on the runner,
mounting throwaway fixtures, resolving `group_add: 65532` rather than the
deployment's `989`. It corroborates the deployment's shape on an independent
host and says nothing about the operator's configuration or the artifact the
operator would deploy. That needs `docs/VERIFICATION.md` §6.1, which only the
operator can run. One open required row is an open phase.

Twenty-eight findings were raised and resolved along the way, five of them by
hosted CI runs that a local suite could not have produced. The most serious
were a `pipefail`/SIGPIPE race that made the secret scanner report a planted
private key as clean 200 times out of 200 in a 1 MB file
(`docs/VERIFICATION.md` §4.1), and seventeen false-pass defects in the runtime
verifier itself, found in two review rounds and none by execution (§4.7, §4.8).

### 3.1 Work items

| # | Work | Requirement |
| --- | --- | --- |
| 1 | Container checker corrections | SW-P1-01 |
| 2 | Separate repository verification from operator Docker verification | SW-P1-02 |
| 3 | Check command and parsing failures explicitly | SW-P1-03 |
| 4 | Evaluate only successfully captured structured results | SW-P1-04 |
| 5 | Verify exact image identity and deployment settings | SW-P1-05 |
| 6 | Isolate inspection resources; clean up only what this run created | SW-P1-06 |
| 7 | Regression tests for the false-pass classes | SW-P1-07 |
| 8 | ShellCheck review of shell scripts | SW-P1-08 |
| 9 | Independent secret detector alongside project controls | SW-P1-09 |
| 10 | Review critical Go paths | SW-P1-10 |
| 11 | govulncheck result handling by content | SW-P1-11 |
| 12 | Reproducible CI, constrained permissions, recorded tool versions | SW-P1-12 |
| 13 | Preserve and rerun pre-existing tests | SW-P1-13 |
| 14 | Remove gate nondeterminism | SW-P1-14 |
| 15 | Test the CLI read-only guarantee | SW-P1-15 |

Items 1–7 and 13 were completed in commits `36ed21b` … `2edb95a`. Items 8–12
and 14–15 were completed in later sessions.

**ORDER 1: implementation complete, acceptance half-evidenced.** The code is
written, tested and committed. The order's acceptance also requires *applicable
real-runtime evidence*, which needs an operator build (§6.5 step A) **and** a
hosted run. **The operator build has been done** — at `c35b1e6`, closing
SW-P1-05 and SW-P1-20 (`docs/VERIFICATION.md` §3.22). **The hosted run has now been done too** — the operator approved a
push, and run 34394790484 at `87bdfaf` passed all 28 gates
(`docs/VERIFICATION.md` §3.25), closing SW-P1-12. Both halves of ORDER 1's
real-runtime evidence therefore exist: an operator build against this
deployment, and a hosted run over this tree's own gate list.

**The question that stood in the way has been answered, and ORDER 1's
acceptance follows.** Whether the commit that fixed the CI failure also demotes
SW-P1-05 turned on a reading of the evidence-renewal rule that the session which
raised it declined to settle in its own favour. The operator has settled it:
renewal follows a row's affected evidence-producing inputs — transitive
dependencies, configuration and test controls included — and the Source / Tests
columns are an index over that rule rather than its boundary
(`docs/REQUIREMENTS_MATRIX.md` §5, §5.1). The analysis the rule requires is
`docs/VERIFICATION.md` §3.28: no input either image-bound row's evidence was
produced from has changed since `c35b1e6`, so **no operator rebuild is required
and no row moves.** ORDER 1's acceptance condition — implementation plus
applicable real-runtime evidence — is met by the operator build at `c35b1e6`
and the hosted run at `87bdfaf`, each bound to the identities it was produced
against.

**The ORDER 1 package was reviewed, and the review found three more defects.**
They were in the step lifecycle ORDER 1 itself introduced: a terminal step
record published in pieces rather than atomically, a prerequisite comparison
that skipped whatever binding happened to be absent, and no exclusion between
concurrent invocations sharing a work directory. FINDING-57, FINDING-58 and
FINDING-59, fixed at `04e7ea4`; `docs/VERIFICATION.md` §3.18 and §4.16. That
procedure has now carried defects at every one of four reviews, which is the
argument for reviewing it a fifth time rather than for declaring it settled.

**FINDING-60 is fixed, and the gate suite has no failing gate.** `go test -race
./...` was failing about 8% of runs on a coincidence in
`cmd/scamwall/e2e_test.go` that predates this work — a two-digit constant
colliding with the random component of a temporary path. It was deferred at
`04e7ea4` because the fix changes Go source and moves rows under §5 of the
matrix, which is not a call to make while cleaning up a package; the reviewer
then instructed it, and it was made at `ff2e734`. The check's haystack was
narrowed and its property was not, with mutation evidence for the difference —
`docs/VERIFICATION.md` §3.19 and §4.16. The episode also shows that SW-P1-14's
determinism evidence never covered the Go gate; that gap is recorded against
the row rather than papered over.


**Item 5 was the one still open, and ORDER 1 is about its procedure.**
SW-P1-05 is renewed by `docs/VERIFICATION.md` §6.5 step A, which the operator
runs. That procedure has now been reviewed four times and has carried defects
every time: nine at `6a737f3` (§4.13), two at `5af270d` (§4.14), six at
`76f3bfd` (§4.15), and three at `04e7ea4` (§4.16). ORDER 1 covers the third
set and adds an explicit step lifecycle so that a step's result is bound to the
identities it was produced against, and so that a rebuild or a configuration
change invalidates downstream acceptance rather than being inherited by it. The
fourth set is about that lifecycle itself.

**Item 5 is now closed, and it closed the way this paragraph said it would.**
Correcting the renewal procedure was never performing the renewal; SW-P1-05
closed when an operator ran step A against this deployment and returned its
result. That happened at `c35b1e6`: preflight 9 passed, step A 22 passed,
verifier 95 passed / 0 failed / 0 blocked / 0 cleanup problems, close-out 7
passed, image `sha256:0efff150…`. `docs/VERIFICATION.md` §3.22.

**The fifth review of that procedure was running it.** Four reading passes had
found twenty defects in it without a daemon. This run is the first evidence
about how it behaves *with* one, and it covers the preflight, step A and the
close-out only — steps B, C and D were not run and nothing is established about
them. It also produced one new finding, in the verifier rather than the handoff:
FINDING-68, a stale note that denies an inspection the same transcript performs.
It is a wording defect, recorded and deliberately not fixed here, because
the verifier's output is an evidence-producing input for the rows this run has
just renewed. `docs/VERIFICATION.md` §4.19 — where it was scoped, and where it
is now recorded as **closed at `e2b740b`**.

**ORDER 2: implemented, researched, and still not accepted — for a different reason than before.** The registry schema is enforced rather than described —
`internal/sourceregistry` refuses a record that breaks the rules
`docs/SOURCE_REGISTRY.md` states, and a required gate validates the shipped
file on every run. Implementing the prose surfaced two gaps in it, FINDING-61
and FINDING-62, recorded in the schema table itself.

**The catalog blocker is discharged, and every entry is researched.** The
paragraph that stood here recorded the blocker in its own terms: the 85-entry
catalog was supplied in the ORDER 2 text, was in none of the tracked tree, the
untracked and ignored files, or the history across all branches, and was not
reconstructed from recollection because a guessed provider name or licence term
laundered into a provenance record is the exact failure the registry exists to
prevent. That reasoning stands; the condition no longer holds.

The catalog is now tracked at `docs/SOURCE_CATALOG.md`, so a cleared
conversation can no longer erase the research scope, and
`docs/source-registry.json` carries **85 records — one per entry**, each field
read from the URL it cites on the date it cites. Dispositions: 21
`commercial-approval-required`, 14 `credentials-required`, 6 `historical`, 3
`unavailable`, 41 `unresolved`. **Zero `verified-available`, zero enabled, and
zero records declaring an intended operation** — this was research, and
researching a source is not qualifying it. Eleven entries could not be
researched at all and each names its blocker. `docs/VERIFICATION.md` §3.20,
§4.17; `docs/SOURCE_REGISTRY.md` §1.1 and §3.1.

This was ORDER 2's *independent* work, which §2.2's rule on working around an
external blocker permits. **It still does not open Phase 3 for any source**, and
the reason has changed rather than gone away: Phase 3 does not open for a source
without a disposition, and it does not open for a source whose disposition is
`unresolved`, `credentials-required` or `commercial-approval-required` either.
Every one of the 85 is in one of those states. Not one reached
`verified-available`, because §3 of the registry requires access to be
*confirmed* and this research was forbidden from fetching any data — so access
is documented everywhere and confirmed nowhere.

What exists instead is a **proposal**: four sources, in prose, at §5.4, none
enabled and none declaring an intended operation in the registry.
**ORDER 2 §3 complete: the registry authorization semantics.** Reviewing the
registry against the full source-qualification requirements found five defects
in it — FINDING-63 to FINDING-67, fixed at `e8f8683`. The consequential one is
FINDING-63: rights were three fields and a boolean, which over-refused a source
whose terms permit a local lookup and forbid republication, and under-refused
by saying nothing at all about retrieval, storage, enrichment or training.
Authorization is now per operation, `conditional` authorises nothing until
every condition is assessed and satisfied, and `unknown` refuses.
`docs/VERIFICATION.md` §3.21, §4.18.

**ORDER 2 §7 prepared:** `docs/EVALUATION_PROTOCOL.md`, written before any
evaluation data exists. It proposes no numeric thresholds; §8 of that document
gives each threshold's shape and rationale and leaves the value blank for
agreement before the held-out window opens.

**ORDER 2 §§4–6 remain blocked on the catalog.** No entry can be researched, so
no wave can be selected, so no adapter contract can be written for sources that
have not been chosen. ORDER 2 is **not accepted**: acceptance needs all 85
entries to carry a disposition and zero do.


### 3.2 Approach for the outstanding items

**ShellCheck (SW-P1-08).** Run over every tracked shell script at
`--severity=style`. Findings are fixed rather than suppressed wherever fixing
is honest; the two informational findings that are false positives — a function
invoked only through `trap`, and a deliberately single-quoted regex — get inline
`# shellcheck disable=` directives *with a reason on the line above*. A bare
disable directive is a silenced check, which is the thing this phase exists to
prevent.

**Independent secret detector (SW-P1-09).** `scripts/secret-scan.sh` encodes
ScamWall-specific knowledge: which paths must never be tracked, that the
Pi-hole password lives at a fixed location, that a certificate body means the
private CA leaked. A generic scanner knows none of that, and conversely knows
hundreds of credential formats the project scanner does not. They are
complementary, so both run and both are required.

The independent detector must scan **what would be published** — the commit
history and the tracked/staged tree — rather than the working directory as it
happens to sit on disk. Scanning the raw directory reports the operator's
correctly-ignored local key material as a finding, which trains people to
ignore the tool. The publishable tree is materialised with `git archive`, so
the scanner sees exactly the bytes a clone would.

Allowlisting is the risk here. Every allowlist entry is a hole, so each one
carries a written justification in `.gitleaks.toml`, and a positive control
proves the detector still fires.

**govulncheck (SW-P1-11).** The gate must decide from result *content*.
`govulncheck`'s default text mode exits nonzero on findings, so the current
gate is not wrong — but its correctness is accidental, resting on a property of
one output mode. In `-format json` and `-format sarif` the exit status is `0`
whether or not findings exist. A gate written against those modes without
parsing the output reports a vulnerable dependency set as clean. The gate is
therefore rewritten to capture JSON, count findings by osv/finding records, and
fail on a nonzero count — and to fail if the output cannot be parsed at all,
because an unparseable result is an unrun check.

**CI (SW-P1-12).** GitHub Actions, with: actions pinned by commit SHA rather
than by tag; a top-level `permissions: contents: read`; `pull_request` rather
than `pull_request_target`, so fork contributions run without repository
secrets and without a writable token; every tool version echoed into the run
log; and the same gate list as `scripts/check.sh`.

The last clause of that paragraph used to read "Docker-dependent gates are
reported as blocked in CI exactly as they are locally", and that was wrong about
the hosted runner: it **has** a daemon, so those gates attempt to run rather than
block. The first hosted run proved it by building the image successfully and
then failing the runtime verification. As of `aa49797` the workflow supplies the
two host files the deployment binds — generated on the runner, outside the image
build context, removed by a step that fails the job if the removal did not take
— so the container gates **execute** in CI against a CI-built image.

The rule that decision was made under: **a CI-specific fixture is acceptable; a
CI-specific bypass of a required assertion is not.** The runtime checker
enforces the same mount destinations, the same read-only binds, the same
exact-set rule and the same permission check in both environments; only the bind
*sources* differ, and every destination remains fixed in the compose file with no
override. Where a gate genuinely cannot run — a runner with no daemon — it still
reports BLOCKED and BLOCKED still fails the suite.

**Gate diagnosability.** Added to this phase's scope by the first hosted run
rather than planned into it, and worth recording as a lesson about the plan
rather than only as a fix. Every gate here was designed to distinguish *passed*,
*failed* and *could not run*; none of that survives if the harness prints the
wrong end of the output, and locally the defect was invisible because the two
container gates blocked rather than failed, so the truncation never fired.
Failure reporting is now a separate, self-testing program that prints the
reason, the verdict and the cleanup result before any length limit, sanitizes
everything it prints, and preserves anything it had to omit in an artifact the
workflow uploads. `docs/VERIFICATION.md` §4.9.

**Gate determinism (SW-P1-14).** A nondeterministic failure was observed in
`scripts/tests/runtime-verify-test.sh` and root-caused before being fixed —
patching a flake without understanding it risks converting a random failure into
a random pass, which is strictly worse. The cause turned out not to be confined
to the test at all: a `pipefail` script whose condition ends in a
short-circuiting `grep -q` reads a match as a non-match whenever the producer is
still writing. The same construction appeared throughout `secret-scan.sh`, where
it produced a 100%% false-clean on files above the pipe buffer.
`docs/VERIFICATION.md` §4.1 has the measurements. A static gate now fails the
build if the construction returns.

**CLI test (SW-P1-15).** `cmd/scamwall` had no test file, so the Phase 1 boundary
at the command surface rested on reading the code — the one place where a
regression would be both easy to introduce and invisible to the existing suite.
`cmd/scamwall/main_test.go` now covers it, including that the
`--dry-run=false` refusal happens before configuration is consulted, so a valid
configuration cannot mean the credential was already read from disk.

### 3.3 Acceptance

**Where this stands on the current candidate.** Phase 1 was accepted at
`c35b1e601f2543cb666d34888c61b08406446106` / image
`sha256:0efff1508ab6479fab4c2b09d2900844d8e957ed726cd6d84bbf4132a9493f06`,
qualified by the pending preservation criterion below. That acceptance keeps
those identities. It **does not cover this tree**: this candidate changes the
runtime verifier's emitted output and the compiled Go of the client and CLI, so
SW-P1-05 and SW-P1-20 are open here and `docs/VERIFICATION.md` §6.5 step A is
what renews them. SW-P1-12 is open for the separate reason that no hosted run
has executed this tree. `docs/VERIFICATION.md` §3.31.

*Implementation complete and acceptance evidence present are different
statements, and this document keeps them apart.* The implementation of every
Phase 1 row is complete on this candidate. The evidence for three of them is
not, and neither the completion nor the earlier evidence supplies it.

Phase 1 is complete when, at one commit:


* every required gate that can run, ran and passed;
* every deliberate failure injection produces a nonzero gate result;
* no required gate is silently omitted;
* **a failing gate says why** — its reason, its verdict and its cleanup result
  appear in the log, and anything omitted for length is preserved and pointed
  at. Added after the first hosted run showed a red gate whose diagnosis had
  been discarded (`docs/VERIFICATION.md` §4.9);
* operator verification runs without root git access;
* runtime assertions are tied to the exact inspected image ID;
* existing deployment resources survive checker execution;
* remaining evidence gaps are explicitly `BLOCKED`, with operator commands.

Two were outstanding at `b6e70f4` and neither was satisfiable from the service
account. The operator run at `c35b1e6` covers both. The table is updated rather
than rewritten, so the sequence stays legible:

| Outstanding | Why | Who |
| --- | --- | --- |
| ~~A hosted run that passes~~ | **Done for `72bc84c`** — run 34047025567, 24 passed / 0 failed / 0 BLOCKED. It does **not** cover this tree; see the last row | — |
| ~~The ELF assertion executes in a real build~~ | **Done, twice.** First in the same run's `docker build`, uncached, producing `sha256:d7c44949…`; then, after the Go source moved and demoted the row, in the operator's uncached build of `c35b1e6`, producing `sha256:0efff150…`. SW-P1-20 is bound to the second | — |
| ~~Runtime assertions tied to an image ID, against *this* deployment~~ | **Done** — §6.5 step A at `c35b1e6`, image `sha256:0efff150…`, 95 passed / 0 failed / 0 blocked / 0 cleanup problems on the deployment's own resolved configuration. The four assertions CI could not evaluate ran here. SW-P1-05 (`docs/VERIFICATION.md` §3.22) | — |
| The checker cleans up after itself on a host that carries a live deployment | **Done for the run's own resources** — 0 cleanup problems from the verifier, and the close-out's leftover enumeration, searching the identities step A recorded, found none. `docs/VERIFICATION.md` §3.22. **Not the same as preservation of unrelated resources**, which no run has observed here: that is established of the program by the cases in §3.30 and is **pending** as an observation about this deployment | Operator — capture a before/after inventory during a future §6.5 step A |
| ~~A hosted run over the current gate list~~ | **Done.** The operator approved a push; run 34394790484 at `87bdfaf` executed all 28 entries of this tree's own list — 28 passed, 0 failed, 0 BLOCKED. SW-P1-12 is VERIFIED. `docs/VERIFICATION.md` §3.25 | — |
| ~~One question about the renewal rule~~ | **Answered by the operator.** Renewal follows a row's affected evidence-producing inputs, including transitive dependencies, configuration and test controls; the Source / Tests columns are an index, not the dependency boundary. Applied to every commit since `c35b1e6`, no such input of SW-P1-05 or SW-P1-20 changed, so **no rebuild is required** and the rows keep their identities. `docs/REQUIREMENTS_MATRIX.md` §5.1; `docs/VERIFICATION.md` §3.28 | — |

#### Reconciliation against every acceptance criterion — **Phase 1 ACCEPTED, with one criterion pending**

Each criterion above, with what satisfies it and where the observation is
recorded. A criterion is marked met only where an identity-bound observation
exists; "expected" was never allowed to stand in for "observed" in this phase
and does not start now.

| Criterion | Met by | Verdict |
| --- | --- | --- |
| Every required gate that can run, ran and passed | Locally 26 passed / 0 failed / 2 BLOCKED, direct exit 1, on the clean committed tree — `docs/VERIFICATION.md` §3.26. The two BLOCKED are `docker build` and `container runtime verification`, blocked here for want of a daemon and **not** blocked on an independent host: both ran and passed in hosted runs 34394790484 (§3.25) and 34396978547 (§3.27), where the full list is 28 passed / 0 failed / 0 BLOCKED | **Met** |
| Every deliberate failure injection produces a nonzero gate result | `docs/VERIFICATION.md` §3.5, retained per gate rather than re-run, plus the pre-fix controls at §4.9 and §4.10 | **Met** |
| No required gate is silently omitted | CI executes `scripts/check.sh` itself and maintains no second list, so the hosted list is the local one by construction; `gate diagnostics self-test` and its regression suite are themselves gates. §3.25 | **Met** |
| A failing gate says why | FINDING-23's fix, demonstrated end to end at §3.10 — and then demonstrated by an unplanned case: run 34392469729 failed, and its three failing assertions were diagnosable from its own log, which is how FINDING-71 was found. §3.25, §4.22 | **Met** |
| Operator verification runs without root git access | SW-P1-02: the verifier never invokes git and succeeds with a hostile `git` on `PATH`; the handoff reads repository metadata as the tree's owner and takes no `safe.directory` exception. Observed against a real daemon in the operator's run — §3.22, §6.5 | **Met** |
| Runtime assertions are tied to the exact inspected image ID | The tag was resolved to an immutable ID and pinned through `SCAMWALL_EXPECTED_IMAGE_ID`; 95 assertions ran against that ID. §3.22 | **Met**, at image `sha256:0efff150…` |
| Existing deployment resources survive checker execution | **The program-level property is established by tests that check it directly**, against the scripted fake daemon in `scripts/tests/runtime-verify-test.sh`: the `unrelated-preserved` case places a coexisting deployment container in the fake and asserts that no unfiltered container, network or volume listing is performed, that the deployment project is never targeted (no `compose down`, `--all` or `prune`), and that the coexisting container is never removed; `create-fail-existing` asserts a pre-existing container is never adopted or removed after a failed create; `named-network-preexisting` asserts a pre-existing network is never removed and that **no resource at all** is removed when a name would escape isolation; `partial-create` asserts that only the resource this invocation created is removed. `docs/VERIFICATION.md` §3.1, §3.30 | **Pending against this deployment** — see below |
| Remaining evidence gaps are explicitly `BLOCKED`, with operator commands | SW-P2-04 and every Phase 2 row are BLOCKED with the procedure named: §6.2 for the live read, §6.5 steps B–D for the handoff's remainder, §6.6 for the disposable-appliance run | **Met** |
| The twenty requirement rows | All **VERIFIED**, each against its own acceptance criterion and evidence section. `docs/REQUIREMENTS_MATRIX.md` §3 is authoritative and states the identities row by row | **Met** |

**About "at one commit".** No single commit carries every artifact, and the
criterion is not read as if one did. What it requires is one *input state*, and
that is what exists: the last commit to change any gate input is `87bdfaf`, and
every commit since is documentation-only, so `HEAD`'s gate inputs are
`87bdfaf`'s. The image-bound rows are bound to `c35b1e6`, and the two
non-documentation commits between it and `HEAD` touch no input their evidence
was produced from — `docs/VERIFICATION.md` §3.28. One input state, two
artifacts, each named where it is used. The alternative reading — that evidence
must be regenerated at whichever commit is newest — is the one this record
rejected long ago, because it would make writing the evidence down invalidate
it.

**One criterion is pending, and the acceptance is qualified by it.** *"Existing
deployment resources survive checker execution"* is established as a property of
the program, by cases that assert it directly against the scripted fake. It is
**not** established as an observation about this household's deployment: nobody
recorded an inventory of the deployment's own containers, networks and volumes
before and after the operator's run and compared the two. The evidence cited for
it until now — 0 cleanup problems, and a close-out enumeration that found no
leftovers attributable to the run — cannot carry it, because absence of the
run's own leftovers says nothing about resources the run might have removed.
`docs/VERIFICATION.md` §3.30 records this, and names what would close it: a
labelled before/after inventory captured during a future §6.5 step A run. **No
live test was initiated to close it here**, and Phase 1 is accepted with that
criterion outstanding rather than by treating the tests as if they were the
observation.

**What this acceptance covers, and what it does not.** It covers the
verification apparatus and the evidence it produced. It does **not** say the
application runs *as deployed*, authenticates, or reads its mounted secret. The
execution boundary is the one `docs/VERIFICATION.md` §3.22 states: the in-build
assertions executed, an isolated `scamwall version` probe ran with no network,
no mounts and no credential, the deployment inspection container was created and
never started, and no live Pi-hole operation was performed. Steps B, C and D of
§6.5 remain unexecuted. It says nothing about fork pull requests, which a branch
push cannot show. It says nothing about detection, feeds, or any effect on a
household's DNS. **Phase 2 and all broader product validation stay pending**,
SW-P2-04 stays BLOCKED. FINDING-68 was **closed at `e2b740b`** — the wording
correction, its regression, and the pre-fix control that shows the new cases
fail against the superseded text. Because the file it corrects is the verifier,
closing it demotes the image-bound rows on the current candidate:
`docs/VERIFICATION.md` §4.19 and §3.31.

### 3.4 Previous-state validation

There is no earlier phase, so this reduces to: the functional, security, race,
and offline-plan tests that already existed must still exist and still pass,
and any intentional behavior change must be explained. Tracked in SW-P1-13.

---

## 4. Phase 2 — Verified read-only Pi-hole integration

**State at the current candidate: implementation advanced, acceptance not
approached, phase not open.**

The read-only client and its CLI were red-teamed against this phase's own
acceptance criteria and five defects were found and fixed — FINDING-72 … -76,
`docs/VERIFICATION.md` §4.23 … §4.27. Seven further surfaces were examined,
found already correct, and given the regressions they lacked (§4.29). The
operator handoff's step C was tightened onto the last of those fixes.

**Then that work was itself reviewed, and four more findings came back** —
FINDING-77 … FINDING-80, `docs/VERIFICATION.md` §4.30 … §4.33 — every one of
them in code this pass had just added. The most serious is FINDING-77: the
duplicate-key error written for FINDING-73 reproduced the offending key, and a
peer that returned the password or the session id as a duplicated key name had
it printed to stdout. It was demonstrated doing so against the superseded code
before being fixed, and it never left the local branch. The others: a
regression built on a sleep rather than synchronisation, teardown state
surviving into the next session attempt, and a comment overstating what
`doctor --offline` avoids constructing.

**Validating those four produced a fifth** — FINDING-81, `docs/VERIFICATION.md`
§4.34. Re-running the discrimination against the one half of FINDING-79 that had
never been mutated showed the regression cited for it does not discriminate it:
writing the forbidden reset into `claimSession`'s refused branch passes the whole
`-race` suite. The state is unreachable because `Logout` clears the session id,
the outcome and the claim in a single critical section. The code is left as it
is and the citation is corrected — a test that cannot fail is not evidence, and
saying so is the same correction FINDING-76 and FINDING-80 made about prose.

That is the argument for reviewing a candidate before building or pushing it,
made concrete: five defects found in the client, then four more found in the
fixes for them.

**None of that is acceptance, and the distinction is the whole point of this
section.**
 `docs/REQUIREMENTS_MATRIX.md` §4.1 now carries a traceability table
mapping every Phase 2 row to its implementation, its tests, its missing
evidence, and whether it needs a real daemon, the production credential, or
contact with the appliance. It fixes four evidence levels — static review,
fake-server test, disposable-container integration, live-appliance
observation — and records that **nothing here is above the second for any Phase
2 row**. A fake written from `docs/PIHOLE_API_CONTRACT.md` passes whether or not
the appliance agrees with that document, so passing against it establishes
conformance to the document and nothing about the deployment.

What each row still needs:

* **SW-P2-01 … SW-P2-03, SW-P2-06** — level 3 or 4 evidence. §6.5 steps B and D,
  or SW-P2-05's disposable instance.
* **SW-P2-04** — still **BLOCKED**, and the blocker is unchanged: the runtime
  verifier deliberately never starts the application, so a passing run is
  *absent* evidence about credential access rather than weak evidence. §6.5
  step C is the procedure that would produce it, and it has not been run.
* **SW-P2-05** — **MISSING**. §6.6 is prepared and unexecuted.
* **SW-P2-07** — the steps exist and are tested against a scripted fake Docker,
  git and Compose (400 cases). Whether they behave the same against a real
  daemon is level 3, and step D additionally requires a new, explicit operator
  decision taken after A, B and C have been run and read.



**Entry.** Phase 1 verification accepted for the relevant source and artifacts.

**Objective.** Move the Pi-hole client from "tested against a fake" to "proven
against something real", without ever writing to Pi-hole.

### 4.1 Work items

1. Define the permitted method/path set, including authentication and session
   cleanup. The set is already a constant pair in
   `internal/adapters/pihole/client.go` (`/api/auth`, `/api/info/version`) and
   is asserted structurally by `guard_test.go`; Phase 2 makes that definition
   authoritative and links it to `docs/PIHOLE_API_CONTRACT.md`.
2. Enforce TLS verification, intended destination handling, redirect
   restriction, deadlines, bounded responses, controlled proxy behavior.
3. Bounded retries, cancellation, rate-limit handling, credential-safe
   diagnostics.
4. Verify secret permissions and access **under the actual container
   identity** — not under the service account, and not by reading the file mode
   and reasoning about it. The distinction matters: the current record
   establishes configured permissions, and explicitly not proven access
   (`docs/SECURITY_BOUNDARIES.md` §5.1).
5. Stand up a disposable Pi-hole instance and document the compatibility scope
   — which Pi-hole versions this contract was observed against, and what
   happens outside that range.
6. Test correct credentials, rejected credentials, invalid CA, wrong hostname,
   unavailable server, malformed responses, rate limits, interrupted execution.
7. Provide operator commands for **one** controlled live read-only test, after
   the permitted operations have been reviewed. It is not started
   automatically.

### 4.2 Acceptance

Read-only integration succeeds against the disposable environment; approved
live evidence is captured with no credential or session token in it; no
blocking-state mutation occurs; failure paths terminate within their defined
limits; session cleanup is verified **including its failure cases**; permission
and compatibility assumptions are written down.

### 4.3 Previous-phase validation

Rerun the Phase 1 gates against the resulting source and image. Any new failure
class discovered here gets a regression test before the phase closes.

---

## 5. Phase 3 — Trusted feeds, policy, and durable state

**Entry.** Earlier applicable gates pass.

**Objective.** Make the inputs and the persisted state defensible against a
publisher that is wrong, compromised, or replaying.

### 5.1 Work items

1. Strict, versioned configuration and feed schemas.
2. Key provisioning, rotation, revocation, sequence and freshness checks,
   expiry, replay protection.
3. **Evaluate TUF, or an equivalent established signed-update design, before
   writing a custom lifecycle protocol.** Record the decision and its scope.
   The baseline uses a single Ed25519 key with no rotation or revocation path,
   which is adequate for a fixture and inadequate for a distributed feed.
   Rolling a bespoke key-lifecycle protocol is a well-known way to reinvent
   known vulnerabilities, so the default is to adopt rather than invent, and
   the burden of argument sits on inventing.
4. Publisher provenance, review, withdrawal, signing-key separation.
5. **Separate domain validity from maliciousness classification.** A mixed-script
   label or the mere presence of non-ASCII must not, on its own, establish that
   a domain is malicious. Today `domain.Normalize` rejects mixed-script labels
   as *invalid*, and one rejected record fails the whole feed. That conflates
   two different judgements and produces a bad outcome in both directions: a
   legitimate internationalized domain is unusable, and a homograph is recorded
   as a parse error rather than as the signal it actually is. The homograph
   check becomes a classification input with its own reason code.
6. Exact-domain and subdomain semantics, duplicate handling, source conflicts,
   confidence rules, expiry, user exceptions, reason codes.
7. Behavior for unavailable, stale, revoked, or invalid feeds — including what
   happens to state that already exists.
8. Bounded input processing; fuzz the parsers and the normalizer. `Normalize`
   is the single highest-value fuzz target in the tree: it is the only place
   attacker-influenced text drives a complex third-party state machine, and it
   is exactly where the two reachable `govulncheck` findings landed
   (`docs/SECURITY_BOUNDARIES.md` §5.3).
9. Atomic state updates, locking, corruption handling, schema migration,
   storage limits.
10. Versioned, deterministic plans bound to feed identity, policy and
    configuration identity, destination identity, creation and expiry,
    actions, exclusions, and application preconditions. The baseline plan
    digest covers format version, feed ID, manifest version, and entries; the
    remaining bindings do not exist yet.
11. Test clock anomalies, interrupted writes, concurrent runs, oversized input,
    recovery.

### 5.2 Acceptance

Tampered, stale, replayed, malformed, and oversized inputs all have tested
outcomes. Trust changes and withdrawals have tested procedures. Policy
precedence is explicit and deterministic. State survives tested interruption
without silently accepting corruption. Documentation states plainly that
**signing establishes authenticity, not accuracy** — a correctly signed feed
can still be entirely wrong.

### 5.3 Previous-phase validation

Rerun Phase 1–2 gates. Confirm that no feed or state change broadens the
Pi-hole permission surface.

---

### 5.4 First-wave source proposal

**Status: a proposal, and nothing more.** No source below is enabled, none
declares an intended operation in `docs/source-registry.json`, and every one of
them still needs evidence this project has not got. Selecting from a research
record is not the same as acting on it.

**What did the selecting.** The registry, and only the registry. Four filters
were applied in this order, and each one is a field in the record rather than a
judgement about the provider's reputation:

1. **Is the output DNS-actionable?** The Phase 1 deployment target is a DNS
   sinkhole. It cannot act on an IP netblock, a certificate fingerprint, a
   phone number, a wallet address, a message body or an IDS rule. This filter
   alone removes most of the catalog — 11, 13, 14, 17, 18, 19, 20, 21, 29, 30,
   32, 33, 36, 40 … 45, 46 … 54, 55, 57, 59, 60, 61, 74, 78, 80, 85 — and it
   removes them for a structural reason, not a quality one.
2. **Do the recorded terms permit the operation proposed?** This removes
   catalog 7 outright: OpenPhish's community Terms of Use name "detection" and
   "enrichment" among prohibited commercial purposes. It removes catalog 38 and
   57, which publish no licence at all. It removes catalog 23, whose amalgam
   includes at least one non-commercial-with-attribution upstream that binds
   the whole file.
3. **Is access operationally available without an act this order forbids?**
   This removes everything at `credentials-required` and
   `commercial-approval-required` from the *first* wave — catalog 1, 2, 6, 16,
   25, 26, 28 among them — not because they are unsuitable but because reaching
   them means registering an account or opening a commercial conversation, and
   both are operator decisions.
4. **Is it independent, or is it a copy?** Catalog 9 aggregates four other
   catalog entries by name, so selecting it would be selecting them badly.

**No priority label played any part**, because none exists: the catalog as
supplied to this project carried entry numbers and nothing else, and
`requested_priority` reads `unknown` on all 85 records. Nothing here was chosen
because it was once described as "VERY HIGH".

#### The four proposed, and what each still needs

**Four, not five.** A fifth would have meant reaching past the filters above.

| | src-0062 · catalog 62 · Scam Sniffer open database |
| --- | --- |
| **Operation proposed** | `retrieval` of `blacklist/domains.json` from the public repository, then `local_storage` of a derived manifest. Nothing else. Not `redistribution`, not `derived_output`, not `model_training` |
| **Access required** | None. A public repository file. No key, no account, no terms to accept |
| **Unresolved conditions** | Two, both recorded in the registry as unsatisfied. (a) GPL-3.0 requires notices to be preserved, and no mechanism here carries an upstream notice. (b) ScamWall is AGPL-3.0-only and the effect of combining a GPL-3.0 data set into that distribution has not been assessed. The second is a question for the operator, not for an engineer |
| **Adapter input format** | JSON, described in the repository README as a list of phishing domains. **The file itself has not been read** — fetching indicators is outside the order this research was done under — so §5.5's parser is written against a described shape and must fail closed when the real file differs |
| **Typed output** | `feed.Manifest` carrying `feed.Record{Action: block, Confidence: medium}` per accepted domain, signed locally and consumed through the existing verified feed path. No new trust path |
| **Provenance** | Per record: the source_id, the upstream path, the commit or ETag the file was fetched at, and the fetch time. `feed.Record` has no field for this today — §5.5 states the schema change that would be needed, and it is a Phase 3 schema bump, not an adapter detail |
| **Expiration** | The provider publishes none. Any expiry is therefore **the adapter's invention** and must be labelled as such: a manifest `expires_at` of fetch + 14 days, chosen to be shorter than any plausible staleness tolerance and longer than the fetch interval. A record that outlives its manifest is dropped by the existing loader |
| **Correction / deletion** | Upstream: not documented. A domain leaves by disappearing from the next build, so removal propagates only as fast as the fetch interval, and there is no retraction signal to act on. Locally: the operator exception list is the remedy, and it must be applied after the feed rather than merged into it |
| **Overlap with the others** | Low. Web3 and crypto phishing is a distinct population from the general phishing lists at catalog 8 and 22 |
| **Evidence still needed before enabling** | (1) the actual file, read once, to confirm the shape §5.5 assumes; (2) an operator decision on the AGPL/GPL combination; (3) a measurement of what the documented **seven-day delay** costs — for phishing domains, whose useful life is often hours, a seven-day-old list may be almost entirely spent, and that is a measurement, not a guess in either direction |

| | src-0008 · catalog 8 · Phishing.Database |
| --- | --- |
| **Operation proposed** | `retrieval` and `local_storage` of the active-domain list |
| **Access required** | None. Public repository files |
| **Unresolved conditions** | One: MIT requires the notice to accompany copies, and nothing here carries it yet. That is satisfiable by building the mechanism — the cleanest rights position of the four |
| **Adapter input format** | Newline-delimited domain lists. Not read; same caveat as above |
| **Typed output** | As src-0062 |
| **Provenance** | As src-0062. The project separates active, inactive and invalid lists, so which list was taken is itself provenance and must be recorded |
| **Expiration** | None published. The adapter's own, as above |
| **Correction / deletion** | No documented retraction or appeal process. The project's own retesting moves a domain between lists, which is a reachability judgement rather than a correction |
| **Overlap with the others** | **Expected to be high with src-0022**, and unmeasurable in advance: neither enumerates its upstreams, so both may be drawing from the same community reports. Treating agreement between them as corroboration would be the aggregator error, and this pairing is where it would happen |
| **Evidence still needed before enabling** | (1) the file shapes; (2) an overlap measurement against src-0022 before either is treated as adding coverage; (3) `IndependenceClaimable` returns **false** for this record — upstreams are undocumented — so nothing may describe it as an independent source |

| | src-0022 · catalog 22 · HaGeZi, **the TIF list only** |
| --- | --- |
| **Operation proposed** | `retrieval` and `local_storage` of the Threat Intelligence Feeds list. **Not the Light/Normal/Pro/Pro++/Ultimate tiers** |
| **Access required** | None |
| **Unresolved conditions** | GPL-3.0 notice and copyleft, as for src-0062 |
| **Adapter input format** | Domain list. Not read |
| **Typed output** | As above |
| **Provenance** | Which list and which mirror. The mirror matters here: the repository publishes one build per day and the build mirror "roughly every 4 to 8 hours", so two consumers of "HaGeZi" can hold materially different data |
| **Expiration** | None published. The adapter's own |
| **Correction / deletion** | Documented and honest: "Review and removal requests are handled on a best-effort basis, with no guaranteed response time." Better than most of the catalog, and still not a guarantee |
| **Overlap with the others** | High with src-0008, as above |
| **Evidence still needed before enabling** | (1) confirmation that the TIF list can be consumed separately from the tiers; (2) the overlap measurement; (3) an explicit decision that the ad-and-tracking tiers stay out — mixing them in would make any false-positive number meaningless, because a blocked tracker is not a false positive and not a scam detection either |

| | src-0024 · catalog 24 · CERT Polska Warning List |
| --- | --- |
| **Operation proposed** | `retrieval` and `local_storage` of `domains.txt` or the RPZ export |
| **Access required** | None technically |
| **Unresolved conditions** | **One, and it is decisive: no reuse terms are published anywhere this project could find.** Neither the description page nor the data directory states a licence. An absent restriction is not a grant, so this source is proposed *conditionally on getting an answer*, and cannot be enabled without one |
| **Adapter input format** | Published in txt, csv, json, xml, adblock, hosts, MikroTik, RPZ and uBlock. Not read |
| **Typed output** | As above |
| **Provenance** | The best available anywhere in the catalog: a statutory basis, and a published actions log recording listing and delisting events |
| **Expiration** | **The provider's own, and real**: domains remain listed for six months maximum. The only source in the first wave that supplies its own expiry rather than borrowing one from the adapter |
| **Correction / deletion** | A statutory appeal to the Polish communications authority, available to the domain holder. Nothing else in the catalog offers a route with legal force |
| **Overlap with the others** | Low, and for an unhelpful reason: it is scoped to domains defrauding Polish internet users |
| **Evidence still needed before enabling** | (1) **a written answer on reuse terms** — this is the single highest-value question in the whole first wave, because everything else about this source is already better than its alternatives; (2) a measurement of how much of it a non-Polish household would ever resolve, which may be close to none |

#### What the four do not add up to

* **They are all domain lists.** The first wave tests one indicator type against
  one enforcement mechanism. It says nothing about email, phone, wallet,
  message or social indicators, and no result from it may be reported as if it
  did.
* **Two of the four cannot claim independence.** `IndependenceClaimable`
  returns true only for src-0024 and src-0062, and only because their upstreams
  are recorded as `documented_complete`. That is a statement about what was
  recorded.
* **Two of the four are narrow by construction** — one Polish, one web3 — and
  the two broad ones are the two most likely to be copies of each other.
* **The honest expected outcome is small.** A household already running a
  general blocklist may see very little incremental detection from these four,
  and `docs/EVALUATION_PROTOCOL.md` is written so that finding that out counts
  as a result rather than as a failure.

#### Explicitly rejected, with the reason

| Not proposed | Reason, from the record |
| --- | --- |
| Catalog 7 OpenPhish | Terms prohibit detection and enrichment as commercial purposes without written consent; redistribution and derivative works prohibited outright |
| Catalog 9 Phishing Army | Aggregates four other catalog entries; CC BY-NC; and it redistributes OpenPhish data whose own terms forbid redistribution — a conflict this project would inherit |
| Catalog 23 StevenBlack | Mixed upstream licences including non-commercial-with-attribution; overwhelmingly advertising and tracking rather than scams |
| Catalog 12 Spamhaus DBL | A live DNSBL query discloses every looked-up domain to the provider. That is household browsing leaving the house, which §4 of the registry forbids |
| Catalog 1 URLhaus, 2 ThreatFox, 6 PhishTank, 25 urlscan.io, 26 Safe Browsing, 28 VirusTotal | All require an account or key. Registering is an operator decision, not an engineering one |
| Catalog 38 FakeFilter, 57 CryptoScamDB | No licence published. Nothing is granted |
| Everything at `commercial-approval-required` | 21 records. Each needs a contract, a membership or a paid tier |

### 5.5 Adapter specification — src-0062, the best-supported first source

**Scope.** This specifies a **parser and a converter**. It specifies no network
code: fetching is a separate work item behind an operator decision, and this
document does not authorise it. It also specifies **no threat score.** There is
no universal confidence number to compute, and inventing one would erase the
only thing the registry has established — that a given provider said a given
thing about a given name.

**Why src-0062 and not the source with the best data.** src-0024 has better
provenance, a real expiry and a statutory appeal route, and it cannot be
specified against because its reuse terms are unknown. src-0062 is the
best-*supported*: licence read from the repository's own `LICENSE` file, formats
named in its README, cadence published, delay published, and
`IndependenceClaimable` true. Best-supported and best are different, and the
difference is worth a sentence rather than a silence.

#### Placement in the existing trust path

The adapter does **not** introduce a second way for data to reach policy. It
produces a `feed.Manifest`, which is signed with the local operator key and then
loaded by `feed.LoadFile` exactly as today's fixture is. Everything the existing
path enforces — signature over the raw payload bytes, schema version, record
limits, expiry, `domain.Normalize` — applies unchanged.

```
upstream file  ->  adapter (this spec)  ->  unsigned Manifest
               ->  operator signing     ->  signed feed file
               ->  feed.LoadFile        ->  []feed.Indicator  ->  policy
```

The consequence worth stating: **an upstream domain that
`domain.Normalize` rejects never reaches policy**, and the adapter must not work
around that. It records the rejection and drops the record.

#### Input, as described rather than as observed

The README describes `blacklist/domains.json` as a list of phishing domains.
**The file has not been read.** So the parser is specified to accept exactly one
shape and to refuse everything else, including shapes that would be reasonable:

```json
["example-phish.invalid", "another-phish.invalid"]
```

| Rule | Behaviour |
| --- | --- |
| Top level is not a JSON array | Refuse the whole file. No partial import |
| An element is not a string | Refuse the whole file, naming the index |
| Duplicate keys, trailing content, or a byte-order mark | Refuse the whole file |
| File over 32 MiB | Refuse. A hand-checkable bound, an order of magnitude above the plausible size |
| More than 500,000 elements | Refuse. The published list is a fraction of this |
| Empty array | Accept, and produce a manifest with zero records — which the operator must be able to tell apart from a fetch failure. A zero-record manifest is a **result**, not an error, and the count is reported |

Refusing the file rather than skipping the element is deliberate: a shape this
project has never seen is a signal that the upstream changed, and the right
response to that is to stop and be looked at, not to import whatever survived.

#### Per-element handling

| Input | Outcome | Why |
| --- | --- | --- |
| `"example-phish.invalid"` | Accepted → `Record{Domain: "example-phish.invalid", Action: block, Confidence: medium}` | The ordinary case |
| `"EXAMPLE-PHISH.INVALID"` | Accepted, normalised by `domain.Normalize` | Case is not meaningful in DNS |
| `"  example-phish.invalid  "` | Accepted after trimming | Whitespace is a formatting artefact |
| `""` | Dropped, counted as `empty` | Not a domain |
| `"not a domain"` | Dropped, counted as `unparseable`, with the reason from `Normalize` | |
| `"еxample.invalid"` (Cyrillic е) | **Dropped today**, counted as `unparseable` — and this is the defect Phase 3 item 5 already names. Once validity and classification are separated, this becomes an accepted record carrying a homograph **signal**, which is what it actually is | The registry's own rule: a signal is not a verdict |
| `"*.example.invalid"` | Dropped, counted as `wildcard_unsupported` | Wildcard semantics are a Phase 3 policy decision, not an adapter decision |
| `"192.0.2.1"` | Dropped, counted as `not_a_domain` | A DNS sinkhole blocks names |
| A domain appearing twice | Kept once, second occurrence counted as `duplicate` | Deterministic output |
| A domain on the operator's exception list | **Kept in the manifest, excluded at policy** | The feed records what the provider said. Local exceptions are a policy decision applied afterwards, and merging them here would destroy the record of what was published |

Every drop is counted by reason and reported. A run that drops 80% of its input
must look different from one that drops none.

#### Confidence, and why it is a constant

Every record is emitted at `Confidence: medium`, for the whole feed, always.
The provider publishes no per-entry confidence, so any variation would be this
project's invention presented as the provider's judgement. `medium` is a
placeholder for "one source said so", and the moment a second source is enabled
the right change is a policy rule about agreement between named sources — not a
number computed here.

#### Provenance, and the schema change it needs

`feed.Record` today carries `Domain`, `Action`, `Confidence`, `Category`,
`Reference` and `ExpiresAt`. It has **no field naming the source**, and the
first wave cannot ship without one: a decision that cannot name which provider
caused it is not auditable, and `docs/REQUIREMENTS_MATRIX.md`'s Phase 3 rows
require reason codes and source conflict handling that this field is a
precondition for.

The change belongs in Phase 3's schema work, not in an adapter:

| Field | Value for this adapter |
| --- | --- |
| `source_id` | `src-0062` — the registry identifier, never the display name |
| `source_ref` | the upstream path, and the commit or ETag the file was fetched at |
| `observed_at` | the fetch time |

Until those exist, the adapter writes the same information into `Category` and
`Reference` as a documented stopgap, and the stopgap is recorded here so it
cannot become the design by inattention.

#### Manifest fields

| Field | Value | Note |
| --- | --- | --- |
| `manifest_version` | the fetch timestamp in RFC 3339 | |
| `feed_id` | `scamwall.local/src-0062` | Local, because this manifest is this project's rendering of the upstream, not the upstream itself |
| `issued_at` | the fetch time | |
| `expires_at` | fetch + 14 days | **This project's invention.** The provider publishes no expiry. It bounds staleness; it does not reflect anything the provider said, and no report may present it as if it did |

#### Expected validation behaviour, as test cases

These are the cases a test suite must cover before the adapter is written —
written first, as the project's other suites were:

| Case | Expected |
| --- | --- |
| The two-element example above | 2 records, 0 drops, manifest expiry = fetch + 14 days |
| `{}` at top level | Whole-file refusal naming the top-level type |
| `["a.invalid", 7]` | Whole-file refusal naming index 1 |
| `["a.invalid", "a.invalid"]` | 1 record, 1 duplicate counted |
| `["", "   "]` | 0 records, 2 empty counted, manifest still produced |
| `[]` | 0 records, manifest produced, zero-count reported distinctly from a failure |
| A 500,001-element array | Whole-file refusal on the record bound |
| A 33 MiB file | Whole-file refusal on the size bound, **before parsing** |
| A file with a duplicate JSON key inside any object form | Refusal — the same rule `internal/sourceregistry` already applies, and for the same reason: the reviewer reads the first value and the program uses the second |
| Output fed to `feed.LoadFile` after local signing | Loads clean; indicator count matches the record count minus expiries |
| Output with one byte flipped after signing | `feed.LoadFile` refuses. The adapter must not become a way around the signature check |

#### What this adapter must never do

* Fetch any URL the data names. Collecting a domain is not visiting it.
* Merge sources. One adapter, one source, one manifest — because a merged
  manifest cannot answer "which provider said this".
* Compute a cross-source score.
* Apply operator exceptions. Those are policy, applied after.
* Silently skip a malformed file. The upstream changing shape is news.

### 5.6 Everything else stays in the roadmap, with its dependency named

The catalog's indicator scope is far wider than a DNS pilot, and the widening is
gated on access, not on effort. Each line below names what must be obtained
before the work is even schedulable.

| Expansion | Blocked on | Nearest catalog evidence |
| --- | --- | --- |
| **Email indicators** | An enforcement point. This project has no mail path, so an email indicator has nowhere to act. Corpora at catalog 40, 41, 43, 44, 45 are historical and, in one case, published by someone who states he does not hold the rights | Registry records for 40 … 45 |
| **Disposable-email domains** | Nothing technical — catalog 37 is CC0 — but a *product* decision: blocking a disposable-mail domain at a household resolver stops a household member using one, which is not this product's purpose | Registry record for 37 |
| **Phone numbers** | A commercial arrangement with a carrier-facing provider, plus a delivery path that does not exist. Every candidate — 46, 48, 49, 51, 52, 54 — is `commercial-approval-required` or unreadable, and a DNS resolver cannot act on a number in any case | Registry records for 46 … 54 |
| **Crypto addresses** | The three analytics vendors are all `commercial-approval-required`; the community sources are one merged (56), one stale since 2022 (57), one unreachable (58). Catalog 55 needs an API key and partner vetting for the useful fields | Registry records for 55 … 62 |
| **Message classification** | Historical corpora only, with a privacy question on the best of them: catalog 45's later mailboxes are not anonymised. Nothing current, nothing licensed for training except under attribution and an unanswered privacy assessment | Registry records for 40 … 45 |
| **Social handles** | No source in the catalog supplies them outside a commercial digital-risk product (70, 71) | Registry records for 70, 71 |
| **Registration and DNS observations** | RDAP (74) is a protocol whose every server sets its own terms; the commercial providers (75, 76, 77) are unread or contract-gated. And domain youth is a risk signal, never a blocking ground | Registry records for 74 … 78 |
| **Campaign relationships** | The one source modelling them for this problem is catalog 79, gated behind APWG membership and a Data Sharing Agreement | Registry record for 79 |

**The rule that governs all of it:** a DNS pilot result may never be reported as
evidence about email, phone, wallet or message detection.
`docs/EVALUATION_PROTOCOL.md` holds that boundary.

---

### 5.7 The indicator core, built ahead of Phase 3 at `9cf5f10`

ORDER 5 built the internal foundation the work items above depend on, before
any source is enabled. Three things exist now that did not:

* **A provenance-carrying observation model** (`internal/observation`). The
  unit is one source's statement about one indicator at one time; an indicator
  is the set of observations sharing `(type, canonical value)`. It refuses the
  four ways an independent-source count inflates — a repeat import, an
  aggregator beside its upstream, undocumented lineage, and an id that
  resolves to nothing — and retains conflicting classifications, expired
  evidence and withdrawn evidence rather than resolving or deleting them.
* **Rights binding to the registry.** Derived output needs unanimity over live
  contributors; local use does not need redistribution rights; an unresolvable
  or retired source id authorises nothing; retaining a raw provider response
  is a local-storage operation.
* **An evaluation harness** (`internal/evaluation`) implementing
  `docs/EVALUATION_PROTOCOL.md` §5.1's definitions, able to demonstrate both
  improvement and regression.

**None of this advances a phase.** The packages are not reachable from
`cmd/scamwall`, no source was enabled, no disposition changed, no provider was
contacted and no external data was fetched. §5.1's work items are unchanged,
and SW-P3-06 stays MISSING: a foundation for a requirement is not that
requirement.

What it does change is what §5.1 costs. The adapter specified in §5.5 now has
somewhere to put a record that says who reported an indicator, when, on whose
terms, and whether anyone else agrees — and a way to find out whether the
decision rule built on top of it is better than the one before it.
`docs/VERIFICATION.md` §3.36.

#### 5.7.1 Corrected at `0ff221c`, and still not a phase

Reviewing the above found nineteen defects in it — FINDING-89 through
FINDING-107, `docs/VERIFICATION.md` §4.37. Four bear directly on the claims
made in §5.7 and are worth restating here, because the original wording would
otherwise read as stronger than the code was:

* **"Rights binding to the registry"** was accurate about the *functions* and
  wrong about the *enforcement*. `RetentionPermitted` returned the correct
  answer and nothing on the ingest path called it, so a raw provider response
  from a source that authorised nothing entered the trusted store without
  complaint (FINDING-102). `Store.Add` now asks, on every record, and fails
  closed when there is no authority to ask.
* **"Refuses the four ways an independent-source count inflates"** was true of
  the four named ways and untrue of the headline number itself: `Supporting
  Count` summed lineage EDGES, so four live sources could be reported as six
  (FINDING-103).
* **A provider correction that changed a record's subject** was not treated as
  a correction at all, leaving the withdrawn subject live for the rest of the
  store's life (FINDING-95).
* **The canonical value** — the indicator identity the whole model rests on —
  was accepted as a caller assertion rather than derived from what was
  observed (FINDING-97).

**Still no phase advances.** The four packages remain unreachable from
`cmd/scamwall`; the executable is byte-identical to the one at `3152485`
(`docs/VERIFICATION.md` §3.38). No source was enabled, no disposition changed,
no provider was contacted and no external data was fetched. §5.1's work items
are unchanged and **SW-P3-06 stays MISSING**. Correcting a foundation does not
turn it into the requirement it is a foundation for, and nineteen defects found
in it is a reason for less confidence in the original claim, not more.

---

#### 5.7.2 Corrected again at `49fab8a` — what the harness's own output claimed

Reviewing the corrections found four more defects — FINDING-108 through
FINDING-111, `docs/VERIFICATION.md` §4.38 — and they are worth naming here
because three of them are about the **claims the harness makes about itself**
rather than about the numbers it computes.

§5.7 described an evaluation harness "able to demonstrate both improvement and
regression". That remains true. What was not true was the sentence the harness
printed beneath every result: *"this result carries every binding needed to
reproduce it"*. `Reproducible()` asked of each binding only whether the field
was non-empty, so a stored result naming its source commit as `deadbeef`, its
fixture digest as `x`, and recording no evaluation instant at all printed that
sentence unchanged (FINDING-108, FINDING-110).

* The **source commit** must now be a whole object name. An abbreviation
  resolves differently in different clones and identifies nothing durable. The
  report also now distinguishes *identified* from *obtainable* — the check is
  on the identifier, and this package does not run git.
* The **evaluation instant** was recorded and then used nowhere, although it is
  the only input to expiry and withdrawal. Two runs over byte-identical
  fixtures eleven years apart compared as one measurement (FINDING-109). They
  no longer do, and the report prints the instant the result is bound to rather
  than only the one the run announced.
* The **diagnostic** a malformed fixture produced was escaped but unbounded: a
  3.5 MB document yielded a 4.2 MB error, and the 8 MiB input ceiling permits
  roughly ten megabytes in one string (FINDING-111). Bounded now, at the value,
  at the count listed, and at the count built — with the number omitted always
  stated, because a truncated list that looks complete is worse than a long
  one.

**None of this advances a phase, and the reason is the same as in §5.7.1.**
`internal/evaluation` has no production consumer; it is not on
`go list -deps ./cmd/scamwall`. Four defects corrected in a package the binary
does not carry give it no consumer. The §6.1 work items below are unchanged,
and SW-P3-06 stays MISSING.

What it does change is whether a number this harness prints can be taken at
face value. Twenty-three defects across two review passes in a foundation is a
reason for *less* confidence in what was originally claimed for it, not more —
and the harness now refuses to make the one claim it was least entitled to
make.

### 5.8 ORDER 6 — the foundation reaches the executable

Every entry above ends the same way: *`internal/evaluation` has no production
consumer; `internal/observation` is not on `go list -deps ./cmd/scamwall`;
SW-P3-06 stays MISSING.* That sentence was accurate and it was the whole
objection. ORDER 6 answers it.

**What was built.**

| | |
| --- | --- |
| `internal/feed/evidence.go` | a `schema_version 2` signed document whose records carry `source_id`, plus the operator's **signer authority** document deciding which source ids a signer may assert |
| `internal/proposal` | matching over canonical DNS labels, explicit scope with a documented apex decision, the household's exceptions with precedence by specificity, a closed reason vocabulary, and a report bound to its inputs by digest |
| `internal/safetext` | the one copy of the report-field escaping and bounding, shared rather than duplicated |
| `scamwall propose` | four explicit local paths, no configuration, no credential, no socket, three meaningful exit codes |

`go list -deps ./cmd/scamwall` now names `internal/observation`,
`internal/sourceregistry`, `internal/proposal` and `internal/safetext`.

**Two decisions that were available and were not taken.**

1. **The v1 feed was not given a source.** It could have been — the feed id,
   the key id, a literal `"legacy"`. A v1 document says nothing about who
   observed anything, and inventing an answer manufactures provenance that
   every rule counting sources would then count. v1 is untouched and each
   loader refuses the other's schema version.
2. **`min_independent_sources` was not given a default.** Any default would be
   a recommendation this project is in no position to make, and would be quoted
   later as ScamWall's advice. A policy that omits it is refused.

**What moves, and what does not.**

SW-P3-06 moves MISSING → IMPLEMENTED-UNVERIFIED, and it is the only status
promotion in the pass. **No phase advances.** SW-P3-02, SW-P3-03, SW-P3-04,
SW-P3-07, SW-P3-08, SW-P3-09, SW-P3-10 and SW-P3-11 are untouched, and Phase 3
acceptance requires all of them. SW-P1-10 and SW-P1-15 are **demoted from
VERIFIED** — the critical-path review and the command-surface guarantee are
both about a surface that just changed.

The §6.1 work items below are unchanged. What this pass does for Phase 4 is
give it a rule worth evaluating and a defective control to measure the harness
against; it does not give it a held-out dataset, an independent labeller, or
any of the other things §6.1 names.

**Where the executable stands.** Built `-trimpath -buildvcs=false` with
`CGO_ENABLED=0`, `./cmd/scamwall` is `228e10a8…` at this candidate and
`15fabb9e…` at `005e06d`. Every previous ORDER 5 pass could say the binary was
byte-identical. This one changes it deliberately, which widens the rebuild
obligation owed back to `c35b1e6` rather than narrowing it.

**Twenty-four defects and counting is still a reason for less confidence, not
more.** §4.40 and §4.41 of `docs/VERIFICATION.md` add eight more — seven in the
harness's own binding and diagnostic paths, one in the new ingestion boundary.
The new path is younger than any of them and has had exactly one adversarial
pass.

## 6. Phase 4 — Independent effectiveness evaluation

**Entry.** Feed and policy behavior stable enough for meaningful evaluation.

**Objective.** Find out whether ScamWall actually works, in a way that cannot
flatter itself.

### 6.1 Work items

1. A versioned evaluation runner.
2. Lawful data sourcing and redistribution constraints, documented.
3. **Labels independent of the feed under evaluation.** Scoring a feed against
   itself measures nothing.
4. Development data separated from held-out data, with documented leakage
   controls and time boundaries.
5. Malicious, legitimate, uncertain, and internationalized domains in the set.
   Internationalized names are not decoration here — they are where the
   validity/maliciousness conflation of Phase 3 does its damage.
6. Precision, recall on the dataset, false-positive rate, feed delay,
   withdrawal delay, resource use.
7. Sample sizes, uncertainty, label limitations, category-level results.
8. **Numerical thresholds proposed and recorded before the acceptance run**,
   and before anyone looks at final held-out results. A threshold chosen after
   seeing the number is not a threshold.
9. Uncertain labels handled explicitly. They are not quietly counted as
   whichever category improves the headline.

### 6.2 Acceptance

Reproducible from recorded inputs. Predeclared thresholds assessed honestly.
Failures lead to remediation **and a fresh evaluation**, not to a re-reading of
the same run. Synthetic fixtures are never presented as real-world accuracy
evidence — `testdata/feed.json` is evidence about signature verification and
nothing else.

### 6.3 Previous-phase validation

Rerun earlier gates after any policy or dependency change. Recheck held-out
data integrity before each acceptance evaluation.

---

## 7. Phase 5 — Operational read-only pilot

**Entry.** Earlier gates pass and evaluation supports proceeding.

**Objective.** Run ScamWall against the real household network for a defined
period, changing nothing.

### 7.1 Work items

1. Scope, observation period, stop conditions, and operator responsibilities —
   agreed **before** launch, because a stop condition invented after a problem
   appears is a negotiation, not a control.
2. Scheduling with overlap prevention, bounded retries, cancellation.
3. Distinguish healthy, stale, degraded, authentication-failed, and disabled.
   Collapsing these into up/down is what makes an outage invisible: a feed that
   has been stale for a week reports "healthy" under a naive check.
4. Bounded logs and storage; redacted sensitive fields; documented retention.
5. **No DNS query history collected by default.** This is a household network.
   The query log is the most sensitive data in reach and ScamWall has no need
   for it in this phase.
6. Test restart, power interruption, clock issues, feed outages, credential
   rotation, application upgrades.
7. Dependency and licence inventory; release evidence tied to source and image.
8. Safe installation, update, diagnostics, and recovery instructions.

### 7.2 Acceptance

The agreed observation period and review volume are completed. Failures and
incorrect proposals are measured, and each is resolved or explicitly accepted.
No Pi-hole blocking-state change occurs. Resource and privacy requirements
hold.

### 7.3 Previous-phase validation

Run applicable earlier gates before pilot start and after every pilot software
or configuration change. Re-evaluate accuracy whenever detection behavior
changes.

---

## 8. Phase 6 — Controlled enforcement

**Entry.** Phases 1–5 pass.

**Household enforcement remains disabled pending a separate review of concrete
results.** Reaching this phase authorises building and testing enforcement in
isolated environments. It does not authorise turning it on.

### 8.1 Work items

1. Implement and test against disposable Pi-hole instances first.
2. Track ScamWall-owned entries **without assuming exclusive ownership** of
   entries the user already had. Pi-hole's blocklists are a shared namespace;
   an entry ScamWall did not create is not ScamWall's to remove.
3. Recheck plan expiry, target identity, policy/feed identity, and
   observed-state preconditions immediately before applying — not at plan time.
4. Absolute and proportional change limits. A plan that wants to add ten
   thousand entries, or to triple the blocklist, stops and asks.
5. Journal operations; reconcile partial success.
6. Idempotent repeated application.
7. Detect concurrent user changes.
8. Conditional rollback that preserves later user changes and reports
   conflicts rather than resolving them silently.
9. Test interruption between **every** meaningful mutation step.
10. Verify disable, uninstall, and recovery remove only attributable changes.
11. Define stale-feed behavior for entries already applied.
12. A limited deployment proposal: exact changes, limits, monitoring, rollback
    commands.
13. Widen the structural guards. `TestNoMutatingEndpoints` scans only
    `internal/adapters/pihole/`, which is correct while that is the only
    package able to make an HTTP request. The moment enforcement gains network
    access the guard stops covering the thing it exists to cover, so it is
    widened in the same change — not afterwards.

### 8.2 Acceptance

Mutation and recovery tests pass in isolated environments. No user-managed
change is overwritten or removed improperly. Partial failures leave
understandable, recoverable state. All earlier applicable gates pass against
the enforcement candidate. The operator reviews the concrete deployment
proposal before any live enforcement.

### 8.3 A structural note

Phase 1 made enforcement *absent* rather than *disabled*: there is no
`enforce`-tagged source file, so `go build -tags enforce` fails to compile
rather than producing an enforcing binary. Phase 6 necessarily introduces that
file. That single change demotes every Phase 1 and Phase 2 container and
command-surface row to `IMPLEMENTED-UNVERIFIED` until the gates are re-run
against the enforcement candidate — by design.

---

## 9. Standing constraints

These hold in every phase.

* **Do not push, merge, publish, or enable live enforcement.**
* **Docker operations are operator-executed.** No Docker socket access, no
  repository ownership change, no `safe.directory` exception.
* **Secrets, network topology, and household data stay out of public commits
  and diagnostic output.** Staged content is reviewed and secret checks are run
  before every commit.
* **Do not rewrite working components without a demonstrated requirement.**
* **Never convert a failed prerequisite or an unavailable required check into a
  pass.**

---

## 10. The path to automatic synchronization, as it now stands

Added at ORDER 7's second pass, `d104949`. Evidence:
`docs/VERIFICATION.md` §4.43.

The product this is for maintains ScamWall's own blocks in the household's
Pi-hole without asking about each domain. This section records what is built
towards that, what is deliberately not, and the one thing that comes next.

### 10.1 Built

| piece | where | state |
| --- | --- | --- |
| **The automatic contract.** Nine values the household must state before unattended blocking. Nothing defaults; a missing value is visibly unresolved and suppresses every block it would have authorised | `internal/proposal/automatic.go`, `docs/EVIDENCE_SCHEMA.md` §3.5 | done, locally tested, **never filled in by a household** |
| **The qualifying layer.** `proposal.Qualify` maps a report plus a contract onto `automatic_block` / `abstain` / `refuse`, and never upgrades a decision the proposal layer already took | same | done |
| **The shadow comparison.** What ScamWall would request of a Pi-hole it has READ: additions, already-present, present-but-disabled, conflicts, removals | `internal/shadow`, `cmd/scamwall shadow` | done as code; **never completed against a real appliance** |
| **The read.** One narrow endpoint, `GET /api/domains/deny/exact`, under the same (method, path) allowlist as everything else | `internal/adapters/pihole` | done; reached a real appliance only as far as `GET /api/auth` |

### 10.2 Deliberately not built in this order

An **enforcement command**. The order that added the shadow path withheld it,
and the milestone that adds it needs five things first, in this order:

1. **an ownership ledger** — a journal of what ScamWall actually did, written
   before the act and reconciled after it;
2. **limits that count across runs** — the contract already requires
   `max_additions_per_day` and `max_removals_per_day`, and this build records
   them without acting on them, because a daily limit needs (1);
3. **block lifetime** — same reason: a lifetime is measured from when a block
   was added, which only (1) records;
4. **idempotent reconciliation** — a second run over an unchanged appliance
   must request nothing, and a run interrupted halfway must be safe to repeat;
5. **disposable-Pi-hole interruption tests** — the failure modes of (4),
   exercised against an appliance nobody minds breaking.

### 10.3 Why the ledger is first, and why it is a ledger

`shadow` can say what it would add. It cannot say what it would REMOVE,
because it cannot tell its own blocks from the household's.

The two candidate signals are both wrong in the direction that costs the
household something. A **domain** cannot establish ownership — "it is a scam
domain and ScamWall blocks scam domains" would make ScamWall claim, and later
delete, an entry a person added deliberately, possibly for a reason ScamWall's
evidence does not know about. A **comment** cannot either: it is free text, and
a program that treats its own name in a field it does not control as proof of
ownership can be made to delete whatever an attacker labels.

So ownership comes from a record of what ScamWall did, kept by ScamWall. Until
one exists, `shadow` passes `NoOwnership`, every observed entry is the
household's, the removal list is empty for the stated reason rather than by
accident, and the plan says so in its own output.

The ledger needs **no new Pi-hole permission** — it is local state — so it can
be built and tested entirely offline. That is the same property that made the
shadow path reviewable, and it is why it is the next step rather than a later
one.

### 10.4 What still cannot be settled here

* **Authentication against a real appliance.** The credential is unreadable by
  the executing account; `/etc/scamwall/secrets` is `drwxr-x--- root swsecret`
  and that group has no members. Permissions are not widened.
* **An image identity for this tree.** Both Docker gates are BLOCKED.
* **Whether the nine contract fields are the right nine.** That is a product
  question and needs a household, not a test.
