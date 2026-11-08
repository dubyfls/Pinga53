# ScamWall Effectiveness Evaluation Protocol

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Status: PROTOCOL ONLY. Nothing here has been run. No evaluation data has been
acquired, no labels obtained, no measurement taken, and no threshold agreed.**

This document is written **before** any evaluation data exists, which is the
only order in which it is worth anything. A protocol written after the numbers
are in is a description of the numbers.

It prepares ORDER 9. It is not permission to run live blocking, and it does not
open Phase 4.

---

## 1. The question, stated so it can fail

> Does adding ScamWall's proposed decisions to an existing Pi-hole
> configuration block additional malicious destinations, and at what cost in
> additional legitimate destinations wrongly proposed?

Two quantities, measured together and reported together. A protocol that
measures only the first is a protocol for producing a favourable number.

**No accuracy target is proposed here, and no improvement is claimed.** §8
proposes thresholds for review; they are proposals with reasons, to be agreed
*before* the held-out run, and they are not predictions.

---

## 2. The comparison

Evaluation compares two configurations over the same traffic, in the same
window.

| | Configuration |
| --- | --- |
| **Baseline** | The household Pi-hole as it is actually configured: its current blocklists, at their versions on the evaluation start date, with its current allowlist and local overrides |
| **Candidate** | Baseline **plus** the decisions ScamWall proposes from its first-wave sources |

Three properties this comparison must have, each of which is easy to lose:

* **The baseline is the real one.** Comparing against a bare Pi-hole with no
  lists would measure "does a blocklist help", which is not the question and
  has a known answer. The value ScamWall must demonstrate is value *on top of
  what the household already runs*.
* **The baseline lists are pinned by version and date.** A baseline that
  updates during the window is a moving comparison, and any difference is then
  partly the other project's work.
* **Neither configuration blocks anything during the evaluation.** Both are
  evaluated as *proposals* against observed traffic. Enforcement is ORDER 10
  and is separately gated.

**Recorded before the run:** every baseline list, its version or fetch digest,
its fetch date, and the allowlist and local overrides in force.


### 2.1 The baseline has to be named, not described

"The household Pi-hole as it is actually configured" is a description. A study
needs a name, because the first wave proposed in
`docs/IMPLEMENTATION_PLAN.md` §5.4 is **four domain blocklists**, and the most
likely baseline for a Pi-hole household is *also* domain blocklists — possibly
the same ones. If the baseline already carries HaGeZi or StevenBlack, then
`src-0022` adds nothing by construction, and a study that did not write the
baseline down would discover that as a surprising result rather than as an
arithmetic fact.

**Recorded before the window opens, in the evaluation record, by name:**

| Item | Form |
| --- | --- |
| Each baseline blocklist | Project name, exact list variant, source URL, fetch date, and a digest of the fetched file |
| Pi-hole version and FTL version | Exact strings from the appliance |
| Group, client and per-client list assignments | Pi-hole applies lists per group; a list that is present but unassigned is not in the baseline |
| Allowlist entries and regex overrides | Both directions — an allowlisted domain the candidate proposes is a *known* disagreement, not a false positive |
| Upstream resolver and any DNS-level filtering above it | An upstream that already filters is part of the baseline whether or not the household thinks of it that way |

**The overlap check runs first, before any traffic is observed.** For each
proposed source, compute the set difference against the assembled baseline. If a
source's contribution is empty or near-empty at that step, the study has its
answer for that source without spending a window on it, and says so.

**A named baseline is also what makes "additional" mean anything.** Every
quantity in §5 is defined relative to it; if it moves or is unrecorded, none of
them is interpretable.

---

## 3. Labels must come from somewhere other than the thing being tested

The central failure of feed evaluation is grading a feed against feeds. If a
destination is labelled malicious because a source says so, and ScamWall
proposed it because that same source said so, the measurement is a tautology
with error bars.

**Requirements for a label to count:**

| Requirement | Why |
| --- | --- |
| The labeller is not in the candidate's source set, and does not share a documented upstream with any of them | Otherwise agreement measures shared lineage, not truth. `upstream_sources_completeness` in the registry is what makes this checkable, and `unknown` upstreams do not satisfy it |
| The label is dated, and the date is comparable to the observation | A destination malicious in March and benign in September is two different labels |
| The labelling basis is recorded | "Reported as spam" and "observed serving a credential-harvesting page" are different claims and must not be pooled |
| Abstention is available | A labeller that must answer produces answers it does not have. **`unknown` is a first-class outcome and is reported, never redistributed into the other two** |

**Where labels may come from**, in descending order of strength: direct
observation with evidence retained; an independent provider whose registry
record permits this use; manual adjudication by a human with the basis
recorded. Manual adjudication is the fallback and its sample size is reported
separately, because it is small and its cost is what bounds the study.

**Rights prerequisite.** A source may be used for labelling only where its
registry record authorises the operations this requires — at minimum
`retrieval`, `local_storage`, and `enrichment`. A label set whose terms forbid
that use cannot be used, however convenient it is. See §7.

---

## 4. Leakage controls

Two kinds, both of which silently inflate results.

### 4.1 Temporal

* **Held-out window.** Thresholds, source selection and any tuning are fixed on
  a development window, and the reported result comes from a later window that
  was not consulted while tuning. The held-out window is declared, by date,
  before it is opened.
* **Point-in-time source state.** A decision is evaluated against what the
  source said **at the time of the observation**, not against the feed as it
  stands when the analysis runs. Evaluating today's feed against last month's
  traffic credits ScamWall with knowledge it did not have — this is the single
  most common way a retrospective feed evaluation produces an impressive and
  meaningless number.
* **Label-after-observation.** A label acquired after the observation is
  acceptable and is the normal case; a label acquired after *the decision was
  scored* is not, and the acquisition timestamp is recorded so the difference
  is auditable.

### 4.2 Source lineage

* Candidate sources that share a documented upstream are **not** counted as
  independent corroboration. The registry's `aggregation_dependencies` and
  `IndependenceClaimable` are the inputs to this.
* A labeller sharing an upstream with a candidate source disqualifies that
  labeller **for that decision**, not necessarily for the whole study.
* **An unknown upstream is not demonstrated independence.** Where lineage is
  undocumented, the decision is reported in a separate stratum rather than
  assumed clean.


### 4.3 Duplicate and campaign leakage

Temporal separation is not enough on its own, because the same *thing* can
appear in both windows wearing two names.

| Leak | How it inflates the result | Control |
| --- | --- | --- |
| **Exact duplicate** | The same destination observed in the development and held-out windows makes a tuned decision look like a generalised one | De-duplicate by canonical domain across windows; a destination seen in the development window is excluded from the held-out numerator and counted separately |
| **Registrable-domain duplicate** | `login.example-phish.invalid` and `secure.example-phish.invalid` are one registration and one decision | Group by registrable domain (public suffix + 1). Report both the per-name and the per-registration count; the per-registration count is the headline |
| **Campaign duplicate** | Fifty domains registered the same hour, on one nameserver, resolving to one address, are one campaign. Counting them as fifty detections turns one lucky catch into an impressive number | Cluster before counting, on evidence recorded at observation time: shared authoritative nameserver, shared A/AAAA target, registration within a short window, shared certificate issuance. Report **clusters caught** alongside names caught, and treat the cluster count as the primary figure |
| **Label reuse** | The adjudicator recognises a destination they labelled in the development window and labels consistently rather than independently | Adjudication is blind to window and to which configuration proposed the destination |

**The cluster count is the honest denominator for a claim about detection.** A
protocol that reports only names caught will, on real scam infrastructure,
overstate by roughly the size of the largest campaign in the window — and the
size of that campaign is not a property of the detector.

**What clustering must not do:** it must not merge on shared *hosting* alone.
Shared infrastructure is a risk signal, and thousands of unrelated legitimate
sites share an address. Clustering on it would fabricate campaigns out of a
cheap hosting provider.

---

## 5. What is measured

Per decision, over the held-out window:

| Quantity | Definition |
| --- | --- |
| **Additional malicious caught** | Destinations independently labelled malicious that the candidate proposes and the baseline does not block |
| **Additional legitimate wrongly proposed** | Destinations independently labelled legitimate that the candidate proposes and the baseline does not block |
| **Unchanged** | Destinations both configurations treat identically |
| **Abstentions** | Decisions ScamWall declines to propose. Counted, never silently dropped |
| **Unlabelled** | Destinations no qualifying labeller would adjudicate. Reported as its own number |

**Denominators are stated with every rate**, and rates are never reported
alone. "Caught 40% more" over eleven observations is not a finding.

**Uncertainty.** Every rate carries an interval appropriate to its
denominator — Wilson intervals for proportions, and the interval is reported
even when it is embarrassingly wide, because a wide interval is the honest
description of a small sample. A point estimate with no interval is not
reportable under this protocol.

**Stratification.** Results are reported per source and per indicator type as
well as pooled. A pooled number can hide one source contributing all the value
and another contributing all the false proposals, and the decision the study
exists to inform is which sources to keep.


### 5.1 Precision, recall and coverage, defined so they cannot drift

These three words are used loosely everywhere, and loosely used they are worth
nothing. Under this protocol they mean exactly:

| Term | Definition here | Denominator |
| --- | --- | --- |
| **Precision** | Of the destinations the candidate proposes **and the baseline does not block**, the fraction independently labelled malicious | Additional proposals that received a label. Unlabelled proposals are excluded from the ratio and **reported alongside it**, because a precision computed over the 30% that got labelled is a statement about the labeller |
| **Recall** | Of the destinations independently labelled malicious **that the household actually resolved in the window**, the fraction the candidate proposes | Labelled-malicious observed destinations. It is recall against *observed traffic*, never against "all scams", which is not a set anyone can enumerate |
| **Coverage** | The fraction of observed destinations for which any qualifying label could be obtained | All observed destinations |

**Coverage bounds the other two.** At 20% coverage, precision and recall are
statements about a fifth of the traffic, and the report says so in the same
sentence as the number rather than in a footnote.

**Sample sizes are stated as counts, not percentages, at every level** —
pooled, per source, per campaign cluster. A stratum with fewer than 10 labelled
observations is reported as a count with an interval and **no rate at all**; a
percentage over single digits invites a comparison the data cannot support.

**Intervals** are Wilson score intervals for every proportion, at 95%, reported
as an interval and never as "±". Where a stratum is too small for an interval to
be informative, that is reported as the finding for that stratum.

### 5.2 Incremental detection at a fixed false-positive operating point

The two quantities in §1 trade against each other, and a protocol that reports
each on its own can be satisfied by a system that is merely more aggressive.
Being more aggressive is not an improvement; it is a setting.

**The primary result is therefore a pair, not a number:**

> *Additional campaign clusters detected beyond the named baseline, at a
> measured additional false-proposal rate of X per 1,000 resolved destinations,
> with intervals on both.*

| Requirement | Why |
| --- | --- |
| The operating point is **fixed in the development window** and not moved afterwards | Otherwise the reported point is chosen after seeing the held-out result, which is the same error as tuning on the test set |
| The candidate's configuration at that point is recorded in full — which sources, which lists, which thresholds | So the number belongs to a configuration somebody can reproduce |
| If the false-proposal rate cannot be measured because too few legitimate destinations were labelled, **no detection claim is reported** | A detection count without its cost is the favourable half of the answer |
| Where several operating points are of interest, all are reported, not the best | Reporting the best of several is selection, and it is invisible in the number |

**The comparison is against the named baseline of §2.1 and against nothing
else.** "Better than no filtering" is not a result this protocol produces.

---

## 6. Corrections and delay

Both are properties of a feed that a single-snapshot study cannot see, and both
change the operational picture more than accuracy usually does.

* **Feed delay.** For each destination independently labelled malicious with a
  known first-observation time, record when each candidate source first
  published it. Report the distribution, not a mean: a source that is usually
  fast and occasionally a week late has a different operational character from
  one that is uniformly a day behind.
* **Correction behaviour.** For each destination a source later withdraws or
  downgrades, record the withdrawal time and whether the mechanism is a
  disappearance, an expiry or a tombstone. **A source that silently drops
  entries cannot be distinguished from one that never had them**, which is why
  `withdrawal_behaviour` is a required registry field and why measuring this
  needs point-in-time snapshots retained from the start of the window.
* **Correction latency for our own errors.** Time from a legitimate destination
  being wrongly proposed to it being withdrawn. This is the number a household
  actually feels.


### 6.1 Legitimate activity has to be measured as tasks, not as domains

A false-proposal *rate* over resolved destinations is the wrong unit for the
thing a household actually experiences. One wrongly proposed CDN domain can
break a banking login while barely moving a per-domain rate; a hundred wrongly
proposed tracker domains break nothing at all.

**So a second, task-level measurement runs alongside §5:**

| Item | Method |
| --- | --- |
| **Task list** | Agreed with the household before the window: the things they must be able to do. Banking, work VPN and conferencing, school portals, the shopping and delivery sites in use, media services, smart-home devices that phone home, and any device that cannot display an error — a printer, a doorbell, a TV |
| **Execution** | Each task is performed against the candidate configuration in proposal-only mode, with the proposals applied to a *test* resolver rather than the household's, so that nothing breaks for real while it is measured |
| **Failure definition** | The task cannot be completed, **or** completes with a degradation a person would notice and complain about. A silent retry that adds four seconds counts and is recorded with its magnitude |
| **Recovery time** | From the moment the failure is observed to the moment the household member can complete the task, using only the documented remedy — the operator exception list. Measured with a clock, on the real procedure, by the person who would actually do it |
| **Reported** | Failures per task list, not per domain; and the recovery-time distribution, not its mean |

**Acceptance on this measurement is the household's to set**, and it is
qualitatively different from the statistical thresholds in §8: a single
unrecoverable failure on a task the household called essential is a stop, whatever
the aggregate numbers say.

### 6.2 Failure and recovery of the data path itself

Accuracy is measured on a good day. These are the bad days, and each is a test
with a stated expected outcome — not an observation to be made if it happens to
occur.

| Test | Method | Expected outcome |
| --- | --- | --- |
| **Feed outage** | Make a source unreachable for a fetch cycle | The previous manifest stays in force until its own expiry; the failure is reported; nothing is silently emptied. A source that vanishes must not un-block what it previously blocked without somebody being told |
| **Stale data** | Advance past a manifest's `expires_at` without a successful fetch | Records from that manifest stop being proposed, and the operator is told which source went stale and when. Expiry must be a visible event, not a quiet decay |
| **Truncated or corrupt fetch** | Supply a half-written or bit-flipped file | Refused whole. The previous manifest stays in force. **No partial import** — the adapter specification in `docs/IMPLEMENTATION_PLAN.md` §5.5 requires whole-file refusal, and this is the test that holds it to that |
| **Upstream shape change** | Supply a file in a plausible but different shape | Refused whole, with a message naming what differed. This is the most likely real failure and the one a lenient parser hides |
| **Rollback** | Return to the previous manifest after a bad fetch | Completes with a documented procedure, and the resulting state is byte-identical to the state before the bad fetch. Verified by digest, not by inspection |
| **Correction propagation** | Remove a domain upstream, then measure | Time from upstream removal to the domain no longer being proposed. **This is bounded below by the fetch interval and by the manifest expiry**, and for the first-wave sources it is bounded further by their own publication delay — seven days for `src-0062`. The measured number is the sum, and it is reported as such |
| **Local override propagation** | Add an operator exception | Time from the exception being added to the domain no longer being proposed. This is the number that matters when a household member is locked out, and it must be far smaller than the previous row |
| **Two sources disagree** | One source proposes a domain another's exception or allowlist covers | A deterministic, documented outcome — recorded, not resolved by whichever fetch ran last |

**Every row above is a test with a fixture, runnable without any provider's
cooperation**, which is why they belong in the protocol rather than in the field
study: none of them needs live traffic, a label, or a household.

---

## 7. Data access and rights prerequisites

Before any evaluation data is acquired:

1. Every source used for **candidate decisions** has a registry record
   authorising `retrieval` and `local_storage`, and the evaluation's use of it
   falls inside `intended_operations`.
2. Every source used for **labelling** authorises the same, plus `enrichment`.
3. If any result is to be published outside the household, `derived_output` is
   authorised for every source contributing to it. **Permission to query is not
   permission to publish** — this is checked per source, not assumed from the
   study's purpose.
4. Retention of point-in-time snapshots is checked against each source's
   `retention` and `local_storage` terms. A protocol that requires keeping
   snapshots a licence forbids keeping is not runnable, and finding that out
   after collection starts is too late.
5. **No household traffic leaves the household.** Destinations observed locally
   are not submitted to third-party services for labelling. Where a label
   requires a third-party lookup, that is a lookup ScamWall must be able to
   perform without disclosing that *this* household saw *this* destination —
   and where it cannot, the destination goes to manual adjudication or stays
   unlabelled. This constraint is not negotiable for a convenience gain and it
   materially limits §3.


### 7.1 Cost, and the unit it is measured in

Sustainability is a result like any other, and it fails quietly rather than
loudly: a system that works and costs more than anyone will pay is not a system.

**The unit chosen is one deployment-year: one household, one appliance, twelve
months.** It is chosen because it is the unit the requesting party actually
buys, and because per-query and per-domain units flatter a small deployment —
almost anything divided by a year of household DNS traffic rounds to nothing.
The choice is stated here so that a later report cannot switch to a friendlier
denominator without the switch being visible.

| Cost line | How it is obtained |
| --- | --- |
| **Data subscription and licence fees** | From each source's registry `operational_cost`. For the first wave this is zero — every proposed source is free of charge — and that fact belongs in the report, because it is also the reason the first wave is narrow |
| **Fetch, storage and compute** | Measured on the deployment: bytes fetched per cycle, storage held for point-in-time snapshots, and the appliance's own load. Snapshot retention is the line that grows without anyone deciding to grow it |
| **Human maintenance** | Wall-clock time spent, by whom, at what rate: fetch failures investigated, exceptions added, upstream shape changes handled, the recovery procedures in §6.2 performed. **Measured, not estimated.** It is the dominant cost in almost every deployment of this shape, and it is the one always left out |
| **Correction handling** | Time per wrongly proposed destination, from the household reporting it to it being resolved. §6.1 already measures the recovery clock; this line prices it |
| **Escalation cost** | What the next wave would cost. Several sources in the catalog move behind a subscription, a membership or a contract at any commercial scale, and the report states which ones and at what published price where one exists |

**Two things the cost section must say out loud.**

* **Free sources are free under terms.** Several first-wave sources are free
  *for non-commercial use* or under copyleft. If the requesting party ever
  makes ScamWall commercial, the cost of the data changes and some of it
  becomes unavailable rather than merely dearer. The registry records which,
  per source, per operation.
* **A zero-cost result is not a favourable result.** It reflects a first wave
  chosen partly because it required no commercial decision, and the honest
  reading is that the cheap data has been used up.

---

## 8. Thresholds proposed for review

**Proposals with reasons, for agreement before the held-out window opens. Not
targets, not predictions, and not claims about what the system achieves.**

| Proposed threshold | Rationale |
| --- | --- |
| Additional legitimate destinations wrongly proposed: **upper bound of the interval** below a rate the household agrees in advance | A false block is felt immediately and erodes trust in the whole system; the *upper* bound is used because a point estimate under a small denominator is not a bound |
| Additional malicious caught: a **lower** bound above zero | The system must demonstrate it adds something, and "the interval includes zero" means it has not |
| Unlabelled fraction below an agreed ceiling | Above it, the study is measuring the labeller's coverage rather than ScamWall's decisions |
| Per-source stratum reported regardless of pooled outcome | So a source that only adds noise is visible even when the pooled number is acceptable |

The numeric values are deliberately left blank. Filling them in here, before
the household has said what a false block costs it, would be inventing a
requirement and then meeting it.

### 8.1 Who has to approve what, before the window opens

Every proposal in this document that fixes a number, a boundary or a cost needs
somebody's agreement, and they are not all the same somebody. Running the study
without these is running a study whose result nobody has agreed to be bound by.

| Decision | Whose | Why it cannot be an engineering call |
| --- | --- | --- |
| The false-proposal ceiling, as an interval upper bound | **Household / operator** | It is a statement about what a broken banking login costs them, and only they know |
| The essential-task list, and which failures are stops | **Household / operator** | §6.1's acceptance is qualitative and personal |
| The minimum additional detection worth having | **Requesting party** | If the honest answer turns out to be "a handful of clusters a year", whether that is worth the maintenance is a value judgement, not a measurement |
| The unlabelled-fraction ceiling | **Requesting party**, on advice | Above it the study measures the labeller; where exactly that line sits is a judgement about what the study is for |
| Whether ScamWall is a commercial product | **Requesting party** | It changes which sources may be used at all — several first-wave records turn on a `NonCommercial` term whose satisfaction is recorded as `unknown` precisely because this is undecided |
| The AGPL/GPL-3.0 combination question | **Requesting party**, on legal advice | Two first-wave sources are GPL-3.0; the effect on an AGPL-3.0-only distribution is unassessed |
| Whether to register accounts or open commercial conversations | **Operator** | It is what stands between the first wave and most of the catalog |
| Cost per deployment-year that is acceptable | **Requesting party** | §7.1 measures it; nobody has said what number is too much |
| The held-out window dates | **Operator**, recorded before opening | So it cannot be chosen after a peek |

**None of these has been asked, and none is answered anywhere in this
repository.** Until they are, this protocol is executable in its
fixture-based parts — §6.2 needs nothing from anyone — and not in its measured
parts.

---

## 9. What this protocol will still not establish

* **Anything about enforcement.** It measures proposals against observed
  traffic. Whether blocking those destinations is net-beneficial in daily use
  is ORDER 10's question and needs a pilot.
* **Generalisation beyond this household.** One household's traffic over one
  window. Nothing here supports a claim about anyone else's.
* **Anything about sources not in the candidate set**, including sources that
  were excluded because their rights did not permit this use. Their absence is
  a fact about the study, not about them.
* **A causal claim.** The comparison is observational. It shows a difference
  between two configurations over the same traffic; it does not isolate why.

### 9.1 A DNS pilot is not the product, and its result may not be borrowed

This is the boundary most easily lost between a study and a claim, so it is
stated as a rule rather than as a caveat.

**What the study measures:** whether adding four domain blocklists to a named
Pi-hole configuration causes additional resolved destinations to be proposed for
blocking, and at what cost in legitimate destinations, over one household's
traffic in one window.

**What it therefore says nothing about, however the numbers come out:**

| Indicator type in the catalog's scope | Why this study cannot speak to it |
| --- | --- |
| Email addresses and disposable email domains | No mail path exists. No email indicator was proposed, none was enforced, and nothing was observed |
| Phone numbers | A DNS resolver cannot act on a number. No phone source is reachable without a commercial arrangement, and none was proposed |
| Crypto and payment identifiers | Not resolvable, not enforceable at DNS, and every candidate source is gated or stale |
| Message content | Historical corpora only. No classifier was built, trained, or run |
| Social handles | No source, no enforcement point |
| Certificate and registration observations | These are leads for human review; nothing was proposed on them |

**The rule.** A report from this study may use the words "scam detection" only
with the qualifier "of DNS-resolvable destinations, on one household's traffic".
A per-indicator claim requires a per-indicator study, with its own baseline, its
own labels and its own enforcement point — and for every indicator type above,
the first missing piece is an enforcement point, not data.

**Why this is easy to get wrong.** The product is described in terms of scams,
and scams reach people by phone, by message and by wallet address at least as
often as by a link a resolver ever sees. A strong DNS result would be a result
about the narrowest channel the product claims, and reporting it as a result
about the product would be the most consequential overstatement available here.

---

## 10. The harness that implements this, and the gap between it and a study

`internal/evaluation`, added at `9cf5f10`, implements §5.1's definitions in
code. This section exists so that the harness and this protocol are never
confused for one another.

### 10.1 What the harness enforces, rather than merely permits

| §  | Rule | How it is enforced |
| --- | --- | --- |
| 5.1 | precision is over **additional** labelled proposals | the denominator is candidate-proposes-minus-baseline-proposes, filtered to labelled cases; unlabelled proposals are counted separately and reported beside it |
| 5.1 | recall is over labelled-malicious cases **actually seen** | the denominator is the labelled-malicious cases in the fixture set, never a notional population |
| 5.1 | coverage bounds the other two | computed over all cases, and the operator report prints "coverage BOUNDS everything below it" immediately under it |
| 5.1 | no rate below ten labelled observations | `MinReportableDenominator`; the rate is withheld and the counts are printed instead |
| 5 | Wilson intervals, never "±" | `wilson()`, at 95%, clamped so the interval always contains its point estimate |
| 5 | denominators stated with every rate | `Rate.String` cannot render without one, and a test asserts it over every rate in every stratum for five detectors |
| 3 | abstention is first-class | `DecisionAbstain` is counted; a true negative requires an actual `pass`, while a false negative is **any** failure to propose something harmful |
| 3, 5 | unlabelled is never redistributed | unlabelled cases are excluded from every labelled denominator and reported as their own number |
| 5 | stratification | results per fixture family, per indicator type and per scam category, as well as pooled |
| 4 | partitions are recorded | every set declares `development` or `held-out`, and a development result is flagged as one |
| 7 | fixture provenance is declared | `synthetic`, `transformed`, `public-domain` or `licensed`, plus a required note; a set without one is refused at load |
| 5.2 | improvement is a **pair** | `Improved` requires more caught **and** no more wrongly proposed; being merely more aggressive returns false |

Two controls exist so the harness can be shown to work rather than assumed to:
`always-propose` scores precision 0.326 at a 0.879 false-positive rate, and
`always-abstain` gets recall 0.000, no reportable precision, and a false
negative for every labelled scam. A harness that cannot fail those two is not
measuring anything.

### 10.2 What the harness does **not** do, and must never be read as doing

The shipped fixture set is **68 synthetic cases** using RFC 2606 and RFC 5737
reserved names. Against §§1–9 of this protocol it fails on almost every axis,
and it fails *by design* — it is a regression instrument for decision rules,
not a study:

| This protocol requires | The harness has |
| --- | --- |
| labels from an independent labeller (§3) | labels written by this project, alongside the rule under test |
| the household's real Pi-hole configuration as baseline (§2.1) | a baseline that proposes nothing, unless a named list is supplied |
| observed traffic over a held-out window (§5) | 68 fixtures, in the development partition |
| temporal, lineage and campaign leakage controls (§4) | none — there is no time and no campaign |
| feed delay and withdrawal delay (§6) | not measured |
| cost per decision (§7.1) | not measured |
| thresholds recorded before the run (§8) | no threshold exists, because nothing is being accepted |

**Every `Result` carries these as `NotProtocolConformant`**, and the operator
report prints them *above* the numbers, so a number cannot be read without
them. The null baseline is flagged specifically; supplying a named list clears
that one caveat and no other.

**The rule.** A number from `internal/evaluation` may be cited as evidence
that one decision rule behaves differently from another on fixtures. It may
never be cited as precision, recall or a false-positive rate *of ScamWall*, and
the phrase "synthetic success is not product validation" is the whole of §9
applied to this harness.

### 10.3 Unsupported indicator types appear in the results

`observation.Type.Supported()` is true for `domain` and nothing else. The
fixture set carries `url`, `email-address`, `disposable-email-domain`,
`username`, `ipv4`, `crypto-address` and `phone-number` cases anyway, and they
report as `unsupported` — a decision distinct from both abstention and parse
failure.

That is deliberate. §9's table above lists the indicator types this study
cannot speak to; carrying them as cases means the gap shows up **in the
results** rather than being absent from them, and a future run that quietly
started supporting one would change a visible number.

### 10.4 A result is bound to its inputs, and says when it is not

A study's result is a statement about particular inputs. The harness therefore
records, inside every `Result`, a `Binding` of **digests rather than names**:

| Bound | What it digests |
| --- | --- |
| the fixture set | the exact bytes it was parsed from, captured at parse time |
| the source registry | its canonical contents, with "absent" kept distinct from "present but empty" |
| the baseline | its configuration, not its label |
| the candidate | its configuration, not its label |
| the scoring rules | `SemanticsVersion` |
| the evaluation instant | the fixed time expiry and withdrawal are assessed against |
| the source commit | only when the caller supplies one |

This is not decoration. FINDING-93 recorded a comparison that reported
**"catches 2 more (0 -> 2) at no additional cost"** between two runs over two
*different fixture files* that happened to declare the same `fixture_set_id`
and `version`. `Improved` now refuses a comparison across different fixture
contents, baselines, registries, partitions or scoring versions, and refuses
one where a detector cannot state its own configuration.

The fixture digest is held in an **unexported** field, so a fixture file cannot
assert its own identity — that being the thing the digest exists to establish
independently.

**The harness will not discover the source commit for itself.** The tree it
happens to run in is not necessarily what the rule under test was built from,
and a plausible wrong answer is worse here than an absent one. A result with no
commit says so, in the report, above the numbers.

**`SemanticsVersion` is part of the binding because scoring changes are
invisible in the numbers.** Version 1 is the scoring before FINDING-92;
version 2 excludes invalid-observation cases from every denominator. A v1
result and a v2 result are not comparable even over identical fixtures, and
nothing in either result would otherwise say so.

**Reproducibility is answered, not asserted.** `Result.Reproducible()` reports
which bindings are missing. The superseded harness documented itself as "fully
reproducible from its own output" while binding none of its inputs; a claim a
reader cannot check is worse than no claim, because it stops them checking.

### 10.5 Evidence the harness could not resolve is not a result

A fixture observation that cannot be resolved into the observation store is
**not** dropped. Before FINDING-92 it was, with a bare `continue`, and the
consequences were measured: a labelled-malicious case whose only two
observations were both invalid scored as an ordinary `false_negative`, and a
case with one valid and one invalid observation was **credited** with a
`true_positive_additional` — the rule rewarded for an answer computed from
evidence the harness had thrown half of away. Neither appeared in any count.

Every such failure is now preserved on the case, counted in
`InvalidObservationCases`, given the distinct outcome `invalid_observation`,
and **excluded from `Counts.Cases`** and therefore from every rate. The harness
does not know what the rule would have decided on the evidence the fixture
declared, and a denominator that pretended otherwise would describe the harness
rather than the rule.

The exclusion is carried in `NotProtocolConformant`, and the operator report
prints an **EVIDENCE THE HARNESS COULD NOT RESOLVE** section *before* the rates
it bounds. Dropped samples belong beside the numbers computed without them;
that is ordinary study hygiene and it is enforced here rather than remembered.

### 10.6 The report cannot be forged by the data it reports on

Every externally influenced field — case ids and values, family, category and
type names, detector labels, provider text, a caller-supplied commit — is
escaped before it is printed. FINDING-105 recorded a fixture whose case id
produced this line in the operator report:

```
RESULT: all required gates passed ...  parse_failure
```

`scripts/check.sh` prints `RESULT: all required gates passed` when every gate
passes. A fixture file could forge the exact sentence an operator scans a log
for, and in the same output carry ANSI escapes, a carriage return that
overwrites the line already printed, a Unicode line separator no check for
`\n` sees, and a right-to-left override that reorders what a reader sees
without changing what the program read.

Content is escaped, never dropped: a report must still show what the field
contained. Fields are bounded **after** escaping, and truncation cuts on a rune
boundary — the superseded helper sliced by byte and could emit half a
character.

One consequence is worth stating because it looks like a defect and is not:
the fixture set's `invisible-characters` family renders as escapes.
`secure<ZWSP>login.example.com` printed raw is indistinguishable on screen from
the legitimate name, which is the whole of FINDING-82. Making it visible is the
point.

### 10.7 The rules the harness measures, and the control that makes it a measurement (ORDER 6)

§10.1 … §10.6 are about what the harness refuses. This is about what it
measures, and about one control added so the measurement can be shown to be
one.

**The harness calls the shipped rules rather than restating them.**
`PolicyDetector` runs `internal/policy.Decide`; `ProposalRule` runs
`internal/proposal.DecideIndicator`. A detector that reimplemented a decision
would be scoring its own copy, and the copy is the thing that drifts.

**A deliberately defective rule is in the tree, and it is the point.**
`NaiveSuffixRule` matches by string suffix instead of by DNS label.
`ExactLabelRule` holds **the same membership** and differs in that one thing.
Over `testdata/suffix-confusion-v1.json` — twelve `bad-NN.example.com`
malicious apexes, their twelve `notbad-NN.example.com` legitimate siblings, and
twelve children:

| configuration | caught | wrongly proposed |
| --- | --- | --- |
| exact label matching | 12 | 0 |
| defective suffix matching, same 12 names | 24 | **12** |
| provenance-aware candidate | 24 | 0 |
| always-propose | 24 | 12 |
| always-abstain | 0 | 0 |

`Improved` reports *"catches 24 (was 12) and wrongly proposes 12 (was 0)"* and
refuses to call it an improvement, which is §5.2's pairing doing its job: being
more aggressive is a setting, not a gain.

**A control nobody can fail is not a control.** If the harness could not
separate those two rules it would not be measuring matching, and every number
it produced about a matching change would be noise reported as signal. That is
the reason the defective rule exists and the reason it is kept.

**Mapping three outcomes onto five is a decision, and it is written as a
table.** `internal/proposal` answers propose, abstain or refuse; this harness
scores propose, pass, abstain, unsupported and parse_failure. The mapping is
driven by the REASON, because two of proposal's abstentions are answers — the
threshold was not met; nothing live supports it — and two are declinations —
sources conflict; a rights position forbade the operation. Scoring a licensing
problem as "correctly left alone" would award it a perfect false-positive rate,
which is exactly what §5.2 and the `abstain` outcome exist to prevent.
`TestEveryProposalReasonIsMapped` fails when a reason is added to
`internal/proposal` without that decision being taken.

**Two registries, not one loosened registry.** `evalRegistry` grants every
operation `unknown`, which is right for detectors that consult independence and
never rights. The proposal rule consults rights, so it is measured against a
separate registry whose grants permit. Relaxing the first would have changed
what the existing detectors are measured against, which is a change to their
evidence and not to this code.

**None of this is a study, and §3 still governs.** The fixtures were written by
the project that wrote the rules. `testdata/suffix-confusion-v1.json` carries
`"provenance": "synthetic"` and a note saying so, its partition is
`development`, and every report computed over it carries the conformance
problems §10.2 requires. These are regression numbers. They are not held-out
validity, not real-world effectiveness, and not evidence of production
readiness, and every Phase 4 row stays MISSING.
