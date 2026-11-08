# ScamWall Source Registry — structure, enforcement, and what is now in it

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Status: RESEARCHED, NOT AUTHORISED.** All 85 catalog entries now carry a
record. Every field in every record was read from the URL it cites, on the date
it cites. **Nothing is enabled, no record claims `verified-available`, and no
record declares an intended operation.** Researching a source is not qualifying
it, and qualifying it is not switching it on.

`internal/sourceregistry` loads `docs/source-registry.json` and refuses a record
that breaks the rules this file states; `go test -race ./...` — a required gate
— validates the shipped file on every run. What that does and does not
establish is §6.

---

## 1. What this is for, and where the catalog lives

The catalog of 85 candidates is now **in the repository**, at
`docs/SOURCE_CATALOG.md`. That closes a blocker this file used to record: the
list existed only in the text of an order, so a cleared conversation could erase
the research scope, and no record could be written without reconstructing
provider names from memory — the precise failure this registry exists to
prevent.

What the catalog is: a list of candidates. What it is not: a statement about any
provider's current capabilities, licence terms, or access status. Those are
researched per entry, against the provider's own current documentation, and
recorded here with the date they were read.

**The catalog carried no priority labels**, and so `requested_priority` reads
`unknown` on all 85 records. That is worth stating plainly, because an earlier
version of this project's material referred to entries marked "VERY HIGH": no
such label reached this registry, and no selection can therefore rest on one.

Entering a source here does not enable it. Enabling is a separate decision that
requires a disposition of `verified-available` **and** rights that permit the
intended use.

### 1.1 What the first research pass found, in one table

| | Records |
| --- | --- |
| Catalog entries represented | **85 of 85** |
| Enabled | **0** |
| `verified-available` | **0** — see §3.1 |
| `credentials-required` | 14 |
| `commercial-approval-required` | 21 |
| `historical` | 6 |
| `unavailable` | 3 |
| `unresolved` | 41 |
| Records carrying at least one operation their terms authorise | **2** (catalog 37 and 80, both CC0) |
| Records declaring an intended operation | **0** |
| Entries whose documentation could not be read at all | 11, each naming its blocker |

The 41 `unresolved` records are not 41 unexamined ones. §3.1 explains what that
disposition is carrying, and why the vocabulary as it stands cannot say
anything better.

---

## 2. Record schema

One record per source. Every field is required; `unknown` is a permitted value
and is not the same as absent.

| Field | Meaning |
| --- | --- |
| `source_id` | stable internal identifier. Never reused, never renumbered |
| `catalog_ref` | the entry number in the supplied catalog, or `none` for a source added later |
| `requested_priority` | the priority the catalog stated, preserved verbatim. It is an input, not a finding |
| `official_name` | the provider's current name for itself |
| `official_documentation` | URL of the documentation the record was read from |
| `verified_on` | the date that documentation was read. A record with no date states nothing current |
| `kind` | one of: bulk feed, lookup API, enrichment service, corpus, platform, advisory source, commercial partnership, unknown. `unknown` was added by FINDING-69: eleven entries have a product shape nobody has been able to read |
| `indicator_types` | the types it actually publishes, using the registry's own type vocabulary |
| `classification_meaning` | what the provider's own labels mean. "Spam" from one source and "phishing" from another are not the same claim |
| `authentication` | none, key, account, contract, unknown — FINDING-69 |
| `quotas` | documented request or volume limits |
| `update_cadence` | how often the data changes, as documented |
| `retention` | how long the provider retains records |
| `withdrawal_behaviour` | what happens when the provider retracts an entry: does it disappear, expire, or carry a tombstone |
| `permissions` | one grant **per operation** — see §2.1. **Replaces schema 1's `commercial_use`, `caching` and `redistribution` — FINDING-63.** |
| `intended_operations` | the operations this project intends to perform on this source. Enabling checks these, and only these |
| `attribution_required` | yes, no, unknown |
| `derived_data_restrictions` | what the licence says about data derived from it |
| `upstream_sources` | the sources it aggregates, where documented |
| `upstream_labels` | **Optional. Added by the implementation — C-04.** The machine-readable half of `upstream_sources`. Every entry must resolve to a `source_id` in this registry, to this record's own id (a primary saying "everything here is mine" out loud), or to an entry in the top-level `external_origins` list. A label that resolves to nothing is a configuration error, not a weaker claim. Labels are `[a-z0-9_-]`, at most 64 bytes. It is a **second** field rather than a rule imposed on `upstream_sources` because that field holds human-readable provider names across the shipped records, and turning it into a label list means deciding which of six provider names corresponds to which registry id — research, and the owner's |
| `trust_tier` | **Optional. Added by the implementation — C-07.** `ordinary` (the default, and what an absent key means) or `authoritative`. An `authoritative` source may satisfy the proposal threshold **alone**, and only when the household's policy sets `accept_authoritative_alone`. Only **primary lineage** may hold it: a record naming any upstream, or whose `upstream_sources_completeness` is not `documented_complete`, is refused. An aggregator trusted alone would let one republished corpus block by itself, which is the inflation the independence count exists to refuse |
| `upstream_sources_completeness` | `documented_complete`, `documented_partial` or `unknown`. **Added by the implementation — FINDING-66.** An unknown upstream is not demonstrated independence, and without this field the two were indistinguishable |
| `aggregation_dependencies` | known shared upstreams with other registry entries. This is what stops three feeds being counted as three independent sources |
| `access_status` | the disposition. Exactly one, from the vocabulary in §3 |
| `disposition_reason` | why the record carries that disposition. **Added by the implementation — FINDING-61.** §3 requires that a source whose documentation cannot be read "stays `unresolved` with the reason recorded", and §2 as written provided nowhere to record it |
| `privacy_implications` | what personal data it carries, and whose |
| `intended_permitted_use` | the use this project intends, checked against the fields above |
| `coverage_limitations` | what the source is documented NOT to cover. **Added by the implementation.** ORDER 2 §4 requires it per record |
| `operational_cost` | only where officially published; otherwise `unknown` |
| `enabled` | boolean. Defaults to false. True requires `verified-available` **and** that every operation in `intended_operations` is authorised — §2.1 |

One field belongs to the file rather than to a record:

| Field | Meaning |
| --- | --- |
| `external_origins` | **Optional. Added by the implementation — C-04.** Origins this registry holds no record for: a public corpus, a submission queue, somebody else's aggregate. Without it, lineage is visible only between records this file happens to contain, and two feeds that both republish the same external corpus are counted as two independent voices. An entry may not also be a `source_id` — a label that resolves two ways resolves to two different things, and the independence computation would silently pick one |
| `retired_source_ids` | identifiers that were used once and must never be used again. **Added by the implementation — FINDING-62.** §2 requires that a `source_id` is "never reused, never renumbered", and that cannot be checked against the current file alone: an id deleted in one commit is free for the taking in the next. Retiring it is what makes the rule enforceable |

**Technical availability and permission to use are different fields and are
never collapsed.** A feed that downloads without authentication may still
prohibit the use intended for it.

### 2.1 Permissions are per operation

Schema 1 carried three rights fields and one `enabled` boolean. That model
cannot express what matters, and it failed in both directions — FINDING-63:

* **It over-refused.** A source whose terms permit querying and forbid
  republishing was unusable, though a purely local lookup is exactly what it
  permits. Requiring redistribution rights to perform a permitted local lookup
  is a category error.
* **It under-refused.** `permitted` in three fields said nothing about whether
  ScamWall could keep a copy, use the data to annotate other records, or train
  on it. Those operations were authorised by silence.

Every record now carries a grant for each of seven operations. An operation
with no grant is refused: silence is not a permission.

| Operation | What it covers |
| --- | --- |
| `retrieval` | fetching the data at all |
| `local_storage` | keeping a local copy beyond one request |
| `enrichment` | using it to annotate or score records from elsewhere |
| `model_training` | using it as training data. Frequently prohibited where everything else is permitted, which is why it is not folded into enrichment |
| `commercial_use` | use in a commercial context |
| `redistribution` | passing the provider's records to anyone else |
| `derived_output` | publishing something computed FROM it. A blocklist derived from a feed is not the feed, and a licence may treat the two differently in either direction |

A grant is `permitted`, `prohibited`, `conditional`, `unknown`, or
`not_applicable`. **Only `permitted`, and `conditional` with every condition
satisfied, authorise anything.** `unknown` refuses: an unestablished right is
indistinguishable from an absent one at the moment it matters.

`conditional` never authorises on its own. It carries an enumerated list of
conditions, each with `satisfied` (`yes`/`no`/`unknown`) and a `basis` saying
why. Any condition that is unsatisfied or unassessed refuses the operation, and
a `conditional` grant with no conditions is refused outright — otherwise
`conditional` would be a synonym for `permitted` written by an author who had
not finished reading.

**Permission to query does not imply permission to publish**, and the reverse
is not implied either. Each operation is assessed and checked on its own.

### 2.2 Every rights assertion carries its evidence

A grant that asserts anything — `permitted`, `prohibited` or `conditional` —
must cite the provider's own terms: a URL, the day it was read, and what the
page said. A rights assertion with no citation is an opinion. FINDING-64.

Evidence keeps four things apart that a single free-text field would blur, and
whose blurring is the usual way a provenance record becomes untrustworthy:

| Slot | What belongs in it |
| --- | --- |
| `provider_terms` | what the provider's terms SAY, quoted |
| `technical_capability` | what the documentation says the thing CAN DO. A marketing page describing a capability is not a term of licence, and a licence permitting a use is not evidence the API exposes the field |
| `researcher_interpretation` | this project's READING, labelled so it can never be mistaken for the provider's words |
| `unresolved_questions` | what is still not known, recorded rather than rounded to a conclusion in either direction |


---

## 3. Disposition vocabulary

Exactly one per source:

| Disposition | Meaning |
| --- | --- |
| `verified-available` | documentation read, access confirmed, and rights permit the intended use |
| `credentials-required` | available in principle; needs a key or account that has not been obtained |
| `commercial-approval-required` | needs a contract, membership, or paid tier |
| `historical` | the dataset exists but is not current. Usable as seed or training data if rights permit, never as live intelligence |
| `unavailable` | the provider or dataset no longer exists, or refuses this use |
| `unresolved` | not yet researched, or researched with something still outstanding — §3.1 |

`unresolved` and `unavailable` are not synonyms, and neither is a reason to
guess. A source whose documentation cannot be read stays `unresolved` with the
reason recorded.

### 3.1 What `unresolved` is carrying, and the strain it is under

Forty-one records carry `unresolved`, and they are not one thing. Three
distinguishable states share the value:

| State | Example | Count |
| --- | --- | --- |
| Documentation could not be read at all — 403, an unverifiable TLS chain, a host the fetcher cannot reach, a timeout | catalog 34, 35, 42, 47, 50, 58, 64, 65, 71, 75, 84 | 11 |
| Documentation read; the provider states **no terms**, or points at terms on a page that was not read | catalog 4, 14, 19, 24, 32, 36, 78 | 7 |
| Documentation read, **terms read and recorded in full**, and the only thing outstanding is access confirmation | catalog 8, 11, 12, 18, 22, 23, 37, 62, 80 among others | the rest |

**The third state is the strain.** `verified-available` requires that access is
*confirmed*, not merely documented — and the order under which this research was
done forbids fetching the data. So a record whose licence is CC0, whose formats
are published, and whose cadence is stated still cannot claim
`verified-available`, and the only other honest value is `unresolved`, whose own
definition begins "not yet researched". That is close to backwards for catalog
37, where every rights question is answered.

**This is recorded rather than fixed, deliberately.** Adding a value —
`rights-cleared`, say, for "researched; access confirmation outstanding" —
would be redesigning the disposition vocabulary to suit the convenience of the
research pass that first exercised it, which is exactly what the order
authorising this work forbids. The existing model is used, `disposition_reason`
carries the distinction on every affected record in words, and the vocabulary
question is put to the next order rather than answered here.

What must not happen in the meantime: reading `unresolved` as "nothing is known
about this source". On nine of these records, more is known than on several
records carrying a definite disposition.

---

## 4. Rules that bind every record

* **Never fetch the malicious destinations a feed describes.** Collecting
  intelligence about a URL is not visiting it. These are separate code paths
  and separate decisions, and the second one is not authorised.
* **Downloaded records are untrusted input.** So are provider documentation
  pages, archives and message bodies. They are parsed defensively and never
  executed.
* **A priority label overrides nothing.** Not licensing, not access, not
  privacy, not the evidence requirements. No priority label reached this
  registry at all — §1.
* **A provider report is an allegation or an observation with provenance**, not
  a verified fact, and the registry records which it is.
* **No household URL, message, identity or file is submitted to any third
  party**, at any point, by anything this registry enables.

### 4.1 Rules the first research pass turned from prose into findings

Each of these was written as a caution before any research happened. Each is now
attached to specific records, which is the difference between a principle and a
finding.

| Rule | Where it bit |
| --- | --- |
| **A public URL is not permission.** | Catalog 7: the OpenPhish community feed downloads without authentication, and its Terms of Use forbid "security operations, threat intelligence, detection, enrichment ... customer protection" without written consent. Availability and permission point in opposite directions on the same feed |
| **An absent restriction is not a grant.** | Catalog 38: FakeFilter publishes daily data and no licence — the repository has no `LICENSE` file. Nothing is granted, so nothing may be used. Compare catalog 24, where a statutory, appealable, five-minute-cadence list states no reuse terms either, and is therefore equally unusable |
| **Do not transfer one product's terms to another.** | Catalog 11 and 12: Spamhaus DROP is free with a credit requirement and no restriction on business type; the Spamhaus DNSBLs including DBL are free only for low-volume non-commercial users, with an annual subscription required for commercial use. One provider, two answers |
| **Aggregator copies are not independent corroboration.** | Catalog 9 aggregates four other catalog entries by name. Catalog 20 says outright that "IP Lists are a property of their maintainers". Catalog 21 counts how many upstream lists name an address, which reads as confidence and is not, whenever two upstreams share a source |
| **An aggregator's licence may not reach its content.** | Catalog 20 (GPLv2 tooling, third-party data), 21 (The Unlicense on a repository of other people's lists), 23 (a documented per-source licence table including "non-commercial with attribution") |
| **Historical corpora are not current feeds.** | Catalog 40, 41, 43, 44, 45 and 57 are `historical`. Catalog 43 was donated in 1999. Catalog 57's front page claims daily updates and its data repository last moved in June 2022 |
| **Scanner observations are not scam attribution.** | Catalog 25's documentation defines no maliciousness verdict; catalog 30 defines its noise flag as "observed scanning the internet in the last 90 days"; catalog 78 records that a certificate was issued |
| **Risk signals are not blocking grounds.** | Catalog 37, 38 and 39 list disposable email domains — a fact about a mail service. Catalog 54 reports line type. Catalog 74 reports registration age. None is a finding of wrongdoing |
| **Community reports are allegations.** | Catalog 29 requires a reporter to warrant the association and disclaims liability for false reports; catalog 55 attaches a confidence score and a verified flag to community submissions |
| **Renames and acquisitions need evidence and a retained mapping.** | Catalog 16 (AlienVault → LevelBlue), 56 (BitcoinAbuse → merged into Chainabuse), 72 (Cybersixgill → Bitsight, evidenced by the provider's own 301), 73 (ke-la.com → kelacyber.com, likewise). Each keeps its catalog number |
| **A platform is not a source.** | Catalog 15 (MISP, a feed directory), 10 (Spamhaus, a provider with several differently-licensed products), 74 (RDAP, a protocol whose every server sets its own terms) |

---

## 5. What has NOT been done

* **No feed, API or dataset has been fetched, in whole or in part.** No
  indicator has been retrieved. Research was documentation only.
* No account has been created, no key requested, no terms accepted, no
  membership taken, and no provider contacted.
* No commercial discussion has begun.
* No source is enabled, and none has a `verified-available` disposition.
* No record declares an intended operation. Operations are proposed in prose —
  `docs/IMPLEMENTATION_PLAN.md` — and written here only when the operator
  approves a pilot.
* Independence has been **claimed** for no source. `IndependenceClaimable`
  returns true only where upstreams are `documented_complete`, and that is a
  statement about what was recorded, not a discovery about what is true.

---

## 6. What the validator enforces, and what it cannot

`internal/sourceregistry` is the machine-readable half of this file.
`docs/source-registry.json` is the registry. `go test -race ./...` — already a
required gate — validates the shipped file on every run, so a record that
breaks a rule below cannot be committed without the gate going red. No new gate
was added to `scripts/check.sh`: it would have run the same Go test a second
time, and a gate that duplicates another gate makes the suite slower without
making it stricter.

### Enforced

| Rule | Where it comes from |
| --- | --- |
| Every field is present. **An absent key is refused even though `unknown` is accepted**, because they are different claims and a decoded struct cannot tell them apart | §2 |
| A misspelled field name is refused, by path, rather than silently dropped | §2 |
| A field of the wrong TYPE is reported by path and dropped, so one bad field does not abort every other diagnostic in the file | FINDING-67 |
| A **duplicate JSON key** is refused. `encoding/json` keeps the last occurrence silently — for a document of record that is the worst resolution, because the reviewer reads the first value and the program uses the second | FINDING-67 |
| Trailing content after the document, and unknown top-level keys, are refused | FINDING-67 |
| Input over 8 MiB is refused. This file is hand-maintained; a larger one is a mistake or a hostile input, not a bigger registry | FINDING-67, §4 |
| An empty string is refused wherever `unknown` is the available answer | §2 |
| `kind`, `authentication`, `attribution_required`, `access_status`, grant status, condition satisfaction and upstream completeness are closed vocabularies. `kind` and `authentication` accept `unknown` — FINDING-69; everything else outside a set is still refused | §2, §3, §2.1 |
| An unsupported `schema_version` is refused **and validation stops there**, rather than emitting confident findings about a document whose field meanings are unknown | FINDING-67 |
| `source_id` is unique within the file and cannot take an id in `retired_source_ids` | §2 |
| Two records cannot claim the same `catalog_ref` | §2 |
| A researched record must carry a real, non-future `verified_on` and an `https` documentation URL. `unresolved` may leave both `unknown`, because it means nobody has looked | §2, §3 |
| **Every operation carries a grant**; an operation nobody assessed is not authorised by silence | §2.1 |
| **`conditional` authorises only when every condition is `satisfied: yes` with a basis.** Unsatisfied and unassessed both refuse | §2.1 |
| `unknown` and `not_applicable` refuse | §2.1 |
| Conditions on a non-conditional grant are refused | §2.1 |
| An asserting grant must cite `provider_terms`, and every citation needs an `https` URL, a real non-future date, and a quote | §2.2 |
| `enabled: true` requires `verified-available` **and** that every operation in `intended_operations` is authorised — not that unrelated rights happen to read `permitted` | §1, §2.1 |
| Lineage edges must name records that exist, must not be self-edges, must not repeat, and **must not form a cycle** | §2, FINDING-66 |
| A record claiming `documented_complete` upstreams while carrying lineage edges and no upstreams is refused as self-contradictory | FINDING-66 |
| Removing a record without retiring its id is refused, **by comparison against the previous committed version**, and retirement is permanent | FINDING-65 |
| The shipped registry enables nothing and claims no `verified-available` disposition | §1, §3.1 |
| The shipped registry declares **no intended operation**, and no record both authorises an operation and declares it intended | §2.1, and the note below |

**The note on that last row, because a test was deliberately weakened and that
should not be discoverable only by reading a diff.** Until the first research
pass, a test asserted that the shipped registry authorised *no operation at
all*. It could, because the file held no records. It cannot now: two providers —
catalog 37 and catalog 80 — release their data under CC0, which grants every
operation with no condition to satisfy. Recording those as `conditional` or
`unknown` in order to keep a test green would have been a false record, and
producing false records is the one thing this registry exists to prevent. So the
record was written truthfully and the test was replaced.

What replaced it guards the thing that matters. A **grant** says what a provider
permits. `intended_operations` says what this project proposes to do. Harm needs
both, and the shipped file now has none of the second: no record declares an
intended operation, so no authorised operation is also a proposed one. Moving a
proposal from `docs/IMPLEMENTATION_PLAN.md` into the registry is the act the
replacement test is positioned to make deliberate.

**This is weaker than what it replaced, and the honest summary is that the
earlier test was only as strong as it was because the file was empty.**

### Not enforced, and not enforceable here

* **Whether any field is true.** A grant of `permitted` is checked to be a
  member of the vocabulary and to carry a citation. Whether the cited page
  actually says what the quote claims, and whether the licence really permits
  the operation, is a human reading a human document — no validator can do it.
  The same holds for every other field a person types.
* **Whether `official_documentation` belongs to the provider.** It is checked to
  be an absolute `https` URL. Nothing checks whose.
* **Whether `upstream_sources` is complete**, and therefore **whether two
  sources are independent**. `upstream_sources_completeness` records how much is
  known, and `IndependenceClaimable` refuses to call independence demonstrated
  when the answer is `unknown` or `documented_partial` — but that is a check on
  what was recorded, not a discovery of what is true.
  `aggregation_dependencies` is checked for dangling references and cycles; it
  cannot discover a shared upstream nobody recorded. Independence remains a
  research finding, not a computed property. This is the limit that
  matters most, because §2 offers that field as the thing that "stops three
  feeds being counted as three independent sources" — it stops three *recorded*
  dependencies being ignored, which is a smaller claim.
* **Historical non-reuse, from the current file.** The current-file validator
  sees one version. It enforces uniqueness within that version and refuses an
  id already retired; it cannot know that an id ever meant something else. The
  history walk closes this by comparing **every consecutive committed pair** of
  versions and refusing a removal that did not retire its id — but note where
  that bites: it flags the **removal**, not the later reappearance. By the time
  an id is taken again the baseline no longer mentions it, and nothing at that
  step can tell. Three rules together give the invariant, and none gives it
  alone: removal must retire, retirement is permanent, and a retired id cannot
  be taken. The walk also says nothing about a rewritten history, or about a
  version that never reached a commit.
* **Whether a condition recorded as `satisfied: yes` really is.** The
  validator requires the condition to be enumerated, assessed, and given a
  `basis`; it cannot check the basis. What it does guarantee is that nothing is
  authorised on a condition nobody assessed — `unknown` refuses exactly as `no`
  does — and that a `conditional` grant with no conditions authorises nothing.

So the validator makes a false record harder to write **by accident**. It does
not make one impossible to write **on purpose**, and it is not evidence about
any provider.

