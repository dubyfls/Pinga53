# The evidence document, the signer authority, and the proposal policy

Three local documents that `scamwall propose` reads, and nothing else. None is
fetched, none is written, and no default path exists for any of them: each is
named explicitly on the command line.

Implementation: `internal/feed/evidence.go` (the first two),
`internal/proposal/policy.go` (the third). Where this document and the code
disagree, the code is the schema and this file is the defect.

---

## 0. What a signature establishes, and what it does not

**Authenticity only.** A verified signature says that the holder of a key the
operator recorded produced these bytes. It says nothing about whether any claim
inside them is accurate, and nothing about whether the signer was entitled to
make it.

`docs/REQUIREMENTS_MATRIX.md` §4.2 states the same thing as a Phase 3
acceptance criterion. It is repeated here because this is where somebody
writing a document will read it.

---

## 1. The evidence document — `schema_version: 2`

### 1.1 Why it is not the v1 feed

The v1 feed (`internal/feed/feed.go`, `schema_version: 1`) is a publisher's
list of domains to block. Every record carries an action and a confidence, and
there is no field saying WHO observed the domain — there could not be, because
the document has one author and asserts everything in its own voice.

A v1 record **must not** be given a source. Assigning its records to the feed
id, the key id, or a literal `"legacy"` would manufacture provenance nobody
asserted, and every rule that counts sources would then count it.

So v1 is untouched. `Validate` refuses `schema_version: 2`, `ValidateEvidence`
refuses `schema_version: 1`, and the refusal says why the two are different
rather than only that they are.

### 1.2 Envelope

```json
{
  "schema_version": 2,
  "signature": {
    "algorithm": "ed25519",
    "key_id": "<an id the signer authority names>",
    "value": "<base64 Ed25519 signature over the payload bytes>"
  },
  "payload": { "...": "the manifest, below" }
}
```

The signature is over the **payload bytes as they appear in the file**, not
over a re-encoding of the decoded value.

The key id is resolved in the operator's signer-authority document **before**
the signature is checked, because the key to check it with comes from there and
from nowhere else. There is no fallback key: a document signed by a key the
operator has not recorded is not admitted on the strength of being well-formed.

Unknown fields are refused, at every level. A field this build does not
understand may qualify what the publisher meant, and acting on a different
document than the one that was signed is worse than refusing.

A second JSON document appended after the first is refused.

### 1.3 Manifest (the payload)

```json
{
  "manifest_version": "1.0",
  "feed_id": "<the publisher's own id for this document>",
  "issued_at": "2026-06-01T00:00:00Z",
  "expires_at": "2026-06-02T00:00:00Z",
  "records": [ ... ]
}
```

| check | behaviour |
| --- | --- |
| `manifest_version` | must be `1.0` |
| `issued_at`, `expires_at` | both required, `expires_at` strictly after `issued_at` |
| not yet valid | `issued_at` more than 5 minutes (`ClockSkewTolerance`) in the future is refused |
| expired | `expires_at` at or before the evaluation instant is refused |
| empty | a document with no records is refused |
| too many | above `--max-records` is refused |

### 1.4 Record

```json
{
  "type": "domain",
  "value": "bad.example.com",
  "source_id": "src-a",
  "source_record_id": "a1",

  "provider_classification": "phishing",
  "classification": "malicious",
  "state": "active",
  "status": "current",
  "category": "credential-phishing",

  "first_seen": "2026-05-01T00:00:00Z",
  "last_seen":  "2026-05-30T00:00:00Z",
  "expires_at": "2026-07-01T00:00:00Z",

  "raw_retention": "none",
  "raw": ""
}
```

| field | required | notes |
| --- | --- | --- |
| `type` | yes | from `internal/observation`'s vocabulary. Only `domain` is implemented; a known-but-unsupported type and an unknown one are refused with **different** reason codes |
| `value` | yes | as the SOURCE wrote it, before canonicalisation. `internal/domain.Assess` canonicalises and its failures are SYNTAX failures — never a claim that the name is suspicious |
| `source_id` | yes | authenticated, and not thereby true. See §2 |
| `source_record_id` | no | the provider's own record id. Load-bearing: it is what makes a correction attachable to the thing it corrects, and it is scoped to `(source_id, source_record_id)` — never to the record id alone |
| `classification` | yes | mapped into `internal/observation`'s closed vocabulary |
| `provider_classification` | no | the provider's own word, verbatim and bounded, kept beside the mapped form so a mapping can be audited rather than trusted |
| `state` | yes | what the provider says about liveness |
| `status` | no | `current` (default) or `withdrawn` |
| `first_seen`, `last_seen`, `expires_at` | no | the provider's own window. Absent is absent, never the zero time. Impossible orderings are refused |
| `raw_retention` | no | `none` (default) or `retained` |
| `raw` | no | see §1.5 |

**Corrections.** Two records sharing `(source_id, source_record_id)` are two
revisions of one statement, and the later supersedes the earlier — **including
across canonical domains**. A provider that revises the SUBJECT of a record is
making one statement twice, not two statements, and the superseded subject
stops being live while staying in the history.

**Duplicates.** The same source record saying the same thing twice is a
duplicate, not a second voice. Support is counted **per source**, never per
record: one provider publishing an indicator under three record ids is one
source.

### 1.5 Raw provider content

Absent by default, and its absence is not the whole answer.

| what the document says | what happens |
| --- | --- |
| no `raw_retention`, or `none` | the field defaults to `none`. Any `raw` sent anyway is DROPPED and the drop is reported |
| `retained`, and the source's registry record authorises `local_storage` | kept |
| `retained`, and it does not | dropped, reported, and **the record is still admitted** — the normalised observation cleared the `local_storage` grant separately |
| anything else | `record_invalid`. An invented retention value is a malformed field, not a policy |

**Removing raw bytes does not authorise keeping what was extracted from
them.** The normalised record is a separate operation, asked separately. See
§4.

---

## 2. The signer authority — `schema_version: 1`

The operator's statement about who may speak for what.

```json
{
  "schema_version": 1,
  "note": "why these signers exist",
  "signers": [
    {
      "key_id": "publisher-key-1",
      "public_key": "<base64 Ed25519 public key>",
      "asserts_source_ids": ["src-a"],
      "aggregator_for": ["src-b"],
      "note": "the operator's own record of why"
    }
  ]
}
```

### 2.1 A signature is not an authority

`source_id` is a field **inside the signed payload**. A signer free to write
any source id it liked could manufacture its own corroboration: assert one
indicator under three source ids and collect three independent votes for it.
Signing a claim does not make it true; it makes it attributable to the signer,
which is a different and much weaker fact.

So authority is recorded by the operator, here, and enforced against every
record. A record whose `source_id` is outside its signer's authority is
**refused and reported** — not dropped.

### 2.2 The two grants

| field | what it claims |
| --- | --- |
| `asserts_source_ids` | this signer speaks for these sources in its own right |
| `aggregator_for` | this signer is an approved AGGREGATOR for these — it republishes what those sources said rather than observing it |

**ADMISSION is identical. COUNTING is not.** A record under either grant is
admitted, and the report records which grant admitted it. But a claim that
reached this build only by republication is **evidence and is not independent
confirmation**, so it does not count towards `min_independent_sources`: one
signer republishing two upstreams in one document is one attestation, and
counting it as two is the inflation the provenance model exists to prevent
(FINDING-122).

An operator who wants a source's claim to count independently lists it under
`asserts_source_ids` instead — which is the operator stating that this signer
speaks for that source in its own right. **The schema already had the knob;
this is what makes it load-bearing.** No `count_aggregated_as_independent`
flag was added, because it would be a second way to say the same thing and the
two would drift.

`accept_unestablished_independence` is deliberately NOT reused either. It
means "the registry cannot establish lineage between these sources", which is
a different problem with a different fix; one flag covering both would let an
operator loosen one and silently loosen the other. Asserted by
`TestAcceptUnestablishedIndependenceDoesNotAdmitAggregatedClaims`.

A source id in **both** lists resolves to `own`: the stronger claim wins, or
adding an id to one list would silently weaken the other.

An aggregated claim is REPORTED, in `aggregated_sources` and in the text
report, with reason code `aggregated_claims_are_not_independent_confirmation`
when it is what the threshold was short of. An operator who cannot see the
claims cannot act on them.

**What this does not establish.** That a DIRECT assertion is true; that two
directly-asserting signers are independent of each other; that a source id
names a real organisation; or that an aggregator has not silently dropped or
altered what it republished — nothing in schema 2 carries the upstream's own
signature.

### 2.3 What is refused

| | |
| --- | --- |
| `"*"` as a source id | there is no spelling for "may assert anything"; the refusal says why |
| a signer with neither grant | an operator who wrote the record meant something by it, and granting nothing silently would read identically to granting everything in a report that only listed refusals |
| one key id twice | the authority would depend on which record was found first |
| a public key that is not 32 base64 bytes | |
| no signers at all | nothing could ever be admitted |
| a file over 1 MiB, more than 64 signers, or more than 4096 source ids on one signer | a mistyped path finding a core dump is refused by size rather than parsed |
| unknown fields, or a second document | |

Authority is **not** derived from the registry, and **not** from the key id
matching the source id. The registry says what a source IS; it does not say who
may speak for it, and inferring one from the other is the same conflation in a
different direction.

---

## 3. The proposal policy — `schema_version: 1`

```json
{
  "schema_version": 1,
  "note": "this household's policy",
  "min_independent_sources": 2,
  "proposal_scope": "exact",
  "accept_unestablished_independence": false,
  "accept_authoritative_alone": false,
  "exceptions": [
    {"value": "bank.example.com", "scope": "exact", "note": "the household's bank"},
    {"value": "work.example.net", "scope": "subdomains", "note": "the employer's VPN"}
  ]
}
```

### 3.1 `min_independent_sources` has no default

It is required, and a policy that omits it is refused rather than given a
number. Any default would be a recommendation this project is in no position to
make: the right number depends on which sources are enabled, what their lineage
is, and what the household's tolerance for a false proposal is. A default would
be quoted later as ScamWall's advice.

A threshold below 1 is refused: proposing everything any source mentions is not
a policy.

### 3.2 Scope is written down, never inferred

"Block example.com" is ambiguous in the way that matters — that one name, or
everything under it. Inferring which from the shape of the name produces a rule
whose reach depends on a heuristic the operator never saw.

| scope | reaches |
| --- | --- |
| `exact` | the name itself, and nothing else |
| `subdomains` | every name **strictly beneath** it, and **NOT** the name itself |

**The apex decision.** `subdomains` excluding the apex is a product choice, and
it is this one because the two scopes then compose: an operator who wants both
writes both, and an operator who wants only the children can say so. Under the
other reading, "children but not the apex" has no spelling at all. It is
revisable without a silent change of meaning, because the scope is explicit in
every document that uses it.

**Matching compares canonical DNS labels.** Never a substring, never a naive
suffix. `strings.HasSuffix("notbad.example.com", "bad.example.com")` is true
and `notbad.example.com` is somebody else's domain; requiring the separator to
be part of the match is what makes the comparison be about labels.

**Public suffixes.** `com`, `co.uk` and `github.io` cannot be written at any
scope, because `internal/domain.Normalize` refuses a public suffix and a single
label outright, from the compiled `golang.org/x/net/publicsuffix` list. The
list is a snapshot in that module, not a live one: a name that becomes a public
suffix after this build was compiled is not refused.

### 3.3 Exceptions

The household's own statement, and it outranks every source. A bank, a school
portal, an employer's VPN endpoint: the cost of proposing one of those is not
symmetric with the cost of missing a scam site, and no amount of corroboration
from strangers should override the person whose network it is.

**Precedence is by specificity** — the exception naming more labels wins, and
`exact` beats `subdomains` at equal depth. It is the only rule under which
adding a NARROWER exception cannot change the decision about a name the
narrower one does not itself reach. Under "first match wins" the answer would
depend on file order.

The same `(name, scope)` pair twice is refused rather than deduplicated: the
operator wrote the rule twice and probably meant two different things by the
second one.

A matched exception is recorded on the outcome **whichever reason wins**, so an
operator is never left wondering whether theirs was seen.

### 3.4 `accept_unestablished_independence`

Defaults to `false`, which is the fail-closed direction: a source whose
upstreams are undocumented has not demonstrated independence, and counting it
is the inflation the source registry exists to prevent.


### 3.4a `accept_authoritative_alone`

Defaults to `false`. When true, **one** adverse source holding the source
registry's `authoritative` tier satisfies `min_independent_sources` by itself,
and the outcome carries its own reason — `authoritative_source_accepted_alone`
— so a one-source proposal can never be read as ordinary corroboration.

Two things keep this from becoming a way around the provenance model:

* **Only primary lineage may hold the tier.** A record marked `authoritative`
  that names any upstream, or whose `upstream_sources_completeness` is not
  `documented_complete`, is refused by the registry validator. An aggregator
  trusted alone would let one republished corpus block by itself, which is the
  inflation the independence count exists to refuse.
* **The household still decides.** The tier is a claim the registry author
  makes about a provider; acting on one source is a decision about this
  network's risk. A registry cannot grant itself permission to take it.

The tier is reported on every outcome an authoritative source takes part in,
**whether or not the switch was on**, because an operator deciding whether to
turn it on needs to see that it would have made a difference.

### 3.5 `automatic` — the household's unattended-blocking contract

A proposal is a statement that a domain met the policy. The product this is
for **blocks routine scam domains without asking about each one**, and that is
a larger grant. The difference is not a flag: it is nine values the household
has to have decided.

```json
"automatic": {
  "enabled": null,
  "max_additions_per_run": null,
  "max_removals_per_run": null,
  "max_additions_per_day": null,
  "max_removals_per_day": null,
  "block_lifetime": null,
  "on_source_outage": null,
  "alert_channel": null,
  "emergency_disable_path": null
}
```

`deploy/compose/policy.example.json` is exactly this, and every value is
`null` on purpose: a household filling in a blank needs to see the field
names, and an explicit `null` means the same as an absent key. Neither is
given a value by this build.

| field | what it decides |
| --- | --- |
| `enabled` | whether the contract may run unattended. Required **even when false**: "we decided not yet" and "we have not decided" are different states and only one of them is finished |
| `max_additions_per_run` | how many blocks one run may add. A run that would exceed it is held **entirely**, not truncated to the limit |
| `max_additions_per_day` | a limit across runs. **Enforced.** Adds beyond what the day has left are **deferred, newest evidence first** — carried to the next run, never dropped. A run given the day's journal counts what prior runs did, *including what shadow runs proposed*: in this build the only path from a decision to the appliance is an operator applying a shadow plan. A run given **no** journal still applies the number to itself, so that not keeping a journal is never the more permissive option, and the plan's `not_enforced_by_this_build` says which of the two happened |
| `max_removals_per_day`, `max_removals_per_run` | a limit on removals. The rule is `proposal.AssessRemovals`, including the abnormal-run guard: a run proposing to remove more than 25% of what ScamWall owns is held whole, because a removal is an unblock. **Nothing calls it yet** — this build keeps no ownership ledger, so it proposes no removals and the caps have nothing to bound |
| `block_lifetime` | how long one ScamWall block survives without being re-justified, as a Go duration (`"720h"`). **Declared and not enforced** — measured from when a block was added, which needs an ownership ledger |
| `on_source_outage` | `"hold_existing_blocks"` or `"expire_existing_blocks"`. What happens to existing blocks when the evidence stops arriving. No default, and no third option |
| `alert_channel` | where an unattended run reports what it did. Free text the household writes; **this build never contacts it** |
| `emergency_disable_path` | a path whose EXISTENCE stops automatic blocking. A file rather than a field, because the household needs a way to stop it that does not involve editing JSON correctly under pressure |

#### 3.5.1 Nothing defaults, and a missing value is visible

A default here would be ScamWall choosing, on the household's behalf, how many
of their domains it may block before a person looks at it. Every plausible
default is either so tight it never runs or so loose it is not a limit, and
whichever were shipped would be quoted back as a recommendation.

So a missing value is **UNRESOLVED**. The policy still loads, the run still
produces its proposal decisions, and every indicator that would otherwise have
qualified answers `abstain` under `automatic_contract_unresolved`, with the
missing field named in the output. Nothing is substituted.

A value that is **present and malformed** is a different case and is refused
at load: a negative limit, a zero lifetime, an outage word this build does not
know, an empty alert channel or an empty stop path. The household wrote
something and meant something, and this build cannot guess what.

#### 3.5.2 Four states, kept apart

| state | meaning |
| --- | --- |
| `not_configured` | the policy has no `automatic` key. The household has not started |
| `unresolved` | the key is there and at least one required value is missing. They are **named** |
| `disabled` | every value is set and `enabled` is false. A complete contract, switched off |
| `active` | complete and switched on |

An operator chasing a missing block needs to know which of these they are in,
and a single "automatic blocking is off" would not tell them.

#### 3.5.3 Three outcomes, and the contract never upgrades one

`automatic_block`, `abstain`, `refuse` — kept distinct for the reason the
proposal decisions are. An abstention is answered by more evidence or a
different policy number; a refusal is answered by neither.

The proposal decision is the **floor**. An indicator the report abstained on is
abstained here; one it refused is refused here, with its identity still
withheld if a rights position withheld it. The contract only ever moves a
`propose` **down**, because every rule in it is a further condition on acting
without asking. A household that has not finished it gets the protection
decisions they already had, reported honestly as not-blocked.

#### 3.5.4 An abnormal bulk change holds the whole run

Three qualifying domains against `max_additions_per_run: 2` produces **zero**
blocks and three abstentions under `bulk_change_exceeds_per_run_limit`, not two
blocks and one abstention. A limit reached is the signal that something
upstream changed, and applying the first N of a batch nobody vetted is the
worst reading of both options: the household gets some of an unvetted change
*and* a partial state the next run reconciles differently.

#### 3.5.5 An absent `exceptions` key is not an empty one

Both decode to no exceptions and they are different statements about whether
the household has been asked. The presence of the key is taken from the raw
document, kept, and is **in the policy digest**, so two reports cannot share a
policy identity when one of them was decided under a policy nobody had
reviewed for exceptions.

#### 3.5.6 The contract is in the policy digest

Whole, including its unset fields, and carried as pointers — so filling a value
in changes the digest exactly as much as changing one does. Two policies that
differ only in `max_additions_per_run` produce different unattended behaviour,
and a digest that ignored the block would let a reader compare two reports,
find the same policy digest, and conclude they were governed by the same terms.

---

## 4. Rights, at the operation boundary each one actually is

`docs/SOURCE_REGISTRY.md` defines seven operations. They are applied
**separately, to separate things**:

| what is being done | operation asked of the source's registry record |
| --- | --- |
| keeping the provider's own response bytes | `local_storage` |
| keeping the normalised observation | `local_storage` |
| combining it with another source's observations | `enrichment` |
| putting a derived result in a report the operator reads | `derived_output` |
| anything leaving the household | `redistribution` — **never exercised** by this command |
| fetching it | `retrieval` — **never exercised**; nothing is fetched |

A storage refusal refuses the RECORD. An enrichment or derived-output refusal
refuses the INDICATOR — derivation does not launder provenance, so one
contributing source's prohibition refuses the whole derived result however much
the others permit.

`unknown`, `not_applicable`, `prohibited`, and `conditional` with any condition
unsatisfied or unassessed all refuse. Only `permitted`, and `conditional` with
every condition recorded as satisfied with a basis, authorise anything.

---

## 5. Reason codes

Stable, machine-readable, and closed. They appear in the report and in its
JSON; changing one is a change to the output format, not a rename.
`internal/proposal.AllReasons` is the vocabulary and a test enumerates it.

**Record admission** — a way a record does not become evidence:

| code | |
| --- | --- |
| `record_value_invalid` | the value is not valid for its type. SYNTAX only |
| `indicator_type_unknown` | not in the vocabulary at all |
| `indicator_type_unsupported` | a known type this build does not implement |
| `signer_not_authorised_for_source` | the signature verified and the signer may not speak for that source |
| `source_not_in_registry` | nothing establishes whose data this is |
| `source_retired` | the id was used once and withdrawn; its records must not be re-attributed |
| `source_rights_refuse_local_storage` | |
| `raw_retention_not_authorised` | |
| `record_invalid` | failed observation validation for a reason the above do not name |

**Indicator outcome:**

| code | decision | |
| --- | --- | --- |
| `corroborated` | propose | the threshold was met with adverse classifications |
| `insufficient_independent_support` | abstain | admissible evidence, below the threshold |
| `no_live_evidence` | abstain | nothing current supports it at the evaluation instant |
| `expired_only` | abstain | every supporting observation has lapsed |
| `withdrawn_only` | abstain | every supporting source has withdrawn |
| `sources_conflict` | abstain | current sources disagree. Reported, never resolved |
| `name_requires_review` | abstain | the written form carried `invisible_character` or `mixed_script`. A property of the NAME; never evidence of maliciousness |
| `user_exception` | refuse | the household said no |
| `source_rights_refuse_derived_output` | refuse | |
| `source_rights_refuse_enrichment` | refuse | |

**Abstain and refuse answer different questions.** Abstaining says the evidence
was read and did not meet the policy — a policy question, answerable by
changing the policy. Refusing says it will not be proposed and not because the
evidence fell short. Changing `min_independent_sources` cannot turn a refusal
into a proposal, and folding the two together would invite an operator to try.

---

## 6. The report

Text and JSON carry the same content. Every caller-controlled field is escaped
and bounded by `internal/safetext` before it is printed: an ESC in a terminal
is a command, a newline lets a field forge a line of output, and a bidi
override reorders what a reader sees without changing what the program read.

The report **binds** what it was computed from, by digest rather than by name:

| binding | identifies |
| --- | --- |
| `evidence_digest` | the exact bytes of the signed document |
| `evidence_feed_id`, `evidence_manifest_version` | what the document CLAIMS about itself, for readability. Never relied on for identity |
| `signing_key_id` | the key id the envelope carried |
| `authority_digest` | the **WHOLE** signer-authority document |
| `signer_grant_digest` | the **ONE** signer that signed this document |
| `registry_digest` | the registry's canonical contents |
| `policy_digest` | the policy AS REPORTED — **including the operator notes** |
| `evaluated_at` | the instant expiry and withdrawal were decided against |
| `semantics_version` | `internal/proposal`'s DECISION RULES. **Not a build stamp** |
| `build_identity`, `build_identity_state` | the code that produced the report, when the caller supplied one |

**The two authority digests are two different facts.** The whole document is
what the operator wrote; the selected grant is what decided THIS run. Removing
a different signer's authority changes the first and not the second. The
superseded implementation carried one field, named it for the document,
documented it as covering the document, and computed it over the selected
signer alone (FINDING-124).

**`policy_digest` includes the notes**, both the policy's own and each
exception's. A matched exception's note is QUOTED in the outcome, so two
policies whose notes differ produce two different reports; a digest ignoring
them would let a reader conclude the two were computed under the same policy
(FINDING-123). The cost — editing a comment moves the digest — is correct for
what this is: a citation of the document the report quotes, not a
comparability key.

**`semantics_version` is a manually maintained RULE version and is never
evidence of which commit or binary ran.** A report can carry semantics v1 from
any number of commits. The code identity is `build_identity`, which only the
caller knows — `cmd/scamwall` supplies it from its own `-ldflags` — and which
is reported as `absent` when it was not supplied. This package will not go
looking for it: the commit a working tree happens to sit at is not necessarily
the commit a binary was built from, and a plausible wrong answer is worse than
an absent one.

The two operator documents are digested over their **values**, so reformatting
a file does not read as a change of policy while adding an exception does. The
evidence document is digested over its **bytes**, because it is the signed file
that is cited.

`limitations` travels inside the JSON document and is printed at the end of the
text report, so quoting a count without it takes effort.
---

## 7. What a rights refusal may disclose

A refusal on `enrichment` or `derived_output` says this build was not
authorised to combine the observations, or not authorised to put a result
derived from them in front of anyone.

**Emitting the derived result beside that sentence performs the operation the
sentence says was refused.** The superseded implementation did exactly that:
it computed the canonical value, the source lists, the corroboration, the
signals and the conflict flag, and then returned a refusal carrying all of
them, in both formats, with the record rows naming the same indicator
(FINDING-120).

### 7.1 The permitted shape

A rights-refused outcome carries **exactly** these fields and no others:

| field | why it is permitted |
| --- | --- |
| `type` | the indicator TYPE, not the indicator. It is a property of the schema, not of the provider's data |
| `decision` | `refuse` |
| `reason` | `source_rights_refuse_enrichment` or `source_rights_refuse_derived_output` |
| `identity_withheld` | `true`. It distinguishes *withheld* from *there was nothing*, which an empty field alone cannot |
| `refused_sources` | the source ids whose recorded grant refused. This is the actionable half: it is what the operator edits |
| `explanation` | built only from the source registry's own refusal vocabulary — a source id and an operation name. It never contains an indicator value |

Every other field is **absent from the value**, not hidden by a renderer:
`canonical`, `scope`, `sources`, `independent_sources`,
`unestablished_sources`, `adverse_sources`, `signals`, `conflicted`,
`exception`.

`internal/proposal.DecideIndicator` returns before any of them is computed,
which is why the text and JSON renderings cannot disagree: there is nothing
for either to withhold. `TestTheRefusalShapeIsDecidedForEveryOutcomeField`
fails when a field is added to the struct without that decision being taken.

### 7.2 The matched exception is withheld too, and this reverses an earlier decision

ORDER 6 recorded the opposite: that a matched household exception is carried
on a rights-refused outcome "so nothing is lost". That was wrong. A matched
exception says THIS INDICATOR matched a rule the operator wrote against a
specific name; printing it hands the reader the indicator.

The concern behind the old rule is met differently. The refusal names the
grant to edit; once it is fixed and the run repeated, the exception appears.
One run's worth of "your exception was seen" is a smaller cost than
disclosing an indicator this build was told not to disclose.

### 7.3 `enrichment` is treated exactly like `derived_output`

It is the narrower prohibition, and it is not given a narrower treatment.

An indicator is by construction a combination of what its sources said, so
naming one in a report is reporting a combination. Separating the two would
mean deciding, per field, which half of a join each value came from, and
getting that wrong is a disclosure rather than a formatting error.

### 7.4 The record list has its own rule, and the two differ by the expiry position

| list | governed by |
| --- | --- |
| outcomes | `Indicator.Authorizes` — unanimity over **live** contributors, expired and superseded ones deliberately not consulted |
| records | the record's **own source**, per record, whether or not the record is still live |

The record list reports what ARRIVED. A record from a source that prohibits
`derived_output` or `enrichment` is that source's data whether or not it has
lapsed, so its `canonical` is withheld and `canonical_withheld` is set.

Where the two rules differ, they differ by exactly the expiry position
`internal/observation` states and defends: a lapsed record from a restricted
source has its value withheld in the record list while a live permitted
source's outcome may still name the same value. That is asserted by
`TestALapsedRecordFromARestrictedSourceIsStillThatSourcesData` rather than
left to be discovered.

### 7.5 Anti-laundering

If **any** contributing source's value is withheld under §7.4, **every**
record naming that canonical value is withheld — including rows from sources
that permit everything.

Withholding only the restricted source's own row would print the same value
one row down and the reader would have it anyway.

Indicators the restricted source never touched are unaffected. The rule is
about the value that source supplied, not about every value in the document.

### 7.6 The strict half, and what it costs

`sourceMayBeNamedInOutput` requires **both** `derived_output` and
`enrichment`. The second is deliberately strict: a source that prohibits only
`enrichment` permits its own data being put in front of someone, so a
single-source indicator of its own could legitimately be printed, and this
withholds it anyway.

It is one rule rather than a conditional one because the alternative is
deciding, per row, whether the surrounding rows make the list a join. Two
records naming one value, from two sources, adjacent and index-keyed, IS the
combination `enrichment` governs, and a rule that permitted the first row and
forbade the second would depend on the order the document listed them in.

The operator is not left blind. A withheld row still carries the index, the
source id, the admission outcome and `canonical_withheld`; the text report
lists those rows under their own heading and the counts carry
`records_value_withheld`.
