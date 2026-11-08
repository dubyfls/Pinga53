# Pi-hole v6 API Contract (as observed)

This document records the **live** API contract of the Pi-hole instance ScamWall
integrates with. It is derived from the OpenAPI specification served by that
instance and from unauthenticated probes against it, not from upstream
documentation on the internet.

Nothing in this document is installation-specific. It contains no hostnames
beyond the public service name `pi.hole`, no IP addresses, no certificates, no
session identifiers, and no credentials.

---

## 1. How this contract was captured

The specification was fetched over TLS with full certificate **and hostname**
verification against the Pi-hole private CA:

```
curl --cacert <pihole-ca.crt> --resolve pi.hole:443:<pihole-host-ip> \
     https://pi.hole/api/docs/specs/main.yaml
```

Two properties of that command matter and are preserved everywhere in ScamWall:

* `--cacert` pins trust to the Pi-hole private CA only.
* `--resolve` overrides **name resolution only**. The TLS peer is still
  validated against the name `pi.hole`, matching the leaf certificate's
  `subjectAltName`. This is not a verification bypass; `-k` /
  `InsecureSkipVerify` are never used, in tooling or in code.

The resolution override is required because in this environment the DNS name
`pi.hole` does not resolve to the host running Pi-hole. See
`docs/SECURITY_BOUNDARIES.md`.


Specification documents retrieved:

| Document | Result |
| --- | --- |
| `/api/docs/specs/main.yaml` | `200`, `text/plain`, 8511 bytes |
| `/api/docs/specs/auth.yaml` | `200`, 22143 bytes |
| `/api/docs/specs/info.yaml` | `200`, 50388 bytes |
| `/api/docs` | `301` &rarr; `/api/docs/` (same origin) |

Specification identity:

```yaml
openapi: 3.0.2
info:
  title: Pi-hole API
  version: "6.0"
```

---

## 2. Transport requirements

| Property | Value |
| --- | --- |
| Scheme | `https` only |
| Default port | `443` |
| Base path | `/api` |
| Response media type | `application/json; charset=utf-8` |
| Certificate chain | Pi-hole private CA &rarr; leaf `CN=pi.hole`, SAN `DNS:pi.hole` |

The specification also advertises an `http://{url}:{port}/{path}` server on port
`80`. **ScamWall refuses plaintext HTTP unconditionally.** On this host port 80
is served by Apache and returns `404` for `/api/auth`, so no plaintext API
surface exists to fall back to — but the refusal is enforced in code regardless
of what the remote offers.

Every successful JSON response carries a `took` field (seconds, floating point)
describing server-side processing time. ScamWall tolerates but ignores it.

---

## 3. Authentication

### 3.1 Declared security schemes

`main.yaml` declares five schemes:

| Scheme | Location | Name | ScamWall |
| --- | --- | --- | --- |
| `x_header_sid` | header | `X-FTL-SID` | **Used** |
| `header_sid` | header | `sid` | Not used |
| `cookie_sid` | cookie | `sid` | Not used |
| `query_sid` | query | `sid` | **Refused** — would place the session ID in a URL |
| `query_password` | query | `password` | **Refused** — would place the password in a URL |

ScamWall transmits the session identifier **only** in the `X-FTL-SID` request
header. URLs are never used to carry authentication material, because URLs are
routinely captured by proxy logs, access logs, browser history, and error
reports.

### 3.2 `POST /api/auth` — establish a session

Request body (`application/json`):

```json
{ "password": "<application password>" }
```

Per the specification: *"The password isn't stored in the session nor used to
create the session token. Instead, the session token is produced using a
cryptographically secure random number generator."*

Success response `200`:

```json
{
  "session": {
    "valid":    true,
    "totp":     false,
    "sid":      "<opaque session id>",
    "csrf":     "<opaque csrf token>",
    "validity": 1800,
    "message":  null
  },
  "took": 0.0001
}
```

Schema (`auth.yaml#/components/schemas/session`), required keys `valid`, `sid`,
`validity`, `message`, `totp`:

| Field | Type | Notes |
| --- | --- | --- |
| `valid` | boolean | Client is authenticated |
| `totp` | boolean | 2FA enabled on this Pi-hole |
| `sid` | string, nullable | Session ID |
| `csrf` | string, nullable | CSRF token; required only for cookie auth |
| `validity` | integer | Remaining lifetime in seconds |
| `message` | string, nullable | Human-readable status |

Session lifetime defaults to **30 minutes** and is extended by any authenticated
action. A session is invalidated by logout, by session deletion, by a password
change, or by creation of a new application password.

Because ScamWall authenticates with the `X-FTL-SID` header rather than a cookie,
**the CSRF token is not needed and is never retained**. It is discarded at parse
time and never logged.

Documented failure responses:

| Status | Meaning | Observed body shape |
| --- | --- | --- |
| `400` | Bad Request | `no_payload`, `no_password`, `password_inval`, `totp_missing` |
| `401` | Unauthorized | `totp_invalid`, `totp_reused` |
| `429` | Too Many Requests | `rate_limit`, `no_seats`, `totp_rate_limit` |

### 3.3 `DELETE /api/auth` — destroy the session

| Status | Meaning |
| --- | --- |
| `204` | No Content — session deleted |
| `404` | No session active |
| `401` | Unauthorized |

`204` matches the behaviour previously observed on this installation. ScamWall
treats `204` and `404` as equivalent success outcomes for logout, since both end
with no live session.

### 3.4 `GET /api/auth` — probe session state

Requires no credentials. Returns `200` with a valid session when the server
requires no authentication, otherwise `401` with `valid: false`. ScamWall uses
this endpoint in `doctor` to determine whether authentication is required
**without transmitting a password**.

---

## 4. Read-only endpoints used in Phase 1

Phase 1 reads **only** version and status information. It touches no endpoint
that returns query logs, client identities, network device inventories, DHCP
leases, or configuration.

### 4.1 `GET /api/info/version`

Documented as *"Request versions of the individual Pi-hole components."*
Response shape (`info.yaml#/components/schemas/version`):

```json
{
  "version": {
    "core": { "local": { "branch": "...", "version": "...", "hash": "..." },
              "remote": { "version": "...", "hash": "..." } },
    "web":  { "local": { "branch": "...", "version": "...", "hash": "..." },
              "remote": { "version": "...", "hash": "..." } },
    "ftl":  { "local": { "branch": "...", "version": "...", "hash": "...",
                         "date": "..." },
              "remote": { "version": "...", "hash": "..." } }
  },
  "took": 0.0001
}
```

Every leaf string is `nullable`. ScamWall's decoder treats all of them as
optional and never panics on a null.

This endpoint is **non-sensitive**: it exposes software version numbers only.

---

## 4A. First contact by ScamWall itself — ORDER 7, commit `d104949`

Everything above was observed with `curl`. This is the first record of the
**ScamWall binary** reaching a real Pi-hole.

Binary: `scamwall order7-candidate (commit d104949f…)`,
`sha256:6c73c839a80712b7d98e982860d5962a788f90149ed271c8778c79e908fba805`.
Appliance: installed on this host, `127.0.0.1:443`.

| request | result |
| --- | --- |
| `GET /api/auth` (no credential) | `401`, JSON, the five-field `session` object. Reported by `doctor` as `reachable over TLS; authentication required`. Exit **0** |
| `POST /api/auth` | **never sent.** The run stops before it, at `open secret: /etc/scamwall/secrets/pihole_app_password: permission denied` |
| `DELETE /api/auth` | never needed — no session was created |
| `GET /api/info/version` | **never sent** — requires a session |
| `GET /api/domains/deny/exact` | **never sent by ScamWall** — requires a session. A `curl` probe confirmed the path answers `401` unauthenticated, which is the only new observation of it |

**No configuration mutation occurred, and none could.** The only method
contacted was `GET`.

### 4A.1 TLS target identity, established for the first time through the client

Section 1 records that the pin is configured and that name resolution is
overridden. Section 3.7 of `docs/VERIFICATION.md` recorded that **nothing had
been sent through the pin**. That is no longer true.

The certificate served at `127.0.0.1:443` under SNI `pi.hole` is `CN=pi.hole`,
SAN `DNS:pi.hole`, issued by `CN=pi.hole, O=Pi-hole, C=DE`, valid
`2026-09-05`–`2026-10-22`, `sha256:F0:2F:F6:03:…:7E:28`. It verifies against
the pinned CA both by `openssl verify` and by the client's own handshake, with
`InsecureSkipVerify` false and the system trust store not consulted.

**And the pin was measured refusing the wrong host.** Section 1 already records
that `pi.hole` does not resolve to the Pi-hole on this network; what it did not
record is what happens when ScamWall follows that resolution. It now does:

```
FAIL  pi-hole connectivity  TLS verification failed for /api/auth:
      tls: failed to verify certificate: x509: certificate is valid for
      pinga53.local, not pi.hole
```

exit **1**. The name resolves to `192.0.2.10` / `2001:db8:53:…`, a
different machine presenting a self-signed `CN=pinga53.local`,
`sha256:CC:04:EC:A8:…:34:7B`, which the pinned CA did not issue. The connection
is refused rather than completed. **That is the pin doing its job, demonstrated
rather than described.**

### 4A.2 FINDING-130 — raised, then WITHDRAWN

Recorded rather than deleted, so the identifier is not reused and the reasoning
error stays visible.

**Claimed:** that `deploy/compose/config.example.json` is defective for
carrying no `address_override`, while §1 above says the override is required in
this environment.

**Wrong, because** that file is mounted INTO THE CONTAINER, where the name is
resolved by Compose and not by the host resolver:
`deploy/compose/compose.yaml:39` declares
`extra_hosts: ["pi.hole:${PIHOLE_HOST_IP:-host-gateway}"]`, and
`deploy/compose/.env.example` documents `PIHOLE_HOST_IP` as the address
`pi.hole` resolves to inside the container. The example is correct for its
documented deployment. The FAIL in §4A.1 came from running the binary **on the
host**, which that file does not configure.

**FINDING-130 is WITHDRAWN.** The observation in §4A.1 stands on its own; the
defect claim does not. See `docs/VERIFICATION.md` §4.43.4.2.

---

## 5. Endpoints deliberately NOT used in Phase 1

The specification exposes a large mutating surface. Phase 1 issues **no**
request to any of the following, and the client contains no code path that can
construct one:

| Category | Endpoints |
| --- | --- |
| Domain management | `POST/PUT/DELETE /api/domains/...`, `/api/domains:batchDelete` |
| Group management | `/api/groups`, `/api/groups:batchDelete` |
| Client management | `/api/clients`, `/api/clients:batchDelete` |
| List management | `/api/lists`, `/api/lists:batchDelete` |
| DNS control | `/api/dns/blocking` |
| Actions | `/api/action/gravity`, `/api/action/restartdns`, `/api/action/flush/*` |
| Configuration | `/api/config`, `/api/config/{element}`, `/api/config/{element}/{value}` |
| Teleporter | `/api/teleporter` (backup/restore) |
| DHCP | `/api/dhcp/leases` |

Additionally, these **read** endpoints are avoided in Phase 1 because they return
personally identifying or otherwise sensitive data:

`/api/queries`, `/api/history*`, `/api/stats/top_domains`,
`/api/stats/top_clients`, `/api/network/devices`, `/api/dhcp/leases`,
`/api/logs/*`, `/api/info/messages`, `/api/padd`.

---

## 6. Live behaviour observed on this installation

All probes below were issued **without credentials**. No mutation was attempted.

| Probe | Status | Body |
| --- | --- | --- |
| `GET /api/auth` | `401` | `{"session":{"valid":false,"totp":false,"sid":null,"validity":-1,"message":"no SID provided"},"took":...}` |
| `GET /api/info/version` | `401` | `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":...}` |
| `POST /api/auth` body `{}` | `400` | `{"error":{"key":"bad_request","message":"No password found in JSON payload","hint":null},"took":...}` |
| `GET /api/docs` | `301` | `Location: /api/docs/` (same origin) |
| `GET http://<host>:80/api/auth` | `404` | Apache; no API surface |

The error envelope is consistent:

```json
{ "error": { "key": "...", "message": "...", "hint": null }, "took": 0.0 }
```

`hint` is nullable. ScamWall surfaces `key` and `message` in redacted operator
errors and never echoes a request body.

### Divergence assessment

**No material divergence.** Every endpoint reachable without credentials
returned exactly the status code, media type, and JSON envelope described by the
specification served by that same instance. The `session` object returned by
`GET /api/auth` contains precisely the five required fields declared in
`auth.yaml`.

The authenticated paths (`POST /api/auth` success, `GET /api/info/version`
success, `DELETE /api/auth` &rarr; `204`) have **not** yet been re-verified live by
ScamWall, because the application password is not readable by a non-root
process on this host. They are exercised in full against a fake Pi-hole HTTPS
server in the test suite. See "Open verification items" in
`docs/SECURITY_BOUNDARIES.md`.

---

## 7. Client obligations derived from this contract

These are requirements on ScamWall, enforced in `internal/adapters/pihole`.

### 7.1 The permitted set

"Read-only" is **not** "GET only". A session has to be created and destroyed,
and neither is a GET, so a method-only rule would either forbid authentication
or permit every POST. What makes this client read-only is that the only non-GET
requests it can construct act on **ScamWall's own session** and nothing else.

The set is a table in `client.go` (`PermittedOperations`), enforced at run time
rather than described in prose:

| Operation | Retried | Why it is permitted |
| --- | --- | --- |
| `POST /api/auth` | No | Creates ScamWall's own session. Changes no Pi-hole state. Never retried: Pi-hole rate-limits login and has a finite number of session seats, so a retry storm could lock out an operator during an incident |
| `DELETE /api/auth` | No | Destroys ScamWall's own session. Changes no Pi-hole state. Not retried: a second delete of an already-deleted session is answered `404`, which the caller already treats as the desired end state |
| `GET /api/auth` | Yes | Reads session state without sending a credential |
| `GET /api/info/version` | Yes | Reads component version numbers. Non-sensitive |
| `GET /api/domains/deny/exact` | Yes | Reads the exact deny entries the appliance currently holds. The shadow comparison needs the target's **own** state: a comparison against a remembered or assumed list is an offline proposal with the appliance's name on it. Read-only, and narrow — the path names `deny/exact`, so no group or list is fetched |
| `GET /api/domains/allow/exact` | Yes | Reads the household's exact allow entries. Added by ORDER 8 for FINDING-132: without them a shadow plan states additions the appliance would override the moment they landed, and cannot say which. Read-only and fully qualified |
| `GET /api/domains/allow/regex` | Yes | Reads the household's allow regexes. A regex allow covers hosts no exact list names, so reading only the exact list would leave the same gap one shape over. Whether a pattern can be evaluated faithfully is a separate question, answered by abstaining rather than guessing. Read-only and fully qualified |

Two properties of the enforcement matter as much as the table:

* **It runs before any network activity.** The check precedes URL construction,
  name resolution, the dial and the TLS handshake. A request outside the
  contract fails as a programming error and does not put a packet on the wire on
  its way to failing. The test that proves this points the client at an address
  nothing is listening on: if the check were moved later, the failure would be a
  dial error rather than `ErrOperationNotPermitted`, and the test would say so.
* **It runs again on every redirect.** A redirect is a request the *server*
  chose. Same-origin is necessary but not sufficient: a Pi-hole answering
  `GET /api/info/version` with a `302` to a configuration or DNS-control
  endpoint would be steering the client, within the approved origin, to
  something this contract forbids. A redirect target that is not in the table is
  refused, and so is any redirect target carrying a query string — Pi-hole
  accepts the session id as a `sid` parameter, and a redirect is the only way a
  URL this client did not build could acquire one.

### 7.2 The rest of the obligations

1. HTTPS only; plaintext refused before a connection is attempted.
2. Trust anchored to the configured private CA. System roots are not consulted.
3. Hostname verified as `pi.hole`, independent of the address dialled.
4. Destination pinned: the dialler refuses any address but the configured one,
   so no response can steer the client at another host.
5. No proxy. `Transport.Proxy` is nil, so `HTTPS_PROXY` in the environment
   changes nothing — the peer is on the local network by definition, and a proxy
   would terminate or observe that connection.
6. Session ID carried only in `X-FTL-SID`; never in a URL, never in a log.
7. Password read from a file, held as narrowly as possible, never logged.
8. CSRF token discarded immediately; unused under header authentication.
9. `DELETE /api/auth` attempted on **every** exit path, including error and
   cancellation, under its own bounded timeout derived from — but not cancelled
   by — the caller's context.
10. A session is never nested. `WithSession` refuses when one is already active,
    because a second login would overwrite the id held in memory and leave the
    overwritten session valid on the server with no way left to destroy it.
11. Response bodies bounded by a hard byte limit before decoding; error bodies
    bounded by the same limit.
12. `Content-Type` verified as JSON before decoding.
13. Cross-origin redirects refused; redirect count capped.
14. Retries with jitter permitted only for operations the table marks retryable.
    A rejected credential is never retried.
15. **One deadline for the whole operation.** `TotalTimeout` bounds the request,
    its retries and the delays between them. `http.Client.Timeout` bounds a
    single request and does not bound a sequence of them, so without this the
    real ceiling would be `attempts x RequestTimeout` plus every backoff and
    would grow with `MaxRetries`.
16. `Retry-After` honoured where it is longer than the local backoff, and capped
    either way, so a peer cannot park the process by naming a large number.
    Both RFC 9110 forms are parsed and the raw header value is discarded.
17. All errors redacted: no bodies, no headers, no credentials. In addition,
    peer-supplied strings are scrubbed of the live session id, and the
    authentication error is scrubbed of the password, so that a Pi-hole quoting
    back what it was sent cannot put a credential into a log that ScamWall never
    printed.

### 7.3 What the test suite establishes, and against what

Every network test in this repository runs against a **local fake HTTPS server**
that impersonates the parts of this API ScamWall uses, with a throwaway CA
generated per run. That establishes the client's behaviour — trust, pinning,
redirects, bounds, deadlines, cancellation, redaction — and it establishes
nothing whatever about compatibility with a real Pi-hole. The divergence
assessment in section 6 is the only evidence about the real appliance, and it
covers unauthenticated probes only.
