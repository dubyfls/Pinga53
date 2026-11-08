# ScamWall Security Boundaries

This document states, in operational terms, what ScamWall is permitted to do,
what it is structurally incapable of doing, and what was observed about this
specific deployment during Phase 1 discovery.

It is written to be checkable. Every claim should be falsifiable by running a
command.

---

## 1. Hard boundaries (Phase 1)

ScamWall **must not**, and in Phase 1 **cannot**:

| # | Boundary | Enforcement |
| --- | --- | --- |
| 1 | Modify, restart, reconfigure, upgrade, containerise, or patch Pi-hole | No such code path; no mutating endpoint is reachable |
| 2 | Modify Pi-hole files, databases, systemd units, or web interface | `/etc/pihole` is never mounted; container has no host write access |
| 3 | Enable `webserver.api.app_sudo` | `/api/config` is never called |
| 4 | Enable destructive API operations | No `POST`/`PUT`/`PATCH`/`DELETE` except `DELETE /api/auth` (own session) |
| 5 | Modify firewall, router, DNS clients, Apache, or host networking | No `NET_ADMIN`; all capabilities dropped; no host networking |
| 6 | Expose container ports | No `ports:` key; verified by compose inspection and by container inspection (§5.4) |
| 7 | Mount `/etc/pihole` or `/var/run/docker.sock` | No such mount; verified by compose inspection and by container inspection (§5.4) |
| 8 | Print, inspect, copy, log, or commit the application password | `Secret` type + logger redaction + secret scan in CI |
| 9 | Disable TLS verification | `InsecureSkipVerify` absent; asserted by test |
| 10 | Use `curl -k` or equivalent | Never used in code, scripts, or tooling |
| 11 | Push to GitHub during Phase 1 | Local commits only |
| 12 | Make any Pi-hole API mutation | See #4 |
| 13 | Download or enforce third-party domain feeds | Feed source is a repository-owned fixture only |
| 14 | Install host packages without approval | Approvals recorded in this document |

`DELETE /api/auth` is the single non-`GET` request ScamWall issues besides
`POST /api/auth`. It deletes **only ScamWall's own session** and changes no
Pi-hole configuration, no blocklist, and no persistent state. Not logging out
would be the less safe choice: abandoned sessions remain valid for 30 minutes
and consume finite session seats.

---

## 2. Stop conditions

Phase 1 halts immediately if any of these hold. Status as assessed:

| Condition | Status |
| --- | --- |
| `pi.hole` cannot be mapped to the container's view of the Pi-hole host | **Resolved** — pinned via `extra_hosts` (§4) |
| The certificate does not validate for `pi.hole` | **Passes** — `Verify return code: 0 (ok)` with `-verify_hostname pi.hole` |
| The secret cannot be made readable to a non-root container without becoming world-readable | **Open** — deferred; see §5 |
| Docker requires privileged mode, host networking, added capabilities, or socket access | **Passes** — none required |
| The installed API differs materially from its live documentation | **Passes** — no divergence; see `PIHOLE_API_CONTRACT.md` §6 |

---

## 3. Discovery observations

Captured read-only. No host state was changed.

| Item | Observation |
| --- | --- |
| Working directory | `/home/scamwall/scamwall` — ScamWall refuses to operate elsewhere |
| Service account | `uid=1000(scamwall) gid=1000(scamwall)` |
| Supplementary groups | `cdrom, floppy, audio, dip, video, plugdev, users, netdev` — **not** `docker` |
| Docker Engine | 29.8.0, `containerd.io` 2.3.4, buildx 0.37.0, compose 5.5.1 |
| Docker socket | `srw-rw---- root:docker /var/run/docker.sock`; group `docker` (gid 990) is empty |
| User-namespace remapping | **Not active** |
| Rootless mode | **Not active** — `DOCKER_HOST` unset, no `/run/user/1000/docker.sock` |
| Docker bridge | `docker0` at `172.17.0.1/16`, state DOWN (no containers running) |
| Firewall managers | `ufw`, `firewalld`, `nftables`, `netfilter-persistent` all **inactive**; `ufw` not installed |
| Firewall rules | Enumeration requires root; attempted read-only, denied, **not escalated** |
| Occupied ports | `53/tcp+udp` (Pi-hole), `443/tcp` (Pi-hole API), `80/tcp` (Apache), `22/tcp` (sshd), `123/udp` (ntp), `68/udp` (dhcp client) |
| Port conflicts | None — ScamWall publishes no ports |
| Git | 2.47.3 |
| GitHub CLI | 2.100.0, authenticated as the maintainer, scopes `gist, read:org, repo`. Token masked by `gh`; **never printed or stored** |
| Repository | `github.com/dubyfls/Pinga53`, **public**, default branch `main` (**protected**) |
| Working branch | `feat/phase-1-core` — the only branch ScamWall commits to |

Because the repository is **public**, `.gitignore` is deny-by-default for
credentials, certificates, keys, state, and logs, and a secret scan runs before
each commit.

---

## 4. Finding: `pi.hole` does not resolve to the Pi-hole host

**This is the most operationally significant discovery of Phase 1.**

On this network, DNS resolution of `pi.hole` returns `<unrelated-appliance-ip>` — a different
appliance, presenting a self-signed certificate `CN=<unrelated-appliance>`
(SAN `IP:<unrelated-appliance-ip>, DNS:<unrelated-appliance>`). The host actually running Pi-hole is a
different machine on the same subnet.

Consequences:

* A naive `curl https://pi.hole/api/...` from this host fails with `unknown CA`.
  That failure is **correct behaviour** — TLS refused to trust a device that is
  not the intended peer. The correct response is to fix resolution, never to
  add `-k`.
* Anything on this host that trusts DNS for the name `pi.hole` is talking to
  another device. This is worth reviewing independently of ScamWall.

Resolution: `pi.hole` is pinned to the Pi-hole host's address via `extra_hosts`,
overriding **name resolution only**. Certificate and hostname verification are
unchanged — the leaf must still present `SAN DNS:pi.hole` and chain to the
configured private CA.

```yaml
extra_hosts:
  # PIHOLE_HOST_IP comes from a local, gitignored .env file so that no
  # site-specific address is ever committed to this public repository.
  # It defaults to the Docker bridge gateway when unset.
  - "pi.hole:${PIHOLE_HOST_IP:-host-gateway}"
```

Two forms are supported and verify identically:

* **`host-gateway`** — resolves to the `docker0` bridge gateway. Keeps
  container&rarr;host traffic on the Docker bridge. This is the default.
* **An explicit LAN address** — routes container&rarr;host traffic over the host's
  LAN interface instead. Set `PIHOLE_HOST_IP` in `.env` to use it.

The same pinning is available to the binary outside a container through a
configured address override, which is the exact analogue of `curl --resolve`.
It is not, and must never become, a verification bypass.

---

## 5. Open verification items

Honest accounting of what is **not** yet proven on live infrastructure.

> **Where this sits.** `docs/VERIFICATION.md` is the authoritative evidence
> record — every gate result, tied to a commit, tool versions, and where
> relevant an image ID — and `docs/REQUIREMENTS_MATRIX.md` tracks which
> requirement each piece of evidence discharges. This section stays as the
> narrative account of the boundaries themselves and of the discovery work
> behind them. When the two disagree about a status, `docs/VERIFICATION.md` is
> correct and this section is stale.

### 5.1 Secret readability — grant applied, live authentication still unverified

The minimal grant below has been applied on this host. A dedicated system group
owns the secret; the service account is not a member of it, and the password is
never world-readable:

```bash
sudo groupadd -r swsecret
sudo chgrp swsecret /etc/scamwall/secrets /etc/scamwall/secrets/pihole_app_password
sudo chmod 0750 /etc/scamwall/secrets
sudo chmod 0640 /etc/scamwall/secrets/pihole_app_password
```

Operator-verified host metadata: the `swsecret` group exists,
`/etc/scamwall/secrets` is `root:swsecret 0750`, and
`/etc/scamwall/secrets/pihole_app_password` is `root:swsecret 0640`. The
compose definition resolves `group_add` to that group's GID — but only when
`--env-file deploy/compose/.env` is passed explicitly, because Compose reads a
bare `.env` from the current directory, not from the compose file's directory.
Omit it and `group_add` silently falls back to the `65532` default, which grants
nothing.

**This establishes configured permissions, not proven access.** No ScamWall
process has been observed reading the password file, and no live authentication
has been performed. The grant makes success *possible*; it does not demonstrate
it.

Still unverified against live infrastructure: `POST /api/auth` success,
authenticated `GET /api/info/version`, and `DELETE /api/auth` &rarr; `204`. These
are exercised **only** against the fake Pi-hole HTTPS server in the test suite.

### 5.2 Docker daemon access

The service account is not in the `docker` group and has no passwordless sudo.
By operator decision, Docker commands are executed by the operator rather than
granting the account root-equivalent access.

This is the more conservative choice: `docker` group membership is effectively
root on this host, since it permits mounting the host filesystem into a
container.

Consequently `docker build` and `scripts/container-runtime-verify.sh` are
operator-executed, and are reported as BLOCKED — never as passing — when
`scripts/check.sh` runs as the service account. The verifier itself has no git
dependency, so the operator needs no `safe.directory` exception to run it here
(§5.5).

`docker compose config` is **not** in that set. It parses, interpolates and
validates the definition entirely client-side, so it runs without daemon
access and is gated separately. It was previously grouped with the daemon
checks, which reported a runnable check as BLOCKED on every host without socket
access.

### 5.3 Go toolchain — RESOLVED, and a finding in its own right

Go is installed. The distribution package is `go1.24.4`, which is **end-of-life
upstream**: the supported set at the time of writing is `go1.26.8` and
`go1.27.1`.

Running `govulncheck` against the 1.24.4 build produced **26 findings** — 24 in
the standard library plus two in dependencies. Two were reachable from
ScamWall's own code, both through the same call path that processes untrusted
feed content:

| Finding | Reached via | Effect |
| --- | --- | --- |
| `GO-2026-5970` | `domain.Normalize` &rarr; `idna.ToASCII` &rarr; `norm.Form.Bytes` | Infinite loop on crafted input in `golang.org/x/text` — a denial of service in domain validation |
| `GO-2026-5026` | `domain.Normalize` &rarr; `idna.Profile.ToASCII` | Vulnerability in `golang.org/x/net/idna` |

That a feed-processing path reached a denial-of-service bug is the reason the
toolchain and dependency versions are treated as security controls rather than
housekeeping.

Resolution:

* `go.mod` pins `toolchain go1.26.8`, a currently supported release.
* `golang.org/x/net` raised to `v0.58.0`, `golang.org/x/text` to `v0.41.0`.
* The container base image is pinned to `golang:1.26.8-trixie` by digest, so
  local, CI and container builds use the same compiler.
* `GOTOOLCHAIN=local` in the image build forbids an implicit toolchain download,
  so a mismatch fails visibly instead of silently fetching another compiler.

`govulncheck` now reports **no vulnerabilities**.

Note that `go1.26.8` is obtained through Go's own toolchain mechanism rather
than from apt, and is verified against the Go checksum database. The apt package
remains at 1.24.4 and is not used for this module.

### 5.4 Container runtime verification — evidence, and its limits

Operator-executed, since the service account cannot reach the daemon (§5.2).

**Scope: image `sha256:4a5bfa3dcb86550ed4ce76a4570f24d63ee363770b290dc364dbfea57a0859fd`.**
Every claim in this section is scoped to that exact image ID and to no other.
An earlier round of evidence, against image `sha256:303426…c08eb`, is
superseded and has been removed rather than left to look current.

**Binary identity.** The image reports the commit it was built from and,
critically, that enforcement is not compiled in:

```
version: 9fc3b1a
commit:  9fc3b1abf70313b49c6f603b7773f341fcb7d789
built:   2026-09-05T22:39:31Z
enforcement compiled in: false
mode:    read-only, dry-run
VERSION exit=0
```

**Offline execution.** The same image completed `plan` with the network
disabled, no password mount and no CA mount, a read-only rootfs with read-only
config and feed mounts, uid/gid 65532:65532, all capabilities dropped,
`no-new-privileges`, restricted tmpfs, 128 MiB memory and memory-swap, 64 PIDs
and 0.5 CPU:

```
feed:   scamwall-test-feed (manifest 1.0)
digest: sha256:4d1ed4ba4d3c7de138258360b2ed5e7b25442fc5bb42cca14693b0a35cbb952f
5 proposed, 3 excluded (1 not block, 1 below confidence, 1 expired)
PLAN exit=0
```

With no network namespace at all, this is a demonstration rather than a claim
about intent: plan computation cannot have contacted anything.

**Recreated deployment container.** Inspected, never started:

| Property | Observed |
| --- | --- |
| `Image` | matched the exact image ID above |
| `State.Status` | `created` |
| `Config.Healthcheck` | `null` |
| exit status | `RECREATE exit=0` |

`Healthcheck=null` confirms the Dockerfile's `HEALTHCHECK` removal; `Status=created`
confirms the authenticated default command never ran.

**What this evidence does NOT establish.** Stated plainly, because each of
these has at some point been read into results that did not support it:

* **Not live authentication.** `POST /api/auth`, authenticated
  `GET /api/info/version`, and `DELETE /api/auth` &rarr; `204` remain unverified
  against live infrastructure (§5.1).
* **Not runtime password access.** §5.1's grant is a permissions
  configuration. No ScamWall process has been observed reading the password.
* **Not completion of the corrected automated runtime gate.**
  `scripts/container-runtime-verify.sh` — which asserts the full property set
  and fails when an inspection cannot run — has **not** been run against this
  image. This section is a hand-collected subset, not that gate's output.

### 5.5 How runtime verification is structured

Two programs, split along the privilege boundary rather than by topic:

| | `container-security-check.sh` | `container-runtime-verify.sh` |
| --- | --- | --- |
| Runs as | the `scamwall` service account | the operator |
| Inspects | repository content | the daemon's image and container |
| Uses git | yes, and requires it | **never** |
| In `check.sh` | runs every time | BLOCKED without daemon access |

The Docker path has no git dependency by design. The operator runs it as root
against a repository owned by `scamwall`, where git refuses with a
dubious-ownership error. The alternatives — a `safe.directory` exception,
changing repository ownership, or putting the service account in the `docker`
group — each widen a trust boundary to buy convenience. Instead the verifier
derives the repository root from its own location and confirms it by the files
it must contain, so none of those grants is needed.

Correctness properties the verifier now holds, each of which replaced a
false pass:

* Creation status is checked explicitly, and the inspection container is
  created under a Compose project name private to that invocation — so a
  pre-existing container can neither mask a failed create nor be inspected in
  its place.
* Inspection output is captured and its exit status verified before any
  assertion reads it, and assertions are evaluated with `jq` over that JSON.
  A failed `docker inspect` or `docker history` can no longer be mistaken for
  a satisfied property, and error text on either stream cannot match a
  credential pattern.
* The requested image is resolved to its immutable image ID, and the inspected
  container's `.Image` must equal it. `SCAMWALL_EXPECTED_IMAGE_ID` pins that
  ID when the operator wants to verify one specific build.
* Prohibited mounts are detected through `.Mounts`, which covers binds,
  volumes and tmpfs alike. `.HostConfig.Binds` reflects only one way of
  requesting a mount and misses the rest.
* Only resources created by the invocation are removed, including on failure
  or interruption. `compose down` is always scoped to the private project.
* Image history is labelled a **limited pattern check** over build
  instructions — evidence against a pasted credential, not proof that the
  filesystem holds no secret.
* Filesystem enumeration is retained, with every step's status checked, and
  its results are described as absence **of the enumerated paths**. An
  arbitrarily renamed executable is not ruled out and is not claimed to be.

`scripts/tests/runtime-verify-test.sh` drives the verifier against a scripted
fake Docker and asserts that each of those failure modes produces a nonzero
exit. It needs no daemon, so it runs in the ordinary gate suite as the service
account.

### 5.6 Operator rerun procedure

The corrected automated gate has not been run against the image in §5.4. These
are the exact commands that close that gap. Run them from the repository root
as the operator; the service account cannot reach the daemon (§5.2).

`--env-file` is explicit in every Compose invocation, because Compose resolves
a bare `.env` against the current working directory — omit it and
`group_add` silently falls back to its default.

**1. Rebuild the image.**

```bash
cd /home/scamwall/scamwall

docker build \
  -f container/Dockerfile \
  -t scamwall:local \
  --build-arg VERSION="$(git describe --tags --always --dirty)" \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  .

docker image inspect -f '{{.Id}}' scamwall:local
```

If the build arguments are produced on the operator's side, note that `git` is
needed for those two substitutions only — not by any verification step. An
operator without git access can pass literal values instead.

**2. Recreate the deployment container WITHOUT starting it.**

The image's `CMD` is `sync --dry-run`, which performs a live authenticated
read. Use `create`; do **not** use `up`, `start`, or `run` with the default
command.

```bash
docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml \
  create --no-build

docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml \
  ps -a
```

**3. Run the corrected runtime verification.**

This is the step that produces the gate output §5.4 does not yet have. It
creates its own inspection container under a private Compose project, removes
only what it created, and needs no git — so it is safe to run as root in this
`scamwall`-owned repository without a `safe.directory` exception.

```bash
# Pin the expected image so a stale local tag cannot be verified by mistake.
SCAMWALL_EXPECTED_IMAGE_ID="$(docker image inspect -f '{{.Id}}' scamwall:local)" \
  bash scripts/container-runtime-verify.sh
echo "VERIFY exit=$?"
```

Exit 0 means every required check ran and passed. Any nonzero exit means at
least one check failed **or could not run**; the output distinguishes the two.

**4. Repeat the offline plan.**

`plan` reads only the configuration and the signed feed — it opens neither the
CA nor the password, so neither is mounted.

```bash
docker run --rm \
  --network none \
  --read-only \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --memory 128m --memory-swap 128m --pids-limit 64 --cpus 0.50 \
  -v "$PWD/deploy/compose/config.example.json:/etc/scamwall/config.json:ro" \
  -v "$PWD/testdata/feed.json:/etc/scamwall/feed.json:ro" \
  scamwall:local plan
echo "PLAN exit=$?"
```

**5. Confirm nothing was left running.**

```bash
docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml ps -a
docker ps -a --filter 'name=scamwall-verify-' --format '{{.Names}}'   # expect no output
```

**Live authentication remains UNVERIFIED.** No step above authenticates to
Pi-hole, and none is intended to. Proving `POST /api/auth`, authenticated
`GET /api/info/version`, and `DELETE /api/auth` &rarr; `204` against live
infrastructure is a separate, explicitly authorised action (§5.1). Until it is
performed, those paths are exercised only against the test suite's fake HTTPS
server.

---

## 6. What a full ScamWall compromise would yield

Assume an attacker achieves arbitrary code execution inside the container.

They obtain: the Pi-hole application password, a valid API session, and
read access to version information and the feed fixture.

They do **not** obtain: any capability (all dropped), any writable host path
(read-only root filesystem, read-only mounts), the Docker socket, host
networking, any listening port, or the ability to escalate privileges
(`no-new-privileges`).

They **could** authenticate to the Pi-hole API with the stolen password and call
mutating endpoints directly — ScamWall's own inability to mutate does not
constrain an attacker holding the credential. This is the principal residual
risk of Phase 1 and is addressed in `docs/THREAT_MODEL.md`. It is the reason
the application password should be scoped as narrowly as Pi-hole permits and
rotated if the container is ever suspected of compromise.
