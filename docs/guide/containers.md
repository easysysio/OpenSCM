# Containers

OpenSCM treats **application containers** (Docker, Podman) as first-class
inventory under each Linux host. Containers appear nested under their host in
the Systems list, get a full configuration detail panel, and can be tested
with two new container-only elements (`IMAGE`, `NETWORK`). Discovery is
automatic — no per-container enrollment, no in-container agent.

!!! info "OS containers vs app containers"
    "Container" in OpenSCM means an **app container** — Docker, Podman,
    eventually Kubernetes pods. **OS containers** (LXC, LXD, BSD jails) are
    full Linux userspaces with their own init systems; install the OpenSCM
    agent inside them, treat them as regular systems, and you get the full
    host test surface inside. The host running them does **not** appear to
    have container inventory in OpenSCM, and that's correct.

---

## Discovery

Each Linux agent enumerates containers on every heartbeat. For each
runtime detected (`docker --version` or `podman --version` exits 0), it lists
the **running** containers via `<runtime> ps --format json` and pulls the
configuration metadata via `<runtime> inspect <id>`. The list ships with the
heartbeat payload.

| Runtime | Detection | Listing |
| :--- | :--- | :--- |
| Docker | `docker` CLI on `$PATH` | `docker ps --format '{{json .}}'` |
| Podman | `podman` CLI on `$PATH` | `podman ps --format json` |
| Kubernetes | (not yet — planned for a future release) | — |

!!! note "Running containers only (since 0.6.1)"
    Inventory tracks **running** (and paused) containers — not stopped/exited
    ones. Stop a container and it drops off the host's next heartbeat report,
    and the server removes it from the inventory. A host with a working
    runtime but **zero** running containers reports an explicit empty set, so
    its last container is cleared too. (If the runtime's daemon is unreachable,
    the agent reports *nothing* rather than an empty set, so a transient outage
    never wipes a host's inventory.)

The agent soft-fails on missing runtime or permission errors — if the agent
isn't in the `docker` group, Docker discovery is skipped silently and the
heartbeat continues. Non-Linux platforms (macOS, Windows, FreeBSD) return an
empty list without any shell-outs.

### Permissions

The agent typically runs as root on a host, so Docker socket / Podman CLI
access is automatic. For non-root deployments:

- **Docker** — the agent user must be in the `docker` group, OR the agent
  process must have read access to `/var/run/docker.sock`.
- **Rootless Podman** — the agent only sees containers owned by the user
  it's running as. This is usually correct; document if it matters for your
  environment.

---

## Inventory in the Systems list

Systems with at least one container get a left-side **▶** chevron in the
Managed Systems table. Click to expand a nested table showing every
container on that host:

```
▶ ID  Name              OS              IP            Agent  Last Seen
▼ 12  web-host-01       Ubuntu 24.04    192.168.1.50  v0.9.3  30s ago
   ├─ 🐳 nginx-prod      nginx:1.27-alpine   running  172.17.0.2
   ├─ 🐳 redis           redis:7-alpine      running  172.17.0.3
   └─ 🦭 worker          internal/job:42     running  172.17.0.4
```

Runtime icons: 🐳 Docker, 🦭 Podman. Clicking a container row opens the
**Container Details** modal with the full configuration snapshot:

| Field | Source |
| :--- | :--- |
| Image + tag + digest | `inspect.Image` |
| IP | `NetworkSettings.IPAddress` (or first network in `Networks`) |
| Run user | `Config.User` |
| Network mode | `HostConfig.NetworkMode` |
| Privileged | `HostConfig.Privileged` |
| Read-only filesystem | `HostConfig.ReadonlyRootfs` |
| Restart policy | `HostConfig.RestartPolicy.Name` |
| Health check defined | `Config.Healthcheck` present |
| Exposed ports | `NetworkSettings.Ports` |
| Mounts | `Mounts` (`source`, `destination`, `type`, `ro`) |
| Added capabilities | `HostConfig.CapAdd` |
| First / last seen | OpenSCM timestamps (preserved across rebuilds) |

`first_seen` is preserved across container rebuilds — useful for "how long
has this container been running on this host" questions. Containers that
disappear from a heartbeat are deleted immediately if the agent reports an
empty list, or aged out after **Container Retention (days)** if the host
itself stops reporting.

---

## Retention

Configurable per-tenant under **Admin → Settings → General → Container
Retention (days)**. Default is **7**; set to **0** to keep forever. Container
churn is normally high so the default is intentionally short — long-lived
containers stay because each heartbeat refreshes `last_seen`. Successful
trims write a `retention.containers_pruned` audit row with the count.

A second cleanup happens *immediately* on every heartbeat: containers the
agent stopped reporting since the previous tick are deleted right away
(stragglers from the previous scan). This keeps the UI matching reality
without waiting for the daily prune.

---

## Container-only test elements

All evaluated by the agent, like every other element type in OpenSCM —
uniform dispatch, uniform applicability, uniform result lifecycle. The
metadata elements + `EXEC` shipped in 0.5.0–0.7.0.

| Element | Scope | Common use |
| :--- | :--- | :--- |
| `CONTAINER` | per-host | "is a container runtime installed here?" — great as an applicability gate |
| `IMAGE` | per-container | image identity (tag, digest, registry source, name) |
| `NETWORK` | per-container | network mode (`host`, `bridge`, `none`, named) |
| `PRIVILEGED` | per-container | `--privileged` flag (CIS Docker 5.4) |
| `RUN_USER` | per-container | container's running user (CIS Docker 4.1) |
| `MOUNT` | per-container | bind-mount source paths (CIS Docker 5.5 — block `/var/run/docker.sock`) |
| `EXPOSED_PORT` | per-container | ports published to the host |
| `READ_ONLY_FS` | per-container | `--read-only` flag (CIS Docker 5.12) |
| `HEALTH_CHECK` | per-container | `HEALTHCHECK` directive present |
| `EXEC` *(0.7.0, opt-in)* | per-container | run a command **inside** each container via `docker exec` / `podman exec`; tests `OUTPUT` or `EXIT CODE`. Requires the agent's `cmd_enabled = true` and a shell in the image. The container-side counterpart to host `CMD`. |

### IMAGE

Tests against the container's image reference. Sub-elements:

| Sub-element | What it returns | Example |
| :--- | :--- | :--- |
| `NAME` | Image name without tag/registry (e.g. `library/nginx`) | `IMAGE NAME contains library` |
| `TAG` | Tag after `:` (`latest` if absent) | `IMAGE TAG not equals latest` |
| `DIGEST` | Pulled image digest (`sha256:...`) | `IMAGE DIGEST contains sha256:abc...` |
| `SOURCE` | Registry host (`docker.io` if implicit) | `IMAGE SOURCE equals registry.corp.example.com` |

Image reference parsing follows the standard Docker rules: the first path
component is the registry host only when it contains `.`/`:`/is `localhost`;
otherwise it's the namespace.

### NETWORK

Tests against the container's network configuration. Sub-elements:

| Sub-element | What it returns | Example |
| :--- | :--- | :--- |
| `MODE` | `host` / `bridge` / `none` / `container:<id>` / named network | `NETWORK MODE not equals host` |

### CONTAINER

Host-level runtime presence check. Unlike IMAGE / NETWORK, this is
**evaluated by the agent** as part of the standard host dispatch — same
path as PROCESS, SERVICE, FILE, etc. The agent runs `docker --version`
and `podman --version`; if either succeeds, the runtime is considered
present.

| Sub-element | What it checks |
| :--- | :--- |
| `EXISTS` | PASS if `docker` OR `podman` CLI is on `$PATH` |
| `NOT EXISTS` | PASS if neither `docker` nor `podman` is on `$PATH` |

Input, condition, and sinput are ignored.

#### Recommended use — as an applicability gate

Because CONTAINER is agent-side, it works in the standard `applicability`
section. Add it to a host-level test (CMD / PROCESS / FILE / ...) that
should only run on container hosts:

```json
{
  "name": "Docker daemon is hardened",
  "conditions": [
    { "element": "CMD", "input": "docker info | grep ...",
      "selement": "OUTPUT", "condition": "CONTAINS", "sinput": "..." }
  ],
  "applicability": [
    { "element": "CONTAINER", "input": "", "selement": "EXISTS",
      "condition": null, "sinput": null }
  ]
}
```

On a host without Docker or Podman, applicability fails, the test
returns NA, and the report shows "not applicable" rather than a noisy
FAIL.

### PRIVILEGED

Per-container test for the `--privileged` flag (CIS Docker 5.4). A
privileged container bypasses nearly every kernel isolation property
and is functionally equivalent to a root shell on the host.

| Sub-element | What it checks |
| :--- | :--- |
| `EXISTS` | PASS iff the container was started with `--privileged` |
| `NOT EXISTS` | PASS iff the container is **not** privileged |

Input, condition, and sinput are ignored.

### RUN_USER

Per-container test for the user the container is running as
(CIS Docker 4.1 — don't run as root). Reads `Config.User` from the
inspect output.

| Sub-element | What it checks |
| :--- | :--- |
| `CONTENT` | The user string — works with `EQUALS`, `NOT EQUALS`, `CONTAINS`, `REGEX` |

Example: `RUN_USER CONTENT NOT EQUALS root` PASSes when the container
runs as anyone other than root.

### MOUNT

Per-container test for bind-mount source paths (CIS Docker 5.5 — the
most common container-escape misconfiguration is mounting
`/var/run/docker.sock`). Input is the host path to search for;
substring match against each mount's `src` field.

| Sub-element | What it checks |
| :--- | :--- |
| `EXISTS` | PASS iff any mount's source path contains the input |
| `NOT EXISTS` | PASS iff no mount source matches |

Example: `MOUNT NOT EXISTS input='/var/run/docker.sock'` PASSes when
the Docker socket is not mounted into the container.

### EXPOSED_PORT

Per-container test for ports published to the host. Reads
`NetworkSettings.Ports`, which is a JSON map keyed by `"port/proto"`
strings (`22/tcp`, `443/tcp`, `53/udp`, …).

| Sub-element | What it checks |
| :--- | :--- |
| `EXISTS` | PASS iff any exposed port substring-matches the input (e.g. input `22` matches `22/tcp` and `22/udp`; input `22/tcp` only matches that exact entry) |
| `NOT EXISTS` | PASS iff no exposed port matches |
| `COUNT` | Numeric condition on the total exposed-port count (input ignored; uses condition + sinput, e.g. `COUNT EQUALS 0`) |

### READ_ONLY_FS

Per-container test for the `--read-only` flag (CIS Docker 5.12 — cheap
defence in depth for stateless workloads).

| Sub-element | What it checks |
| :--- | :--- |
| `EXISTS` | PASS iff the container's root filesystem is read-only |
| `NOT EXISTS` | PASS iff the root filesystem is writable |

Input, condition, and sinput are ignored.

### HEALTH_CHECK

Per-container test for the presence of a `HEALTHCHECK` directive
(observability hygiene — containers without HEALTHCHECK can't be
restarted on liveness failure by orchestrators).

| Sub-element | What it checks |
| :--- | :--- |
| `EXISTS` | PASS iff `Config.Healthcheck` is present in the inspect output |
| `NOT EXISTS` | PASS iff no HEALTHCHECK is defined |

This checks for *presence*, not for HEALTHCHECK correctness — catches
the common "we just forgot" case.

---

## How container tests run

Container tests follow the same path as every other test in OpenSCM:

1. **Run Policy** (manual or scheduled) queues entries in the `commands` table.
2. The Linux agent picks up the queued tests on its next **heartbeat**.
3. The **element type decides where each test runs** — there's no separate
   host/container toggle:
   - **Per-container elements** — the metadata elements (`IMAGE`, `NETWORK`,
     `PRIVILEGED`, `RUN_USER`, `MOUNT`, `EXPOSED_PORT`, `READ_ONLY_FS`,
     `HEALTH_CHECK`) **and `EXEC`** are evaluated once **per container**,
     sending one result per container. `EXEC` runs its command *inside* each
     container via `docker exec` / `podman exec`.
   - **Host elements** (`CMD`, `FILE`, `PROCESS`, `SERVICE`, `CONTAINER`, …)
     are evaluated once on the host.
4. The server resolves each container's `runtime_id` to the `containers.id`
   it knows about and writes one row in `results` per result received
   (host results bind `container_id = 0`).

Results appear once the agent's next heartbeat completes — the same lag as
any other test in the system.

!!! note "Host elements inside a container"
    A test that mixes a per-container element (e.g. `EXEC`) with a host element
    (e.g. `FILE`) evaluates the host element as **NA** in the per-container
    pass — host elements have no meaning inside a container. To run a shell
    check inside a container, use `EXEC`; to check the host, use `CMD`.
    Images without a shell (`scratch`, distroless) make `exec` fail, so a CMD
    check there returns **FAIL** with a clear log line.

### Per-container compliance — a separate axis

Container results are scored on their **own axis**, independent of the host.
A host's system/policy/test compliance counts only host-level results
(`container_id = 0`), so container pass/fails never distort host numbers.
Each container gets its own `compliance_score` (% of its non-NA, non-excluded
results that passed), shown on the inventory row, the container detail panel,
and a **Containers** subsection nested under the host in policy and system
reports. A policy made entirely of container tests (e.g. the canned CIS
Docker policy) reports its container-axis average instead of "Not Scanned."

### Container detail panel

Click a container in the Systems list, then **Full Detail & Test Results**
(or open `/systems/{host_id}/containers/{container_id}`) to see the
container's identity, full configuration metadata, its compliance score, and
its recent per-container test results with the per-condition "why?" panel.

### Result history

Container results live in the same `results` table as host results, with a
non-zero `container_id`. Host results bind `container_id = 0`. The primary
key is `(tenant_id, system_id, test_id, container_id)`, so per-container
verdicts can coexist with the host-level verdict for the same test.

Results survive container churn — if a container is rebuilt with a new ID,
its prior results are still queryable for archival reports, rendered as
`(container removed)` in the UI if the row no longer exists in `containers`.

---

## Canned policy — Container Configuration Hardening L1

The OpenSCM Store ships a starter policy (`cis-container-config-l1.json`,
v1.3.0) with **12 tests** — the 8 metadata-element checks below plus an
in-container `EXEC` check (added in 0.7.0):

| Test | Element | Severity | What it checks |
| :--- | :--- | :--- | :--- |
| Image is not tagged `:latest` | IMAGE TAG | Medium | Tag pinning |
| Image source declared (explicit registry host) | IMAGE SOURCE | Low | Supply-chain provenance |
| Container does not use host network namespace | NETWORK MODE | High | CIS Docker 5.9 |
| Container is not network-isolated (`none` mode) | NETWORK MODE | Informational | Inventory / drift |
| Image name does not contain "test" or "dev" | IMAGE NAME (×2) | Low | Promotion-stage drift |
| Container is not running with `--privileged` | PRIVILEGED NOT EXISTS | High | CIS Docker 5.4 |
| Container is not running as root | RUN_USER CONTENT | Medium | CIS Docker 4.1 |
| Container does not mount the Docker socket | MOUNT NOT EXISTS | High | CIS Docker 5.5 |
| Container does not expose the SSH port | EXPOSED_PORT NOT EXISTS | Medium | Attack-surface reduction |
| Container has a read-only root filesystem | READ_ONLY_FS EXISTS | Low | CIS Docker 5.12 |
| Container defines a HEALTHCHECK | HEALTH_CHECK EXISTS | Informational | Observability hygiene |
| SSH server is not running inside the container | EXEC OUTPUT | Medium | CIS Docker 5.6 |

!!! note "The in-container EXEC check"
    The SSH test runs `ps` **inside** each container via `docker exec` /
    `podman exec`, so it needs the agent's `cmd_enabled = true` and an image
    with a shell. No-shell images (scratch/distroless) make `exec` fail and the
    test reports **FAIL** — exclude it for those (they're SSH-free by nature).

Sync the store under **Compliance → Policy Store**, import this policy,
assign it to a system group, and click **Run**. Per-container results
arrive on the next agent heartbeat — one result per container per test.

---

## Roadmap

Container support shipped in **0.5.0**. Releases since then have focused on
the surrounding platform rather than new container element types:

- **0.5.1** — Systems-list rendering fix (container chevron now paints on
  every host across all pages).
- **0.5.2** — [Automatic Groups](systems.md#automatic-groups): rule-based
  membership including container-aware fields (`containers_exists`,
  `has_runtime`, `any_container_image`).
- **0.5.3** — Performance pass on group reconciliation and compliance recalc.

Shipped in **0.7.0** — *finished* container compliance:

- **Per-container compliance axis** — container results no longer distort
  host/policy/system scores; each container is scored on its own.
- **Nested container results in reports** + a **container detail panel**.
- **Commands *inside* containers** — the new `EXEC` element runs a command in
  each container via `docker exec` / `podman exec`.

Still planned for container scanning itself:

- **`FILE` / `PACKAGE` / `USER`-style probes inside containers** — syscall- and
  filesystem-level checks via an injected probe (today only `CMD` and the
  metadata elements run inside a container).
- **Kubernetes** — pod inventory and per-pod / per-container tests;
  kubeconfig handling and RBAC. (Tentatively a future release.)

---

## Current limitations

- **App containers only** — Docker and Podman. LXC / LXD inventory deliberately not implemented; install an agent inside the OS container instead.
- **Linux agents only** — Docker Desktop on Windows / macOS runs containers inside a hidden VM that the host agent can't reach.
- **Only `CMD` and metadata elements run inside containers** — `FILE` / `PACKAGE` / `USER`-style checks against a container's filesystem aren't supported yet (they return NA inside a container). `CMD` requires a shell in the image.
- **No Kubernetes** — pods aren't inventoried; planned for a future release.
