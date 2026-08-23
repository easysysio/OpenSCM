# Systems & Groups

OpenSCM uses an automated discovery model paired with a manual approval gate —
agents register themselves automatically, but a security administrator must explicitly
approve each one before it can receive compliance tests.

---

## Systems

A **System** represents any endpoint running the `scmclient` agent — servers,
workstations, or any supported device.

### Automatic Discovery

You do not need to manually create system entries in the dashboard.

1. Install `scmclient` on the endpoint
2. Configure the server URL in the config file:

=== "Linux"
```toml
    # /etc/openscm/scmclient.config
    [server]
    url = "https://your-openscm-server.com"
    organization = "default"
```

=== "FreeBSD / macOS"
```toml
    # /usr/local/etc/openscm/scmclient.config
    [server]
    url = "https://your-openscm-server.com"
    organization = "default"
```

=== "Windows"
    Set `ServerURL` in the registry at:
    `HKEY_LOCAL_MACHINE\SOFTWARE\OpenSCM\Client`

3. Start the agent service — it will automatically register with the server
4. The system appears in the dashboard under **Systems** highlighted as **New**

### Adding a New System

Click the **New System** button at the top of the Systems page to open the agent
download page, where you can download and install `scmclient` on a new endpoint.

### Approving a System

New systems are **Pending** and cannot receive compliance tests until approved.

1. Navigate to **Systems**
2. Locate the system marked with a **New** badge
3. Review the metadata — Hostname, IP, OS, Architecture — to verify it is a
   legitimate device
4. Click **Approve**
5. On the next heartbeat the cryptographic handshake completes and the system
   becomes **Active**

!!! warning "Security Notice"
    Never approve a system you do not recognize. The approval step exists specifically
    to prevent unauthorized agents from joining your compliance network.

### Enrollment Tokens (auto-approval)

!!! info "Added in 0.6.0"
    For fleet provisioning, manually approving every new system doesn't scale.
    An **enrollment token** lets a system come up **Active** automatically —
    no Approve click — while still completing the full cryptographic handshake.

An enrollment token is a secret an admin mints once and bakes into an agent's
config (golden image, cloud-init, configuration management). Any system that
enrolls presenting a valid token is auto-approved. Combined with
[Automatic Groups](#automatic-groups), a freshly-provisioned box goes from
install → active → grouped → scanned with no human steps.

!!! warning "Approval, not authentication"
    A token only **skips the approval step** — exactly what an admin does by
    clicking Approve. It does **not** weaken agent security: every agent still
    generates its own keypair and signs every request. A leaked token can only
    auto-approve a system that could already enroll as *pending* anyway; it
    cannot impersonate an existing system or forge results.

#### Creating a token

1. Navigate to **Systems → Enrollment Tokens** *(Admin role required)*
2. Click **Create**, give it a name, and optionally set:
    - **Expiry** — a date after which the token stops auto-approving
    - **Max uses** — how many systems may enroll with it (blank = unlimited)
3. The secret (`oscm_…`) is shown **once** — copy it now; it is never displayed
   again (only a hashed form is stored)

#### Using a token

Add it to the agent configuration under `[server]`:

```toml
[server]
url               = "https://scm.example.com"
organization      = "default"
enrollment_token  = "oscm_…"
```

On Windows, set the `EnrollmentToken` value under
`HKLM\SOFTWARE\OpenSCM\Client`. The token is sent **only at first
registration**, never on routine heartbeats.

#### Managing tokens

The token list shows each token's status (**Active / Disabled / Expired /
Used up**), expiry, use count, and last-used time. You can **disable** a token
(keeps it for later) or **delete** it. Revoking a token only affects *future*
enrollments — already-approved systems are unaffected, since their ongoing
trust is the cryptographic signature, not the token.

!!! note "Invalid tokens are lenient"
    A typo'd, expired, or disabled token never blocks enrollment — the system
    simply falls back to **Pending** for manual approval, and the attempt is
    recorded in the [Audit Log](admin.md). Every token create / enable /
    disable / delete and every auto-approval is audited.

### Assigning a System to Groups

After approval, assign the system to one or more groups:

1. Click the **Edit** (pencil) icon next to the system
2. Select the desired groups from the dual list
3. Click **Save Changes**

Group assignment determines which policies the system participates in.

### Bulk Actions

Select multiple systems using the checkboxes on the left of each row, then use
the bulk toolbar that appears at the top of the table:

| Action | Description |
| :--- | :--- |
| **Approve** | Approve all selected pending systems in one click |
| **Add to Group** | Assign all selected systems to a group |
| **Upgrade** | Queue an agent upgrade for every selected system (Admin only) |
| **Delete** | Permanently remove all selected systems |

The **Select All** checkbox in the header selects all rows matching the current
search filter, not just the visible page.

!!! note "Role requirements"
    Approve / Add to Group / Delete require at least the **Editor** role.
    **Upgrade** requires the **Admin** role since it pushes a new binary to the
    endpoint.

### Upgrading Agents

The server bundles client binaries for every supported platform at build time.
When a registered system reports a version older than the bundled one, an amber
**Upgrade → vX.Y.Z** button appears on its row in the Systems list:

1. Click the **Upgrade** button on a single system, or select multiple systems
   and click **Upgrade** in the bulk toolbar
2. The server queues an `UPGRADE` command for each system in its commands table
3. On the agent's next heartbeat the server sends the upgrade command with the
   download URL, SHA-256 hash, and target version
4. The agent downloads the new binary, verifies the hash, atomically replaces
   itself on disk, and restarts
5. The new agent picks up any pending tests on its next heartbeat — nothing is
   lost during the upgrade

The button compares versions using semver, so it only appears when the bundled
version is strictly newer. Re-clicking an already-queued upgrade is a no-op (one
upgrade per system at a time, enforced by a unique index).

!!! tip "Per-platform availability"
    The Upgrade button only appears when the server bundles a binary for that
    system's platform (`{arch}-{os}` — for example `x86_64-linux`). If a system
    runs on an architecture that wasn't compiled into the server, no upgrade is
    offered.

### Live Telemetry

Each agent reports basic host telemetry with every heartbeat:

- **CPU Usage** — system-wide average, sampled over a 500ms window
- **Memory** — used / total in GB
- **Disk** — used / total in GB for the root volume (`/` on Unix, largest mount on Windows)
- **Uptime** — formatted as days + hours since boot

Telemetry appears as a compact line under each system's name in the Managed Systems list, and in the **Live Telemetry** section of the Quick View modal. Older agents that pre-date this feature show no telemetry — the fields are optional throughout, so mixed fleets are supported.

### Rejecting or Deleting a System

- **Reject (Pending)** — click the **Delete** button on a pending system to reject
  the registration request
- **Delete (Active)** — removes the system and all its compliance history from the
  database

!!! danger "Data Loss Warning"
    Deleting an active system permanently removes its historical compliance data.
    If the agent is still running on the endpoint it will attempt to re-register
    as a new pending system and require re-approval.

### Decommissioning a System

Deleting a system in the UI does not remove the agent from the machine, which
is why a live endpoint reappears as pending. To retire a machine properly,
uninstall the agent on it first:

```bash
curl -fsSL https://repo.openscm.io/install.sh | sh -s -- --uninstall
```

Then delete the system here. Add `--purge` to the command to also remove the
agent's config, its logs and the OpenSCM package repository. See
[Removing the agent](../start/installation.md#removing-the-agent).

!!! tip "Order matters"
    Uninstall first, then delete. Deleting first leaves a window in which the
    agent checks in again and comes back as a new pending system.

---

## System Groups

Groups organize your infrastructure logically — by department, environment, OS type,
or any other classification that makes sense for your organization.

Groups are the link between systems and policies. A policy is assigned to one or more
groups — every system in those groups participates in that policy's compliance scans.

```
System Group "Production-Linux"
    ├── web-server-01
    ├── web-server-02
    └── db-server-01
            ↓
    Policy: "CIS Ubuntu 22.04"
            ↓
    All three systems are scanned against this policy
```

### Creating a Group

1. Navigate to **System Groups**
2. Click **New Group**
3. Enter a name and description
4. Optionally assign systems immediately using the dual list
5. Click **Create Group**

### Editing a Group

Click the **Edit** icon to:

- Rename the group or update its description
- Add or remove systems using the dual list

Changes take effect immediately — systems added to a group will be included in
the next policy scan.

### Deleting a Group

Deleting a group removes the group definition and unlinks all systems from it.
The systems themselves are **not** deleted — they remain in the inventory and
can be assigned to other groups. Deleting an **auto group** also removes its
rule.

## Automatic Groups

!!! info "Added in 0.5.2"
    Auto-managed groups remove the manual "drag the new server into the right
    group" step. You define a **rule** once, and every system — new or
    existing — that matches the rule is placed in the group automatically and
    removed again if it ever stops matching.

A group is one of two types, chosen at creation and **immutable** afterwards:

| Type | Membership | Edited via |
|---|---|---|
| **Manual** | You add / remove systems yourself | The dual-list on the group page |
| **Auto** | Determined entirely by a rule | The rule editor |

A system can belong to any number of manual **and** auto groups at the same
time — they're independent. Manual memberships are never touched by rules, and
auto memberships can't be changed by hand (the next heartbeat would just undo
it), so the "Add to Group" pickers only ever show manual groups.

### How it works

```
Rule: os_family equals "linux"  AND  containers_exists is true
                          ↓  (evaluated on every heartbeat)
        matching systems join "Linux-Container-Hosts"
                          ↓
        Policy attached to that group scans them automatically
```

Membership is reconciled on **every agent heartbeat** — so a freshly-approved
system lands in the right groups within one heartbeat interval, and a policy
attached to those groups picks it up on the next scan. No manual step in
between.

### Creating an Auto Group

1. Navigate to **System Groups → New Auto Group** *(Admin role required)*
2. Give it a name and description
3. Build the rule with the click-based editor — one row per condition:
    - **Field** — what to test (grouped as Identity / Platform / Telemetry / Containers)
    - **Operator** — automatically narrowed to the operators valid for that field
    - **Value** — with an inline hint for the expected format
4. Add up to 8 conditions; **all** must match (logical **AND**)
5. Save — every existing system is evaluated immediately, and the **Currently
   matching** panel shows which systems the rule catches right now

!!! tip "Need OR logic?"
    A single rule is AND-only. To express OR, create a **second** auto group
    with its own rule and attach the same policy to both groups.

### Rule fields

Every field is something OpenSCM already collects — no extra data is gathered
from your systems (privacy-first):

| Category | Fields |
|---|---|
| **Identity** | `hostname`, `ip`, `status` |
| **Platform** | `os`, `os_family` (linux / macos / windows / freebsd / …), `arch`, `platform`, `ver` (agent version, semver-aware) |
| **Telemetry** | `mem_total_mb`, `disk_total_gb`, `uptime_secs` |
| **Containers** | `containers_exists`, `has_runtime` (docker / podman), `any_container_image` |

### Operators

| Field type | Operators |
|---|---|
| Text (`hostname`, `os`, …) | `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex` |
| IP (`ip`) | the text operators **plus** `in_cidr` (e.g. `10.10.0.0/16`) |
| Enum (`os_family`, `arch`, `status`, `has_runtime`) | `equals`, `not_equals`, `contains`, `not_contains`, `in`, `not_in` (comma-separated list) |
| Numeric (`mem_total_mb`, …) | `eq`, `ne`, `lt`, `le`, `gt`, `ge` |
| Agent version (`ver`) | text operators **plus** semver compare (`lt`/`le`/`gt`/`ge`) |
| Boolean (`containers_exists`) | `equals`, `not_equals` |

!!! note "Case-insensitive matching"
    `contains` / `not_contains` / `starts_with` / `ends_with` ignore case — so
    `os contains "mac"` matches a host reporting `Mac OS 14.5`. `equals` and
    `regex` are case-sensitive (use `(?i)` in a regex to opt out).

### Enabling, disabling, and editing

- **Edit** an auto group to change its name, description, or rule conditions —
  saving re-evaluates every system immediately.
- **Disable** a rule with the toggle to drop every matching system out of the
  group while keeping the rule definition for later. Re-enabling re-populates
  it.
- Every create / edit / enable / disable / delete is recorded in the
  [Audit Log](admin.md), with a count of how many systems the change moved.

### Auto groups in policies

Auto groups appear in the policy scope picker marked with **✨ (auto)** and
sorted after manual groups. Attach a policy to an auto group once, and the
policy's scope expands and contracts automatically as systems match or stop
matching the rule — no policy edit needed when fleet membership changes.

!!! tip "Best Practice"
    Structure your groups to mirror your infrastructure segments. For example:

    - `Production-Linux` — production Linux servers
    - `Production-Windows` — production Windows servers
    - `Dev-Linux` — development and staging Linux systems
    - `Network-DMZ` — DMZ-facing systems requiring stricter policies

    This makes it easy to apply different policy strictness levels to different
    segments of your network.
