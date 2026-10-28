# Admin Settings

This section covers administrative tasks in OpenSCM — user management, roles,
server settings, and maintenance. Admin functions are only accessible to users with the
**Administrator** role.

---

## User Management

Navigate to **Settings > Users** to manage user accounts.

### User Roles

OpenSCM uses a four-tier role model. Each role inherits the permissions of
the roles below it.

| Role | Permissions |
| :--- | :--- |
| **Administrator** | Full access — user management, all editor/runner/viewer functions |
| **Editor** | Create and manage tests, policies, system groups |
| **Runner** | Execute policy scans, save reports |
| **Viewer** | Read-only access to dashboard, systems, policies, and reports |

### Creating a User

1. Navigate to **Settings > Users**
2. Click **New User**
3. Fill in the required fields:

| Field | Description |
| :--- | :--- |
| **Display Name** | Full name shown in the UI and reports |
| **Email** | User email address |
| **Username** | Login username |
| **Password** | Initial password — minimum 8 characters |
| **Role** | Access level assigned to the user |

4. Click **Create Account**

The user can log in immediately with the credentials you set. Advise them
to change their password on first login.

!!! warning "Password Policy"
    Passwords must be at least **8 characters**. There is currently no
    forced password change on first login — remind new users to change
    their password immediately.

### Editing a User

Click the **Edit** icon next to any user to update their:

- Display name
- Email address
- Role assignment

!!! note "Role Changes"
    Only administrators can change a user's role. Non-admin users can
    edit their own display name and email but cannot change their own role.

### Changing a Password

Each user can change their own password from their profile page:

1. Click the username in the top-right navigation bar
2. Select **Profile**
3. Scroll to **Security: Change Password**
4. Enter and confirm the new password
5. Click **Update Security Credentials**

Administrators can also change any user's password from the user edit page.

### Deleting a User

Click the **Delete** icon next to a user to remove their account.

!!! danger "Deletion Notes"
    - You cannot delete your own account
    - The default `admin` account (ID 1) cannot be deleted
    - Deletion is immediate and permanent — the user loses access instantly

---

## Default Admin Account

OpenSCM ships with a default administrator account:

| Field | Value |
| :--- | :--- |
| **Username** | `admin` |
| **Password** | `admin` |

!!! danger "Change Immediately"
    The default credentials must be changed immediately after installation.
    Anyone with network access to the dashboard can log in with these
    credentials until they are changed.

    Go to **Profile → Security: Change Password** after your first login.

---

## Role Assignment Guidelines

Assign the minimum role necessary for each user's responsibilities:

| User Type | Recommended Role |
| :--- | :--- |
| Security engineer managing tests and policies | Editor |
| Operations team running scans | Runner |
| Auditor reviewing compliance results | Viewer |
| Security administrator managing the platform | Administrator |

!!! tip "Principle of Least Privilege"
    Avoid assigning Administrator or Editor roles to users who only need
    to view reports. Use the Viewer role for auditors and stakeholders
    who need read-only access to compliance data.

---

## Server Settings

Navigate to **Settings > Settings** to configure server-wide options.

### General

| Setting | Description | Default |
| :--- | :--- | :--- |
| **Offline Threshold** | Minutes without activity before a system is marked offline and grayed out | `60` |
| **Auto-Delete Inactive Systems** | Minutes without activity before an active system is automatically deleted (`0` = disabled) | `0` |
| **Audit Log Retention (days)** | Days to keep entries in the audit log before they are automatically pruned (`0` = keep forever) | `730` |
| **Report Retention (days)** | Days to keep saved policy and system report snapshots before they are automatically pruned (`0` = keep forever) | `0` |
| **Notification Retention (days)** | Days to keep bell-icon notifications before they are automatically pruned (`0` = keep forever) | `30` |
| **System/Policy Trend Retention (days)** | Days to keep the hourly per-system / per-policy compliance snapshots behind the report trend charts (`0` = keep forever) | `90` |
| **Compliance Trend Retention (days)** | Days to keep the fleet-wide hourly snapshots behind the dashboard's compliance trend (`0` = keep forever) | `365` |

!!! warning "Auto-Delete Inactive Systems is destructive — and server downtime is not inactivity"
    A system deleted by this setting takes its results and compliance history with it;
    the agent re-registers on its next heartbeat, but as a **pending** system (unless it
    enrols with a token) and without its history. Leave it at `0` unless you actively
    need it, and set the threshold comfortably above your heartbeat interval plus jitter.

    Since **0.7.7** the prune is gated on **server uptime**: no system is judged
    inactive until the server has itself been running for at least the threshold, so a
    long outage can no longer delete the whole fleet on the first tick after a restart
    (while the server is down, no agent can check in). Frequent restarts simply mean
    pruning doesn't happen — it never deletes early.

!!! info "Retention Behavior"
    The retention pruners run **once per UTC day** from the scheduler. Each tenant's value is read at prune time so a setting change takes effect on the next daily tick (no restart required). Pruning is itself audited — successful trims write `retention.*` rows (e.g. `retention.reports_pruned`, `retention.entity_trends_pruned`) so you can answer "why did this data disappear" from the audit log. Set any value to `0` to disable pruning for that data type.

!!! warning "Fleet trend retention is new in 0.7.2"
    Before 0.7.2 the dashboard's compliance trend history was kept forever. On upgrade it starts trimming to **365 days** — set **Compliance Trend Retention** to `0` before the next daily prune if you want to keep the full history.

### Compliance

| Setting | Description | Default |
| :--- | :--- | :--- |
| **SAT Threshold** | Minimum compliance percentage to display green | `80%` |
| **MARGINAL Threshold** | Minimum compliance percentage to display yellow | `60%` |
| **Policy Compliance** | How a policy's score is computed — **Per test** (% of test results that passed) or **Per system** (% of systems that passed *every* test) | `Per test` |
| **System Compliance** | How a system's score is computed — **Per test** (% of its tests that passed) or **Per policy** (% of its assigned policies passed in full) | `Per test` |

Scores below the MARGINAL threshold are automatically displayed in red (UNSAT).
These thresholds affect compliance colors across the dashboard, policies, and reports.

!!! tip "Threshold Guidelines"
    - DISA STIG environments typically require 100% — set SAT to `100`
    - CIS Benchmark environments typically target 80–90%
    - MARGINAL threshold must always be lower than SAT threshold

!!! info "Per-test vs all-or-nothing (0.6.5 / 0.6.6)"
    **Per test** rewards partial progress (a host failing 1 of 10 tests still
    contributes 9 passes); **Per system / Per policy** is strict, all-or-nothing —
    one failing test drops the whole unit to 0%, the view auditors usually want.
    Both toggles are **per tenant**. As of **0.6.6**, switching either toggle takes
    effect **immediately** (both scores are stored at every recalc) and the
    compliance trend chart re-draws its full history in the selected mode instead
    of stepping at the switch point — see [Compliance Scoring](policies.md#compliance-scoring).

---

## Session Management

A sign-in lasts **8 hours** from the moment of login, whether or not the
user is active. Users are then redirected to the login page.

Sessions are signed cookies, keyed from the server's private key, and the
expiry is part of the signed value — a copied cookie stops working when it
expires, not merely when the browser discards it. Restarting the server does
not end existing sessions.

Every request is also checked against the current state of the account, so
these take effect **immediately**, without waiting for the session to expire:

| Change | Effect on open sessions |
|---|---|
| User deleted | All of that user's sessions end |
| Role changed | The new role applies from the next page load |
| Password changed or reset | All of that user's sessions end — except, when users change their own password, the browser they did it from |
| Organization suspended (SaaS) | All sessions in that organization end |
| Single sign-on identity unlinked (SaaS) | All of that user's sessions end — except, when admins unlink their own account, the browser they did it from |

!!! note "Secure cookies"
    The session cookie is marked **Secure** (sent only over HTTPS) when the
    **App URL** under **Settings → Email** starts with `https://`.
    Set it if you serve OpenSCM over HTTPS, including behind a proxy.

### Failed sign-in limits

Repeated failed sign-ins lock further attempts for **15 minutes**:

| Limit | Locks |
|---|---|
| 10 failures for one account within 15 minutes | That account, from every address |
| 30 failures from one address within 15 minutes | That address, for every account |

While a lock is on, the sign-in page says *Too many failed sign-in
attempts. Try again in N minutes.* The password isn't checked during a lock,
not even a correct one, so a guess made then reveals nothing. A successful
sign-in resets the account's count. Password and LDAP sign-ins both count.

The start of each lock is recorded once in the audit log as
`auth.login_locked`. An account lock is logged in that account's
organization; an address lock in the platform's log.

Counts are kept in memory: restarting the server clears every count and
every lock. To unlock an account early, restart the server.

!!! warning "Behind a proxy, check the trusted proxies"
    The address limit relies on knowing the visitor's real address. Behind a
    proxy or CDN on a public address, add it to `trusted_proxies` (see
    [Configuration](../start/configuration.md#behind-a-proxy-or-cdn)), or all
    visitors share the proxy's address and one limit.

---

## Server Maintenance

### Restarting the Server

Configuration changes require a service restart to take effect.

=== "Linux"
    ```bash
    sudo systemctl restart scmserver
    ```

=== "Windows"
    ```powershell
    Restart-Service OpenSCMServer
    ```

### Viewing Server Logs

=== "Linux"
    ```bash
    # Follow live logs
    sudo journalctl -u scmserver -f

    # View last 100 lines
    sudo journalctl -u scmserver -n 100
    ```

=== "Windows"
    ```powershell
    Get-EventLog -LogName Application -Source OpenSCMServer -Newest 50
    ```

### Database Location

The SQLite database is stored at a fixed location:

- **Linux:** `/var/lib/openscm/scm.db`
- **Windows:** `C:\ProgramData\OpenSCM\Server\scm.db`

### Database Backup

Back up the database file regularly to prevent data loss:

=== "Linux"
    ```bash
    # Stop the server before backing up for consistency
    sudo systemctl stop scmserver
    sudo cp /var/lib/openscm/scm.db /backup/scm.db.$(date +%Y%m%d)
    sudo systemctl start scmserver
    ```

=== "Windows"
    ```powershell
    Stop-Service OpenSCMServer
    Copy-Item "C:\ProgramData\OpenSCM\Server\scm.db" "C:\Backup\scm.db_$(Get-Date -Format yyyyMMdd)"
    Start-Service OpenSCMServer
    ```

### One Server per Database

The server locks `scmserver.lock`, next to the database, while it runs. A
second server started on the same database (a second service, or a second
container on the same volume) stops at startup with a message saying another
server is using it. The lock is released when the server exits, even after a
crash, so the file never needs deleting by hand.

### Downgrading

A database upgraded by a newer OpenSCM can't be used by an older one. If you
install an older version, or copy in a database from a newer server, the
server refuses to start and names the version it needs. The database is not
changed; install that version or a later one.

### Key Backup

!!! warning "Since 0.10.4, agents pin the server's key"
    Losing the key file now also means visiting every host running a 0.10.4
    or later agent, to run `scmclient --reset-server-key`. Back it up.

Back up the server's key file **together with the database**. The secrets
OpenSCM has to use are stored in the database encrypted under a key derived
from it:

- each organization's agent-signing key
- the SMTP password
- LDAP bind passwords
- single sign-on client secrets
- webhook secrets

A copy of the database alone doesn't reveal them. A database restored
without its key file can't read them either. If the key file is lost or
replaced:

- Every session ends, and users sign in again.
- Agents stop accepting the server's answers. Under **Settings → Danger
  Zone**, **Rotate Signing Key** issues a new key. Agents older than 0.10.4
  pick it up on their own. Agents from 0.10.4 on only trust a new key when
  the old one hands it over, and the old key is gone, so run
  `scmclient --reset-server-key` on each of their hosts (see
  [Configuration](../start/configuration.md#server-key-pinning)).
- Re-enter the SMTP password, LDAP bind passwords, the single sign-on client
  secret and webhook secrets. Until you do, they read as not set, and the
  server log names each one it couldn't read.

=== "Linux"
    ```bash
    sudo cp -r /etc/openscm/keys/ /backup/openscm-keys-$(date +%Y%m%d)/
    ```

=== "Windows"
    ```powershell
    Copy-Item "C:\ProgramData\OpenSCM\Server\keys\" "C:\Backup\openscm-keys-$(Get-Date -Format yyyyMMdd)\" -Recurse
    ```

!!! danger "Protect Your Keys"
    Server key files should be stored securely with restricted permissions.
    Never commit key files to version control or store them in publicly
    accessible locations.

---

## Version Update Notifications

OpenSCM checks for new releases automatically every hour by querying the GitHub
releases API. When a newer version is available, all **Administrator** users receive
an in-app notification with the new version number and a link to the download page.

- Notifications are deduplicated — each administrator is notified only once per version
- The check runs silently in the background and does not affect server performance
- No data is sent to GitHub — only a public API read request is made
