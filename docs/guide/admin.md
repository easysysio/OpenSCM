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

!!! note "Secure cookies"
    The session cookie is marked **Secure** (sent only over HTTPS) when the
    **App URL** under **Settings → Email** starts with `https://`.
    Set it if you serve OpenSCM over HTTPS, including behind a proxy.

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

### Key Backup

Back up your server keypair alongside the database. If the server keys
are lost all registered agents will fail signature verification and need
to re-register.

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
