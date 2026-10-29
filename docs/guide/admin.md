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

### Backups

`scmserver backup` writes one encrypted file holding everything the server
needs to come back as it was: the database, the server key pair and the
config. It runs while the server is running; there is no need to stop it.

=== "Linux"
    ```bash
    sudo scmserver backup
    ```

=== "Docker"
    ```bash
    docker exec -it openscm scmserver backup
    ```

=== "Windows"
    ```powershell
    # From the OpenSCM Server installation directory, as Administrator
    .\scmserver.exe backup
    ```

The file is written to `backups/` next to the database (on Linux
`/var/lib/openscm/backups/openscm-<host>-<time>.oscm-backup`, readable by
its owner only; on Docker that is on the data volume). `--out` names another
file or directory.

The backup is encrypted with a passphrase of at least 12 characters, asked
for when you run the command. For cron jobs, put it in a file only the
backup user can read and pass `--passphrase-file`, or set
`OPENSCM_BACKUP_PASSPHRASE`.

!!! warning "Keep the passphrase"
    Without the passphrase a backup cannot be opened, by you or anyone
    else. Store it somewhere other than next to the backups — a password
    manager or a sealed envelope.

Check a backup:

```bash
sudo scmserver backup verify /var/lib/openscm/backups/openscm-web1-20261029T020000Z.oscm-backup
```

`verify` decrypts it, checks every file against the checksums inside it and
the database copy with SQLite's `integrity_check`, and prints the OpenSCM
version, the counts of organizations, systems, results and saved reports, and
whether the server key is this server's. It never touches the running
server.

Copy backups off the server with your own tools (rsync, your backup agent,
`docker cp`): a backup on the same disk does not survive the disk. The
OpenSCM web interface never offers backups for download.

### Scheduled Backups

Scheduled backups are set up in **Settings → Backup**, which only
superusers see. They are off until you turn them on, and until then
superusers see a reminder on the dashboard.

1. On the server, set the backup passphrase once:

    === "Linux"
        ```bash
        sudo scmserver backup set-passphrase
        ```

    === "Docker"
        ```bash
        docker exec -it openscm scmserver backup set-passphrase
        ```

    === "Windows"
        ```powershell
        .\scmserver.exe backup set-passphrase
        ```

    It is stored in `backup.passphrase` beside the config
    (`/etc/openscm/backup.passphrase` on Linux), readable by the service
    account only. The web interface never sets or shows it, so a stolen
    session cannot choose the key to your backups. Changing it later does
    not change backups already made: they keep the passphrase they were made
    with.

2. In **Settings → Backup**, turn on **Back up on a schedule**, set the
   schedule (a cron expression in UTC; `0 2 * * *` is 02:00 every day) and
   how many backups to keep, and save.

Each backup is verified right after it is written. Only then are the oldest
backups in the folder deleted down to the number to keep; a failed backup
never deletes anything. Backups are written to `backups/` next to the
database, the same folder as `scmserver backup`.

**Back up now** on the same page starts a backup straight away. The page
shows the last result, the next scheduled run and the backups in the folder.

When a backup fails, superusers get a notification and a dashboard banner,
and the audit log records `backup.failed`. Successful backups are recorded as
`backup.create`, including ones made on the command line.

`scmserver backup` on the command line also uses the passphrase file when
no other passphrase is given, which makes it easy to call from your own
scripts.

### Restoring a Backup

`scmserver restore` puts a backup back: the database and the server key pair,
and the config with `--include-config`. The server must be stopped; restore
refuses to run while it is running.

=== "Linux"
    ```bash
    sudo systemctl stop scmserver
    sudo scmserver restore /var/lib/openscm/backups/openscm-web1-20261029T020000Z.oscm-backup
    sudo systemctl start scmserver
    ```

=== "Docker"
    ```bash
    docker stop openscm
    docker run --rm -it \
      -v openscm_data:/var/lib/openscm -v openscm_config:/etc/openscm \
      openscm/scmserver:latest \
      scmserver restore /var/lib/openscm/backups/openscm-web1-20261029T020000Z.oscm-backup
    docker start openscm
    ```

=== "Windows"
    ```powershell
    Stop-Service OpenSCMServer
    .\scmserver.exe restore C:\ProgramData\OpenSCM\Server\backups\openscm-web1-20261029T020000Z.oscm-backup
    Start-Service OpenSCMServer
    ```

Restore checks the backup as `verify` does, shows what it holds, and asks you
to type `restore` before changing anything (`--yes` skips the question). It
refuses:

- a backup from a **newer** OpenSCM — install that version or later first.
  A backup from an **older** OpenSCM is fine: the server upgrades it when it
  starts, as after a package upgrade.
- a SaaS backup on a Community or Enterprise server, and the other way round.

The files it replaces are moved to `pre-restore-<time>/` next to the
database. To undo a restore, stop the server and move them back. Restored
files keep the owner and permissions of the files they replace, so the
service account can still read them.

The config is left alone unless you pass `--include-config`: when restoring
onto a new machine, its TLS paths and addresses usually differ.

After the restore the server key is the backup's. Agents enrolled with that
server reconnect on their own. Agents that pinned a different key (0.10.4 and
later) need `scmclient --reset-server-key`. The first start after a restore
records it in the audit log (`backup.restored`).

!!! tip "Practice a restore"
    Restore your latest backup onto a spare machine every few months. It is
    the only proof that the backups and the passphrase work.

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

`scmserver backup` (above) includes the key pair. If you back up by hand,
back up the server's key file **together with the database**. The secrets
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
