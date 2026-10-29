# Backup & Restore

OpenSCM keeps audit evidence: results, saved reports, the audit log. This
page covers keeping it safe: what a backup holds, setting up scheduled
backups, getting them off the server, restoring, and checking that a restore
works before you need it.

---

## What a Backup Holds

A backup is one encrypted file, `openscm-<host>-<time>.oscm-backup`,
holding everything the server needs to come back as it was:

| Part | Why it matters |
|---|---|
| **The database**, a consistent copy taken while the server runs | Systems, tests, policies, results, saved reports, users, the audit log, settings |
| **The server key pair** | Agents from 0.10.4 on trust only this key, and the stored secrets (SMTP, LDAP, single sign-on, webhooks, each organization's signing key) are encrypted with a key derived from it |
| **The config file** (`scmserver.config`; not on Windows, where settings are in the registry) | Port, log level, trusted proxies |

It does **not** hold:

- server logs (journald, or the Windows event log)
- TLS certificates of a reverse proxy in front of OpenSCM
- anything on the agents; they keep their own key and settings

The file is always encrypted ([age](https://age-encryption.org), with a
passphrase), because it holds the server's private key: anyone with an
unencrypted copy could impersonate the server to every agent.

| | Linux | FreeBSD / macOS | Windows |
|---|---|---|---|
| Backups folder | `/var/lib/openscm/backups/` | `/var/db/openscm/backups/` | `C:\ProgramData\OpenSCM\Server\backups\` |
| Passphrase file | `/etc/openscm/backup.passphrase` | `/usr/local/etc/openscm/backup.passphrase` | `C:\ProgramData\OpenSCM\Server\backup.passphrase` |

With Docker the backups folder is on the data volume (`openscm_data`) and the
passphrase file on the config volume (`openscm_config`).

---

## Setting Up Scheduled Backups

**1. Set the passphrase**, once, on the server:

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
    # From the OpenSCM Server installation directory, as Administrator
    .\scmserver.exe backup set-passphrase
    ```

It asks twice and needs at least 12 characters. The file is readable by the
service account only. The web interface never sets or shows the passphrase,
so a stolen session cannot choose the key to your backups.

!!! warning "Keep a copy of the passphrase away from the server"
    Without it no backup can be opened, by you or anyone else. Put it in a
    password manager or a sealed envelope, not next to the backups.
    Changing it later does not change backups already made: each keeps the
    passphrase it was made with.

**2. Turn on the schedule.** In **Settings → Backup** (superusers only), turn
on **Back up on a schedule**, set the schedule and how many backups to keep,
and save. The schedule is a cron expression in UTC: `0 2 * * *` is 02:00
every day, `0 */6 * * *` every six hours. Changes apply without a restart.

Every backup is checked right after it is written: decrypted, each file
compared with its checksum, the database copy run through SQLite's
`integrity_check`. Only after that are the oldest backups in the folder
deleted down to the number to keep. A failed backup deletes nothing.

**3. Get told when it fails.** Superusers get a notification and a dashboard
banner when a backup fails. For email, webhook or syslog as well, create an
alert that watches **Server backups**
([Alerts](alerts.md#alerts-on-failed-backups)).

The Backup tab shows the last result, the next run and the backups in the
folder, and **Back up now** starts one straight away. Until scheduled
backups are on, superusers see a reminder on the dashboard.

The audit log records `backup.create`, `backup.failed`, `backup.settings`
and `backup.restored`.

---

## Command-Line Backups

`scmserver backup` makes a backup while the server runs, for your own
scripts or a one-off before an upgrade:

=== "Linux"
    ```bash
    sudo scmserver backup
    sudo scmserver backup --out /mnt/backup/   # a folder or a file name
    ```

=== "Docker"
    ```bash
    docker exec openscm scmserver backup
    ```

=== "Windows"
    ```powershell
    .\scmserver.exe backup
    ```

The passphrase comes from, in order: `--passphrase-file FILE`, the
`OPENSCM_BACKUP_PASSPHRASE` variable, the server's passphrase file, or a
prompt. With the passphrase file set up, no options are needed, so a cron
entry is one line:

```bash
# /etc/cron.d/openscm-backup — 03:30 every day
30 3 * * * root /usr/bin/scmserver backup >> /var/log/openscm-backup.log 2>&1
```

On Windows, a scheduled task does the same:

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\Program Files\OpenSCM\Server\scmserver.exe" -Argument "backup"
$trigger = New-ScheduledTaskTrigger -Daily -At 3:30am
Register-ScheduledTask -TaskName "OpenSCM backup" -Action $action -Trigger $trigger -User "SYSTEM"
```

(Adjust the path to where OpenSCM Server is installed.) The command exits
with a non-zero status on any failure, so cron mail and task history show it.

Check any backup without touching the server:

```bash
sudo scmserver backup verify /var/lib/openscm/backups/openscm-web1-20261029T020000Z.oscm-backup
```

```
Backup OK: /var/lib/openscm/backups/openscm-web1-20261029T020000Z.oscm-backup
  Made           2026-10-29T02:00:00Z on web1
  OpenSCM        1.0.0 (Community Edition), schema 50
  Organizations  1
  Systems        212
  Results        48210
  Saved reports  36
  Server key     SHA256:mK0f…
                 the same key as this server
  Config         included
```

---

## Getting Backups Off the Server

A backup on the server's own disk does not survive that disk. Copy the
backups folder somewhere else every day. OpenSCM never offers backups for
download in the web interface; copying them is the job of your own tools.

=== "rsync (pull)"
    Run this **on the backup host**, so the OpenSCM server holds no
    credentials for your backup storage:

    ```bash
    # crontab on the backup host — 04:00, after the 02:00 backup
    0 4 * * * rsync -a --delete-after backupuser@scm01:/var/lib/openscm/backups/ /srv/backups/openscm/
    ```

    Give `backupuser` read access to the folder only (for example through a
    group). `--delete-after` mirrors the server's retention; leave it out to
    keep older copies on the backup host.

=== "restic / borg"
    Add the backups folder to your existing job. The files are already
    encrypted and compressed, so deduplication gains little; keep that in
    mind for retention.

=== "Docker"
    The backups are on the `openscm_data` volume. Copy them with your volume
    backup, or:

    ```bash
    docker cp openscm:/var/lib/openscm/backups/ ./openscm-backups/
    ```

=== "Windows"
    ```powershell
    robocopy "C:\ProgramData\OpenSCM\Server\backups" "\\fileserver\backups\openscm" *.oscm-backup /MIR
    ```

---

## Restoring

`scmserver restore` puts a backup back: the database and the server key
pair, and the config when you pass `--include-config`. The server must be
stopped; restore refuses to run while it is running.

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

Restore checks the backup as `verify` does, shows what it holds, and asks
you to type `restore` before it changes anything (`--yes` skips the
question, for scripts). It refuses:

- a backup from a **newer** OpenSCM: install that version or later first.
  A backup from an **older** OpenSCM is fine; the server upgrades it when it
  starts, as after a package upgrade.
- a SaaS backup on a Community or Enterprise server, and the other way round.

The files it replaces are moved to `pre-restore-<time>/` next to the
database. Restored files keep the owner and permissions of the files they
replace, so the service account can still read them. If anything fails
partway, the old files are put back.

The first start after a restore records it in the audit log
(`backup.restored`), naming the backup.

### Moving to a New Machine

1. Install OpenSCM on the new machine: the **same version or newer** than the
   one that made the backup (`backup verify` shows it). Don't complete the
   setup page.
2. Copy the backup file across, and stop the server.
3. Restore. Add `--include-config` if the new machine should use the old
   config file as it is; leave it out if the port or trusted proxies differ.
4. Start the server and sign in with your usual account.
5. Point the agents at the new machine: change the DNS name they use, or
   their server address. The key is the backup's, so agents enrolled with
   the old server trust the new one at once.

Agents that pinned a different key (0.10.4 and later, enrolled with another
server) need `scmclient --reset-server-key`; see
[Configuration](../start/configuration.md#server-key-pinning).

### Undoing a Restore

The replaced files are in `pre-restore-<time>/` next to the database. To go
back, stop the server and move them into place:

=== "Linux"
    ```bash
    sudo systemctl stop scmserver
    cd /var/lib/openscm/pre-restore-20261029T101500Z
    sudo mv scm.db scm.db-wal scm.db-shm /var/lib/openscm/ 2>/dev/null
    sudo mv keys/scmserver.key keys/scmserver.pub /etc/openscm/keys/
    sudo mv scmserver.config /etc/openscm/ 2>/dev/null   # only with --include-config
    sudo systemctl start scmserver
    ```

=== "Windows"
    ```powershell
    Stop-Service OpenSCMServer
    $pre = "C:\ProgramData\OpenSCM\Server\pre-restore-20261029T101500Z"
    Move-Item "$pre\scm.db*" "C:\ProgramData\OpenSCM\Server\" -Force
    Move-Item "$pre\keys\*" "C:\ProgramData\OpenSCM\Server\keys\" -Force
    Start-Service OpenSCMServer
    ```

Once you are sure the restore is what you wanted, delete the
`pre-restore-…` folder: it holds the old database and key.

---

## Practise a Restore

A backup nobody has restored is a hope, not a backup. Every few months,
restore the latest one onto a spare machine or VM:

1. On a spare kept away from your agents (no DNS name they use, no route
   to them), install the same OpenSCM version as production.
2. Copy over the newest backup from your **off-server** copy, not from
   the server itself. That also tests the copying.
3. Restore it, with the passphrase from where you keep it, not from the
   server.
4. Start the server and sign in.
5. Compare the dashboard counts with what `backup verify` printed.
6. Open a recent saved report.
7. **Settings → Email → Send Test Email**. It only works if the stored
   SMTP password decrypted, which proves the key pair came back with the
   database.
8. Delete the spare: it now holds the server key.

---

## Opening a Backup Without OpenSCM

A backup is a standard age file holding a tar.gz. With the
[age](https://age-encryption.org) tool you can open one on any machine, for
example for an auditor, or if OpenSCM itself cannot be installed:

```bash
age -d openscm-web1-20261029T020000Z.oscm-backup | tar xz
```

It asks for the passphrase and unpacks `manifest.json`, `scm.db`,
`keys/scmserver.key`, `keys/scmserver.pub` and `scmserver.config`. Handle the
unpacked files like the server's own: the key file is the server's identity.

---

## Troubleshooting

| Message | What to do |
|---|---|
| *Another OpenSCM server is already using this database … The server must be stopped for a restore* | Stop the service (or container) first. |
| *Wrong passphrase, or the file was changed* | Check the passphrase. If it is right, the file is damaged: use another copy. |
| *This backup is from OpenSCM X … Install OpenSCM X or later first* | Upgrade this machine to that version, then restore. |
| *No backup passphrase is set* | Run `scmserver backup set-passphrase` on the server. |
| *… can be read by other accounts (mode 644)* | `sudo chmod 600 /etc/openscm/backup.passphrase` |
| *… is shorter than 12 characters* | Set a longer one with `scmserver backup set-passphrase`. |
| *Writing the backup failed: No space left on device* | Free space in the backups folder, or lower **Keep**. A backup needs about the database's size again while it is written. |
| *The backup was written but did not verify* | Usually a failing disk: check the server's disk and the server log. The broken file was deleted. |
