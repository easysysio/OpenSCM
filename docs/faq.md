# Frequently Asked Questions

---

## General

??? question "What is OpenSCM?"
    OpenSCM is a self-hosted, privacy-first security compliance platform built in Rust.
    It allows you to define security tests, group them into policies, deploy them to
    your infrastructure, and generate formal compliance reports — all without raw
    system data ever leaving your network.

??? question "Is OpenSCM free to use?"
    The **client agent** (`scmclient`) is licensed under **Apache 2.0** — completely
    free with no restrictions.

    The **server** (`scmserver`) is licensed under **FSL-1.1-ALv2** — free to use,
    self-host, and inspect. The license converts to Apache 2.0 two years after each
    release.

??? question "What operating systems are supported?"
    The agent supports **Linux** (Debian/Ubuntu, RHEL/Fedora, Arch Linux),
    **Windows**, **macOS**, and **FreeBSD** on x86_64, ARM64, ARMv7,
    i686 (32-bit x86), RISC-V 64, PowerPC 64 LE, s390x (IBM Z), and LoongArch64
    architectures. The server runs on Linux (x86_64, ARM64) and Windows (x86_64).

??? question "Do I need an internet connection to run OpenSCM?"
    No. OpenSCM is fully self-hosted. The server and agents communicate only with
    each other on your network. No data is sent to external servers.

??? question "How is OpenSCM different from other compliance tools?"
    Most compliance tools collect raw system data — file contents, logs, user lists —
    and send it to a central server. OpenSCM agents execute all checks locally and
    only report `PASS`, `FAIL`, or `NA`. Your system data never leaves your network.

---

## Installation & Setup

??? question "What are the server requirements?"
    OpenSCM server is a single binary with no external dependencies. It runs
    comfortably on a small VM or even a Raspberry Pi. Minimum recommended:

    - 1 CPU core
    - 512MB RAM
    - 1GB disk space (more for large deployments with many reports)

??? question "Do I need a database server?"
    No. OpenSCM uses **SQLite** embedded in the server binary. No PostgreSQL,
    MySQL, or any other database server is required.

??? question "Do I need a web server like Nginx?"
    Not for basic operation — OpenSCM serves its own web interface. However for
    production deployments we strongly recommend running behind a reverse proxy
    (Nginx or Caddy) for TLS termination and HTTPS support.

??? question "How do I enable HTTPS?"
    Place a reverse proxy in front of OpenSCM. Example with Caddy:

    ```
    # Caddyfile
    openscm.yourdomain.com {
        reverse_proxy localhost:8000
    }
    ```

    Caddy handles automatic TLS certificate issuance. See the
    [Configuration](start/configuration.md) guide for details.

??? question "The agent installed but doesn't appear in the dashboard"
    Check the following:

    1. Verify the `url` in `scmclient.config` points to your server correctly
    2. Ensure the server is reachable from the agent's network
    3. Check agent logs: `sudo journalctl -u scmclient -f`
    4. Confirm the server port (default `8000`) is not blocked by a firewall

??? question "I forgot the admin password. How do I reset it?"
    Password reset requires direct database access. Connect to the SQLite
    database and update the password hash:

    ```bash
    sqlite3 /var/lib/openscm/scm.db
    ```

    Generate a bcrypt hash for your new password (cost factor 12 recommended),
    then update the admin user:

    ```sql
    UPDATE users SET password_hash = '<bcrypt_hash>' WHERE username = 'admin';
    ```

    A CLI reset command is planned for a future release.

---

## Agents & Systems

??? question "How does an agent register with the server?"
    On first start the agent generates a unique Ed25519 keypair locally and sends
    a registration request (ID 0) to the server with its public key and system
    metadata. The system appears as **Pending** in the dashboard until an
    administrator approves it.

??? question "What happens if I delete an agent's key files?"
    The agent loses its identity and automatically initiates a new registration
    request. It will appear as a new **Pending** system and require re-approval
    by an administrator. The previous system entry and its compliance history
    remain in the database under the old identity.

??? question "Can one agent connect to multiple servers?"
    Yes. The agent maintains a separate keypair per server URL, stored as files
    named with a hash of the server URL. Each server relationship is completely
    independent.

??? question "How often does the agent check in?"
    The default heartbeat interval is **300 seconds** (5 minutes). This can be
    configured in `scmclient.config`:

    ```toml
    [client]
    heartbeat = "300"
    ```

    A random jitter of 0–9 seconds is automatically added to prevent
    thundering herd problems in large deployments.

??? question "Does the agent need root/administrator privileges?"
    For most compliance checks — file permissions, package lists, process status —
    the agent needs elevated privileges to read system state accurately. Running
    as root on Linux or as a service with Administrator privileges on Windows
    is recommended.

---

## Tests & Policies

??? question "What is the difference between a test and a policy?"
    A **test** is a single compliance check — one thing to verify on a system.
    A **policy** is a collection of tests bundled together and assigned to system
    groups. Tests are reusable — the same test can appear in multiple policies.

??? question "How many conditions can a test have?"
    Each test supports up to **5 conditions** combined with either **ALL**
    (every condition must pass) or **ANY** (at least one must pass) logic.

??? question "What does NA mean in test results?"
    `NA` (Not Applicable) means the test was skipped because it does not apply
    to that system. `NA` results are excluded from the compliance score calculation.

??? question "Can I assign a system to multiple groups?"
    Yes. A system can belong to multiple groups simultaneously. It will participate
    in the policies assigned to all of its groups.

??? question "Can the same test be in multiple policies?"
    Yes. Tests are defined once in the test library and can be included in as
    many policies as needed.

??? question "What happens to compliance scores when I add a new test to a policy?"
    The score will update after the next policy run. Systems that have not yet
    been scanned for the new test will not have a result for it until the next
    heartbeat cycle.

---

## Reports

??? question "Are reports saved automatically?"
    By default, reports must be saved manually — click **Save to History** after
    reviewing the live policy results to archive the snapshot.

    Each policy also supports an optional **report schedule** that saves compliance
    snapshots automatically on a defined interval. Configure it under the policy's
    **Schedule** settings.

??? question "Can I export reports?"
    Yes — reports can be exported as **PDF** from both the live policy report
    view and the saved reports archive.

??? question "Can I delete a saved report?"
    Yes, but deletion is permanent and cannot be undone. Export a PDF copy
    before deleting if you may need the record for future audits.

??? question "What timezone are the times shown in?"
    Since **0.7.4**, every timestamp in the web UI — systems, audit log, live and
    saved reports, containers, enrolment tokens — is rendered in **your browser's
    timezone**, with the zone abbreviation shown (e.g. `15/06/2026, 17:30:00 GMT+3`).
    Two colleagues in different countries each see the same instant in their own local
    time. Times are stored as UTC on the server and converted in the browser, so the
    server's own timezone no longer affects what you read.

    The trend charts follow the same rule: the hourly axis is plotted in your local
    time (since 0.7.5). PDF exports are generated server-side and are not affected.

??? question "Can I re-scan just one policy on one system?"
    Yes — since **0.7.7**, each policy card on the live system report has a **Run**
    button that queues only that policy's tests for that host. Useful for confirming a
    fix without re-scanning the fleet. Results appear after the agent's next heartbeat.
    See [Re-running One Policy on One System](guide/reports.md#re-running-one-policy-on-one-system).

---

## Security

??? question "Is communication between the agent and server encrypted?"
    All payloads are **cryptographically signed** with Ed25519 keys — ensuring
    authenticity and tamper-proofing. Transport **confidentiality** is provided
    by TLS via your reverse proxy. The server should always be placed behind
    a reverse proxy with HTTPS enabled in production.

??? question "What data does the agent send to the server?"
    The agent sends:

    - **Registration:** hostname, IP address, OS, architecture, agent version, public key
    - **Heartbeat:** system metadata updates, compliance test results (PASS/FAIL/NA only)

    Raw file contents, log entries, user data, and system configuration details
    are **never** transmitted.

??? question "How do I report a security vulnerability?"
    Please do **not** open a public GitHub issue for security vulnerabilities.
    Report them responsibly to **security@openscm.io**. We respond within 48 hours.

---

## Troubleshooting

??? question "The dashboard shows no compliance data after running a policy"
    Check the following:

    1. Confirm the system is **Active** (not Pending) in the Systems list
    2. Verify the system is assigned to a group that is linked to the policy
    3. Check the agent logs for errors: `sudo journalctl -u scmclient -f`
    4. Wait for the next heartbeat cycle — results are not instant

??? question "Compliance score shows -1 or Not Scanned"
    The policy has never been run. Click the **Run** button on the policy card
    to execute the first scan, or configure a schedule to run it automatically.

??? question "The agent shows as Active but no tests are running"
    Verify that:

    1. The system is assigned to at least one system group
    2. That system group is assigned to at least one policy
    3. The policy contains at least one test

??? question "The UI looks stale or slightly broken right after upgrading"
    Static assets are cached by the browser for up to an hour (since
    **0.7.10**), so immediately after an upgrade you may briefly be running new
    HTML against a cached stylesheet or script. The cache validator includes the
    build version, so this corrects itself on the next revalidation — but a
    hard refresh (**Ctrl/Cmd + Shift + R**) fixes it at once.

    If it persists well beyond an hour, check that your reverse proxy is not
    rewriting or stripping `ETag` / `Cache-Control` headers.

??? question "I see several scmclient processes on one host"
    First check whether they are really on the *same* host. On a container host
    (Proxmox/LXC, Docker), `ps` on the host also lists processes running **inside**
    each container, so one agent per container looks like many agents. Compare their
    mount namespaces — different values mean different containers, which is expected:

    ```bash
    for p in $(pgrep -x scmclient); do
      printf 'pid=%s mnt=%s\n' "$p" "$(readlink /proc/$p/ns/mnt)"
    done | sort -k2
    ```

    If they genuinely share one namespace, they are duplicates. Agents **before
    0.7.6** could accumulate this way across self-upgrades, and the strays are
    detached from the service manager, so upgrading alone will not clear them:

    ```bash
    sudo systemctl stop scmclient
    sudo pkill -x scmclient
    sudo systemctl start scmclient
    ```

    From **0.7.6** the agent holds a single-instance lock (`scmclient.lock`, beside
    its config), so a second copy on the same host exits instead of running in
    parallel. The lock is per-filesystem, so one agent per container is still allowed.

??? question "The agent is using a lot of memory"
    Upgrade to **0.7.6 or later**. Earlier agents ran on a multi-threaded runtime whose
    per-worker memory arenas never returned freed memory to the OS, so long-lived
    agents could grow to multi-GB RSS. The agent now runs single-threaded (it only
    ever does one thing at a time) and memory stays flat. If you also see many
    `scmclient` processes, see the previous question.

??? question "How do I view server logs?"

    === "Linux"
        ```bash
        sudo journalctl -u scmserver -f
        ```

    === "Windows"
        ```powershell
        Get-EventLog -LogName Application -Source OpenSCMServer -Newest 50
        ```
