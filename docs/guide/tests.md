# Compliance Tests

A **Test** is the fundamental building block of OpenSCM compliance auditing. Each test
defines a single automated check — what to inspect, how to evaluate it, and what the
expected state should be.

Tests are executed **locally** by the agent. Only the result (`PASS`, `FAIL`, or `NA`)
is sent back to the server — no raw file contents, logs, or system data ever leaves
the endpoint.

---

## Test Structure

Each test consists of up to **5 conditions** combined with **ALL** or **ANY** logic:

```
Test: "Ensure SSH root login is disabled"
Filter: ALL conditions must pass

Condition 1:
    Element:     File
    Input:       /etc/ssh/sshd_config
    Sub-Element: Content
    Condition:   Contains
    Expected:    PermitRootLogin no
```

| Field | Description |
| :--- | :--- |
| **Element** | What to inspect (file, process, package, registry...) |
| **Input** | The target — file path, process name, package name, etc. |
| **Sub-Element** | What aspect to check (content, exists, permissions...) |
| **Condition** | How to evaluate (equals, contains, greater than...) |
| **Expected** | The value that constitutes a passing result |

!!! info "Where a test runs is decided by its element (0.7.0)"
    There's no host/container toggle — the **element type** decides. Host
    elements (`CMD`, `FILE`, `PROCESS`, …) run on the host; the container
    elements (`IMAGE`, `PRIVILEGED`, …) and the new **`EXEC`** element run
    **per container**. Use `EXEC` to run a shell command *inside* each container
    via `docker exec` / `podman exec` (the container-side counterpart to `CMD`).
    See [Containers](containers.md#container-only-test-elements).

---

## Supported Elements

### File

Checks properties of files on the filesystem.

| Sub-Element | Description | Example Input |
| :--- | :--- | :--- |
| `Exists` | File exists | `/etc/shadow` |
| `Not Exists` | File does not exist | `/etc/telnet.conf` |
| `Content` | The file's lines, checked one at a time — see [Checking file content](#checking-file-content) | `/etc/ssh/sshd_config` |
| `Permissions` | Octal permissions — see [Comparing permissions](#comparing-permissions) | `/etc/shadow` → `0640` |
| `Owner` | File owner, by name or numeric id — `equals` or `not equals` | `/etc/shadow` → `root` |
| `Group` | File group, by name or numeric id — supports `equals`, `not equals`, `contains`, `regex` | `/etc/shadow` → `shadow` |
| `SHA1` | SHA1 hash of file | `/bin/su` |
| `SHA256` | SHA256 hash of file | `/bin/su` |

#### Checking file content

A content check looks at the file **line by line**. If the path is a directory, every file directly inside it is checked.

| Condition | Passes when |
| :--- | :--- |
| `Contains`, `Equals`, `Regular Expression` | **at least one** line matches |
| `Not Contains`, `Not Equals` | **no** line matches |

So `Not Contains` `PermitRootLogin yes` passes only if that text appears nowhere in the file. A file that does not exist has no lines: it fails `Contains` and passes `Not Contains`. Pair the check with `Exists` if the file must also be present. A file the agent cannot read fails either way.

`Contains` is a plain substring match, so it also matches a commented-out line such as `#PermitRootLogin no`. Use `Regular Expression` with `^` when that matters: `^PermitRootLogin\s+no`.

#### Comparing permissions

Permissions are compared as sets of permission bits, not as numbers.

| Condition | Passes when | Example with expected `644` |
| :--- | :--- | :--- |
| `Equals` | the mode is exactly the expected one | `644` only |
| `Not Equals` | the mode is anything else | `600`, `664`, … |
| `Less Than` | the file grants **nothing beyond** the expected mode ("this or more restrictive") | `644`, `640`, `600`, `400` pass; `664`, `755`, `477` fail |
| `More Than` | the file grants **at least** the expected mode | `644`, `664`, `755` pass; `600` fails |

Write the expected value in octal: `644`, `0644` or, with the setuid / setgid / sticky bits, `4755` or `1777`. Those special bits are part of the comparison, so a setuid `4755` file is not `Equals 755`. A path that does not exist fails every permission check. An expected value that is not octal makes the test **N/A**, with an error in the agent log.

!!! note "Changed in 0.9.5"
    Before agent 0.9.5, `Less Than` and `More Than` compared modes as plain numbers, so `477` (full access for group and other) counted as "less than `644`", and a missing file passed. `Not Contains` and `Not Equals` on file content passed whenever *any* line lacked the text. Both gave false passes. After agents are upgraded to 0.9.5, tests that were passing for these reasons will correctly fail.

### Directory

Checks properties of directories.

| Sub-Element | Description |
| :--- | :--- |
| `Exists` | Directory exists |
| `Not Exists` | Directory does not exist |
| `Content` | Directory contains an entry with the given name — `not contains` / `not equals` require that it does not |
| `Permissions` | Octal permissions — see [Comparing permissions](#comparing-permissions) |
| `Owner` | Directory owner, by name or numeric id — `equals` or `not equals` |
| `Group` | Directory group, by name or numeric id — supports `equals`, `not equals`, `contains`, `regex` |

### Package

Checks installed software packages.

| Sub-Element | Description | Platforms |
| :--- | :--- | :--- |
| `Exists` | Package is installed | Linux, Windows |
| `Not Exists` | Package is not installed | Linux, Windows |
| `Version` | Installed version comparison — see [Comparing versions](#comparing-versions) | Linux, Windows |

#### Comparing versions

Version checks (`Package`, `OS` and `Agent`) understand real package versions, not only `1.2.3`.

- Versions are compared part by part, split on `.`; numbers compare as numbers (`2.10` is more than `2.9`) and a missing part counts as `0` (`1.2` equals `1.2.0`).
- Write the expected value the way the software's own documentation does. A distribution's packaging suffix and epoch are ignored unless your expected value includes them: with expected `8.0`, an installed `1:8.9p1-3ubuntu0.6` is compared as `8.9p1`.
- To pin an exact package build, include the suffix: `Equals` `3.0.2-0ubuntu1.15`.

| Installed | Condition | Expected | Result |
| :--- | :--- | :--- | :--- |
| `8.9p1-3ubuntu0.6` | `More Than` | `8.0` | Pass |
| `3.0.2-0ubuntu1.15` | `Equals` | `3.0.2` | Pass |
| `3.0.2-0ubuntu1.15` | `Equals` | `3.0.2-0ubuntu1.9` | Fail |
| `2.36-9+deb12u4` | `More Than` | `2.30` | Pass |
| `5.14.0-362.el9` | `Less Than` | `6.0` | Pass |

`Contains` and `Regular Expression` treat the version as plain text.

### Process

Checks running processes by name (substring, case-insensitive). Input = process name (e.g. `nginx`, `sshd`).

| Sub-Element | Description |
| :--- | :--- |
| `Exists` | At least one process matching the name is running |
| `Not Exists` | No process matching the name is running |
| `Count` | Number of matching processes — use with numeric conditions (`equals 1`, `more than 0`) |
| `Owner` | Username of the first matching process — use with `equals`, `contains`, `regex` |

**Example use cases:**

- Singleton daemon check (`sshd` Count `equals 1`)
- Privilege check (`nginx` Owner `equals www-data`)
- Banned process (`telnetd` Not Exists)

### Service

First-class service-state checks for "is this managed service enabled and running" controls — the kind auditors actually ask about. Input = service name (e.g. `auditd`, `sshd`, `firewalld`). No expected value needed — the sub-elements are boolean.

| Sub-Element | Description |
| :--- | :--- |
| `Active` | Service is currently running |
| `Inactive` | Service is currently stopped |
| `Enabled` | Service is configured to start at boot |
| `Disabled` | Service is not configured to start at boot |

**Platform support:**

| Platform | Active check | Enabled check |
| :--- | :--- | :--- |
| Linux | `systemctl is-active` | `systemctl is-enabled` |
| macOS | `launchctl print system/<name>` | `launchctl print-disabled system` |
| Windows | `sc query <name>` | `sc qc <name>` |
| FreeBSD | `service <name> status` | `sysrc -n <name>_enable` |

Returns `NA` when the platform's service manager isn't reachable (very rare — only on stripped-down systems without an init system).

**Example use cases:**

- CIS control: Ensure auditd is enabled (`auditd` Enabled)
- CIS control: Ensure firewalld is active (`firewalld` Active)
- STIG control: Ensure telnet.socket is disabled (`telnet.socket` Disabled)

### Port

Checks TCP port availability on localhost.

| Sub-Element | Description |
| :--- | :--- |
| `Exists` | Port is open and listening |
| `Not Exists` | Port is not listening |

### User

Checks local user accounts.

| Sub-Element | Description |
| :--- | :--- |
| `Exists` | User account exists |
| `Not Exists` | User account does not exist |

### Group

Checks local groups and membership.

| Sub-Element | Description |
| :--- | :--- |
| `Exists` | Group exists |
| `Not Exists` | Group does not exist |
| `Content` | User is a member of the group — set Expected to the username |

### CMD *(opt-in)*

Runs a shell command on the agent and evaluates its output or exit code against a condition.
On Linux/macOS the command is executed via `sh -c`; on Windows via `cmd /C`.

| Sub-Element | Description |
| :--- | :--- |
| `Output` | The combined stdout+stderr output of the command |
| `Exit Code` | The integer exit code — use `equals 0` for success, `not equals 0` for failure |

!!! warning "Requires explicit opt-in"
    CMD tests return `NA` unless `cmd_enabled = true` is set in the **client**
    (`scmclient.config`) on each agent. This is an intentional safety gate —
    an administrator must explicitly permit command execution per agent before
    any CMD test will run.

**Example use cases:**

- Check sysctl kernel parameters (`sysctl net.ipv4.conf.all.forwarding`)
- Verify firewall rules (`iptables -L`)
- Read values not exposed via files or packages
- Check a service's exit code (`systemctl is-active sshd` → Exit Code equals `0`)

### PowerShell *(opt-in, Windows only)*

Runs a PowerShell command on the agent and evaluates its output or exit code.
Tries `powershell.exe` (Windows PowerShell 5.x) first, then falls back to `pwsh` (PowerShell Core 7+).
On Linux/macOS this element always returns `NA` — use CMD instead.

| Sub-Element | Description |
| :--- | :--- |
| `Output` | The combined stdout+stderr output of the script |
| `Exit Code` | The integer exit code — use `equals 0` for success |

!!! warning "Requires explicit opt-in"
    PowerShell tests return `NA` unless `ps_enabled = true` is set in the Windows Registry
    at `HKLM\SOFTWARE\OpenSCM\Client` (`PsEnabled = true`). This is an intentional safety gate —
    an administrator must explicitly permit PowerShell execution per agent.

**Example use cases:**

- Read a registry value with complex logic (`(Get-ItemProperty ...).Value`)
- Check Windows Defender status (`Get-MpComputerStatus | Select -Expand RealTimeProtectionEnabled`)
- Validate Windows Update settings (`Get-WindowsUpdateLog`)
- Check service state (`(Get-Service wuauserv).Status` → Output equals `Running`)

### Registry *(Windows only)*

Validates Windows Registry values.

| Sub-Element | Description | Example Input |
| :--- | :--- | :--- |
| `Content` | Registry value data | `HKLM\SYSTEM\CurrentControlSet\...\path\|ValueName` |
| `Exists` | Registry key or value exists | |
| `Not Exists` | Registry key or value does not exist | |

!!! info "Registry Input Format"
    Use `path|ValueName` format for the input field.
    Example: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate|DisableWindowsUpdateAccess`

### OS

Checks operating system information.

| Sub-Element | Description |
| :--- | :--- |
| `Content` | OS name string — supports `equals`, `contains`, `regex` |
| `Version` | OS version comparison |

### Hostname

Checks the system hostname.

| Sub-Element | Description |
| :--- | :--- |
| `Content` | Hostname string — supports `equals`, `contains`, `regex` |

### IP

Checks IP address presence on the system.

| Sub-Element | Description |
| :--- | :--- |
| `Exists` | IP address is assigned to the system |
| `Content` | IP address matches condition — supports `equals`, `contains`, `regex` |

### Domain

Checks domain or workgroup membership.

| Sub-Element | Description |
| :--- | :--- |
| `Content` | Domain or workgroup name — supports `equals`, `contains`, `regex` |

### Architecture

Checks CPU architecture.

| Sub-Element | Description |
| :--- | :--- |
| `Content` | Architecture string (e.g. `x86_64`, `aarch64`) |

### Agent

Checks the installed agent version.

| Sub-Element | Description |
| :--- | :--- |
| `Version` | Agent version comparison |
| `Content` | Agent version string — supports `equals`, `contains`, `regex` |

---

## Supported Conditions

| Condition | Description | Example |
| :--- | :--- | :--- |
| `Contains` | Value contains the expected string | File content contains `PermitRootLogin no` |
| `Not Contains` | Value does not contain the string | Config does not contain `PermitRootLogin yes` |
| `Equals` | Exact match, ignoring letter case | Hostname equals `web-server-01` |
| `Not Equals` | Does not match | OS is not `Windows XP` |
| `More Than` | Greater than (strictly) | Process count > `0`, agent version > `0.1.0` |
| `Less Than` | Less than (strictly) | Command output < `10` |
| `Regular Expression` | Regular expression match ([Rust `regex` syntax](https://docs.rs/regex/latest/regex/#syntax); look-around and back-references are not supported) | Content matches `^Protocol\s+2$` |

`More Than` and `Less Than` compare **numbers** for counts, command output and exit codes; a value that is not a number fails. For versions they follow [Comparing versions](#comparing-versions), and for permissions [Comparing permissions](#comparing-permissions).

When a check looks at several values at once — the lines of a file, a file's group name and numeric id, a host's IP addresses — `Contains` and `Equals` pass if **any** of them matches, and `Not Contains` and `Not Equals` pass only if **none** does.

---

## Test Logic (Filter)

Each test uses one of two filter modes to evaluate its conditions:

| Filter | Behaviour |
| :--- | :--- |
| `ALL` | Every condition must pass for the test to pass |
| `ANY` | At least one condition must pass for the test to pass |

---

## Execution Flow

``` mermaid
sequenceDiagram
    participant S as OpenSCM Server
    participant A as Agent

    A->>S: Heartbeat (signed with agent Ed25519 key)
    S-->>A: Pending test commands (signed with server Ed25519 key)
    Note right of A: Agent executes tests locally
    A->>S: Results: PASS / FAIL / NA (signed)
    Note over S: Dashboard and reports updated
```

---

## Creating a Test

1. Navigate to **Tests** in the sidebar
2. Click **New Test**
3. Fill in the metadata — name, severity, description, rationale, remediation
4. Set the filter mode (**ALL** or **ANY**)
5. Add one or more conditions using the condition builder
6. Click **Save Test Definition**

!!! tip "Severity Levels"
    Assign severity to help prioritize remediation efforts:

    - **Critical** — immediate risk, must be remediated urgently
    - **High** — significant risk, remediate as soon as possible
    - **Medium** — moderate risk, schedule remediation
    - **Low** — minor risk, remediate when convenient
    - **Information** — informational only, no direct risk

Once created, tests can be added to one or more **Policies** for deployment
across your infrastructure.

---

## Bulk Actions

Select multiple tests using the checkboxes on the left of each row, then use
the bulk toolbar that appears at the top of the table:

| Action | Description |
| :--- | :--- |
| **Add to Policy** | Add all selected tests to a chosen policy |
| **Delete** | Permanently remove all selected tests |

The **Select All** checkbox in the header selects all rows matching the current
search filter, not just the visible page.

!!! note "Editor role required"
    Bulk actions require at least the **Editor** role.
