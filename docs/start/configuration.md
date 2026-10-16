# Configuration

OpenSCM uses a platform-native approach to configuration. On **Linux**, **FreeBSD**, and **macOS**, configuration 
is handled via TOML files. On **Windows**, settings are stored in the **System Registry** 
to facilitate enterprise deployment via Group Policy (GPO).

---

## Server Configuration

The `scmserver` manages the central database and agent authorizations.

=== "Linux"

    **Default Path:** `/etc/openscm/scmserver.config`

    ```toml
    [server]
    port = "8000"       # Port for the web server
    loglevel = "info"   # debug | info | warn | error

    [database]
    # OpenSCM uses SQLite — no database server required.
    # The database file path is fixed (see Fixed Paths below).
    ```

=== "Windows (Registry)"

    **Path:** `HKEY_LOCAL_MACHINE\SOFTWARE\OpenSCM\Server`

    | Value Name | Type | Description |
    | :--- | :--- | :--- |
    | `Port` | REG_SZ | Port for the server (e.g., `8000`) |
    | `LogLevel` | REG_SZ | Logging level (`info`, `debug`, etc.) |
    | `TrustedProxies` | REG_SZ | Optional. Comma-separated; see [Behind a proxy or CDN](#behind-a-proxy-or-cdn) |

!!! info "Fixed Paths"
    The SQLite database and key paths are fixed and cannot be changed via config.

    | Resource | Linux | Windows |
    | :--- | :--- | :--- |
    | SQLite DB | `/var/lib/openscm/scm.db` | `C:\ProgramData\OpenSCM\Server\scm.db` |
    | Keys | `/etc/openscm/keys/` | `C:\ProgramData\OpenSCM\Server\keys\` |
    | Logs | `/var/log/openscm/` | `C:\ProgramData\OpenSCM\Server\logs\` |

---

## Database

OpenSCM uses **SQLite** — a single file embedded in the server process. No database server, no connection strings, no external dependencies.

The database file is created automatically on first run at the fixed path shown in the Fixed Paths table above. No `[database]` config is needed unless you want to acknowledge the path.

!!! tip "Setup wizard"
    On a fresh installation the first-run setup wizard initialises the database and creates the bootstrap admin account automatically.

---

## Client Configuration

The `scmclient` agent handles heartbeats and local compliance scanning.

=== "Linux"

    **Default Path:** `/etc/openscm/scmclient.config`

    ```toml
    [server]
    url = "http://localhost:8000"   # URL of your OpenSCM Server
    organization = "default"          # Organization identifier
    # enrollment_token = "oscm_…"     # Optional: auto-approve this system at enrollment

    [client]
    heartbeat = "300"              # Check-in interval in seconds
    loglevel = "info"              # debug | info | warn | error
    cmd_enabled = false            # Allow CMD tests to run (opt-in)
    ps_enabled  = false            # Allow PowerShell tests to run (opt-in, Windows only)
    ```

=== "FreeBSD"

    **Default Path:** `/usr/local/etc/openscm/scmclient.config`

    ```toml
    [server]
    url = "http://localhost:8000"   # URL of your OpenSCM Server
    organization = "default"          # Organization identifier
    # enrollment_token = "oscm_…"     # Optional: auto-approve this system at enrollment

    [client]
    heartbeat = "300"              # Check-in interval in seconds
    loglevel = "info"              # debug | info | warn | error
    cmd_enabled = false            # Allow CMD tests to run (opt-in)
    ps_enabled  = false            # Allow PowerShell tests to run (opt-in, Windows only)
    ```

=== "macOS"

    **Default Path:** `/usr/local/etc/openscm/scmclient.config`

    ```toml
    [server]
    url = "http://localhost:8000"   # URL of your OpenSCM Server
    organization = "default"          # Organization identifier
    # enrollment_token = "oscm_…"     # Optional: auto-approve this system at enrollment

    [client]
    heartbeat = "300"              # Check-in interval in seconds
    loglevel = "info"              # debug | info | warn | error
    cmd_enabled = false            # Allow CMD tests to run (opt-in)
    ps_enabled  = false            # Allow PowerShell tests to run (opt-in, Windows only)
    ```

=== "Windows (Registry)"

    **Path:** `HKEY_LOCAL_MACHINE\SOFTWARE\OpenSCM\Client`

    | Value Name | Type | Description |
    | :--- | :--- | :--- |
    | `ServerURL` | REG_SZ | URL of the OpenSCM Server |
    | `Organization` | REG_SZ | Organization identifier |
    | `Heartbeat` | REG_SZ | Check-in interval in seconds |
    | `LogLevel` | REG_SZ | Logging level |
    | `CmdEnabled` | REG_SZ | Allow CMD tests to run (`true` / `false`) |
    | `PsEnabled` | REG_SZ | Allow PowerShell tests to run (`true` / `false`) |

!!! info "Fixed Paths"
    The key paths are fixed and cannot be changed:

    | Resource | Linux | FreeBSD / macOS | Windows |
    | :--- | :--- | :--- | :--- |
    | Keys | `/etc/openscm/keys/` | `/usr/local/etc/openscm/keys/` | `C:\ProgramData\OpenSCM\Client\keys\` |
    | Logs | `/var/log/openscm/` | `/var/log/openscm/` | `C:\ProgramData\OpenSCM\Client\logs\` |

---

## Parameter Reference

### Server Parameters

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `server.port` | `8000` | Port the server listens on |
| `server.loglevel` | `info` | Log verbosity: `error`, `warn`, `info`, `debug` |
| `server.trusted_proxies` | loopback and private ranges | Addresses allowed to tell the server who the client is. See below |

#### Behind a proxy or CDN

OpenSCM records the client's address in the audit log and uses it for the
sign-in rate limits. Behind a reverse proxy, the connection comes from the
proxy, and the real address arrives in the `X-Forwarded-For` header. Anyone
can send that header, so OpenSCM only believes it when the connection comes
from a trusted proxy.

By default, loopback (`127.0.0.0/8`, `::1`) and the private ranges
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) are trusted.
That covers nginx or Caddy on the same host or the same Docker network, and
needs no setting.

If something on a public address sits in front, such as Cloudflare or a cloud
load balancer, list its ranges, together with your own proxy:

```toml
[server]
trusted_proxies = ["127.0.0.1", "173.245.48.0/20", "103.21.244.0/22"]
```

Setting the list replaces the defaults; it doesn't add to them. Without the
CDN's ranges, every visitor appears with the CDN's address, and visitors
share one sign-in rate limit. An empty list (`trusted_proxies = []`) trusts
nobody and ignores the header entirely, the right choice when nothing sits in
front of OpenSCM.

Make sure your proxy appends the client's address to `X-Forwarded-For` rather
than passing the client's own header through unchanged. Caddy does this by
default. In nginx:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

### Client Parameters

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `server.url` | `http://localhost:8000` | OpenSCM server URL |
| `server.organization` | `default` | Organization identifier |
| `server.enrollment_token` | _(none)_ | Optional golden token (`oscm_…`) that auto-approves this system at enrollment. See [Enrollment Tokens](../guide/systems.md#enrollment-tokens-auto-approval). Sent only at first registration. |
| `client.heartbeat` | `300` | Check-in interval in seconds |
| `client.loglevel` | `info` | Log verbosity: `error`, `warn`, `info`, `debug` |
| `client.cmd_enabled` | `false` | Allow CMD tests to run. When `false`, all CMD tests return `NA`. |
| `client.ps_enabled` | `false` | Allow PowerShell tests to run (Windows only). When `false`, all PowerShell tests return `NA`. |

!!! warning "CMD and PowerShell element security"
    Enabling `cmd_enabled` or `ps_enabled` permits the agent to run shell/PowerShell commands as defined in your compliance tests. Only enable these if you trust the tests assigned to the agent and understand the security implications.

---

## Heartbeat Interval Guidelines

The `heartbeat` setting controls how frequently the agent checks in with the server.

| Environment | Recommended | Reason |
| :--- | :--- | :--- |
| High-security | `60`–`120`s | Faster detection of policy changes |
| Standard | `300`s | Good balance of responsiveness and load |
| Large fleets (1000+) | `600`s+ | Reduces server load |

!!! tip
    A random jitter of 0–9 seconds is automatically added to each heartbeat 
    interval to prevent thundering herd problems in large deployments.

---

## Key Management

!!! danger "Identity Loss"
    If the files in the keys directory are deleted, the agent loses its identity. It will 
    automatically trigger a new **ID 0** registration and require an administrator 
    to re-approve the system in the dashboard.

!!! warning "Key Backup"
    Back up your **server** key files regularly. If the server keys are lost, 
    all registered agents will fail signature verification and need to re-register.

Keys are generated automatically on first run — no manual setup required.

---

## Applying Changes

Configuration changes take effect on service restart.

=== "Linux (systemd)"

    ```bash
    # Server
    sudo systemctl restart scmserver

    # Agent
    sudo systemctl restart scmclient
    ```

=== "FreeBSD"

    ```bash
    # Agent
    service scmclient restart
    ```

=== "macOS"

    ```bash
    # Agent
    sudo launchctl bootout system/io.openscm.scmclient
    sudo launchctl bootstrap system /Library/LaunchDaemons/io.openscm.scmclient.plist
    ```

=== "Windows (PowerShell)"

    ```powershell
    # Server
    Restart-Service OpenSCMServer

    # Agent
    Restart-Service OpenSCMClient
    ```

=== "CLI Override"

    The server URL can be overridden at runtime without editing the config file:

    ```bash
    scmclient --url https://openscm.yourcompany.com
    ```

    This saves the new URL to the config and persists across restarts.
