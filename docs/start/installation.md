# Installation

OpenSCM is designed to be lightweight with minimal dependencies, running on everything
from enterprise servers to edge devices.

## Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Operating System** | Linux, Windows 10+, FreeBSD, macOS, Arch Linux |
| **Architecture** | x86_64, ARM64, ARMv7, i686, RISC-V 64, PowerPC 64 LE, s390x, LoongArch64 |
| **Privileges** | `sudo` (Linux/macOS) or Administrator (Windows) |

---

## Server Installation

The server only needs to be installed once on a central host.

=== "Debian / Ubuntu"

    **1. Set up the repository:**

    ```bash
    curl -sS https://repo.openscm.io/openscm.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openscm.gpg
    echo "deb [signed-by=/usr/share/keyrings/openscm.gpg] https://repo.openscm.io/stable/debian stable main" | sudo tee /etc/apt/sources.list.d/openscm.list
    sudo apt update
    ```

    **2. Install:**

    ```bash
    sudo apt install scmserver
    ```

=== "RedHat / Fedora / CentOS"

    **1. Set up the repository:**

    ```bash
    sudo tee /etc/yum.repos.d/openscm.repo <<EOF
    [openscm]
    name=OpenSCM Stable
    baseurl=https://repo.openscm.io/stable/redhat/
    enabled=1
    gpgcheck=1
    gpgkey=https://repo.openscm.io/openscm.gpg
    EOF
    ```

    **2. Install:**

    ```bash
    sudo yum install scmserver
    ```

=== "openSUSE"

    **1. Set up the repository:**

    ```bash
    sudo zypper addrepo https://repo.openscm.io/stable/redhat/ openscm
    sudo zypper refresh
    ```

    **2. Install:**

    ```bash
    sudo zypper install scmserver
    ```

=== "Docker"

    ```bash
    docker run -d \
      --name openscm \
      -p 8000:8000 \
      -v openscm_config:/etc/openscm \
      -v openscm_data:/var/lib/openscm \
      openscm/scmserver:latest
    ```

    Or using Docker Compose:

    ```yaml
    version: '3.8'

    services:
      openscm:
        image: openscm/scmserver:latest
        container_name: openscm
        restart: unless-stopped
        ports:
          - "8000:8000"
        volumes:
          - openscm_data:/var/lib/openscm
          - openscm_config:/etc/openscm

    volumes:
      openscm_data:
      openscm_config:
    ```

    !!! warning "Volume Backup"
        Always mount the `/etc/openscm` volume. If it is lost all registered
        agents will need to re-register.

=== "Windows"

    Download the installer from the [Downloads](downloads.md) page and run the
    setup wizard. The server will be registered as a **Windows Service** automatically.

    Access the dashboard at **http://localhost:8000** after installation.

=== "Direct Download"

    Prefer a direct download? Get the latest packages from the [Downloads](downloads.md) page.

    ```bash
    # Debian/Ubuntu example
    sudo dpkg -i scmserver_0.7.12-1_amd64.deb
    ```

---

## Agent Installation

Install the agent on every system you want to monitor. The agent is lightweight
and has no runtime dependencies.

=== "Debian / Ubuntu"

    **1. Set up the repository:**

    ```bash
    curl -sS https://repo.openscm.io/openscm.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openscm.gpg
    echo "deb [signed-by=/usr/share/keyrings/openscm.gpg] https://repo.openscm.io/stable/debian stable main" | sudo tee /etc/apt/sources.list.d/openscm.list
    sudo apt update
    ```

    **2. Install:**

    ```bash
    sudo apt install scmclient
    ```

=== "RedHat / Fedora / CentOS"

    **1. Set up the repository:**

    ```bash
    sudo tee /etc/yum.repos.d/openscm.repo <<EOF
    [openscm]
    name=OpenSCM Stable
    baseurl=https://repo.openscm.io/stable/redhat/
    enabled=1
    gpgcheck=1
    gpgkey=https://repo.openscm.io/openscm.gpg
    EOF
    ```

    **2. Install:**

    ```bash
    sudo yum install scmclient
    ```

=== "openSUSE"

    **1. Set up the repository:**

    ```bash
    sudo zypper addrepo https://repo.openscm.io/stable/redhat/ openscm
    sudo zypper refresh
    ```

    **2. Install:**

    ```bash
    sudo zypper install scmclient
    ```

=== "Arch Linux"

    Import the OpenSCM signing key:

    ```bash
    curl -sS https://repo.openscm.io/openscm.gpg -o /tmp/openscm.gpg
    sudo pacman-key --add /tmp/openscm.gpg
    sudo pacman-key --lsign-key 8A39E120F8B52DBB
    ```

    Install directly from the repository:

    ```bash
    sudo pacman -U https://repo.openscm.io/stable/arch/scmclient_0.7.12-1_x86_64.pkg.tar.zst
    ```

    Available architectures: `x86_64`, `aarch64`, `armv7h`

    !!! note
        Arch Linux packages are available for x86_64, ARM64, and ARMv7 only.
        For i686, s390x, and LoongArch64 use the Debian or RPM packages.

=== "FreeBSD"

    Download the package from the [Downloads](downloads.md) page and run:

    ```bash
    pkg add scmclient-0.7.12-freebsd-amd64.pkg
    ```

    The service will start automatically after installation. Edit the config
    to point to your server then restart:

    ```bash
    vi /usr/local/etc/openscm/scmclient.config
    service scmclient restart
    ```

=== "macOS"

    Download the package from the [Downloads](downloads.md) page and double-click
    to install, or from the terminal:

    ```bash
    sudo installer -pkg scmclient_0.7.12-1_macos.pkg -target /
    ```

    Edit the config to point to your server then restart:

    ```bash
    sudo vi /usr/local/etc/openscm/scmclient.config
    sudo launchctl bootout system/io.openscm.scmclient
    sudo launchctl bootstrap system /Library/LaunchDaemons/io.openscm.scmclient.plist
    ```

=== "Windows"

    Download the installer from the [Downloads](downloads.md) page and run the
    setup wizard. The agent will be registered as a **Windows Service** automatically.

=== "Direct Download"

    ```bash
    # Debian/Ubuntu example
    sudo dpkg -i scmclient_0.7.12-1_amd64.deb
    ```

---

## Post-Installation Setup

### 1. Configure the Agent

Edit the config file and point it to your server:

=== "Linux / Arch Linux"

    ```bash
    sudo vi /etc/openscm/scmclient.config
    ```

=== "FreeBSD"

    ```bash
    vi /usr/local/etc/openscm/scmclient.config
    ```

=== "macOS"

    ```bash
    sudo vi /usr/local/etc/openscm/scmclient.config
    ```

=== "Windows"

    Use the registry editor or the installer wizard to set the server URL.

```toml
[server]
url = "https://your-openscm-server.com"  # Your server URL
organization = "default"                    # Organization identifier

[client]
heartbeat = "300"                        # Check-in interval in seconds
loglevel = "info"
```

### 2. Restart the Agent

=== "Linux / Arch Linux"

    ```bash
    sudo systemctl restart scmclient
    sudo systemctl enable scmclient
    ```

=== "FreeBSD"

    ```bash
    service scmclient restart
    ```

=== "macOS"

    ```bash
    sudo launchctl bootout system/io.openscm.scmclient
    sudo launchctl bootstrap system /Library/LaunchDaemons/io.openscm.scmclient.plist
    ```

=== "Windows"

    ```powershell
    Restart-Service OpenSCMClient
    ```

### 3. Approve the Agent

Once the agent starts it will send a registration request to the server.

1. Log in to the OpenSCM dashboard
2. Navigate to **Systems**
3. Find the pending system and click **Approve**

The agent is now active and will begin receiving compliance tests.

!!! tip "First-run Setup"
    On a fresh installation, the dashboard will walk you through creating your
    admin account on the first visit. No default credentials are set.

---

## Verify Installation

=== "Linux / Arch Linux"

    ```bash
    # Check server status
    sudo systemctl status scmserver

    # Check agent status
    sudo systemctl status scmclient

    # View logs
    sudo journalctl -u scmserver -f
    sudo journalctl -u scmclient -f
    ```

=== "FreeBSD"

    ```bash
    # Check agent status
    service scmclient status

    # View logs
    tail -f /var/log/openscm/scmclient.log
    ```

=== "macOS"

    ```bash
    # Check agent status
    sudo launchctl list | grep openscm

    # View logs
    tail -f /var/log/openscm/scmclient.log
    ```

=== "Windows"

    ```powershell
    # Check service status
    Get-Service OpenSCMServer
    Get-Service OpenSCMClient
    ```

---

## Health Probes

The server exposes two public, unauthenticated HTTP endpoints for use by
load balancers, container orchestrators, and uptime monitors. Both are
whitelisted by the init-guard middleware so they answer even before the
first-run setup is complete — which means a Kubernetes pod can come up
cleanly during a fresh install or a rolling upgrade with mid-flight
migrations.

### `GET /health` — liveness

"Is the process alive and accepting HTTP?" Returns immediately, no
database query, no work.

```bash
$ curl -i http://localhost:8000/health
HTTP/1.1 200 OK
content-type: application/json

{"status":"ok"}
```

Use for Kubernetes `livenessProbe`, the Docker image's `HEALTHCHECK`, and
basic load-balancer pool-membership decisions. If `/health` ever stops
returning 200, the orchestrator should restart the container.

### `GET /ready` — readiness

"Is the server able to serve real user traffic?" Returns `200 OK` only
when the database pool answers a trivial query **and** the schema is set
up. Returns `503 Service Unavailable` otherwise.

| Response | When | What it means |
| :--- | :--- | :--- |
| `200 OK` with `{"status":"ok","schema_version":N}` | DB reachable, schema present | Send traffic |
| `503` with `{"status":"db_unavailable"}` | DB pool can't `SELECT 1` | Hold traffic; check disk / DB lock |
| `503` with `{"status":"setup_pending"}` | Fresh install — `/install` not completed yet | Hold traffic until the first-run wizard is finished |

Use for Kubernetes `readinessProbe` so the load balancer keeps the old
pod in rotation while a rolling deploy runs migrations on the new one.

### Example wiring

=== "Kubernetes"

    ```yaml
    livenessProbe:
      httpGet:
        path: /health
        port: 8000
      periodSeconds: 10
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /ready
        port: 8000
      periodSeconds: 5
      failureThreshold: 3
    ```

=== "Docker / Compose"

    ```dockerfile
    HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
      CMD curl -fsS http://localhost:8000/health || exit 1
    ```

    ```yaml
    # docker-compose.yml
    services:
      scmserver:
        image: openscm/scmserver:latest
        healthcheck:
          test: ["CMD", "curl", "-fsS", "http://localhost:8000/health"]
          interval: 30s
          timeout: 3s
          retries: 3
    ```

=== "HAProxy"

    ```
    backend openscm
        option httpchk GET /ready
        http-check expect status 200
        server srv1 10.0.0.1:8000 check inter 5s fall 3 rise 2
        server srv2 10.0.0.2:8000 check inter 5s fall 3 rise 2
    ```

=== "Nginx (upstream health)"

    Add `nginx-plus` / `ngx_http_upstream_check_module`:

    ```nginx
    upstream openscm {
        server 10.0.0.1:8000;
        server 10.0.0.2:8000;
        check interval=5000 rise=2 fall=3 timeout=3000 type=http;
        check_http_send "GET /ready HTTP/1.0\r\n\r\n";
        check_http_expect_alive http_2xx;
    }
    ```

!!! tip "Let the server compress — don't strip `Accept-Encoding`"
    Since **0.7.12** OpenSCM compresses its own responses (gzip/brotli) and
    serves static assets with `ETag` + `Cache-Control`, which is most of the
    reason a page costs ~290 KB instead of ~4.8 MB. Both depend on headers
    surviving your reverse proxy:

    - Forward the client's `Accept-Encoding` header. Some proxy configurations
      clear it, which silently disables compression.
    - Don't strip `ETag` or `Cache-Control` from responses, or every navigation
      re-downloads the full asset set.
    - You do **not** need `gzip on` in Nginx for OpenSCM's own responses — it
      will not double-compress something already carrying `Content-Encoding`.
      Leaving it on is harmless.

!!! note "Both endpoints bypass the init-guard"
    Unlike every other route on the server, `/health` and `/ready` answer
    even before `/install` has been completed. This is deliberate so that
    a Kubernetes pod can be marked alive (and the load balancer can wait
    for it to become ready) during the brief window between container
    start and the first-run admin completing the setup wizard.
