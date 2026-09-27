# Downloads

Choose your platform to download OpenSCM. Version **0.9.4** is the current stable release.

!!! tip "Most people do not need this page"
    On Linux, macOS and FreeBSD, one command installs the agent, picks the
    right architecture and configures it:

    ```bash
    curl -fsSL https://repo.openscm.io/install.sh | sh -s -- \
        --server https://your-openscm-server
    ```

    The tables below are for choosing a specific file — air-gapped installs,
    your own automation, or building a golden image. See the
    [Installation Guide](installation.md) for both routes.

---

## Server (`scmserver`)

The central server manages agents, policies, and compliance reports.

=== "Debian / Ubuntu"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 (amd64) | [:material-download: scmserver_0.9.4-1_amd64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmserver/scmserver_0.9.4-1_amd64.deb) |
    | ARM64 (aarch64) | [:material-download: scmserver_0.9.4-1_arm64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmserver/scmserver_0.9.4-1_arm64.deb) |

    ```bash
    sudo dpkg -i scmserver_0.9.4-1_amd64.deb
    ```

=== "RedHat / Fedora / openSUSE"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmserver-0.9.4-1.x86_64.rpm](https://repo.openscm.io/stable/redhat/scmserver-0.9.4-1.x86_64.rpm) |
    | ARM64 (aarch64) | [:material-download: scmserver-0.9.4-1.aarch64.rpm](https://repo.openscm.io/stable/redhat/scmserver-0.9.4-1.aarch64.rpm) |

    ```bash
    sudo rpm -i scmserver-0.9.4-1.x86_64.rpm
    ```

=== "Windows"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmserver-0.9.4-1-x86_64.exe](https://repo.openscm.io/stable/windows/scmserver-0.9.4-1-x86_64.exe) |

    Run the installer and follow the setup wizard. The server will be registered
    as a Windows Service automatically.

---

## Agent (`scmclient`)

The agent is installed on every system you want to monitor. Unless you need a
particular file, use the one-line installer above — it selects the correct
package for the machine it runs on.

=== "Debian / Ubuntu"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 (amd64) | [:material-download: scmclient_0.9.4-1_amd64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_amd64.deb) |
    | ARM64 (aarch64) | [:material-download: scmclient_0.9.4-1_arm64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_arm64.deb) |
    | ARMv7 (armhf) | [:material-download: scmclient_0.9.4-1_armhf.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_armhf.deb) |
    | i686 (32-bit x86) | [:material-download: scmclient_0.9.4-1_i386.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_i386.deb) |
    | RISC-V 64 | [:material-download: scmclient_0.9.4-1_riscv64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_riscv64.deb) |
    | PowerPC 64 LE | [:material-download: scmclient_0.9.4-1_ppc64el.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_ppc64el.deb) |
    | s390x (IBM Z) | [:material-download: scmclient_0.9.4-1_s390x.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_s390x.deb) |
    | LoongArch64 | [:material-download: scmclient_0.9.4-1_loong64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.9.4-1_loong64.deb) |

    ```bash
    sudo dpkg -i scmclient_0.9.4-1_amd64.deb
    ```

=== "RedHat / Fedora / openSUSE"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmclient-0.9.4-1.x86_64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.x86_64.rpm) |
    | ARM64 (aarch64) | [:material-download: scmclient-0.9.4-1.aarch64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.aarch64.rpm) |
    | ARMv7 (armhf) | [:material-download: scmclient-0.9.4-1.armhf.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.armhf.rpm) |
    | i686 (32-bit x86) | [:material-download: scmclient-0.9.4-1.i386.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.i386.rpm) |
    | RISC-V 64 | [:material-download: scmclient-0.9.4-1.riscv64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.riscv64.rpm) |
    | PowerPC 64 LE | [:material-download: scmclient-0.9.4-1.ppc64le.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.ppc64le.rpm) |
    | s390x (IBM Z) | [:material-download: scmclient-0.9.4-1.s390x.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.s390x.rpm) |
    | LoongArch64 | [:material-download: scmclient-0.9.4-1.loongarch64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.9.4-1.loongarch64.rpm) |

    ```bash
    sudo rpm -i scmclient-0.9.4-1.x86_64.rpm
    ```

=== "Arch Linux"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmclient-0.9.4-1-x86_64.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient-0.9.4-1-x86_64.pkg.tar.zst) |
    | ARM64 (aarch64) | [:material-download: scmclient-0.9.4-1-aarch64.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient-0.9.4-1-aarch64.pkg.tar.zst) |
    | ARMv7 (armhf) | [:material-download: scmclient-0.9.4-1-armhf.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient-0.9.4-1-armhf.pkg.tar.zst) |
    | ppc64le | [:material-download: scmclient-0.9.4-1-ppc64le.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient-0.9.4-1-ppc64le.pkg.tar.zst) |
    | RISC-V 64 | [:material-download: scmclient-0.9.4-1-riscv64.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient-0.9.4-1-riscv64.pkg.tar.zst) |

    Install directly from the repository:

    ```bash
    sudo pacman -U https://repo.openscm.io/stable/arch/scmclient-0.9.4-1-x86_64.pkg.tar.zst
    ```

    Or install the downloaded package:

    ```bash
    sudo pacman -U scmclient-0.9.4-1-x86_64.pkg.tar.zst
    ```

=== "FreeBSD"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 (amd64) | [:material-download: scmclient-0.9.4-1-freebsd-amd64.pkg](https://repo.openscm.io/stable/freebsd/scmclient-0.9.4-1-freebsd-amd64.pkg) |

    ```bash
    pkg add scmclient-0.9.4-1-freebsd-amd64.pkg
    ```

=== "macOS"

    | Architecture | Package |
    | :--- | :--- |
    | Universal (ARM64 + x86_64) | [:material-download: scmclient_0.9.4-1_macos.pkg](https://repo.openscm.io/stable/macos/scmclient_0.9.4-1_macos.pkg) |

    Double-click the package to install, or from the terminal:

    ```bash
    sudo installer -pkg scmclient_0.9.4-1_macos.pkg -target /
    ```

=== "Windows"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmclient-0.9.4-1-x86_64.exe](https://repo.openscm.io/stable/windows/scmclient-0.9.4-1-x86_64.exe) |

    Run the installer. The agent can be configured to run as a Windows Service
    during installation.

---

## Verify Your Download

We recommend verifying the integrity of your download using SHA-256:

=== "Linux / Arch Linux"

    ```bash
    sha256sum scmclient_0.9.4-1_amd64.deb
    ```

=== "macOS"

    ```bash
    shasum -a 256 scmclient_0.9.4-1_macos.pkg
    ```

=== "Windows (PowerShell)"

    ```powershell
    Get-FileHash scmclient-0.9.4-1-x86_64.exe -Algorithm SHA256
    ```

Compare the output against the checksums published on our
[GitHub Releases](https://github.com/easysysio/OpenSCM/releases/tag/v0.9.4) page.
