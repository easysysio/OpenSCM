# Downloads

Choose your platform to download OpenSCM. Version **0.8.0** is the current stable release.

!!! tip "Package Repository"
    For automatic updates, we recommend using the package repository instead of
    direct downloads. See the [Installation Guide](installation.md) for setup instructions.

---

## Server (`scmserver`)

The central server manages agents, policies, and compliance reports.

=== "Debian / Ubuntu"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 (amd64) | [:material-download: scmserver_0.8.0-1_amd64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmserver/scmserver_0.8.0-1_amd64.deb) |
    | ARM64 (aarch64) | [:material-download: scmserver_0.8.0-1_arm64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmserver/scmserver_0.8.0-1_arm64.deb) |

    ```bash
    sudo dpkg -i scmserver_0.8.0-1_amd64.deb
    ```

=== "RedHat / Fedora / openSUSE"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmserver-0.8.0-1.x86_64.rpm](https://repo.openscm.io/stable/redhat/scmserver-0.8.0-1.x86_64.rpm) |
    | ARM64 (aarch64) | [:material-download: scmserver-0.8.0-1.aarch64.rpm](https://repo.openscm.io/stable/redhat/scmserver-0.8.0-1.aarch64.rpm) |

    ```bash
    sudo rpm -i scmserver-0.8.0-1.x86_64.rpm
    ```

=== "Windows"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmserver-0.8.0-1-x86_64.exe](https://repo.openscm.io/stable/windows/scmserver-0.8.0-1-x86_64.exe) |

    Run the installer and follow the setup wizard. The server will be registered
    as a Windows Service automatically.

---

## Agent (`scmclient`)

The agent is installed on every system you want to monitor.

=== "Debian / Ubuntu"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 (amd64) | [:material-download: scmclient_0.8.0-1_amd64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_amd64.deb) |
    | ARM64 (aarch64) | [:material-download: scmclient_0.8.0-1_arm64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_arm64.deb) |
    | ARMv7 (armhf) | [:material-download: scmclient_0.8.0-1_armhf.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_armhf.deb) |
    | i686 (32-bit x86) | [:material-download: scmclient_0.8.0-1_i386.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_i386.deb) |
    | RISC-V 64 | [:material-download: scmclient_0.8.0-1_riscv64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_riscv64.deb) |
    | PowerPC 64 LE | [:material-download: scmclient_0.8.0-1_ppc64el.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_ppc64el.deb) |
    | s390x (IBM Z) | [:material-download: scmclient_0.8.0-1_s390x.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_s390x.deb) |
    | LoongArch64 | [:material-download: scmclient_0.8.0-1_loong64.deb](https://repo.openscm.io/stable/debian/pool/main/s/scmclient/scmclient_0.8.0-1_loong64.deb) |

    ```bash
    sudo dpkg -i scmclient_0.8.0-1_amd64.deb
    ```

=== "RedHat / Fedora / openSUSE"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmclient-0.8.0-1.x86_64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.x86_64.rpm) |
    | ARM64 (aarch64) | [:material-download: scmclient-0.8.0-1.aarch64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.aarch64.rpm) |
    | ARMv7 (armhf) | [:material-download: scmclient-0.8.0-1.armhfp.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.armhfp.rpm) |
    | i686 (32-bit x86) | [:material-download: scmclient-0.8.0-1.i686.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.i686.rpm) |
    | RISC-V 64 | [:material-download: scmclient-0.8.0-1.riscv64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.riscv64.rpm) |
    | PowerPC 64 LE | [:material-download: scmclient-0.8.0-1.ppc64le.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.ppc64le.rpm) |
    | s390x (IBM Z) | [:material-download: scmclient-0.8.0-1.s390x.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.s390x.rpm) |
    | LoongArch64 | [:material-download: scmclient-0.8.0-1.loongarch64.rpm](https://repo.openscm.io/stable/redhat/scmclient-0.8.0-1.loongarch64.rpm) |

    ```bash
    sudo rpm -i scmclient-0.8.0-1.x86_64.rpm
    ```

=== "Arch Linux"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmclient_0.8.0-1_x86_64.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient_0.8.0-1_x86_64.pkg.tar.zst) |
    | ARM64 (aarch64) | [:material-download: scmclient_0.8.0-1_aarch64.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient_0.8.0-1_aarch64.pkg.tar.zst) |
    | ARMv7h | [:material-download: scmclient_0.8.0-1_armv7h.pkg.tar.zst](https://repo.openscm.io/stable/arch/scmclient_0.8.0-1_armv7h.pkg.tar.zst) |

    Install directly from the repository:

    ```bash
    sudo pacman -U https://repo.openscm.io/stable/arch/scmclient_0.8.0-1_x86_64.pkg.tar.zst
    ```

    Or install the downloaded package:

    ```bash
    sudo pacman -U scmclient_0.8.0-1_x86_64.pkg.tar.zst
    ```

=== "FreeBSD"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 (amd64) | [:material-download: scmclient-0.8.0-1-freebsd-amd64.pkg](https://repo.openscm.io/stable/freebsd/scmclient-0.8.0-1-freebsd-amd64.pkg) |

    ```bash
    pkg add scmclient-0.8.0-1-freebsd-amd64.pkg
    ```

=== "macOS"

    | Architecture | Package |
    | :--- | :--- |
    | Universal (ARM64 + x86_64) | [:material-download: scmclient_0.8.0-1_macos.pkg](https://repo.openscm.io/stable/macos/scmclient_0.8.0-1_macos.pkg) |

    Double-click the package to install, or from the terminal:

    ```bash
    sudo installer -pkg scmclient_0.8.0-1_macos.pkg -target /
    ```

=== "Windows"

    | Architecture | Package |
    | :--- | :--- |
    | x86_64 | [:material-download: scmclient-0.8.0-1-x86_64.exe](https://repo.openscm.io/stable/windows/scmclient-0.8.0-1-x86_64.exe) |

    Run the installer. The agent can be configured to run as a Windows Service
    during installation.

---

## Verify Your Download

We recommend verifying the integrity of your download using SHA-256:

=== "Linux / Arch Linux"

    ```bash
    sha256sum scmclient_0.8.0-1_amd64.deb
    ```

=== "macOS"

    ```bash
    shasum -a 256 scmclient_0.8.0-1_macos.pkg
    ```

=== "Windows (PowerShell)"

    ```powershell
    Get-FileHash scmclient-0.8.0-1-x86_64.exe -Algorithm SHA256
    ```

Compare the output against the checksums published on our
[GitHub Releases](https://github.com/easysysio/OpenSCM/releases/tag/v0.8.0) page.
