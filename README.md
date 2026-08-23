# OpenSCM — Open Security Compliance Manager

[![License](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](https://fsl.software/)
[![Client License](https://img.shields.io/badge/client-Apache%202.0-green)](https://www.apache.org/licenses/LICENSE-2.0)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)](https://rust-lang.org/)
![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20Windows%20|%20FreeBSD%20|%20macOS-lightgrey)
![Architectures](https://img.shields.io/badge/arch-x86__64%20|%20ARM64%20|%20ARMv7%20|%20i686%20|%20RISC--V%20|%20PowerPC64%20|%20s390x%20|%20LoongArch64-blue)
[![Docker](https://img.shields.io/badge/docker-openscm%2Fscmserver-blue)](https://hub.docker.com/r/openscm/scmserver)

A self-hosted, privacy-first security compliance platform built in Rust.

Unlike traditional compliance tools, OpenSCM agents execute tests locally and only report `PASS`, `FAIL`, or `NA` — your configuration files, user data, and system details **never leave your network**.

For full documentation, installation guides, and user manual visit **[openscm.io](https://openscm.io)**.

---

## Documentation
To check out docs, visit [openscm.io](https://openscm.io).

## 🚀 Key Features

- **Privacy-First** — agents report results only, no raw system data leaves your network
- **Mutual Ed25519 Signing** — every payload is cryptographically signed in both directions
- **UI-Driven Policy Builder** — define compliance tests visually, no scripting required
- **Evidence-Grade Reports** — archive compliance results as formal audit evidence (PDF)
- **Universal Platform Support** — Linux, Windows, FreeBSD and macOS on x86_64, ARM64, ARMv7, i686, RISC-V, PowerPC64, s390x and LoongArch64
- **Single Binary Deployment** — server ships with all assets embedded, no setup required
- **Scheduled Scanning** — automate compliance scans on any schedule
- **Role-Based Access Control** — Administrator, Editor, Runner, Viewer

---

## Supported Platforms

| Platform | Architecture | Server | Client | Package Format |
|:---|:---|:---:|:---:|:---|
| Linux | x86_64 | ✅ | ✅ | deb, rpm, pkg.tar.zst |
| Linux | ARM64 (aarch64) | ✅ | ✅ | deb, rpm, pkg.tar.zst |
| Linux | ARMv7 (armhf) | ❌ | ✅ | deb, rpm, pkg.tar.zst |
| Linux | i686 (32-bit x86) | ❌ | ✅ | deb, rpm |
| Linux | RISC-V 64 | ❌ | ✅ | deb, rpm, pkg.tar.zst |
| Linux | PowerPC64LE | ❌ | ✅ | deb, rpm, pkg.tar.zst |
| Linux | s390x (IBM Z) | ❌ | ✅ | deb, rpm |
| Linux | LoongArch64 | ❌ | ✅ | deb, rpm |
| Windows | x86_64 | ✅ | ✅ | exe (NSIS) |
| macOS | Universal (ARM64 + x86_64) | ❌ | ✅ | pkg |
| FreeBSD | x86_64 | ❌ | ✅ | pkg |
| Docker | amd64, arm64 | ✅ | ❌ | image |

---

## ⚡ Installation

### Agent — one command

Run this on every machine you want to monitor. It detects the OS and CPU,
installs the right package, points the agent at your server and starts it:

```bash
curl -fsSL https://repo.openscm.io/install.sh | sh -s -- \
    --server https://your-openscm-server
```

Debian, Ubuntu, RHEL, Fedora, CentOS, Rocky, Alma, openSUSE, Arch, FreeBSD and
macOS, on every architecture the repository publishes. Add `--dry-run` to see
what it would do first, or `--help` for all options.

The machine then appears in OpenSCM under **Systems** as *pending* — approve it
there and it starts receiving compliance tests.

On **Windows**, download the installer from
**[openscm.io/start/downloads](https://openscm.io/start/downloads/)** and run
the setup wizard; the agent is registered as a Windows Service.

To remove the agent again:

```bash
curl -fsSL https://repo.openscm.io/install.sh | sh -s -- --uninstall
```

Add `--purge` to also drop its config, logs and the package repository.

### Server

**Ubuntu / Debian**

```bash
curl -sS https://repo.openscm.io/openscm.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openscm.gpg
echo "deb [signed-by=/usr/share/keyrings/openscm.gpg] https://repo.openscm.io/stable/debian stable main" | sudo tee /etc/apt/sources.list.d/openscm.list
sudo apt update
sudo apt install scmserver
```

**RedHat / CentOS / Fedora**

```bash
sudo tee /etc/yum.repos.d/openscm.repo <<EOF
[openscm]
name=OpenSCM Stable
baseurl=https://repo.openscm.io/stable/redhat/
enabled=1
gpgcheck=1
gpgkey=https://repo.openscm.io/openscm.gpg
EOF
sudo yum install scmserver
```

Windows installers and every other platform are on
**[openscm.io/start/downloads](https://openscm.io/start/downloads/)**.

Then browse to the server and the first-run setup will create your admin
account. Full instructions, including manual and air-gapped agent installs, are
in the **[installation guide](https://openscm.io/start/installation/)**.

## ⚖️ Licensing

| Component | License |
| :--- | :--- |
| **Server & Dashboard** | [FSL-1.1-ALv2](LICENSE-FSL) — converts to Apache 2.0 after 2 years |
| **Client Agent** | [Apache 2.0](LICENSE-APACHE) — no restrictions |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

For major changes please open an issue first to discuss what you'd like to change.

---

## 🔒 Security Disclosure

Please **do not** open public issues for security vulnerabilities.
Report them responsibly to **security@openscm.io** — we respond within 48 hours.

---

## 🛡️ Support

- **Docs & User Guide:** [openscm.io](https://openscm.io)
- **Bugs:** [GitHub Issues](https://github.com/easysysio/OpenSCM/issues)

---

<div align="center">
  <strong>Built with ❤️ and Rust</strong><br>
  <a href="https://openscm.io">openscm.io</a>
</div>
