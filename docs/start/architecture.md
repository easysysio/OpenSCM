# Architecture & Security

OpenSCM is designed with a "Security-First" philosophy. By leveraging the **Rust** 
programming language and a decentralized identity model, we ensure that the management 
infrastructure is as secure as the systems it monitors.

## The Handshake Protocol

OpenSCM operates on a strict **Server-Agent** model. Trust is established through a 
multi-stage cryptographic handshake using **Ed25519** asymmetric keys.

### 1. Registration (ID 0)
When an agent is first deployed, it generates a unique **Ed25519 keypair** locally. 
It then initiates an **ID 0** request, sending its **Public Key** and initial system 
metadata to the server. At this stage, the agent does not yet trust the server.

### 2. The Waiting Room (Pending)
The server receives the registration and assigns a unique ID to the system, but marks 
it as **Pending**. In this state:

- The server will **not** send security policies or compliance tests to the agent.
- The server will **not** disclose its own Server Public Key.
- The agent remains in a restricted heartbeat mode.

### 3. Administrator Approval
A security administrator must manually review and approve the pending system in the 
OpenSCM Dashboard. This prevents unauthorized agents from joining the network.

### 4. Verified Handshake
On the next heartbeat after approval, the server sends its **Server Public Key** to 
the agent. Both parties now possess each other's public keys. All subsequent communication is:

- **Authenticated** — every payload is signed with the sender's Ed25519 private key
- **Integrity-verified** — the receiver verifies the signature before processing
- **Tamper-proof** — a modified payload produces an invalid signature and is rejected

!!! info "Transport Security"
    Payload signing ensures **authenticity and integrity**. Transport **confidentiality** 
    is provided by TLS via a reverse proxy (Nginx, Caddy). This is the correct 
    separation of concerns — signing and encryption serve different security goals.

---

## Core Security Features

### :material-swap-horizontal: Namespaced Identity
Each agent maintains a separate keypair per server URL, stored as local files named 
with an 8-character hash of the server URL. This means:

- **Multi-server support** — one agent can register with multiple OpenSCM servers 
  simultaneously, each with its own independent identity
- **Isolated trust** — compromising one server's relationship doesn't affect others
- **Self-contained** — the agent's identity is stored locally, not dependent on 
  server-side sessions

### :material-autorenew: Self-Healing Identity
If an agent detects that its identity files (the local keypair) have been deleted or 
corrupted, it will automatically initiate a new **ID 0** registration.

!!! warning "Security Notice"
    The server treats a self-healed agent as a **new** registration. An administrator 
    must re-approve the system to restore its **Active** status. This prevents an 
    attacker from impersonating a lost agent without manual oversight.

### :material-shield-check: Memory Safety
By using **Rust**, OpenSCM avoids entire classes of vulnerabilities — buffer overflows, 
use-after-free, data races — that frequently affect security tools written in C or C++. 
This ensures the handshake and verification logic cannot themselves be used as exploit 
vectors.

---

## Privacy Architecture

OpenSCM follows a strict **Privacy-First** data model. This is a core design principle, 
not an afterthought.
