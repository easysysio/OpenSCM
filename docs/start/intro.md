# Welcome to OpenSCM

**OpenSCM** (Open Security Compliance Manager) is a self-hosted, privacy-first 
security compliance platform built in Rust.

Unlike traditional compliance tools that collect and centralize sensitive system data, 
OpenSCM agents execute tests locally and only report `PASS`, `FAIL`, or `NA` — your 
configuration files, user data, and system details **never leave your network**.

---

## Getting Started

New to OpenSCM? Start here:

<div class="grid cards" markdown>

-   :material-map-marker-path:{ .lg .middle } __Architecture__
    ---
    Understand the security model, handshake protocol, and privacy architecture.

    [:octicons-arrow-right-24: Read more](architecture.md)

-   :material-download:{ .lg .middle } __Installation__
    ---
    Install the server and agent on your infrastructure in minutes.

    [:octicons-arrow-right-24: Get started](installation.md)

-   :material-cog:{ .lg .middle } __Configuration__
    ---
    Configure the server and agents for your environment.

    [:octicons-arrow-right-24: Configure](configuration.md)

-   :material-shield-check:{ .lg .middle } __User Guide__
    ---
    Learn how to create tests, build policies, and generate compliance reports.

    [:octicons-arrow-right-24: Open guide](../guide/index.md)

</div>

---


## How It Works

```
1. Install scmserver     →  Central dashboard and policy management
2. Install scmclient     →  Agent on every system to monitor
3. Define tests          →  What to check (files, packages, ports, users...)
4. Build policies        →  Group tests and assign to system groups
5. Run or schedule       →  Agents execute locally, report PASS/FAIL/NA
6. Review reports        →  Dashboard, PDF evidence, compliance scores
```

---

## License

| Component | License |
| :--- | :--- |
| **Server & Dashboard** | FSL-1.1-ALv2 — converts to Apache 2.0 after 2 years |
| **Client Agent** | Apache 2.0 — no restrictions |
