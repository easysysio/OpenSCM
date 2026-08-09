# User Guide

This guide covers the core features of the OpenSCM Dashboard. Whether you are
managing a small lab or an enterprise fleet, these sections cover everything
you need to know.

---

## Core Modules

### :material-devices: [Systems & System Groups](systems.md)
The foundation of OpenSCM. Learn how to approve newly discovered endpoints,
organize them into logical groups, and manage group assignments.

### :material-list-status: [Compliance Tests](tests.md)
Define individual security checks — from simple file existence checks to
complex registry and configuration audits across Linux and Windows systems.

### :material-shield-check: [Security Policies](policies.md)
Bundle tests into policies and assign them to system groups. Learn how to
build a policy, run it, view live results, and save compliance reports.

### :material-file-chart: [Reports & Audits](reports.md)
Turn compliance results into formal audit evidence. Covers saving snapshots,
viewing historical records, and exporting PDF reports.

### :material-clock-outline: [Task Scheduler](scheduler.md)
Automate recurring compliance scans so your dashboard stays current without
manual intervention.

### :material-cog: [Admin Settings](admin.md)
Manage users, roles, and server settings including compliance thresholds and offline detection.

---

## Typical Workflow

New to OpenSCM? Follow this order to get your first compliance scan running:

1. **Install the agent** — deploy `scmclient` on the systems you want to monitor
2. **Approve systems** — go to [Systems](systems.md) and approve pending endpoints
3. **Assign groups** — organize systems into logical [System Groups](systems.md)
4. **Define tests** — create [Compliance Tests](tests.md) for what you want to check
5. **Build a policy** — group tests into a [Policy](policies.md) and assign it to your groups
6. **Run the policy** — execute manually or set a [Schedule](scheduler.md)
7. **Review results** — view the live report and save it to the [Reports](reports.md) archive

---

!!! info "Need help?"
    Check the [FAQ](../faq.md) for common questions and troubleshooting tips.
