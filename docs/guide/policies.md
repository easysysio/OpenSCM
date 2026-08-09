# Security Policies

A **Policy** is a collection of [Compliance Tests](tests.md) bundled together to
define a security standard for a segment of your infrastructure. While tests define
individual rules, policies are the mechanism used to deploy those rules to your systems.

By grouping tests into policies you can manage different compliance requirements
independently — for example a "Linux Server Baseline" for all Linux servers and a
"PCI-DSS Controls" policy for payment systems.

---

## How Policies Work

A policy connects your test library to your system groups.

``` mermaid
graph TD
    A[Tests Library] -->|Selected into| B{Security Policy}
    B -->|Assigned to| C[System Group: Production]
    B -->|Assigned to| D[System Group: Staging]
    C -->|Contains| E[web-server-01]
    C -->|Contains| F[web-server-02]
    D -->|Contains| G[staging-01]
```

1. **Select** — choose tests from your library to include in the policy
2. **Assign** — link the policy to one or more system groups
3. **Run** — agents in those groups receive the tests and execute them locally
4. **Report** — results are collected and the compliance score is calculated

---

## Creating a Policy

Navigate to **Policies** and click **New Policy**.

### Basic Information

| Field | Description |
| :--- | :--- |
| **Name** | A descriptive title, e.g. `CIS Ubuntu 22.04 Level 1` |
| **Version** | Policy version, e.g. `1.0.0` |
| **Description** | What this policy covers and which framework it maps to |

### Selecting Tests

Use the dual list to move tests from **Available** to **Selected for Policy**.
Tests are shown with their severity level to help you identify critical checks.

### Assigning System Groups

Use the second dual list to select which system groups this policy applies to.
Every system in the selected groups will participate in compliance scans for this policy.

!!! note
    A system group can have multiple policies assigned simultaneously. The agent
    aggregates tests from all assigned policies and runs them in a single pass.

### Scheduling *(Optional)*

Each policy supports two independent schedules — one for automated scanning and one
for automated report archiving. Both can be configured independently with different
frequencies.

#### Auto-Scan

Enable **Auto-Scan** to run the policy automatically on a schedule:

| Frequency | Description |
| :--- | :--- |
| Daily | Runs once per day |
| Weekly | Runs once per week |
| Monthly | Runs once per month |
| Custom | Cron expression for full control |

When triggered, the scheduler queues compliance tests for all agents in the
assigned system groups. Agents pick up tests on their next heartbeat and
return results shortly after.

#### Auto-Report

Enable **Auto-Report** to automatically archive a compliance snapshot on a schedule:

| Frequency | Description |
| :--- | :--- |
| Daily | Saves a report once per day |
| Weekly | Saves a report once per week |
| Monthly | Saves a report once per month |
| Custom | Cron expression for full control |

When triggered, the scheduler saves the current compliance state as an archived
report — identical to clicking **Save to History** manually. The submitter is
recorded as `Scheduler`.

!!! tip "Recommended Combination"
    Run Auto-Scan daily and Auto-Report monthly. This keeps compliance data
    current while producing regular formal audit records automatically.

!!! note
    Auto-Report saves whatever results are currently available. For best results
    schedule the report to run after the scan has had time to complete and agents
    have returned their results.

See the [Scheduler](scheduler.md) guide for details.

---

## Running a Policy

To run a policy immediately click the **Run** (rocket) button on the policy card.
This queues compliance tests for all agents in the assigned system groups.

Tests are picked up by agents on their next heartbeat and executed locally. Results
are returned on the following heartbeat.

---

## Compliance Scoring

OpenSCM calculates a **Compliance Score** for each policy. How that score is
computed is configurable in **Settings > Settings > Compliance** — choose
whichever model matches how you report:

=== "Per test (default)"

    Counts individual test results across all systems in the policy:

    ```
    Score = (Tests passed / Tests applicable) × 100
    ```

    A system that fails 1 of 10 tests still contributes 9 passing results — so
    partial progress is visible. This is the right view for tracking remediation.

=== "Per system"

    Counts whole systems, all-or-nothing — the strict audit view:

    ```
    Score = (Systems that passed every test / Systems applicable) × 100
    ```

    A system with even one failing test counts as a full failure. A policy with
    one system that fails 1 of 5 tests scores **0%**.

| Score | Status | Meaning |
| :--- | :--- | :--- |
| `≥ SAT threshold` | :material-shield-check: SAT | Meets the compliance target |
| `≥ MARGINAL threshold` | :material-shield-alert: MARGINAL | Partial — some failures |
| `< MARGINAL threshold` | :material-shield-off: UNSAT | Below the acceptable bar |
| `-1` | :material-minus-circle: Not Scanned | Policy has never been run |

!!! info "Added in 0.6.5 / 0.6.6"
    The **Per test / Per system** toggle was added in 0.6.5 (and a matching
    **System Compliance** toggle — *Per test / Per policy* — governs how a
    *system's* score is computed). As of **0.6.6** both scores are stored at
    every recalculation, so switching the toggle updates the dashboard, policy
    list, and reports **instantly** (no recompute wait) and the **compliance
    trend chart re-renders its whole history in the chosen mode** rather than
    showing an artificial step at the moment you switched. Both settings are
    **per tenant** and default to **Per test**.

!!! note "NA Results"
    Tests that return `NA` (Not Applicable) are excluded from the compliance score
    in every mode — they are kept out of both the numerator and denominator. A
    system with only NA results is treated as **Not Scanned**.

!!! note "Configurable Thresholds"
    SAT and MARGINAL thresholds are configurable in **Settings > Settings > Compliance**.
    Defaults are 80% for SAT and 60% for MARGINAL.

!!! note "Score Updates"
    The compliance score updates each time an agent returns results. The dashboard
    always reflects the most recent scan results available.

---

## Policy Reports

Click **View Report** on a policy card to see a live compliance report showing
per-system, per-test results.

From the report you can:

- See which systems are compliant and which are not
- See exactly which tests failed on each system
- Click any test name to view its **description, check procedure, and remediation steps**
- **Save to History** — archives the current results as a formal compliance record
- **Export PDF** — downloads a printable audit report

Saved reports are accessible from the **Reports** section and serve as evidence
for security audits.

---

## Best Practices

**Use focused policies over large ones**

Instead of one policy with hundreds of tests, create smaller focused policies:

- `OS-Baseline-Linux` — core hardening for all Linux systems
- `OS-Baseline-Windows` — core hardening for all Windows systems
- `Web-Server-Hardening` — additional controls for web-facing systems
- `PCI-DSS-Controls` — controls required for payment system compliance

This makes it easier to understand failures, assign responsibility, and
produce targeted audit evidence.

**Use versioning**

Increment the policy version when you add or remove tests. This makes it
clear in archived reports exactly which set of controls was active at the
time of a scan.

**Assign policies at the group level**

When a new system is approved and added to a group it automatically
participates in all policies assigned to that group on the next heartbeat.
Set up a baseline group with your global standards so every new system is
covered immediately upon approval.

**Combine Auto-Scan and Auto-Report for full automation**

For audit-ready environments configure both schedules. Run scans frequently
to keep compliance data current, and save reports on a cadence that matches
your audit requirements — weekly, monthly, or quarterly.
