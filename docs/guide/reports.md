# Reports & Audits

The **Reports** module is the historical record of your compliance efforts. A report
is a **point-in-time snapshot** of results — immutable evidence that can be used for
internal audits, SOC 2 verification, or regulatory compliance.

OpenSCM supports two types of saved reports:

| Type | Scope | Source |
| :--- | :--- | :--- |
| **Policy Report** | All systems evaluated against one policy | Live policy report |
| **System Report** | All policies applied to one system | Live system report |

---

## Why Reports Matter

Unlike the live views which show the current state, a saved report captures the exact
status of every test at the moment it was generated. This allows you to:

- **Maintain Evidence** — prove your infrastructure met security standards on a specific date
- **Track Progress** — compare snapshots over time to measure security posture improvement
- **Audit Readiness** — provide auditors with formal documentation without giving them
  access to your production environment

---

## Policy Reports

A policy report captures the compliance status of **every system** evaluated against
a single policy at a point in time.

### Creating a Policy Report

``` mermaid
graph TD
    A[Run Policy] -->|Agent returns results| B[Live Policy Report]
    B -->|Click Save Report| C{Policy Reports Archive}
    C --> D[View in Browser]
    C --> E[Download PDF]
    C --> F[Delete Record]
```

1. Open a policy and view the **Live Report**
2. Click **Save Report** to archive the current results
3. The snapshot is stored with a timestamp and the name of the user who saved it

!!! info "Compliance Trend (added in 0.7.2)"
    The **live** policy and system report pages include a **Compliance Trend**
    chart — the entity's own compliance history, so when a score moves you can
    see *since when*. Snapshots are recorded every hour for each scanned system
    and policy, and both score calculations are stored per snapshot — so
    switching the Per-test / Per-system / Per-policy toggle in
    **Settings → Compliance** re-renders the whole line in the chosen mode
    rather than showing a step. Hover a point for its pass/fail tallies.

    **Ranges (0.7.5).** The card header carries the same
    **Hourly / Daily / Weekly / Monthly / Yearly** selector as the dashboard
    trend — Hourly shows the last 24 hours, Daily the last 30 days, Weekly and
    Monthly the last 12, Yearly the last 10; coarser buckets average their
    hourly snapshots. Use the **−** button to collapse the card. The chart
    appears as soon as the first snapshot exists (up to an hour after
    upgrading), and its history length is governed by **System/Policy Trend
    Retention** (default 90 days, `0` = forever).

### Policy Report Contents

Each saved policy report captures:

| Field | Description |
| :--- | :--- |
| **Policy Name & Version** | The exact policy that was evaluated |
| **Date & Time** | When the report was saved |
| **Saved By** | The user who saved the report |
| **Per-System Results** | PASS / FAIL / NA / EXCLUDED for every test on every system |
| **Compliance Verdict** | COMPLIANT, NON-COMPLIANT, or NOT APPLICABLE per system |
| **Test Metadata** | Name and description of every test included |
| **Result Counts** | Per-system Passed / Failed / NA / Excluded tallies in the card header |
| **Aggregate Totals** | Policy-wide Pass / Fail / NA / Excl counts plus a percent-compliant badge in the top card |

### Why a Test Failed

!!! info "Added in 0.6.4"
    Stop guessing which part of a multi-condition test went wrong.

On a live policy or system report, any **FAILED** or **NA** row shows a small
**"why?"** link next to its status badge. Click it to expand a per-condition
breakdown:

| Check | Expected | Result | Note |
| :--- | :--- | :--- | :--- |
| `FILE /etc/ssh/sshd_config` | `contains 'PermitRootLogin no'` | **FAIL** | expected to contains 'PermitRootLogin no' — not satisfied |
| `FILE /etc/ssh/sshd_config` | `exists` | PASS | matched |

Each condition shows the element + parameter, the operator and expected value,
its individual PASS / FAIL / NA, and a short note. The failing condition(s) are
highlighted, so you can see exactly which part of the test the system didn't
meet. **NA** rows explain themselves too — they list the **applicability**
condition that wasn't met (i.e. *why the test didn't run here*).

!!! note "Privacy: match-only"
    The breakdown shows only the test definition (element, operator, expected
    value) and a pass/fail/note — **never the actual file contents or command
    output** observed on the host. Nothing sensitive leaves the endpoint.

!!! warning "Requirements"
    Evidence is captured by the **agent**, so it needs:

    - Agents on **0.6.4** or later
    - A **fresh scan** after upgrading — results already in the database were
      recorded before evidence capture and show no "why?" link until the test
      runs again

### Excluding a Finding

Sometimes a failing test doesn't really apply to a given system — a deprecated
control, an approved deviation, a known-false-positive. To prevent it from
dragging down the compliance score:

1. Open the live policy report (`Policies → View Live Report`) or the live system
   report (`Systems → Compliance Report`)
2. **Right-click** the row of the test you want to exclude
3. Choose **Exclude** from the context menu that appears
4. The row now shows a grey **EXCLUDED** badge instead of PASS/FAIL/NA, and the
   per-system + per-policy compliance score is recalculated as if the finding
   were NA — removed from both numerator and denominator
5. To restore the finding, right-click the same row and choose **Unexclude**

!!! note "Permanence"
    Exclusions persist across compliance scans — re-running the policy will never
    clear them. They're only removed automatically when the underlying system or
    test is deleted. Saved snapshots freeze the exclusion state at save time;
    archived reports show the badges but cannot be modified.

!!! tip "Role requirements"
    Excluding and un-excluding findings requires the **Editor** role or higher.

---

## System Reports

A system report captures the compliance status of **every policy** applied to a single
system at a point in time — a full picture of that system's security posture.

### Creating a System Report

``` mermaid
graph TD
    A[Systems List] -->|Click clipboard icon| B[Live System Report]
    B -->|Click Save Report| C{System Reports Archive}
    C --> D[View in Browser]
    C --> E[Download PDF]
    C --> F[Delete Record]
```

1. Go to **Systems** and click the clipboard icon on any active system, or navigate
   directly to **Systems → Live Report**
2. The live report shows every policy the system belongs to, with each test result
   grouped per policy
3. Click **Save Report** to archive the current results

### System Report Contents

Each saved system report captures:

| Field | Description |
| :--- | :--- |
| **System Name, OS, IP** | System identity at the time of the snapshot |
| **Last Seen** | Agent last check-in at time of snapshot |
| **Overall Compliance Score** | Aggregate score across all policies |
| **Per-Policy Results** | PASS / FAIL / NA / EXCLUDED for every test, grouped by policy |
| **Policy Verdict** | COMPLIANT / NON-COMPLIANT / NOT APPLICABLE per policy |
| **Result Counts** | Per-policy Passed / Failed / NA / Excluded tallies in the card header |
| **Date & Time** | When the report was saved |
| **Saved By** | The user who saved the report |

### Policy Coverage

The system report header includes a collapsible **View Policy Coverage** section listing
every policy the system belongs to, along with each policy's description. This gives
auditors immediate context about the scope of controls evaluated.

### Re-running One Policy on One System

!!! info "Added in 0.7.7"

Each policy card on the **live** system report carries a **Run** button. It queues just
that policy's tests for just that host — so after fixing a finding you can re-check the
one machine instead of re-scanning the whole fleet from the Policies page.

Scans are **queued, not pushed**: the tests are handed to the agent on its next
heartbeat (default 300 s), so the report reflects them a little later rather than
immediately. Re-clicking before the agent checks in is harmless — the queue is
deduplicated.

Requires the **Runner** role; the action is written to the audit log as
`policy.run_on_system`.

### Filtering by Status

!!! info "Added in 0.7.8"

The **Passed / Failed / NA / Excluded** counts in each card header are clickable
filters. Click **Failed** to collapse the card down to only its failing tests, click
another status to switch, or click the active one again to clear.

Filtering is scoped to a single card — on a system report each *policy* filters
independently, on a policy report each *system* does — so you can drill into one
policy's failures while the rest stay as they are. It works on both the live reports
and the saved snapshots under **Reports**, and it's purely a display filter: nothing is
changed or recalculated, and the counts always match what the filter shows.

---

## Viewing Saved Reports

Navigate to **Reports** to see the full archive. The page has two tabs:

- **Policy Reports** — snapshots saved from the live policy report
- **System Reports** — snapshots saved from the live system report

From either list you can:

- **View** — open the full snapshot in the browser
- **Download PDF** — export a formatted, printable audit report
- **View Live Report** — jump to the current live report for the same policy or system.
  If the policy or system has since been deleted, this button is replaced with a
  greyed-out **Deleted** badge.
- **Delete** — permanently remove the snapshot

!!! danger "Deletion is permanent"
    Deleted reports cannot be recovered. Export a PDF copy before deleting any record
    that may be needed for future audits.

### Bulk Delete

Select multiple reports using the row checkboxes, then click **Delete** in the bulk
toolbar to remove them all at once.

!!! note "Role requirements"
    Saving reports requires the **Runner** role or higher.  
    Deleting reports requires the **Editor** role or higher.

---

## PDF Export

PDF reports are available from both the live report pages and the saved snapshot pages.

### Policy Report PDF

- Policy name, version, date, and author
- Per-system compliance verdict (COMPLIANT / NON-COMPLIANT)
- Full breakdown of every test result per system
- Compliance summary with pass/fail counts
- Disclaimer page

### System Report PDF

- System name, OS, architecture, IP, last seen, and compliance score
- Per-policy sections with verdict (COMPLIANT / NON-COMPLIANT / NOT APPLICABLE)
- Policy description under each section heading
- Full breakdown of every test result per policy
- Disclaimer page

PDF reports are suitable for submission to external auditors and can be stored in your
document management system as formal compliance evidence.

---

## Best Practices

**Save reports at regular intervals**

Even if you use the scheduler for automated scans, establish a routine of saving
reports — monthly at minimum, or after any significant infrastructure change.

**Save before and after remediation**

When you identify and fix a compliance failure, save a report before the fix (to
document the gap) and after the fix (to prove remediation). This creates a clean
audit trail.

**Use both report types**

Policy reports answer *"did all my systems pass this control framework?"* — useful
for compliance owners. System reports answer *"is this specific host fully compliant?"*
— useful for system owners and incident responders.

**Use policy versioning**

When you update a policy, increment the version number before the next scan. This
ensures saved reports clearly identify which set of controls was in effect at the
time of each snapshot.
