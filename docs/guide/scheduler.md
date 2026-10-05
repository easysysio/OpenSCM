# Task Scheduler

The OpenSCM scheduler allows you to automate compliance scans on a recurring
schedule. Instead of manually running policies, the scheduler triggers scans
automatically and notifies you of the results.

---

## How It Works

The scheduler runs as part of the OpenSCM server process. It checks for due
policies at regular intervals and queues compliance tests for all agents in
the assigned system groups.

``` mermaid
sequenceDiagram
    participant SC as Scheduler
    participant DB as Database
    participant A as Agent

    loop Every minute
        SC->>DB: Check for due policies
        DB-->>SC: Return due schedules
        SC->>DB: Queue tests for all agents in policy groups
        SC->>DB: Update next_run timestamp
    end

    A->>DB: Heartbeat — picks up queued tests
    A-->>DB: Returns PASS / FAIL / NA results
    SC->>DB: Send notification on completion
```

Agents pick up queued tests on their next heartbeat and return results
automatically. The scheduler sends a notification when each scheduled
run completes — or if it fails.

---

## Configuring a Schedule

Schedules are configured per policy. You can set a schedule when creating
a new policy or by editing an existing one.

### Enable Auto-Scan

On the policy create or edit page, scroll to **Automation & Scheduling**
and toggle **Enable Auto-Scan**.

### Frequency Options

| Option | Description |
| :--- | :--- |
| **Daily** | Runs once every 24 hours from the first execution time |
| **Weekly** | Runs once every 7 days |
| **Monthly** | Runs once every 30 days |
| **Custom (Cron)** | A cron expression, for runs tied to the clock or the calendar |

### First Execution Time

Set the **First Execution Time** to control when the first run happens.
Subsequent runs are calculated from this time based on the selected frequency,
so a daily schedule first run at 02:00 keeps running at 02:00.

The time you pick is **your own local time** — the form names the time zone it
is using — and the edit page shows the next run in your local time as well.
The server stores and compares schedule times in UTC.

If no first execution time is set the schedule starts immediately. On the edit
page, leaving the time as it is keeps the schedule's current next run.

The daily, weekly and monthly intervals are fixed lengths of time, so they do
not follow daylight-saving changes: after the clocks change, a daily run
appears one hour earlier or later on your clock. Use a cron schedule in UTC if
the run must stay at a fixed UTC time.

### After Downtime

If the server was stopped when a run was due, that schedule runs **once** when
the server is back and then continues from its next future time. Missed runs
are not replayed one after another.

### Custom Cron Expressions

Select **Custom (Cron)** to enter a cron expression. The expression decides
every run, so there is no first execution time to pick; after saving, the edit
page shows when the next run will be.

!!! warning "Cron expressions are in UTC"
    A cron expression is evaluated in **UTC**, not in your local time. In a
    UTC+3 zone, `0 2 * * *` runs at 05:00 on your clock. The form shows the
    current UTC time next to the field to make the difference easy to work out.

```
┌─────────── minute (0–59)
│ ┌───────── hour (0–23)
│ │ ┌─────── day of month (1–31)
│ │ │ ┌───── month (1–12)
│ │ │ │ ┌─── day of week (0–6, Sunday=0)
│ │ │ │ │
* * * * *
```

**Common examples:**

| Expression | Meaning |
| :--- | :--- |
| `0 2 * * *` | Every day at 2:00 AM |
| `0 0 * * 1` | Every Monday at midnight |
| `0 6 1 * *` | First day of every month at 6:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 9 * * 1-5` | Weekdays at 9:00 AM |
| `*/15 * * * *` | Every 15 minutes |
| `30 1 1,15 * *` | The 1st and 15th of each month at 1:30 AM |

All times above are UTC.

**Syntax.** Each of the five fields accepts `*`, a number, a range (`1-5`), a
list (`1,15`), and a step (`*/6`, `0-30/10`). Months and weekdays can be
written as three-letter names (`jan`, `mon`), and Sunday is `0` or `7`. When
both the day of month and the day of week are restricted, the schedule runs
when **either** matches — the usual cron rule — so `0 0 1 * 1` is the 1st of
the month and every Monday.

An expression is checked when you save. One that is malformed, or that can
never occur (such as `0 0 31 2 *`, the 31st of February), is refused with a
message saying what is wrong.

!!! note "Changed in 0.9.5"
    Before 0.9.5 the cron expression was saved but not used: every Custom
    schedule ran once a day. Existing Custom schedules start following their
    expression after the upgrade. Any that hold an expression that is not valid
    keep running daily, and each run writes an error to the server log, until
    the expression is corrected.

    Also before 0.9.5, the time picked in the form was stored as if it were
    UTC, so schedules ran earlier or later than intended by your UTC offset.
    Existing schedules keep running at the same moments as before; the edit
    page now shows that moment correctly in your local time.

---

## Notifications

The scheduler sends a dashboard notification when a scheduled run completes:

- **Success** — policy ran and results were collected
- **Failure** — policy run encountered an error

Notifications appear in the bell icon in the top navigation bar and are
visible to all administrators of the tenant.

---

## Disabling a Schedule

To disable automatic scanning without deleting the schedule:

1. Navigate to **Policies** and click **Edit** on the policy
2. Scroll to **Automation & Scheduling**
3. Toggle **Enable Auto-Scan** off
4. Click **Update Policy**

The schedule configuration is preserved — re-enabling it restores the
previous frequency and timing settings.

---

## Best Practices

**Stagger your schedules**

If you have multiple policies avoid scheduling them all at the same time.
Staggering scans reduces peak load on the server and agents.

```
Policy: OS-Baseline-Linux     →  Daily at 02:00
Policy: OS-Baseline-Windows   →  Daily at 02:30
Policy: Web-Hardening         →  Daily at 03:00
Policy: PCI-DSS-Controls      →  Weekly on Monday at 04:00
```

**Match frequency to risk level**

Not every policy needs to run daily. Match the scan frequency to the
sensitivity of the systems and the rate of change in your environment:

| Environment | Recommended Frequency |
| :--- | :--- |
| Production / Critical systems | Daily |
| Staging / Development | Weekly |
| Low-risk internal systems | Monthly |
| Compliance audit preparation | On-demand |

**Save reports after scheduled scans**

The scheduler runs policy scans automatically but does not save reports.
After a scheduled scan completes, review the live results and click
**Save to History** to archive the compliance snapshot.

!!! tip
    Build a routine of reviewing and saving reports after your scheduled
    scans — weekly for production systems, monthly for everything else.
    This creates a consistent audit trail over time.
