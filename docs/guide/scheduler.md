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
| **Custom (Cron)** | Full cron expression for precise control |

### First Execution Time

Set the **First Execution Time** to control when the first run happens.
Subsequent runs are calculated from this time based on the selected frequency.

If no first execution time is set the schedule starts immediately.

### Custom Cron Expressions

Select **Custom (Cron)** to enter a cron expression for full control:

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
