# Alerts

OpenSCM records a compliance score every time a policy runs, so the server
already knows the moment a fleet falls from 94% to 61%. An **alert** turns that
into something that reaches you, instead of waiting for someone to open a page.

---

## Creating an alert

**Alerts → New alert.** A rule has three parts:

| | |
|---|---|
| **Watches** | one policy, or all of them |
| **When** | the score drops by, rises by, falls below, or rises above a value |
| **Then** | notify in OpenSCM, email, webhook, or syslog |

!!! warning "Points and percentages are not the same thing"
    **Drops by 10** means a fall of 10 points — from 94% to 84%.
    **Falls below 10** means the score itself going under 10%.

    The unit next to the threshold box changes with the trigger to make this
    visible. Choosing the wrong one produces a rule that almost never fires, or
    one that fires immediately.

### Which compliance score it watches

OpenSCM keeps two compliance axes — **test compliance** (how many checks
passed) and **system compliance** (how many systems are fully compliant). A
rule watches whichever you pick, and keeps watching it. Changing which axis the
interface displays later does not silently change what your alerts mean.

---

## When an alert fires

Alerts are evaluated **whenever a score actually changes** — a scheduled run, a
manual run, a group edit, an exclusion — not on a timer. A dip that recovers
within the hour is still caught.

### It fires on the crossing, not on every run

This is the behaviour worth understanding, because it is what stops alerting
becoming noise. A rule set to **rise above 80%** behaves like this:

| Scan | Score | Alert? |
|---|---|---|
| 1 | 75% → 85% | **Yes** — crossed the threshold |
| 2 | 85% → 85% | No — already above |
| 3 | 85% → 92% | No — still above |
| 4 | 92% → 70% | No — fell back, and this rule watches for rises |
| 5 | 70% → 85% | **Yes** — crossed again |

A rule alerts when the condition *becomes* true, then stays quiet for as long as
it remains true, and re-arms once the score returns to the other side.

The alternative — alerting whenever the score is above 80% — would send a
message on every single scan for as long as the policy stayed healthy. That is
what teaches people to mute alerts, and a muted alert misses the real incident
too.

### Cooldown

A separate guard: **cooldown** sets the minimum gap between alerts from the same
rule for the same policy, 60 minutes by default. A score oscillating across the
threshold cannot page you repeatedly.

### Never-scanned policies

A policy that has not been scanned has no score — not a score of zero. Such a
policy is never reported as a catastrophic drop, and a policy being scanned for
the first time does not alert simply for existing.

### After a restart

The first compliance calculation after the server starts records where
everything stands **without sending anything**. Returning from an outage does
not announce the outage, and the next genuine change is still measured
correctly.

---

## Delivery

=== "Notify in OpenSCM"

    Goes to the bell icon for every administrator. No configuration, nothing to
    break — which is why it is also used to tell you when another transport has
    failed permanently.

=== "Email"

    Comma-separate multiple recipients. Requires SMTP to be configured under
    **Settings**.

=== "Webhook"

    A `POST` with a JSON body, so it reaches Slack, Teams, PagerDuty and any
    internal automation without a bespoke integration. An optional value is sent
    as the `Authorization` header.

    ```json
    {
      "version": 1,
      "event": "compliance.alert",
      "tenant": "acme",
      "alert":  { "id": 7, "name": "Production CIS drop" },
      "policy": { "id": 3, "name": "CIS Ubuntu 22.04" },
      "score":  { "previous": 94.2, "current": 61.0, "delta": -33.2 }
    }
    ```

    The payload is versioned so that anything parsing it has a contract to rely
    on.

=== "Syslog"

    `host` or `host:port` — RFC 5424 over UDP, port 514 by default. UDP is
    fire-and-forget: a successful send is all the protocol can confirm, so a
    message shown as sent means it left this server, not that it arrived.

### Test it before you rely on it

Each rule has a **Test** button that sends a real message through the real
transport. A mistyped webhook URL or a firewalled syslog port is otherwise
invisible until a genuine incident fails to reach anyone.

### When delivery fails

Failed deliveries retry after 1, 5 and 15 minutes. If a transport still cannot
be reached, the alert is marked failed and an administrator is notified inside
OpenSCM — a silently broken webhook is worse than no webhook.

**Alerts → Delivery history** shows what was sent, what failed, and the reason.

---

## Permissions

| Action | Role |
|---|---|
| View alerts and delivery history | Viewer |
| Create, edit, enable, delete, test | Admin |

Managing alerts is an administrative action: a rule holds a recipient list and
a webhook secret, and it makes the server send traffic to an address of your
choosing.

!!! note "Webhook destinations in the hosted service"
    In OpenSCM Cloud, webhook targets must be `https` and must resolve to a
    public address. This is checked when the rule is saved and again each time
    it is delivered. Self-hosted installations may post anywhere on their own
    network.

---

## Retention

Delivery history is kept for **90 days** by default, configurable per
organisation with `alert_history_retention_days` (0 keeps it forever).
