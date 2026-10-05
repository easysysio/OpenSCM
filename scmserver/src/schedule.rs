// =============================================================================
// schedule.rs — when a policy schedule runs next
//
// Pure calculation, no database and no clock of its own: cron expressions,
// the fixed intervals, and converting the form's local time to UTC. The
// scheduler loop (scheduler.rs) and the policy forms (policies.rs) call in
// here. Everything is in UTC; times are "YYYY-MM-DDTHH:MM" strings, the shape
// policy_schedules.next_run has always had.
// =============================================================================

use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Timelike};

/// The storage format of policy_schedules.next_run / last_run (UTC).
pub const FMT: &str = "%Y-%m-%dT%H:%M";

// ─────────────────────────────────────────────────────────────────────────────
// Helper: parse_time
// Reads a stored or submitted time. A datetime-local input may add seconds.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_time(s: &str) -> Option<NaiveDateTime> {
    let s = s.trim();
    NaiveDateTime::parse_from_str(s, FMT)
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f"))
        .ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: local_to_utc
// Converts the value of a <input type="datetime-local"> to UTC.
//
// The browser sends that field as wall-clock time with no zone. The server
// stored it as it came and compared it with UTC, so every schedule ran late or
// early by the viewer's UTC offset (three hours late in UTC+3). The form now
// also sends JavaScript's getTimezoneOffset() FOR THE CHOSEN INSTANT — minutes
// to ADD to local time to reach UTC, daylight saving included — and this
// applies it. Without an offset (no JavaScript) the value is taken as UTC,
// which is what the server did before.
// ─────────────────────────────────────────────────────────────────────────────
pub fn local_to_utc(local: &str, offset_minutes: Option<i64>) -> Option<String> {
    let t = parse_time(local)?;
    // Real offsets span −14h … +12h; anything else is a broken client.
    let off = offset_minutes.filter(|m| (-14 * 60..=14 * 60).contains(m)).unwrap_or(0);
    Some((t + Duration::minutes(off)).format(FMT).to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// CronExpr — a standard five-field cron expression
//
//     minute  hour  day-of-month  month  day-of-week
//     0–59    0–23  1–31          1–12   0–6 (Sunday = 0; 7 also means Sunday)
//
// Each field is a comma-separated list of: `*`, a number, a range `a-b`, and
// any of those with a step: `*/n`, `a-b/n`, `a/n` (from a to the maximum).
// Months and weekdays may be written as three-letter names (jan, mon, …).
//
// When BOTH day fields are restricted the day matches if EITHER does — the
// long-standing cron rule, so `0 0 1 * 1` is "the 1st, and every Monday".
//
// Written here rather than taken from a crate: the available parsers bring a
// dozen transitive dependencies for what is a hundred lines, and this product
// ships to targets where every dependency has to cross-compile.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
pub struct CronExpr {
    minutes: u64, // bit n = minute n
    hours:   u64,
    dom:     u64, // bit n = day n (1–31)
    months:  u64, // bit n = month n (1–12)
    dow:     u64, // bit n = weekday n (0 = Sunday)
    dom_any: bool,
    dow_any: bool,
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const DAYS:   [&str; 7]  = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

// Parses one number, or a name where the field has names.
fn field_value(s: &str, names: &[&str], first_name_value: u32) -> Option<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Some(n);
    }
    let l = s.to_ascii_lowercase();
    names.iter().position(|n| *n == l).map(|i| i as u32 + first_name_value)
}

// Parses one field into a bit set.
fn parse_field(field: &str, what: &str, min: u32, max: u32, names: &[&str]) -> Result<u64, String> {
    let mut bits = 0u64;
    for item in field.split(',') {
        if item.is_empty() {
            return Err(format!("{what}: empty entry in '{field}'"));
        }
        let (range, step) = match item.split_once('/') {
            Some((r, s)) => {
                let step: u32 = s.parse().map_err(|_| format!("{what}: '{s}' is not a step"))?;
                if step == 0 {
                    return Err(format!("{what}: a step cannot be 0"));
                }
                (r, Some(step))
            }
            None => (item, None),
        };
        let value = |s: &str| -> Result<u32, String> {
            field_value(s, names, min)
                .ok_or_else(|| format!("{what}: '{s}' is not a value"))
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (value(a)?, value(b)?)
        } else {
            let a = value(range)?;
            // "a/n" runs from a to the maximum; a bare "a" is just a.
            (a, if step.is_some() { max } else { a })
        };
        // Sunday may be written 0 or 7; weekday values are taken modulo 7.
        let is_dow = what == "day of week";
        let upper = if is_dow { 7 } else { max };
        if lo < min || hi > upper || lo > hi {
            return Err(format!("{what}: '{range}' is outside {min}-{max}"));
        }
        let mut v = lo;
        while v <= hi {
            bits |= 1 << if is_dow { v % 7 } else { v };
            v += step.unwrap_or(1);
        }
    }
    Ok(bits)
}

impl CronExpr {
    // ─────────────────────────────────────────────────────────────────────────
    // parse
    // ─────────────────────────────────────────────────────────────────────────
    pub fn parse(expr: &str) -> Result<CronExpr, String> {
        let f: Vec<&str> = expr.split_whitespace().collect();
        if f.len() != 5 {
            return Err(format!(
                "a cron expression has 5 fields (minute hour day-of-month month day-of-week); this has {}",
                f.len()
            ));
        }
        Ok(CronExpr {
            minutes: parse_field(f[0], "minute", 0, 59, &[])?,
            hours:   parse_field(f[1], "hour", 0, 23, &[])?,
            dom:     parse_field(f[2], "day of month", 1, 31, &[])?,
            months:  parse_field(f[3], "month", 1, 12, &MONTHS)?,
            dow:     parse_field(f[4], "day of week", 0, 6, &DAYS)?,
            // As in cron itself, a field that starts with '*' ("*", "*/2") is
            // unrestricted for the either-day rule.
            dom_any: f[2].starts_with('*'),
            dow_any: f[4].starts_with('*'),
        })
    }

    fn day_matches(&self, d: NaiveDate) -> bool {
        if self.months & (1 << d.month()) == 0 {
            return false;
        }
        let dom = self.dom & (1 << d.day()) != 0;
        let dow = self.dow & (1 << d.weekday().num_days_from_sunday()) != 0;
        match (self.dom_any, self.dow_any) {
            (true, true)   => true,
            (true, false)  => dow,
            (false, true)  => dom,
            (false, false) => dom || dow,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // next_after
    // The first matching minute strictly after `after`. None when the
    // expression can never match (the 31st of February).
    // ─────────────────────────────────────────────────────────────────────────
    pub fn next_after(&self, after: NaiveDateTime) -> Option<NaiveDateTime> {
        let start = after.with_second(0)?.with_nanosecond(0)? + Duration::minutes(1);
        let mut day = start.date();
        // 29 February can be eight years away (2096 → 2104).
        for i in 0..(366 * 9) {
            if self.day_matches(day) {
                let (from_h, from_m) = if i == 0 { (start.hour(), start.minute()) } else { (0, 0) };
                for h in from_h..24 {
                    if self.hours & (1 << h) == 0 {
                        continue;
                    }
                    let first_m = if i == 0 && h == from_h { from_m } else { 0 };
                    for m in first_m..60 {
                        if self.minutes & (1 << m) != 0 {
                            return day.and_hms_opt(h, m, 0);
                        }
                    }
                }
            }
            day = day.succ_opt()?;
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: validate_cron
// Ok, or a message fit to show beside the form field.
// ─────────────────────────────────────────────────────────────────────────────
pub fn validate_cron(expr: &str, now: NaiveDateTime) -> Result<(), String> {
    let c = CronExpr::parse(expr)?;
    c.next_after(now)
        .map(|_| ())
        .ok_or_else(|| "this expression never occurs (check the day and month)".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: next_cron_run
// The next run of a cron expression after `now`, formatted for storage.
// ─────────────────────────────────────────────────────────────────────────────
pub fn next_cron_run(expr: &str, now: NaiveDateTime) -> Result<String, String> {
    CronExpr::parse(expr)?
        .next_after(now)
        .map(|t| t.format(FMT).to_string())
        .ok_or_else(|| "this expression never occurs".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: next_run
// When a schedule that has just run should run next.
//
//   • "custom" follows its cron expression: the next match after `now`. Until
//     0.9.5 the expression was stored and never read, so every Custom schedule
//     simply ran daily. An expression that does not parse — none were
//     validated before 0.9.5 — falls back to daily and reports the error, so
//     an upgrade cannot stop a schedule that was running.
//   • The fixed intervals step forward from the PLANNED time, not from `now`,
//     so a daily 02:00 run stays at 02:00 however late a tick fires. They step
//     until the result is in the future: after an outage a schedule runs once
//     and resumes, instead of replaying each missed run a minute apart.
//
// Returns (next_run, error). The error, when present, should be logged.
// ─────────────────────────────────────────────────────────────────────────────
pub fn next_run(
    frequency: &str,
    cron_expression: Option<&str>,
    planned: &str,
    now: NaiveDateTime,
) -> (String, Option<String>) {
    let mut problem = None;
    if frequency == "custom" {
        match cron_expression.map(str::trim).filter(|e| !e.is_empty()) {
            Some(expr) => match next_cron_run(expr, now) {
                Ok(next) => return (next, None),
                Err(e) => problem = Some(format!("cron expression '{expr}' is not usable ({e}); running daily instead")),
            },
            None => problem = Some("custom schedule has no cron expression; running daily instead".to_string()),
        }
    }

    let step = match frequency {
        "weekly"   => Duration::weeks(1),
        "biweekly" => Duration::days(14),
        "monthly"  => Duration::days(30),
        _          => Duration::days(1),
    };
    let mut next = parse_time(planned).unwrap_or(now) + step;
    while next <= now {
        next += step;
    }
    (next.format(FMT).to_string(), problem)
}

// ─────────────────────────────────────────────────────────────────────────────
// Submitted — one schedule section of the policy form, ready to store
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
pub struct Submitted {
    pub enabled:   bool,
    pub frequency: String,
    pub cron:      Option<String>,
    /// Some(UTC time) when the form determines the next run — a time was
    /// picked, or the schedule is a cron expression. None means "the form
    /// says nothing": a new schedule starts now, an existing one keeps the
    /// time it has.
    pub next_run:  Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: resolve_submission
// Validates one schedule section and works out its next run.
//
//   • Custom: the next run comes from the expression, so the time picker is
//     ignored. An ENABLED custom schedule must have a usable expression; this
//     is the first place expressions are checked at all. A disabled one is
//     stored as typed, so switching a schedule off never fails on its content.
//   • Otherwise the picked time, if any, is converted from the browser's local
//     time to UTC (see local_to_utc).
//
// Err is a message for the user, prefixed with `label` ("Auto-scan schedule").
// ─────────────────────────────────────────────────────────────────────────────
pub fn resolve_submission(
    label: &str,
    enabled: bool,
    frequency: &str,
    cron: Option<&str>,
    picked_local: Option<&str>,
    tz_offset_minutes: Option<i64>,
    now: NaiveDateTime,
) -> Result<Submitted, String> {
    let frequency = match frequency.trim() {
        f @ ("daily" | "weekly" | "biweekly" | "monthly" | "custom") => f.to_string(),
        _ => "daily".to_string(),
    };
    let cron = cron.map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);

    let next_run = if frequency == "custom" {
        match (&cron, enabled) {
            (Some(expr), _) => match next_cron_run(expr, now) {
                Ok(next) => Some(next),
                Err(e) if enabled => return Err(format!("{label}: the cron expression is not valid — {e}")),
                Err(_) => None,
            },
            (None, true) => return Err(format!("{label}: Custom (Cron) needs a cron expression, such as 0 2 * * *")),
            (None, false) => None,
        }
    } else {
        match picked_local.map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => Some(
                local_to_utc(p, tz_offset_minutes)
                    .ok_or_else(|| format!("{label}: '{p}' is not a valid date and time"))?,
            ),
            None => None,
        }
    };

    Ok(Submitted { enabled, frequency, cron, next_run })
}


#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> NaiveDateTime {
        parse_time(s).unwrap_or_else(|| panic!("bad test time {s}"))
    }
    fn after(expr: &str, from: &str) -> String {
        CronExpr::parse(expr).unwrap().next_after(t(from)).unwrap().format(FMT).to_string()
    }

    // The five examples in docs/guide/scheduler.md. 2026-10-05 is a Monday.
    #[test]
    fn the_documented_examples() {
        assert_eq!(after("0 2 * * *", "2026-10-05T01:30"), "2026-10-05T02:00", "every day at 02:00");
        assert_eq!(after("0 2 * * *", "2026-10-05T02:00"), "2026-10-06T02:00", "strictly after");
        assert_eq!(after("0 0 * * 1", "2026-10-05T00:00"), "2026-10-12T00:00", "every Monday at midnight");
        assert_eq!(after("0 0 * * 1", "2026-10-07T09:00"), "2026-10-12T00:00");
        assert_eq!(after("0 6 1 * *", "2026-10-05T00:00"), "2026-11-01T06:00", "the 1st at 06:00");
        assert_eq!(after("0 */6 * * *", "2026-10-05T07:15"), "2026-10-05T12:00", "every 6 hours");
        assert_eq!(after("0 */6 * * *", "2026-10-05T18:00"), "2026-10-06T00:00");
        assert_eq!(after("0 9 * * 1-5", "2026-10-09T09:00"), "2026-10-12T09:00", "weekdays: Fri → Mon");
        assert_eq!(after("0 9 * * 1-5", "2026-10-06T08:00"), "2026-10-06T09:00");
    }

    #[test]
    fn steps_lists_and_ranges() {
        assert_eq!(after("*/5 * * * *", "2026-10-05T15:21"), "2026-10-05T15:25");
        assert_eq!(after("*/5 * * * *", "2026-10-05T15:25"), "2026-10-05T15:30");
        assert_eq!(after("*/5 * * * *", "2026-10-05T23:58"), "2026-10-06T00:00");
        assert_eq!(after("15,45 * * * *", "2026-10-05T10:20"), "2026-10-05T10:45");
        assert_eq!(after("0 8-10 * * *", "2026-10-05T10:30"), "2026-10-06T08:00");
        assert_eq!(after("10-50/20 * * * *", "2026-10-05T10:31"), "2026-10-05T10:50");
        assert_eq!(after("5/20 * * * *", "2026-10-05T10:26"), "2026-10-05T10:45", "a/n runs to the maximum");
        assert_eq!(after("* * * * *", "2026-10-05T10:26"), "2026-10-05T10:27");
        assert_eq!(after("* * * * *", "2026-12-31T23:59"), "2027-01-01T00:00");
    }

    #[test]
    fn names_and_sunday_as_seven() {
        assert_eq!(after("0 0 * jan *", "2026-10-05T00:00"), "2027-01-01T00:00");
        assert_eq!(after("0 0 * * SUN", "2026-10-05T00:00"), "2026-10-11T00:00");
        assert_eq!(after("0 0 * * 7", "2026-10-05T00:00"), "2026-10-11T00:00");
        assert_eq!(after("0 0 * * 0", "2026-10-05T00:00"), "2026-10-11T00:00");
        assert_eq!(after("0 0 * * mon-fri", "2026-10-10T00:00"), "2026-10-12T00:00");
        assert_eq!(after("0 0 * * 6-7", "2026-10-05T00:00"), "2026-10-10T00:00", "Sat–Sun");
        assert_eq!(after("0 0 * * 6-7", "2026-10-10T00:00"), "2026-10-11T00:00");
    }

    // Both day fields restricted → either matches (standard cron).
    #[test]
    fn day_of_month_or_day_of_week() {
        // The 15th (a Thursday) or any Monday, from Tue 6 Oct.
        assert_eq!(after("0 0 15 * 1", "2026-10-06T00:00"), "2026-10-12T00:00");
        assert_eq!(after("0 0 15 * 1", "2026-10-12T00:00"), "2026-10-15T00:00");
        // Only one restricted → that one alone.
        assert_eq!(after("0 0 15 * *", "2026-10-06T00:00"), "2026-10-15T00:00");
        assert_eq!(after("0 0 */2 * 1", "2026-10-06T00:00"), "2026-10-12T00:00", "*/2 counts as unrestricted");
    }

    #[test]
    fn rare_and_impossible_dates() {
        assert_eq!(after("0 0 29 2 *", "2026-10-05T00:00"), "2028-02-29T00:00", "next leap day");
        assert_eq!(after("0 0 31 * *", "2026-11-01T00:00"), "2026-12-31T00:00", "skips 30-day months");
        assert!(CronExpr::parse("0 0 31 2 *").unwrap().next_after(t("2026-10-05T00:00")).is_none());
        assert!(validate_cron("0 0 31 2 *", t("2026-10-05T00:00")).is_err());
        assert!(validate_cron("0 0 30 feb *", t("2026-10-05T00:00")).is_err());
    }

    #[test]
    fn malformed_expressions_are_rejected_with_a_reason() {
        for bad in ["", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *",
                    "* * * 13 *", "* * * 0 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *",
                    "1,,2 * * * *", "* * * * mon-", "1/x * * * *", "-5 * * * *", "@daily"] {
            assert!(CronExpr::parse(bad).is_err(), "{bad:?} should be rejected");
        }
        let msg = CronExpr::parse("0 25 * * *").unwrap_err();
        assert!(msg.contains("hour"), "the message should name the field: {msg}");
        assert!(validate_cron("0 2 * * *", t("2026-10-05T00:00")).is_ok());
        assert!(validate_cron("  0   2  *  *  *  ", t("2026-10-05T00:00")).is_ok(), "extra spaces are fine");
    }

    // ── next_run ────────────────────────────────────────────────────────────
    #[test]
    fn custom_schedules_follow_their_expression() {
        let now = t("2026-10-05T15:21");
        // The reviewed bug: "every 5 minutes" was pushed a whole day out.
        assert_eq!(next_run("custom", Some("*/5 * * * *"), "2026-10-05T15:20", now), ("2026-10-05T15:25".into(), None));
        assert_eq!(next_run("custom", Some("0 2 * * *"), "2026-10-05T02:00", now), ("2026-10-06T02:00".into(), None));
    }

    #[test]
    fn an_unusable_expression_falls_back_to_daily_and_says_so() {
        let now = t("2026-10-05T15:21");
        for expr in [Some("not cron"), Some(""), None, Some("0 0 31 2 *")] {
            let (next, problem) = next_run("custom", expr, "2026-10-05T15:20", now);
            assert_eq!(next, "2026-10-06T15:20", "{expr:?}");
            assert!(problem.is_some(), "{expr:?} must be reported");
        }
    }

    #[test]
    fn intervals_step_from_the_planned_time() {
        let now = t("2026-10-05T02:01"); // the tick fired a minute late
        assert_eq!(next_run("daily", None, "2026-10-05T02:00", now).0, "2026-10-06T02:00");
        assert_eq!(next_run("weekly", None, "2026-10-05T02:00", now).0, "2026-10-12T02:00");
        assert_eq!(next_run("biweekly", None, "2026-10-05T02:00", now).0, "2026-10-19T02:00");
        assert_eq!(next_run("monthly", None, "2026-10-05T02:00", now).0, "2026-11-04T02:00");
        assert_eq!(next_run("anything-else", None, "2026-10-05T02:00", now).0, "2026-10-06T02:00");
        assert_eq!(next_run("daily", Some("ignored"), "2026-10-05T02:00", now), ("2026-10-06T02:00".into(), None));
    }

    // Five days of downtime: one run, then the next FUTURE slot — not five
    // runs a minute apart.
    #[test]
    fn after_an_outage_the_next_run_is_in_the_future() {
        let now = t("2026-10-10T09:30");
        assert_eq!(next_run("daily", None, "2026-10-05T02:00", now).0, "2026-10-11T02:00");
        assert_eq!(next_run("weekly", None, "2026-09-07T02:00", now).0, "2026-10-12T02:00");
        // Exactly on the boundary still moves forward.
        assert_eq!(next_run("daily", None, "2026-10-09T09:30", now).0, "2026-10-11T09:30");
        // An unreadable stored time starts again from now.
        assert_eq!(next_run("daily", None, "garbage", now).0, "2026-10-11T09:30");
    }

    // ── local_to_utc ────────────────────────────────────────────────────────
    #[test]
    fn local_times_are_converted_with_the_browsers_offset() {
        // getTimezoneOffset() is UTC − local, in minutes: −180 in UTC+3.
        assert_eq!(local_to_utc("2026-10-05T18:20", Some(-180)).as_deref(), Some("2026-10-05T15:20"));
        assert_eq!(local_to_utc("2026-10-05T09:00", Some(300)).as_deref(), Some("2026-10-05T14:00"), "UTC−5");
        assert_eq!(local_to_utc("2026-10-05T01:30", Some(-180)).as_deref(), Some("2026-10-04T22:30"), "crosses midnight");
        assert_eq!(local_to_utc("2026-10-05T05:45", Some(-345)).as_deref(), Some("2026-10-05T00:00"), "UTC+5:45");
        assert_eq!(local_to_utc("2026-10-05T18:20:30", Some(0)).as_deref(), Some("2026-10-05T18:20"), "seconds dropped");
    }

    // Same wall-clock time, different offsets either side of a daylight-saving
    // change: the browser reports the offset for the chosen date.
    #[test]
    fn the_offset_belongs_to_the_chosen_date() {
        assert_eq!(local_to_utc("2026-07-01T09:00", Some(-180)).as_deref(), Some("2026-07-01T06:00"), "summer, UTC+3");
        assert_eq!(local_to_utc("2026-12-01T09:00", Some(-120)).as_deref(), Some("2026-12-01T07:00"), "winter, UTC+2");
    }

    #[test]
    fn without_an_offset_the_time_is_taken_as_utc() {
        assert_eq!(local_to_utc("2026-10-05T18:20", None).as_deref(), Some("2026-10-05T18:20"));
        assert_eq!(local_to_utc("2026-10-05T18:20", Some(99_999)).as_deref(), Some("2026-10-05T18:20"), "absurd offset ignored");
        assert_eq!(local_to_utc("", Some(-180)), None);
        assert_eq!(local_to_utc("tomorrow", Some(-180)), None);
    }

    // ── resolve_submission ──────────────────────────────────────────────────
    fn now() -> NaiveDateTime { t("2026-10-05T15:21") }

    #[test]
    fn a_picked_time_is_stored_in_utc() {
        let s = resolve_submission("Auto-scan schedule", true, "daily", None, Some("2026-10-06T09:00"), Some(-180), now()).unwrap();
        assert_eq!(s.next_run.as_deref(), Some("2026-10-06T06:00"));
        assert_eq!((s.frequency.as_str(), s.enabled, s.cron), ("daily", true, None));
    }

    #[test]
    fn an_empty_picker_says_nothing_about_the_next_run() {
        for picked in [None, Some(""), Some("   ")] {
            let s = resolve_submission("x", true, "weekly", None, picked, Some(-180), now()).unwrap();
            assert_eq!(s.next_run, None, "{picked:?}");
        }
    }

    #[test]
    fn a_custom_schedule_takes_its_next_run_from_the_expression() {
        // The picker is ignored for cron schedules.
        let s = resolve_submission("x", true, "custom", Some(" 0 2 * * * "), Some("2030-01-01T00:00"), Some(-180), now()).unwrap();
        assert_eq!(s.next_run.as_deref(), Some("2026-10-06T02:00"));
        assert_eq!(s.cron.as_deref(), Some("0 2 * * *"), "stored trimmed");
    }

    #[test]
    fn an_enabled_custom_schedule_needs_a_valid_expression() {
        let e = resolve_submission("Auto-scan schedule", true, "custom", Some("every day"), None, None, now()).unwrap_err();
        assert!(e.starts_with("Auto-scan schedule:") && e.contains("not valid"), "{e}");
        let e = resolve_submission("Auto-report schedule", true, "custom", Some("  "), None, None, now()).unwrap_err();
        assert!(e.contains("needs a cron expression"), "{e}");
        assert!(resolve_submission("x", true, "custom", None, None, None, now()).is_err());
        assert!(resolve_submission("x", true, "custom", Some("0 0 31 2 *"), None, None, now()).is_err(), "never occurs");
    }

    // Turning a schedule off must not fail because of what is in the box.
    #[test]
    fn a_disabled_schedule_is_stored_as_typed() {
        let s = resolve_submission("x", false, "custom", Some("every day"), None, None, now()).unwrap();
        assert_eq!((s.enabled, s.cron.as_deref(), s.next_run), (false, Some("every day"), None));
        assert!(resolve_submission("x", false, "custom", None, None, None, now()).is_ok());
    }

    #[test]
    fn bad_input_is_refused_or_defaulted() {
        let e = resolve_submission("Auto-scan schedule", true, "daily", None, Some("next tuesday"), Some(0), now()).unwrap_err();
        assert!(e.contains("not a valid date"), "{e}");
        let s = resolve_submission("x", true, "hourly", None, None, None, now()).unwrap();
        assert_eq!(s.frequency, "daily", "an unknown interval becomes daily");
    }
}
