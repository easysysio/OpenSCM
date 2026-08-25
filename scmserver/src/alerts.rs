// alerts.rs — compliance alerting.
//
// Design: docs/design/0.9.0-alerting.md.
//
// The server already knows the moment a policy falls from 94% to 61% — that
// knowledge just used to die in a chart until somebody opened the page. This
// module turns it into something that reaches a person.
//
// WHERE EVALUATION HAPPENS, AND WHY NOT ON THE HOURLY TICK
//
// Alerts are evaluated from `run_recalc`, not from the hourly snapshot.
// `record_entity_history` runs at minute 0; a policy that drops at 14:05 and
// recovers at 14:50 looks identical in the 14:00 and 15:00 snapshots, so an
// hourly evaluator would miss the excursion entirely — and would report a real
// drop 55 minutes late. `run_recalc` is the single choke point every score
// change passes through: scheduled runs, manual runs, group edits, exclusions.
//
// Evaluation runs AFTER the recalc transaction commits. Delivery is network
// I/O, and holding a SQLite write transaction open across a hung webhook would
// block every writer in the process.

use serde::Serialize;
use sqlx::{Row, SqlitePool};
use tracing::{error, info};


// ─────────────────────────────────────────────────────────────────────────────
// Struct: Rule
// One alert rule, as evaluated.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: i64,
    pub tenant_id: String,
    pub name: String,
    pub scope_type: String,
    pub policy_id: Option<i64>,
    pub trigger_type: String,
    pub threshold: f64,
    pub score_axis: String,
    pub action: String,
    pub target: Option<String>,
    pub cooldown_minutes: i64,
}


// ─────────────────────────────────────────────────────────────────────────────
// Struct: Observation
// One policy's score before and after a recalculation.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub previous: f64,
    pub current: f64,
}


// ─────────────────────────────────────────────────────────────────────────────
// Enum: Decision
// What evaluating a rule against an observation concluded. Distinguishing
// "nothing happened" from "would have fired but is muted" matters: a muted
// evaluation still has to advance the stored state, or the cooldown ends with
// a stale baseline and the next comparison is wrong.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Deliver, and mark the pair as firing.
    Fire,
    /// Threshold not met. `state` becomes 'ok' so a guarded rule re-arms.
    Quiet,
    /// Threshold met but the pair is inside its cooldown window.
    Muted,
    /// No usable comparison — a score of -1 means "never scanned", not zero.
    /// Record the new baseline and decide nothing.
    NoComparison,
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: is_scanned
// -1.0 is the "never scanned" sentinel used throughout the compliance tables.
// It is not a score, and must never take part in arithmetic: a policy going
// unscanned would otherwise read as a 95-point drop and page someone at 03:00
// over a bookkeeping change.
// ─────────────────────────────────────────────────────────────────────────────
fn is_scanned(score: f64) -> bool {
    score >= 0.0
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: evaluate
// Pure decision function: rule + observation + state → Decision.
//
// Everything is EDGE triggered. `below`/`above` carry an explicit previous-side
// guard, because without it a policy resting at 60% against an 80% threshold
// delivers on every single recalculation, forever. That is the classic
// alerting failure, and it is what makes people turn alerting off.
// ─────────────────────────────────────────────────────────────────────────────
pub fn evaluate(rule: &Rule, obs: Observation, in_cooldown: bool) -> Decision {
    // A transition into or out of "never scanned" is not a score movement.
    if !is_scanned(obs.current) || !is_scanned(obs.previous) {
        return Decision::NoComparison;
    }

    let t = rule.threshold;
    let fired = match rule.trigger_type.as_str() {
        "drop"  => obs.previous - obs.current >= t,
        "gain"  => obs.current - obs.previous >= t,
        "below" => obs.current < t && obs.previous >= t,
        "above" => obs.current > t && obs.previous <= t,
        other => {
            error!("Alert {} has unknown trigger_type '{}' — ignoring.", rule.id, other);
            false
        }
    };

    if !fired {
        return Decision::Quiet;
    }
    if in_cooldown {
        return Decision::Muted;
    }
    Decision::Fire
}


// ─────────────────────────────────────────────────────────────────────────────
// Struct: Payload
// The versioned body a webhook receives, and the source of the text used by
// the other transports. Versioned because downstream consumers parse it — this
// is effectively the product's first public data contract.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Serialize)]
pub struct Payload {
    pub version: u32,
    pub event: &'static str,
    pub fired_at: String,
    pub server: String,
    pub tenant: String,
    pub alert: PayloadAlert,
    pub policy: PayloadPolicy,
    pub score: PayloadScore,
}

#[derive(Debug, Serialize)]
pub struct PayloadAlert {
    pub id: i64,
    pub name: String,
    pub trigger: String,
    pub threshold: f64,
    pub axis: String,
}

#[derive(Debug, Serialize)]
pub struct PayloadPolicy {
    pub id: i64,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct PayloadScore {
    pub previous: f64,
    pub current: f64,
    pub delta: f64,
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: build_payload
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_payload(
    rule: &Rule,
    policy_id: i64,
    policy_name: &str,
    obs: Observation,
    server_url: &str,
) -> Payload {
    let base = server_url.trim_end_matches('/');
    Payload {
        version: 1,
        event: "compliance.alert",
        fired_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        server: base.to_string(),
        tenant: rule.tenant_id.clone(),
        alert: PayloadAlert {
            id: rule.id,
            name: rule.name.clone(),
            trigger: rule.trigger_type.clone(),
            threshold: rule.threshold,
            axis: rule.score_axis.clone(),
        },
        policy: PayloadPolicy {
            id: policy_id,
            name: policy_name.to_string(),
            url: format!("{}/policies/report/{}", base, policy_id),
        },
        score: PayloadScore {
            previous: obs.previous,
            current: obs.current,
            // Rounded: these are percentages to two places everywhere else in
            // the product, and float subtraction otherwise emits 33.19999999.
            delta: ((obs.current - obs.previous) * 100.0).round() / 100.0,
        },
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: summary_line
// One-line human rendering, shared by the bell notification, the email subject
// and the syslog message so the three cannot describe the same event
// differently.
// ─────────────────────────────────────────────────────────────────────────────
pub fn summary_line(policy_name: &str, obs: Observation) -> String {
    format!(
        "{} compliance {:.2}% → {:.2}%",
        policy_name, obs.previous, obs.current
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: load_rules
// Enabled rules for a tenant (or every tenant when `tenant` is None).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_rules(pool: &SqlitePool, tenant: Option<&str>) -> Vec<Rule> {
    let sql = "SELECT id, tenant_id, name, scope_type, policy_id, trigger_type,
                      threshold, score_axis, action, target, cooldown_minutes
               FROM alerts
               WHERE enabled = 1";
    let rows = match tenant {
        Some(t) => {
            sqlx::query(&format!("{sql} AND tenant_id = ?")).bind(t).fetch_all(pool).await
        }
        None => sqlx::query(sql).fetch_all(pool).await,
    };

    match rows {
        Ok(rows) => rows
            .into_iter()
            .map(|r| Rule {
                id: r.try_get("id").unwrap_or_default(),
                tenant_id: r.try_get("tenant_id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                scope_type: r.try_get("scope_type").unwrap_or_else(|_| "policy".into()),
                policy_id: r.try_get("policy_id").ok().flatten(),
                trigger_type: r.try_get("trigger_type").unwrap_or_default(),
                threshold: r.try_get("threshold").unwrap_or_default(),
                score_axis: r.try_get("score_axis").unwrap_or_else(|_| "test".into()),
                action: r.try_get("action").unwrap_or_else(|_| "notify".into()),
                target: r.try_get("target").ok().flatten(),
                cooldown_minutes: r.try_get("cooldown_minutes").unwrap_or(60),
            })
            .collect(),
        Err(e) => {
            error!("Failed to load alert rules: {}", e);
            Vec::new()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: applies_to
// Whether a rule watches a given policy.
// ─────────────────────────────────────────────────────────────────────────────
pub fn applies_to(rule: &Rule, policy_id: i64) -> bool {
    match rule.scope_type.as_str() {
        "all_policies" => true,
        _ => rule.policy_id == Some(policy_id),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: queue_delivery
// Writes the delivery as `pending`; the scheduler drains it.
//
// Queued rather than sent inline so that a slow webhook cannot delay a
// recalculation, and so a restart mid-delivery loses nothing — the row is
// still pending. alert_name and policy_name are denormalised so the history
// stays readable after the rule or policy is deleted.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn queue_delivery(
    pool: &SqlitePool,
    rule: &Rule,
    policy_id: i64,
    policy_name: &str,
    obs: Observation,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO alert_deliveries
            (tenant_id, alert_id, policy_id, alert_name, policy_name,
             old_score, new_score, action, target, status, next_retry_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)",
    )
    .bind(&rule.tenant_id)
    .bind(rule.id)
    .bind(policy_id)
    .bind(&rule.name)
    .bind(policy_name)
    .bind(obs.previous)
    .bind(obs.current)
    .bind(&rule.action)
    .bind(&rule.target)
    .execute(pool)
    .await
    {
        error!("Failed to queue alert delivery for alert {}: {}", rule.id, e);
    } else {
        info!(
            "Alert '{}' fired for policy {} ({}) — queued {} delivery",
            rule.name, policy_id, summary_line(policy_name, obs), rule.action
        );
    }
}
