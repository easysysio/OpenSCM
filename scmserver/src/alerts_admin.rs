// alerts_admin.rs — the Alerts section.
//
// Managing a rule is Admin work, not Editor work: a rule carries an SMTP
// recipient list and a webhook secret, and it makes the server emit traffic to
// an address of the operator's choosing. Reading is Viewer, so anyone who can
// see compliance can see what would be alerted on.

use axum::extract::{Extension, Path, RawForm};
use axum::response::{IntoResponse, Redirect};
use bytes::Bytes;
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tera::{Context, Tera};
use tracing::{error, info};

use crate::auth;
use crate::handlers::{parse_form_data, render_template};
use crate::models::{AuthSession, UserRole};


// ─────────────────────────────────────────────────────────────────────────────
// Struct: AlertRow / DeliveryRow
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Serialize)]
pub struct AlertRow {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub scope_type: String,
    pub policy_id: Option<i64>,
    pub policy_name: String,
    pub trigger_type: String,
    pub threshold: f64,
    pub score_axis: String,
    pub action: String,
    pub target: String,
    pub cooldown_minutes: i64,
    pub last_fired_at: Option<String>,
    /// Rendered here rather than in the template: "drops by 10 points" and
    /// "falls below 10%" are different rules and must never look alike.
    pub condition: String,
}

#[derive(Serialize)]
pub struct DeliveryRow {
    pub id: i64,
    pub fired_at: String,
    pub alert_name: String,
    pub policy_name: String,
    pub old_score: f64,
    pub new_score: f64,
    pub action: String,
    pub target: String,
    pub status: String,
    pub attempts: i64,
    pub last_error: String,
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: describe
// One-line English for a trigger. The unit differs by trigger type, which is
// exactly the thing a bare number on a list page would hide.
// ─────────────────────────────────────────────────────────────────────────────
fn describe(trigger: &str, threshold: f64, axis: &str) -> String {
    let axis_label = if axis == "system" { "system compliance" } else { "test compliance" };
    match trigger {
        "drop"  => format!("{axis_label} drops by {threshold:.0} points or more"),
        "gain"  => format!("{axis_label} rises by {threshold:.0} points or more"),
        "below" => format!("{axis_label} falls below {threshold:.0}%"),
        "above" => format!("{axis_label} rises above {threshold:.0}%"),
        other   => format!("{other} {threshold}"),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: load_alerts
// ─────────────────────────────────────────────────────────────────────────────
async fn load_alerts(pool: &SqlitePool, tenant: &str) -> Vec<AlertRow> {
    let rows = sqlx::query(
        "SELECT a.id, a.name, a.enabled, a.scope_type, a.policy_id,
                COALESCE(p.name, '') AS policy_name,
                a.trigger_type, a.threshold, a.score_axis, a.action,
                COALESCE(a.target, '') AS target, a.cooldown_minutes,
                (SELECT MAX(last_fired_at) FROM alert_state s WHERE s.alert_id = a.id) AS last_fired_at
         FROM alerts a
         LEFT JOIN policies p ON p.id = a.policy_id AND p.tenant_id = a.tenant_id
         WHERE a.tenant_id = ?
         ORDER BY a.name",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|r| {
            let trigger: String = r.try_get("trigger_type").unwrap_or_default();
            let threshold: f64 = r.try_get("threshold").unwrap_or_default();
            let axis: String = r.try_get("score_axis").unwrap_or_else(|_| "test".into());
            let scope: String = r.try_get("scope_type").unwrap_or_else(|_| "policy".into());
            AlertRow {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                enabled: r.try_get::<i64, _>("enabled").unwrap_or(1) != 0,
                policy_name: if scope == "all_policies" {
                    "All policies".to_string()
                } else {
                    r.try_get("policy_name").unwrap_or_default()
                },
                scope_type: scope,
                policy_id: r.try_get("policy_id").ok().flatten(),
                condition: describe(&trigger, threshold, &axis),
                trigger_type: trigger,
                threshold,
                score_axis: axis,
                action: r.try_get("action").unwrap_or_default(),
                target: r.try_get("target").unwrap_or_default(),
                cooldown_minutes: r.try_get("cooldown_minutes").unwrap_or(60),
                last_fired_at: r.try_get("last_fired_at").ok().flatten(),
            }
        })
        .collect()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /alerts
// Role: Viewer.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn alerts_page(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }
    let alerts = load_alerts(&pool, &auth.tenant_id).await;
    let mut ctx = Context::new();
    ctx.insert("alerts", &alerts);
    render_template(&tera, Some(&pool), "alerts.html", ctx, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /alerts/new  and  GET /alerts/{id}/edit
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn alerts_form(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
    id: Option<Path<i64>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let policies: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM policies WHERE tenant_id = ? ORDER BY name",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    ctx.insert("policies", &policies);
    if let Some(Path(alert_id)) = id {
        let existing = load_alerts(&pool, &auth.tenant_id)
            .await
            .into_iter()
            .find(|a| a.id == alert_id);
        match existing {
            Some(a) => ctx.insert("alert", &a),
            None => return Redirect::to("/alerts?error_message=Alert+not+found").into_response(),
        }
    }
    render_template(&tera, Some(&pool), "alerts_form.html", ctx, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: read_form
// Pulls and validates the rule fields shared by create and update.
// ─────────────────────────────────────────────────────────────────────────────
struct FormValues {
    name: String,
    scope_type: String,
    policy_id: Option<i64>,
    trigger_type: String,
    threshold: f64,
    score_axis: String,
    action: String,
    target: Option<String>,
    target_secret: Option<String>,
    cooldown_minutes: i64,
    enabled: i64,
}

fn read_form(raw: &str) -> Result<FormValues, String> {
    let f = parse_form_data(raw);
    let get = |k: &str| f.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();

    let name = get("name").trim().to_string();
    if name.is_empty() {
        return Err("A name is required".into());
    }

    let scope_type = match get("scope_type").as_str() {
        "all_policies" => "all_policies".to_string(),
        _ => "policy".to_string(),
    };
    let policy_id = if scope_type == "policy" {
        match get("policy_id").parse::<i64>() {
            Ok(p) => Some(p),
            Err(_) => return Err("Choose a policy, or select All policies".into()),
        }
    } else {
        None
    };

    let trigger_type = get("trigger_type");
    if !matches!(trigger_type.as_str(), "drop" | "gain" | "below" | "above") {
        return Err("Unknown trigger".into());
    }

    let threshold: f64 = get("threshold").trim().parse().map_err(|_| "Threshold must be a number")?;
    if threshold <= 0.0 {
        return Err("Threshold must be greater than zero".into());
    }
    // below/above are percentages; a threshold above 100 can never be crossed.
    if matches!(trigger_type.as_str(), "below" | "above") && threshold > 100.0 {
        return Err("A percentage threshold cannot exceed 100".into());
    }

    let score_axis = if get("score_axis") == "system" { "system" } else { "test" }.to_string();

    let action = get("action");
    if !matches!(action.as_str(), "notify" | "email" | "webhook" | "syslog") {
        return Err("Unknown action".into());
    }

    let target = get("target").trim().to_string();
    if action != "notify" && target.is_empty() {
        return Err("This action needs a destination".into());
    }
    if action == "webhook" {
        crate::alert_delivery::validate_webhook_target(&target, crate::handlers::is_saas_mode())?;
    }

    let secret = get("target_secret").trim().to_string();

    Ok(FormValues {
        name,
        scope_type,
        policy_id,
        trigger_type,
        threshold,
        score_axis,
        action,
        target: if target.is_empty() { None } else { Some(target) },
        target_secret: if secret.is_empty() { None } else { Some(secret) },
        cooldown_minutes: get("cooldown_minutes").trim().parse().unwrap_or(60),
        enabled: if get("enabled") == "on" { 1 } else { 0 },
    })
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /alerts/create   and   POST /alerts/{id}/update
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn alerts_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    id: Option<Path<i64>>,
    raw: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let body = String::from_utf8_lossy(&Bytes::from(raw.0)).to_string();
    let v = match read_form(&body) {
        Ok(v) => v,
        Err(e) => {
            let msg = urlencoding::encode(&e).to_string();
            return Redirect::to(&format!("/alerts?error_message={msg}")).into_response();
        }
    };

    let result = match id {
        Some(Path(alert_id)) => {
            sqlx::query(
                "UPDATE alerts SET name=?, enabled=?, scope_type=?, policy_id=?, trigger_type=?,
                                   threshold=?, score_axis=?, action=?, target=?,
                                   target_secret=COALESCE(?, target_secret), cooldown_minutes=?
                 WHERE id=? AND tenant_id=?",
            )
            .bind(&v.name).bind(v.enabled).bind(&v.scope_type).bind(v.policy_id)
            .bind(&v.trigger_type).bind(v.threshold).bind(&v.score_axis)
            .bind(&v.action).bind(&v.target).bind(&v.target_secret)
            .bind(v.cooldown_minutes).bind(alert_id).bind(&auth.tenant_id)
            .execute(&*pool).await
        }
        None => {
            sqlx::query(
                "INSERT INTO alerts (tenant_id, name, enabled, scope_type, policy_id,
                                     trigger_type, threshold, score_axis, action, target,
                                     target_secret, cooldown_minutes, created_by)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(&auth.tenant_id).bind(&v.name).bind(v.enabled).bind(&v.scope_type)
            .bind(v.policy_id).bind(&v.trigger_type).bind(v.threshold).bind(&v.score_axis)
            .bind(&v.action).bind(&v.target).bind(&v.target_secret)
            .bind(v.cooldown_minutes).bind(auth.userid)
            .execute(&*pool).await
        }
    };

    match result {
        Ok(_) => {
            info!("Alert '{}' saved by '{}'", v.name, auth.username);
            Redirect::to("/alerts?success_message=Alert+saved").into_response()
        }
        Err(e) => {
            error!("Failed to save alert: {}", e);
            Redirect::to("/alerts?error_message=Could+not+save+the+alert").into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /alerts/{id}/toggle | /delete
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn alerts_toggle(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let _ = sqlx::query(
        "UPDATE alerts SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .execute(&*pool).await;
    Redirect::to("/alerts?success_message=Alert+updated").into_response()
}

pub async fn alerts_delete(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    // The delivery history deliberately survives: alert_id goes NULL and the
    // rows keep their denormalised names, so the record of what was already
    // sent is not erased along with the rule.
    let _ = sqlx::query("UPDATE alert_deliveries SET alert_id = NULL WHERE alert_id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).execute(&*pool).await;
    let _ = sqlx::query("DELETE FROM alerts WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).execute(&*pool).await;
    info!("Alert {} deleted by '{}'", id, auth.username);
    Redirect::to("/alerts?success_message=Alert+deleted").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /alerts/{id}/test
// Queues a synthetic delivery through the real transport.
//
// Not a nicety: a typo'd webhook URL or a firewalled syslog port is otherwise
// invisible until a real incident fails to deliver.
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn alerts_test(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let row = sqlx::query("SELECT name, action, target FROM alerts WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id)
        .fetch_optional(&*pool).await.ok().flatten();
    let Some(row) = row else {
        return Redirect::to("/alerts?error_message=Alert+not+found").into_response();
    };

    let name: String = row.try_get("name").unwrap_or_default();
    let action: String = row.try_get("action").unwrap_or_default();
    let target: Option<String> = row.try_get("target").ok().flatten();

    let _ = sqlx::query(
        "INSERT INTO alert_deliveries
            (tenant_id, alert_id, policy_id, alert_name, policy_name,
             old_score, new_score, action, target, status, next_retry_at)
         VALUES (?, ?, NULL, ?, 'Test — no policy', 100.0, 0.0, ?, ?, 'pending', CURRENT_TIMESTAMP)",
    )
    .bind(&auth.tenant_id).bind(id)
    .bind(format!("{name} (test)"))
    .bind(&action).bind(&target)
    .execute(&*pool).await;

    info!("Test delivery queued for alert {} by '{}'", id, auth.username);
    Redirect::to("/alerts/history?success_message=Test+queued+—+it+is+sent+within+a+minute")
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /alerts/history
// Role: Viewer.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn alerts_history(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let rows = sqlx::query(
        "SELECT id, fired_at, COALESCE(alert_name,'(deleted)') AS alert_name,
                COALESCE(policy_name,'') AS policy_name, old_score, new_score,
                action, COALESCE(target,'') AS target, status, attempts,
                COALESCE(last_error,'') AS last_error
         FROM alert_deliveries WHERE tenant_id = ?
         ORDER BY fired_at DESC LIMIT 200",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    let deliveries: Vec<DeliveryRow> = rows
        .into_iter()
        .map(|r| DeliveryRow {
            id: r.try_get("id").unwrap_or_default(),
            fired_at: r.try_get("fired_at").unwrap_or_default(),
            alert_name: r.try_get("alert_name").unwrap_or_default(),
            policy_name: r.try_get("policy_name").unwrap_or_default(),
            old_score: r.try_get("old_score").unwrap_or(-1.0),
            new_score: r.try_get("new_score").unwrap_or(-1.0),
            action: r.try_get("action").unwrap_or_default(),
            target: r.try_get("target").unwrap_or_default(),
            status: r.try_get("status").unwrap_or_default(),
            attempts: r.try_get("attempts").unwrap_or(0),
            last_error: r.try_get("last_error").unwrap_or_default(),
        })
        .collect();

    let mut ctx = Context::new();
    ctx.insert("deliveries", &deliveries);
    render_template(&tera, Some(&pool), "alerts_history.html", ctx, Some(auth))
        .await
        .into_response()
}
