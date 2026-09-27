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
use tracing::{error, info, warn};

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
    /// Every action, for display and for re-checking boxes on the edit form.
    pub actions: Vec<ActionRow>,
    pub cooldown_minutes: i64,
    pub last_fired_at: Option<String>,
    /// Rendered here rather than in the template: "drops by 10 points" and
    /// "falls below 10%" are different rules and must never look alike.
    pub condition: String,
}

#[derive(Serialize, Clone)]
pub struct ActionRow {
    pub action: String,
    pub target: String,
    /// Whether a secret is stored. The value itself is never sent to the
    /// browser; the form only needs to know whether to say "unchanged".
    pub has_secret: bool,
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
                a.trigger_type, a.threshold, a.score_axis,
                a.cooldown_minutes,
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

    let mut out = Vec::new();
    for r in rows {
        {
            let trigger: String = r.try_get("trigger_type").unwrap_or_default();
            let threshold: f64 = r.try_get("threshold").unwrap_or_default();
            let axis: String = r.try_get("score_axis").unwrap_or_else(|_| "test".into());
            let scope: String = r.try_get("scope_type").unwrap_or_else(|_| "policy".into());
            let row = AlertRow {
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
                actions: load_action_rows(pool, r.try_get("id").unwrap_or_default()).await,
                cooldown_minutes: r.try_get("cooldown_minutes").unwrap_or(60),
                last_fired_at: r.try_get("last_fired_at").ok().flatten(),
            };
            out.push(row);
        }
    }
    out
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: load_action_rows
// ─────────────────────────────────────────────────────────────────────────────
async fn load_action_rows(pool: &SqlitePool, alert_id: i64) -> Vec<ActionRow> {
    sqlx::query("SELECT action, COALESCE(target,'') AS target, target_secret
                 FROM alert_actions WHERE alert_id = ? ORDER BY id")
        .bind(alert_id)
        .fetch_all(pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|r| ActionRow {
                    action: r.try_get("action").unwrap_or_default(),
                    target: r.try_get("target").unwrap_or_default(),
                    has_secret: r
                        .try_get::<Option<String>, _>("target_secret")
                        .ok()
                        .flatten()
                        .is_some_and(|s| !s.is_empty()),
                })
                .collect()
        })
        .unwrap_or_default()
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

    // (id, name, test score, system score). The scores let the form say where
    // each policy stands right now, which is the only way to notice that a
    // threshold rule has already been crossed and so cannot fire yet.
    // -1 means never scanned.
    let policies: Vec<(i64, String, f64, f64)> = sqlx::query_as(
        "SELECT id, name, COALESCE(score_test, -1.0), COALESCE(score_system, -1.0)
         FROM policies WHERE tenant_id = ? ORDER BY name",
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
    /// (action, target, secret) — one per checked action.
    actions: Vec<(String, Option<String>, Option<String>)>,
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

    // Each action is an independent checkbox with its own destination field,
    // so a rule can email AND notify AND post to a webhook from one event.
    let mut actions: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    for kind in ["notify", "email", "webhook", "syslog"] {
        if get(&format!("action_{kind}")) != "on" {
            continue;
        }
        let target = get(&format!("target_{kind}")).trim().to_string();
        if kind != "notify" && target.is_empty() {
            return Err(format!("The {kind} action needs a destination"));
        }
        if kind == "webhook" {
            crate::alert_delivery::validate_webhook_target(
                &target, crate::handlers::is_saas_mode(),
            )?;
        }
        let secret = get(&format!("secret_{kind}")).trim().to_string();
        actions.push((
            kind.to_string(),
            if target.is_empty() { None } else { Some(target) },
            if secret.is_empty() { None } else { Some(secret) },
        ));
    }
    if actions.is_empty() {
        return Err("Choose at least one action — an alert that does nothing is not an alert".into());
    }

    Ok(FormValues {
        name,
        scope_type,
        policy_id,
        trigger_type,
        threshold,
        score_axis,
        actions,
        cooldown_minutes: get("cooldown_minutes").trim().parse().unwrap_or(60),
        enabled: if get("enabled") == "on" { 1 } else { 0 },
    })
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: save_actions
// Replaces a rule's actions wholesale.
//
// A blank secret means "leave it alone", not "clear it" — the form never sends
// the stored value back to the browser, so an edit that does not retype it must
// not wipe it.
//
// alert_actions has no tenant_id of its own, so ownership is checked here
// against the parent rule rather than trusted from the caller: this function
// is the one place those rows are written, and it must never touch a rule
// outside the given tenant.
// ─────────────────────────────────────────────────────────────────────────────
async fn save_actions(
    pool: &SqlitePool,
    tenant_id: &str,
    alert_id: i64,
    actions: &[(String, Option<String>, Option<String>)],
) {
    let owned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE id = ? AND tenant_id = ?",
    )
    .bind(alert_id).bind(tenant_id)
    .fetch_one(pool).await.unwrap_or(0);
    if owned != 1 {
        error!("Refusing to write actions for alert {} outside tenant '{}'", alert_id, tenant_id);
        return;
    }

    let existing: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT action, target_secret FROM alert_actions WHERE alert_id = ?",
    )
    .bind(alert_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let _ = sqlx::query("DELETE FROM alert_actions WHERE alert_id = ?")
        .bind(alert_id).execute(pool).await;

    for (kind, target, secret) in actions {
        let keep = secret.clone().or_else(|| {
            existing.iter().find(|(k, _)| k == kind).and_then(|(_, s)| s.clone())
        });
        if let Err(e) = sqlx::query(
            "INSERT INTO alert_actions (alert_id, action, target, target_secret)
             VALUES (?, ?, ?, ?)",
        )
        .bind(alert_id).bind(kind).bind(target).bind(&keep)
        .execute(pool).await
        {
            error!("Failed to save {} action for alert {}: {}", kind, alert_id, e);
        }
    }
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

    // The policy picker only lists this tenant's policies, but the posted id
    // is not bound by that. A foreign id would never fire (evaluation skips
    // cross-tenant pairs), so this is about not storing a dangling reference
    // into another tenant rather than a leak.
    if let Some(pid) = v.policy_id {
        let owned: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM policies WHERE id = ? AND tenant_id = ?",
        )
        .bind(pid).bind(&auth.tenant_id)
        .fetch_one(&*pool).await.unwrap_or(0);
        if owned != 1 {
            return Redirect::to("/alerts?error_message=Choose+one+of+your+policies").into_response();
        }
    }

    let result = match id {
        Some(Path(alert_id)) => {
            let r = sqlx::query(
                "UPDATE alerts SET name=?, enabled=?, scope_type=?, policy_id=?, trigger_type=?,
                                   threshold=?, score_axis=?, cooldown_minutes=?
                 WHERE id=? AND tenant_id=?",
            )
            .bind(&v.name).bind(v.enabled).bind(&v.scope_type).bind(v.policy_id)
            .bind(&v.trigger_type).bind(v.threshold).bind(&v.score_axis)
            .bind(v.cooldown_minutes).bind(alert_id).bind(&auth.tenant_id)
            .execute(&*pool).await;
            // is_ok() is not enough: an UPDATE scoped to the caller's tenant
            // that matches no row still succeeds. Gating on it let an admin in
            // one tenant post to another tenant's alert id and have
            // save_actions rewrite that alert's destinations — keeping its
            // stored webhook secret — while the UPDATE itself did nothing.
            match r {
                Ok(ref res) if res.rows_affected() == 1 => {
                    save_actions(&pool, &auth.tenant_id, alert_id, &v.actions).await;
                }
                Ok(_) => {
                    warn!("Alert update for id {} matched nothing in tenant '{}' (user '{}')",
                          alert_id, auth.tenant_id, auth.username);
                    return Redirect::to("/alerts?error_message=Alert+not+found").into_response();
                }
                Err(_) => {}
            }
            r
        }
        None => {
            let r = sqlx::query(
                "INSERT INTO alerts (tenant_id, name, enabled, scope_type, policy_id,
                                     trigger_type, threshold, score_axis,
                                     cooldown_minutes, created_by)
                 VALUES (?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(&auth.tenant_id).bind(&v.name).bind(v.enabled).bind(&v.scope_type)
            .bind(v.policy_id).bind(&v.trigger_type).bind(v.threshold).bind(&v.score_axis)
            .bind(v.cooldown_minutes).bind(auth.userid)
            .execute(&*pool).await;
            if let Ok(ref res) = r {
                save_actions(&pool, &auth.tenant_id, res.last_insert_rowid(), &v.actions).await;
            }
            r
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

    let name: Option<String> = sqlx::query_scalar(
        "SELECT name FROM alerts WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&*pool).await.ok().flatten();
    let Some(name) = name else {
        return Redirect::to("/alerts?error_message=Alert+not+found").into_response();
    };

    // Every action, not just the first: the point of the button is to prove
    // each transport works, and they fail independently.
    let actions = crate::alerts::load_actions(&pool, id).await;
    if actions.is_empty() {
        return Redirect::to("/alerts?error_message=This+alert+has+no+actions+to+test").into_response();
    }

    for act in &actions {
        let _ = sqlx::query(
            "INSERT INTO alert_deliveries
                (tenant_id, alert_id, action_id, policy_id, alert_name, policy_name,
                 old_score, new_score, action, target, status, next_retry_at)
             VALUES (?, ?, ?, NULL, ?, 'Test — no policy', 100.0, 0.0, ?, ?, 'pending', CURRENT_TIMESTAMP)",
        )
        .bind(&auth.tenant_id).bind(id).bind(act.id)
        .bind(format!("{name} (test)"))
        .bind(&act.action).bind(&act.target)
        .execute(&*pool).await;
    }

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
