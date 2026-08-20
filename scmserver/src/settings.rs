// =============================================================================
// settings.rs — admin settings: thresholds, SMTP, email test, DB reset
//
// All routes require Admin role or higher. SMTP settings are global (stored
// under the default tenant); compliance thresholds are per-tenant.
// =============================================================================

use axum::response::{IntoResponse, Redirect};
use axum::extract::{Extension, Query, Form};
use axum::extract::RawForm;
use axum::http::StatusCode;
use axum::Json;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::{info, error};
use urlencoding;
use serde::Serialize;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::models::{ErrorQuery, UserRole, AuthSession};
use crate::auth;
use crate::handlers::{render_template, parse_form_data};

#[derive(serde::Serialize)]
pub struct Settings {
    pub schema_version: String,
    pub offline_threshold: String,
    pub auto_prune_inactive: String,
    pub compliance_sat: String,
    pub compliance_marginal: String,
    // Per-tenant compliance calculation modes (two independent toggles).
    //   policy_compliance_mode: "test" | "system"  (how a POLICY's % is scored)
    //   system_compliance_mode: "test" | "policy"  (how a SYSTEM's % is scored)
    pub policy_compliance_mode: String,
    pub system_compliance_mode: String,
    pub audit_log_retention_days: String,
    pub report_retention_days: String,
    pub notification_retention_days: String,
    pub container_retention_days: String,
    pub entity_trend_retention_days: String,
    pub fleet_trend_retention_days: String,
    pub smtp_host:     String,
    pub smtp_port:     String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from:     String,
    pub smtp_tls:      String,
    pub app_url:       String,
    // SaaS-only platform setting (global, stored under the 'default' tenant).
    // "1" = email superusers when a new tenant self-registers, "0" = off.
    // Defaults to "1" to preserve the behaviour shipped in SaaS 0.4.3.
    pub notify_new_tenant: String,
    /// Days after which a registration whose email was never verified is
    /// deleted. Nothing exists to keep. "0" disables. SaaS-only.
    pub dormant_unverified_days: String,
    /// Days after which a verified organization that never enrolled a system
    /// is acted on — deleted if it holds nothing, suspended if it authored
    /// tests/policies or was once in use. "0" disables. SaaS-only.
    pub dormant_unused_days: String,
    /// How many days before that the tenant's admins are warned by email.
    pub dormant_warn_days: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /settings
// Render the admin settings page with current thresholds and SMTP config.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn settings(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Per-tenant settings (compliance thresholds, offline threshold)
    let rows = sqlx::query(
        "SELECT skey, value FROM settings WHERE tenant_id = ?
         AND skey NOT IN ('smtp_host','smtp_port','smtp_username','smtp_password','smtp_from','smtp_tls','app_url')",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    let mut map = std::collections::HashMap::new();
    for row in rows {
        let key: String = row.get("skey");
        let value: String = row.get("value");
        map.insert(key, value);
    }

    // SMTP settings + SaaS platform settings are global — read from default tenant
    let smtp_rows = sqlx::query(
        "SELECT skey, value FROM settings WHERE tenant_id = 'default'
         AND skey IN ('smtp_host','smtp_port','smtp_username','smtp_password','smtp_from','smtp_tls','app_url','notify_new_tenant','dormant_unverified_days','dormant_unused_days','dormant_warn_days')",
    )
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    for row in smtp_rows {
        let key: String = row.get("skey");
        let value: String = row.get("value");
        map.insert(key, value);
    }

    // Schema version lives in schema_info, not in the settings key-value store.
    let schema_version: i64 = sqlx::query_scalar("SELECT version FROM schema_info WHERE id = 1")
        .fetch_one(&*pool)
        .await
        .unwrap_or(0);

    let settings = Settings {
        schema_version:    schema_version.to_string(),
        offline_threshold: map.get("offline_threshold").cloned().unwrap_or_else(|| "60".to_string()),
        auto_prune_inactive: map.get("auto_prune_inactive").cloned().unwrap_or_else(|| "0".to_string()),
        compliance_sat:    map.get("compliance_sat").cloned().unwrap_or_else(|| "80".to_string()),
        compliance_marginal: map.get("compliance_marginal").cloned().unwrap_or_else(|| "60".to_string()),
        policy_compliance_mode: map.get("policy_compliance_mode").cloned().unwrap_or_else(|| "test".to_string()),
        system_compliance_mode: map.get("system_compliance_mode").cloned().unwrap_or_else(|| "test".to_string()),
        audit_log_retention_days: map.get("audit_log_retention_days").cloned().unwrap_or_else(|| "730".to_string()),
        report_retention_days: map.get("report_retention_days").cloned().unwrap_or_else(|| "0".to_string()),
        notification_retention_days: map.get("notification_retention_days").cloned().unwrap_or_else(|| "30".to_string()),
        container_retention_days: map.get("container_retention_days").cloned().unwrap_or_else(|| "7".to_string()),
        entity_trend_retention_days: map.get("entity_trend_retention_days").cloned().unwrap_or_else(|| "90".to_string()),
        fleet_trend_retention_days: map.get("fleet_trend_retention_days").cloned().unwrap_or_else(|| "365".to_string()),
        smtp_host:     map.get("smtp_host").cloned().unwrap_or_default(),
        smtp_port:     map.get("smtp_port").cloned().unwrap_or_else(|| "587".to_string()),
        smtp_username: map.get("smtp_username").cloned().unwrap_or_default(),
        smtp_password: map.get("smtp_password").cloned().unwrap_or_default(),
        smtp_from:     map.get("smtp_from").cloned().unwrap_or_default(),
        smtp_tls:      map.get("smtp_tls").cloned().unwrap_or_else(|| "starttls".to_string()),
        app_url:       map.get("app_url").cloned().unwrap_or_default(),
        notify_new_tenant: map.get("notify_new_tenant").cloned().unwrap_or_else(|| "1".to_string()),
        // Default 0: auto-suspension is opt-in. A sweep that silently disables
        // accounts should never switch itself on during an upgrade.
        dormant_unverified_days: map.get("dormant_unverified_days").cloned().unwrap_or_else(|| "0".to_string()),
        dormant_unused_days:     map.get("dormant_unused_days").cloned().unwrap_or_else(|| "0".to_string()),
        dormant_warn_days:   map.get("dormant_warn_days").cloned().unwrap_or_else(|| "14".to_string()),
    };

    // Active signing key fingerprint and creation date for the Danger Zone card.
    let key_row = sqlx::query(
        "SELECT public_key, created_at FROM tenant_keys WHERE tenant_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
    )
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await
    .unwrap_or(None);

    let (key_fingerprint, key_created_at) = if let Some(row) = key_row {
        let pub_key: String = row.get("public_key");
        let created_at: String = row.try_get("created_at").unwrap_or_default();
        // Show first 24 chars of the base64 public key as a fingerprint — enough to confirm a rotation.
        let fingerprint = format!("{}…", &pub_key[..pub_key.len().min(24)]);
        (fingerprint, created_at)
    } else {
        ("(none)".to_string(), String::new())
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message { context.insert("error_message", &msg); }
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    context.insert("settings", &settings);
    context.insert("key_fingerprint", &key_fingerprint);
    context.insert("key_created_at", &key_created_at);

    render_template(&tera, Some(&pool), "settings.html", context, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/save
// Persist updated compliance thresholds and (if Superuser) SMTP settings.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn settings_save(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<tokio::sync::mpsc::Sender<()>>,
    RawForm(raw_form): RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let raw_string = String::from_utf8_lossy(&raw_form).to_string();
    let form_data = parse_form_data(&raw_string);

    // M7: Validate numeric settings before persisting.
    let raw_threshold    = form_data.get("offline_threshold").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_auto_prune   = form_data.get("auto_prune_inactive").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_sat          = form_data.get("compliance_sat").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_marginal     = form_data.get("compliance_marginal").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_audit_keep   = form_data.get("audit_log_retention_days").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_report_keep  = form_data.get("report_retention_days").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_notify_keep  = form_data.get("notification_retention_days").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_container_keep = form_data.get("container_retention_days").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_entity_trend_keep = form_data.get("entity_trend_retention_days").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_fleet_trend_keep  = form_data.get("fleet_trend_retention_days").and_then(|v| v.first()).cloned().unwrap_or_default();

    let threshold: i64 = match raw_threshold.parse() {
        Ok(v) if v >= 1 => v,
        _ => return Redirect::to("/settings?error_message=Offline+threshold+must+be+a+positive+number+of+minutes").into_response(),
    };

    let auto_prune: i64 = match raw_auto_prune.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if v >= 1 => v,
        _ => return Redirect::to("/settings?error_message=Auto-prune+threshold+must+be+0+(disabled)+or+a+positive+number+of+minutes").into_response(),
    };

    let sat: i64 = match raw_sat.parse() {
        Ok(v) if (0..=100).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Compliance+satisfied+threshold+must+be+0-100").into_response(),
    };

    let marginal: i64 = match raw_marginal.parse() {
        Ok(v) if (0..=100).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Compliance+marginal+threshold+must+be+0-100").into_response(),
    };

    if marginal >= sat {
        return Redirect::to("/settings?error_message=Marginal+threshold+must+be+less+than+Satisfied+threshold").into_response();
    }

    // 0 = retain forever; otherwise must be a positive day count. Cap at
    // ~27 years (10,000 days) so a typo can't accidentally lock a tenant
    // into "audit log too big to query" territory.
    let audit_keep: i64 = match raw_audit_keep.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if (1..=10000).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Audit+log+retention+must+be+0+(forever)+or+1-10000+days").into_response(),
    };

    let report_keep: i64 = match raw_report_keep.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if (1..=10000).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Report+retention+must+be+0+(forever)+or+1-10000+days").into_response(),
    };

    let notify_keep: i64 = match raw_notify_keep.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if (1..=10000).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Notification+retention+must+be+0+(forever)+or+1-10000+days").into_response(),
    };

    let container_keep: i64 = match raw_container_keep.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if (1..=10000).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Container+retention+must+be+0+(forever)+or+1-10000+days").into_response(),
    };

    let entity_trend_keep: i64 = match raw_entity_trend_keep.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if (1..=10000).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=System%2FPolicy+trend+retention+must+be+0+(forever)+or+1-10000+days").into_response(),
    };

    let fleet_trend_keep: i64 = match raw_fleet_trend_keep.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if (1..=10000).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Compliance+trend+retention+must+be+0+(forever)+or+1-10000+days").into_response(),
    };

    // Compliance modes — validated to their allowed values; anything else → "test".
    let policy_mode = match form_data.get("policy_compliance_mode").and_then(|v| v.first()).map(String::as_str) {
        Some("system") => "system",
        _ => "test",
    };
    let system_mode = match form_data.get("system_compliance_mode").and_then(|v| v.first()).map(String::as_str) {
        Some("policy") => "policy",
        _ => "test",
    };

    let mut updates: Vec<(&str, String)> = vec![
        ("offline_threshold",            threshold.to_string()),
        ("auto_prune_inactive",          auto_prune.to_string()),
        ("compliance_sat",               sat.to_string()),
        ("compliance_marginal",          marginal.to_string()),
        ("policy_compliance_mode",       policy_mode.to_string()),
        ("system_compliance_mode",       system_mode.to_string()),
        ("audit_log_retention_days",     audit_keep.to_string()),
        ("report_retention_days",        report_keep.to_string()),
        ("notification_retention_days",  notify_keep.to_string()),
        ("container_retention_days",     container_keep.to_string()),
        ("entity_trend_retention_days",  entity_trend_keep.to_string()),
        ("fleet_trend_retention_days",   fleet_trend_keep.to_string()),
    ];

    // Email settings — superuser only
    if UserRole::from(auth.role.as_str()) >= UserRole::Superuser {
        let smtp_host     = form_data.get("smtp_host").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_port_raw = form_data.get("smtp_port").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_username = form_data.get("smtp_username").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_password = form_data.get("smtp_password").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_from     = form_data.get("smtp_from").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_tls      = form_data.get("smtp_tls").and_then(|v| v.first()).cloned().unwrap_or_default();
        let app_url       = form_data.get("app_url").and_then(|v| v.first()).cloned().unwrap_or_default();

        let smtp_port: String = match smtp_port_raw.parse::<u16>() {
            Ok(p) if p >= 1 => p.to_string(),
            _ => "587".to_string(),
        };

        updates.extend([
            ("smtp_host",     smtp_host),
            ("smtp_port",     smtp_port),
            ("smtp_username", smtp_username),
            ("smtp_from",     smtp_from),
            ("smtp_tls",      smtp_tls),
            ("app_url",       app_url),
        ]);

        if !smtp_password.is_empty() {
            updates.push(("smtp_password", smtp_password));
        }

        // SaaS-only platform toggle (superuser, global). Checkbox: present in
        // the form only when checked, so absence means "off". Gated on
        // is_saas_mode() so the key never appears in CE deployments.
        if crate::handlers::is_saas_mode() {
            let notify = if form_data.contains_key("notify_new_tenant") { "1" } else { "0" };
            updates.push(("notify_new_tenant", notify.to_string()));

            // Dormant-tenant sweep. 0 disables it; anything else must be a
            // sane number of days. The warning lead is clamped below the
            // threshold so a warning cannot be scheduled after the suspension
            // it is meant to precede.
            let num = |k: &str, dflt: i64| -> i64 {
                form_data.get(k).and_then(|v| v.first())
                    .and_then(|v| v.parse().ok()).unwrap_or(dflt)
            };
            let unverified = num("dormant_unverified_days", 0).clamp(0, 3650);
            let unused     = num("dormant_unused_days", 0).clamp(0, 3650);
            // Clamp the warning lead below the shorter active threshold so a
            // warning can never be scheduled after the action it precedes.
            let shortest = [unused].into_iter().filter(|d| *d > 0).min().unwrap_or(0);
            let warn_days = num("dormant_warn_days", 14).clamp(0, (shortest - 1).max(0));
            updates.push(("dormant_unverified_days", unverified.to_string()));
            updates.push(("dormant_unused_days",     unused.to_string()));
            updates.push(("dormant_warn_days",       warn_days.to_string()));
        }
    }

    // Keys stored globally under the 'default' tenant rather than per-tenant.
    const GLOBAL_KEYS: &[&str] = &[
        "smtp_host", "smtp_port", "smtp_username", "smtp_password",
        "smtp_from", "smtp_tls", "app_url",
        "notify_new_tenant",
    ];

    for (key, value) in updates {
        // SMTP + SaaS platform settings are global — stored under default tenant
        let tenant = if GLOBAL_KEYS.contains(&key) { "default" } else { &auth.tenant_id };
        if let Err(e) = sqlx::query(
            "INSERT INTO settings (tenant_id, skey, value)
     VALUES (?, ?, ?)
     ON CONFLICT (tenant_id, skey) DO UPDATE SET value = excluded.value"
        )
        .bind(tenant)
        .bind(key)
        .bind(&value)
        .execute(&pool)
        .await
        {
            let encoded = urlencoding::encode(&format!("Error saving setting {}: {}", key, e)).to_string();
            return Redirect::to(&format!("/settings?error_message={}", encoded)).into_response();
        }
    }

    // Recompute stored compliance aggregates — the policy/system compliance
    // toggles (and the SAT/MARGINAL thresholds) change how dashboard / list
    // scores are derived, so signal the sync worker to recalculate.
    let _ = sync_tx.try_send(());

    info!("Settings updated by '{}'.", auth.username);
    Redirect::to("/settings?success_message=Settings+saved+successfully").into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/test-email
// Send a test email to the logged-in user's address via the configured SMTP.
// Role: Superuser
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TestEmailResponse {
    pub ok:      bool,
    pub message: String,
}

pub async fn settings_test_email(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
) -> (StatusCode, Json<TestEmailResponse>) {
    if auth::authorize(&auth.role, UserRole::Superuser).is_some() {
        return (StatusCode::FORBIDDEN, Json(TestEmailResponse {
            ok: false,
            message: "Access denied.".into(),
        }));
    }

    // Recipient: logged-in user's email address (looked up from DB)
    let to: String = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT email FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(auth.userid)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None)
    .flatten()
    .filter(|e| !e.is_empty()) {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(TestEmailResponse {
            ok: false,
            message: "Your account has no email address. Edit your profile and add one first.".into(),
        })),
    };

    // SMTP settings are global — always read from the default tenant
    let rows = sqlx::query(
        "SELECT skey, value FROM settings WHERE tenant_id = 'default'
         AND skey IN ('smtp_host','smtp_port','smtp_username','smtp_password','smtp_from','smtp_tls','app_url')"
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let mut map = std::collections::HashMap::new();
    for row in rows {
        let k: String = row.get("skey");
        let v: String = row.get("value");
        map.insert(k, v);
    }

    let host = map.get("smtp_host").cloned().unwrap_or_default();
    if host.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(TestEmailResponse {
            ok: false,
            message: "SMTP Host is not configured. Save your settings first.".into(),
        }));
    }

    let port: u16 = map.get("smtp_port").and_then(|v| v.parse().ok()).unwrap_or(587);
    let username  = map.get("smtp_username").cloned().unwrap_or_default();
    let password  = map.get("smtp_password").cloned().unwrap_or_default();
    let from      = map.get("smtp_from").cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("OpenSCM <noreply@{}>", host));
    let tls_mode  = map.get("smtp_tls").cloned().unwrap_or_else(|| "starttls".into());

    // Build transport using the shared email module helper
    let transport = match crate::email::build_transport(&host, port, &tls_mode, &username, &password) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(TestEmailResponse {
            ok: false,
            message: format!("Failed to create SMTP transport: {}", e),
        })),
    };

    // Build and send a test message
    use lettre::{AsyncTransport, Message, message::header::ContentType};
    let message = match Message::builder()
        .from(from.parse().unwrap_or_else(|_| "OpenSCM <noreply@openscm.io>".parse().unwrap()))
        .to(match to.parse() {
            Ok(m) => m,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(TestEmailResponse {
                ok: false,
                message: format!("Invalid recipient address: {}", e),
            })),
        })
        .subject("OpenSCM — SMTP Test Email")
        .header(ContentType::TEXT_HTML)
        .body("<p>This is a test email from <strong>OpenSCM</strong>.</p><p>Your SMTP relay is configured correctly.</p>".to_string())
    {
        Ok(m) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(TestEmailResponse {
            ok: false,
            message: format!("Failed to build email: {}", e),
        })),
    };

    match transport.send(message).await {
        Ok(_) => {
            info!("Test email sent to {} by '{}'", to, auth.username);
            (StatusCode::OK, Json(TestEmailResponse {
                ok: true,
                message: format!("Test email sent successfully to {}.", to),
            }))
        }
        Err(e) => {
            error!("Test email failed for '{}': {}", auth.username, e);
            (StatusCode::BAD_GATEWAY, Json(TestEmailResponse {
                ok: false,
                message: format!("SMTP error: {}", e),
            }))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/reset
// Wipe all tenant operational data; requires the literal "RESET" confirmation.
// Role: Superuser
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ResetForm {
    confirm: String,
}

pub async fn settings_reset(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    Form(form): Form<ResetForm>,
) -> impl IntoResponse {
    // Admin or higher. The reset is always scoped to the caller's own tenant
    // via `auth.tenant_id` below — an Admin can only wipe their own tenant,
    // and the Superuser-of-default-tenant case (CE single-tenant + SaaS
    // platform admin) keeps working unchanged because Superuser > Admin.
    if auth::authorize(&auth.role, UserRole::Admin).is_some() {
        return Redirect::to("/settings?error_message=Access+denied").into_response();
    }

    // Require exact confirmation token
    if form.confirm.trim() != "RESET" {
        return Redirect::to("/settings?error_message=Confirmation+text+did+not+match").into_response();
    }

    let tenant = &auth.tenant_id;

    let result: Result<(), sqlx::Error> = async {
        let mut tx = pool.begin().await?;

        // Delete all operational data for this tenant, preserving:
        //   - users WHERE id = 1 AND tenant_id = 'default'  (bootstrap admin)
        //   - settings                                       (SMTP config, thresholds)
        //   - tenant_keys WHERE tenant_id = 'default'        (default tenant signing keys only)
        //   - schema_info                                    (migration state)

        // Dependent tables first (foreign keys with ON DELETE CASCADE handle most,
        // but we delete explicitly to be safe with all SQLite pragma states).
        for sql in &[
            // Results & history
            format!("DELETE FROM results            WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM compliance_history WHERE tenant_id = '{tenant}'"),
            // Reports
            format!("DELETE FROM system_reports     WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM reports            WHERE tenant_id = '{tenant}'"),
            // Scheduler
            format!("DELETE FROM policy_schedules   WHERE tenant_id = '{tenant}'"),
            // Policy / test relations
            format!("DELETE FROM tests_in_policy    WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM test_conditions    WHERE tenant_id = '{tenant}'"),
            // System relations
            format!("DELETE FROM systems_in_policy  WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM systems_in_groups  WHERE tenant_id = '{tenant}'"),
            // Top-level entities
            format!("DELETE FROM policies           WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM tests              WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM system_groups      WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM systems            WHERE tenant_id = '{tenant}'"),
            // Notifications
            format!("DELETE FROM notify             WHERE tenant_id = '{tenant}'"),
            // Auth tokens (base schema — present in all editions)
            format!("DELETE FROM email_verifications WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM password_resets     WHERE user_id IN (SELECT id FROM users WHERE tenant_id = '{tenant}')"),
            // Users — keep bootstrap admin (id=1, default tenant)
            format!("DELETE FROM users WHERE tenant_id = '{tenant}' AND NOT (id = 1 AND tenant_id = 'default')"),
            // Tenant keys — keep only default tenant keys
            "DELETE FROM tenant_keys WHERE tenant_id != 'default'".to_string(),
        ] {
            sqlx::query(sql).execute(&mut *tx).await?;
        }

        tx.commit().await
    }.await;

    match result {
        Ok(_) => {
            info!(
                "Database reset performed by superuser '{}' (tenant: {})",
                auth.username, auth.tenant_id
            );
            Redirect::to("/settings?success_message=Database+cleaned+successfully").into_response()
        }
        Err(e) => {
            error!("Database reset failed for '{}': {}", auth.username, e);
            let msg = urlencoding::encode(&format!("Reset failed: {}", e)).to_string();
            Redirect::to(&format!("/settings?error_message={}", msg)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/rotate-keys
// Generate a new Ed25519 keypair for the caller's tenant, deactivate the old
// one, and insert the new one as the active key.
// All agents currently registered to this tenant will fail signature
// verification on their next heartbeat and automatically re-enrol.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn settings_rotate_keys(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if auth::authorize(&auth.role, UserRole::Admin).is_some() {
        return Redirect::to("/settings?error_message=Access+denied").into_response();
    }

    let mut csprng = OsRng;
    let signing_key  = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let private_b64  = general_purpose::STANDARD.encode(signing_key.to_bytes());
    let public_b64   = general_purpose::STANDARD.encode(verifying_key.to_bytes());

    let result: Result<(), sqlx::Error> = async {
        // Deactivate all current keys for this tenant
        sqlx::query("UPDATE tenant_keys SET is_active = 0 WHERE tenant_id = ?")
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await?;

        // Insert the new active key
        sqlx::query(
            "INSERT INTO tenant_keys (tenant_id, public_key, private_key, is_active) VALUES (?, ?, ?, 1)",
        )
        .bind(&auth.tenant_id)
        .bind(&public_b64)
        .bind(&private_b64)
        .execute(&pool)
        .await?;

        Ok(())
    }.await;

    match result {
        Ok(_) => {
            info!(
                "Signing key rotated by '{}' (tenant: {})", auth.username, auth.tenant_id
            );
            crate::audit::record(
                &pool,
                &auth.tenant_id,
                Some(&auth),
                Some(ip.as_str()),
                "tenant.key_rotated",
                Some("tenant"),
                Some(auth.tenant_id.as_str()),
                Some(&format!("{{\"new_fingerprint\":\"{}\"}}", &public_b64[..public_b64.len().min(24)])),
            ).await;
            Redirect::to("/settings?success_message=Signing+key+rotated+successfully.+All+agents+will+re-enrol+on+next+heartbeat.#danger").into_response()
        }
        Err(e) => {
            error!("Key rotation failed for tenant '{}': {}", auth.tenant_id, e);
            let msg = urlencoding::encode(&format!("Key rotation failed: {}", e)).to_string();
            Redirect::to(&format!("/settings?error_message={}", msg)).into_response()
        }
    }
}
