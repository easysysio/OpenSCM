// =============================================================================
// audit.rs — immutable record of state-changing admin actions
//
// Every handler that mutates a row that an auditor would later want to ask
// "who did this?" calls `audit::record(...).await` exactly once. The call is
// fire-and-forget: a DB error during the audit write is logged via tracing
// but never propagated, because failing the audit must not fail the request
// being audited.
//
// The audit_log table and its retention setting (settings.audit_log_retention_days)
// are introduced by schema migration v19 → v20. The actual retention-cleanup
// scheduler tick lives in Task #9 (data retention / cleanup policy).
// =============================================================================

use axum::extract::{Extension, Query};
use axum::response::IntoResponse;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use tera::{Tera, Context};
use tracing::error;

use crate::auth;
use crate::handlers::render_template;
use crate::models::{AuditEntry, AuthSession, UserRole};

// ─────────────────────────────────────────────────────────────────────────────
// record
// Writes one audit_log row. `details` is a JSON object (or None): the type
// keeps plain text out, so the API can serve every new entry as an object.
// Swallows DB errors so the request being audited
// can never fail because of a logging side-effect. Pass actor=None for events
// triggered without an authenticated session (e.g. a failed login attempt
// before AuthSession exists, or a background scheduler job).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record(
    pool:        &SqlitePool,
    tenant_id:   &str,
    actor:       Option<&AuthSession>,
    ip_address:  Option<&str>,
    action:      &str,
    target_type: Option<&str>,
    target_id:   Option<&str>,
    details:     Option<serde_json::Value>,
) {
    let (actor_user_id, actor_username): (Option<i32>, &str) = match actor {
        Some(s) => (Some(s.userid), s.username.as_str()),
        None    => (None,           "system"),
    };
    record_raw(pool, tenant_id, actor_user_id, actor_username,
               ip_address, action, target_type, target_id, details).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// record_raw
// Lower-level primitive for events where there is no AuthSession yet —
// e.g. a failed login attempt that still needs to record the attempted
// username, or a background scheduler event with no human actor at all.
// Pass actor_user_id=None + actor_username="system" for daemon-originated.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record_raw(
    pool:           &SqlitePool,
    tenant_id:      &str,
    actor_user_id:  Option<i32>,
    actor_username: &str,
    ip_address:     Option<&str>,
    action:         &str,
    target_type:    Option<&str>,
    target_id:      Option<&str>,
    details:        Option<serde_json::Value>,
) {
    let res = sqlx::query(
        "INSERT INTO audit_log
            (tenant_id, actor_user_id, actor_username, action,
             target_type, target_id, details, ip_address)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(actor_username)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details.map(|d| d.to_string()))
    .bind(ip_address)
    .execute(pool)
    .await;

    if let Err(e) = res {
        error!(
            "audit_log write failed (action={}, tenant={}, target={:?}): {}",
            action, tenant_id, target_id, e
        );
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/audit-log
// Read-only paginated viewer of recent audit_log rows for the caller's tenant.
// Admin role only. No filters in v1 — just the last N rows ordered newest-first.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct AuditQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

pub async fn audit_log_view(
    auth: AuthSession,
    Query(q): Query<AuditQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir.into_response();
    }

    let per_page = q.per_page.unwrap_or(100).clamp(10, 500);
    let page     = q.page.unwrap_or(1).max(1);
    let offset   = (page - 1) * per_page;

    // Superusers see across all tenants — needed in SaaS where the platform
    // admin debugs customer incidents from the `default` tenant and would
    // otherwise have no visibility into customer-tenant events. Regular
    // Admins stay scoped to their own tenant.
    let cross_tenant = UserRole::from(auth.role.as_str()) >= UserRole::Superuser;

    let entries: Vec<AuditEntry> = if cross_tenant {
        sqlx::query_as(
            "SELECT id, tenant_id, actor_user_id, actor_username, action,
                    target_type, target_id, details, ip_address, created_at
             FROM audit_log
             ORDER BY id DESC
             LIMIT ? OFFSET ?",
        )
        .bind(per_page as i64)
        .bind(offset as i64)
        .fetch_all(&pool)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_as(
            "SELECT id, tenant_id, actor_user_id, actor_username, action,
                    target_type, target_id, details, ip_address, created_at
             FROM audit_log
             WHERE tenant_id = ?
             ORDER BY id DESC
             LIMIT ? OFFSET ?",
        )
        .bind(&auth.tenant_id)
        .bind(per_page as i64)
        .bind(offset as i64)
        .fetch_all(&pool)
        .await
        .unwrap_or_default()
    };

    let total: i64 = if cross_tenant {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&pool).await.unwrap_or(0)
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?")
            .bind(&auth.tenant_id).fetch_one(&pool).await.unwrap_or(0)
    };

    let retention_days: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings
         WHERE tenant_id = ? AND skey = 'audit_log_retention_days'",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(730);

    let total_pages = ((total as u32) + per_page - 1) / per_page.max(1);

    let mut ctx = Context::new();
    ctx.insert("entries",        &entries);
    ctx.insert("total",          &total);
    ctx.insert("page",           &page);
    ctx.insert("per_page",       &per_page);
    ctx.insert("total_pages",    &total_pages);
    ctx.insert("retention_days", &retention_days);
    ctx.insert("cross_tenant",   &cross_tenant);

    render_template(&tera, Some(&pool), "audit_log.html", ctx, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// prune
// Per-tenant cleanup of audit_log rows older than the tenant's
// audit_log_retention_days setting. Tenants whose retention is 0 (or missing)
// are skipped — 0 means "keep forever" per the settings UI.
//
// The prune itself records one audit_log row per tenant that had rows
// deleted (action "audit.prune") so the cleanup is itself auditable. If a
// tenant's prune SQL fails the loop continues to the next tenant — one
// noisy tenant must not break maintenance for the rest.
//
// Called once per day from the scheduler's main heartbeat loop.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn prune(pool: &SqlitePool) {
    let tenants: Vec<(String, i64)> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT tenant_id, CAST(value AS INTEGER) FROM settings
         WHERE skey = 'audit_log_retention_days' AND CAST(value AS INTEGER) > 0",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("audit prune: failed to fetch retention settings: {}", e);
            return;
        }
    };

    for (tenant_id, days) in tenants {
        let res = sqlx::query(
            "DELETE FROM audit_log
             WHERE tenant_id = ?
               AND created_at < datetime('now', '-' || ? || ' days')",
        )
        .bind(&tenant_id)
        .bind(days)
        .execute(pool)
        .await;

        match res {
            Ok(r) if r.rows_affected() > 0 => {
                let removed = r.rows_affected();
                tracing::info!(
                    "audit prune: removed {} row(s) older than {} day(s) for tenant '{}'.",
                    removed, days, tenant_id
                );
                // Record the cleanup itself so auditors can answer
                // "why did the audit log get shorter overnight?".
                record_raw(
                    pool, &tenant_id,
                    None, "system",
                    None,
                    "audit.prune",
                    Some("audit_log"), None,
                    Some(serde_json::json!({"removed": removed, "retention_days": days})),
                ).await;
            }
            Ok(_) => {}  // nothing to prune today
            Err(e) => error!(
                "audit prune: delete failed for tenant '{}': {}", tenant_id, e
            ),
        }
    }
}
