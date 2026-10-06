// =============================================================================
// plan.rs — per-plan resource limits (SaaS)
//
// A tenant's plan caps how many systems, policies and saved reports it may
// have (plan_limits, seeded by the SaaS binary). The SaaS request middleware
// enforces the caps on the ordinary "create" routes, but several things create
// these resources without passing through a route it watches: the scheduler
// saving a report, a policy arriving by import or from the policy store, a
// system approved by an enrollment token. Each of those asks here instead.
//
// In Community Edition plan_limits exists but is empty, so nothing is ever
// limited.
// =============================================================================

use sqlx::{SqliteConnection, SqlitePool};
use tracing::warn;

/// A tenant has as many of a resource as its plan allows.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitReached {
    pub plan:     String,
    pub resource: &'static str,
    pub limit:    i64,
    pub count:    i64,
}

impl LimitReached {
    // ─────────────────────────────────────────────────────────────────────────
    // message
    // The sentence shown to the user — the same wording wherever a limit stops
    // something.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn message(&self) -> String {
        format!(
            "Plan limit reached: your {} plan allows {} {}. Upgrade to add more.",
            self.plan, self.limit, self.resource
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: limit_reached
// Some(..) when the tenant already has as many of `resource` ("systems",
// "policies" or "reports") as its plan allows; None when there is room, the
// plan has no cap (0 or no row), or the resource is not a limited one.
//
// Takes a connection so it can run inside the caller's transaction and see
// rows that transaction has already written.
//
// What counts: ACTIVE systems (pending ones are not yet using the plan), every
// policy, every saved policy report.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn limit_reached(
    conn: &mut SqliteConnection,
    tenant_id: &str,
    resource: &str,
) -> Option<LimitReached> {
    let (resource, count_sql): (&'static str, &str) = match resource {
        "systems"  => ("systems",  "SELECT COUNT(*) FROM systems  WHERE tenant_id = ? AND status = 'active'"),
        "policies" => ("policies", "SELECT COUNT(*) FROM policies WHERE tenant_id = ?"),
        "reports"  => ("reports",  "SELECT COUNT(*) FROM reports  WHERE tenant_id = ?"),
        _ => return None,
    };

    let plan: String = sqlx::query_scalar("SELECT COALESCE(plan, 'free') FROM tenants WHERE id = ?")
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "free".to_string());

    // No row, or 0, means unlimited.
    let limit: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max_count, 0) FROM plan_limits WHERE plan = ? AND resource = ?",
    )
    .bind(&plan)
    .bind(resource)
    .fetch_optional(&mut *conn)
    .await
    .ok()
    .flatten()
    .unwrap_or(0);
    if limit <= 0 {
        return None;
    }

    let count: i64 = sqlx::query_scalar(count_sql)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or(0);

    (count >= limit).then_some(LimitReached { plan, resource, limit, count })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: limit_reached_pool
// limit_reached for callers that are not inside a transaction.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn limit_reached_pool(
    pool: &SqlitePool,
    tenant_id: &str,
    resource: &str,
) -> Option<LimitReached> {
    let mut conn = pool.acquire().await.ok()?;
    limit_reached(&mut conn, tenant_id, resource).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: notify_admins_once
// Tells the tenant's administrators something they need to act on, without
// repeating it: an administrator who still has the identical notification
// unread is not sent another. A background event (a daily scheduled report, a
// fleet of agents enrolling) would otherwise fill the bell with copies.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn notify_admins_once(pool: &SqlitePool, tenant_id: &str, level: &str, message: &str) {
    let admins: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = ? AND role IN ('admin', 'superuser')",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for owner in admins {
        let already: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notify WHERE tenant_id = ? AND owner_id = ? AND message = ?",
        )
        .bind(tenant_id)
        .bind(owner)
        .bind(message)
        .fetch_one(pool)
        .await
        .unwrap_or(0);
        if already == 0 {
            crate::handlers::add_notification(pool, tenant_id, level, owner, message).await;
        }
    }
    warn!("[{}] {}", tenant_id, message);
}
