// =============================================================================
// scheduler.rs — background compliance aggregation and policy scheduler
//
// Spawned once at startup. Main loop ticks every 60 seconds:
//   Task A — fires any policy scan/report schedules that are due.
//   Task B — records hourly compliance history snapshots.
//   Task C — checks GitHub for new releases once per hour.
// =============================================================================

use sqlx::{SqlitePool, Row};
use tokio::time::{self, Duration};
use chrono::{Utc, Timelike, Datelike};
use tracing::{info, warn, error};
use reqwest::Client;

use crate::models::PolicySchedule;
use crate::policies::execute_policy_run_logic;
use crate::handlers::add_notification;
use crate::reports::save_policy_report_logic;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: calculate_next_run
// Adds the schedule frequency interval to a planned run time string.
// ─────────────────────────────────────────────────────────────────────────────
fn calculate_next_run(frequency: &str, last_planned_run: &str) -> String {
    let current = chrono::NaiveDateTime::parse_from_str(last_planned_run, "%Y-%m-%dT%H:%M")
        .unwrap_or_else(|_| Utc::now().naive_utc());

    let next = match frequency {
        "daily"    => current + chrono::Duration::days(1),
        "weekly"   => current + chrono::Duration::weeks(1),
        "biweekly" => current + chrono::Duration::days(14),
        "monthly"  => current + chrono::Duration::days(30),
        _          => current + chrono::Duration::days(1),
    };

    next.format("%Y-%m-%dT%H:%M").to_string()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: get_policy_owners
// Returns all Admin-or-higher user IDs for a tenant (used to send schedule
// notifications). Matches both `admin` and `superuser` — without superuser
// the bootstrap admin on a fresh CE install (role = 'superuser', see
// install.rs) is silently excluded and scheduled-report notifications go
// nowhere.
// ─────────────────────────────────────────────────────────────────────────────
async fn get_policy_owners(pool: &SqlitePool, tenant_id: &str) -> Vec<i32> {
    sqlx::query(
        "SELECT id FROM users WHERE tenant_id = ? AND role IN ('admin', 'superuser')",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|row| row.get("id"))
    .collect()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: purge_ghost_results
// Deletes result rows for (system, test) pairs that are no longer reachable via
// the current policy → group → system assignment graph.
// Must be called inside an active transaction.
// ─────────────────────────────────────────────────────────────────────────────
async fn purge_ghost_results(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: Option<&str>,
) -> Result<(), sqlx::Error> {
    // When `tenant` is Some, restrict the purge to that tenant's results.
    // Correctness is unaffected by scoping: the NOT EXISTS subquery only ever
    // joins rows within the same tenant (sig.tenant_id = results.tenant_id),
    // so a tenant's ghost results can only be determined by that tenant's own
    // group/policy/test wiring.
    let clause = if tenant.is_some() { " AND results.tenant_id = ?" } else { "" };
    let sql = format!(r#"
        DELETE FROM results
        WHERE NOT EXISTS (
            SELECT 1
            FROM systems_in_groups sig
            JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                AND sig.tenant_id = sip.tenant_id
            JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
                AND sip.tenant_id = tip.tenant_id
            WHERE sig.system_id = results.system_id
              AND tip.test_id   = results.test_id
              AND sig.tenant_id = results.tenant_id
        ){}
    "#, clause);
    let mut q = sqlx::query(&sql);
    if let Some(t) = tenant { q = q.bind(t); }
    q.execute(&mut **tx).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: update_test_stats
// Recalculates systems_passed, systems_failed, and compliance_score for every
// test, counting only active systems.
// Must be called inside an active transaction.
// ─────────────────────────────────────────────────────────────────────────────
async fn update_test_stats(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: Option<&str>,
) -> Result<(), sqlx::Error> {
    // The NOT EXISTS clause treats excluded (system, test) pairs as if the
    // result row didn't exist — matches the live-report rendering.
    // Scoping: each test's stats are computed purely from its own tenant's
    // results (r.tenant_id = tests.tenant_id), so a per-tenant WHERE on the
    // outer UPDATE is correct and just limits which test rows get rewritten.
    let clause = if tenant.is_some() { " WHERE tenant_id = ?" } else { "" };
    let sql = format!(r#"
        UPDATE tests SET
            systems_passed = (
                SELECT COUNT(*) FROM results r
                JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
                WHERE r.test_id    = tests.id
                  AND r.tenant_id  = tests.tenant_id
                  AND r.result     = 'PASS'
                  AND s.status     = 'active'
                  AND r.excluded = 0
                  AND r.container_id = 0
            ),
            systems_failed = (
                SELECT COUNT(*) FROM results r
                JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
                WHERE r.test_id    = tests.id
                  AND r.tenant_id  = tests.tenant_id
                  AND r.result     = 'FAIL'
                  AND s.status     = 'active'
                  AND r.excluded = 0
                  AND r.container_id = 0
            ),
            compliance_score = (
                SELECT CASE WHEN COUNT(*) = 0 THEN -1.0
                ELSE (CAST(SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100
                END
                FROM results r
                JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
                WHERE r.test_id   = tests.id
                  AND r.tenant_id = tests.tenant_id
                  AND s.status    = 'active'
                  AND r.result    != 'NA'
                  AND r.excluded = 0
                  AND r.container_id = 0
            )
        {}
    "#, clause);
    let mut q = sqlx::query(&sql);
    if let Some(t) = tenant { q = q.bind(t); }
    q.execute(&mut **tx).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: update_system_stats
// Recalculates tests_passed, tests_failed, total_tests, and compliance_score
// for every active system. tests_* are always raw test tallies. The
// compliance_score honours the tenant's `system_compliance_mode` (0.6.5):
//   • "test"   — % of the system's tests that passed (PASS / (PASS + FAIL)).
//   • "policy" — % of the system's assigned policies it fully passes. A system
//                "passes" a policy iff it has no FAIL and ≥1 PASS among that
//                policy's tests; applicable policies = those with ≥1 PASS/FAIL.
//                So one assigned policy with any failing test → 0%.
// Must be called inside an active transaction, after update_test_stats.
// ─────────────────────────────────────────────────────────────────────────────
async fn update_system_stats(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: Option<&str>,
) -> Result<(), sqlx::Error> {
    // Excluded (system, test) pairs are treated as if their result row didn't
    // exist — they don't contribute to PASS, FAIL, total, or score.
    // Scoping appends to the existing `WHERE status = 'active'`.
    let clause = if tenant.is_some() { " AND tenant_id = ?" } else { "" };
    // SYSTEM compliance mode for the system's tenant: 'policy' → per-policy
    // (binary), else per-test. Default 'test'.
    let mode = "COALESCE((SELECT value FROM settings \
                WHERE tenant_id = systems.tenant_id AND skey = 'system_compliance_mode'), 'test')";

    // Per-test score: % of the system's own tests that passed.
    let test_expr = "SELECT CASE WHEN COUNT(*) = 0 THEN -1.0 \
        ELSE (CAST(SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100 END \
        FROM results r WHERE r.system_id = systems.id AND r.tenant_id = systems.tenant_id \
          AND r.result != 'NA' AND r.excluded = 0 AND r.container_id = 0";

    // Per-policy score: % of the system's assigned policies it fully passes
    // (no FAIL, ≥1 PASS) among applicable policies (≥1 PASS/FAIL).
    let policy_expr = "SELECT CASE WHEN COUNT(*) = 0 THEN -1.0 \
        ELSE CAST(SUM(CASE WHEN p_fail = 0 AND p_pass > 0 THEN 1 ELSE 0 END) AS REAL) * 100 / COUNT(*) END \
        FROM ( \
            SELECT sip.policy_id, \
                SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) AS p_pass, \
                SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) AS p_fail \
            FROM systems_in_groups sig \
            JOIN systems_in_policy sip ON sip.group_id = sig.group_id AND sip.tenant_id = sig.tenant_id \
            JOIN tests_in_policy tip ON tip.policy_id = sip.policy_id AND tip.tenant_id = sip.tenant_id \
            LEFT JOIN results r ON r.system_id = systems.id AND r.test_id = tip.test_id \
                AND r.tenant_id = systems.tenant_id AND r.excluded = 0 AND r.container_id = 0 \
            WHERE sig.system_id = systems.id AND sig.tenant_id = systems.tenant_id \
            GROUP BY sip.policy_id \
            HAVING SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) > 0 \
                OR SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) > 0 \
        ) per_policy";

    let sql = format!(r#"
        UPDATE systems SET
            tests_passed = (
                SELECT COUNT(*) FROM results r
                WHERE r.system_id = systems.id
                  AND r.tenant_id = systems.tenant_id
                  AND r.result    = 'PASS'
                  AND r.excluded = 0
                  AND r.container_id = 0
            ),
            tests_failed = (
                SELECT COUNT(*) FROM results r
                WHERE r.system_id = systems.id
                  AND r.tenant_id = systems.tenant_id
                  AND r.result    = 'FAIL'
                  AND r.excluded = 0
                  AND r.container_id = 0
            ),
            total_tests = (
                SELECT COUNT(*) FROM results r
                WHERE r.system_id = systems.id
                  AND r.tenant_id = systems.tenant_id
                  AND r.excluded = 0
                  AND r.container_id = 0
            ),
            score_test   = ({test_expr}),
            score_policy = ({policy_expr}),
            compliance_score = (
                CASE WHEN {mode} = 'policy' THEN ({policy_expr}) ELSE ({test_expr}) END
            )
        WHERE status = 'active'{clause}
    "#, mode = mode, test_expr = test_expr, policy_expr = policy_expr, clause = clause);
    let mut q = sqlx::query(&sql);
    if let Some(t) = tenant { q = q.bind(t); }
    q.execute(&mut **tx).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: update_policy_stats
// MODE-AWARE compliance (0.6.5). Each policy's score honours its tenant's
// `policy_compliance_mode` setting (Settings → Compliance):
//   • "system" — % of systems fully compliant (no FAIL, ≥1 PASS) among scanned
//                systems. systems_passed/_failed = compliant / failed SYSTEMS.
//   • "test"   — % of individual test results that passed
//                (total PASS / (PASS + FAIL)). systems_passed/_failed = total
//                PASS / FAIL TESTS. (default)
// Both derive from one per-system aggregation (passes/fails per system); the
// mode is read per policy's tenant via a correlated settings lookup, so a
// single statement handles a fleet of mixed-mode tenants. Column names retained
// for schema stability; displayed under the generic "Pass/Fail" header.
// NA and excluded results stay out of both numerator and denominator.
// Must be called inside an active transaction, after update_system_stats.
// ─────────────────────────────────────────────────────────────────────────────
async fn update_policy_stats(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: Option<&str>,
) -> Result<(), sqlx::Error> {
    // Each policy's stats derive only from its own tenant's systems/results
    // (every JOIN carries tenant_id), so a per-tenant outer WHERE is correct.
    let clause = if tenant.is_some() { " WHERE tenant_id = ?" } else { "" };

    // POLICY compliance mode for the policy's tenant: 'system' → per-system
    // (binary), else per-test. Default 'test'.
    let mode = "COALESCE((SELECT value FROM settings \
                WHERE tenant_id = policies.tenant_id AND skey = 'policy_compliance_mode'), 'test')";

    // Per-system PASS/FAIL aggregation for the policy's active in-scope systems.
    // LEFT JOIN so a scanned-but-resultless system still appears (passes=fails=0)
    // and is correctly treated as out-of-scope by both modes.
    let per_system = r#"
        SELECT s.id AS sysid,
            SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) AS passes,
            SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) AS fails
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            AND sip.tenant_id = sig.tenant_id
        JOIN systems s ON sig.system_id = s.id
            AND sig.tenant_id = s.tenant_id
        LEFT JOIN results r ON r.system_id = s.id
            AND r.tenant_id = s.tenant_id
            AND r.test_id IN (
                SELECT test_id FROM tests_in_policy
                WHERE policy_id = policies.id AND tenant_id = policies.tenant_id
            )
            AND r.excluded = 0
            AND r.container_id = 0
        WHERE sip.policy_id = policies.id
          AND sip.tenant_id = policies.tenant_id
          AND s.status = 'active'
        GROUP BY s.id
    "#;

    let sql = format!(r#"
        UPDATE policies SET
            systems_passed = (
                SELECT CASE WHEN {mode} = 'system'
                    THEN COUNT(CASE WHEN passes > 0 AND fails = 0 THEN 1 END)
                    ELSE COALESCE(SUM(passes), 0) END
                FROM ({ps}) sub
            ),
            systems_failed = (
                SELECT CASE WHEN {mode} = 'system'
                    THEN COUNT(CASE WHEN fails > 0 THEN 1 END)
                    ELSE COALESCE(SUM(fails), 0) END
                FROM ({ps}) sub
            ),
            score_test = (
                SELECT CASE WHEN COALESCE(SUM(passes),0) + COALESCE(SUM(fails),0) = 0 THEN -1.0
                            ELSE CAST(SUM(passes) AS REAL) * 100 / (SUM(passes) + SUM(fails)) END
                FROM ({ps}) sub
            ),
            score_system = (
                SELECT CASE WHEN COUNT(CASE WHEN passes > 0 OR fails > 0 THEN 1 END) = 0 THEN -1.0
                            ELSE CAST(COUNT(CASE WHEN passes > 0 AND fails = 0 THEN 1 END) AS REAL) * 100
                                 / COUNT(CASE WHEN passes > 0 OR fails > 0 THEN 1 END) END
                FROM ({ps}) sub
            ),
            -- Container axis: mean compliance of containers that have at least one
            -- scored result for this policy's tests on an in-scope system. Used as
            -- the headline fallback for pure-container policies. -1.0 when none.
            score_container = (
                SELECT CASE WHEN COUNT(*) = 0 THEN -1.0 ELSE ROUND(AVG(c.compliance_score), 2) END
                FROM containers c
                WHERE c.tenant_id = policies.tenant_id
                  AND c.compliance_score >= 0
                  AND EXISTS (
                      SELECT 1 FROM results r
                      WHERE r.container_id = c.id AND r.tenant_id = c.tenant_id
                        AND r.excluded = 0 AND r.result != 'NA'
                        AND r.test_id IN (
                            SELECT test_id FROM tests_in_policy
                            WHERE policy_id = policies.id AND tenant_id = policies.tenant_id)
                        AND r.system_id IN (
                            SELECT sig.system_id FROM systems_in_groups sig
                            JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                                AND sig.tenant_id = sip.tenant_id
                            WHERE sip.policy_id = policies.id AND sip.tenant_id = policies.tenant_id)
                  )
            ),
            compliance_score = (
                SELECT CASE WHEN {mode} = 'system'
                    THEN (CASE WHEN COUNT(CASE WHEN passes > 0 OR fails > 0 THEN 1 END) = 0 THEN -1.0
                               ELSE CAST(COUNT(CASE WHEN passes > 0 AND fails = 0 THEN 1 END) AS REAL) * 100
                                    / COUNT(CASE WHEN passes > 0 OR fails > 0 THEN 1 END) END)
                    ELSE (CASE WHEN COALESCE(SUM(passes),0) + COALESCE(SUM(fails),0) = 0 THEN -1.0
                               ELSE CAST(SUM(passes) AS REAL) * 100
                                    / (SUM(passes) + SUM(fails)) END)
                END
                FROM ({ps}) sub
            )
        {clause}
    "#, mode = mode, ps = per_system, clause = clause);
    let mut q = sqlx::query(&sql);
    if let Some(t) = tenant { q = q.bind(t); }
    q.execute(&mut **tx).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: update_container_stats
// Per-container compliance on its OWN axis (separate from host/system scores —
// design §11). A container's score is the % of its own result rows that PASS
// among non-NA, non-excluded results (results.container_id = containers.id; the
// host axis uses container_id = 0). −1.0 ("Not Scanned") when the container has
// no applicable results yet. tests_passed/_failed are raw PASS/FAIL tallies.
// Must run inside the recalc transaction, after update_system_stats. Scoped to
// one tenant when `tenant` is Some — containers carry tenant_id like every row.
// ─────────────────────────────────────────────────────────────────────────────
async fn update_container_stats(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: Option<&str>,
) -> Result<(), sqlx::Error> {
    let clause = if tenant.is_some() { " WHERE tenant_id = ?" } else { "" };
    let sql = format!(r#"
        UPDATE containers SET
            tests_passed = (
                SELECT COUNT(*) FROM results r
                WHERE r.container_id = containers.id
                  AND r.tenant_id    = containers.tenant_id
                  AND r.result       = 'PASS'
                  AND r.excluded     = 0
            ),
            tests_failed = (
                SELECT COUNT(*) FROM results r
                WHERE r.container_id = containers.id
                  AND r.tenant_id    = containers.tenant_id
                  AND r.result       = 'FAIL'
                  AND r.excluded     = 0
            ),
            compliance_score = (
                SELECT CASE WHEN COUNT(*) = 0 THEN -1.0
                ELSE ROUND((CAST(SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100, 2)
                END
                FROM results r
                WHERE r.container_id = containers.id
                  AND r.tenant_id    = containers.tenant_id
                  AND r.result      != 'NA'
                  AND r.excluded     = 0
            )
        {clause}
    "#, clause = clause);
    let mut q = sqlx::query(&sql);
    if let Some(t) = tenant { q = q.bind(t); }
    q.execute(&mut **tx).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Enum: AlertMode
// Whether a recalculation may deliver alerts. BaselineOnly records the new
// scores as alert state without notifying anyone — see
// recalculate_current_compliance_at_startup.
// ─────────────────────────────────────────────────────────────────────────────
pub use crate::alerts::AlertMode;

// ─────────────────────────────────────────────────────────────────────────────
// Private: run_recalc
// Core aggregation. `tenant = None` recalculates every tenant (startup, manual
// sync_tx edits); `tenant = Some(id)` scopes all four passes to one tenant —
// used by the auto-group dirty-bit consumer so a single membership change
// doesn't trigger a full-fleet recompute across unrelated tenants.
//
// Tenant isolation is a hard boundary in the schema: every results / systems /
// policies / tests row carries tenant_id and all aggregation JOINs are
// tenant-local, so per-tenant scoping yields identical numbers to the global
// pass for that tenant — it just skips touching everyone else.
// ─────────────────────────────────────────────────────────────────────────────
async fn run_recalc(
    pool: &SqlitePool,
    tenant: Option<&str>,
    alerts: AlertMode,
) -> Result<(), sqlx::Error> {
    // Scores BEFORE the recalculation. This is the only moment the previous
    // value is still available, and alerting is entirely a comparison.
    let before = crate::alerts::snapshot_scores(pool, tenant).await;

    let mut tx = pool.begin().await?;

    purge_ghost_results(&mut tx, tenant).await?;
    update_test_stats(&mut tx, tenant).await?;
    update_system_stats(&mut tx, tenant).await?;
    update_container_stats(&mut tx, tenant).await?;
    update_policy_stats(&mut tx, tenant).await?;

    tx.commit().await?;

    // AFTER the commit, never inside the transaction: evaluation queues rows
    // and the delivery that follows is network I/O. Holding a SQLite write
    // transaction open across a hung webhook blocks every writer in the
    // process.
    let after = crate::alerts::snapshot_scores(pool, tenant).await;
    crate::alerts::evaluate_all(pool, tenant, &before, &after, alerts).await;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: recalculate_current_compliance
// Global recompute across all tenants.  Used on startup and by the manual
// sync_tx worker (group edits, policy edits, exclusions — which may touch any
// tenant the editing admin belongs to).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn recalculate_current_compliance(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    info!("Starting compliance aggregation (all tenants, active systems only)...");
    run_recalc(pool, None, AlertMode::Deliver).await?;
    info!("Compliance recalculation complete.");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: recalculate_current_compliance_for_tenant
// Single-tenant recompute.  Used by the auto-group dirty-bit consumer (TASK F)
// so membership churn in one tenant only recomputes that tenant's stats.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn recalculate_current_compliance_for_tenant(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<(), sqlx::Error> {
    run_recalc(pool, Some(tenant_id), AlertMode::Deliver).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: recalculate_current_compliance_at_startup
// The first recalculation after boot, which records alert baselines but
// delivers nothing.
//
// After a long outage this pass can move hundreds of scores at once — every
// one of them looking like a fresh excursion — and would fire an alert storm
// describing an outage the operator already knows about. Same failure shape as
// the prune_inactive_systems data loss fixed in 0.7.6: a restart is not an
// event, it is the absence of observation.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn recalculate_current_compliance_at_startup(
    pool: &SqlitePool,
) -> Result<(), sqlx::Error> {
    info!("Starting compliance aggregation (startup — alerts suppressed)...");
    run_recalc(pool, None, AlertMode::BaselineOnly).await?;
    info!("Compliance recalculation complete.");
    Ok(())
}




// ─────────────────────────────────────────────────────────────────────────────
// Helper: record_compliance_history
// Inserts one compliance_history row per tenant with current avg scores.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record_compliance_history(pool: &SqlitePool) -> Result<(), sqlx::Error> {

    // Get all active tenants
    let tenants: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM tenants",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for tenant_id in tenants {

        // Snapshot BOTH modes (0.6.5): the active score plus the per-test and
        // per-(policy|system) variants, so the trend re-renders in whichever
        // mode the tenant later picks — no jump. AVG ignores NULLs, so each
        // CASE averages only that column's scanned rows.
        let sys_stats = sqlx::query(
            "SELECT AVG(CASE WHEN compliance_score >= 0 THEN compliance_score END) as avg_score,
                    AVG(CASE WHEN score_test   >= 0 THEN score_test   END) as avg_test,
                    AVG(CASE WHEN score_policy >= 0 THEN score_policy END) as avg_policy,
                    COUNT(CASE WHEN compliance_score >= 0 THEN 1 END) as total
             FROM systems WHERE tenant_id = ? AND status = 'active'",
        )
        .bind(&tenant_id)
        .fetch_one(pool)
        .await?;

        let pol_stats = sqlx::query(
            "SELECT AVG(CASE WHEN compliance_score >= 0 THEN compliance_score END) as avg_score,
                    AVG(CASE WHEN score_test   >= 0 THEN score_test   END) as avg_test,
                    AVG(CASE WHEN score_system >= 0 THEN score_system END) as avg_system,
                    COUNT(CASE WHEN compliance_score >= 0 THEN 1 END) as total
             FROM policies WHERE tenant_id = ?",
        )
        .bind(&tenant_id)
        .fetch_one(pool)
        .await?;

        let round2 = |v: f64| (v * 100.0).round() / 100.0;
        let systems_score         = round2(sys_stats.try_get::<f64, _>("avg_score").unwrap_or(0.0));
        let systems_score_test    = round2(sys_stats.try_get::<f64, _>("avg_test").unwrap_or(0.0));
        let systems_score_policy  = round2(sys_stats.try_get::<f64, _>("avg_policy").unwrap_or(0.0));
        let policies_score        = round2(pol_stats.try_get::<f64, _>("avg_score").unwrap_or(0.0));
        let policies_score_test   = round2(pol_stats.try_get::<f64, _>("avg_test").unwrap_or(0.0));
        let policies_score_system = round2(pol_stats.try_get::<f64, _>("avg_system").unwrap_or(0.0));
        // COUNT(*) returns i64 in SQLite — use i64 to avoid overflow
        let total_systems  = sys_stats.try_get::<i64, _>("total").unwrap_or(0);
        let total_policies = pol_stats.try_get::<i64, _>("total").unwrap_or(0);

        sqlx::query(r#"
            INSERT INTO compliance_history (
                tenant_id, systems_score, policies_score,
                systems_score_test, systems_score_policy,
                policies_score_test, policies_score_system,
                total_systems, total_policies, failed_systems, failed_policies
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,
                (SELECT COUNT(*) FROM systems
                 WHERE compliance_score < 100
                 AND compliance_score >= 0
                 AND tenant_id = ?
                 AND status = 'active'),
                (SELECT COUNT(*) FROM policies
                 WHERE compliance_score < 100
                 AND compliance_score >= 0
                 AND tenant_id = ?)
            )
        "#)
        .bind(&tenant_id)
        .bind(systems_score)
        .bind(policies_score)
        .bind(systems_score_test)
        .bind(systems_score_policy)
        .bind(policies_score_test)
        .bind(policies_score_system)
        .bind(total_systems)
        .bind(total_policies)
        .bind(&tenant_id)
        .bind(&tenant_id)
        .execute(pool)
        .await?;

        info!(
            "Compliance trend snapshot recorded for tenant '{}': Sys {}%, Pol {}%",
            tenant_id, systems_score, policies_score
        );
    }

    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: record_entity_history
// Hourly per-ENTITY compliance snapshots (design: 0.7.2-entity-trends.md).
// One row per scanned system and per scanned policy, carrying BOTH compliance
// axes so the report trend charts re-render the whole history when the tenant
// flips a compliance-mode toggle (the 0.6.6 dual-mode lesson):
//   • system → score_test + score_policy  (stored as score_strict)
//   • policy → score_test + score_system  (stored as score_strict)
// Reads the stored aggregates maintained by every recalc — never computes.
// Not-scanned entities (compliance_score < 0) are skipped, not stored: a gap
// in the chart renders as a gap. Set-based INSERTs, no per-row loop.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record_entity_history(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO entity_compliance_history
            (tenant_id, entity_type, entity_id, score_test, score_strict,
             tests_passed, tests_failed)
         SELECT tenant_id, 'system', id, score_test, score_policy,
                tests_passed, tests_failed
         FROM systems
         WHERE status = 'active' AND compliance_score >= 0",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO entity_compliance_history
            (tenant_id, entity_type, entity_id, score_test, score_strict,
             tests_passed, tests_failed)
         SELECT tenant_id, 'policy', id, score_test, score_system,
                systems_passed, systems_failed
         FROM policies
         WHERE compliance_score >= 0",
    )
    .execute(pool)
    .await?;

    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: start_background_scheduler
// Spawns startup compliance sync and the 60-second main heartbeat loop.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn start_background_scheduler(pool: SqlitePool) {
    // Startup compliance sync
    let startup_pool = pool.clone();
    tokio::spawn(async move {
        info!("Initiating startup compliance synchronization...");
        if let Err(e) = recalculate_current_compliance_at_startup(&startup_pool).await {
            error!("Startup compliance recalculation failed: {}", e);
        } else {
            info!("Compliance status successfully synchronized on startup.");
        }
    });

    // Main heartbeat loop — every 60 seconds
    let mut interval = time::interval(Duration::from_secs(60));
    let loop_pool = pool.clone();

    tokio::spawn(async move {
        // When this server process came up. Used to gate the inactive-system
        // prune so a server outage can't be mistaken for absent agents.
        let started_at = std::time::Instant::now();
        let mut last_snapshot_hour: i32 = Utc::now().hour() as i32;
        // Track the last calendar day on which daily-prune tasks ran so
        // the daily tick fires exactly once per UTC day regardless of
        // when the server started. Drives audit-log, report, and
        // notification retention pruning together.
        let mut last_daily_prune_day: i32 = -1;

        loop {
            interval.tick().await;

            let now = Utc::now();
            let now_str = now.format("%Y-%m-%dT%H:%M").to_string();
            let current_hour = now.hour() as i32;
            // ordinal0() = 0-based day-of-year. Wraparound (year change) is
            // handled fine because last_audit_prune_day starts at -1 and any
            // change != prior value triggers one prune, then re-syncs.
            let current_day  = now.ordinal0() as i32;

            // --- TASK A: POLICY SCHEDULER (scan + report) ---
            let due_schedules = match sqlx::query_as::<_, PolicySchedule>(
                "SELECT id, tenant_id, policy_id, schedule_type,
                        CAST(enabled AS INTEGER) AS enabled,
                        frequency, cron_expression,
                        CAST(next_run AS TEXT) AS next_run, CAST(last_run AS TEXT) AS last_run
                 FROM policy_schedules WHERE enabled = 1 AND next_run <= ?",
            )
            .bind(&now_str)
            .fetch_all(&loop_pool)
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to fetch due schedules: {}", e);
                    vec![]
                }
            };

            for schedule in due_schedules {
                info!(
                    "Scheduler: Triggering Policy ID {} type='{}' at '{}'",
                    schedule.policy_id, schedule.schedule_type, now_str
                );

                let result = match schedule.schedule_type.as_str() {
                    "report" => {
                        save_policy_report_logic(
                            schedule.policy_id as i64,
                            &loop_pool,
                            &schedule.tenant_id,
                            "Scheduler",
                        )
                        .await
                    }
                    _ => {
                        execute_policy_run_logic(
                            schedule.policy_id,
                            &loop_pool,
                            &schedule.tenant_id,
                        )
                        .await
                    }
                };

                match result {
                    Ok(_) => {
                        let next_run_time = calculate_next_run(&schedule.frequency, &schedule.next_run);
                        if let Err(e) = sqlx::query(
                            "UPDATE policy_schedules SET next_run = ?, last_run = ? WHERE id = ?",
                        )
                        .bind(&next_run_time)
                        .bind(&now_str)
                        .bind(schedule.id)
                        .execute(&loop_pool)
                        .await
                        {
                            error!("Failed to update schedule for policy {}: {}", schedule.policy_id, e);
                        } else {
                            let msg = match schedule.schedule_type.as_str() {
                                "report" => format!("Scheduled report saved for Policy ID {}.", schedule.policy_id),
                                _ => format!("Scheduled scan completed for Policy ID {}.", schedule.policy_id),
                            };
                            info!("{}", msg);
                            for owner_id in get_policy_owners(&loop_pool, &schedule.tenant_id).await {
                                add_notification(&loop_pool, &schedule.tenant_id, "info", owner_id, &msg).await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Scheduled {} failed for policy {}: {}", schedule.schedule_type, schedule.policy_id, e);
                        let msg = format!(
                            "Scheduled {} FAILED for Policy ID {}. Error: {}",
                            schedule.schedule_type, schedule.policy_id, e
                        );
                        for owner_id in get_policy_owners(&loop_pool, &schedule.tenant_id).await {
                            add_notification(&loop_pool, &schedule.tenant_id, "warning", owner_id, &msg).await;
                        }
                    }
                }
            }

            // --- TASK B: AUTO-PRUNE INACTIVE SYSTEMS ---
            prune_inactive_systems(&loop_pool, started_at.elapsed()).await;

            // --- TASK C: HOURLY COMPLIANCE SNAPSHOT ---
            if now.minute() == 0 && current_hour != last_snapshot_hour {
                info!("Running hourly compliance aggregation snapshot...");
                if let Err(e) = record_compliance_history(&loop_pool).await {
                    error!("Hourly compliance snapshot failed: {}", e);
                } else {
                    last_snapshot_hour = current_hour;
                    info!("Hourly compliance snapshot recorded successfully.");
                }
                // Per-system / per-policy snapshots for the report trend
                // charts. Non-fatal: a failure here must not skip TASK D or
                // re-run the fleet snapshot next minute.
                if let Err(e) = record_entity_history(&loop_pool).await {
                    error!("Hourly entity trend snapshot failed: {}", e);
                }

                // --- TASK D: VERSION UPDATE CHECK ---
                check_for_updates(&loop_pool).await;
            }

            // --- TASK F: AUTO-GROUP COMPLIANCE DIRTY BIT ---
            // Heartbeats whose auto-group membership churned set
            // systems.compliance_dirty = 1 (see auto_groups::apply_auto_groups).
            // We consume the bit here rather than synchronously recalculating
            // on the heartbeat hot path — keeps /send fast even when a rule
            // edit triggers cascading membership changes across many systems.
            //
            // Scoping: we recompute ONLY the tenants that actually have dirty
            // systems, not the whole fleet.  On a multi-tenant deployment a
            // single new Linux box joining a group in tenant A no longer
            // forces a recompute of tenants B…Z.  We collect DISTINCT dirty
            // tenant_ids first, then recalc each.
            //
            // Strategy: clear the flag BEFORE running the recalc, so any
            // concurrent heartbeat that flags a NEW system during the recalc
            // window survives to the next tick.  Worst case is one tick (60s)
            // of latency, matching the "accept the lag" decision in
            // docs/design/0.5.2-auto-groups.md §14 Q2.  Both the SELECT and
            // the clearing UPDATE ride the partial index
            // `idx_systems_compliance_dirty`, so the no-dirt steady state is
            // one cheap indexed scan per tick.
            let dirty_tenants: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT tenant_id FROM systems WHERE compliance_dirty = 1"
            )
            .fetch_all(&loop_pool)
            .await
            .unwrap_or_default();

            if !dirty_tenants.is_empty() {
                info!("auto-groups: {} tenant(s) flagged compliance_dirty — recalculating",
                      dirty_tenants.len());

                // Clear the flags for exactly the tenants we're about to
                // process.  A tenant that gains a NEW dirty system after this
                // clear keeps its bit set and is picked up next tick.
                if let Err(e) = sqlx::query(
                    "UPDATE systems SET compliance_dirty = 0 WHERE compliance_dirty = 1"
                )
                .execute(&loop_pool)
                .await {
                    warn!("auto-groups: could not clear compliance_dirty bits: {}", e);
                }

                for tenant_id in &dirty_tenants {
                    if let Err(e) = recalculate_current_compliance_for_tenant(&loop_pool, tenant_id).await {
                        error!("auto-groups: compliance recalc for tenant {} failed: {}",
                               tenant_id, e);
                    }
                }
            }

            // --- TASK E: DAILY RETENTION PRUNE ---
            // Runs once per UTC day at the first tick that lands on a new
            // day. Per-tenant retention is read from settings inside each
            // prune helper; tenants with retention = 0 (forever) are
            // skipped there. Covers audit log, saved reports, notifications,
            // and container inventory in one daily pass.
            if current_day != last_daily_prune_day {
                crate::audit::prune(&loop_pool).await;
                prune_reports(&loop_pool).await;
                prune_notifications(&loop_pool).await;
                prune_containers(&loop_pool).await;
                prune_trends(&loop_pool).await;
                last_daily_prune_day = current_day;
            }
        }
    });
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: prune_inactive_systems
// For each tenant with auto_prune_inactive > 0, deletes active systems whose
// last_seen is older than the configured number of minutes.
//
// `uptime` is how long THIS server process has been running, and it gates the
// whole pass: a system is only genuinely "inactive" if it failed to check in
// while the server was actually up to receive the heartbeat. While the server
// is down no agent can report, so every last_seen goes stale — without this
// guard, a server outage longer than the threshold wiped the entire fleet on
// the first tick after restart, before any agent had a chance to check in.
// We therefore skip a tenant until the server has been up at least as long as
// its own threshold; only then is a still-stale system provably absent.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn prune_inactive_systems(pool: &SqlitePool, uptime: Duration) {
    let tenants: Vec<(String, i64)> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT tenant_id, CAST(value AS INTEGER) FROM settings
         WHERE skey = 'auto_prune_inactive' AND CAST(value AS INTEGER) > 0",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => { error!("Auto-prune: failed to fetch thresholds: {}", e); return; }
    };

    for (tenant_id, minutes) in tenants {
        // Downtime guard (see the header): until the server has been up for the
        // tenant's own threshold, a stale last_seen can't be distinguished from
        // "the server wasn't there to hear it", so pruning is unsafe.
        if uptime < Duration::from_secs(minutes.max(0) as u64 * 60) {
            info!(
                "Auto-prune: skipping tenant '{}' — server uptime {}m < threshold {}m; \
                 waiting for agents to check in before judging them inactive.",
                tenant_id, uptime.as_secs() / 60, minutes
            );
            continue;
        }

        // Compute the cutoff timestamp in Rust rather than doing per-row
        // strftime math in SQL.  `last_seen < ?` is sargable, so with
        // idx_systems_prune (tenant_id, status, last_seen) this is a range
        // scan instead of a full scan of the tenant's active systems on every
        // 60s tick.  SQLite stores CURRENT_TIMESTAMP as "%Y-%m-%d %H:%M:%S",
        // which sorts lexically == chronologically, so a string comparison
        // against a same-format cutoff is correct.
        let cutoff = (Utc::now() - chrono::Duration::minutes(minutes))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        let deleted = sqlx::query(
            "DELETE FROM systems
             WHERE tenant_id = ?
               AND status = 'active'
               AND last_seen IS NOT NULL
               AND last_seen < ?",
        )
        .bind(&tenant_id)
        .bind(&cutoff)
        .execute(pool)
        .await;

        match deleted {
            Ok(r) if r.rows_affected() > 0 => {
                info!("Auto-prune: removed {} inactive system(s) for tenant '{}'.", r.rows_affected(), tenant_id);
            }
            Ok(_) => {}
            Err(e) => error!("Auto-prune: delete failed for tenant '{}': {}", tenant_id, e),
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: prune_reports
// For each tenant with report_retention_days > 0, deletes rows from both
// `reports` (policy snapshots) and `system_reports` whose submission_date is
// older than the configured threshold. One `retention.reports_pruned` audit
// entry per tenant whose data was actually trimmed.
// ─────────────────────────────────────────────────────────────────────────────
async fn prune_reports(pool: &SqlitePool) {
    let tenants: Vec<(String, i64)> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT tenant_id, CAST(value AS INTEGER) FROM settings
         WHERE skey = 'report_retention_days' AND CAST(value AS INTEGER) > 0",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => { error!("report prune: failed to fetch retention settings: {}", e); return; }
    };

    for (tenant_id, days) in tenants {
        let cutoff_clause = "submission_date < datetime('now', '-' || ? || ' days')";

        let policy_del = sqlx::query(&format!(
            "DELETE FROM reports WHERE tenant_id = ? AND {}", cutoff_clause
        ))
        .bind(&tenant_id).bind(days)
        .execute(pool).await;

        let system_del = sqlx::query(&format!(
            "DELETE FROM system_reports WHERE tenant_id = ? AND {}", cutoff_clause
        ))
        .bind(&tenant_id).bind(days)
        .execute(pool).await;

        let removed = match (&policy_del, &system_del) {
            (Ok(p), Ok(s)) => p.rows_affected() + s.rows_affected(),
            _ => 0,
        };

        if let Err(e) = &policy_del { error!("report prune: policy delete failed for tenant '{}': {}", tenant_id, e); }
        if let Err(e) = &system_del { error!("report prune: system delete failed for tenant '{}': {}", tenant_id, e); }

        if removed > 0 {
            info!("report prune: removed {} report snapshot(s) older than {} day(s) for tenant '{}'.", removed, days, tenant_id);
            crate::audit::record_raw(
                pool, &tenant_id,
                None, "system",
                None,
                "retention.reports_pruned",
                Some("reports"), None,
                Some(&format!("{{\"removed\":{},\"retention_days\":{}}}", removed, days)),
            ).await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: prune_notifications
// For each tenant with notification_retention_days > 0, deletes rows from the
// `notify` table whose `nts` timestamp is older than the configured threshold.
// `nts` is stored as an ISO-8601 string; lexical comparison is correct for that
// format. One `retention.notifications_pruned` audit entry per tenant whose
// data was actually trimmed.
// ─────────────────────────────────────────────────────────────────────────────
async fn prune_notifications(pool: &SqlitePool) {
    let tenants: Vec<(String, i64)> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT tenant_id, CAST(value AS INTEGER) FROM settings
         WHERE skey = 'notification_retention_days' AND CAST(value AS INTEGER) > 0",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => { error!("notification prune: failed to fetch retention settings: {}", e); return; }
    };

    for (tenant_id, days) in tenants {
        let res = sqlx::query(
            "DELETE FROM notify
             WHERE tenant_id = ?
               AND nts < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-' || ? || ' days')",
        )
        .bind(&tenant_id).bind(days)
        .execute(pool).await;

        match res {
            Ok(r) if r.rows_affected() > 0 => {
                let removed = r.rows_affected();
                info!("notification prune: removed {} row(s) older than {} day(s) for tenant '{}'.", removed, days, tenant_id);
                crate::audit::record_raw(
                    pool, &tenant_id,
                    None, "system",
                    None,
                    "retention.notifications_pruned",
                    Some("notify"), None,
                    Some(&format!("{{\"removed\":{},\"retention_days\":{}}}", removed, days)),
                ).await;
            }
            Ok(_) => {}
            Err(e) => error!("notification prune: delete failed for tenant '{}': {}", tenant_id, e),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: prune_containers
// For each tenant with container_retention_days > 0, deletes rows from the
// `containers` table whose `last_seen` is older than the configured threshold.
// Two-phase staleness: the heartbeat ingest already deletes containers that
// the agent stopped reporting (stragglers from previous ticks). This prune
// handles the case where the *host itself* stopped checking in — its
// containers' last_seen freezes, and after the retention window we drop them.
// One `retention.containers_pruned` audit entry per tenant whose data was
// actually trimmed.
// ─────────────────────────────────────────────────────────────────────────────
async fn prune_containers(pool: &SqlitePool) {
    let tenants: Vec<(String, i64)> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT tenant_id, CAST(value AS INTEGER) FROM settings
         WHERE skey = 'container_retention_days' AND CAST(value AS INTEGER) > 0",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => { error!("container prune: failed to fetch retention settings: {}", e); return; }
    };

    for (tenant_id, days) in tenants {
        let res = sqlx::query(
            "DELETE FROM containers
             WHERE tenant_id = ?
               AND last_seen < datetime('now', '-' || ? || ' days')",
        )
        .bind(&tenant_id).bind(days)
        .execute(pool).await;

        match res {
            Ok(r) if r.rows_affected() > 0 => {
                let removed = r.rows_affected();
                info!("container prune: removed {} row(s) older than {} day(s) for tenant '{}'.", removed, days, tenant_id);
                crate::audit::record_raw(
                    pool, &tenant_id,
                    None, "system",
                    None,
                    "retention.containers_pruned",
                    Some("containers"), None,
                    Some(&format!("{{\"removed\":{},\"retention_days\":{}}}", removed, days)),
                ).await;
            }
            Ok(_) => {}
            Err(e) => error!("container prune: delete failed for tenant '{}': {}", tenant_id, e),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: prune_trends
// Two retention passes for the compliance trend snapshots (0.7.2):
//   • entity_trend_retention_days → entity_compliance_history (per-system /
//     per-policy rows; high volume, default 90 days)
//   • fleet_trend_retention_days  → compliance_history (the dashboard's
//     fleet-wide trend; one row per tenant per hour, default 365 days —
//     previously keep-forever)
// Tenants with retention = 0 are skipped by the settings query. Cutoffs use
// the same sargable strftime form as the other prunes (check_date < cutoff
// hits the lookup index / a range scan). One retention.* audit row per
// tenant per table whose data was trimmed.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn prune_trends(pool: &SqlitePool) {
    // (skey, table, audit action) — both passes share the loop body.
    let passes: [(&str, &str, &str); 2] = [
        ("entity_trend_retention_days", "entity_compliance_history", "retention.entity_trends_pruned"),
        ("fleet_trend_retention_days",  "compliance_history",        "retention.fleet_trends_pruned"),
    ];

    for (skey, table, action) in passes {
        let tenants: Vec<(String, i64)> = match sqlx::query_as::<_, (String, i64)>(
            &format!(
                "SELECT tenant_id, CAST(value AS INTEGER) FROM settings
                 WHERE skey = '{}' AND CAST(value AS INTEGER) > 0", skey),
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => { error!("trend prune: failed to fetch {} settings: {}", skey, e); continue; }
        };

        for (tenant_id, days) in tenants {
            let res = sqlx::query(&format!(
                "DELETE FROM {}
                 WHERE tenant_id = ?
                   AND check_date < strftime('%Y-%m-%d %H:%M:%S', 'now', '-' || ? || ' days')", table))
            .bind(&tenant_id).bind(days)
            .execute(pool).await;

            match res {
                Ok(r) if r.rows_affected() > 0 => {
                    let removed = r.rows_affected();
                    info!("trend prune: removed {} row(s) from {} older than {} day(s) for tenant '{}'.", removed, table, days, tenant_id);
                    crate::audit::record_raw(
                        pool, &tenant_id,
                        None, "system",
                        None,
                        action,
                        Some(table), None,
                        Some(&format!("{{\"removed\":{},\"retention_days\":{}}}", removed, days)),
                    ).await;
                }
                Ok(_) => {}
                Err(e) => error!("trend prune: delete from {} failed for tenant '{}': {}", table, tenant_id, e),
            }
        }
    }
}


// ============================================================
// VERSION UPDATE CHECK
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_for_updates
// Queries GitHub releases API; notifies admins if a newer version is available.
// ─────────────────────────────────────────────────────────────────────────────
async fn check_for_updates(pool: &SqlitePool) {
    let current = env!("CARGO_PKG_VERSION");

    let client = match Client::builder()
        .user_agent("OpenSCM-Server")
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => { error!("Version check: failed to build HTTP client: {}", e); return; }
    };

    let resp = match client
        .get("https://api.github.com/repos/easysysio/OpenSCM/releases/latest")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => { error!("Version check: request failed: {}", e); return; }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => { error!("Version check: failed to parse response: {}", e); return; }
    };

    let latest_tag = match json.get("tag_name").and_then(|v| v.as_str()) {
        Some(t) => t.trim_start_matches('v').to_string(),
        None => { error!("Version check: tag_name missing from GitHub response"); return; }
    };

    if !is_newer(&latest_tag, current) {
        info!("Version check: up to date ({})", current);
        return;
    }

    info!("Version check: new version {} available (current: {})", latest_tag, current);

    let msg = format!(
        "OpenSCM {} is available. You are running {}. Visit https://openscm.io to update.",
        latest_tag, current
    );

    // Notify all admin-or-higher users in all tenants (skip if already
    // notified about this version). Same caveat as get_policy_owners: the
    // bootstrap admin on a fresh CE install has role 'superuser', so a
    // plain role = 'admin' filter silently excludes them and the bell
    // never lights up.
    let admin_rows = match sqlx::query(
        "SELECT id, tenant_id FROM users WHERE role IN ('admin', 'superuser')",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => { error!("Version check: failed to fetch admin users: {}", e); return; }
    };

    for row in admin_rows {
        let user_id: i32 = row.get("id");
        let tenant_id: String = row.get("tenant_id");

        // Skip if already notified about this version
        let already: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notify WHERE owner_id = ? AND message LIKE ?",
        )
        .bind(user_id)
        .bind(format!("%{}%", latest_tag))
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        if already == 0 {
            add_notification(pool, &tenant_id, "warning", user_id, &msg).await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: is_newer
// Returns true if latest semver string is higher than current.
// ─────────────────────────────────────────────────────────────────────────────
fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> (u32, u32, u32) {
        let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    }
    parse(latest) > parse(current)
}
