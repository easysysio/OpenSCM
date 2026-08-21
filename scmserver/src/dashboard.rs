// =============================================================================
// dashboard.rs — main dashboard handler
//
// Aggregates system counts, top-failing policies/systems, compliance trend
// history, and optional plan-limit data for the dashboard landing page.
// Role: Viewer (minimum — any authenticated user may view).
// =============================================================================

use axum::response::IntoResponse;
use axum::http::StatusCode;
use axum::extract::{Extension, Query};
use tera::{Tera, Context};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::error;

use crate::models::{ComplianceHistoryRow, PolicyFailRow, SystemFailRow, AuthSession};
use crate::handlers::render_template;



#[derive(serde::Deserialize)] // Add Serialize if passing to template
pub struct DashboardParams {
    #[serde(default)] // Helps handle empty strings/missing keys
    pub error_message: Option<String>,
    #[serde(default)]
    pub success_message: Option<String>,
    #[serde(default)]
    pub range: Option<String>,
    /// `?tour=1` re-opens the guided first-run tour without clearing
    /// users.tour_done — see GET /tour/reopen.
    #[serde(default)]
    pub tour: Option<String>,
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /
// Render the main dashboard: stats, top failures, compliance trend chart.
// Role: Viewer (any authenticated user; no explicit authorize() call needed)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(auth: AuthSession, Query(params): Query<DashboardParams>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> impl IntoResponse {

    let range: &str = match params.range.as_deref() {
        Some("yearly")  => "yearly",
        Some("weekly")  => "weekly",
        Some("monthly") => "monthly",
        Some("daily")   => "daily",
        _               => "hourly",   // default view
    };


    let mut context = Context::new();
    
    // 1. Get counts for the Small Boxes
    let systems_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE status = 'active' AND tenant_id = ?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch systems count: {}", e); 0 });

    
    let pending_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE status = 'pending' AND tenant_id=?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch pending systems count: {}", e); 0 });

    let policies_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE tenant_id=?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch policies count: {}", e); 0 });

    let reports_count: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM reports WHERE tenant_id = ?) +
                (SELECT COUNT(*) FROM system_reports WHERE tenant_id = ?)"
    )
        .bind(&auth.tenant_id)
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch reports count: {}", e); 0 });


    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_sat'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&*pool)
    .await
    .unwrap_or(80);

    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_marginal'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&*pool)
    .await
    .unwrap_or(60);

    
    // Dual-mode compliance (0.6.5): read the tenant's policy/system modes and
    // pick the matching stored column, so the dashboard tables + trend switch
    // instantly (no recompute) and the trend re-renders the whole history in
    // the chosen mode (no jump). score_test / score_system / score_policy are
    // both kept current by every recalc; the active mode just selects which.
    let pol_mode = crate::policies::read_compliance_mode(&pool, &auth.tenant_id, "policy_compliance_mode").await;
    let sys_mode = crate::policies::read_compliance_mode(&pool, &auth.tenant_id, "system_compliance_mode").await;
    let pol_col  = if pol_mode == "system" { "score_system" } else { "score_test" };
    let sys_col  = if sys_mode == "policy" { "score_policy" } else { "score_test" };
    let pol_hist = if pol_mode == "system" { "policies_score_system" } else { "policies_score_test" };
    let sys_hist = if sys_mode == "policy" { "systems_score_policy"  } else { "systems_score_test" };

    // 2. Get Critical Policy Failures
    let top_failed_policies = sqlx::query_as::<_, PolicyFailRow>(&format!(
        r#"
        SELECT
            id as policy_id,
	    name as policy_name,
            version as policy_version,
            {pol_col} as compliance,
            systems_passed as systems_passed,
            systems_failed as systems_failed
        FROM policies
        WHERE tenant_id = ?
        AND {pol_col} >= 0
        ORDER BY {pol_col} ASC
        LIMIT 5
        "#
    ))
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Dashboard Policy Fetch Error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 3. Get Highest Risk Assets
    let top_failed_systems = sqlx::query_as::<_, SystemFailRow>(&format!(
        "SELECT id as system_id, name as system_name, os, {sys_col} as compliance,
        tests_passed, tests_failed,
        MAX(0, total_tests - tests_passed - tests_failed) as tests_na
        FROM systems WHERE status='active' AND tenant_id = ?
        AND {sys_col} >= 0 ORDER BY {sys_col} ASC LIMIT 5"
    ))
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await.map_err(|e| { error!("{}", e); StatusCode::INTERNAL_SERVER_ERROR })?;


    // 4. Fetch History including POLICY_SCORE
    
    let date_col: &str = match range {
        "yearly"  => "strftime('%Y', check_date)",
        "weekly"  => "strftime('%Y-W%W', check_date)",
        "monthly" => "strftime('%m-%Y', check_date)",
        "hourly"  => "strftime('%m-%d %H:00', check_date)",
        _         => "strftime('%Y-%m-%d', check_date)",
    };
    let (order_col, limit) = match range {
        "yearly"  => ("check_date", 10i32),
        "weekly"  => ("check_date", 12),
        "monthly" => ("check_date", 12),
        "daily"   => ("id",         30),  // last 30 days
        _         => ("id",         24),  // hourly: last 24 hours
    };
    let history_query = format!(
        "SELECT {date_col} as check_date, \
                AVG({sys_hist}) as systems_score, \
                AVG({pol_hist}) as policies_score \
         FROM compliance_history WHERE tenant_id = ? \
         GROUP BY 1 ORDER BY {order_col} DESC LIMIT {limit}"
    );

    let history = sqlx::query_as::<_, ComplianceHistoryRow>(&history_query)
        .bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch compliance history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;


    let mut labels = Vec::new();
    let mut systems_scores= Vec::new();
    let mut policies_scores = Vec::new(); 

    for rec in history.into_iter().rev() {
        labels.push(rec.check_date); 
        systems_scores.push(rec.systems_score); 
        policies_scores.push(rec.policies_score); // NEW
    }


    context.insert("range", &range);
    context.insert("systems_count", &systems_count);
    context.insert("pending_count", &pending_count);
    context.insert("policies_count", &policies_count);
    context.insert("reports_count", &reports_count);
    context.insert("top_failed_systems", &top_failed_systems); 
    context.insert("top_failed_policies", &top_failed_policies);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);

    // Graph Data
    context.insert("trend_labels", &labels);
    context.insert("trend_systems_scores", &systems_scores);
    context.insert("trend_policies_scores", &policies_scores); 


    // 5. Optional plan limits — only present when the plan_limits table exists (SaaS).
    //    Silently returns None in CE where the table is absent.
    let plan_limits_exist: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plan_limits'"
    )
    .fetch_one(&*pool)
    .await
    .unwrap_or(0);

    let (systems_limit_text, policies_limit_text, reports_limit_text): (Option<String>, Option<String>, Option<String>) =
        if plan_limits_exist > 0 {
            let plan: String = sqlx::query_scalar(
                "SELECT COALESCE(plan, 'free') FROM tenants WHERE id = ?"
            )
            .bind(&auth.tenant_id)
            .fetch_optional(&*pool)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "free".to_string());

            fn fmt_limit(v: Option<i64>) -> Option<String> {
                match v {
                    Some(0) => Some("Unlimited".to_string()),
                    Some(n) => Some(n.to_string()),
                    None    => None,
                }
            }

            let sl: Option<i64> = sqlx::query_scalar(
                "SELECT max_count FROM plan_limits WHERE plan = ? AND resource = 'systems'"
            ).bind(&plan).fetch_optional(&*pool).await.ok().flatten();

            let pl: Option<i64> = sqlx::query_scalar(
                "SELECT max_count FROM plan_limits WHERE plan = ? AND resource = 'policies'"
            ).bind(&plan).fetch_optional(&*pool).await.ok().flatten();

            let rl: Option<i64> = sqlx::query_scalar(
                "SELECT max_count FROM plan_limits WHERE plan = ? AND resource = 'reports'"
            ).bind(&plan).fetch_optional(&*pool).await.ok().flatten();

            (fmt_limit(sl), fmt_limit(pl), fmt_limit(rl))
        } else {
            (None, None, None)
        };

    context.insert("systems_limit_text",  &systems_limit_text);
    context.insert("policies_limit_text", &policies_limit_text);
    context.insert("reports_limit_text",  &reports_limit_text);

    // 6. Fill Context
    if let Some(msg) = &params.error_message {
        context.insert("error_message", msg);
    }
    if let Some(msg) = &params.success_message {
        context.insert("success_message", msg);
    }


    // Guided first-run tour. Only ever offered on the dashboard: a modal that
    // can appear over any page will eventually appear over a half-filled form.
    let force_tour = params.tour.as_deref() == Some("1");
    if let Some(info) = crate::tour::tour_info(&pool, &auth, force_tour).await {
        context.insert("show_tour", &true);
        context.insert("tour", &info);
    } else {
        context.insert("show_tour", &false);
    }

    render_template(&tera, Some(&pool), "dashboard.html", context, Some(auth)).await
}

