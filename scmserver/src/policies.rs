// =============================================================================
// policies.rs — policy CRUD, run, live report, and PDF download
//
// All routes are tenant-scoped. Viewer role required for reads;
// Editor role required for writes; Runner role required to trigger a scan.
// =============================================================================

use axum::response::{Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::BTreeMap;
use tracing::{info, error};
use chrono::Utc;
use genpdf::{fonts, elements, style, Element, Margins};

use crate::models::{
    ErrorQuery, SystemGroup, Test, Policy, PolicySchedule,
    SystemInsidePolicy, TestInsidePolicy, PolicyCompliance,
    ReportData, TestMeta, SystemReport, IndividualResult, ContainerReportGroup,
    UserRole, AuthSession,
    PolicyExport, PolicyExportPolicy, PolicyExportTest, PolicyExportTestCondition,
    PolicyImportSummary,
};
use axum::extract::Multipart;
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data, normalize_status, is_system_passed};



// ============================================================
// HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// GET /policies
// List all policies with live compliance scores for the current tenant.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

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

    // Dual-mode (0.6.5): read the per-tenant policy compliance mode and show
    // the matching stored score (score_test / score_system). Both are kept
    // current by every recalc, so switching the toggle is instant and the list
    // stays consistent with the dashboard + reports. (Previously the list
    // hardcoded per-system, ignoring the toggle.)
    let pol_mode = read_compliance_mode(&pool, &auth.tenant_id, "policy_compliance_mode").await;
    let pol_col  = if pol_mode == "system" { "p.score_system" } else { "p.score_test" };
    // Pure-container policies have no host-axis score (-1); fall back to the
    // stored container axis so a CIS-Docker policy shows a real number.
    let compliance_expr = format!("COALESCE(NULLIF({pol_col}, -1.0), p.score_container)");
    let rows = match sqlx::query(&format!(r#"
        SELECT
            p.id AS policy_id,
            p.name AS policy_name,
            p.version AS policy_version,
            p.description AS policy_description,
            p.author AS author,
            {compliance_expr} AS compliance,
            (SELECT COUNT(*) FROM tests_in_policy WHERE policy_id = p.id) as test_count,
            (SELECT COUNT(*) FROM systems_in_policy WHERE policy_id = p.id) as system_count
        FROM policies p
        WHERE p.tenant_id = ?
        ORDER BY p.id ASC
    "#))
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = ?e, "Failed to fetch policy compliance list");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let policies: Vec<PolicyCompliance> = rows
        .into_iter()
        .map(|row| PolicyCompliance {
            policy_id: row.get::<i64, _>("policy_id"),
            policy_name: row.get::<String, _>("policy_name"),
            policy_version: row.get::<String, _>("policy_version"),
            policy_description: Some(
                row.get::<Option<String>, _>("policy_description")
                    .unwrap_or_default(),
            ),
            author: row.try_get::<Option<String>, _>("author").unwrap_or(None),
            compliance: row.get::<f64, _>("compliance"),
            test_count: row.get::<i64, _>("test_count"),
            system_count: row.get::<i64, _>("system_count"),
            systems_passed: None,
            systems_failed: None,
        })
        .collect();

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    context.insert("policies", &policies);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    render_template(&tera, Some(&pool), "policies.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/add
// Render the add-policy form with available tests and system groups.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_add(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let tests_result = sqlx::query(
        "SELECT id, name, severity FROM tests WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let tests: Vec<Test> = match tests_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| Test {
                id: row.get("id"),
                name: row.get("name"),
                severity: row.get("severity"),
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch tests for policy add: {}", e);
            vec![]
        }
    };

    // Pull auto_managed so the template can render a visual marker on
    // auto-groups in the duallistbox. Auto groups ARE selectable as
    // policy scope (rule-driven membership is fine for compliance
    // scope); the marker is purely to help admins tell them apart from
    // manual groups in the picker.  Order: manual first, then auto,
    // each alphabetical — admins typically reach for manual groups
    // when defining policy scope, and grouping by type avoids a mixed
    // list that's hard to scan.
    let groups_result = sqlx::query(
        "SELECT id, name, auto_managed FROM system_groups
         WHERE tenant_id = ?
         ORDER BY auto_managed ASC, name ASC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let system_groups: Vec<SystemGroup> = match groups_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemGroup {
                id: row.get("id"),
                name: row.get("name"),
                auto_managed: row.try_get("auto_managed").unwrap_or(0),
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch system groups for policy add: {}", e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("tests", &tests);
    context.insert("system_groups", &system_groups);
    render_template(&tera, Some(&pool), "policies_add.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /policies/add
// Save a new policy with tests, system groups, and optional schedules.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_add_save(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    RawForm(raw_form): RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    let raw_string = match String::from_utf8(raw_form.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/policies?error_message=Policy+name+is+required").into_response(),
    };

    let version = match form_data.get("version").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/policies?error_message=Version+is+required").into_response(),
    };

    let description: Option<String> = form_data
        .get("description")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let author: Option<String> = form_data
        .get("author")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let tests = form_data.get("tests").cloned().unwrap_or_default();
    let system_groups = form_data.get("system_groups").cloned().unwrap_or_default();

    // Auto-Scan schedule
    let schedule_enabled = form_data.get("schedule_enabled").and_then(|v| v.first()).map(|v| v == "on").unwrap_or(false);
    let frequency = form_data.get("frequency").and_then(|v| v.first()).cloned().unwrap_or_else(|| "daily".to_string());
    let cron_val = form_data.get("cron_val").and_then(|v| v.first()).cloned();
    let next_run = form_data.get("next_run").and_then(|v| v.first()).cloned();

    // Auto-Report schedule
    let report_schedule_enabled = form_data.get("report_schedule_enabled").and_then(|v| v.first()).map(|v| v == "on").unwrap_or(false);
    let report_frequency = form_data.get("report_frequency").and_then(|v| v.first()).cloned().unwrap_or_else(|| "daily".to_string());
    let report_cron_val = form_data.get("report_cron_val").and_then(|v| v.first()).cloned();
    let report_next_run = form_data.get("report_next_run").and_then(|v| v.first()).cloned();

    // Insert policy (with auto-generated external_id for stable cross-system identity)
    let external_id = crate::schema::generate_external_id();
    let result = sqlx::query(
        "INSERT INTO policies (tenant_id, name, version, description, author, external_id) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&version)
    .bind(&description)
    .bind(&author)
    .bind(&external_id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }
    let policy_id: i64 = match sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(&mut *tx)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    // Insert auto-scan schedule if enabled
    if schedule_enabled {
        // M6: Use UTC so the scheduler (which also uses UTC) compares apples to apples.
        let start_time = next_run.filter(|s| !s.is_empty()).unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M").to_string());
        if let Err(e) = sqlx::query(
            "INSERT INTO policy_schedules (tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run)
             VALUES (?, ?, 'scan', ?, ?, ?, ?)",
        )
        .bind(&auth.tenant_id)
        .bind(policy_id)
        .bind(1)
        .bind(&frequency)
        .bind(&cron_val)
        .bind(&start_time)
        .execute(&mut *tx)
        .await
        {
            let encoded = urlencoding::encode(&format!("Schedule error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    }

    // Insert auto-report schedule if enabled
    if report_schedule_enabled {
        let start_time = report_next_run.filter(|s| !s.is_empty()).unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M").to_string());
        if let Err(e) = sqlx::query(
            "INSERT INTO policy_schedules (tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run)
             VALUES (?, ?, 'report', ?, ?, ?, ?)",
        )
        .bind(&auth.tenant_id)
        .bind(policy_id)
        .bind(1)
        .bind(&report_frequency)
        .bind(&report_cron_val)
        .bind(&start_time)
        .execute(&mut *tx)
        .await
        {
            let encoded = urlencoding::encode(&format!("Report schedule error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    }

    // Insert tests
    for test_id_str in tests {
        if let Ok(test_id) = test_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(policy_id)
            .bind(test_id)
            .execute(&mut *tx)
            .await
            {
                let encoded = urlencoding::encode(&format!("Failed to add test: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    // Insert system groups
    for group_id_str in system_groups {
        if let Ok(group_id) = group_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(policy_id)
            .bind(group_id)
            .execute(&mut *tx)
            .await
            {
                let encoded = urlencoding::encode(&format!("Failed to add system group: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    info!("Policy '{}' created by '{}'.", name, auth.username);
    Redirect::to("/policies").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/edit/{id}
// Render the edit-policy form pre-populated with existing data.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT id, name, version, description, author, external_id FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        Err(e) => {
            error!("Database error fetching policy {}: {}", id, e);
            return Redirect::to("/policies?error_message=Database+error").into_response();
        }
    };

    let policy = Policy {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        description: row.get("description"),
        author: row.try_get("author").ok(),
        external_id: row.try_get("external_id").ok(),
    };

    // Fetch scan schedule
    let schedule_row = sqlx::query_as::<_, PolicySchedule>(
        "SELECT id, tenant_id, policy_id, schedule_type,
                CAST(enabled AS INTEGER) AS enabled, frequency, cron_expression,
                CAST(next_run AS TEXT) AS next_run, CAST(last_run AS TEXT) AS last_run
         FROM policy_schedules WHERE policy_id = ? AND tenant_id = ? AND schedule_type = 'scan'",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await
    .unwrap_or(None);

    // Fetch report schedule
    let report_schedule_row = sqlx::query_as::<_, PolicySchedule>(
        "SELECT id, tenant_id, policy_id, schedule_type,
                CAST(enabled AS INTEGER) AS enabled, frequency, cron_expression,
                CAST(next_run AS TEXT) AS next_run, CAST(last_run AS TEXT) AS last_run
         FROM policy_schedules WHERE policy_id = ? AND tenant_id = ? AND schedule_type = 'report'",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await
    .unwrap_or(None);

    let tests_result = sqlx::query(
        "SELECT id, name, severity FROM tests WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let test_groups: Vec<Test> = match tests_result {
        Ok(rows) => rows.into_iter().map(|r| Test { id: r.get("id"), name: r.get("name"), severity: r.get("severity"), ..Default::default() }).collect(),
        Err(e) => { error!("Failed to fetch tests for policy edit {}: {}", id, e); vec![] }
    };

    // Auto-groups are valid policy targets — pull the flag so the picker
    // can mark them.  Manual first, then auto, alphabetical within each.
    let groups_result = sqlx::query(
        "SELECT id, name, auto_managed FROM system_groups
         WHERE tenant_id = ?
         ORDER BY auto_managed ASC, name ASC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let system_groups: Vec<SystemGroup> = match groups_result {
        Ok(rows) => rows.into_iter().map(|r| SystemGroup {
            id: r.get("id"),
            name: r.get("name"),
            auto_managed: r.try_get("auto_managed").unwrap_or(0),
            ..Default::default()
        }).collect(),
        Err(e) => { error!("Failed to fetch system groups for policy edit {}: {}", id, e); vec![] }
    };

    let tip_result = sqlx::query(
        "SELECT policy_id, test_id FROM tests_in_policy WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let tests_in_policy: Vec<TestInsidePolicy> = match tip_result {
        Ok(rows) => rows.into_iter().map(|r| TestInsidePolicy { policy_id: r.get("policy_id"), test_id: r.get("test_id") }).collect(),
        Err(e) => { error!("Failed to fetch tests in policy {}: {}", id, e); vec![] }
    };

    let sip_result = sqlx::query(
        "SELECT policy_id, group_id FROM systems_in_policy WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems_in_policy: Vec<SystemInsidePolicy> = match sip_result {
        Ok(rows) => rows.into_iter().map(|r| SystemInsidePolicy { policy_id: r.get("policy_id"), group_id: r.get("group_id") }).collect(),
        Err(e) => { error!("Failed to fetch systems in policy {}: {}", id, e); vec![] }
    };

    let mut context = Context::new();
    context.insert("policy", &policy);
    context.insert("schedule", &schedule_row);
    context.insert("report_schedule", &report_schedule_row);
    context.insert("tests", &test_groups);
    context.insert("system_groups", &system_groups);
    context.insert("tests_in_policy", &tests_in_policy);
    context.insert("systems_in_policy", &systems_in_policy);
    render_template(&tera, Some(&pool), "policies_edit.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /policies/edit/{id}
// Save changes to policy metadata, tests, system groups, and schedules.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    RawForm(raw_form): RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    let raw_string = String::from_utf8_lossy(&raw_form).to_string();
    let form_data = parse_form_data(&raw_string);

    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => { tx.rollback().await.ok(); return Redirect::to("/policies?error_message=Policy+name+is+required").into_response(); }
    };

    let version = match form_data.get("version").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => { tx.rollback().await.ok(); return Redirect::to("/policies?error_message=Version+is+required").into_response(); }
    };

    let description = form_data.get("description").and_then(|v| v.first()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let author      = form_data.get("author").and_then(|v| v.first()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    // Auto-Scan schedule
    let schedule_enabled = form_data.get("schedule_enabled").and_then(|v| v.first()).map(|v| v == "on").unwrap_or(false);
    let frequency = form_data.get("frequency").and_then(|v| v.first()).cloned().unwrap_or_else(|| "daily".to_string());
    let cron_val = form_data.get("cron_val").and_then(|v| v.first()).cloned();
    let next_run = form_data.get("next_run").and_then(|v| v.first()).cloned();

    // Auto-Report schedule
    let report_schedule_enabled = form_data.get("report_schedule_enabled").and_then(|v| v.first()).map(|v| v == "on").unwrap_or(false);
    let report_frequency = form_data.get("report_frequency").and_then(|v| v.first()).cloned().unwrap_or_else(|| "daily".to_string());
    let report_cron_val = form_data.get("report_cron_val").and_then(|v| v.first()).cloned();
    let report_next_run = form_data.get("report_next_run").and_then(|v| v.first()).cloned();

    // Update policy metadata
    if let Err(e) = sqlx::query(
        "UPDATE policies SET name = ?, version = ?, description = ?, author = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name).bind(&version).bind(&description).bind(&author).bind(id).bind(&auth.tenant_id)
    .execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Error updating policy: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    // Upsert auto-scan schedule (M6: UTC for scheduler consistency).
    // Only override next_run when the user explicitly provides a new value; otherwise
    // preserve what the scheduler last wrote so we don't reset a future firing time.
    let scan_explicit_next_run = next_run.filter(|s| !s.is_empty());
    let scan_default_next_run = Utc::now().format("%Y-%m-%dT%H:%M").to_string();
    if let Err(e) = sqlx::query(&format!(
        r#"INSERT INTO policy_schedules
               (tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run)
           VALUES (?, ?, 'scan', ?, ?, ?, ?)
           ON CONFLICT(policy_id, schedule_type) DO UPDATE SET
               enabled          = excluded.enabled,
               frequency        = excluded.frequency,
               cron_expression  = excluded.cron_expression,
               next_run         = CASE
                                    WHEN excluded.next_run != '' THEN excluded.next_run
                                    ELSE next_run
                                  END"#
    ))
    .bind(&auth.tenant_id)
    .bind(id)
    .bind(schedule_enabled)
    .bind(&frequency)
    .bind(&cron_val)
    .bind(scan_explicit_next_run.as_deref().unwrap_or(&scan_default_next_run))
    .execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Schedule update error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    // Upsert auto-report schedule (M6: UTC for scheduler consistency).
    // Same next_run preservation logic as scan schedule above.
    let report_explicit_next_run = report_next_run.filter(|s| !s.is_empty());
    let report_default_next_run = Utc::now().format("%Y-%m-%dT%H:%M").to_string();
    if let Err(e) = sqlx::query(&format!(
        r#"INSERT INTO policy_schedules
               (tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run)
           VALUES (?, ?, 'report', ?, ?, ?, ?)
           ON CONFLICT(policy_id, schedule_type) DO UPDATE SET
               enabled          = excluded.enabled,
               frequency        = excluded.frequency,
               cron_expression  = excluded.cron_expression,
               next_run         = CASE
                                    WHEN excluded.next_run != '' THEN excluded.next_run
                                    ELSE next_run
                                  END"#
    ))
    .bind(&auth.tenant_id)
    .bind(id)
    .bind(report_schedule_enabled)
    .bind(&report_frequency)
    .bind(&report_cron_val)
    .bind(report_explicit_next_run.as_deref().unwrap_or(&report_default_next_run))
    .execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Report schedule update error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    // Clear and re-insert tests
    if let Err(e) = sqlx::query("DELETE FROM tests_in_policy WHERE policy_id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Error clearing tests: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    for test_id_str in form_data.get("tests").cloned().unwrap_or_default() {
        if let Ok(test_id) = test_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id).bind(id).bind(test_id).execute(&mut *tx).await
            {
                let encoded = urlencoding::encode(&format!("Error adding test: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    // Clear and re-insert system groups
    if let Err(e) = sqlx::query("DELETE FROM systems_in_policy WHERE policy_id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Error clearing system groups: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    for group_id_str in form_data.get("system_groups").cloned().unwrap_or_default() {
        if let Ok(group_id) = group_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id).bind(id).bind(group_id).execute(&mut *tx).await
            {
                let encoded = urlencoding::encode(&format!("Error adding system group: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    // Clean up results for tests no longer reachable through any policy
    if let Err(e) = sqlx::query(r#"
        DELETE FROM results
        WHERE system_id IN (
            SELECT id FROM systems WHERE tenant_id = ?
        )
        AND test_id NOT IN (
            SELECT DISTINCT tip.test_id
            FROM tests_in_policy tip
            JOIN systems_in_policy sip ON tip.policy_id = sip.policy_id
            JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            WHERE sig.tenant_id = ?
        )
    "#)
    .bind(&auth.tenant_id).bind(&auth.tenant_id).execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Policy ID {} updated by '{}'.", id, auth.username);
    Redirect::to("/policies").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/delete/{id}
// Delete a policy and clean up associated results and schedules.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    if let Err(e) = sqlx::query(r#"
        DELETE FROM results
        WHERE system_id IN (
            SELECT id FROM systems WHERE tenant_id = ?
        )
        AND test_id NOT IN (
            SELECT DISTINCT tip.test_id
            FROM tests_in_policy tip
            JOIN systems_in_policy sip ON tip.policy_id = sip.policy_id
            JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            WHERE sig.tenant_id = ?
            AND tip.policy_id != ?
        )
    "#)
    .bind(&auth.tenant_id).bind(&auth.tenant_id).bind(id).execute(&pool).await
    {
        error!("Failed to clean up results for deleted policy {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    if let Err(e) = sqlx::query("DELETE FROM policies WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).execute(&pool).await
    {
        error!("Failed to delete policy {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting policy: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    // Trend history has no FK (deletion must never be blocked by it) — clean
    // up explicitly; anything missed ages out via entity_trend_retention_days.
    let _ = sqlx::query(
        "DELETE FROM entity_compliance_history
         WHERE tenant_id = ? AND entity_type = 'policy' AND entity_id = ?")
        .bind(&auth.tenant_id).bind(id)
        .execute(&pool).await;

    let _ = sync_tx.send(()).await;
    info!("Policy ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/policies").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/run/{id}
// Queue scan commands for all systems linked to the policy.
// Role: Runner
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_run(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    match execute_policy_run_logic(id, &pool, &auth.tenant_id).await {
        Ok(_) => {
            info!("Policy ID {} run by '{}'.", id, auth.username);
            Redirect::to("/policies?success_message=Policy+run+successfully").into_response()
        }
        Err(e) => {
            error!("Failed to run policy {}: {}", id, e);
            let encoded = urlencoding::encode(&format!("Error running policy: {}", e)).to_string();
            Redirect::to(&format!("/policies?error_message={}", encoded)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: read_compliance_mode
// Reads a per-tenant compliance-mode setting by key (0.6.5). There are two
// independent toggles (Settings → Compliance):
//   • "policy_compliance_mode": "test" | "system"  — how a POLICY's % is scored
//   • "system_compliance_mode": "test" | "policy"  — how a SYSTEM's % is scored
// Unset / unrecognised → "test".
// ─────────────────────────────────────────────────────────────────────────────
pub async fn read_compliance_mode(pool: &SqlitePool, tenant_id: &str, skey: &str) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE tenant_id = ? AND skey = ?",
    )
    .bind(tenant_id)
    .bind(skey)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .filter(|v| v == "system" || v == "policy" || v == "test")
    .unwrap_or_else(|| "test".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: compliance_pct
// Aggregate compliance % over a set of "units", each a (pass_count, fail_count)
// pair. A unit is a SYSTEM when scoring a policy, or a POLICY when scoring a
// system. NA / excluded are already out of the counts upstream.
//   • binary = true  — % of units that FULLY comply (no FAIL, ≥1 PASS) among
//                      applicable units (≥1 PASS/FAIL). Per-system / per-policy.
//   • binary = false — % of individual test results that passed
//                      (total PASS / (PASS + FAIL)). Per-test.
// Returns -1.0 ("not scanned") when nothing is applicable, so the template can
// render a "Not Scanned" badge instead of "0% Non-Compliant".
// ─────────────────────────────────────────────────────────────────────────────
pub fn compliance_pct(binary: bool, units: &[(usize, usize)]) -> f64 {
    if binary {
        let applicable = units.iter().filter(|(p, f)| *p > 0 || *f > 0).count();
        if applicable == 0 { return -1.0; }
        let compliant = units.iter().filter(|(p, f)| *f == 0 && *p > 0).count();
        (compliant as f64 / applicable as f64) * 100.0
    } else {
        let tp: usize = units.iter().map(|(p, _)| *p).sum();
        let tf: usize = units.iter().map(|(_, f)| *f).sum();
        if tp + tf == 0 { return -1.0; }
        (tp as f64 / (tp + tf) as f64) * 100.0
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /policies/report/{policy_id}/exclude/{system_id}/{test_id}
// Mark a (system, test) finding as excluded from the live policy report and
// compliance scoring. Idempotent — repeat clicks are no-ops via INSERT OR IGNORE.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_report_exclude(
    auth: AuthSession,
    Path((policy_id, system_id, test_id)): Path<(i32, i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let res = sqlx::query(
        "UPDATE results SET excluded = 1, excluded_by = ?, excluded_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ? AND system_id = ? AND test_id = ?",
    )
    .bind(&auth.username)
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(test_id)
    .execute(&pool)
    .await;

    let back = format!("/policies/report/{}", policy_id);
    match res {
        Ok(_) => {
            info!(
                "Result excluded by '{}' — policy={} system={} test={}",
                auth.username, policy_id, system_id, test_id
            );
            crate::audit::record(
                &pool, &auth.tenant_id,
                Some(&auth), Some(ip.as_str()),
                "policy.result_exclude",
                Some("result"),
                Some(&format!("policy:{}/sys:{}/test:{}", policy_id, system_id, test_id)),
                None,
            ).await;
            // Compliance scores need to drop the excluded finding.
            let _ = sync_tx.try_send(());
            let msg = urlencoding::encode("Finding excluded.").to_string();
            Redirect::to(&format!("{}?success_message={}", back, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to insert result exclusion: {}", e);
            let msg = urlencoding::encode("Failed to exclude finding.").to_string();
            Redirect::to(&format!("{}?error_message={}", back, msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /policies/report/{policy_id}/unexclude/{system_id}/{test_id}
// Remove an exclusion so the finding counts in compliance again.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_report_unexclude(
    auth: AuthSession,
    Path((policy_id, system_id, test_id)): Path<(i32, i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let res = sqlx::query(
        "UPDATE results SET excluded = 0, excluded_by = NULL, excluded_at = NULL
         WHERE tenant_id = ? AND system_id = ? AND test_id = ?",
    )
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(test_id)
    .execute(&pool)
    .await;

    let back = format!("/policies/report/{}", policy_id);
    match res {
        Ok(_) => {
            info!(
                "Result un-excluded by '{}' — policy={} system={} test={}",
                auth.username, policy_id, system_id, test_id
            );
            crate::audit::record(
                &pool, &auth.tenant_id,
                Some(&auth), Some(ip.as_str()),
                "policy.result_unexclude",
                Some("result"),
                Some(&format!("policy:{}/sys:{}/test:{}", policy_id, system_id, test_id)),
                None,
            ).await;
            let _ = sync_tx.try_send(());
            let msg = urlencoding::encode("Finding restored.").to_string();
            Redirect::to(&format!("{}?success_message={}", back, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to delete result exclusion: {}", e);
            let msg = urlencoding::encode("Failed to restore finding.").to_string();
            Redirect::to(&format!("{}?error_message={}", back, msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/report/{id}
// Render the live compliance report for a policy (current results).
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_report(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let policy_row = match sqlx::query(
        "SELECT id, name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id).fetch_optional(&*pool).await
    {
        Ok(Some(row)) => row,
        Ok(None) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        Err(e) => { error!(error = ?e, policy_id = %id, "Failed to fetch policy details"); return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
    };

    let test_rows = match sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
    "#)
    .bind(id).bind(&auth.tenant_id).fetch_all(&*pool).await
    {
        Ok(rows) => rows,
        Err(e) => { error!(error = ?e, policy_id = %id, "Failed to fetch tests for policy report"); return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
    };

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get("description"),
        rational: row.get("rational"),
        remediation: row.get("remediation"),
    }).collect();

    let result_rows = match sqlx::query(r#"
        SELECT
            s.id   as system_id,
            s.name as system_name,
            t.id   as test_id,
            t.name as test_name,
            r.result as status,
            r.excluded as is_excluded,
            r.evidence as evidence
        FROM results r
        JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
        JOIN tests t ON r.test_id = t.id AND r.tenant_id = t.tenant_id
        WHERE r.tenant_id = ?
          AND r.container_id = 0
          AND r.test_id IN (
              SELECT test_id FROM tests_in_policy
              WHERE policy_id = ? AND tenant_id = ?
          )
          AND r.system_id IN (
              SELECT sig.system_id FROM systems_in_groups sig
              JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                  AND sig.tenant_id = sip.tenant_id
              WHERE sip.policy_id = ? AND sip.tenant_id = ?
          )
    "#)
    .bind(&auth.tenant_id).bind(id).bind(&auth.tenant_id).bind(id).bind(&auth.tenant_id)
    .fetch_all(&*pool).await
    {
        Ok(rows) => rows,
        Err(e) => { error!(error = ?e, policy_id = %id, "Failed to fetch policy results"); return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
    };

    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        let system_name = row.get::<Option<String>, _>("system_name").unwrap_or_else(|| "Unknown System".to_string());
        let test_name: String = row.get("test_name");
        let status_raw: String = row.get("status");
        let status = normalize_status(&status_raw).to_string();
        let is_excluded: bool = row.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0;
        let system_id: Option<i64> = row.try_get("system_id").ok();
        let test_id:   Option<i64> = row.try_get("test_id").ok();
        system_map.entry(system_name).or_insert_with(Vec::new).push(IndividualResult {
            test_name,
            status,
            is_excluded,
            is_excludable: true, // live report → right-click menu enabled
            system_id,
            test_id,
            evidence: row.try_get("evidence").ok().flatten(),
        });
    }

    // Per-container results nested under their host (separate axis). Empty for
    // hosts with no container tests; a DB hiccup degrades to host-only rendering.
    let mut container_map = fetch_policy_container_groups(&pool, &auth.tenant_id, id as i64)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to fetch container results for policy {}: {}", id, e);
            Default::default()
        });

    // Excluded findings count as NA: removed from both numerator and denominator.
    let system_reports: Vec<SystemReport> = system_map.into_iter().map(|(name, results)| {
        let pass_count     = results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
        let fail_count     = results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
        let na_count       = results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();
        let excluded_count = results.iter().filter(|r| r.is_excluded).count();
        let is_passed = is_system_passed(pass_count, fail_count);
        let containers = container_map.remove(&name).unwrap_or_default();
        SystemReport { system_name: name, results, is_passed, pass_count, fail_count, na_count, excluded_count, containers }
    }).collect();

    // All-NA systems (exempt) are not counted as failures.
    let fail_count = system_reports.iter().filter(|s| s.fail_count > 0).count();

    // Top-card aggregates: sum per-system counts and compute a policy-level
    // compliance score (% systems COMPLIANT among non-exempt systems).
    let total_pass:     usize = system_reports.iter().map(|s| s.pass_count).sum();
    let total_fail:     usize = system_reports.iter().map(|s| s.fail_count).sum();
    let total_na:       usize = system_reports.iter().map(|s| s.na_count).sum();
    let total_excluded: usize = system_reports.iter().map(|s| s.excluded_count).sum();
    let pmode = read_compliance_mode(&pool, &auth.tenant_id, "policy_compliance_mode").await;
    let units: Vec<(usize, usize)> = system_reports.iter().map(|s| (s.pass_count, s.fail_count)).collect();
    let host_score = compliance_pct(pmode == "system", &units);
    // Pure-container policy: no host-axis score → show the container axis.
    let compliance_score = if host_score < 0.0 {
        container_axis_avg(&system_reports).unwrap_or(host_score)
    } else { host_score };

    let report_data = ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row.get::<Option<String>, _>("description").unwrap_or_default(),
        // Stored/displayed as canonical UTC (no tz marker); the web UI converts
        // it to the viewer's browser timezone client-side.
        submission_date: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        submitter_name: auth.username.clone(),
        tests_metadata,
        system_reports,
        total_pass,
        total_fail,
        total_na,
        total_excluded,
        compliance_score,
    };

    // Compliance thresholds for the top-card badge (same source as the
    // policies list and the system report).
    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_sat'",
    )
    .bind(&auth.tenant_id).fetch_one(&*pool).await.unwrap_or(80);
    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_marginal'",
    )
    .bind(&auth.tenant_id).fetch_one(&*pool).await.unwrap_or(60);

    // Trend for this policy (mode-aware, ?range= bucketed; empty → card hidden).
    let trend_range = normalize_trend_range(query.range.as_deref());
    let (trend_labels, trend_scores, trend_passed, trend_failed) =
        fetch_entity_trend(&pool, &auth.tenant_id, "policy", id as i64, pmode == "system", trend_range).await;

    let mut context = Context::new();
    context.insert("report", &report_data);
    context.insert("fail_count", &fail_count);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    context.insert("trend_labels", &trend_labels);
    context.insert("trend_scores", &trend_scores);
    context.insert("trend_passed", &trend_passed);
    context.insert("trend_failed", &trend_failed);
    context.insert("trend_range", &trend_range);
    context.insert("is_smtp_configured", &crate::reports::is_smtp_configured(&pool).await);
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    render_template(&tera, Some(&pool), "policies_report.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: cell
// Wraps a PDF element with uniform cell padding for table layout.
// ─────────────────────────────────────────────────────────────────────────────
fn cell<E: Element + 'static>(e: E) -> Box<dyn Element> {
    Box::new(elements::PaddedElement::new(e, Margins::trbl(1.5, 2.0, 1.5, 2.0)))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/download/{id}
// Generate and stream a PDF version of the live policy compliance report.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// Helper: assemble_container_groups
// Folds a flat result set of per-container rows (one row per container × test)
// into one ContainerReportGroup per container, keyed by host system name. Each
// group carries the container's own compliance_score (separate axis) and its
// per-test IndividualResults. Container rows are never excludable (exclusion is
// keyed on (system,test), independent of container), so is_excludable = false.
// Expected columns: system_name, container_id, container_name, runtime, image,
// cscore, test_name, status, is_excluded, evidence, system_id, test_id.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn assemble_container_groups(
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> BTreeMap<String, Vec<ContainerReportGroup>> {
    let mut by_sys: BTreeMap<String, BTreeMap<i64, ContainerReportGroup>> = BTreeMap::new();
    for row in rows {
        let system_name: String = row.get::<Option<String>, _>("system_name")
            .unwrap_or_else(|| "Unknown System".to_string());
        let cid: i64 = row.get("container_id");
        let grp = by_sys.entry(system_name).or_default().entry(cid).or_insert_with(|| {
            ContainerReportGroup {
                container_id: cid,
                name: row.get::<Option<String>, _>("container_name").unwrap_or_default(),
                runtime: row.get::<Option<String>, _>("runtime").unwrap_or_default(),
                image: row.try_get("image").ok().flatten(),
                // Round defensively: values stored before the ROUND-at-source
                // fix may carry full float precision, and saved snapshots
                // freeze whatever is rendered here.
                compliance_score: (row.try_get::<f64, _>("cscore").unwrap_or(-1.0) * 100.0).round() / 100.0,
                pass_count: 0, fail_count: 0, na_count: 0,
                results: Vec::new(),
            }
        });
        grp.results.push(IndividualResult {
            test_name: row.get("test_name"),
            status: normalize_status(&row.get::<String, _>("status")).to_string(),
            is_excluded: row.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0,
            is_excludable: false,
            system_id: row.try_get("system_id").ok(),
            test_id: row.try_get("test_id").ok(),
            evidence: row.try_get("evidence").ok().flatten(),
        });
    }
    by_sys.into_iter().map(|(sys, cmap)| {
        let mut groups: Vec<ContainerReportGroup> = cmap.into_values().map(|mut g| {
            g.pass_count = g.results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
            g.fail_count = g.results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
            g.na_count   = g.results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();
            g
        }).collect();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        (sys, groups)
    }).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: fetch_entity_trend
// Trend points for one system or policy, for the report-page chart (0.7.2).
// Mode-aware: `strict` selects the all-or-nothing axis (score_strict) instead
// of per-test, mirroring the dashboard's column pick — so flipping a
// compliance-mode toggle re-renders the whole line, no jump. `range` buckets
// the hourly snapshots exactly like the dashboard's fleet trend: hourly (last
// 24), daily (last 30), weekly / monthly (last 12), yearly (last 10); buckets
// average their snapshots. Not-scanned points (score < 0) are filtered out.
// Returns (labels, scores, tests_passed, tests_failed), oldest first; the
// tallies are per-bucket averages, shown in the chart tooltip.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) async fn fetch_entity_trend(
    pool: &SqlitePool,
    tenant_id: &str,
    entity_type: &str,
    entity_id: i64,
    strict: bool,
    range: &str,
) -> (Vec<String>, Vec<f64>, Vec<i64>, Vec<i64>) {
    let col = if strict { "score_strict" } else { "score_test" };
    // Same bucketing/format/limits as the dashboard's fleet trend.
    let date_col: &str = match range {
        "yearly"  => "strftime('%Y', check_date)",
        "weekly"  => "strftime('%Y-W%W', check_date)",
        "monthly" => "strftime('%m-%Y', check_date)",
        "daily"   => "strftime('%Y-%m-%d', check_date)",
        _         => "strftime('%m-%d %H:00', check_date)",
    };
    let limit: i32 = match range {
        "yearly"  => 10,
        "weekly" | "monthly" => 12,
        "daily"   => 30,
        _         => 24, // hourly: last 24 hours
    };

    let rows = sqlx::query(&format!(
        "SELECT {date_col} AS label,
                ROUND(AVG({col}), 2) AS score,
                CAST(ROUND(AVG(tests_passed)) AS INTEGER) AS tests_passed,
                CAST(ROUND(AVG(tests_failed)) AS INTEGER) AS tests_failed
         FROM entity_compliance_history
         WHERE tenant_id = ? AND entity_type = ? AND entity_id = ?
           AND {col} >= 0
         GROUP BY 1 ORDER BY MAX(check_date) DESC LIMIT {limit}"))
    .bind(tenant_id).bind(entity_type).bind(entity_id)
    .fetch_all(pool).await
    .unwrap_or_else(|e| {
        error!("Failed to fetch trend for {} {}: {}", entity_type, entity_id, e);
        Vec::new()
    });

    let mut labels = Vec::with_capacity(rows.len());
    let mut scores = Vec::with_capacity(rows.len());
    let mut passed = Vec::with_capacity(rows.len());
    let mut failed = Vec::with_capacity(rows.len());
    // Query is newest-first (for LIMIT); the chart wants oldest-first.
    for r in rows.into_iter().rev() {
        labels.push(r.get::<String, _>("label"));
        scores.push(r.get::<f64, _>("score"));
        passed.push(r.try_get::<i64, _>("tests_passed").unwrap_or(0));
        failed.push(r.try_get::<i64, _>("tests_failed").unwrap_or(0));
    }
    (labels, scores, passed, failed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: normalize_trend_range
// Clamp a ?range= query value to the known set; anything else → "hourly".
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn normalize_trend_range(range: Option<&str>) -> &'static str {
    match range {
        Some("daily")   => "daily",
        Some("weekly")  => "weekly",
        Some("monthly") => "monthly",
        Some("yearly")  => "yearly",
        _               => "hourly",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: container_axis_avg
// Mean of the per-container compliance scores across all hosts in a report.
// Used as the headline fallback when the host axis is "Not Scanned" (a policy
// made entirely of container tests). Returns None when no container has a
// scored result, so the caller keeps the -1.0 "Not Scanned" headline.
// ─────────────────────────────────────────────────────────────────────────────
fn container_axis_avg(system_reports: &[SystemReport]) -> Option<f64> {
    let scores: Vec<f64> = system_reports.iter()
        .flat_map(|s| s.containers.iter())
        .map(|c| c.compliance_score)
        .filter(|v| *v >= 0.0)
        .collect();
    if scores.is_empty() {
        None
    } else {
        Some((scores.iter().sum::<f64>() / scores.len() as f64 * 100.0).round() / 100.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: fetch_policy_container_groups
// Per-container test results for a policy, grouped by host system name. Scoped
// to the policy's tests and in-scope systems, container rows only (container_id
// > 0). Used to nest containers under each host in the policy report.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) async fn fetch_policy_container_groups(
    pool: &SqlitePool, tenant_id: &str, policy_id: i64,
) -> Result<BTreeMap<String, Vec<ContainerReportGroup>>, sqlx::Error> {
    let rows = sqlx::query(r#"
        SELECT s.name AS system_name, c.id AS container_id, c.name AS container_name,
               c.runtime AS runtime, c.image AS image, c.compliance_score AS cscore,
               t.name AS test_name, r.result AS status, r.excluded AS is_excluded,
               r.evidence AS evidence, r.system_id AS system_id, r.test_id AS test_id
        FROM results r
        JOIN systems s    ON r.system_id    = s.id AND r.tenant_id = s.tenant_id
        JOIN tests t      ON r.test_id      = t.id AND r.tenant_id = t.tenant_id
        JOIN containers c ON r.container_id = c.id AND r.tenant_id = c.tenant_id
        WHERE r.tenant_id = ?
          AND r.container_id > 0
          AND r.test_id IN (
              SELECT test_id FROM tests_in_policy WHERE policy_id = ? AND tenant_id = ?
          )
          AND r.system_id IN (
              SELECT sig.system_id FROM systems_in_groups sig
              JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                  AND sig.tenant_id = sip.tenant_id
              WHERE sip.policy_id = ? AND sip.tenant_id = ?
          )
        ORDER BY s.name, c.name, t.name
    "#)
    .bind(tenant_id).bind(policy_id).bind(tenant_id).bind(policy_id).bind(tenant_id)
    .fetch_all(pool).await?;
    Ok(assemble_container_groups(rows))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: fetch_live_policy_report_data
// Builds a fresh ReportData for the given policy by querying the live tables
// (tests + results) — shared by policies_report_download and the new
// policies_report_email handler so both flows always reflect current state.
// Returns Ok(None) for missing policy / wrong tenant; an Err for DB errors.
// ─────────────────────────────────────────────────────────────────────────────
async fn fetch_live_policy_report_data(
    pool: &SqlitePool,
    tenant_id: &str,
    submitter_name: &str,
    id: i64,
) -> Result<Option<ReportData>, sqlx::Error> {
    let policy_row = match sqlx::query(
        "SELECT id, name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(tenant_id).fetch_optional(pool).await?
    {
        Some(row) => row,
        None => return Ok(None),
    };

    let test_rows = sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
    "#)
    .bind(id).bind(tenant_id).fetch_all(pool).await?;

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        rational: row.get::<Option<String>, _>("rational").unwrap_or_default(),
        remediation: row.get::<Option<String>, _>("remediation").unwrap_or_default(),
    }).collect();

    let result_rows = sqlx::query(r#"
        SELECT DISTINCT
            s.id   as system_id,
            s.name as system_name,
            t.id   as test_id,
            t.name as test_name,
            r.result as status,
            r.excluded as is_excluded,
            r.evidence as evidence
        FROM results r
        JOIN systems s ON r.system_id = s.id
        JOIN tests t ON r.test_id = t.id
        JOIN systems_in_groups sig ON s.id = sig.system_id
        JOIN systems_in_policy sip ON sig.group_id = sip.group_id
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE sip.policy_id = ?
          AND tip.policy_id = ?
          AND sip.tenant_id = ?
          AND r.container_id = 0
    "#)
    .bind(id).bind(id).bind(tenant_id).fetch_all(pool).await?;

    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        let system_name = row.get::<Option<String>, _>("system_name").unwrap_or_else(|| "Unknown System".to_string());
        let test_name: String = row.get("test_name");
        let status_raw: String = row.get("status");
        let status = normalize_status(&status_raw).to_string();
        let is_excluded: bool = row.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0;
        let system_id: Option<i64> = row.try_get("system_id").ok();
        let test_id:   Option<i64> = row.try_get("test_id").ok();
        system_map.entry(system_name).or_insert_with(Vec::new).push(IndividualResult {
            test_name,
            status,
            is_excluded,
            // PDF / email / saved snapshot — not interactive; freeze the badge.
            is_excludable: false,
            system_id,
            test_id,
            evidence: row.try_get("evidence").ok().flatten(),
        });
    }

    let mut container_map = fetch_policy_container_groups(pool, tenant_id, id)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to fetch container results for policy {}: {}", id, e);
            Default::default()
        });

    // Excluded findings count as NA in pass/fail tallies.
    let system_reports: Vec<SystemReport> = system_map.into_iter().map(|(name, results)| {
        let pass_count     = results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
        let fail_count     = results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
        let na_count       = results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();
        let excluded_count = results.iter().filter(|r| r.is_excluded).count();
        let is_passed = is_system_passed(pass_count, fail_count);
        let containers = container_map.remove(&name).unwrap_or_default();
        SystemReport { system_name: name, results, is_passed, pass_count, fail_count, na_count, excluded_count, containers }
    }).collect();

    let total_pass:     usize = system_reports.iter().map(|s| s.pass_count).sum();
    let total_fail:     usize = system_reports.iter().map(|s| s.fail_count).sum();
    let total_na:       usize = system_reports.iter().map(|s| s.na_count).sum();
    let total_excluded: usize = system_reports.iter().map(|s| s.excluded_count).sum();
    let pmode = read_compliance_mode(pool, tenant_id, "policy_compliance_mode").await;
    let units: Vec<(usize, usize)> = system_reports.iter().map(|s| (s.pass_count, s.fail_count)).collect();
    let host_score = compliance_pct(pmode == "system", &units);
    let compliance_score = if host_score < 0.0 {
        container_axis_avg(&system_reports).unwrap_or(host_score)
    } else { host_score };

    Ok(Some(ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row.get::<Option<String>, _>("description").unwrap_or_default(),
        // Canonical UTC (no tz marker); localized to the browser tz in the UI.
        submission_date: Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        submitter_name: submitter_name.to_string(),
        tests_metadata,
        system_reports,
        total_pass,
        total_fail,
        total_na,
        total_excluded,
        compliance_score,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build_live_policy_pdf
// Renders a live-policy compliance report into a PDF byte buffer. Shared by
// the download and the email handler so the two flows can't drift in layout.
// Public so `tests/pdf_render.rs` can render golden fixtures for visual
// before/after comparison across renderer changes.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_live_policy_pdf(report_data: &ReportData) -> Result<Vec<u8>, ()> {
    const FONT_REGULAR: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES: &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    let font_family = match (
        fonts::FontData::new(FONT_REGULAR.to_vec(), None),
        fonts::FontData::new(FONT_BOLD.to_vec(), None),
        fonts::FontData::new(FONT_ITALIC.to_vec(), None),
        fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None),
    ) {
        (Ok(regular), Ok(bold), Ok(italic), Ok(bold_italic)) => fonts::FontFamily { regular, bold, italic, bold_italic },
        _ => { error!("Failed to load PDF fonts"); return Err(()); }
    };

    let mut doc = genpdf::Document::new(font_family);
    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = match elements::Image::from_reader(cursor) {
        Ok(img) => img,
        Err(e) => { error!("Failed to load PDF logo: {}", e); return Err(()); }
    };

    doc.set_title(format!("OpenSCM Compliance Report - {}", report_data.policy_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(style::Style::new().with_font_size(30).bold().with_color(style::Color::Rgb(0, 0, 128))));
    doc.push(elements::Break::new(2.0));

    let mut submitter = elements::Paragraph::new(format!("Generated on {} by {}", report_data.submission_date, report_data.submitter_name));
    submitter.set_alignment(genpdf::Alignment::Center);
    doc.push(submitter);
    doc.push(elements::Break::new(0.5));

    logo.set_dpi(40.0);
    logo.set_alignment(genpdf::Alignment::Center);
    doc.push(logo);
    doc.push(elements::Break::new(1.0));

    doc.push(elements::Text::new("Report Details").styled(style::Style::new().bold().with_font_size(14)));
    doc.push(elements::Break::new(0.5));
    let mut details_table = elements::TableLayout::new(vec![1, 3]);
    details_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));
    if let Err(e) = details_table.push_row(vec![
        cell(elements::Text::new("Policy Name").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(format!("{} v{}", report_data.policy_name, report_data.version))),
    ]) { error!("Failed to add policy name row to PDF: {}", e); }
    if let Err(e) = details_table.push_row(vec![
        cell(elements::Text::new("Description").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(report_data.description.clone())),
    ]) { error!("Failed to add description row to PDF: {}", e); }
    doc.push(details_table);

    // ──────────────────────────────────────────────────────────────────────
    // Tests Summary — name + description of every test in the policy.
    // Renders on its own page so the cover (title + Report Details) and the
    // test catalog don't compete for space on page 1. tests_metadata is
    // already collected from the live DB above, so this section always
    // reflects current test definitions for on-demand PDFs.
    // ──────────────────────────────────────────────────────────────────────
    if !report_data.tests_metadata.is_empty() {
        doc.push(elements::PageBreak::new());
        doc.push(
            elements::Text::new(format!(
                "Tests in this Policy ({})",
                report_data.tests_metadata.len(),
            ))
            .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        let mut tests_table = elements::TableLayout::new(vec![2, 5]);
        tests_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = tests_table.push_row(vec![
            cell(elements::Text::new("Test Name").styled(style::Style::new().bold())),
            cell(elements::Text::new("Description").styled(style::Style::new().bold())),
        ]) {
            error!("Failed to add tests summary header to PDF: {}", e);
        }

        for tm in &report_data.tests_metadata {
            let desc = if tm.description.trim().is_empty() {
                "—".to_string()
            } else {
                tm.description.clone()
            };
            if let Err(e) = tests_table.push_row(vec![
                cell(elements::Paragraph::new(&tm.name)),
                cell(elements::Paragraph::new(&desc)),
            ]) {
                error!("Failed to add tests summary row to PDF: {}", e);
            }
        }

        doc.push(tests_table);
    }

    doc.push(elements::PageBreak::new());

    for system in &report_data.system_reports {
        doc.push(elements::Text::new(format!("Host Name: {}", system.system_name)).styled(style::Style::new().bold().with_font_size(14)));
        doc.push(elements::Break::new(0.5));

        // Excluded findings don't count as PASS or FAIL — match the on-screen
        // tallies and the three-way verdict (Compliant / Non-Compliant / Not Applicable).
        let compliant_count = system.pass_count;
        let violation_count = system.fail_count;
        let na_count        = system.na_count;
        let excluded_count  = system.excluded_count;
        let exempt = compliant_count == 0 && violation_count == 0;
        let (status_text, status_color) = if exempt {
            ("Not Applicable", style::Color::Rgb(120, 120, 120))
        } else if system.is_passed {
            ("Compliant", style::Color::Rgb(0, 128, 0))
        } else {
            ("Non-Compliant", style::Color::Rgb(200, 0, 0))
        };

        let mut summary_table = elements::TableLayout::new(vec![1, 1]);
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));
        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Compliance Status").styled(style::Style::new().bold())),
            cell(elements::Text::new(status_text).styled(
                style::Style::new().with_color(status_color).bold(),
            )),
        ]) { error!("Failed to add compliance status row to PDF: {}", e); }
        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Passed").styled(style::Style::new().bold())),
            cell(elements::Text::new(format!("{}", compliant_count))),
        ]) { error!("Failed to add passed count row to PDF: {}", e); }
        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Failed").styled(style::Style::new().bold())),
            cell(elements::Text::new(format!("{}", violation_count))),
        ]) { error!("Failed to add failed count row to PDF: {}", e); }
        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Not Applicable").styled(style::Style::new().bold())),
            cell(elements::Text::new(format!("{}", na_count))),
        ]) { error!("Failed to add NA count row to PDF: {}", e); }
        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Excluded").styled(style::Style::new().bold())),
            cell(elements::Text::new(format!("{}", excluded_count))),
        ]) { error!("Failed to add excluded count row to PDF: {}", e); }
        doc.push(summary_table);
        doc.push(elements::Break::new(1.0));

        doc.push(elements::Text::new("Audit Rules Detailed Breakdown").styled(style::Style::new().bold().with_font_size(14)));
        doc.push(elements::Break::new(0.5));
        let mut rules_table = elements::TableLayout::new(vec![4, 1]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));
        if let Err(e) = rules_table.push_row(vec![
            cell(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            cell(elements::Text::new("Status").styled(style::Style::new().bold())),
        ]) { error!("Failed to add rules table header to PDF: {}", e); }

        for res in &system.results {
            let (status_text, status_color) = if res.is_excluded {
                ("EXCLUDED", style::Color::Rgb(120, 120, 120))
            } else {
                match res.status.as_str() {
                    "PASS" => ("PASS", style::Color::Rgb(0, 128, 0)),
                    "NA"   => ("N/A",  style::Color::Rgb(120, 120, 120)),
                    _      => ("FAIL", style::Color::Rgb(200, 0, 0)),
                }
            };
            if let Err(e) = rules_table.push_row(vec![
                cell(elements::Paragraph::new(&res.test_name)),
                cell(elements::Text::new(status_text).styled(style::Style::new().with_color(status_color).bold())),
            ]) { error!("Failed to add rule row to PDF: {}", e); }
        }
        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    doc.push(elements::Break::new(2.0));
    doc.push(elements::Paragraph::new(
        "Note: This report contains confidential information about your infrastructure \
         and should be treated as such. Unauthorized distribution is strictly prohibited.",
    ).styled(style::Style::new().with_font_size(10).with_color(style::Color::Rgb(100, 100, 100))));

    let mut buffer = Vec::new();
    doc.render(&mut buffer).map_err(|e| { error!("Failed to render live policy PDF: {}", e); })?;
    Ok(buffer)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/download/{id}
// Generate and stream a PDF of the live policy compliance report.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_report_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let report_data = match fetch_live_policy_report_data(&pool, &auth.tenant_id, &auth.username, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!("Failed to fetch live policy {} for PDF: {}", id, e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let buffer = match build_live_policy_pdf(&report_data) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id))
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|e| { error!("Failed to build PDF response: {}", e); StatusCode::INTERNAL_SERVER_ERROR.into_response() })
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /policies/email/{id}
// Email the live-policy PDF to the logged-in user's address.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_report_email(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/policies/report/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return crate::reports::flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match crate::reports::user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return crate::reports::flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let report_data = match fetch_live_policy_report_data(&pool, &auth.tenant_id, &auth.username, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!("Failed to fetch live policy {} for email: {}", id, e);
            return crate::reports::flash_back(&back, false, "Failed to load report.");
        }
    };

    let bytes = match build_live_policy_pdf(&report_data) {
        Ok(b) => b,
        Err(_) => return crate::reports::flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM Compliance Report — {} (live)", report_data.policy_name);
    let html_body = crate::reports::report_email_body(
        &report_data.policy_name,
        &report_data.version,
        &report_data.submission_date,
    );
    let filename = format!("OpenSCM_Report_{}.pdf", id);

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => crate::reports::flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => crate::reports::flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}


// ============================================================
// INTERNAL LOGIC
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: execute_policy_run_logic
// Inserts commands into the commands table for all systems in a policy.
// ─────────────────────────────────────────────────────────────────────────────
// GET /policies/export/{id}
// Streams a JSON file containing the policy, every linked test, and each
// test's conditions and applicability rules.  Excludes DB-internal ids and
// tenant_id so the file is portable across installations.  The exported
// `external_id` lets a later import update the same policy in place.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_export(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    Path(id): Path<i32>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir.into_response();
    }

    // Fetch the policy.
    let policy_row = match sqlx::query(
        "SELECT name, version, description, author, external_id
         FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&pool).await
    {
        Ok(Some(r)) => r,
        Ok(None)    => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        Err(e)      => {
            error!("DB error exporting policy {}: {}", id, e);
            return Redirect::to("/policies?error_message=Database+error").into_response();
        }
    };

    let policy_export = PolicyExportPolicy {
        external_id: policy_row.try_get::<Option<String>, _>("external_id").unwrap_or(None),
        name:        policy_row.get("name"),
        version:     policy_row.get("version"),
        description: policy_row.try_get::<Option<String>, _>("description").unwrap_or(None),
        author:      policy_row.try_get::<Option<String>, _>("author").unwrap_or(None),
    };

    // Fetch all tests linked to this policy.
    let test_rows = match sqlx::query(
        "SELECT t.id, t.name, t.description, t.rational, t.remediation,
                t.severity, t.filter, t.app_filter, t.external_id
         FROM tests t
         JOIN tests_in_policy tip ON t.id = tip.test_id
         WHERE tip.policy_id = ? AND tip.tenant_id = ?
         ORDER BY t.id ASC",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_all(&pool).await
    {
        Ok(rows) => rows,
        Err(e)   => {
            error!("DB error fetching tests for export {}: {}", id, e);
            return Redirect::to("/policies?error_message=Database+error").into_response();
        }
    };

    let mut tests: Vec<PolicyExportTest> = Vec::with_capacity(test_rows.len());
    for t in test_rows {
        let test_id: i64 = t.get("id");

        let cond_rows = match sqlx::query(
            "SELECT `type`, element, input, selement, condition, sinput
             FROM test_conditions
             WHERE test_id = ? AND tenant_id = ?
             ORDER BY id ASC",
        )
        .bind(test_id).bind(&auth.tenant_id)
        .fetch_all(&pool).await
        {
            Ok(rows) => rows,
            Err(e)   => {
                error!("DB error fetching conditions for test {}: {}", test_id, e);
                return Redirect::to("/policies?error_message=Database+error").into_response();
            }
        };

        let mut conditions   = Vec::new();
        let mut applicability = Vec::new();
        for c in cond_rows {
            let entry = PolicyExportTestCondition {
                r#type:    c.get("type"),
                element:   c.get("element"),
                input:     c.get("input"),
                selement:  c.get("selement"),
                condition: c.try_get::<Option<String>, _>("condition").unwrap_or(None),
                sinput:    c.try_get::<Option<String>, _>("sinput").unwrap_or(None),
            };
            if entry.r#type == "applicability" {
                applicability.push(entry);
            } else {
                conditions.push(entry);
            }
        }

        tests.push(PolicyExportTest {
            external_id: t.try_get::<Option<String>, _>("external_id").unwrap_or(None),
            name:        t.get("name"),
            description: t.try_get::<Option<String>, _>("description").unwrap_or(None),
            rational:    t.try_get::<Option<String>, _>("rational").unwrap_or(None),
            remediation: t.try_get::<Option<String>, _>("remediation").unwrap_or(None),
            severity:    t.try_get::<Option<String>, _>("severity").unwrap_or(None),
            filter:      t.try_get::<Option<String>, _>("filter").unwrap_or(None),
            app_filter:  t.try_get::<Option<String>, _>("app_filter").unwrap_or(None),
            conditions,
            applicability,
        });
    }

    let export = PolicyExport { format_version: 3, policy: policy_export, tests };
    let body = match serde_json::to_vec_pretty(&export) {
        Ok(b)  => b,
        Err(e) => {
            error!("Serialise error for export {}: {}", id, e);
            return Redirect::to("/policies?error_message=Serialise+error").into_response();
        }
    };

    // Build filename: slug-version.json (lowercase, spaces→dashes, drop unsafe chars).
    let slug: String = export.policy.name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() }
                 else if c.is_whitespace() { '-' } else { '_' })
        .collect();
    let filename = format!("{}-{}.json", slug, export.policy.version);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .body(axum::body::Body::from(body))
        .unwrap()
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /policies/import
// Accepts a multipart upload with a single field "file" containing the JSON
// produced by policies_export.  Behaviour depends on external_id:
//   * Match on (tenant_id, external_id) → UPDATE policy metadata; DELETE
//     previously-linked tests + their conditions; INSERT fresh tests.
//   * No match → INSERT as a new policy; generate a fresh external_id when
//     the payload doesn't carry one (format v1).
//   * Name collision on insert → append " (imported)", then "-2", "-3", …
// Runs in a single transaction; partial failures roll back.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn policies_import(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir.into_response();
    }

    // Read the uploaded file.
    let mut file_bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            file_bytes = field.bytes().await.ok().map(|b| b.to_vec());
            break;
        }
    }
    let bytes = match file_bytes {
        Some(b) if !b.is_empty() => b,
        _ => return Redirect::to("/policies?error_message=No+file+uploaded").into_response(),
    };

    let export: PolicyExport = match serde_json::from_slice(&bytes) {
        Ok(p)  => p,
        Err(e) => {
            let msg = urlencoding::encode(&format!("Invalid policy file: {}", e)).to_string();
            return Redirect::to(&format!("/policies?error_message={}", msg)).into_response();
        }
    };

    match apply_policy_import(&pool, &auth.tenant_id, export).await {
        Ok(s) => {
            let mut summary = format!(
                "Policy {}: {} new, {} updated",
                s.action, s.inserted_tests, s.updated_tests
            );
            if s.unlinked_tests > 0 {
                summary.push_str(&format!(", {} unlinked", s.unlinked_tests));
            }
            let msg = urlencoding::encode(&summary).to_string();
            Redirect::to(&format!("/policies?success_message={}", msg)).into_response()
        }
        Err(e) => {
            let msg = urlencoding::encode(&e).to_string();
            Redirect::to(&format!("/policies?error_message={}", msg)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared import core.  Called by:
//   * /policies/import (multipart upload — file from the user's disk)
//   * SaaS /store/install/{external_id} (file fetched from the policy store)
// Both paths feed it a parsed PolicyExport and let it do the upsert work in a
// single transaction. Returns a structured summary on success or a
// caller-friendly error string on failure.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn apply_policy_import(
    pool: &SqlitePool,
    tenant_id: &str,
    export: PolicyExport,
) -> Result<PolicyImportSummary, String> {
    if export.format_version < 1 || export.format_version > 3 {
        return Err(format!("Unsupported format_version: {}", export.format_version));
    }

    let mut tx = pool.begin().await
        .map_err(|e| format!("Database error: {}", e))?;

    // Lookup existing policy by external_id within this tenant.
    let existing_id: Option<i64> = if let Some(ref xid) = export.policy.external_id {
        sqlx::query_scalar("SELECT id FROM policies WHERE tenant_id = ? AND external_id = ?")
            .bind(tenant_id).bind(xid)
            .fetch_optional(&mut *tx).await
            .unwrap_or(None)
    } else { None };

    // ── Update path: external_id matched ────────────────────────────────────
    let policy_id: i64 = if let Some(pid) = existing_id {
        sqlx::query(
            "UPDATE policies SET name = ?, version = ?, description = ?, author = ?
             WHERE id = ? AND tenant_id = ?",
        )
        .bind(&export.policy.name).bind(&export.policy.version)
        .bind(&export.policy.description).bind(&export.policy.author)
        .bind(pid).bind(tenant_id)
        .execute(&mut *tx).await
        .map_err(|e| { let _ = tx; format!("Update failed: {}", e) })?;
        pid
    } else {
        // ── Insert path: new policy ─────────────────────────────────────────
        // Resolve name collision within the tenant.
        let mut final_name = export.policy.name.clone();
        let mut suffix = 0;
        loop {
            let existing: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM policies WHERE tenant_id = ? AND name = ? AND version = ?",
            )
            .bind(tenant_id).bind(&final_name).bind(&export.policy.version)
            .fetch_optional(&mut *tx).await.unwrap_or(None);
            if existing.is_none() { break; }
            suffix += 1;
            final_name = if suffix == 1 {
                format!("{} (imported)", export.policy.name)
            } else {
                format!("{} (imported)-{}", export.policy.name, suffix)
            };
        }

        let new_xid = export.policy.external_id.clone()
            .unwrap_or_else(crate::schema::generate_external_id);

        sqlx::query(
            "INSERT INTO policies (tenant_id, name, version, description, author, external_id)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(tenant_id).bind(&final_name).bind(&export.policy.version)
        .bind(&export.policy.description).bind(&export.policy.author).bind(&new_xid)
        .execute(&mut *tx).await
        .map_err(|e| format!("Insert failed: {}", e))?;

        sqlx::query_scalar::<_, i64>("SELECT last_insert_rowid()")
            .fetch_one(&mut *tx).await
            .map_err(|e| format!("Insert failed: {}", e))?
    };

    // ── Upsert each test by external_id; replace its conditions; link to policy ──
    let mut imported_test_ids: Vec<i64> = Vec::with_capacity(export.tests.len());
    let mut updated_count = 0usize;
    let mut inserted_count = 0usize;

    for test in &export.tests {
        let existing_test_id: Option<i64> = if let Some(ref xid) = test.external_id {
            sqlx::query_scalar("SELECT id FROM tests WHERE tenant_id = ? AND external_id = ?")
                .bind(tenant_id).bind(xid)
                .fetch_optional(&mut *tx).await
                .unwrap_or(None)
        } else { None };

        let test_id: i64 = if let Some(tid) = existing_test_id {
            sqlx::query(
                "UPDATE tests SET name = ?, description = ?, rational = ?, remediation = ?,
                                  severity = ?, filter = ?, app_filter = ?
                 WHERE id = ? AND tenant_id = ?",
            )
            .bind(&test.name).bind(&test.description).bind(&test.rational).bind(&test.remediation)
            .bind(&test.severity).bind(&test.filter).bind(&test.app_filter)
            .bind(tid).bind(tenant_id)
            .execute(&mut *tx).await
            .map_err(|e| format!("Test update failed: {}", e))?;
            sqlx::query("DELETE FROM test_conditions WHERE test_id = ? AND tenant_id = ?")
                .bind(tid).bind(tenant_id)
                .execute(&mut *tx).await
                .map_err(|e| format!("Condition cleanup failed: {}", e))?;
            updated_count += 1;
            tid
        } else {
            let new_xid = test.external_id.clone()
                .unwrap_or_else(crate::schema::generate_external_id);
            sqlx::query(
                "INSERT INTO tests (tenant_id, name, description, rational, remediation, severity, filter, app_filter, external_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(tenant_id).bind(&test.name).bind(&test.description).bind(&test.rational)
            .bind(&test.remediation).bind(&test.severity).bind(&test.filter).bind(&test.app_filter)
            .bind(&new_xid)
            .execute(&mut *tx).await
            .map_err(|e| format!("Test insert failed: {}", e))?;
            let new_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
                .fetch_one(&mut *tx).await
                .map_err(|e| format!("Test insert failed: {}", e))?;
            inserted_count += 1;
            new_id
        };

        // Insert this test's conditions + applicability rules.
        let all_conds = test.conditions.iter().map(|c| ("condition", c))
            .chain(test.applicability.iter().map(|c| ("applicability", c)));
        for (ctype, c) in all_conds {
            sqlx::query(
                "INSERT INTO test_conditions (tenant_id, test_id, `type`, element, input, selement, condition, sinput)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(tenant_id).bind(test_id).bind(ctype)
            .bind(&c.element).bind(&c.input).bind(&c.selement).bind(&c.condition).bind(&c.sinput)
            .execute(&mut *tx).await
            .map_err(|e| format!("Condition insert failed: {}", e))?;
        }

        sqlx::query(
            "INSERT OR IGNORE INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES (?, ?, ?)",
        )
        .bind(tenant_id).bind(policy_id).bind(test_id)
        .execute(&mut *tx).await
        .map_err(|e| format!("Link insert failed: {}", e))?;

        imported_test_ids.push(test_id);
    }

    // Unlink tests previously linked to this policy that are not in the import.
    let unlinked_count = if existing_id.is_some() && !imported_test_ids.is_empty() {
        let placeholders = imported_test_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM tests_in_policy
             WHERE tenant_id = ? AND policy_id = ?
               AND test_id NOT IN ({})",
            placeholders,
        );
        let mut q = sqlx::query(&sql).bind(tenant_id).bind(policy_id);
        for tid in &imported_test_ids { q = q.bind(*tid); }
        q.execute(&mut *tx).await
            .map_err(|e| format!("Unlink failed: {}", e))?
            .rows_affected()
    } else { 0 };

    tx.commit().await.map_err(|e| format!("Commit failed: {}", e))?;

    Ok(PolicyImportSummary {
        policy_id,
        action:         if existing_id.is_some() { "updated" } else { "imported" },
        inserted_tests: inserted_count,
        updated_tests:  updated_count,
        unlinked_tests: unlinked_count,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Called by both the HTTP handler and the background scheduler.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn execute_policy_run_logic(
    id: i32,
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<(), sqlx::Error> {
    // Every test queues into the commands table the same way — agent
    // picks them up on its next heartbeat and evaluates locally against
    // its own world (host facts AND its discovered container inventory).
    // Per-container results come back with a `container_runtime_id`
    // field that the result handler resolves to containers.id.
    sqlx::query(r#"
        INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id)
        SELECT ?, sig.system_id, tip.test_id
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
        JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
        WHERE sip.policy_id = ?
          AND sip.tenant_id = ?
    "#)
    .bind(tenant_id).bind(id).bind(tenant_id)
    .execute(pool).await?;
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: execute_policy_run_for_system
// Same as execute_policy_run_logic but scoped to ONE system — backs the
// per-policy "Run" button on the system report, so an admin can re-check a
// single host after fixing a finding instead of rescanning the whole fleet.
//
// The systems_in_policy → systems_in_groups join is the safety property: a
// system the policy doesn't actually cover matches zero rows, so a crafted
// request can't queue a policy's tests onto an unrelated host. Returns the
// number of the policy's tests that APPLY to this system (0 = not covered), so
// the caller can report "queued 42" vs "this policy doesn't apply here".
// ─────────────────────────────────────────────────────────────────────────────
pub async fn execute_policy_run_for_system(
    policy_id: i32,
    system_id: i32,
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<u64, sqlx::Error> {
    // Count what APPLIES first, separately from the insert. `INSERT OR IGNORE`
    // reports rows_affected = 0 when the commands are already pending (a prior
    // run or the policy's schedule queued them and the agent hasn't consumed
    // them yet), so using that count would wrongly report a covered policy as
    // "does not apply to this system". COUNT(DISTINCT) mirrors the INSERT's
    // dedup when a system sits in several of the policy's groups.
    let applicable: i64 = sqlx::query_scalar(r#"
        SELECT COUNT(DISTINCT tip.test_id)
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
        JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
        WHERE sip.policy_id = ?
          AND sip.tenant_id = ?
          AND sig.system_id = ?
    "#)
    .bind(policy_id).bind(tenant_id).bind(system_id)
    .fetch_one(pool).await?;

    if applicable == 0 {
        return Ok(0); // policy genuinely doesn't cover this system
    }

    // Queue them. Idempotent — already-pending commands are left as they are.
    sqlx::query(r#"
        INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id)
        SELECT ?, sig.system_id, tip.test_id
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
        JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
        WHERE sip.policy_id = ?
          AND sip.tenant_id = ?
          AND sig.system_id = ?
    "#)
    .bind(tenant_id).bind(policy_id).bind(tenant_id).bind(system_id)
    .execute(pool).await?;

    Ok(applicable as u64)
}


#[cfg(test)]
mod tests {
    use super::compliance_pct;

    // (pass, fail) units — a "unit" is a system (policy scoring) or a policy
    // (system scoring); the math is identical either way.
    #[test]
    fn empty_scope_is_not_scanned() {
        assert_eq!(compliance_pct(false, &[]), -1.0);
        assert_eq!(compliance_pct(true,  &[]), -1.0);
        // All-NA units (no pass/fail) → -1.0 in both modes.
        let na = vec![(0usize, 0usize), (0, 0)];
        assert_eq!(compliance_pct(false, &na), -1.0);
        assert_eq!(compliance_pct(true,  &na), -1.0);
    }

    #[test]
    fn the_divergence_case() {
        // 4 units, each with exactly 1 of 10 checks failing.
        let u = vec![(9usize, 1usize), (9, 1), (9, 1), (9, 1)];
        // Per-test: 36 pass / 40 total = 90%.
        assert!((compliance_pct(false, &u) - 90.0).abs() < 1e-9);
        // Binary (per-system / per-policy): 0 of 4 fully compliant = 0%.
        assert_eq!(compliance_pct(true, &u), 0.0);
    }

    #[test]
    fn all_pass_is_100_both_modes() {
        let u = vec![(5usize, 0usize), (3, 0)];
        assert!((compliance_pct(false, &u) - 100.0).abs() < 1e-9);
        assert!((compliance_pct(true,  &u) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn mixed_units() {
        // One fully-compliant (5,0), one with failures (3,2).
        let u = vec![(5usize, 0usize), (3, 2)];
        // Per-test: 8 pass / 10 total = 80%.
        assert!((compliance_pct(false, &u) - 80.0).abs() < 1e-9);
        // Binary: 1 of 2 fully compliant = 50%.
        assert!((compliance_pct(true, &u) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn single_failing_unit_is_zero_binary() {
        // The user's case: one policy with a failing test → 0% per-policy.
        let u = vec![(1usize, 4usize)];
        assert!((compliance_pct(false, &u) - 20.0).abs() < 1e-9); // per test: 1/5
        assert_eq!(compliance_pct(true, &u), 0.0);                // binary: 0 of 1
    }

    // Pure-container-policy headline fallback: mean of scored containers only.
    fn mk_container(score: f64) -> crate::models::ContainerReportGroup {
        crate::models::ContainerReportGroup {
            container_id: 1, name: "c".into(), runtime: "docker".into(), image: None,
            compliance_score: score, pass_count: 0, fail_count: 0, na_count: 0, results: vec![],
        }
    }
    fn mk_system(containers: Vec<crate::models::ContainerReportGroup>) -> crate::models::SystemReport {
        crate::models::SystemReport {
            system_name: "h".into(), results: vec![], is_passed: false,
            pass_count: 0, fail_count: 0, na_count: 0, excluded_count: 0, containers,
        }
    }

    #[test]
    fn container_axis_avg_no_containers_is_none() {
        assert_eq!(super::container_axis_avg(&[mk_system(vec![])]), None);
    }

    #[test]
    fn container_axis_avg_ignores_unscanned_and_means_the_rest() {
        // 80 and 100 are scored; -1.0 (Not Scanned) is excluded → mean 90.
        let systems = vec![
            mk_system(vec![mk_container(80.0), mk_container(-1.0)]),
            mk_system(vec![mk_container(100.0)]),
        ];
        assert_eq!(super::container_axis_avg(&systems), Some(90.0));
    }
}
