// =============================================================================
// reports.rs — saved report CRUD, PDF download, and bulk actions
//
// Handles both policy reports (snapshots of policy compliance results) and
// system reports (snapshots of per-system compliance data). All routes are
// tenant-scoped. Viewer for reads; Runner to save; Editor for deletes.
// =============================================================================

use axum::response::{Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use bytes::Bytes;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::collections::BTreeMap;
use tracing::{info, error};
use serde_json;
use urlencoding;
use genpdf::{fonts, elements, style, Element, Margins};

use crate::pdf::{status_badge, Align, Cell, Doc, Style, Table, LOGO_WIDTH_MM};
use crate::auth::{self};
use crate::handlers::{render_template, normalize_status, parse_form_data, is_system_passed};
use crate::models::{
    UserRole, TestMeta, SystemReport, IndividualResult,
    Report, SavedSystemReport, ErrorQuery, AuthSession, SystemReportData,
};
use crate::systems::fetch_system_report_data;


// ============================================================
// HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// GET /reports
// List all saved policy reports and system reports for the current tenant.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Fetch policy reports
    let policy_reports: Vec<Report> = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, NULL as policy_description,
                submitter_name, NULL as tests_metadata, NULL as report_results
         FROM reports
         WHERE tenant_id = ?
         ORDER BY submission_date DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch policy reports: {}", e);
            vec![]
        }
    };

    // Fetch system reports
    let system_reports: Vec<SavedSystemReport> = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, NULL as report_data
         FROM system_reports
         WHERE tenant_id = ?
         ORDER BY submission_date DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch system reports: {}", e);
            vec![]
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    context.insert("reports", &policy_reports);
    context.insert("system_reports", &system_reports);
    render_template(&tera, Some(&pool), "reports.html", context, Some(auth))
        .await
        .into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// Helper: save_policy_report_logic
// Snapshots current policy compliance results to the reports table.
// Called by the HTTP handler and the background scheduler.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn save_policy_report_logic(
    id: i64,
    pool: &SqlitePool,
    tenant_id: &str,
    submitter_name: &str,
) -> Result<(), sqlx::Error> {

    // Fetch policy header
    let policy_row = match sqlx::query(
        "SELECT name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    {
        Some(row) => row,
        None => {
            error!("Policy {} not found for report save.", id);
            return Ok(());
        }
    };

    // Fetch tests metadata
    let test_rows = sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tp ON t.id = tp.test_id
        WHERE tp.policy_id = ? AND tp.tenant_id = ?
    "#)
    .bind(id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get("description"),
        rational: row.get("rational"),
        remediation: row.get("remediation"),
    }).collect();

    // Fetch system results — tenant_id is enforced on every join (M2 tenant isolation fix).
    // Pull the excluded flag too so the saved snapshot freezes it for the audit trail.
    let raw_results = sqlx::query(r#"
        SELECT
            s.name AS system_name,
            t.name AS test_name,
            res.result AS status_text,
            res.excluded AS is_excluded
        FROM tests_in_policy tip
        JOIN tests t ON tip.test_id = t.id
        JOIN results res ON t.id = res.test_id AND res.tenant_id = tip.tenant_id
        JOIN systems s ON res.system_id = s.id AND s.tenant_id = tip.tenant_id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
          AND res.container_id = 0
    "#)
    .bind(id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    // Group results by system
    let mut reports_map: BTreeMap<String, SystemReport> = BTreeMap::new();
    for row in raw_results {
        let s_name: String = row.get("system_name");
        let t_name: String = row.get("test_name");
        let status_raw: String = row.get("status_text");
        let status = normalize_status(&status_raw).to_string();
        let is_excluded: bool = row.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0;

        let entry = reports_map.entry(s_name.clone()).or_insert(SystemReport {
            system_name: s_name,
            results: Vec::new(),
            is_passed: false,
            pass_count: 0,
            fail_count: 0,
            na_count: 0,
            excluded_count: 0,
            containers: Vec::new(),
        });

        entry.results.push(IndividualResult {
            test_name: t_name,
            status: status.clone(),
            is_excluded,
            ..Default::default()
        });
    }

    // Recalculate is_passed, pass_count, and fail_count after all results are collected.
    // A system passes when it has no FAILs AND at least one PASS.
    // All-NA systems (pass_count == 0 && fail_count == 0) are shown as "NOT APPLICABLE"
    // by the template — is_passed value does not affect their display.
    for entry in reports_map.values_mut() {
        entry.pass_count     = entry.results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
        entry.fail_count     = entry.results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
        entry.na_count       = entry.results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();
        entry.excluded_count = entry.results.iter().filter(|r| r.is_excluded).count();
        entry.is_passed = is_system_passed(entry.pass_count, entry.fail_count);
    }

    // Freeze per-container results into the snapshot too (nested under each host).
    let mut container_map = crate::policies::fetch_policy_container_groups(pool, tenant_id, id)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to fetch container results for policy snapshot {}: {}", id, e);
            Default::default()
        });
    for (name, entry) in reports_map.iter_mut() {
        entry.containers = container_map.remove(name).unwrap_or_default();
    }

    let system_reports: Vec<SystemReport> = reports_map.into_values().collect();

    // Serialize
    let tests_json = serde_json::to_string(&tests_metadata)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize tests: {}", e)))?;
    let results_json = serde_json::to_string(&system_reports)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize results: {}", e)))?;

    // Save report
    sqlx::query(r#"
        INSERT INTO reports
            (tenant_id, policy_name, policy_version, policy_description,
             submitter_name, tests_metadata, report_results)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    "#)
    .bind(tenant_id)
    .bind(policy_row.get::<String, _>("name"))
    .bind(policy_row.get::<String, _>("version"))
    .bind(policy_row.get::<Option<String>, _>("description"))
    .bind(submitter_name)
    .bind(tests_json)
    .bind(results_json)
    .execute(pool)
    .await?;

    info!("Report saved for policy {} by '{}'.", id, submitter_name);
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/save/{id}
// Save a snapshot of the current policy compliance results.
// Role: Runner
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_save(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    match save_policy_report_logic(id, &pool, &auth.tenant_id, &auth.username).await {
        Ok(_) => {
            info!("Report saved for policy {} by '{}'.", id, auth.username);
            Redirect::to(&format!("/policies/report/{}?success_message=Report+saved", id)).into_response()
        }
        Err(e) => {
            error!("Failed to save report for policy {}: {}", id, e);
            Redirect::to(&format!("/policies/report/{}?error_message=Failed+to+save+report", id)).into_response()
        }
    }
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/view/{id}
// View a saved policy compliance report snapshot.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Fetch the saved report
    let report = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, policy_description,
                submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/reports?error_message=Report+not+found").into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch report for viewing");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Deserialize JSON fields
    let tests_metadata: Vec<TestMeta> = match serde_json::from_str(
        report.tests_metadata.as_deref().unwrap_or("[]"),
    ) {
        Ok(m) => m,
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to deserialize tests metadata");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut system_reports: Vec<SystemReport> = match serde_json::from_str(
        report.report_results.as_deref().unwrap_or("[]"),
    ) {
        Ok(r) => r,
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to deserialize system reports");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Always recompute counts from the saved results array. Older snapshots
    // may have pass/fail set but lack na/excluded; conditionally backfilling
    // (the previous approach) left na_count at zero for those. Recomputing is
    // cheap and idempotent — results are the source of truth in the snapshot.
    for s in &mut system_reports {
        if !s.results.is_empty() {
            s.pass_count     = s.results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
            s.fail_count     = s.results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
            s.na_count       = s.results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();
            s.excluded_count = s.results.iter().filter(|r| r.is_excluded).count();
            s.is_passed      = is_system_passed(s.pass_count, s.fail_count);
        }
    }

    // Check if the originating policy still exists (by name + version)
    let live_policy_id: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM policies WHERE name = ? AND version = ? AND tenant_id = ?",
    )
    .bind(&report.policy_name)
    .bind(report.policy_version.as_deref().unwrap_or(""))
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None);

    let fail_count = system_reports.iter().filter(|s| s.fail_count > 0).count();

    // Top-card totals (mirror the live report layout). Snapshots saved before
    // these counters existed get computed on the fly from individual results.
    let total_pass:     usize = system_reports.iter().map(|s| s.pass_count).sum();
    let total_fail:     usize = system_reports.iter().map(|s| s.fail_count).sum();
    let total_na:       usize = system_reports.iter().map(|s| s.na_count).sum();
    let total_excluded: usize = system_reports.iter().map(|s| s.excluded_count).sum();
    // Mode-aware (0.6.5): honour the per-tenant POLICY compliance toggle.
    // Archived reports recompute the % on view from their frozen per-system
    // results, so flipping the setting changes this number too.
    let pmode = crate::policies::read_compliance_mode(&pool, &auth.tenant_id, "policy_compliance_mode").await;
    let units: Vec<(usize, usize)> = system_reports.iter().map(|s| (s.pass_count, s.fail_count)).collect();
    let compliance_score = crate::policies::compliance_pct(pmode == "system", &units);

    // Compliance thresholds — same source as live policy report / system report.
    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_sat'",
    )
    .bind(&auth.tenant_id).fetch_one(&pool).await.unwrap_or(80);
    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_marginal'",
    )
    .bind(&auth.tenant_id).fetch_one(&pool).await.unwrap_or(60);

    let mut context = Context::new();
    context.insert("report", &report);
    context.insert("tests_metadata", &tests_metadata);
    context.insert("system_reports", &system_reports);
    context.insert("fail_count", &fail_count);
    context.insert("total_pass", &total_pass);
    context.insert("total_fail", &total_fail);
    context.insert("total_na", &total_na);
    context.insert("total_excluded", &total_excluded);
    context.insert("compliance_score", &compliance_score);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    context.insert("live_policy_id", &live_policy_id);
    context.insert("is_smtp_configured", &is_smtp_configured(&pool).await);
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    if let Some(msg) = query.error_message   { context.insert("error_message",   &msg); }
    render_template(&tera, Some(&pool), "reports_view.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/diff?a={older_id}&b={newer_id}
// Side-by-side diff of two saved policy report snapshots.
// Both snapshots must belong to the same policy (same name + version);
// otherwise the comparison is meaningless and we bounce with an error.
// IDs can be passed in either order — handler swaps to put the older one
// on the left automatically by submission_date.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
#[derive(serde::Deserialize)]
pub struct DiffQuery {
    pub a: i32,
    pub b: i32,
}

/// Per-test diff row used by the template.
#[derive(serde::Serialize)]
struct ResultDiff {
    test_name:  String,
    old_status: Option<String>,   // None means the test wasn't present in the older snapshot
    new_status: Option<String>,   // None means the test isn't present in the newer one
    old_excluded: bool,
    new_excluded: bool,
    /// One of: unchanged | improved | regressed | added | removed | changed
    /// (`changed` covers NA→PASS, NA→FAIL, PASS→NA, etc. that aren't pure
    /// improvements or regressions.)
    change: &'static str,
}

/// Per-system diff row used by the template.
#[derive(serde::Serialize)]
struct SystemDiff {
    system_name: String,
    /// One of: new | removed | present (in both)
    presence: &'static str,
    results: Vec<ResultDiff>,
    /// Aggregate counters for the system card header.
    improved:  usize,
    regressed: usize,
    added:     usize,
    removed:   usize,
    changed:   usize,
    unchanged: usize,
}

fn classify(old: Option<&str>, new: Option<&str>) -> &'static str {
    match (old, new) {
        (None,    Some(_))            => "added",
        (Some(_), None)               => "removed",
        (Some(a), Some(b)) if a == b  => "unchanged",
        (Some("FAIL"), Some("PASS"))  => "improved",
        (Some("PASS"), Some("FAIL"))  => "regressed",
        _                             => "changed",
    }
}

pub async fn reports_diff(
    auth: AuthSession,
    Query(q): Query<DiffQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    if q.a == q.b {
        return Redirect::to("/reports?error_message=Pick+two+different+snapshots+to+compare").into_response();
    }

    // Fetch both reports in one query so a missing/wrong-tenant id can't slip through.
    let rows = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, policy_description,
                submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id IN (?, ?) AND tenant_id = ?",
    )
    .bind(q.a)
    .bind(q.b)
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = ?e, "diff: failed to fetch reports");
            return Redirect::to("/reports?error_message=Database+error").into_response();
        }
    };

    if rows.len() != 2 {
        return Redirect::to("/reports?error_message=One+or+both+snapshots+not+found").into_response();
    }

    // Same-policy check: identical (name, version).
    let (n0, v0) = (&rows[0].policy_name, rows[0].policy_version.as_deref().unwrap_or(""));
    let (n1, v1) = (&rows[1].policy_name, rows[1].policy_version.as_deref().unwrap_or(""));
    if n0 != n1 || v0 != v1 {
        return Redirect::to(
            "/reports?error_message=Both+snapshots+must+be+the+same+policy+name+and+version"
        ).into_response();
    }

    // Order by submission_date so "old" is on the left even if the caller
    // passed them in reverse. Falls back to id ordering if either date is empty.
    let mut sorted = rows;
    sorted.sort_by(|a, b| a.submission_date.cmp(&b.submission_date));
    let old_report = &sorted[0];
    let new_report = &sorted[1];

    // Deserialise both report_results blobs.
    let old_systems: Vec<SystemReport> = serde_json::from_str(
        old_report.report_results.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();
    let new_systems: Vec<SystemReport> = serde_json::from_str(
        new_report.report_results.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();
    let tests_metadata: Vec<TestMeta> = serde_json::from_str(
        new_report.tests_metadata.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();

    // Build a (system_name → results map) index so we can join the two sides.
    use std::collections::BTreeMap;
    let old_map: BTreeMap<&str, &Vec<crate::models::IndividualResult>> =
        old_systems.iter().map(|s| (s.system_name.as_str(), &s.results)).collect();
    let new_map: BTreeMap<&str, &Vec<crate::models::IndividualResult>> =
        new_systems.iter().map(|s| (s.system_name.as_str(), &s.results)).collect();

    // Union the system names (stable order: alphabetical).
    let mut names: Vec<&str> = old_map.keys().chain(new_map.keys()).copied().collect();
    names.sort();
    names.dedup();

    let mut diffs: Vec<SystemDiff> = Vec::with_capacity(names.len());
    let mut tot_improved  = 0usize;
    let mut tot_regressed = 0usize;
    let mut tot_added     = 0usize;
    let mut tot_removed   = 0usize;
    let mut tot_changed   = 0usize;

    for name in names {
        let old_results = old_map.get(name);
        let new_results = new_map.get(name);
        let presence = match (old_results.is_some(), new_results.is_some()) {
            (false, true) => "new",
            (true, false) => "removed",
            _             => "present",
        };

        // Build a (test_name → IndividualResult) map per side.
        let old_t: BTreeMap<&str, &crate::models::IndividualResult> = old_results
            .map(|v| v.iter().map(|r| (r.test_name.as_str(), r)).collect())
            .unwrap_or_default();
        let new_t: BTreeMap<&str, &crate::models::IndividualResult> = new_results
            .map(|v| v.iter().map(|r| (r.test_name.as_str(), r)).collect())
            .unwrap_or_default();

        let mut test_names: Vec<&str> = old_t.keys().chain(new_t.keys()).copied().collect();
        test_names.sort();
        test_names.dedup();

        let mut results: Vec<ResultDiff> = Vec::with_capacity(test_names.len());
        let (mut improved, mut regressed, mut added, mut removed, mut changed, mut unchanged) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);

        for tn in test_names {
            let o = old_t.get(tn);
            let n = new_t.get(tn);
            let kind = classify(o.map(|r| r.status.as_str()), n.map(|r| r.status.as_str()));
            match kind {
                "improved"  => improved  += 1,
                "regressed" => regressed += 1,
                "added"     => added     += 1,
                "removed"   => removed   += 1,
                "changed"   => changed   += 1,
                _           => unchanged += 1,
            }
            results.push(ResultDiff {
                test_name:    tn.to_string(),
                old_status:   o.map(|r| r.status.clone()),
                new_status:   n.map(|r| r.status.clone()),
                old_excluded: o.map(|r| r.is_excluded).unwrap_or(false),
                new_excluded: n.map(|r| r.is_excluded).unwrap_or(false),
                change:       kind,
            });
        }

        tot_improved  += improved;
        tot_regressed += regressed;
        tot_added     += added;
        tot_removed   += removed;
        tot_changed   += changed;

        diffs.push(SystemDiff {
            system_name: name.to_string(),
            presence,
            results,
            improved, regressed, added, removed, changed, unchanged,
        });
    }

    let mut ctx = Context::new();
    ctx.insert("old_report",       old_report);
    ctx.insert("new_report",       new_report);
    ctx.insert("tests_metadata",   &tests_metadata);
    ctx.insert("diffs",            &diffs);
    ctx.insert("tot_improved",     &tot_improved);
    ctx.insert("tot_regressed",    &tot_regressed);
    ctx.insert("tot_added",        &tot_added);
    ctx.insert("tot_removed",      &tot_removed);
    ctx.insert("tot_changed",      &tot_changed);

    render_template(&tera, Some(&pool), "reports_diff.html", ctx, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/delete/{id}
// Delete a saved policy compliance report.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    if let Err(e) = sqlx::query("DELETE FROM reports WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        error!("Failed to delete report {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting report: {}", e)).to_string();
        return Redirect::to(&format!("/reports?error_message={}", encoded)).into_response();
    }

    info!("Report ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/reports").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: cell
// Wraps a PDF element with uniform cell padding for table layout.
// ─────────────────────────────────────────────────────────────────────────────
fn cell<E: Element + 'static>(e: E) -> Box<dyn Element> {
    Box::new(elements::PaddedElement::new(e, Margins::trbl(1.5, 2.0, 1.5, 2.0)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared by the four "Email Me PDF" handlers (reports_email,
// system_reports_email, policies_report_email, system_report_live_email).
// Kept tiny and stringly-typed because the flash flow is the same across all
// four endpoints — flag SMTP missing, missing user email, render failure,
// SMTP failure, success — and we want the same wording everywhere.
// ─────────────────────────────────────────────────────────────────────────────

// is_smtp_configured — used by the four report-view handlers to decide
// whether to render the "Email Me PDF" button on the page.
pub async fn is_smtp_configured(pool: &SqlitePool) -> bool {
    let host: String = sqlx::query_scalar(
        "SELECT value FROM settings WHERE tenant_id = 'default' AND skey = 'smtp_host'",
    )
    .fetch_optional(pool).await.unwrap_or(None).unwrap_or_default();
    !host.trim().is_empty()
}

// user_email — fetch the logged-in user's email from the users table,
// returning None for empty/missing values so callers can flash a clear
// error rather than try to send to "".
pub(crate) async fn user_email(pool: &SqlitePool, user_id: i32, tenant_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT email FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(user_id).bind(tenant_id)
    .fetch_optional(pool).await
    .unwrap_or(None).flatten()
    .filter(|e| !e.trim().is_empty())
}

// flash_back — redirect to `back` with a flash message. Single helper so
// every email handler reads the same way. `ok = true` becomes success_message,
// `ok = false` becomes error_message.
pub(crate) fn flash_back(back: &str, ok: bool, msg: &str) -> Response {
    let key = if ok { "success_message" } else { "error_message" };
    let encoded = urlencoding::encode(msg).to_string();
    let sep = if back.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{}{}{}={}", back, sep, key, encoded)).into_response()
}

// report_email_body — short HTML wrapper for the report email itself.
// Kept generic so the same body works for policy-archive, policy-live,
// system-archive, and system-live reports.
pub(crate) fn report_email_body(name: &str, version: &str, when: &str) -> String {
    let version_line = if version.is_empty() {
        String::new()
    } else {
        format!("<p><strong>Version:</strong> {}</p>", version)
    };
    format!(
        r#"<p>The OpenSCM compliance report you requested is attached as a PDF.</p>
<p><strong>Report:</strong> {name}</p>
{version_line}
<p><strong>Generated:</strong> {when}</p>
<p>This report contains confidential information about your infrastructure
and should be treated as such.</p>"#
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: fetch_archive_policy_report
// Pulls a saved policy report + its system_reports + tests_metadata in the
// shape the PDF builder wants. Returns None if the row doesn't exist for
// the caller's tenant. Shared by reports_download and reports_email so the
// fetch path stays in one place.
// ─────────────────────────────────────────────────────────────────────────────
async fn fetch_archive_policy_report(
    pool: &SqlitePool,
    tenant_id: &str,
    id: i64,
) -> Result<Option<(Report, Vec<SystemReport>, Vec<TestMeta>)>, sqlx::Error> {
    let row = sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, policy_description,
                submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(tenant_id)
    .fetch_optional(pool).await?;

    let Some(report) = row else { return Ok(None); };

    let mut system_reports: Vec<SystemReport> = serde_json::from_str(
        report.report_results.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();

    // Always recompute counts from the saved results array. Older snapshots
    // may have pass/fail set but lack na/excluded; conditionally backfilling
    // (the previous approach) left na_count at zero for those. Recomputing is
    // cheap and idempotent — results are the source of truth in the snapshot.
    for s in &mut system_reports {
        if !s.results.is_empty() {
            s.pass_count     = s.results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
            s.fail_count     = s.results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
            s.na_count       = s.results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();
            s.excluded_count = s.results.iter().filter(|r| r.is_excluded).count();
            s.is_passed      = is_system_passed(s.pass_count, s.fail_count);
        }
    }

    let tests_metadata: Vec<TestMeta> = serde_json::from_str(
        report.tests_metadata.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();

    Ok(Some((report, system_reports, tests_metadata)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build_archive_policy_pdf
// Renders a saved-policy compliance report into a PDF byte buffer. The
// download and email handlers both call into this so there is one canonical
// place where the PDF layout lives.
// Public so `tests/pdf_render.rs` can render golden fixtures for visual
// before/after comparison across renderer changes.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_archive_policy_pdf(
    report: &Report,
    system_reports: &[SystemReport],
    tests_metadata: &[TestMeta],
) -> Result<Vec<u8>, ()> {
    const FONT_REGULAR:     &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD:        &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC:      &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES:       &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    let font_family = match (
        fonts::FontData::new(FONT_REGULAR.to_vec(), None),
        fonts::FontData::new(FONT_BOLD.to_vec(), None),
        fonts::FontData::new(FONT_ITALIC.to_vec(), None),
        fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None),
    ) {
        (Ok(regular), Ok(bold), Ok(italic), Ok(bold_italic)) =>
            fonts::FontFamily { regular, bold, italic, bold_italic },
        _ => { error!("Failed to load PDF fonts for archive policy report"); return Err(()); }
    };

    let mut doc = genpdf::Document::new(font_family);

    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = match elements::Image::from_reader(cursor) {
        Ok(img) => img,
        Err(e) => { error!("Failed to load PDF logo: {}", e); return Err(()); }
    };

    doc.set_title(format!("OpenSCM Compliance Report - {}", report.policy_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Title
    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(
        style::Style::new().with_font_size(30).bold()
            .with_color(style::Color::Rgb(0, 0, 128)),
    ));
    doc.push(elements::Break::new(2.0));

    let mut submitter = elements::Paragraph::new(format!(
        "Generated on {} by {}",
        report.submission_date,
        report.submitter_name.as_deref().unwrap_or("Unknown"),
    ));
    submitter.set_alignment(genpdf::Alignment::Center);
    doc.push(submitter);
    doc.push(elements::Break::new(0.5));

    logo.set_dpi(40.0);
    logo.set_alignment(genpdf::Alignment::Center);
    doc.push(logo);
    doc.push(elements::Break::new(1.0));

    // Report details table
    doc.push(elements::Text::new("Report Details")
        .styled(style::Style::new().bold().with_font_size(14)));
    doc.push(elements::Break::new(0.5));
    let mut details_table = elements::TableLayout::new(vec![1, 3]);
    details_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

    if let Err(e) = details_table.push_row(vec![
        cell(elements::Text::new("Policy Name").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(format!(
            "{} v{}",
            report.policy_name,
            report.policy_version.as_deref().unwrap_or(""),
        ))),
    ]) { error!("Failed to add policy name row to PDF: {}", e); }

    if let Err(e) = details_table.push_row(vec![
        cell(elements::Text::new("Description").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(
            report.policy_description.as_deref().unwrap_or("").to_string(),
        )),
    ]) { error!("Failed to add description row to PDF: {}", e); }

    doc.push(details_table);

    // Tests Summary — name + description of every test in the policy.
    // Renders on its own page after the Report Details so the cover and
    // the test catalog don't compete for space on page 1.
    if !tests_metadata.is_empty() {
        doc.push(elements::PageBreak::new());
        doc.push(
            elements::Text::new(format!("Tests in this Policy ({})", tests_metadata.len()))
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        let mut tests_table = elements::TableLayout::new(vec![2, 5]);
        tests_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = tests_table.push_row(vec![
            cell(elements::Text::new("Test Name").styled(style::Style::new().bold())),
            cell(elements::Text::new("Description").styled(style::Style::new().bold())),
        ]) { error!("Failed to add tests summary header to PDF: {}", e); }

        for tm in tests_metadata {
            let desc = if tm.description.trim().is_empty() { "—".to_string() } else { tm.description.clone() };
            if let Err(e) = tests_table.push_row(vec![
                cell(elements::Paragraph::new(&tm.name)),
                cell(elements::Paragraph::new(&desc)),
            ]) { error!("Failed to add tests summary row to PDF: {}", e); }
        }
        doc.push(tests_table);
    }

    doc.push(elements::PageBreak::new());

    // Per-system audit section
    for system in system_reports {
        doc.push(
            elements::Text::new(format!("Host Name: {}", system.system_name))
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        // Excluded findings are not counted as PASS or FAIL — match the three-way
        // verdict (Compliant / Non-Compliant / Not Applicable) used on screen.
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
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Compliance Status").styled(style::Style::new().bold())),
            cell(elements::Text::new(status_text)
                .styled(style::Style::new().with_color(status_color).bold())),
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

        // Rules breakdown
        doc.push(elements::Text::new("Audit Rules Detailed Breakdown")
            .styled(style::Style::new().bold().with_font_size(14)));
        doc.push(elements::Break::new(0.5));
        let mut rules_table = elements::TableLayout::new(vec![4, 1]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = rules_table.push_row(vec![
            cell(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            cell(elements::Text::new("Status").styled(style::Style::new().bold())),
        ]) { error!("Failed to add rules table header to PDF: {}", e); }

        for res in &system.results {
            let (status_text, status_color) = if res.is_excluded {
                ("EXCLUDED", style::Color::Rgb(100, 100, 100))
            } else {
                match res.status.as_str() {
                    "PASS" => ("PASS", style::Color::Rgb(0, 128, 0)),
                    "FAIL" => ("FAIL", style::Color::Rgb(200, 0, 0)),
                    "NA"   => ("NA",   style::Color::Rgb(100, 100, 100)),
                    _      => ("—",    style::Color::Rgb(150, 150, 150)),
                }
            };
            if let Err(e) = rules_table.push_row(vec![
                cell(elements::Paragraph::new(&res.test_name)),
                cell(elements::Text::new(status_text)
                    .styled(style::Style::new().with_color(status_color).bold())),
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
    doc.render(&mut buffer).map_err(|e| { error!("Failed to render archive policy PDF: {}", e); })?;
    Ok(buffer)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/download/{id}
// Generate and stream a PDF of a saved policy compliance report.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let (report, system_reports, tests_metadata) =
        match fetch_archive_policy_report(&pool, &auth.tenant_id, id).await {
            Ok(Some(tup)) => tup,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                error!(error = ?e, report_id = %id, "Failed to fetch report for download");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let buffer = match build_archive_policy_pdf(&report, &system_reports, &tests_metadata) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|e| {
            error!("Failed to build PDF response for report {}: {}", id, e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/email/{id}
// Email the archive-policy report PDF to the logged-in user's address.
// Role: Viewer (same as download — no information escapes outside the
// configured mail relay; less privileged than the download itself).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_email(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/reports/view/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let (report, system_reports, tests_metadata) =
        match fetch_archive_policy_report(&pool, &auth.tenant_id, id).await {
            Ok(Some(tup)) => tup,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                error!(error = ?e, report_id = %id, "Failed to fetch report for email");
                return flash_back(&back, false, "Failed to load report.");
            }
        };

    let bytes = match build_archive_policy_pdf(&report, &system_reports, &tests_metadata) {
        Ok(b) => b,
        Err(_) => return flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM Compliance Report — {}", report.policy_name);
    let html_body = report_email_body(
        &report.policy_name,
        report.policy_version.as_deref().unwrap_or(""),
        &report.submission_date,
    );
    let filename = format!("OpenSCM_Report_{}.pdf", id);

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}


// ============================================================
// BULK ACTIONS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/bulk/delete
// Bulk delete selected saved policy compliance reports.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_bulk_delete(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/reports?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i64> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/reports?error_message=No+reports+selected").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query("DELETE FROM reports WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await
        {
            error!("Bulk delete: failed for report {}: {}", id, e);
        } else {
            deleted += 1;
        }
    }

    info!("Bulk deleted {} reports by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} report(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/reports?success_message={}", msg)).into_response()
}


// ============================================================
// SYSTEM REPORT HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/report/{id}/save
// Save a snapshot of the live system compliance report to system_reports.
// Role: Runner
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_save(
    auth: AuthSession,
    Path(system_id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    let data = match fetch_system_report_data(system_id, &auth.tenant_id, &pool).await {
        Ok(d) => d,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %system_id, "Failed to fetch system data for snapshot");
            return Redirect::to("/reports?error_message=Failed+to+save+report").into_response();
        }
    };

    let report_json = match serde_json::to_string(&data) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize system report data: {}", e);
            return Redirect::to("/reports?error_message=Failed+to+save+report").into_response();
        }
    };

    match sqlx::query(
        "INSERT INTO system_reports (tenant_id, system_id, system_name, submitter_name, report_data)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(&data.system_name)
    .bind(&auth.username)
    .bind(&report_json)
    .execute(&pool)
    .await
    {
        Ok(_) => {
            info!("System report snapshot saved for system '{}' by '{}'.", data.system_name, auth.username);
            let msg = urlencoding::encode(&format!("Report saved for {}.", data.system_name)).to_string();
            Redirect::to(&format!("/systems/report/{}?success_message={}", system_id, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to insert system report snapshot: {}", e);
            Redirect::to(&format!("/systems/report/{}?error_message=Failed+to+save+report", system_id)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/view/{id}
// View a saved system compliance report snapshot.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let row = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch system report");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut report_data: SystemReportData = match serde_json::from_str(
        row.report_data.as_deref().unwrap_or("{}"),
    ) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to deserialize system report data: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Re-derive the headline score from the snapshot's frozen policy groups
    // under the CURRENT system compliance mode, so flipping the toggle reflects
    // in saved system reports too (matches saved policy reports).
    {
        let smode = crate::policies::read_compliance_mode(&pool, &auth.tenant_id, "system_compliance_mode").await;
        let units: Vec<(usize, usize)> = report_data.policy_groups.iter()
            .map(|p| (p.pass_count, p.fail_count)).collect();
        report_data.compliance_score = crate::policies::compliance_pct(smode == "policy", &units);
    }

    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_sat'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(80);

    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_marginal'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(60);

    let system_exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM systems WHERE id = ? AND tenant_id = ?)"
    )
    .bind(row.system_id)
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(0);

    // Live-DB test metadata so the template can pop a detail modal when a
    // test row is clicked. Snapshots can be older than the current tests
    // table — rows whose name no longer matches any live test fall through
    // to plain text (no link), same as the policy archive view does.
    let tests_metadata = crate::systems::fetch_tenant_tests_metadata(&auth.tenant_id, &pool).await;

    let mut context = Context::new();
    context.insert("meta", &row);
    context.insert("report", &report_data);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    context.insert("system_exists", &system_exists);
    context.insert("is_smtp_configured", &is_smtp_configured(&pool).await);
    context.insert("tests_metadata", &tests_metadata);
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    if let Some(msg) = query.error_message   { context.insert("error_message",   &msg); }
    render_template(&tera, Some(&pool), "system_report_view.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/diff?a={older_id}&b={newer_id}
// Side-by-side diff of two saved system-report snapshots.
// Both snapshots must belong to the same system_id; the handler auto-orders
// by submission_date so "older" is always on the left regardless of input
// order. Mirrors the policy-report diff (reports_diff) but groups by policy
// because system reports are a per-system view across all assigned policies.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
#[derive(serde::Serialize)]
struct PolicyDiff {
    policy_name:    String,
    policy_version: String,
    /// One of: new | removed | present (in both snapshots' policy_groups)
    presence: &'static str,
    results: Vec<ResultDiff>,
    improved:  usize,
    regressed: usize,
    added:     usize,
    removed:   usize,
    changed:   usize,
    unchanged: usize,
}

pub async fn system_reports_diff(
    auth: AuthSession,
    Query(q): Query<DiffQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    if q.a == q.b {
        return Redirect::to("/reports?error_message=Pick+two+different+snapshots+to+compare").into_response();
    }

    let rows = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
         WHERE id IN (?, ?) AND tenant_id = ?",
    )
    .bind(q.a)
    .bind(q.b)
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = ?e, "system diff: failed to fetch reports");
            return Redirect::to("/reports?error_message=Database+error").into_response();
        }
    };

    if rows.len() != 2 {
        return Redirect::to("/reports?error_message=One+or+both+snapshots+not+found").into_response();
    }

    // Same-system check via system_id (FK to systems). Falls back to comparing
    // system_name in case the original system has been deleted and re-created
    // (different id, same hostname) — caller intent is still "compare these
    // two reports for what the host now reads as the same name."
    let same_system = rows[0].system_id == rows[1].system_id
        || rows[0].system_name == rows[1].system_name;
    if !same_system {
        return Redirect::to(
            "/reports?error_message=Both+snapshots+must+belong+to+the+same+system"
        ).into_response();
    }

    // Older on the left.
    let mut sorted = rows;
    sorted.sort_by(|a, b| a.submission_date.cmp(&b.submission_date));
    let old_meta = &sorted[0];
    let new_meta = &sorted[1];

    let old_data: SystemReportData = serde_json::from_str(
        old_meta.report_data.as_deref().unwrap_or("{}"),
    ).unwrap_or_else(|_| SystemReportData {
        system_id: 0, system_name: String::new(), os: String::new(),
        arch: None, ip: None, compliance_score: -1.0, last_seen: None,
        policy_groups: vec![], total_pass: 0, total_fail: 0, total_na: 0,
        containers: vec![],
    });
    let new_data: SystemReportData = serde_json::from_str(
        new_meta.report_data.as_deref().unwrap_or("{}"),
    ).unwrap_or_else(|_| SystemReportData {
        system_id: 0, system_name: String::new(), os: String::new(),
        arch: None, ip: None, compliance_score: -1.0, last_seen: None,
        policy_groups: vec![], total_pass: 0, total_fail: 0, total_na: 0,
        containers: vec![],
    });

    // Build per-policy index keyed by (policy_name, policy_version) so a
    // version bump between snapshots shows up as "removed v1 / added v2"
    // rather than silently masking a real change.
    use std::collections::BTreeMap;
    let old_pol: BTreeMap<(String, String), &crate::models::PolicyResultGroup> = old_data
        .policy_groups.iter()
        .map(|p| ((p.policy_name.clone(), p.policy_version.clone()), p))
        .collect();
    let new_pol: BTreeMap<(String, String), &crate::models::PolicyResultGroup> = new_data
        .policy_groups.iter()
        .map(|p| ((p.policy_name.clone(), p.policy_version.clone()), p))
        .collect();

    let mut keys: Vec<(String, String)> =
        old_pol.keys().chain(new_pol.keys()).cloned().collect();
    keys.sort();
    keys.dedup();

    let mut diffs: Vec<PolicyDiff> = Vec::with_capacity(keys.len());
    let mut tot_improved = 0usize;
    let mut tot_regressed = 0usize;
    let mut tot_added = 0usize;
    let mut tot_removed = 0usize;
    let mut tot_changed = 0usize;

    for key in &keys {
        let o = old_pol.get(key);
        let n = new_pol.get(key);
        let presence = match (o.is_some(), n.is_some()) {
            (false, true) => "new",
            (true, false) => "removed",
            _             => "present",
        };

        // Per-test indexes inside the policy.
        let old_t: BTreeMap<&str, &crate::models::IndividualResult> = o
            .map(|p| p.results.iter().map(|r| (r.test_name.as_str(), r)).collect())
            .unwrap_or_default();
        let new_t: BTreeMap<&str, &crate::models::IndividualResult> = n
            .map(|p| p.results.iter().map(|r| (r.test_name.as_str(), r)).collect())
            .unwrap_or_default();

        let mut test_names: Vec<&str> = old_t.keys().chain(new_t.keys()).copied().collect();
        test_names.sort();
        test_names.dedup();

        let mut results: Vec<ResultDiff> = Vec::with_capacity(test_names.len());
        let (mut improved, mut regressed, mut added, mut removed, mut changed, mut unchanged) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);

        for tn in test_names {
            let oo = old_t.get(tn);
            let nn = new_t.get(tn);
            let kind = classify(oo.map(|r| r.status.as_str()), nn.map(|r| r.status.as_str()));
            match kind {
                "improved"  => improved  += 1,
                "regressed" => regressed += 1,
                "added"     => added     += 1,
                "removed"   => removed   += 1,
                "changed"   => changed   += 1,
                _           => unchanged += 1,
            }
            results.push(ResultDiff {
                test_name:    tn.to_string(),
                old_status:   oo.map(|r| r.status.clone()),
                new_status:   nn.map(|r| r.status.clone()),
                old_excluded: oo.map(|r| r.is_excluded).unwrap_or(false),
                new_excluded: nn.map(|r| r.is_excluded).unwrap_or(false),
                change:       kind,
            });
        }

        tot_improved  += improved;
        tot_regressed += regressed;
        tot_added     += added;
        tot_removed   += removed;
        tot_changed   += changed;

        diffs.push(PolicyDiff {
            policy_name:    key.0.clone(),
            policy_version: key.1.clone(),
            presence,
            results,
            improved, regressed, added, removed, changed, unchanged,
        });
    }

    let mut ctx = Context::new();
    ctx.insert("old_meta",       old_meta);
    ctx.insert("new_meta",       new_meta);
    ctx.insert("system_name",    &new_meta.system_name);
    ctx.insert("diffs",          &diffs);
    ctx.insert("tot_improved",   &tot_improved);
    ctx.insert("tot_regressed",  &tot_regressed);
    ctx.insert("tot_added",      &tot_added);
    ctx.insert("tot_removed",    &tot_removed);
    ctx.insert("tot_changed",    &tot_changed);

    render_template(&tera, Some(&pool), "system_reports_diff.html", ctx, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/delete/{id}
// Delete a saved system compliance report.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    match sqlx::query("DELETE FROM system_reports WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        Ok(_) => Redirect::to("/reports?success_message=System+report+deleted.").into_response(),
        Err(e) => {
            error!("Failed to delete system report {}: {}", id, e);
            Redirect::to("/reports?error_message=Failed+to+delete+report.").into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/system/bulk/delete
// Bulk delete selected saved system compliance reports.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_bulk_delete(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let body = match std::str::from_utf8(&raw_form.0) {
        Ok(s) => s.to_string(),
        Err(_) => return Redirect::to("/reports?error_message=Invalid+form+data.").into_response(),
    };

    let form_data = parse_form_data(&body);
    let ids: Vec<i64> = form_data
        .get("ids")
        .map(|v| v.iter().filter_map(|s| s.parse::<i64>().ok()).collect())
        .unwrap_or_default();

    if ids.is_empty() {
        return Redirect::to("/reports?error_message=No+reports+selected.").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if sqlx::query("DELETE FROM system_reports WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await
            .is_ok()
        {
            deleted += 1;
        }
    }

    info!("Bulk deleted {} system reports by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} system report(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/reports?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: build_system_report_pdf
// Builds a PDF byte buffer for a system compliance report.
// Public so `tests/pdf_render.rs` can render golden fixtures for visual
// before/after comparison across renderer changes.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_system_report_pdf(data: &SystemReportData, subtitle: &str) -> Result<Vec<u8>, ()> {
    const FONT_REGULAR:     &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD:        &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC:      &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES:       &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    let mut doc = Doc::new(
        &format!("OpenSCM System Report - {}", data.system_name),
        FONT_REGULAR, FONT_BOLD, FONT_ITALIC, FONT_BOLD_ITALIC,
    )?;

    // Title
    doc.text(
        "OpenSCM System Compliance Report",
        Style::new().size(28.0).bold().color(0, 0, 128).align(Align::Center),
    );
    doc.space(1.0);
    doc.text(
        subtitle,
        Style::new().size(10.0).color(100, 100, 100).align(Align::Center),
    );
    doc.space(0.5);

    // The 250px logo at genpdf's 40 DPI worked out to 158.75mm; kept identical
    // so the port does not change page 1's composition.
    doc.image_centered(LOGO_BYTES, LOGO_WIDTH_MM);
    doc.space(1.0);

    // System details table
    doc.text("System Details", Style::new().size(13.0).bold());
    doc.space(0.5);

    let mut details = Table::new(vec![1, 3]);
    for (label, value) in &[
        ("System Name",  data.system_name.as_str()),
        ("OS",           data.os.as_str()),
        ("Architecture", data.arch.as_deref().unwrap_or("—")),
        ("IP Address",   data.ip.as_deref().unwrap_or("—")),
        ("Last Seen",    data.last_seen.as_deref().unwrap_or("—")),
    ] {
        details.row(vec![
            Cell::new(*label, Style::new().bold()),
            Cell::new(*value, Style::new()),
        ]);
    }
    let score_text = if data.compliance_score < 0.0 {
        "Not Scanned".to_string()
    } else {
        format!("{:.0}%  ({} pass / {} fail / {} na)",
            data.compliance_score, data.total_pass, data.total_fail, data.total_na)
    };
    details.row(vec![
        Cell::new("Compliance Score", Style::new().bold()),
        Cell::new(score_text, Style::new()),
    ]);
    doc.table(&details);
    doc.page_break();

    // Per-policy sections
    for policy in &data.policy_groups {
        let exempt = policy.pass_count == 0 && policy.fail_count == 0;
        let verdict = if exempt { "NOT APPLICABLE" } else if policy.is_passed { "COMPLIANT" } else { "NON-COMPLIANT" };
        let verdict_color = if exempt {
            (100, 100, 100)
        } else if policy.is_passed {
            (0, 128, 0)
        } else {
            (200, 0, 0)
        };

        doc.text(
            &format!("{} — v{}", policy.policy_name, policy.policy_version),
            Style::new().size(13.0).bold(),
        );
        if let Some(desc) = &policy.policy_description {
            if !desc.is_empty() {
                doc.space(0.2);
                doc.text(desc, Style::new().size(9.0).color(100, 100, 100));
            }
        }
        doc.space(0.3);
        doc.text(
            &format!("Verdict: {}", verdict),
            Style::new().bold().color(verdict_color.0, verdict_color.1, verdict_color.2),
        );
        doc.space(0.2);
        doc.text(
            &format!(
                "Passed: {}    Failed: {}    Not Applicable: {}    Excluded: {}",
                policy.pass_count, policy.fail_count, policy.na_count, policy.excluded_count
            ),
            Style::new().size(9.0).color(80, 80, 80),
        );
        doc.space(0.5);

        let mut rules = Table::new(vec![5, 1]).header(vec![
            Cell::new("Security Requirement", Style::new().bold()),
            Cell::new("Status", Style::new().bold()),
        ]);
        for res in &policy.results {
            let (status_text, color) = status_badge(&res.status, res.is_excluded);
            rules.row(vec![
                Cell::new(res.test_name.clone(), Style::new()),
                Cell::new(status_text, Style::new().bold().color(color.0, color.1, color.2)),
            ]);
        }
        doc.table(&rules);
        doc.page_break();
    }

    doc.space(2.0);
    doc.text(
        "Note: This report contains confidential information about your infrastructure \
         and should be treated as such. Unauthorized distribution is strictly prohibited.",
        Style::new().size(10.0).color(100, 100, 100),
    );

    Ok(doc.finish())
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/download/{id}
// Download a saved system compliance report as a PDF file.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let row = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch system report for download");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let data: SystemReportData = match serde_json::from_str(row.report_data.as_deref().unwrap_or("{}")) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to deserialize system report data for PDF: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let subtitle = format!(
        "Saved on {}  ·  by {}",
        row.submission_date,
        row.submitter_name.as_deref().unwrap_or("Unknown"),
    );

    let buffer = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => {
            error!("Failed to render system report PDF {}", id);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_SystemReport_{}_{}.pdf\"",
                data.system_name.replace(' ', "_"), id),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/report/{id}/download
// Generate and stream a PDF of the live (current) system compliance report.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_live_download(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let data = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(d) => d,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch live system report for PDF");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    use chrono::Local;
    let subtitle = format!("Live Report  ·  {}", Local::now().format("%Y-%m-%d %H:%M"));

    let buffer = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => {
            error!("Failed to render live system report PDF for system {}", id);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_SystemReport_{}_live.pdf\"",
                data.system_name.replace(' ', "_")),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/system/email/{id}
// Email the archive system-report PDF to the logged-in user's address.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_email(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/reports/system/view/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let row = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&pool).await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch system report for email");
            return flash_back(&back, false, "Failed to load report.");
        }
    };

    let data: SystemReportData = match serde_json::from_str(row.report_data.as_deref().unwrap_or("{}")) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to deserialize system report data for email: {}", e);
            return flash_back(&back, false, "Failed to load report data.");
        }
    };

    let subtitle = format!(
        "Saved on {}  ·  by {}",
        row.submission_date,
        row.submitter_name.as_deref().unwrap_or("Unknown"),
    );

    let bytes = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => return flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM System Report — {}", data.system_name);
    let html_body = report_email_body(&data.system_name, "", &row.submission_date);
    let filename = format!("OpenSCM_SystemReport_{}_{}.pdf",
        data.system_name.replace(' ', "_"), id);

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{id}/email
// Email the live system-report PDF (computed against the current state) to
// the logged-in user's address.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_live_email(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/systems/report/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let data = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(d) => d,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch live system report for email");
            return flash_back(&back, false, "Failed to load report.");
        }
    };

    use chrono::Local;
    let now = Local::now().format("%Y-%m-%d %H:%M").to_string();
    let subtitle = format!("Live Report  ·  {}", now);

    let bytes = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => return flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM System Report — {} (live)", data.system_name);
    let html_body = report_email_body(&data.system_name, "", &now);
    let filename = format!("OpenSCM_SystemReport_{}_live.pdf",
        data.system_name.replace(' ', "_"));

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}
