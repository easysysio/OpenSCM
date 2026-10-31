// =============================================================================
// api/read.rs — read endpoints of /api/v1 and v1beta1 (Viewer, unless noted)
//
// Systems, groups, tests, policies, compliance, saved reports and the audit
// log of the token's organization. Lists use cursor pagination (api::Page).
// Compliance comes from the same functions as the pages, PDFs and saved
// reports — fetch_system_report_data and fetch_live_policy_report_data — so
// the API can never compute it differently from what people see.
// See docs/design/0.12.0-rest-api.md, D3 and D4. For /api/v1 each endpoint
// shapes its answer through api::shape (docs/design/1.0.0-api-v1.md); the
// v1beta1 answers are unchanged.
// =============================================================================

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use tracing::error;

use super::shape::{self, opt_score, When};
use super::{iso, page_of, ApiAuth, ApiError, Page};
use crate::models::UserRole;

fn db_err(e: sqlx::Error) -> ApiError {
    error!("API query failed: {}", e);
    ApiError::internal()
}

fn opt_iso(v: Option<String>) -> Value {
    v.filter(|s| !s.is_empty()).map(|s| json!(iso(&s))).unwrap_or(Value::Null)
}

// ── Systems ──────────────────────────────────────────────────────────────────

// Query parameters are spelled out rather than flattening Page in: with
// serde(flatten), query-string values all arrive as strings and `limit=10`
// fails to parse as a number.
#[derive(Debug, Default, Deserialize)]
pub struct SystemFilter {
    limit: Option<i64>,
    cursor: Option<String>,
    /// active | pending
    status: Option<String>,
    /// only systems in this group
    group: Option<i64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: systems_json
// Systems matching the WHERE clause the caller appended to `qb`, as API
// objects: with their groups, whether they are online (the Systems page's
// rule: last check-in within the organization's offline threshold; one that
// has never checked in is not offline) and the agent upgrade on offer.
// ─────────────────────────────────────────────────────────────────────────────
async fn systems_json(auth: &ApiAuth, pool: &SqlitePool, rows: Vec<sqlx::sqlite::SqliteRow>)
    -> Result<(Vec<Value>, Vec<i64>), ApiError>
{
    let ids: Vec<i64> = rows.iter().map(|r| r.get::<i64, _>("id")).collect();
    let mut groups: HashMap<i64, Vec<Value>> = HashMap::new();
    if !ids.is_empty() {
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT sig.system_id, g.id, g.name FROM systems_in_groups sig
               JOIN system_groups g ON g.id = sig.group_id AND g.tenant_id = sig.tenant_id
              WHERE sig.tenant_id = ");
        qb.push_bind(auth.tenant_id.clone()).push(" AND sig.system_id IN (");
        let mut sep = qb.separated(", ");
        for id in &ids { sep.push_bind(*id); }
        qb.push(") ORDER BY g.name");
        for r in qb.build().fetch_all(pool).await.map_err(db_err)? {
            groups.entry(r.get::<i64, _>(0)).or_default()
                .push(json!({"id": r.get::<i64, _>(1), "name": r.get::<String, _>(2)}));
        }
    }
    let pkgs = crate::agents::load_packages(pool).await;
    let out = rows.iter().map(|r| {
        let id: i64 = r.get("id");
        let ver: Option<String> = r.try_get("ver").ok().flatten();
        let arch: Option<String> = r.try_get("arch").ok().flatten();
        let os: Option<String> = r.try_get("os").ok().flatten();
        let upgrade = match (&ver, &arch, &os) {
            (Some(v), Some(a), Some(o)) => crate::agents::available_upgrade(&pkgs, v, a, o),
            _ => None,
        };
        let mut v = json!({
            "id": id,
            "name": r.get::<Option<String>, _>("name"),
            "status": r.get::<Option<String>, _>("status"),
            "online": r.get::<i64, _>("online") != 0,
            "agent": {
                "version": ver,
                "protocol": r.get::<Option<i64>, _>("agent_protocol"),
                "upgrade_available": upgrade,
            },
            "os": os,
            "arch": arch,
            "ip": r.get::<Option<String>, _>("ip"),
            "groups": groups.remove(&id).unwrap_or_default(),
            "compliance": {
                "score": r.get::<Option<f64>, _>("compliance_score"),
                "tests_passed": r.get::<Option<i64>, _>("tests_passed"),
                "tests_failed": r.get::<Option<i64>, _>("tests_failed"),
                "tests_total": r.get::<Option<i64>, _>("total_tests"),
            },
            "telemetry": {
                "cpu_usage": r.get::<Option<f64>, _>("cpu_usage"),
                "mem_used_mb": r.get::<Option<i64>, _>("mem_used_mb"),
                "mem_total_mb": r.get::<Option<i64>, _>("mem_total_mb"),
                "disk_used_gb": r.get::<Option<i64>, _>("disk_used_gb"),
                "disk_total_gb": r.get::<Option<i64>, _>("disk_total_gb"),
                "uptime_secs": r.get::<Option<i64>, _>("uptime_secs"),
            },
            "created_at": opt_iso(r.get("created_date")),
            "last_seen": opt_iso(r.get("last_seen")),
        });
        if auth.v1() {
            v["compliance"]["score"] = json!(opt_score(r.get("compliance_score")));
            if let Some(o) = v.as_object_mut() {
                let seen = o.remove("last_seen").unwrap_or(Value::Null);
                o.insert("last_seen_at".into(), seen);
            }
        }
        v
    }).collect();
    Ok((out, ids))
}

pub(super) async fn offline_secs(pool: &SqlitePool, tenant_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'offline_threshold'")
        .bind(tenant_id).fetch_one(pool).await.unwrap_or(60) * 60
}

fn systems_select(offline_secs: i64) -> QueryBuilder<'static, Sqlite> {
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT s.id, s.name, s.status, s.ver, s.os, s.arch, s.ip,
                CAST(s.created_date AS TEXT) AS created_date, CAST(s.last_seen AS TEXT) AS last_seen,
                s.compliance_score, s.tests_passed, s.tests_failed, s.total_tests,
                s.cpu_usage, s.mem_used_mb, s.mem_total_mb, s.disk_used_gb, s.disk_total_gb,
                s.uptime_secs, s.agent_protocol,
                CASE WHEN s.last_seen IS NOT NULL
                      AND CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', s.last_seen) AS INTEGER) > ");
    qb.push_bind(offline_secs).push(" THEN 0 ELSE 1 END AS online FROM systems s WHERE s.tenant_id = ");
    qb
}

// GET /systems — ?status=active|pending, ?group=<id>, paged.
pub async fn systems_list(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Query(f): Query<SystemFilter>)
    -> Result<Json<Value>, ApiError>
{
    let page = Page { limit: f.limit, cursor: f.cursor.clone() };
    let (after, limit) = (page.after()?, page.limit());
    let mut qb = systems_select(offline_secs(&pool, &auth.tenant_id).await);
    qb.push_bind(auth.tenant_id.clone()).push(" AND s.id > ").push_bind(after);
    match f.status.as_deref() {
        None => {}
        Some(st @ ("active" | "pending")) => { qb.push(" AND s.status = ").push_bind(st.to_string()); }
        Some(_) => return Err(ApiError::bad_request("status must be active or pending")),
    }
    if let Some(g) = f.group {
        qb.push(" AND s.id IN (SELECT system_id FROM systems_in_groups WHERE tenant_id = ")
          .push_bind(auth.tenant_id.clone()).push(" AND group_id = ").push_bind(g).push(")");
    }
    qb.push(" ORDER BY s.id LIMIT ").push_bind(limit + 1);
    let rows = qb.build().fetch_all(&pool).await.map_err(db_err)?;
    let (data, ids) = systems_json(&auth, &pool, rows).await?;
    Ok(page_of(&auth, &page, data, ids, limit))
}

// GET /systems/{id}
pub async fn systems_get(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    let mut qb = systems_select(offline_secs(&pool, &auth.tenant_id).await);
    qb.push_bind(auth.tenant_id.clone()).push(" AND s.id = ").push_bind(id);
    let rows = qb.build().fetch_all(&pool).await.map_err(db_err)?;
    let (mut data, _) = systems_json(&auth, &pool, rows).await?;
    data.pop().map(Json).ok_or_else(|| ApiError::not_found("No such system"))
}

// GET /systems/{id}/compliance — the system report: every policy linked to
// the system, each test's latest result, evidence and exclusion. The same
// data as the system report page and a saved system report.
pub async fn systems_compliance(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    exists(&pool, "systems", &auth.tenant_id, id, "No such system").await?;
    let data = crate::systems::fetch_system_report_data(id as i32, &auth.tenant_id, &pool)
        .await.map_err(db_err)?;
    if auth.v1() {
        let checked = shape::Checked::for_system(&pool, &auth.tenant_id, id).await.map_err(db_err)?;
        let mut body = shape::system_compliance(data, When::Live(&checked), Some(shape::now()));
        // The report data holds last_seen as page text, to the minute; the
        // live answer gives it to the second, as GET /systems/{id} does.
        let seen: Option<String> = sqlx::query_scalar(
            "SELECT CAST(last_seen AS TEXT) FROM systems WHERE id = ? AND tenant_id = ?")
            .bind(id).bind(&auth.tenant_id).fetch_one(&pool).await.map_err(db_err)?;
        body.last_seen_at = shape::opt_timestamp(seen.as_deref());
        return Ok(Json(serde_json::to_value(body).map_err(|_| ApiError::internal())?));
    }
    Ok(Json(serde_json::to_value(data).map_err(|_| ApiError::internal())?))
}

async fn exists(pool: &SqlitePool, table: &str, tenant_id: &str, id: i64, missing: &str) -> Result<(), ApiError> {
    let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id = ? AND tenant_id = ?"))
        .bind(id).bind(tenant_id).fetch_one(pool).await.map_err(db_err)?;
    if n == 0 { Err(ApiError::not_found(missing)) } else { Ok(()) }
}

// ── Groups ───────────────────────────────────────────────────────────────────

fn group_json(r: &sqlx::sqlite::SqliteRow) -> Value {
    json!({
        "id": r.get::<i64, _>("id"),
        "name": r.get::<String, _>("name"),
        "description": r.get::<Option<String>, _>("description"),
        "automatic": r.get::<Option<i64>, _>("auto_managed").unwrap_or(0) != 0,
        "member_count": r.get::<i64, _>("member_count"),
    })
}

const GROUP_SELECT: &str = "SELECT g.id, g.name, g.description, g.auto_managed,
        (SELECT COUNT(*) FROM systems_in_groups m WHERE m.group_id = g.id AND m.tenant_id = g.tenant_id) AS member_count
   FROM system_groups g WHERE g.tenant_id = ?";

// GET /groups — paged.
pub async fn groups_list(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Query(page): Query<Page>)
    -> Result<Json<Value>, ApiError>
{
    let (after, limit) = (page.after()?, page.limit());
    let rows = sqlx::query(&format!("{GROUP_SELECT} AND g.id > ? ORDER BY g.id LIMIT ?"))
        .bind(&auth.tenant_id).bind(after).bind(limit + 1)
        .fetch_all(&pool).await.map_err(db_err)?;
    let ids = rows.iter().map(|r| r.get::<i64, _>("id")).collect();
    Ok(page_of(&auth, &page, rows.iter().map(group_json).collect(), ids, limit))
}

// GET /groups/{id} — with its member systems and the policies it is linked to.
pub async fn groups_get(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    let row = sqlx::query(&format!("{GROUP_SELECT} AND g.id = ?"))
        .bind(&auth.tenant_id).bind(id).fetch_optional(&pool).await.map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("No such group"))?;
    let mut g = group_json(&row);
    g["systems"] = json!(sqlx::query(
        "SELECT s.id, s.name FROM systems_in_groups m JOIN systems s ON s.id = m.system_id AND s.tenant_id = m.tenant_id
          WHERE m.tenant_id = ? AND m.group_id = ? ORDER BY s.name")
        .bind(&auth.tenant_id).bind(id).fetch_all(&pool).await.map_err(db_err)?
        .iter().map(|r| json!({"id": r.get::<i64, _>(0), "name": r.get::<Option<String>, _>(1)})).collect::<Vec<_>>());
    g["policies"] = json!(sqlx::query(
        "SELECT p.id, p.name FROM systems_in_policy sp JOIN policies p ON p.id = sp.policy_id AND p.tenant_id = sp.tenant_id
          WHERE sp.tenant_id = ? AND sp.group_id = ? ORDER BY p.name")
        .bind(&auth.tenant_id).bind(id).fetch_all(&pool).await.map_err(db_err)?
        .iter().map(|r| json!({"id": r.get::<i64, _>(0), "name": r.get::<String, _>(1)})).collect::<Vec<_>>());
    Ok(Json(g))
}

// ── Tests ────────────────────────────────────────────────────────────────────

const TEST_SELECT: &str = "SELECT id, name, description, rational, remediation, severity, filter, app_filter,
        external_id, compliance_score, systems_passed, systems_failed FROM tests WHERE tenant_id = ?";

fn test_json(r: &sqlx::sqlite::SqliteRow, v1: bool) -> Value {
    if v1 {
        let mut v = test_json(r, false);
        for (key, col) in [("description", "description"), ("rationale", "rational"), ("remediation", "remediation")] {
            v[key] = json!(shape::text(r.get::<Option<String>, _>(col)));
        }
        v["compliance"] = json!({
            "score": opt_score(r.get("compliance_score")),
            "systems": {
                "passed": r.get::<Option<i64>, _>("systems_passed"),
                "failed": r.get::<Option<i64>, _>("systems_failed"),
            },
        });
        return v;
    }
    json!({
        "id": r.get::<i64, _>("id"),
        "name": r.get::<String, _>("name"),
        "description": r.get::<Option<String>, _>("description"),
        "rationale": r.get::<Option<String>, _>("rational"),
        "remediation": r.get::<Option<String>, _>("remediation"),
        "severity": r.get::<Option<String>, _>("severity"),
        "filter": r.get::<Option<String>, _>("filter"),
        "app_filter": r.get::<Option<String>, _>("app_filter"),
        "external_id": r.get::<Option<String>, _>("external_id"),
        "compliance": {
            "score": r.get::<Option<f64>, _>("compliance_score"),
            "systems_passed": r.get::<Option<i64>, _>("systems_passed"),
            "systems_failed": r.get::<Option<i64>, _>("systems_failed"),
        },
    })
}

// GET /tests — paged.
pub async fn tests_list(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Query(page): Query<Page>)
    -> Result<Json<Value>, ApiError>
{
    let (after, limit) = (page.after()?, page.limit());
    let rows = sqlx::query(&format!("{TEST_SELECT} AND id > ? ORDER BY id LIMIT ?"))
        .bind(&auth.tenant_id).bind(after).bind(limit + 1)
        .fetch_all(&pool).await.map_err(db_err)?;
    let ids = rows.iter().map(|r| r.get::<i64, _>("id")).collect();
    Ok(page_of(&auth, &page, rows.iter().map(|r| test_json(r, auth.v1())).collect(), ids, limit))
}

// GET /tests/{id} — with its conditions and applicability conditions.
pub async fn tests_get(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    let row = sqlx::query(&format!("{TEST_SELECT} AND id = ?"))
        .bind(&auth.tenant_id).bind(id).fetch_optional(&pool).await.map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("No such test"))?;
    let mut t = test_json(&row, auth.v1());
    let conds = sqlx::query(
        "SELECT `type`, element, input, selement, condition, sinput FROM test_conditions
          WHERE tenant_id = ? AND test_id = ? ORDER BY id")
        .bind(&auth.tenant_id).bind(id).fetch_all(&pool).await.map_err(db_err)?;
    let (mut conditions, mut applicability) = (Vec::new(), Vec::new());
    for c in conds {
        let v = json!({
            "element": c.get::<Option<String>, _>("element"),
            "input": c.get::<Option<String>, _>("input"),
            "selement": c.get::<Option<String>, _>("selement"),
            "condition": c.get::<Option<String>, _>("condition"),
            "sinput": c.get::<Option<String>, _>("sinput"),
        });
        if c.get::<Option<String>, _>("type").as_deref() == Some("applicability") {
            applicability.push(v);
        } else {
            conditions.push(v);
        }
    }
    t["conditions"] = json!(conditions);
    t["applicability"] = json!(applicability);
    Ok(Json(t))
}

// ── Policies ─────────────────────────────────────────────────────────────────

const POLICY_SELECT: &str = "SELECT id, name, description, version, author, external_id, compliance_score,
        score_test, score_system, score_container, systems_passed, systems_failed,
        tests_passed, tests_failed, compliant_systems, failing_systems FROM policies WHERE tenant_id = ?";

// The organization's compliance mode (Settings → Compliance): "test" or "system".
async fn scoring_mode(pool: &SqlitePool, tenant_id: &str) -> String {
    let m: Option<String> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE tenant_id = ? AND skey = 'policy_compliance_mode'")
        .bind(tenant_id).fetch_optional(pool).await.ok().flatten();
    if m.as_deref() == Some("system") { "system".into() } else { "test".into() }
}

// `mode` is Some for v1: both kinds of count, whatever the mode (design D7).
fn policy_json(r: &sqlx::sqlite::SqliteRow, mode: Option<&str>) -> Value {
    if let Some(mode) = mode {
        let mut v = policy_json(r, None);
        v["compliance"] = json!({
            "score": opt_score(r.get("compliance_score")),
            "score_by_test": opt_score(r.get("score_test")),
            "score_by_system": opt_score(r.get("score_system")),
            "score_by_container": opt_score(r.get("score_container")),
            "scoring_mode": mode,
            "systems": {
                "passed": r.get::<Option<i64>, _>("compliant_systems"),
                "failed": r.get::<Option<i64>, _>("failing_systems"),
            },
            "tests": {
                "passed": r.get::<Option<i64>, _>("tests_passed"),
                "failed": r.get::<Option<i64>, _>("tests_failed"),
            },
        });
        return v;
    }
    json!({
        "id": r.get::<i64, _>("id"),
        "name": r.get::<String, _>("name"),
        "description": r.get::<Option<String>, _>("description"),
        "version": r.get::<Option<String>, _>("version"),
        "author": r.get::<Option<String>, _>("author"),
        "external_id": r.get::<Option<String>, _>("external_id"),
        "compliance": {
            "score": r.get::<Option<f64>, _>("compliance_score"),
            "score_by_test": r.get::<Option<f64>, _>("score_test"),
            "score_by_system": r.get::<Option<f64>, _>("score_system"),
            "score_by_container": r.get::<Option<f64>, _>("score_container"),
            "systems_passed": r.get::<Option<i64>, _>("systems_passed"),
            "systems_failed": r.get::<Option<i64>, _>("systems_failed"),
        },
    })
}

// GET /policies — paged.
pub async fn policies_list(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Query(page): Query<Page>)
    -> Result<Json<Value>, ApiError>
{
    let (after, limit) = (page.after()?, page.limit());
    let rows = sqlx::query(&format!("{POLICY_SELECT} AND id > ? ORDER BY id LIMIT ?"))
        .bind(&auth.tenant_id).bind(after).bind(limit + 1)
        .fetch_all(&pool).await.map_err(db_err)?;
    let ids = rows.iter().map(|r| r.get::<i64, _>("id")).collect();
    let mode = if auth.v1() { Some(scoring_mode(&pool, &auth.tenant_id).await) } else { None };
    Ok(page_of(&auth, &page, rows.iter().map(|r| policy_json(r, mode.as_deref())).collect(), ids, limit))
}

// GET /policies/{id} — with its tests and the groups it applies to.
pub async fn policies_get(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    let row = sqlx::query(&format!("{POLICY_SELECT} AND id = ?"))
        .bind(&auth.tenant_id).bind(id).fetch_optional(&pool).await.map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("No such policy"))?;
    let mode = if auth.v1() { Some(scoring_mode(&pool, &auth.tenant_id).await) } else { None };
    let mut p = policy_json(&row, mode.as_deref());
    p["tests"] = json!(sqlx::query(
        "SELECT t.id, t.name, t.severity FROM tests_in_policy tp JOIN tests t ON t.id = tp.test_id AND t.tenant_id = tp.tenant_id
          WHERE tp.tenant_id = ? AND tp.policy_id = ? ORDER BY t.id")
        .bind(&auth.tenant_id).bind(id).fetch_all(&pool).await.map_err(db_err)?
        .iter().map(|r| json!({"id": r.get::<i64, _>(0), "name": r.get::<String, _>(1), "severity": r.get::<Option<String>, _>(2)}))
        .collect::<Vec<_>>());
    p["groups"] = json!(sqlx::query(
        "SELECT g.id, g.name FROM systems_in_policy sp JOIN system_groups g ON g.id = sp.group_id AND g.tenant_id = sp.tenant_id
          WHERE sp.tenant_id = ? AND sp.policy_id = ? ORDER BY g.name")
        .bind(&auth.tenant_id).bind(id).fetch_all(&pool).await.map_err(db_err)?
        .iter().map(|r| json!({"id": r.get::<i64, _>(0), "name": r.get::<String, _>(1)})).collect::<Vec<_>>());
    Ok(Json(p))
}

// GET /policies/{id}/compliance — the live policy report: every system in
// scope, each test's result. The same data as the policy report page and PDF.
pub async fn policies_compliance(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    let data = crate::policies::fetch_live_policy_report_data(&pool, &auth.tenant_id, &auth.username, id)
        .await.map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("No such policy"))?;
    if auth.v1() {
        let checked = shape::Checked::for_policy(&pool, &auth.tenant_id, id).await.map_err(db_err)?;
        let body = shape::policy_compliance(data, &checked);
        return Ok(Json(serde_json::to_value(body).map_err(|_| ApiError::internal())?));
    }
    Ok(Json(serde_json::to_value(data).map_err(|_| ApiError::internal())?))
}

// ── Saved reports ────────────────────────────────────────────────────────────

fn kind_of(kind: &str) -> Result<&'static str, ApiError> {
    match kind {
        "policy" => Ok("policy"),
        "system" => Ok("system"),
        _ => Err(ApiError::not_found("Report kinds are policy and system")),
    }
}

// GET /reports/{policy|system} — saved snapshots, paged.
pub async fn reports_list(auth: ApiAuth, Extension(pool): Extension<SqlitePool>,
                          Path(kind): Path<String>, Query(page): Query<Page>)
    -> Result<Json<Value>, ApiError>
{
    let (after, limit) = (page.after()?, page.limit());
    let (sql, policy) = match kind_of(&kind)? {
        "policy" => ("SELECT id, CAST(submission_date AS TEXT) AS d, policy_name AS name, policy_version AS v,
                             submitter_name AS who, NULL AS sid, policy_id AS pid
                        FROM reports WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ?", true),
        _ => ("SELECT id, CAST(submission_date AS TEXT) AS d, system_name AS name, NULL AS v,
                      submitter_name AS who, system_id AS sid, NULL AS pid
                 FROM system_reports WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ?", false),
    };
    let rows = sqlx::query(sql).bind(&auth.tenant_id).bind(after).bind(limit + 1)
        .fetch_all(&pool).await.map_err(db_err)?;
    let ids = rows.iter().map(|r| r.get::<i64, _>("id")).collect();
    let data = rows.iter().map(|r| {
        let mut v = json!({
            "id": r.get::<i64, _>("id"),
            "kind": kind,
            "saved_at": opt_iso(r.get("d")),
            "saved_by": r.get::<Option<String>, _>("who"),
        });
        if policy {
            v["policy"] = json!({"name": r.get::<Option<String>, _>("name"), "version": r.get::<Option<String>, _>("v")});
            if auth.v1() {
                v["policy"]["id"] = json!(r.get::<Option<i64>, _>("pid"));
            }
        } else {
            v["system"] = json!({"id": r.get::<Option<i64>, _>("sid"), "name": r.get::<Option<String>, _>("name")});
        }
        v
    }).collect();
    Ok(page_of(&auth, &page, data, ids, limit))
}

// GET /reports/{policy|system}/{id} — one saved snapshot, as saved.
pub async fn reports_get(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path((kind, id)): Path<(String, i64)>)
    -> Result<Json<Value>, ApiError>
{
    if kind_of(&kind)? == "policy" {
        let (report, systems, tests) = crate::reports::fetch_archive_policy_report(&pool, &auth.tenant_id, id)
            .await.map_err(db_err)?
            .ok_or_else(|| ApiError::not_found("No such report"))?;
        if auth.v1() {
            let policy_id: Option<i64> = sqlx::query_scalar("SELECT policy_id FROM reports WHERE id = ? AND tenant_id = ?")
                .bind(id).bind(&auth.tenant_id).fetch_one(&pool).await.map_err(db_err)?;
            return Ok(Json(json!({
                "id": report.id,
                "kind": "policy",
                "saved_at": iso(&report.submission_date),
                "saved_by": report.submitter_name,
                "policy": {"id": policy_id, "name": report.policy_name, "version": report.policy_version,
                           "description": report.policy_description},
                "tests": shape::test_meta(tests),
                "systems": systems.into_iter().map(|s| shape::system_report(s, When::Saved)).collect::<Vec<_>>(),
            })));
        }
        return Ok(Json(json!({
            "id": report.id,
            "kind": "policy",
            "saved_at": iso(&report.submission_date),
            "saved_by": report.submitter_name,
            "policy": {"name": report.policy_name, "version": report.policy_version, "description": report.policy_description},
            "tests": tests,
            "systems": systems,
        })));
    }
    let row = sqlx::query(
        "SELECT id, CAST(submission_date AS TEXT) AS d, system_id, system_name, submitter_name, report_data
           FROM system_reports WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).fetch_optional(&pool).await.map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("No such report"))?;
    let raw = row.get::<Option<String>, _>("report_data");
    let data: Value = if auth.v1() {
        // Snapshots from every release deserialise (serde defaults); one that
        // does not is served as null rather than failing the request.
        raw.as_deref()
            .and_then(|r| serde_json::from_str::<crate::models::SystemReportData>(r).ok())
            .map(|d| json!(shape::system_compliance(d, When::Saved, None)))
            .unwrap_or(Value::Null)
    } else {
        serde_json::from_str(raw.as_deref().unwrap_or("{}")).unwrap_or(Value::Null)
    };
    Ok(Json(json!({
        "id": row.get::<i64, _>("id"),
        "kind": "system",
        "saved_at": opt_iso(row.get("d")),
        "saved_by": row.get::<Option<String>, _>("submitter_name"),
        "system": {"id": row.get::<Option<i64>, _>("system_id"), "name": row.get::<Option<String>, _>("system_name")},
        "report": data,
    })))
}

// GET /reports/{policy|system}/{id}/pdf — the same PDF as the Download button.
pub async fn reports_pdf(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path((kind, id)): Path<(String, i64)>)
    -> Result<Response, ApiError>
{
    let bytes = if kind_of(&kind)? == "policy" {
        let (report, systems, tests) = crate::reports::fetch_archive_policy_report(&pool, &auth.tenant_id, id)
            .await.map_err(db_err)?
            .ok_or_else(|| ApiError::not_found("No such report"))?;
        crate::reports::build_archive_policy_pdf(&report, &systems, &tests).map_err(|_| ApiError::internal())?
    } else {
        let row = sqlx::query(
            "SELECT CAST(submission_date AS TEXT) AS d, submitter_name, report_data
               FROM system_reports WHERE id = ? AND tenant_id = ?")
            .bind(id).bind(&auth.tenant_id).fetch_optional(&pool).await.map_err(db_err)?
            .ok_or_else(|| ApiError::not_found("No such report"))?;
        let data: crate::models::SystemReportData =
            serde_json::from_str(row.get::<Option<String>, _>("report_data").as_deref().unwrap_or("{}"))
                .map_err(|_| ApiError::internal())?;
        let subtitle = format!("Saved on {}  ·  by {}", row.get::<String, _>("d"),
                               row.get::<Option<String>, _>("submitter_name").unwrap_or_else(|| "Unknown".into()));
        crate::reports::build_system_report_pdf(&data, &subtitle).map_err(|_| ApiError::internal())?
    };
    Ok((
        [(header::CONTENT_TYPE, "application/pdf".to_string()),
         (header::CONTENT_DISPOSITION, format!("attachment; filename=\"OpenSCM_{kind}_report_{id}.pdf\""))],
        bytes,
    ).into_response())
}

// ── Audit log (Admin) ────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct AuditFilter {
    limit: Option<i64>,
    cursor: Option<String>,
    /// ISO 8601; only entries at or after it.
    since: Option<String>,
    /// Only actions starting with this, e.g. "system." or "auth.login_failure".
    action: Option<String>,
}

// GET /audit-log — oldest first from the cursor (or ?since), paged.
pub async fn audit_log(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Query(f): Query<AuditFilter>)
    -> Result<Json<Value>, ApiError>
{
    auth.require(UserRole::Admin)?;
    let page = Page { limit: f.limit, cursor: f.cursor.clone() };
    let (after, limit) = (page.after()?, page.limit());
    let since = f.since.as_deref().map(|s| s.trim_end_matches('Z').replacen('T', " ", 1));
    let rows = sqlx::query(
        "SELECT id, CAST(created_at AS TEXT) AS at, actor_user_id, actor_username, action,
                target_type, target_id, details, ip_address
           FROM audit_log
          WHERE tenant_id = ? AND id > ?
            AND (? IS NULL OR created_at >= ?)
            AND (? IS NULL OR action LIKE ? || '%')
          ORDER BY id LIMIT ?")
        .bind(&auth.tenant_id).bind(after)
        .bind(&since).bind(&since)
        .bind(&f.action).bind(&f.action)
        .bind(limit + 1)
        .fetch_all(&pool).await.map_err(db_err)?;
    let ids = rows.iter().map(|r| r.get::<i64, _>("id")).collect();
    let data = rows.iter().map(|r| {
        let details: Option<String> = r.get("details");
        if auth.v1() {
            return json!({
                "id": r.get::<i64, _>("id"),
                "created_at": opt_iso(r.get("at")),
                "actor": {"id": r.get::<Option<i64>, _>("actor_user_id"), "username": r.get::<String, _>("actor_username")},
                "action": r.get::<String, _>("action"),
                "target": {"type": r.get::<Option<String>, _>("target_type"), "id": r.get::<Option<String>, _>("target_id")},
                "details": shape::audit_details(details),
                "ip": r.get::<Option<String>, _>("ip_address"),
            });
        }
        json!({
            "id": r.get::<i64, _>("id"),
            "at": opt_iso(r.get("at")),
            "actor": {"id": r.get::<Option<i64>, _>("actor_user_id"), "username": r.get::<String, _>("actor_username")},
            "action": r.get::<String, _>("action"),
            "target": {"type": r.get::<Option<String>, _>("target_type"), "id": r.get::<Option<String>, _>("target_id")},
            // Structured details are returned as JSON, anything else as text.
            "details": details.map(|d| serde_json::from_str::<Value>(&d).unwrap_or(Value::String(d))),
            "ip": r.get::<Option<String>, _>("ip_address"),
        })
    }).collect();
    Ok(page_of(&auth, &page, data, ids, limit))
}
