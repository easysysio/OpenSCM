// =============================================================================
// api/write.rs — write endpoints of /api/v1 and v1beta1
//
// Each does what the matching page button does, through the same shared
// function (approve_system, delete_system, set_exclusion, the upgrade queue,
// execute_policy_run_logic, apply_policy_import, save_policy_report,
// save_system_report), with the same role, plus:
//   • SaaS plan limits, as the pages enforce them (422 plan_limit);
//   • an audit-log entry naming the token ({"via": "api", "token": …}).
// Work that runs later (a scan, an agent upgrade) answers 202 Accepted.
// See docs/design/0.12.0-rest-api.md, D3, D5 and D6. v1 differs only in
// what a policy run answers (docs/design/1.0.0-api-v1.md, D6).
// =============================================================================

use axum::extract::{rejection::JsonRejection, Extension, FromRequest, Path, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use tokio::sync::mpsc;
use tracing::error;

use super::{ApiAuth, ApiError};
use crate::models::{PolicyExport, UserRole};

fn db_err(e: sqlx::Error) -> ApiError {
    error!("API write failed: {}", e);
    ApiError::internal()
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiJson — a JSON body whose problems come back in the API's error shape,
// not axum's plain-text rejection.
// ─────────────────────────────────────────────────────────────────────────────
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(e) => Err(ApiError::bad_request(match e {
                JsonRejection::MissingJsonContentType(_) => "Send the body as JSON (Content-Type: application/json)".to_string(),
                other => format!("Invalid JSON body: {}", other.body_text()),
            })),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: audit — the write, as the token's owner, marked as coming from the
// API and which token. `extra` adds action-specific fields.
// ─────────────────────────────────────────────────────────────────────────────
async fn audit(pool: &SqlitePool, auth: &ApiAuth, action: &str, target: (&str, String), extra: Value) {
    let mut details = json!({"via": "api", "token": auth.token_name});
    if let (Some(d), Some(e)) = (details.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    crate::audit::record(
        pool, &auth.tenant_id, Some(&auth.as_session()), Some(&auth.ip),
        action, Some(target.0), Some(&target.1), Some(details),
    ).await;
}

// 422 when the organization's plan has no room for another `resource`.
async fn check_plan(pool: &SqlitePool, tenant_id: &str, resource: &str) -> Result<(), ApiError> {
    match crate::plan::limit_reached_pool(pool, tenant_id, resource).await {
        Some(limit) => Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "plan_limit", limit.message())),
        None => Ok(()),
    }
}

fn accepted(body: Value) -> Response {
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

// ── Systems ──────────────────────────────────────────────────────────────────

// POST /systems/{id}/approve — Editor. A pending system becomes active.
pub async fn systems_approve(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Json<Value>, ApiError>
{
    auth.require(UserRole::Editor)?;
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM systems WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).fetch_optional(&pool).await.map_err(db_err)?;
    match status.as_deref() {
        None => return Err(ApiError::not_found("No such system")),
        Some("active") => return Ok(Json(json!({"id": id, "status": "active"}))),
        Some(_) => {}
    }
    check_plan(&pool, &auth.tenant_id, "systems").await?;
    crate::systems::approve_system(&pool, &auth.tenant_id, id).await.map_err(db_err)?;
    audit(&pool, &auth, "system.approve", ("system", id.to_string()), json!({})).await;
    Ok(Json(json!({"id": id, "status": "active"})))
}

// DELETE /systems/{id} — Editor. 204.
pub async fn systems_delete(auth: ApiAuth, Extension(pool): Extension<SqlitePool>,
                            Extension(sync_tx): Extension<mpsc::Sender<()>>, Path(id): Path<i64>)
    -> Result<StatusCode, ApiError>
{
    auth.require(UserRole::Editor)?;
    if crate::systems::delete_system(&pool, &auth.tenant_id, id).await.map_err(db_err)? == 0 {
        return Err(ApiError::not_found("No such system"));
    }
    let _ = sync_tx.try_send(());
    audit(&pool, &auth, "system.delete", ("system", id.to_string()), json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct GroupsBody {
    groups: Vec<i64>,
}

// PUT /systems/{id}/groups — Editor. {"groups": [ids]} becomes the system's
// manual group membership. Automatic groups are rule-driven: naming one is a
// 400, and the system's automatic memberships are left as they are.
pub async fn systems_set_groups(auth: ApiAuth, Extension(pool): Extension<SqlitePool>,
                                Extension(sync_tx): Extension<mpsc::Sender<()>>,
                                Path(id): Path<i64>, ApiJson(body): ApiJson<GroupsBody>)
    -> Result<Json<Value>, ApiError>
{
    auth.require(UserRole::Editor)?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).fetch_one(&pool).await.map_err(db_err)?;
    if n == 0 {
        return Err(ApiError::not_found("No such system"));
    }
    let mut wanted = body.groups.clone();
    wanted.sort_unstable();
    wanted.dedup();
    for g in &wanted {
        let auto: Option<i64> = sqlx::query_scalar("SELECT auto_managed FROM system_groups WHERE id = ? AND tenant_id = ?")
            .bind(g).bind(&auth.tenant_id).fetch_optional(&pool).await.map_err(db_err)?;
        match auto {
            None => return Err(ApiError::bad_request(format!("No such group: {g}"))),
            Some(1) => return Err(ApiError::bad_request(format!("Group {g} is automatic; its members come from its rule"))),
            Some(_) => {}
        }
    }
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query(
        "DELETE FROM systems_in_groups WHERE tenant_id = ? AND system_id = ?
           AND group_id IN (SELECT id FROM system_groups WHERE tenant_id = ? AND auto_managed = 0)")
        .bind(&auth.tenant_id).bind(id).bind(&auth.tenant_id)
        .execute(&mut *tx).await.map_err(db_err)?;
    for g in &wanted {
        sqlx::query("INSERT OR IGNORE INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)")
            .bind(id).bind(g).bind(&auth.tenant_id).execute(&mut *tx).await.map_err(db_err)?;
    }
    tx.commit().await.map_err(db_err)?;
    let _ = sync_tx.try_send(());
    audit(&pool, &auth, "system.set_groups", ("system", id.to_string()), json!({"groups": wanted})).await;
    Ok(Json(json!({"id": id, "manual_groups": wanted})))
}

// POST /systems/{id}/upgrade — Admin. Queues the agent upgrade (202); it
// happens at the agent's next check-in, retried if the download fails.
pub async fn systems_upgrade(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Response, ApiError>
{
    auth.require(UserRole::Admin)?;
    let row: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT status, ver, arch, os FROM systems WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).fetch_optional(&pool).await.map_err(db_err)?;
    let Some((status, ver, arch, os)) = row else {
        return Err(ApiError::not_found("No such system"));
    };
    if status != "active" {
        return Err(ApiError::new(StatusCode::CONFLICT, "conflict", "Approve the system before upgrading its agent"));
    }
    let pkgs = crate::agents::load_packages(&pool).await;
    let target = crate::agents::available_upgrade(
        &pkgs, ver.as_deref().unwrap_or(""), arch.as_deref().unwrap_or(""), os.as_deref().unwrap_or(""),
    ).ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "conflict",
        "No newer agent is available for this system's platform"))?;
    sqlx::query("INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type) VALUES (?, ?, NULL, 'UPGRADE')")
        .bind(&auth.tenant_id).bind(id).execute(&pool).await.map_err(db_err)?;
    crate::systems::retry_queued_upgrade_now(&pool, &auth.tenant_id, id).await;
    audit(&pool, &auth, "system.upgrade_queued", ("system", id.to_string()), json!({"version": target})).await;
    Ok(accepted(json!({"id": id, "upgrade_to": target})))
}

#[derive(Deserialize)]
pub struct ExclusionBody {
    reason: Option<String>,
}

// PUT /systems/{system_id}/results/{test_id}/exclusion — Editor.
// {"reason": "…"}: the finding no longer counts against the system.
pub async fn exclusion_set(auth: ApiAuth, Extension(pool): Extension<SqlitePool>,
                           Extension(sync_tx): Extension<mpsc::Sender<()>>,
                           Path((system_id, test_id)): Path<(i64, i64)>, ApiJson(body): ApiJson<ExclusionBody>)
    -> Result<Json<Value>, ApiError>
{
    auth.require(UserRole::Editor)?;
    let reason = body.reason.map(|r| r.trim().chars().take(500).collect::<String>()).filter(|r| !r.is_empty());
    let n = crate::systems::set_exclusion(&pool, &auth.tenant_id, system_id, test_id,
                                          Some((&auth.username, reason.clone()))).await.map_err(db_err)?;
    if n == 0 {
        return Err(ApiError::not_found("No result for that system and test"));
    }
    let _ = sync_tx.try_send(());
    audit(&pool, &auth, "finding.exclude", ("result", format!("{system_id}/{test_id}")), json!({"reason": reason})).await;
    Ok(Json(json!({"system_id": system_id, "test_id": test_id, "excluded": true, "reason": reason})))
}

// DELETE /systems/{system_id}/results/{test_id}/exclusion — Editor.
pub async fn exclusion_clear(auth: ApiAuth, Extension(pool): Extension<SqlitePool>,
                             Extension(sync_tx): Extension<mpsc::Sender<()>>,
                             Path((system_id, test_id)): Path<(i64, i64)>)
    -> Result<StatusCode, ApiError>
{
    auth.require(UserRole::Editor)?;
    let n = crate::systems::set_exclusion(&pool, &auth.tenant_id, system_id, test_id, None).await.map_err(db_err)?;
    if n == 0 {
        return Err(ApiError::not_found("No result for that system and test"));
    }
    let _ = sync_tx.try_send(());
    audit(&pool, &auth, "finding.unexclude", ("result", format!("{system_id}/{test_id}")), json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Policies ─────────────────────────────────────────────────────────────────

// POST /policies/{id}/run — Runner. Queues the policy's tests on every system
// in scope (202); results arrive as agents report.
//
// v1 also answers when the run was queued and which active systems it
// reached. A result is from this run once its checked_at >= queued_at: both
// are whole seconds, and queued_at is taken before anything is queued.
pub async fn policies_run(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, Path(id): Path<i64>)
    -> Result<Response, ApiError>
{
    auth.require(UserRole::Runner)?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).fetch_one(&pool).await.map_err(db_err)?;
    if n == 0 {
        return Err(ApiError::not_found("No such policy"));
    }
    let queued_at = super::shape::now();
    crate::policies::execute_policy_run_logic(id as i32, &pool, &auth.tenant_id).await.map_err(db_err)?;
    audit(&pool, &auth, "policy.run", ("policy", id.to_string()), json!({})).await;
    if !auth.v1() {
        return Ok(accepted(json!({"policy_id": id, "queued": true})));
    }
    let offline = super::read::offline_secs(&pool, &auth.tenant_id).await;
    let systems: Vec<Value> = sqlx::query(
        "SELECT DISTINCT s.id, s.name,
                CASE WHEN s.last_seen IS NOT NULL
                      AND CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', s.last_seen) AS INTEGER) > ?
                     THEN 0 ELSE 1 END AS online
           FROM systems_in_policy sip
           JOIN systems_in_groups sig ON sig.group_id = sip.group_id AND sig.tenant_id = sip.tenant_id
           JOIN systems s ON s.id = sig.system_id AND s.tenant_id = sig.tenant_id
          WHERE sip.tenant_id = ? AND sip.policy_id = ? AND s.status = 'active'
          ORDER BY s.id")
        .bind(offline).bind(&auth.tenant_id).bind(id)
        .fetch_all(&pool).await.map_err(db_err)?
        .iter().map(|r| json!({
            "id": r.get::<i64, _>("id"),
            "name": r.get::<Option<String>, _>("name"),
            "online": r.get::<i64, _>("online") != 0,
        })).collect();
    Ok(accepted(json!({"policy_id": id, "queued_at": queued_at, "systems": systems})))
}

// POST /policies/import — Editor. The body is a policy export (the format of
// Policies → Export and the Policy Store). Imports a new policy, or updates
// the one with the same external id. 201 / 200.
pub async fn policies_import(auth: ApiAuth, Extension(pool): Extension<SqlitePool>, ApiJson(export): ApiJson<PolicyExport>)
    -> Result<Response, ApiError>
{
    auth.require(UserRole::Editor)?;
    match crate::policies::apply_policy_import(&pool, &auth.tenant_id, export).await {
        Ok(s) => {
            audit(&pool, &auth, "policy.import", ("policy", s.policy_id.to_string()),
                  json!({"action": s.action, "inserted_tests": s.inserted_tests, "updated_tests": s.updated_tests})).await;
            let status = if s.action == "imported" { StatusCode::CREATED } else { StatusCode::OK };
            Ok((status, Json(json!({
                "policy_id": s.policy_id,
                "action": s.action,
                "inserted_tests": s.inserted_tests,
                "updated_tests": s.updated_tests,
                "unlinked_tests": s.unlinked_tests,
            }))).into_response())
        }
        Err(msg) => {
            // The import refuses a new policy past the plan's limit with the
            // limit's own message; report that one as 422, like the pages.
            if let Some(limit) = crate::plan::limit_reached_pool(&pool, &auth.tenant_id, "policies").await {
                if msg == limit.message() {
                    return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "plan_limit", msg));
                }
            }
            Err(ApiError::bad_request(msg))
        }
    }
}

// ── Saved reports ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SaveReportBody {
    policy_id: Option<i64>,
    system_id: Option<i64>,
}

// POST /reports/{policy|system} — Runner. Saves a snapshot now:
// {"policy_id": N} or {"system_id": N}. 201 with the new report's id.
pub async fn reports_save(auth: ApiAuth, Extension(pool): Extension<SqlitePool>,
                          Path(kind): Path<String>, ApiJson(body): ApiJson<SaveReportBody>)
    -> Result<Response, ApiError>
{
    auth.require(UserRole::Runner)?;
    check_plan(&pool, &auth.tenant_id, "reports").await?;
    let (id, target) = match kind.as_str() {
        "policy" => {
            let pid = body.policy_id.ok_or_else(|| ApiError::bad_request("policy_id is required"))?;
            let id = crate::reports::save_policy_report(pid, &pool, &auth.tenant_id, &auth.username)
                .await.map_err(db_err)?.ok_or_else(|| ApiError::not_found("No such policy"))?;
            (id, ("policy", pid))
        }
        "system" => {
            let sid = body.system_id.ok_or_else(|| ApiError::bad_request("system_id is required"))?;
            let (id, _) = crate::reports::save_system_report(sid as i32, &pool, &auth.tenant_id, &auth.username)
                .await.map_err(db_err)?.ok_or_else(|| ApiError::not_found("No such system"))?;
            (id, ("system", sid))
        }
        _ => return Err(ApiError::not_found("Report kinds are policy and system")),
    };
    audit(&pool, &auth, "report.save", (target.0, target.1.to_string()), json!({"report_id": id, "kind": kind})).await;
    Ok((StatusCode::CREATED, Json(json!({"id": id, "kind": kind}))).into_response())
}
