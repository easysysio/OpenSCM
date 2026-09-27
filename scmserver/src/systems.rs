// =============================================================================
// systems.rs — managed system CRUD, bulk actions, live compliance report
//
// System-group CRUD (list / add / edit / delete) lives in `groups.rs`.
// `systems_bulk_add_group` is here because it operates on the systems table
// (assigning rows to a group id), even though it's group-adjacent.
//
// All routes are tenant-scoped. Viewer role required for reads;
// Editor role required for writes.
// =============================================================================

use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::HashMap;
use tracing::{info, warn, error};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use std::collections::BTreeMap;
use semver::Version;
use crate::agents::derive_platform;
use crate::handlers::{normalize_status, is_system_passed};
use crate::models::{
    AgentPackage, ErrorQuery, System, SystemGroup, SystemInsideGroup, UserRole, AuthSession,
    IndividualResult, PolicyResultGroup, SystemReportData, TestMeta,
};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ─────────────────────────────────────────────────────────────────────────────
// Helper: systems_page_context
// A Context holding everything systems.html reads besides the system list,
// set to safe defaults. Every handler that renders the page starts from this.
//
// The Pending Systems page renders systems.html too, but its handler never
// supplied `groups` (needed by the bulk "Add to Group" dialog since 0.1.9), so
// Tera failed on the undefined variable and the page was a 500 — as were the
// database-error paths of both handlers. Callers overwrite has_upgradable and
// containers_by_system_json when they have real values.
//
// Only manual groups are listed: auto-managed groups derive their membership
// from a rule, so pushing a system in by hand would be undone on the next
// heartbeat. (Defence in depth: the bulk POST validator also rejects auto
// targets in case the form is replayed against a now-auto group.)
// ─────────────────────────────────────────────────────────────────────────────
async fn systems_page_context(pool: &SqlitePool, tenant_id: &str) -> Context {
    let groups: Vec<(i64, String)> = sqlx::query(
        "SELECT id, name FROM system_groups
         WHERE tenant_id = ? AND auto_managed = 0
         ORDER BY name ASC"
    )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(|r| (r.get("id"), r.get("name"))).collect())
        .unwrap_or_default();

    let mut context = Context::new();
    context.insert("groups", &groups);
    context.insert("has_upgradable", &false);
    context.insert("containers_by_system_json", "{}");
    context
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems
// List all systems (active + pending) for the current tenant, with optional
// ?filter=active|pending query param.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems(
    auth: AuthSession,
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let filter = params.get("filter").map(|s| s.to_lowercase());

    // Fetch threshold first so we can compute is_offline server-side in SQL.
    // Stored in MINUTES (aligned with auto_prune_inactive); the SQL placeholder
    // expects seconds, so we multiply by 60 at bind time below.
    let offline_threshold_min: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'offline_threshold'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(60);
    let offline_threshold = offline_threshold_min * 60;

    let gc        = "GROUP_CONCAT(sg.name)".to_string();
    let created   = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.created_date), '')".to_string();
    let last_seen = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.last_seen), '')".to_string();
    let unix_diff = "(CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', s.last_seen) AS INTEGER))".to_string();

    let rows_result = match filter.as_deref() {
        Some("active") | Some("pending") => {
            let sql = format!(
                r#"SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver,  'NA') AS system_ver,
                    COALESCE(s.ip,   'NA') AS system_ip,
                    COALESCE(s.os,   'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE({gc}, 'none') AS group_names,
                    {created} AS created_date,
                    {last_seen} AS last_seen,
                    CASE
                        WHEN s.status != 'active' THEN 0
                        WHEN s.last_seen IS NULL   THEN 0
                        WHEN {unix_diff} > ?        THEN 1
                        ELSE 0
                    END AS is_offline,
                    s.cpu_usage, s.mem_used_mb, s.mem_total_mb,
                    s.disk_used_gb, s.disk_total_gb, s.uptime_secs
                FROM systems AS s
                LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN system_groups     AS sg  ON sig.group_id = sg.id
                WHERE s.status = ? AND s.tenant_id = ?
                GROUP BY s.id
                ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.name ASC"#
            );
            sqlx::query(&sql)
                .bind(offline_threshold)
                .bind(filter.as_deref().unwrap_or("active"))
                .bind(&auth.tenant_id)
                .fetch_all(&pool)
                .await
        }
        _ => {
            let sql = format!(
                r#"SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver,  'NA') AS system_ver,
                    COALESCE(s.ip,   'NA') AS system_ip,
                    COALESCE(s.os,   'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE({gc}, 'none') AS group_names,
                    {created} AS created_date,
                    {last_seen} AS last_seen,
                    CASE
                        WHEN s.status != 'active' THEN 0
                        WHEN s.last_seen IS NULL   THEN 0
                        WHEN {unix_diff} > ?        THEN 1
                        ELSE 0
                    END AS is_offline,
                    s.cpu_usage, s.mem_used_mb, s.mem_total_mb,
                    s.disk_used_gb, s.disk_total_gb, s.uptime_secs
                FROM systems AS s
                LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN system_groups     AS sg  ON sig.group_id = sg.id
                WHERE s.tenant_id = ?
                GROUP BY s.id
                ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.name ASC"#
            );
            sqlx::query(&sql)
                .bind(offline_threshold)
                .bind(&auth.tenant_id)
                .fetch_all(&pool)
                .await
        }
    };

    let rows = match rows_result {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to fetch systems: {}", e);
            let mut context = systems_page_context(&pool, &auth.tenant_id).await;
            context.insert("error_message", "Failed to load systems.");
            context.insert("systems", &Vec::<System>::new());
            return render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    // Fetch all agent packages once for upgrade-availability annotation.
    // On a DB error, log it and degrade to no upgrade badges.
    let agent_pkgs: HashMap<String, AgentPackage> = sqlx::query_as::<_, AgentPackage>(
        "SELECT platform, version, sha256, url FROM agent_packages",
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_else(|e| { error!("Failed to fetch agent packages: {}", e); Vec::new() })
    .into_iter()
    .map(|p| (p.platform.clone(), p))
    .collect();

    let systems: Vec<System> = rows
        .into_iter()
        .map(|row| {
            let ver:  Option<String> = row.try_get("system_ver").ok();
            let arch: Option<String> = row.try_get("system_arch").ok();
            let os:   Option<String> = row.try_get("system_os").ok();

            // Derive platform on read from arch + os instead of persisting it,
            // so a server upgrade can change the normalisation rules without a
            // backfill migration.
            let platform = match (&arch, &os) {
                (Some(a), Some(o)) if a != "NA" && o != "NA" => Some(derive_platform(a, o)),
                _ => None,
            };

            // Determine upgrade availability: compare versions with semver.
            // Silently ignore unparseable version strings (very old agents may
            // not conform; they simply show no upgrade button).
            let (upgrade_available, upgrade_version) = if let (Some(pf), Some(cv)) = (&platform, &ver) {
                if let Some(pkg) = agent_pkgs.get(pf) {
                    let current  = Version::parse(cv).ok();
                    let available = Version::parse(&pkg.version).ok();
                    match (current, available) {
                        (Some(c), Some(a)) if a > c => (true, Some(pkg.version.clone())),
                        _ => (false, None),
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            System {
                id:               row.try_get("system_id").unwrap_or(None),
                name:             row.get("system_name"),
                ver,
                ip:               row.try_get("system_ip").ok(),
                os,
                arch,
                platform,
                status:           row.try_get("system_status").ok(),
                groups:           row.try_get("group_names").ok(),
                auth_signature:   None,
                auth_public_key:  None,
                trust_challenge:  None,
                trust_proof:      None,
                created_date:     row.try_get::<String, _>("created_date").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
                last_seen:        row.try_get::<String, _>("last_seen").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
                is_offline:       row.try_get::<bool, _>("is_offline").unwrap_or(false),
                upgrade_available,
                upgrade_version,
                cpu_usage:        row.try_get("cpu_usage").ok(),
                mem_used_mb:      row.try_get("mem_used_mb").ok(),
                mem_total_mb:     row.try_get("mem_total_mb").ok(),
                disk_used_gb:     row.try_get("disk_used_gb").ok(),
                disk_total_gb:    row.try_get("disk_total_gb").ok(),
                uptime_secs:      row.try_get("uptime_secs").ok(),
                has_telemetry:    row.try_get::<Option<f32>, _>("cpu_usage").ok().flatten().is_some(),
            }
        })
        .collect();


    let mut context = systems_page_context(&pool, &auth.tenant_id).await;

    if let Some(error_message) = params.get("error_message") {
        context.insert("error_message", error_message);
    }
    if let Some(success_message) = params.get("success_message") {
        context.insert("success_message", success_message);
    }
    let has_upgradable = systems.iter().any(|s| s.upgrade_available && !s.is_offline);

    // Container inventory — one bulk query for every system on the page,
    // grouped by host_system_id, JSON-encoded once and embedded as a script
    // block. The systems-list JS reads it on chevron-click to populate the
    // DataTables child row without a per-system round-trip.
    let host_ids: Vec<i32> = systems.iter().filter_map(|s| s.id).collect();
    let containers_by_system_json: String = if host_ids.is_empty() {
        "{}".to_string()
    } else {
        let placeholders = std::iter::repeat("?").take(host_ids.len()).collect::<Vec<_>>().join(",");
        // Only columns the list/modal actually use. Deliberately excludes the
        // v35 `compliance_score` column (not rendered here) so a database that
        // hasn't reached v35 still returns its inventory rather than silently
        // dropping every container when the SELECT fails.
        let sql = format!(
            "SELECT id, host_system_id, runtime, runtime_id, name, image, image_digest, status, ip,
                    is_privileged, run_user, network_mode, exposed_ports, mounts, capabilities_add,
                    read_only_fs, restart_policy, health_check, first_seen, last_seen
             FROM containers
             WHERE tenant_id = ? AND host_system_id IN ({})
             ORDER BY host_system_id, name",
            placeholders
        );
        let mut q = sqlx::query(&sql).bind(&auth.tenant_id);
        for id in &host_ids { q = q.bind(id); }
        let rows = match q.fetch_all(&pool).await {
            Ok(r) => r,
            Err(e) => {
                // Don't silently hide the inventory — surface the cause.
                error!("Failed to load container inventory for systems list: {}", e);
                Vec::new()
            }
        };
        let mut map: std::collections::BTreeMap<i32, Vec<serde_json::Value>> = std::collections::BTreeMap::new();
        for row in rows {
            let host_id: i32 = row.try_get("host_system_id").unwrap_or(0);
            map.entry(host_id).or_default().push(serde_json::json!({
                "id":               row.try_get::<i64, _>("id").ok(),
                "host_system_id":   host_id,
                "runtime":          row.try_get::<String, _>("runtime").ok(),
                "runtime_id":       row.try_get::<String, _>("runtime_id").ok(),
                "name":             row.try_get::<String, _>("name").ok(),
                "image":            row.try_get::<Option<String>, _>("image").ok().flatten(),
                "image_digest":     row.try_get::<Option<String>, _>("image_digest").ok().flatten(),
                "status":           row.try_get::<Option<String>, _>("status").ok().flatten(),
                "ip":               row.try_get::<Option<String>, _>("ip").ok().flatten(),
                "is_privileged":    row.try_get::<Option<i64>, _>("is_privileged").ok().flatten().map(|v| v != 0),
                "run_user":         row.try_get::<Option<String>, _>("run_user").ok().flatten(),
                "network_mode":     row.try_get::<Option<String>, _>("network_mode").ok().flatten(),
                "exposed_ports":    row.try_get::<Option<String>, _>("exposed_ports").ok().flatten(),
                "mounts":           row.try_get::<Option<String>, _>("mounts").ok().flatten(),
                "capabilities_add": row.try_get::<Option<String>, _>("capabilities_add").ok().flatten(),
                "read_only_fs":     row.try_get::<Option<i64>, _>("read_only_fs").ok().flatten().map(|v| v != 0),
                "restart_policy":   row.try_get::<Option<String>, _>("restart_policy").ok().flatten(),
                "health_check":     row.try_get::<Option<i64>, _>("health_check").ok().flatten().map(|v| v != 0),
                "first_seen":       row.try_get::<Option<String>, _>("first_seen").ok().flatten(),
                "last_seen":        row.try_get::<Option<String>, _>("last_seen").ok().flatten(),
            }));
        }
        // Escaped for <script> embedding: container names are agent-supplied
        // and JSON alone does not neutralise a literal "</script>".
        crate::handlers::escape_json_for_script(
            &serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string()),
        )
    };

    context.insert("systems", &systems);
    context.insert("has_upgradable", &has_upgradable);
    context.insert("containers_by_system_json", &containers_by_system_json);
    render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/approve/{id}
// Approve a pending system (set status → active).
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_approve(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    if let Err(e) = sqlx::query(
        "UPDATE systems SET status = 'active' WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to approve system {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error approving system: {}", e)).to_string();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    info!("System ID {} approved by '{}'.", id, auth.username);
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.approve",
        Some("system"), Some(&id.to_string()),
        None,
    ).await;
    Redirect::to("/systems").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/delete/{id}
// Delete a system and cascade-remove its results; signals compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    // ON DELETE CASCADE handles related records automatically
    if let Err(e) = sqlx::query("DELETE FROM systems WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        error!("Failed to delete system {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting system: {}", e)).to_string();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    // Trend history has no FK (deletion must never be blocked by it) — clean
    // up explicitly; anything missed ages out via entity_trend_retention_days.
    let _ = sqlx::query(
        "DELETE FROM entity_compliance_history
         WHERE tenant_id = ? AND entity_type = 'system' AND entity_id = ?")
        .bind(&auth.tenant_id).bind(id)
        .execute(&pool).await;

    let _ = sync_tx.send(()).await;
    info!("System ID {} deleted by '{}'. Compliance update signaled.", id, auth.username);
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.delete",
        Some("system"), Some(&id.to_string()),
        None,
    ).await;
    Redirect::to("/systems").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/edit/{id}
// Render the system edit form (group assignment).
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT id, name, ver, ip, os, arch, status
         FROM systems
         WHERE id = ? AND tenant_id = ? AND status = 'active'",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!("Database error fetching system {}: {}", id, e);
            return Redirect::to("/systems?error_message=Database+error").into_response();
        }
    };

    let system = System {
        id: row.try_get("id").unwrap_or(None),
        name: row.get("name"),
        ver: row.try_get("ver").ok(),
        ip: row.try_get("ip").ok(),
        os: row.try_get("os").ok(),
        arch: row.try_get("arch").ok(),
        status: row.try_get("status").ok(),
        groups: None,
        auth_signature: None,
        auth_public_key: None,
        trust_challenge: None,
        trust_proof: None,
        created_date: None,
        last_seen: None,
        is_offline: false,
        platform: None,
        upgrade_available: false,
        upgrade_version: None,
        cpu_usage: None,
        mem_used_mb: None,
        mem_total_mb: None,
        disk_used_gb: None,
        disk_total_gb: None,
        uptime_secs: None,
        has_telemetry: false,
    };

    // Edit form's group picker shows manual groups only. Auto-group
    // membership is rule-driven — exposing those in the form would either
    // (a) wipe them on save (DELETE-then-INSERT pattern below) or
    // (b) silently re-add them on next heartbeat. Either way it's
    // confusing. Auto memberships ARE displayed on the systems list /
    // detail (read-only); admins edit them via the rule editor.
    let groups_result = sqlx::query(
        "SELECT sg.id AS group_id, sg.name AS group_name, sg.description AS group_description
         FROM system_groups AS sg
         WHERE sg.tenant_id = ? AND sg.auto_managed = 0",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let groups: Vec<SystemGroup> = match groups_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemGroup {
                id: row.get("group_id"),
                name: row.get("group_name"),
                description: row.try_get("group_description").ok(),
                systems: None,
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch groups for system edit {}: {}", id, e);
            vec![]
        }
    };

    let sig_result = sqlx::query(
        "SELECT system_id, group_id FROM systems_in_groups WHERE system_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems_in_groups: Vec<SystemInsideGroup> = match sig_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemInsideGroup {
                system_id: row.get("system_id"),
                group_id: row.get("group_id"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch group memberships for system {}: {}", id, e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("system", &system);
    context.insert("groups", &groups);
    context.insert("systems_in_groups", &systems_in_groups);
    render_template(&tera, Some(&pool), "systems_edit.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/edit/{id}
// Persist group-membership changes for a system; signals compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = String::from_utf8_lossy(&bytes).to_string();
    let form_data = parse_form_data(&raw_string);
    let selected_groups = form_data.get("groups").cloned();

    // Clear only this system's MANUAL group memberships. Auto-managed
    // memberships are owned by the rule evaluator (auto_groups.rs) and
    // must survive this DELETE-then-INSERT cycle — otherwise saving the
    // edit form would wipe them and the next heartbeat would re-add them
    // (visible churn + audit-log noise).
    if let Err(e) = sqlx::query(
        "DELETE FROM systems_in_groups
         WHERE system_id = ? AND tenant_id = ?
           AND group_id IN (
             SELECT id FROM system_groups
             WHERE tenant_id = ? AND auto_managed = 0
           )"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Failed to clear old groups: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    if let Some(group_ids) = selected_groups {
        for g_id_str in group_ids {
            if let Ok(g_id) = g_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
                )
                .bind(id)
                .bind(g_id)
                .bind(&auth.tenant_id)
                .execute(&mut *tx)
                .await
                {
                    let encoded =
                        urlencoding::encode(&format!("Failed to link group {}: {}", g_id, e))
                            .to_string();
                    tx.rollback().await.ok();
                    return Redirect::to(&format!("/systems?error_message={}", encoded))
                        .into_response();
                }
            }
        }
    }


    // Clean up results for tests no longer reachable through current groups
    if let Err(e) = sqlx::query(r#"
        DELETE FROM results
        WHERE system_id = ?
        AND test_id NOT IN (
            SELECT DISTINCT tip.test_id
            FROM tests_in_policy tip
            JOIN systems_in_policy sip ON tip.policy_id = sip.policy_id
            JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            WHERE sig.system_id = ?
            AND sig.tenant_id = ?
        )
    "#)
    .bind(id)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }



    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("System ID {} groups updated by '{}'.", id, auth.username);
    Redirect::to("/systems?success_message=System+groups+updated+successfully").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/pending
// List all systems with status = 'pending' awaiting approval.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_pending(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let sql = format!(
        r#"SELECT
            s.id AS system_id,
            COALESCE(s.name, 'NA') AS system_name,
            COALESCE(s.ver,  'NA') AS system_ver,
            COALESCE(s.ip,   'NA') AS system_ip,
            COALESCE(s.os,   'NA') AS system_os,
            COALESCE(s.arch, 'NA') AS system_arch,
            COALESCE(s.status, 'NA') AS system_status,
            COALESCE({gc}, 'none') AS group_names,
            {created} AS created_date,
            {last_seen} AS last_seen
        FROM systems AS s
        LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
        LEFT JOIN system_groups     AS sg  ON sig.group_id = sg.id
        WHERE s.status = 'pending' AND s.tenant_id = ?
        GROUP BY s.id"#,
        gc      = "GROUP_CONCAT(sg.name)",
        created = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.created_date), '')",
        last_seen = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.last_seen), '')",
    );
    let rows_result = sqlx::query(&sql)
        .bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await;

    let rows = match rows_result {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to fetch pending systems: {}", e);
            let mut context = systems_page_context(&pool, &auth.tenant_id).await;
            context.insert("error_message", "Failed to load pending systems.");
            context.insert("systems", &Vec::<System>::new());
            return render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let systems: Vec<System> = rows
        .into_iter()
        .map(|row| System {
            id: row.try_get("system_id").unwrap_or(None),
            name: row.get("system_name"),
            ver: row.try_get("system_ver").ok(),
            ip: row.try_get("system_ip").ok(),
            os: row.try_get("system_os").ok(),
            arch: row.try_get("system_arch").ok(),
            status: row.try_get("system_status").ok(),
            groups: row.try_get("group_names").ok(),
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: row.try_get::<String, _>("created_date").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            last_seen: row.try_get::<String, _>("last_seen").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            is_offline: false,
            platform: None,
            upgrade_available: false,
            upgrade_version: None,
            cpu_usage: None,
            mem_used_mb: None,
            mem_total_mb: None,
            disk_used_gb: None,
            disk_total_gb: None,
            uptime_secs: None,
            has_telemetry: false,
        })
        .collect();

    let mut context = systems_page_context(&pool, &auth.tenant_id).await;
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    context.insert("systems", &systems);
    render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// System-group CRUD (list / add / edit / delete) was split out into
// `groups.rs` when this file passed ~1500 lines. `systems_bulk_add_group`
// below stays here because it operates on the systems table — it's a bulk
// action that assigns selected systems to a group id.
// ─────────────────────────────────────────────────────────────────────────────


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/approve
// Approve multiple pending systems in one operation.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_approve(
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
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/systems?error_message=No+systems+selected").into_response();
    }

    let mut approved = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query(
            "UPDATE systems SET status = 'active' WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
        {
            error!("Bulk approve: failed for system {}: {}", id, e);
        } else {
            approved += 1;
        }
    }

    info!("Bulk approved {} systems by '{}'.", approved, auth.username);
    let msg = urlencoding::encode(&format!("{} system(s) approved.", approved)).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/delete
// Delete multiple systems and signal a compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_delete(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/systems?error_message=No+systems+selected").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query("DELETE FROM systems WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await
        {
            error!("Bulk delete: failed for system {}: {}", id, e);
        } else {
            deleted += 1;
            // Trend history has no FK — clean up explicitly (see systems_delete).
            let _ = sqlx::query(
                "DELETE FROM entity_compliance_history
                 WHERE tenant_id = ? AND entity_type = 'system' AND entity_id = ?")
                .bind(&auth.tenant_id).bind(id)
                .execute(&pool).await;
        }
    }

    let _ = sync_tx.send(()).await;
    info!("Bulk deleted {} systems by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} system(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/add-group
// Add multiple systems to a selected group in one operation.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_add_group(
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
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);

    let group_id: i32 = match form_data
        .get("group_id")
        .and_then(|v| v.first())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Redirect::to("/systems?error_message=No+group+selected").into_response(),
    };

    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/systems?error_message=No+systems+selected").into_response();
    }

    // Verify group belongs to this tenant AND is manual. Defence in depth
    // against a replayed / hand-crafted POST against an auto group —
    // membership there is rule-driven and would be undone on next heartbeat
    // anyway, but rejecting up front avoids confusing audit-log entries.
    let group_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_groups
         WHERE id = ? AND tenant_id = ? AND auto_managed = 0",
    )
    .bind(group_id)
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(0i64) > 0;

    if !group_exists {
        return Redirect::to(
            "/systems?error_message=Invalid+group+or+auto-managed+group+cannot+be+added+to+manually"
        ).into_response();
    }

    let mut added = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query(
            "INSERT OR IGNORE INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
        )
        .bind(id)
        .bind(group_id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
        {
            error!("Bulk add group: failed for system {}: {}", id, e);
        } else {
            added += 1;
        }
    }

    info!("Bulk added {} systems to group {} by '{}'.", added, group_id, auth.username);
    let msg = urlencoding::encode(&format!("{} system(s) added to group.", added)).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// fetch_system_report_data
// Gather all policy/test compliance results for one system into
// SystemReportData. Shared by the live report handler and the save handler.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn fetch_system_report_data(
    system_id: i32,
    tenant_id: &str,
    pool: &SqlitePool,
) -> Result<SystemReportData, sqlx::Error> {
    let sys_row = sqlx::query(&format!(
        "SELECT id, name, os, arch, ip, compliance_score,
                {last_seen} AS last_seen
         FROM systems WHERE id = ? AND tenant_id = ?",
        last_seen = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', last_seen), '')",
    ))
    .bind(system_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    let raw = sqlx::query(r#"
        SELECT
            p.id          AS policy_id,
            p.name        AS policy_name,
            p.version     AS policy_version,
            p.description AS policy_description,
            t.id          AS test_id,
            t.name        AS test_name,
            COALESCE(r.result, 'NOT_SCANNED') AS status,
            COALESCE(r.excluded, 0) AS is_excluded,
            r.excluded_reason AS excluded_reason,
            r.evidence AS evidence
        FROM systems_in_groups sig
        JOIN systems_in_policy sip
            ON sig.group_id = sip.group_id AND sig.tenant_id = sip.tenant_id
        JOIN policies p
            ON sip.policy_id = p.id AND p.tenant_id = sip.tenant_id
        JOIN tests_in_policy tip
            ON tip.policy_id = p.id AND tip.tenant_id = p.tenant_id
        JOIN tests t
            ON tip.test_id = t.id
        LEFT JOIN results r
            ON r.test_id = t.id AND r.system_id = ? AND r.tenant_id = ?
            AND r.container_id = 0
        WHERE sig.system_id = ? AND sig.tenant_id = ?
        ORDER BY p.name, t.name
    "#)
    .bind(system_id)
    .bind(tenant_id)
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mut policy_map: BTreeMap<i32, PolicyResultGroup> = BTreeMap::new();
    for row in &raw {
        let policy_id: i32                     = row.get("policy_id");
        let policy_name: String                = row.get("policy_name");
        let policy_version: String             = row.get("policy_version");
        let policy_description: Option<String> = row.try_get("policy_description").ok();
        let test_id: Option<i64>               = row.try_get("test_id").ok();
        let test_name: String                  = row.get("test_name");
        let status_raw: String                 = row.get("status");
        let status = normalize_status(&status_raw).to_string();
        let is_excluded: bool = row.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0;

        let entry = policy_map.entry(policy_id).or_insert_with(|| PolicyResultGroup {
            policy_id,
            policy_name,
            policy_version,
            policy_description,
            results: Vec::new(),
            is_passed: false,
            pass_count: 0,
            fail_count: 0,
            na_count: 0,
            excluded_count: 0,
        });

        // Excluded findings are treated as NA — they don't bump pass or fail counts.
        if is_excluded {
            entry.excluded_count += 1;
        } else {
            match status.as_str() {
                "PASS"                       => entry.pass_count += 1,
                "FAIL"                       => entry.fail_count += 1,
                "NA" | "NOT_SCANNED"         => entry.na_count   += 1,
                _ => {}
            }
        }
        let evidence: Option<String> = row.try_get("evidence").ok().flatten();
        let excluded_reason: Option<String> = row.try_get("excluded_reason").ok().flatten();
        entry.results.push(IndividualResult {
            test_name,
            status,
            is_excluded,
            excluded_reason,
            // System report is read-only; no right-click menu, but show the badge.
            is_excludable: false,
            system_id: Some(system_id as i64),
            test_id,
            evidence,
        });
    }

    let mut policy_groups: Vec<PolicyResultGroup> = policy_map.into_values().collect();
    for p in &mut policy_groups {
        p.is_passed = is_system_passed(p.pass_count, p.fail_count);
    }

    let total_pass: usize = policy_groups.iter().map(|p| p.pass_count).sum();
    let total_fail: usize = policy_groups.iter().map(|p| p.fail_count).sum();

    // Mode-aware system score, computed live so it reflects the SYSTEM
    // compliance toggle immediately. "policy" → % of the system's policies it
    // fully passes (one failing policy → 0%); "test" → % of its tests passed.
    let smode = crate::policies::read_compliance_mode(pool, tenant_id, "system_compliance_mode").await;
    let units: Vec<(usize, usize)> = policy_groups.iter().map(|p| (p.pass_count, p.fail_count)).collect();
    let compliance_score = crate::policies::compliance_pct(smode == "policy", &units);
    // Excluded results are tallied alongside NA so the three counters add up
    // to total results without double-counting.
    let total_na: usize = policy_groups.iter()
        .flat_map(|p| p.results.iter())
        .filter(|r| r.is_excluded || r.status == "NA" || r.status == "NOT_SCANNED")
        .count();

    let last_seen: Option<String> = sys_row
        .try_get::<String, _>("last_seen")
        .ok()
        .map(|s| {
            s.parse::<DateTime<Utc>>()
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or(s)
        });

    // Per-container results on this host (separate axis), grouped per container.
    // Reuses the policy report's assembler; a DB hiccup degrades to host-only.
    let container_rows = sqlx::query(r#"
        SELECT s.name AS system_name, c.id AS container_id, c.name AS container_name,
               c.runtime AS runtime, c.image AS image, c.compliance_score AS cscore,
               t.name AS test_name, r.result AS status, r.excluded AS is_excluded,
               r.evidence AS evidence, r.system_id AS system_id, r.test_id AS test_id
        FROM results r
        JOIN systems s    ON r.system_id    = s.id AND r.tenant_id = s.tenant_id
        JOIN tests t      ON r.test_id      = t.id AND r.tenant_id = t.tenant_id
        JOIN containers c ON r.container_id = c.id AND r.tenant_id = c.tenant_id
        WHERE r.tenant_id = ? AND r.system_id = ? AND r.container_id > 0
        ORDER BY c.name, t.name
    "#)
    .bind(tenant_id).bind(system_id).fetch_all(pool).await
    .unwrap_or_else(|e| {
        error!("Failed to fetch container results for system {}: {}", system_id, e);
        Vec::new()
    });
    let containers = crate::policies::assemble_container_groups(container_rows)
        .into_values().next().unwrap_or_default();

    Ok(SystemReportData {
        system_id:        sys_row.get("id"),
        system_name:      sys_row.get("name"),
        os:               sys_row.get::<Option<String>, _>("os").unwrap_or_default(),
        arch:             sys_row.get("arch"),
        ip:               sys_row.get("ip"),
        compliance_score,
        last_seen,
        policy_groups,
        total_pass,
        total_fail,
        total_na,
        containers,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/report/{id}
// Render the live compliance report for a single system.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let mut report = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(r) => r,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch system report data");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Live system report — enable the right-click Exclude / Unexclude menu.
    // fetch_system_report_data marks rows non-excludable so save / PDF / archive
    // paths freeze the badge; we override that here for the interactive page only.
    for policy in &mut report.policy_groups {
        for r in &mut policy.results {
            r.is_excludable = true;
        }
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

    // Pull live test metadata so the template can pop a detail modal when a
    // test row is clicked (mirrors the policy-report UX). Looked up by name
    // in the template; tests deleted/renamed since this report was rendered
    // simply fall through to plain text — no link.
    let tests_metadata = fetch_tenant_tests_metadata(&auth.tenant_id, &pool).await;

    // Trend for this system (mode-aware, ?range= bucketed; empty → card hidden).
    let smode = crate::policies::read_compliance_mode(&pool, &auth.tenant_id, "system_compliance_mode").await;
    let trend_range = crate::policies::normalize_trend_range(query.range.as_deref());
    let (trend_labels, trend_scores, trend_passed, trend_failed) =
        crate::policies::fetch_entity_trend(&pool, &auth.tenant_id, "system", id as i64, smode == "policy", trend_range).await;

    let mut context = Context::new();
    context.insert("report", &report);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    context.insert("is_smtp_configured", &crate::reports::is_smtp_configured(&pool).await);
    context.insert("tests_metadata", &tests_metadata);
    context.insert("trend_labels", &trend_labels);
    context.insert("trend_scores", &trend_scores);
    context.insert("trend_passed", &trend_passed);
    context.insert("trend_failed", &trend_failed);
    context.insert("trend_range", &trend_range);
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    render_template(&tera, Some(&pool), "systems_report.html", context, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/{id}/containers/{cid}
// Container detail panel: identity, configuration metadata, and recent
// per-container test results (the container's own compliance axis).
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn container_detail(
    auth: AuthSession,
    Path((system_id, container_id)): Path<(i64, i64)>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Container row scoped to tenant + host so one tenant can't read another's.
    let row = match sqlx::query(r#"
        SELECT c.*, s.name AS host_name
        FROM containers c
        JOIN systems s ON c.host_system_id = s.id AND c.tenant_id = s.tenant_id
        WHERE c.id = ? AND c.host_system_id = ? AND c.tenant_id = ?
    "#)
    .bind(container_id).bind(system_id).bind(&auth.tenant_id)
    .fetch_optional(&*pool).await
    {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/systems?error_message=Container+not+found").into_response(),
        Err(e) => {
            error!(error = ?e, container_id, "Failed to fetch container detail");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Recent per-container results joined to test names.
    let result_rows = sqlx::query(r#"
        SELECT t.id AS test_id, t.name AS test_name, r.result AS status,
               r.excluded AS is_excluded, r.excluded_reason AS excluded_reason,
               r.evidence AS evidence
        FROM results r
        JOIN tests t ON r.test_id = t.id AND r.tenant_id = t.tenant_id
        WHERE r.container_id = ? AND r.tenant_id = ?
        ORDER BY t.name
    "#)
    .bind(container_id).bind(&auth.tenant_id)
    .fetch_all(&*pool).await
    .unwrap_or_else(|e| {
        error!("Failed to fetch results for container {}: {}", container_id, e);
        Vec::new()
    });

    let results: Vec<IndividualResult> = result_rows.iter().map(|rr| IndividualResult {
        test_name: rr.get("test_name"),
        status: normalize_status(&rr.get::<String, _>("status")).to_string(),
        is_excluded: rr.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0,
        excluded_reason: rr.try_get("excluded_reason").ok().flatten(),
        is_excludable: false,
        system_id: Some(system_id),
        test_id: rr.try_get("test_id").ok(),
        evidence: rr.try_get("evidence").ok().flatten(),
    }).collect();

    let pass = results.iter().filter(|r| !r.is_excluded && r.status == "PASS").count();
    let fail = results.iter().filter(|r| !r.is_excluded && r.status == "FAIL").count();
    let na   = results.iter().filter(|r| !r.is_excluded && r.status == "NA").count();

    let opt_i = |k: &str| row.try_get::<i64, _>(k).ok();
    let container = serde_json::json!({
        "id":             container_id,
        "host_system_id": system_id,
        "host_name":      row.get::<Option<String>, _>("host_name"),
        "name":           row.get::<Option<String>, _>("name"),
        "runtime":        row.get::<Option<String>, _>("runtime"),
        "runtime_id":     row.get::<Option<String>, _>("runtime_id"),
        "image":          row.get::<Option<String>, _>("image"),
        "image_digest":   row.get::<Option<String>, _>("image_digest"),
        "status":         row.get::<Option<String>, _>("status"),
        "ip":             row.get::<Option<String>, _>("ip"),
        "is_privileged":  opt_i("is_privileged"),
        "run_user":       row.get::<Option<String>, _>("run_user"),
        "network_mode":   row.get::<Option<String>, _>("network_mode"),
        "exposed_ports":  row.get::<Option<String>, _>("exposed_ports"),
        "mounts":         row.get::<Option<String>, _>("mounts"),
        "read_only_fs":   opt_i("read_only_fs"),
        "restart_policy": row.get::<Option<String>, _>("restart_policy"),
        "health_check":   opt_i("health_check"),
        // Round defensively: values stored before the ROUND-at-source fix
        // (or by an older binary) may carry full float precision.
        "compliance_score": (row.try_get::<f64, _>("compliance_score").unwrap_or(-1.0) * 100.0).round() / 100.0,
        "first_seen":     row.get::<Option<String>, _>("first_seen"),
        "last_seen":      row.get::<Option<String>, _>("last_seen"),
        "pass_count":     pass,
        "fail_count":     fail,
        "na_count":       na,
    });

    let mut context = Context::new();
    context.insert("container", &container);
    context.insert("results", &results);
    render_template(&tera, Some(&pool), "container_detail.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{system_id}/run/{policy_id}
// Queue a re-scan of ONE policy on ONE system — the "Run" button on each
// policy card in the system report, for re-checking a host after fixing a
// finding without rescanning the fleet.
//
// Scans are queued, not pushed: the rows land in `commands` and the agent
// picks them up on its next heartbeat, so the flash says so rather than
// implying the report refreshes immediately. A zero-row result means the
// policy doesn't cover this system (see execute_policy_run_for_system) and is
// reported as such instead of a misleading success.
// Role: Runner
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_run_policy(
    auth: AuthSession,
    Path((system_id, policy_id)): Path<(i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    let back = format!("/systems/report/{}", system_id);
    match crate::policies::execute_policy_run_for_system(
        policy_id, system_id, &pool, &auth.tenant_id,
    ).await {
        Ok(0) => {
            warn!(
                "Run requested by '{}' for policy={} on system={}, but the policy does not cover it.",
                auth.username, policy_id, system_id
            );
            let msg = urlencoding::encode(
                "Nothing queued — this policy does not apply to this system.").to_string();
            Redirect::to(&format!("{}?error_message={}", back, msg)).into_response()
        }
        Ok(n) => {
            info!(
                "Policy {} queued for system {} by '{}' ({} test(s)).",
                policy_id, system_id, auth.username, n
            );
            crate::audit::record(
                &pool, &auth.tenant_id,
                Some(&auth), Some(ip.as_str()),
                "policy.run_on_system",
                Some("system"), Some(&system_id.to_string()),
                Some(&format!("{{\"policy_id\":{},\"tests_queued\":{}}}", policy_id, n)),
            ).await;
            let msg = urlencoding::encode(&format!(
                "{} test(s) queued for this system. Results will appear after the agent's next check-in.", n
            )).to_string();
            Redirect::to(&format!("{}?success_message={}", back, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to queue policy {} for system {}: {}", policy_id, system_id, e);
            let msg = urlencoding::encode("Failed to queue the scan.").to_string();
            Redirect::to(&format!("{}?error_message={}", back, msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{system_id}/exclude/{test_id}
// Same effect as the policy-report exclude: flips the `excluded` flag on the
// matching `results` row. Distinct endpoint so the redirect lands back on the
// system report instead of a policy report.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
// Helper: exclusion_reason
// Pulls `reason` out of a urlencoded body and normalises it.
//
// Uses RawForm rather than Form<T> because these handlers already take Path
// and several Extensions, and a typed Form must be the final extractor; RawForm
// keeps the signatures free to grow. An absent or blank reason becomes None
// rather than Some(""), so "no reason recorded" stays distinguishable from a
// reason that is genuinely empty.
//
// Capped at 500 characters: this is an audit note, not a document, and an
// unbounded field reachable by any Editor is a cheap way to bloat the database.
// ─────────────────────────────────────────────────────────────────────────────
pub fn exclusion_reason(body: &[u8]) -> Option<String> {
    let mut out: Option<String> = None;
    for pair in body.split(|b| *b == b'&') {
        let mut it = pair.splitn(2, |b| *b == b'=');
        let k = it.next().unwrap_or(&[]);
        if k != b"reason" {
            continue;
        }
        let v = it.next().unwrap_or(&[]);
        // application/x-www-form-urlencoded encodes spaces as '+'.
        let v: Vec<u8> = v.iter().map(|b| if *b == b'+' { b' ' } else { *b }).collect();
        let decoded = urlencoding::decode(&String::from_utf8_lossy(&v))
            .map(|c| c.into_owned())
            .unwrap_or_default();
        let trimmed = decoded.trim();
        if !trimmed.is_empty() {
            out = Some(trimmed.chars().take(500).collect());
        }
    }
    out
}


// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_exclude(
    auth: AuthSession,
    Path((system_id, test_id)): Path<(i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    RawForm(body): RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let reason = exclusion_reason(&body);

    let res = sqlx::query(
        "UPDATE results SET excluded = 1, excluded_by = ?, excluded_at = CURRENT_TIMESTAMP,
                            excluded_reason = ?
         WHERE tenant_id = ? AND system_id = ? AND test_id = ?",
    )
    .bind(&auth.username)
    .bind(&reason)
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(test_id)
    .execute(&pool)
    .await;

    let back = format!("/systems/report/{}", system_id);
    match res {
        Ok(_) => {
            info!(
                "Result excluded by '{}' from system view — system={} test={}",
                auth.username, system_id, test_id
            );
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
// POST /systems/report/{system_id}/unexclude/{test_id}
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_unexclude(
    auth: AuthSession,
    Path((system_id, test_id)): Path<(i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let res = sqlx::query(
        "UPDATE results SET excluded = 0, excluded_by = NULL, excluded_at = NULL,
                            excluded_reason = NULL
         WHERE tenant_id = ? AND system_id = ? AND test_id = ?",
    )
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(test_id)
    .execute(&pool)
    .await;

    let back = format!("/systems/report/{}", system_id);
    match res {
        Ok(_) => {
            info!(
                "Result un-excluded by '{}' from system view — system={} test={}",
                auth.username, system_id, test_id
            );
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
// Helper: fetch_tenant_tests_metadata
// Pulls every test (name + description + rational + remediation) for the
// given tenant, used by the system-report views so the template can pop a
// detail modal when a test row is clicked. Returns an empty vec on DB error
// — the template just falls back to non-clickable test names. Also re-used
// by reports.rs::system_reports_view (archive flavour).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn fetch_tenant_tests_metadata(
    tenant_id: &str,
    pool: &SqlitePool,
) -> Vec<TestMeta> {
    let rows = sqlx::query(
        "SELECT name, description, rational, remediation
         FROM tests WHERE tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|row| TestMeta {
            name:        row.try_get::<String, _>("name").unwrap_or_default(),
            description: row.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default(),
            rational:    row.try_get::<Option<String>, _>("rational").ok().flatten().unwrap_or_default(),
            remediation: row.try_get::<Option<String>, _>("remediation").ok().flatten().unwrap_or_default(),
        })
        .collect()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/upgrade/{id}
// Queue an upgrade for a single active system. Inserts a row into commands
// with command_type='UPGRADE'; the next heartbeat from that agent dispatches
// the UPGRADE and deletes the row. The partial unique index makes a repeat
// click idempotent — second insert is silently ignored.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_upgrade(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Verify the system exists and is active before queueing.
    let is_active: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM systems WHERE id = ? AND tenant_id = ? AND status = 'active'",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    if is_active.is_none() {
        let msg = urlencoding::encode("System not found or not active.").to_string();
        return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
    }

    match sqlx::query(
        "INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type)
         VALUES (?, ?, NULL, 'UPGRADE')",
    )
    .bind(&auth.tenant_id)
    .bind(id)
    .execute(&pool)
    .await
    {
        Ok(_) => {
            info!("Upgrade queued for system ID {} by '{}'.", id, auth.username);
            crate::audit::record(
                &pool, &auth.tenant_id,
                Some(&auth), Some(ip.as_str()),
                "system.upgrade_queued",
                Some("system"), Some(&id.to_string()),
                None,
            ).await;
            let msg = urlencoding::encode("Upgrade queued — agent will upgrade on next check-in.").to_string();
            Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
        }
        Err(e) => {
            error!("Failed to queue upgrade for system {}: {}", id, e);
            let msg = urlencoding::encode(&format!("Error queuing upgrade: {}", e)).to_string();
            Redirect::to(&format!("/systems?error_message={}", msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/upgrade
// Queue upgrades for all selected active systems.
// Body: repeated `ids` form fields.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_upgrade(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    raw_form: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse::<i32>().ok())
        .collect();

    if ids.is_empty() {
        let msg = urlencoding::encode("No systems selected.").to_string();
        return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
    }

    // INSERT...SELECT FROM systems WHERE active in one query per id — same
    // result as a verify-then-insert but with half the round-trips.
    let mut queued: usize = 0;
    for id in &ids {
        match sqlx::query(
            "INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type)
             SELECT tenant_id, id, NULL, 'UPGRADE'
             FROM systems
             WHERE id = ? AND tenant_id = ? AND status = 'active'",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => queued += 1,
            Ok(_) => {}
            Err(e) => error!("Failed to queue upgrade for system {}: {}", id, e),
        }
    }

    info!(
        "Bulk upgrade queued for {}/{} system(s) by '{}'.",
        queued,
        ids.len(),
        auth.username
    );
    let id_list = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.upgrade_queued_bulk",
        Some("system"), Some(&format!("ids:{}", id_list)),
        Some(&format!("{{\"requested\":{},\"queued\":{}}}", ids.len(), queued)),
    ).await;
    let msg = urlencoding::encode(&format!(
        "Upgrade queued for {} system(s) — agents will upgrade on next check-in.",
        queued
    ))
    .to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/upgrade_all
// Queue an upgrade for every active system that has a newer agent_packages
// row available for its platform. One-click "upgrade the fleet" — same
// semver-aware availability check as the per-row buttons, but applied to the
// whole tenant in a single transaction.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_upgrade_all(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Fetch every active system's (id, ver, arch, os) so we can derive each
    // platform and compare against agent_packages by semver — same logic the
    // /systems page applies at render time when it decides whether to show
    // the per-row Upgrade button.
    let rows = match sqlx::query(
        "SELECT id,
                COALESCE(ver,  '') AS ver,
                COALESCE(arch, '') AS arch,
                COALESCE(os,   '') AS os
         FROM systems
         WHERE tenant_id = ? AND status = 'active'",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("upgrade_all: failed to fetch systems: {}", e);
            let msg = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
        }
    };

    let agent_pkgs: HashMap<String, AgentPackage> = sqlx::query_as::<_, AgentPackage>(
        "SELECT platform, version, sha256, url FROM agent_packages",
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|p| (p.platform.clone(), p))
    .collect();

    // Find every system whose bundled agent_packages row is strictly newer
    // (by semver) than the system's reported version. Systems on platforms
    // we don't ship binaries for are skipped silently.
    let mut targets: Vec<i64> = Vec::new();
    for row in &rows {
        let id:   i64    = row.try_get("id").unwrap_or(0);
        let ver:  String = row.try_get("ver").unwrap_or_default();
        let arch: String = row.try_get("arch").unwrap_or_default();
        let os:   String = row.try_get("os").unwrap_or_default();

        if arch.is_empty() || os.is_empty() || ver.is_empty() {
            continue;
        }
        let platform = crate::agents::derive_platform(&arch, &os);
        let pkg = match agent_pkgs.get(&platform) {
            Some(p) => p,
            None    => continue,
        };
        let current   = Version::parse(&ver).ok();
        let available = Version::parse(&pkg.version).ok();
        if let (Some(c), Some(a)) = (current, available) {
            if a > c {
                targets.push(id);
            }
        }
    }

    if targets.is_empty() {
        let msg = urlencoding::encode("No systems are eligible for upgrade.").to_string();
        return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
    }

    // Queue the UPGRADE row per system. INSERT OR IGNORE means a system that
    // already has an upgrade pending stays at one row, so re-clicking
    // "Upgrade All" is idempotent.
    let mut queued: usize = 0;
    for id in &targets {
        match sqlx::query(
            "INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type)
             VALUES (?, ?, NULL, 'UPGRADE')",
        )
        .bind(&auth.tenant_id)
        .bind(id)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => queued += 1,
            Ok(_) => {}  // already had a pending UPGRADE row
            Err(e) => error!("upgrade_all: queue failed for system {}: {}", id, e),
        }
    }

    info!(
        "Upgrade All queued for {}/{} eligible system(s) by '{}'.",
        queued,
        targets.len(),
        auth.username
    );
    let id_list = targets.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.upgrade_queued_all",
        Some("system"), Some(&format!("ids:{}", id_list)),
        Some(&format!(
            "{{\"eligible\":{},\"queued\":{}}}",
            targets.len(), queued
        )),
    ).await;
    let msg = urlencoding::encode(&format!(
        "Upgrade queued for {} system(s) — agents will upgrade on next check-in.",
        queued
    )).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}
