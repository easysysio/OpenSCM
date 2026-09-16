// =============================================================================
// groups.rs — system-group CRUD: list / add / edit / delete
//
// Split out of systems.rs when that file grew past ~1500 lines. Groups are
// purely about the `system_groups` table and its `systems_in_groups` join —
// bulk actions on systems themselves (including "add selected systems to a
// group") stay in systems.rs. Tenant-scoped throughout; Viewer for reads,
// Editor for writes.
// =============================================================================

use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::{SqlitePool, Row};
use std::sync::Arc;
use urlencoding;
use tracing::{info, warn, error};
use bytes::Bytes;

use crate::models::{
    ErrorQuery, System, SystemGroup, SystemInsideGroup, UserRole, AuthSession,
};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ─────────────────────────────────────────────────────────────────────────────
// Helper: load_system_groups
// Every group in a tenant, with its member names and member count.
// COUNT(DISTINCT s.id) rather than COUNT(*): the LEFT JOIN yields one row for
// an empty group, and that row must count as zero, not one.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_system_groups(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<SystemGroup>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT sg.id, sg.name, sg.description, sg.auto_managed,
            GROUP_CONCAT(s.name) AS systems,
            COUNT(DISTINCT s.id) AS system_count
         FROM system_groups AS sg
         LEFT JOIN systems_in_groups AS sig ON sg.id = sig.group_id
         LEFT JOIN systems AS s ON sig.system_id = s.id AND s.tenant_id = sg.tenant_id
         WHERE sg.tenant_id = ?
         GROUP BY sg.id, sg.name, sg.description, sg.auto_managed",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| SystemGroup {
            id: Some(row.get("id")),
            name: row.get("name"),
            description: row.try_get("description").ok(),
            systems: row.try_get("systems").ok(),
            auto_managed: row.try_get("auto_managed").unwrap_or(0),
            system_count: row.try_get("system_count").unwrap_or(0),
        })
        .collect())
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups
// List all system groups and their member systems for the current tenant.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let rows_result = load_system_groups(&pool, &auth.tenant_id).await;

    let system_groups: Vec<SystemGroup> = match rows_result {
        Ok(groups) => groups,
        Err(e) => {
            error!("Failed to fetch system groups: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load system groups.");
            context.insert("system_groups", &Vec::<SystemGroup>::new());
            return render_template(&tera, Some(&pool), "system_groups.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    context.insert("system_groups", &system_groups);
    render_template(&tera, Some(&pool), "system_groups.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/add
// Render the add-group form with available active systems.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_add(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let rows_result = sqlx::query(
        "SELECT id, name, status FROM systems WHERE status = 'active' AND tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems: Vec<System> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| System {
                id: row.get("id"),
                name: row.get("name"),
                ver: None,
                ip: None,
                os: None,
                arch: None,
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
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch systems for group add: {}", e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("systems", &systems);
    render_template(&tera, Some(&pool), "system_groups_add.html", context, Some(auth))
        .await
        .into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/add
// Create a new system group and associate the selected systems.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_add_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate name
    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => {
            return Redirect::to("/system_groups?error_message=Group+name+is+required").into_response();
        }
    };

    // --- FIX STARTS HERE ---
    // Instead of .filter(!s.is_empty()) which creates a None (NULL),
    // we use unwrap_or_default() to ensure we ALWAYS have a String.
    let description: String = form_data
        .get("description")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();
    // --- FIX ENDS HERE ---

    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    // The bind now sends a String (possibly "") instead of Option<String>
    if let Err(e) = sqlx::query(
        "INSERT INTO system_groups (tenant_id, name, description) VALUES (?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&description)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    let group_id: i64 = match sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(&mut *tx)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
        }
    };

    // Process systems association
    if let Some(system_ids) = systems {
        for system_id_str in system_ids {
            match system_id_str.parse::<i32>() {
                Ok(system_id) => {
                    if let Err(e) = sqlx::query(
                        "INSERT INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
                    )
                    .bind(system_id)
                    .bind(group_id)
                    .bind(&auth.tenant_id)
                    .execute(&mut *tx)
                    .await
                    {
                        let encoded = urlencoding::encode(&format!("Failed to add system: {}", e)).to_string();
                        tx.rollback().await.ok();
                        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
                    }
                }
                Err(_) => {
                    let encoded = urlencoding::encode(&format!("Invalid system ID: {}", system_id_str)).to_string();
                    tx.rollback().await.ok();
                    return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
                }
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    info!("System group '{}' created by '{}'.", name, auth.username);
    Redirect::to("/system_groups").into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/delete/{id}
// Delete a system group and clean up dangling results; signals compliance
// refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }


    // Before the DELETE FROM system_groups:
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
    .bind(&auth.tenant_id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to clean up results for deleted group {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }




    // Capture type + name before the DELETE so the audit row carries
    // meaningful identifiers (the row vanishes via CASCADE in a moment).
    let (was_auto, prior_name): (i64, Option<String>) =
        match sqlx::query("SELECT auto_managed, name FROM system_groups WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .fetch_optional(&pool)
            .await
        {
            Ok(Some(r)) => (r.try_get("auto_managed").unwrap_or(0),
                            r.try_get("name").ok()),
            _ => (0, None),
        };

    // ON DELETE CASCADE handles systems_in_groups AND auto_group_rules.
    if let Err(e) = sqlx::query(
        "DELETE FROM system_groups WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to delete system group {}: {}", id, e);
        let encoded =
            urlencoding::encode(&format!("Error deleting system group: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    // Audit — distinguish manual vs auto so the trail is searchable.
    crate::audit::record(
        &pool, &auth.tenant_id, Some(&auth), None,
        if was_auto == 1 { "auto_group_delete" } else { "group_delete" },
        Some(if was_auto == 1 { "auto_group" } else { "group" }),
        Some(&id.to_string()),
        prior_name.as_deref().map(|n| format!("name={:?}", n)).as_deref(),
    ).await;

    let _ = sync_tx.send(()).await;
    info!("System group ID {} ({}) deleted by '{}'. Compliance update signaled.",
          id, if was_auto == 1 { "auto" } else { "manual" }, auth.username);
    Redirect::to("/system_groups").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/edit/{id}
// Render the edit form for a system group with current membership.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT id, name, description, auto_managed FROM system_groups WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Redirect::to(
                "/system_groups?error_message=System+group+not+found",
            )
            .into_response();
        }
        Err(e) => {
            error!("Database error fetching group {}: {}", id, e);
            return Redirect::to("/system_groups?error_message=Database+error").into_response();
        }
    };

    // Auto groups are edited via the dedicated rule editor — the manual
    // edit form has no UI for the rule conditions and would silently strip
    // them on save. Redirect cleanly so an admin who clicked Edit on an
    // auto group lands in the right place.
    let auto_managed: i64 = row.try_get("auto_managed").unwrap_or(0);
    if auto_managed == 1 {
        return Redirect::to(&format!("/system_groups/auto/edit/{}", id)).into_response();
    }

    let group = SystemGroup {
        id: row.try_get("id").unwrap_or(None),
        name: row.get("name"),
        description: row.try_get("description").ok(),
        systems: None,
        ..Default::default()
    };

    let systems_result = sqlx::query(
        "SELECT id, name, status FROM systems WHERE status = 'active' AND tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems: Vec<System> = match systems_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| System {
                id: row.get("id"),
                name: row.get("name"),
                ver: None,
                ip: None,
                os: None,
                arch: None,
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
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch systems for group edit {}: {}", id, e);
            vec![]
        }
    };

    let sig_result = sqlx::query(
        "SELECT system_id, group_id FROM systems_in_groups WHERE group_id = ? AND tenant_id = ?",
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
            error!("Failed to fetch group memberships for group {}: {}", id, e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("group", &group);
    context.insert("systems", &systems);
    context.insert("systems_in_groups", &systems_in_groups);
    render_template(&tera, Some(&pool), "system_groups_edit.html", context, Some(auth))
        .await
        .into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/edit/{id}
// Persist name, description, and membership changes; signals compliance
// refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_edit_save(
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
            return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                .into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded =
                urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                .into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate name
    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => {
            return Redirect::to("/system_groups?error_message=Group+name+is+required")
                .into_response();
        }
    };

    // --- FIX: Ensure description is NEVER NULL ---
    // Removed .filter(|s| !s.is_empty()) so empty strings stay empty strings
    let description: String = form_data
        .get("description")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    // Update the group details
    if let Err(e) = sqlx::query(
        "UPDATE system_groups SET name = ?, description = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&description) // Binding the String directly
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error updating group: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    // Clear existing associations
    if let Err(e) = sqlx::query("DELETE FROM systems_in_groups WHERE group_id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await
    {
        let encoded =
            urlencoding::encode(&format!("Error clearing group members: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    // Re-add selected systems
    if let Some(system_ids) = systems {
        for system_id_str in system_ids {
            match system_id_str.parse::<i32>() {
                Ok(system_id) => {
                    if let Err(e) = sqlx::query(
                        "INSERT INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
                    )
                    .bind(system_id)
                    .bind(id)
                    .bind(&auth.tenant_id)
                    .execute(&mut *tx)
                    .await
                    {
                        let encoded =
                            urlencoding::encode(&format!("Error adding system to group: {}", e))
                                .to_string();
                        tx.rollback().await.ok();
                        return Redirect::to(&format!(
                            "/system_groups?error_message={}",
                            encoded
                        ))
                        .into_response();
                    }
                }
                Err(_) => {
                    warn!("Invalid system ID in form: {}", system_id_str);
                }
            }
        }
    }

    // Clean up results for tests no longer reachable
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
    .bind(&auth.tenant_id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("System group ID {} updated by '{}'.", id, auth.username);
    Redirect::to("/system_groups").into_response()
}
