// =============================================================================
// auto_groups_admin.rs — HTTP handlers for the auto-group rule editor
//
// Separates UI/handler glue from the pure-logic evaluator in `auto_groups.rs`.
// Routes added by lib.rs:
//
//   GET  /system_groups/auto/add               — render add form (Admin)
//   POST /system_groups/auto/add               — create auto group + rule
//   GET  /system_groups/auto/edit/{id}         — render edit form (Admin)
//   POST /system_groups/auto/edit/{id}         — update auto group + rule
//   POST /system_groups/auto/toggle/{id}       — enable / disable rule
//   POST /system_groups/auto/delete/{id}       — delete auto group + rule
//
// Group deletion of an auto group uses the existing /system_groups/delete/{id}
// path (FK CASCADE removes auto_group_rules) — no separate endpoint needed.
//
// All routes are Admin-gated (creating auto-grouping rules can move a system
// into a sensitive policy's scope; we don't want Editor-level users doing
// that without audit).  Tenant-scoped throughout.
// =============================================================================

use axum::extract::{RawForm, Extension, Path, Query};
use axum::response::{IntoResponse, Redirect};
use sqlx::{SqlitePool, Row};
use std::sync::Arc;
use tera::{Tera, Context};
use tracing::{info, warn, error};
use bytes::Bytes;

use crate::auth;
use crate::audit;
use crate::auto_groups;
use crate::handlers::{render_template, parse_form_data};
use crate::models::{AuthSession, ErrorQuery, UserRole};

// Maximum number of condition rows the click-based rule editor renders.
// Tests cap at 10 (see tests_add.html); auto-group rules rarely exceed 4-5
// in practice, so 8 leaves plenty of headroom without bloating the page.
const MAX_COND: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Helper — redirect_err
// Build a redirect back to /system_groups carrying a URL-encoded error.
// Keeps the verbose match arms readable across the handlers below.
// ─────────────────────────────────────────────────────────────────────────────
fn redirect_err(msg: impl AsRef<str>) -> axum::response::Response {
    let encoded = urlencoding::encode(msg.as_ref()).to_string();
    Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/auto/add
// Render the add-auto-group form. Conditions are entered as a JSON array;
// the template provides a help panel + live-validation hint, the server
// re-validates on POST.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn auto_add(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let mut ctx = Context::new();
    if let Some(msg) = query.error_message {
        ctx.insert("error_message", &msg);
    }
    // Click-based editor: empty rows. The template renders MAX_COND row
    // scaffolds, hidden by default, revealed one-by-one via "Add Condition".
    // No initial row data — the admin builds the rule from scratch with
    // dropdowns + a single value input per row.
    ctx.insert("conditions",   &Vec::<(String, String, String)>::new());
    ctx.insert("max_cond",     &MAX_COND);
    ctx.insert("row_ids",      &(1..=MAX_COND).collect::<Vec<usize>>());

    render_template(&tera, Some(&pool), "auto_groups_add.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/auto/add
// Create a new auto-managed group plus its 1:1 rule row, then run a full
// sweep so existing systems land in the new group on the next page load.
// All three writes (group, rule, sweep) happen in one transaction; if any
// step fails the whole operation rolls back.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn auto_add_save(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => return redirect_err(format!("Invalid form encoding: {}", e)),
    };
    let form = parse_form_data(&raw_string);

    let name = match form.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => return redirect_err("Group name is required"),
    };
    let description = form.get("description")
        .and_then(|v| v.first()).cloned().unwrap_or_default();

    // Assemble the conditions JSON from the click-editor form fields
    // (field_1, op_1, value_1, …). Validate up front so the rollback
    // path stays cheap in the common "incomplete row" case.
    let conditions_raw = match auto_groups::build_conditions_json_from_form(&form, MAX_COND) {
        Ok(s) => s,
        Err(e) => return redirect_err(format!("Rule conditions: {}", e)),
    };
    if let Err(e) = auto_groups::validate_conditions_json(&conditions_raw) {
        return redirect_err(format!("Invalid rule conditions: {}", e));
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return redirect_err(format!("Database error: {}", e)),
    };

    // 1. Insert the system_groups row with auto_managed = 1.
    if let Err(e) = sqlx::query(
        "INSERT INTO system_groups (tenant_id, name, description, auto_managed)
         VALUES (?, ?, ?, 1)"
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&description)
    .execute(&mut *tx)
    .await {
        let _ = tx.rollback().await;
        return redirect_err(format!("Could not create group: {}", e));
    }
    let group_id: i64 = match sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(&mut *tx).await
    {
        Ok(id) => id,
        Err(e) => { let _ = tx.rollback().await;
                    return redirect_err(format!("Database error: {}", e)); }
    };

    // 2. Insert the matching auto_group_rules row.
    if let Err(e) = sqlx::query(
        "INSERT INTO auto_group_rules
            (tenant_id, group_id, name, description, conditions, enabled)
         VALUES (?, ?, ?, ?, ?, 1)"
    )
    .bind(&auth.tenant_id)
    .bind(group_id)
    .bind(&name)
    .bind(&description)
    .bind(&conditions_raw)
    .execute(&mut *tx)
    .await {
        let _ = tx.rollback().await;
        return redirect_err(format!("Could not save rule: {}", e));
    }

    // 3. Commit group + rule before the full sweep (the sweep opens its
    //    own per-system transactions and must see the committed rule).
    if let Err(e) = tx.commit().await {
        return redirect_err(format!("Commit error: {}", e));
    }

    // 4. Full sweep — apply the new rule to every existing system.
    let changed = match auto_groups::apply_auto_groups_for_tenant(&pool, &auth.tenant_id).await {
        Ok(n) => n,
        Err(e) => {
            warn!("auto-groups: post-create sweep failed for tenant {}: {}",
                  auth.tenant_id, e);
            0
        }
    };

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), None,
        "auto_group_create",
        Some("auto_group"),
        Some(&group_id.to_string()),
        Some(serde_json::json!({"name": name, "initial_matches": changed})),
    ).await;

    info!("auto-group '{}' (id={}) created by '{}'; matched {} systems",
          name, group_id, auth.username, changed);
    Redirect::to("/system_groups").into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/auto/edit/{id}
// Render the edit form pre-populated with current name / description /
// conditions / enabled flag.  Existing matching systems are shown read-only
// so the admin can preview what the rule currently catches before editing.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn auto_edit(
    auth: AuthSession,
    Path(id): Path<i64>,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let row_opt = sqlx::query(
        "SELECT sg.id, sg.name, sg.description, sg.auto_managed,
                agr.id AS rule_id, agr.conditions, agr.enabled
         FROM system_groups sg
         LEFT JOIN auto_group_rules agr ON agr.group_id = sg.id
         WHERE sg.id = ? AND sg.tenant_id = ?"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_opt {
        Ok(Some(r)) => r,
        Ok(None)    => return Redirect::to("/system_groups?error_message=Group+not+found")
                              .into_response(),
        Err(e)      => { error!("DB error fetching auto group {}: {}", id, e);
                         return redirect_err("Database error"); }
    };

    let auto_managed: i64 = row.try_get("auto_managed").unwrap_or(0);
    if auto_managed != 1 {
        // Manual group — kick over to the regular editor.
        return Redirect::to(&format!("/system_groups/edit/{}", id)).into_response();
    }

    // Current matching systems (for preview).
    let matching_rows = sqlx::query(
        "SELECT s.id, s.name
         FROM systems_in_groups sig
         JOIN systems s ON s.id = sig.system_id
         WHERE sig.group_id = ? AND sig.tenant_id = ?
         ORDER BY s.name"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();
    let matching: Vec<String> = matching_rows.iter()
        .filter_map(|r| r.try_get::<String, _>("name").ok())
        .collect();

    // Explode the stored JSON conditions into per-row tuples for the
    // click editor.  Returns Vec<(field, operator, display_value)>.
    let conds_raw = row.try_get::<String, _>("conditions").unwrap_or_default();
    let conditions = auto_groups::explode_conditions_for_form(&conds_raw);

    let mut ctx = Context::new();
    if let Some(msg) = query.error_message {
        ctx.insert("error_message", &msg);
    }
    ctx.insert("group_id",    &id);
    ctx.insert("group_name",  &row.try_get::<String, _>("name").unwrap_or_default());
    ctx.insert("description", &row.try_get::<Option<String>, _>("description")
                                     .ok().flatten().unwrap_or_default());
    ctx.insert("conditions",  &conditions);
    ctx.insert("max_cond",    &MAX_COND);
    ctx.insert("row_ids",     &(1..=MAX_COND).collect::<Vec<usize>>());
    ctx.insert("enabled",     &(row.try_get::<i64, _>("enabled").unwrap_or(1) == 1));
    ctx.insert("matching",    &matching);

    render_template(&tera, Some(&pool), "auto_groups_edit.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/auto/edit/{id}
// Persist name / description / conditions / enabled, then run a full sweep
// so the new conditions take effect immediately for existing systems.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn auto_edit_save(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => return redirect_err(format!("Invalid form encoding: {}", e)),
    };
    let form = parse_form_data(&raw_string);

    let name = match form.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => return redirect_err("Group name is required"),
    };
    let description = form.get("description")
        .and_then(|v| v.first()).cloned().unwrap_or_default();
    // Checkboxes only appear in the form when checked.
    let enabled: i64 = if form.contains_key("enabled") { 1 } else { 0 };

    // Assemble + validate conditions from the click-editor form fields.
    let conditions_raw = match auto_groups::build_conditions_json_from_form(&form, MAX_COND) {
        Ok(s) => s,
        Err(e) => return Redirect::to(&format!(
            "/system_groups/auto/edit/{}?error_message={}",
            id, urlencoding::encode(&format!("Rule conditions: {}", e))
        )).into_response(),
    };
    if let Err(e) = auto_groups::validate_conditions_json(&conditions_raw) {
        return Redirect::to(&format!(
            "/system_groups/auto/edit/{}?error_message={}",
            id, urlencoding::encode(&format!("Invalid rule conditions: {}", e))
        )).into_response();
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return redirect_err(format!("Database error: {}", e)),
    };

    // Guard: only allow editing auto-managed groups via this handler.
    let am: i64 = sqlx::query_scalar(
        "SELECT auto_managed FROM system_groups WHERE id = ? AND tenant_id = ?"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .unwrap_or(None)
    .unwrap_or(0);
    if am != 1 {
        let _ = tx.rollback().await;
        return redirect_err("Not an auto-managed group");
    }

    if let Err(e) = sqlx::query(
        "UPDATE system_groups SET name = ?, description = ?
         WHERE id = ? AND tenant_id = ?"
    )
    .bind(&name).bind(&description)
    .bind(id).bind(&auth.tenant_id)
    .execute(&mut *tx).await {
        let _ = tx.rollback().await;
        return redirect_err(format!("Could not update group: {}", e));
    }

    if let Err(e) = sqlx::query(
        "UPDATE auto_group_rules
         SET name = ?, description = ?, conditions = ?, enabled = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE group_id = ? AND tenant_id = ?"
    )
    .bind(&name).bind(&description).bind(&conditions_raw).bind(enabled)
    .bind(id).bind(&auth.tenant_id)
    .execute(&mut *tx).await {
        let _ = tx.rollback().await;
        return redirect_err(format!("Could not update rule: {}", e));
    }

    if let Err(e) = tx.commit().await {
        return redirect_err(format!("Commit error: {}", e));
    }

    // Full sweep so the new rule shape takes effect immediately.
    let changed = match auto_groups::apply_auto_groups_for_tenant(&pool, &auth.tenant_id).await {
        Ok(n) => n,
        Err(e) => { warn!("auto-groups: post-edit sweep failed for tenant {}: {}",
                          auth.tenant_id, e); 0 }
    };

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), None,
        "auto_group_update",
        Some("auto_group"),
        Some(&id.to_string()),
        Some(serde_json::json!({"name": name, "enabled": enabled, "systems_reassigned": changed})),
    ).await;

    info!("auto-group id={} updated by '{}' (enabled={}); reassigned {} systems",
          id, auth.username, enabled, changed);
    Redirect::to("/system_groups").into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/auto/toggle/{id}
// Flip the rule's `enabled` flag and run a full sweep — disabling drops
// every matching system out of the group, enabling re-adds them. Same DB
// path as edit; separated out so the UI can offer it as a one-click button
// on the groups list.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn auto_toggle(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let result = sqlx::query(
        "UPDATE auto_group_rules
         SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
             updated_at = CURRENT_TIMESTAMP
         WHERE group_id = ? AND tenant_id = ?"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await;

    if let Err(e) = result {
        return redirect_err(format!("Could not toggle rule: {}", e));
    }

    let now_enabled: i64 = sqlx::query_scalar(
        "SELECT enabled FROM auto_group_rules WHERE group_id = ? AND tenant_id = ?"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(0);

    let changed = match auto_groups::apply_auto_groups_for_tenant(&pool, &auth.tenant_id).await {
        Ok(n) => n,
        Err(e) => { warn!("auto-groups: post-toggle sweep failed: {}", e); 0 }
    };

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), None,
        if now_enabled == 1 { "auto_group_enable" } else { "auto_group_disable" },
        Some("auto_group"),
        Some(&id.to_string()),
        Some(serde_json::json!({"systems_reassigned": changed})),
    ).await;

    info!("auto-group id={} toggled to enabled={} by '{}'; reassigned {} systems",
          id, now_enabled, auth.username, changed);
    Redirect::to("/system_groups").into_response()
}
