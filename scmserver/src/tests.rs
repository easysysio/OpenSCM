// =============================================================================
// tests.rs — compliance test CRUD, bulk actions
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
use std::collections::HashMap;
use urlencoding;
use tracing::{info, error};
use bytes::Bytes;

use crate::models::{ErrorQuery, Test, TestWithConditions, TestCondition, Element, SElement, Condition, UserRole, AuthSession};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ─────────────────────────────────────────────────────────────────────────────
// fetch_lookup_tables
// Load the elements, selements, and conditions reference tables used to
// populate test-condition form dropdowns.
// ─────────────────────────────────────────────────────────────────────────────
/// Server-side classification used only by the test-builder UI to group
/// container-related elements under their own `<optgroup>` in the Element
/// `<select>`. Purely cosmetic — does not affect dispatch, which is
/// uniform across every element (agent-side).
pub fn is_container_element(name: &str) -> bool {
    // CONTAINER is deliberately NOT in this set — it's a host-level attribute
    // ("does a container runtime exist on this host?") that lives in the same
    // mental category as PROCESS or SERVICE EXISTS. Only the per-container
    // elements (those that yield one result per container) go under the
    // Container <optgroup>.
    matches!(
        name.trim().to_uppercase().as_str(),
        "IMAGE" | "NETWORK" | "PRIVILEGED" | "RUN_USER"
            | "MOUNT" | "EXPOSED_PORT" | "READ_ONLY_FS" | "HEALTH_CHECK"
            // EXEC runs a command inside each container via `<runtime> exec` —
            // a per-container element, so it lives under the Container optgroup.
            | "EXEC"
    )
}

async fn fetch_lookup_tables(
    pool: &SqlitePool,
) -> Result<(Vec<Element>, Vec<SElement>, Vec<Condition>), sqlx::Error> {
    let element_rows = sqlx::query("SELECT id, name FROM elements")
        .fetch_all(pool).await?;
    let elements = element_rows.into_iter().map(|row| Element {
        id: row.get("id"), name: row.get("name"), description: None,
    }).collect();

    let selement_rows = sqlx::query("SELECT id, name FROM selements")
        .fetch_all(pool).await?;
    let selements = selement_rows.into_iter().map(|row| SElement {
        id: row.get("id"), name: row.get("name"), description: None,
    }).collect();

    let condition_rows = sqlx::query("SELECT id, name FROM conditions")
        .fetch_all(pool).await?;
    let conditions = condition_rows.into_iter().map(|row| Condition {
        id: row.get("id"), name: row.get("name"), description: None,
    }).collect();

    Ok((elements, selements, conditions))
}


// Test fields from the form: name, description, severity, rational,
// remediation, filter, app_filter.
type TestMetadata = (String, String, String, String, String, String, String);

// One condition row: element, input, selement, condition, sinput.
type ConditionRow = (String, String, String, Option<String>, Option<String>);

// ─────────────────────────────────────────────────────────────────────────────
// extract_test_metadata
// Pull name, description, severity, rational, remediation, filter, and
// app_filter from parsed form data; returns Err with a human-readable message
// if the required name field is missing.
// ─────────────────────────────────────────────────────────────────────────────
fn extract_test_metadata(
    form_data: &HashMap<String, Vec<String>>,
) -> Result<TestMetadata, String> {
    let name = form_data
        .get("name")
        .and_then(|v| v.first())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| "Test name is required.".to_string())?;

    let get = |key: &str| -> String {
        form_data.get(key).and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default()
    };

    Ok((
        name,
        get("description"),
        get("severity"),
        get("rational"),
        get("remediation"),
        get("filter"),
        get("app_filter"),
    ))
}


// ─────────────────────────────────────────────────────────────────────────────
// extract_fix_scripts
// The two optional fix scripts (shell, PowerShell) from the form. A blank box
// is NULL. Browsers send textarea lines ending in CRLF; /bin/sh would read
// the CR as part of each command, so line endings become LF.
// ─────────────────────────────────────────────────────────────────────────────
pub fn extract_fix_scripts(
    form_data: &HashMap<String, Vec<String>>,
) -> (Option<String>, Option<String>) {
    let get = |key: &str| -> Option<String> {
        form_data.get(key).and_then(|v| v.first())
            .map(|s| s.replace("\r\n", "\n").replace('\r', "\n"))
            .filter(|s| !s.trim().is_empty())
    };
    (get("fix_sh"), get("fix_ps"))
}


// ─────────────────────────────────────────────────────────────────────────────
// extract_conditions_from_form
// Parse up to `max` test-condition rows from form data; skips rows whose
// element field is blank or the placeholder "-- Select --".
// ─────────────────────────────────────────────────────────────────────────────
fn extract_conditions_from_form(
    form_data: &HashMap<String, Vec<String>>,
    max: usize,
) -> Vec<ConditionRow> {
    let mut result = Vec::new();
    for i in 1..=max {
        let element = form_data
            .get(&format!("element_{}", i))
            .and_then(|v| v.first())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if element.is_empty() || element == "-- Select --" {
            continue;
        }
        let input = form_data
            .get(&format!("input_{}", i))
            .and_then(|v| v.first()).cloned().unwrap_or_default();
        let selement = form_data
            .get(&format!("selement_{}", i))
            .and_then(|v| v.first())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "-- None --")
            .unwrap_or_else(|| "None".to_string());
        let condition = form_data
            .get(&format!("condition_{}", i))
            .and_then(|v| v.first()).cloned()
            .filter(|s| !s.is_empty() && s != "-- Select --");
        let sinput = form_data
            .get(&format!("sinput_{}", i))
            .and_then(|v| v.first()).cloned()
            .filter(|s| !s.is_empty());
        result.push((element, input, selement, condition, sinput));
    }
    result
}


// ─────────────────────────────────────────────────────────────────────────────
// build_tests_with_conditions
// Zip a flat test list with a pre-fetched flat conditions list into a
// TestWithConditions vec, separating condition vs. applicability rows.
// ─────────────────────────────────────────────────────────────────────────────
fn build_tests_with_conditions(
    tests: Vec<Test>,
    all_conditions: Vec<TestCondition>,
) -> Vec<TestWithConditions> {
    tests.into_iter().map(|t| {
        let test_id = t.id.unwrap_or(0) as i64;

        let conds: Vec<TestCondition> = all_conditions.iter()
            .filter(|c| c.test_id == test_id && c.r#type =="condition")
            .cloned().collect();

        let app: Vec<TestCondition> = all_conditions.iter()
            .filter(|c| c.test_id == test_id && c.r#type =="applicability")
            .cloned().collect();

        TestWithConditions {
            test: t,
            conditions: conds,
            applicability: if app.is_empty() { None } else { Some(app) },
        }
    }).collect()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /tests
// List all compliance tests with their conditions for the current tenant.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let tests_result = sqlx::query_as::<_, Test>(
        "SELECT id, name, description, severity, rational, remediation, filter, app_filter
         FROM tests WHERE tenant_id = ? ORDER BY name",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let tests: Vec<Test> = match tests_result {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch tests: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load tests.");
            context.insert("tests", &Vec::<TestWithConditions>::new());
            // tests.html also iterates `policies`; insert an empty list so the
            // error page renders instead of failing with "variable not found".
            context.insert("policies", &Vec::<(i64, String)>::new());
            return render_template(&tera, Some(&pool), "tests.html", context, Some(auth))
                .await.into_response();
        }
    };

    // Fetch all conditions for this tenant in one query
    let all_conditions = sqlx::query_as::<_, TestCondition>(
        "SELECT id, tenant_id, test_id, `type`, element, input, selement, condition, sinput
         FROM test_conditions WHERE tenant_id = ? ORDER BY test_id, id ASC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    let tests_with_conditions = build_tests_with_conditions(tests, all_conditions);

    let policies: Vec<(i64, String)> = sqlx::query(
        "SELECT id, name FROM policies WHERE tenant_id = ? ORDER BY name ASC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| (r.get("id"), r.get("name")))
    .collect();

    let mut context = Context::new();
    if let Some(msg) = query.error_message { context.insert("error_message", &msg); }
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    context.insert("policies", &policies);
    context.insert("tests", &tests_with_conditions);
    render_template(&tera, Some(&pool), "tests.html", context, Some(auth))
        .await.into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /tests/add
// Render the add-test form with element/selement/condition dropdowns.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_add(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut context = Context::new();

    match fetch_lookup_tables(&pool).await {
        Ok((elements, selements, conditions)) => {
            // Split into two lists so the template can render <optgroup>s.
            // The combined `elements` list stays for any code path that
            // doesn't want grouping.
            let (container_elements, host_elements): (Vec<_>, Vec<_>) =
                elements.iter().cloned()
                    .partition(|e| is_container_element(&e.name));
            context.insert("elements", &elements);
            context.insert("host_elements", &host_elements);
            context.insert("container_elements", &container_elements);
            context.insert("selements", &selements);
            context.insert("conditions", &conditions);
        }
        Err(e) => {
            error!("Failed to fetch lookup tables: {}", e);
            context.insert("error_message", "Failed to load form data.");
        }
    }

    render_template(&tera, Some(&pool), "tests_add.html", context, Some(auth))
        .await.into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /tests/add
// Persist a new test with its conditions and optional applicability rows.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_add_save(
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
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let (name, description, severity, rational, remediation, filter, app_filter) =
        match extract_test_metadata(&form_data) {
            Ok(fields) => fields,
            Err(msg) => {
                let encoded = urlencoding::encode(&msg).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
            }
        };

    let (fix_sh, fix_ps) = extract_fix_scripts(&form_data);

    let app_type = form_data.get("app_type")
        .and_then(|v| v.first()).map(|s| s.as_str()).unwrap_or("always");

    // Insert test (with auto-generated external_id for stable cross-system identity).
    let external_id = crate::schema::generate_external_id();
    let result = sqlx::query(
        "INSERT INTO tests (tenant_id, name, description, severity, rational, remediation, filter, app_filter, external_id, fix_sh, fix_ps)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name).bind(&description).bind(&severity)
    .bind(&rational).bind(&remediation).bind(&filter).bind(&app_filter)
    .bind(&external_id).bind(&fix_sh).bind(&fix_ps)
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        let encoded = urlencoding::encode(&format!("Database insert error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }
    let test_id: i64 = match sqlx::query_scalar("SELECT last_insert_rowid()")
        .fetch_one(&mut *tx)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    // Insert test conditions (up to 10)
    let conditions = extract_conditions_from_form(&form_data, 10);
    for (element, input, selement, condition, sinput) in &conditions {
        if let Err(e) = sqlx::query(
            "INSERT INTO test_conditions (tenant_id, test_id, `type`, element, input, selement, condition, sinput)
             VALUES (?, ?, 'condition', ?, ?, ?, ?, ?)",
        )
        .bind(&auth.tenant_id).bind(test_id)
        .bind(element).bind(input).bind(selement).bind(condition).bind(sinput)
        .execute(&mut *tx).await
        {
            let encoded = urlencoding::encode(&format!("Error saving condition: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    }

    // Insert applicability conditions if conditional
    if app_type == "conditional" {
        for i in 1..=3 {
            let element = form_data.get(&format!("app_element_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            if element.is_empty() || element == "-- Select --" { continue; }

            let input = form_data.get(&format!("app_input_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            let selement = form_data.get(&format!("app_selement_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            let condition = form_data.get(&format!("app_condition_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            let sinput = form_data.get(&format!("app_sinput_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();

            if let Err(e) = sqlx::query(
                "INSERT INTO test_conditions (tenant_id, test_id, `type`, element, input, selement, condition, sinput)
                 VALUES (?, ?, 'applicability', ?, ?, ?, ?, ?)",
            )
            .bind(&auth.tenant_id).bind(test_id)
            .bind(&element).bind(&input).bind(&selement).bind(&condition).bind(&sinput)
            .execute(&mut *tx).await
            {
                let encoded = urlencoding::encode(&format!("Error saving applicability condition: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    info!("Test '{}' created by '{}'.", name, auth.username);
    Redirect::to("/tests").into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /tests/delete/{id}
// Delete a test (cascades to its conditions); signals compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    // ON DELETE CASCADE handles test_conditions — no transaction needed
    if let Err(e) = sqlx::query("DELETE FROM tests WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id).execute(&pool).await
    {
        error!("Failed to delete test {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting test: {}", e)).to_string();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Test ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/tests").into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /tests/edit/{id}
// Render the edit form for an existing test with its current conditions.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let test = match sqlx::query_as::<_, Test>(
        "SELECT id, name, description, severity, rational, remediation, filter, app_filter
         FROM tests WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&*pool).await
    {
        Ok(Some(t)) => t,
        Ok(None) => return Redirect::to("/tests?error_message=Test+not+found").into_response(),
        Err(e) => {
            error!("Database error fetching test {}: {}", id, e);
            return Redirect::to("/tests?error_message=Database+error").into_response();
        }
    };

    // Fetch test conditions (type='condition'). On a DB error, log it and
    // degrade to an empty list rather than silently hiding the failure.
    let test_conds = sqlx::query_as::<_, TestCondition>(
        "SELECT id, tenant_id, test_id, `type`, element, input, selement, condition, sinput
         FROM test_conditions
         WHERE test_id = ? AND tenant_id = ? AND `type` = 'condition'
         ORDER BY id ASC LIMIT 10",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_all(&*pool).await
    .unwrap_or_else(|e| { error!("Failed to fetch conditions for test {}: {}", id, e); Vec::new() });

    // Fetch applicability conditions
    let app_conditions = sqlx::query_as::<_, TestCondition>(
        "SELECT id, tenant_id, test_id, `type`, element, input, selement, condition, sinput
         FROM test_conditions
         WHERE test_id = ? AND tenant_id = ? AND `type` = 'applicability'
         ORDER BY id ASC LIMIT 3",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_all(&*pool).await
    .unwrap_or_else(|e| { error!("Failed to fetch applicability for test {}: {}", id, e); Vec::new() });

    let mut context = Context::new();
    match fetch_lookup_tables(&pool).await {
        Ok((elements, selements, conditions)) => {
            // Split into two lists so the template can render <optgroup>s.
            // The combined `elements` list stays for any code path that
            // doesn't want grouping.
            let (container_elements, host_elements): (Vec<_>, Vec<_>) =
                elements.iter().cloned()
                    .partition(|e| is_container_element(&e.name));
            context.insert("elements", &elements);
            context.insert("host_elements", &host_elements);
            context.insert("container_elements", &container_elements);
            context.insert("selements", &selements);
            context.insert("conditions", &conditions);
        }
        Err(e) => {
            error!("Failed to fetch lookup tables for test edit {}: {}", id, e);
            context.insert("error_message", "Failed to load form data.");
        }
    }

    // Fix scripts are not on `Test`: that struct is also the agent's TEST
    // payload, and scripts must reach an agent only as a queued fix.
    let (fix_sh, fix_ps): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT fix_sh, fix_ps FROM tests WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_one(&*pool).await
    .unwrap_or_else(|e| {
        error!("Database error fetching fix scripts for test {}: {}", id, e);
        (None, None)
    });
    context.insert("fix_sh", &fix_sh.unwrap_or_default());
    context.insert("fix_ps", &fix_ps.unwrap_or_default());
    context.insert("test", &test);
    context.insert("test_conds", &test_conds);
    context.insert("app_conditions", &app_conditions);
    render_template(&tera, Some(&pool), "tests_edit.html", context, Some(auth))
        .await.into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /tests/edit/{id}
// Persist updated test metadata and conditions; signals compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_edit_save(
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
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let (name, description, severity, rational, remediation, filter, app_filter) =
        match extract_test_metadata(&form_data) {
            Ok(fields) => fields,
            Err(msg) => {
                let encoded = urlencoding::encode(&msg).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
            }
        };

    let (fix_sh, fix_ps) = extract_fix_scripts(&form_data);

    let app_type = form_data.get("app_type")
        .and_then(|v| v.first()).map(|s| s.as_str()).unwrap_or("always");

    // Update test metadata
    if let Err(e) = sqlx::query(
        "UPDATE tests SET name=?, description=?, severity=?, rational=?, remediation=?, filter=?, app_filter=?,
                          fix_sh=?, fix_ps=?
         WHERE id=? AND tenant_id=?",
    )
    .bind(&name).bind(&description).bind(&severity)
    .bind(&rational).bind(&remediation).bind(&filter).bind(&app_filter)
    .bind(&fix_sh).bind(&fix_ps)
    .bind(id).bind(&auth.tenant_id)
    .execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Error updating test: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    // Delete existing conditions (both types) and re-insert
    if let Err(e) = sqlx::query(
        "DELETE FROM test_conditions WHERE test_id = ? AND tenant_id = ?"
    )
    .bind(id).bind(&auth.tenant_id).execute(&mut *tx).await
    {
        let encoded = urlencoding::encode(&format!("Error clearing conditions: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    // Re-insert test conditions (up to 10)
    let conditions = extract_conditions_from_form(&form_data, 10);
    for (element, input, selement, condition, sinput) in &conditions {
        if let Err(e) = sqlx::query(
            "INSERT INTO test_conditions (tenant_id, test_id, `type`, element, input, selement, condition, sinput)
             VALUES (?, ?, 'condition', ?, ?, ?, ?, ?)",
        )
        .bind(&auth.tenant_id).bind(id)
        .bind(element).bind(input).bind(selement).bind(condition).bind(sinput)
        .execute(&mut *tx).await
        {
            let encoded = urlencoding::encode(&format!("Error saving condition: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    }

    // Re-insert applicability conditions if conditional
    if app_type == "conditional" {
        for i in 1..=3 {
            let element = form_data.get(&format!("app_element_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            if element.is_empty() || element == "-- Select --" { continue; }

            let input = form_data.get(&format!("app_input_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            let selement = form_data.get(&format!("app_selement_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            let condition = form_data.get(&format!("app_condition_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();
            let sinput = form_data.get(&format!("app_sinput_{}", i))
                .and_then(|v| v.first()).cloned().unwrap_or_default();

            if let Err(e) = sqlx::query(
                "INSERT INTO test_conditions (tenant_id, test_id, `type`, element, input, selement, condition, sinput)
                 VALUES (?, ?, 'applicability', ?, ?, ?, ?, ?)",
            )
            .bind(&auth.tenant_id).bind(id)
            .bind(&element).bind(&input).bind(&selement).bind(&condition).bind(&sinput)
            .execute(&mut *tx).await
            {
                let encoded = urlencoding::encode(&format!("Error saving applicability condition: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Test ID {} updated by '{}'.", id, auth.username);
    Redirect::to("/tests").into_response()
}




// ─────────────────────────────────────────────────────────────────────────────
// POST /tests/bulk/delete
// Delete multiple tests and signal a compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_bulk_delete(
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
        Err(_) => return Redirect::to("/tests?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i32> = form_data
        .get("ids").cloned().unwrap_or_default()
        .iter().filter_map(|s| s.parse().ok()).collect();

    if ids.is_empty() {
        return Redirect::to("/tests?error_message=No+tests+selected").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query("DELETE FROM tests WHERE id = ? AND tenant_id = ?")
            .bind(id).bind(&auth.tenant_id).execute(&pool).await
        {
            error!("Bulk delete: failed for test {}: {}", id, e);
        } else {
            deleted += 1;
        }
    }

    let _ = sync_tx.send(()).await;
    info!("Bulk deleted {} tests by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} test(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/tests?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /tests/bulk/add-policy
// Link multiple tests to a selected policy in one operation.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tests_bulk_add_policy(
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
        Err(_) => return Redirect::to("/tests?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);

    let policy_id: i32 = match form_data
        .get("policy_id").and_then(|v| v.first()).and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Redirect::to("/tests?error_message=No+policy+selected").into_response(),
    };

    let ids: Vec<i32> = form_data
        .get("ids").cloned().unwrap_or_default()
        .iter().filter_map(|s| s.parse().ok()).collect();

    if ids.is_empty() {
        return Redirect::to("/tests?error_message=No+tests+selected").into_response();
    }

    let policy_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(policy_id).bind(&auth.tenant_id)
    .fetch_one(&pool).await.unwrap_or(0i64) > 0;

    if !policy_exists {
        return Redirect::to("/tests?error_message=Invalid+policy").into_response();
    }

    let mut added = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query(
            "INSERT OR IGNORE INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES (?, ?, ?)",
        )
        .bind(&auth.tenant_id).bind(policy_id).bind(id).execute(&pool).await
        {
            error!("Bulk add policy: failed for test {}: {}", id, e);
        } else {
            added += 1;
        }
    }

    info!("Bulk added {} tests to policy {} by '{}'.", added, policy_id, auth.username);
    let msg = urlencoding::encode(&format!("{} test(s) added to policy.", added)).to_string();
    Redirect::to(&format!("/tests?success_message={}", msg)).into_response()
}
