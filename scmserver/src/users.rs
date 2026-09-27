// =============================================================================
// users.rs — user CRUD, role management, password change
//
// All routes are tenant-scoped. Admin role required for user management;
// users may edit their own profile (name, email, password) at any role.
// =============================================================================

use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path, Form};
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use tracing::{info, error};
use bytes::Bytes;
use bcrypt::{hash, DEFAULT_COST};
use serde::Deserialize;

use crate::models::{ErrorQuery, User, UserRole, AuthSession};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ─────────────────────────────────────────────────────────────────────────────
// GET /users
// List all users for the current tenant.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn users(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let rows_result = sqlx::query(
        "SELECT id, username, role, name, email FROM users WHERE tenant_id = ? ORDER BY username",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let users: Vec<User> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| User {
                id: row.get("id"),
                username: row.get("username"),
                role: row.get("role"),
                name: row.get("name"),
                email: row.get("email"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch users: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load users.");
            context.insert("users", &Vec::<User>::new());
            return render_template(&tera, Some(&pool), "users.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    context.insert("users", &users);
    render_template(&tera, Some(&pool), "users.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /users/add
// Render the add-user form.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn users_add(
    Query(query): Query<ErrorQuery>,
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }

    // Load configured directories for the Authentication Source dropdown.
    // Skipped in SaaS mode — LDAP is a CE/EE-only feature there (the SaaS
    // server can't reach into customer-internal networks; use OIDC/SAML SSO).
    let dirs = if crate::handlers::is_saas_mode() {
        Vec::new()
    } else {
        sqlx::query_as::<_, crate::directories::Directory>(
            "SELECT * FROM directories WHERE tenant_id = ? ORDER BY name ASC"
        )
        .bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await
        .unwrap_or_default()
    };
    context.insert("directories", &dirs);

    render_template(&tera, Some(&pool), "users_add.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /users/add
// Validate, hash password, and persist a new user for the current tenant.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn users_add_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let raw_string = match String::from_utf8(raw_form.0.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate required fields BEFORE opening a transaction
    let username = match form_data.get("username").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/users/add?error_message=Username+is+required").into_response(),
    };

    // Directory-backed user? If directory_id is set, the password lives in LDAP —
    // we don't validate or hash a password, and a placeholder is stored instead.
    let directory_id: Option<i64> = form_data
        .get("directory_id")
        .and_then(|v| v.first())
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| s.trim().parse().ok());

    let external_username: Option<String> = form_data
        .get("external_username")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let password = if directory_id.is_some() {
        // Placeholder — never used; bcrypt will not match it because it's not a valid hash.
        String::new()
    } else {
        match form_data.get("password").and_then(|v| v.first()).filter(|s| s.len() >= 8) {
            Some(v) => v.to_string(),
            None => return Redirect::to("/users/add?error_message=Password+must+be+at+least+8+characters").into_response(),
        }
    };

    let role_raw = match form_data.get("role").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/users/add?error_message=Role+is+required").into_response(),
    };
    // Validate against known roles to prevent arbitrary strings being stored
    let role = match role_raw.to_lowercase().as_str() {
        "superuser" | "admin" | "editor" | "runner" | "viewer" => role_raw,
        _ => return Redirect::to("/users/add?error_message=Invalid+role+selected").into_response(),
    };

    // Only a superuser may create another superuser
    if role.to_lowercase() == "superuser"
        && UserRole::from(auth.role.as_str()) < UserRole::Superuser
    {
        return Redirect::to("/users/add?error_message=Only+a+Superuser+can+assign+the+Superuser+role").into_response();
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let name = form_data
        .get("name")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let email = form_data
        .get("email")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Check if username already exists within this tenant
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND tenant_id = ?)",
    )
    .bind(&username)
    .bind(&auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);

    if exists {
        tx.rollback().await.ok();
        let encoded = urlencoding::encode(&format!("User '{}' already exists", username)).to_string();
        return Redirect::to(&format!("/users/add?error_message={}", encoded)).into_response();
    }

    // Hash password (placeholder used for directory-backed users).
    let password_hash = if directory_id.is_some() {
        // Sentinel string — never validates as bcrypt; LDAP bind is the auth path.
        "ldap:no-local-password".to_string()
    } else {
        match hash(&password, DEFAULT_COST) {
            Ok(h) => h,
            Err(e) => {
                let encoded = urlencoding::encode(&format!("Failed to hash password: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
            }
        }
    };

    // Insert with tenant_id
    if let Err(e) = sqlx::query(
        "INSERT INTO users (tenant_id, name, email, username, password, role, directory_id, external_username)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&email)
    .bind(&username)
    .bind(&password_hash)
    .bind(&role)
    .bind(directory_id)
    .bind(&external_username)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Failed to create user: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    info!("User '{}' created by '{}' (Tenant: {}).", username, auth.username, auth.tenant_id);
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "user.create",
        Some("user"), Some(&username),
        Some(&format!("{{\"role\":\"{}\"}}", role)),
    ).await;
    Redirect::to("/users").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /users/delete/{id}
// Delete a user account; self-deletion is blocked.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn users_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Prevent self-deletion
    if auth.userid == id {
        return Redirect::to("/users?error_message=You+cannot+delete+your+own+account").into_response();
    }

    // Single row delete — no transaction needed
    if let Err(e) = sqlx::query("DELETE FROM users WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&*pool)
        .await
    {
        error!("Failed to delete user {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting user: {}", e)).to_string();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    info!("User ID {} deleted by '{}' (Tenant: {}).", id, auth.username, auth.tenant_id);
    crate::audit::record(
        &*pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "user.delete",
        Some("user"), Some(&id.to_string()),
        None,
    ).await;
    Redirect::to("/users").into_response()
}


#[derive(serde::Deserialize)]
pub struct UserEditParams {
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /users/edit/{id}
// Render the edit form for a user; Admin can edit any user, others only self.
// Role: Viewer (self) / Admin (any)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn users_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(params): Query<UserEditParams>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    let current_role = UserRole::from(auth.role.as_str());
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid == id;

    if !is_admin && !is_owner {
        error!(
            attempted_by = %auth.username,
            user_id = %auth.userid,
            "Unauthorized user edit attempt"
        );
        return Redirect::to("/users?error_message=Unauthorized+edit+attempt").into_response();
    }

    let row_result = sqlx::query(
        "SELECT id, username, name, email, role FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/users?error_message=User+not+found").into_response(),
        Err(e) => {
            error!("Database error fetching user {}: {}", id, e);
            return Redirect::to("/users?error_message=Database+error").into_response();
        }
    };

    let user = User {
        id: row.try_get("id").unwrap_or(0),
        username: row.try_get("username").unwrap_or_default(),
        role: row.try_get("role").unwrap_or_default(),
        name: row.try_get("name").unwrap_or(None),
        email: row.try_get("email").unwrap_or(None),
    };

    let mut context = Context::new();
    if let Some(msg) = &params.error_message {
        context.insert("error_message", msg);
    }
    if let Some(msg) = &params.success_message {
        context.insert("success_message", msg);
    }
    context.insert("user", &user);
    // Bootstrap admin (id=1 in the default tenant) has a protected role — no one
    // can change it to prevent accidental lock-out of the primary account.
    let is_bootstrap = user.id == 1 && auth.tenant_id == "default";
    context.insert("is_bootstrap", &is_bootstrap);
    render_template(&tera, Some(&pool), "users_edit.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /users/edit/{id}
// Persist name, email, and (if Admin) role changes; bootstrap admin's role is
// immutable.
// Role: Viewer (self) / Admin (any)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn users_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    raw_form: RawForm,
) -> impl IntoResponse {

    let current_role = UserRole::from(auth.role.as_str());
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid == id;

    if !is_admin && !is_owner {
        error!(
            attempted_by = %auth.username,
            user_id = %auth.userid,
            "Unauthorized user edit attempt"
        );
        return Redirect::to("/users?error_message=Unauthorized+edit+attempt").into_response();
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded =
                urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let name = form_data
        .get("name")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let email = form_data
        .get("email")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Bootstrap admin (id=1, default tenant) has a permanently locked role.
    let is_bootstrap = id == 1 && auth.tenant_id == "default";

    // Only admins can change roles, and the bootstrap admin's role is never changed.
    let role = if is_bootstrap || !is_admin {
        // Fetch the current role from DB and keep it unchanged.
        match sqlx::query_scalar::<_, String>(
            "SELECT role FROM users WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(Some(r)) => r,
            _ => {
                tx.rollback().await.ok();
                return Redirect::to("/users?error_message=User+not+found").into_response();
            }
        }
    } else {
        match form_data.get("role").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
            Some(r) => r.to_string(),
            None => {
                tx.rollback().await.ok();
                return Redirect::to("/users?error_message=Role+is+required").into_response();
            }
        }
    };

    // Only a superuser may assign or change a role to superuser.
    if role.to_lowercase() == "superuser"
        && UserRole::from(auth.role.as_str()) < UserRole::Superuser
    {
        tx.rollback().await.ok();
        return Redirect::to(&format!(
            "/users/edit/{}?error_message=Only+a+Superuser+can+assign+the+Superuser+role",
            id
        ))
        .into_response();
    }

    if let Err(e) = sqlx::query(
        "UPDATE users SET name = ?, email = ?, role = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&email)
    .bind(&role)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error updating user: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    info!("User ID {} updated by '{}' (Tenant: {}).", id, auth.username, auth.tenant_id);
    // Record at the per-user-edit grain. Bootstrap edits can't change role
    // so action stays user.edit; for admins editing others with potentially
    // a role change we use a distinct action so auditors can filter cleanly.
    let action = if is_admin && !is_owner { "user.edit_by_admin" } else { "user.edit_self" };
    crate::audit::record(
        &*pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        action,
        Some("user"), Some(&id.to_string()),
        Some(&format!("{{\"new_role\":\"{}\"}}", role)),
    ).await;

    let target = if is_admin { "/users" } else { "/" };
    Redirect::to(&format!("{}?success_message=Settings+saved+successfully", target)).into_response()
}


#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub password1: String,
    pub password2: String,
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /users/password/{id}
// Validate, bcrypt-hash, and update a user's password; Admin or self only.
// Role: Viewer (self) / Admin (any)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn change_password(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    jar: axum_extra::extract::cookie::SignedCookieJar,
    Path(user_id): Path<i64>,
    Form(payload): Form<ChangePasswordForm>,
) -> axum::response::Response {

    let current_role = UserRole::from(auth.role.as_str());
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid as i64 == user_id;

    if !is_admin && !is_owner {
        return Redirect::to("/users?error_message=Access+Denied").into_response();
    }

    // Validate passwords match
    if payload.password1 != payload.password2 {
        let encoded = urlencoding::encode("Passwords do not match").to_string();
        return Redirect::to(&format!(
            "/users/edit/{}?error_message={}",
            user_id, encoded
        ))
        .into_response();
    }

    // Validate password length
    if payload.password1.len() < 8 {
        let encoded = urlencoding::encode("Password must be at least 8 characters").to_string();
        return Redirect::to(&format!(
            "/users/edit/{}?error_message={}",
            user_id, encoded
        ))
        .into_response();
    }

    let hashed_password = match hash(&payload.password1, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password for user {}: {}", user_id, e);
            let encoded = urlencoding::encode("Encryption error").to_string();
            return Redirect::to(&format!(
                "/users/edit/{}?error_message={}",
                user_id, encoded
            ))
            .into_response();
        }
    };

    // Update with tenant filter
    match sqlx::query(
        "UPDATE users SET password = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&hashed_password)
    .bind(user_id)
    .bind(&auth.tenant_id)
    .execute(&*pool)
    .await
    {
        Ok(res) if res.rows_affected() == 1 => {
            info!(
                "Password changed for user ID {} by '{}' (Tenant: {}).",
                user_id, auth.username, auth.tenant_id
            );

            // A password change must end the sessions it is meant to lock out
            // — a stolen cookie, or a device left signed in. Every session of
            // this user ends, on every device.
            auth::revoke_sessions(&pool, user_id).await;
            crate::audit::record(
                &pool, &auth.tenant_id,
                Some(&auth), Some(ip.as_str()),
                "user.password_change",
                Some("user"), Some(&user_id.to_string()),
                Some(if is_owner { "self" } else { "by_admin" }),
            ).await;

            let encoded = urlencoding::encode("Password updated successfully").to_string();
            let to = Redirect::to(&format!(
                "/users/edit/{}?success_message={}",
                user_id, encoded
            ));

            // Changing your own password should not sign you out of the
            // browser you did it from: re-issue this one cookie at the new
            // epoch, so only the *other* sessions end.
            if is_owner && auth.impersonating.is_none() {
                let session = serde_json::json!({
                    "username": auth.username,
                    "userid": auth.userid.to_string(),
                    "tenant_id": auth.tenant_id,
                    "role": auth.role,
                });
                let cookie = auth::issue_session_cookie(&pool, session, auth::SESSION_TTL).await;
                return (jar.add(cookie), to).into_response();
            }
            to.into_response()
        }
        Ok(_) => {
            Redirect::to("/users?error_message=User+not+found").into_response()
        }
        Err(e) => {
            error!("Failed to update password for user {}: {}", user_id, e);
            let encoded = urlencoding::encode("Database failure").to_string();
            Redirect::to(&format!(
                "/users/edit/{}?error_message={}",
                user_id, encoded
            ))
            .into_response()
        }
    }
}
