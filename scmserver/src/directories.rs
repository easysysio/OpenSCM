// =============================================================================
// directories.rs — LDAP directory management
//
// Per-tenant configuration of external identity providers (LDAP servers in
// v1). Users with `users.directory_id` set authenticate by LDAP bind instead
// of the local bcrypt password. The bind password for the service account is
// stored in plaintext in the DB — protect the DB file accordingly.
// =============================================================================

use axum::extract::{Extension, Form, Path, Query};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tera::{Context, Tera};
use tracing::{error, info, warn};
use urlencoding;

use crate::auth;
use crate::handlers::{is_saas_mode, render_template};
use crate::models::{AuthSession, ErrorQuery, UserRole};

/// LDAP is intentionally disabled in SaaS mode — the server cannot reach
/// into a customer's internal network to talk to their LDAP server. Use
/// OIDC/SAML SSO (task #3) for SaaS-side identity federation instead.
/// Returns a redirect for HTML handlers; JSON handlers should check this
/// inline and return their own error shape.
fn saas_block_redirect() -> Redirect {
    Redirect::to("/?error_message=LDAP+directories+are+not+available+in+SaaS+mode")
}

// ============================================================
// Domain model
// ============================================================

#[derive(Debug, Serialize, Clone, sqlx::FromRow)]
pub struct Directory {
    pub id: i64,
    pub tenant_id: String,
    pub name: String,
    pub dir_type: String,
    pub host: String,
    pub port: i64,
    pub use_tls: i64,
    pub skip_tls_verify: i64,
    pub base_dn: String,
    pub bind_dn: String,
    #[serde(skip)]
    pub bind_password: String,
    pub user_attribute: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Deserialize)]
pub struct DirectoryForm {
    pub name: String,
    pub host: String,
    pub port: String,
    pub use_tls: Option<String>,
    pub skip_tls_verify: Option<String>,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_attribute: String,
}

// ============================================================
// LDAP — helper
// ============================================================

/// Open an LDAP connection honouring the directory's TLS settings.
fn ldap_connect(dir: &Directory) -> Result<LdapConn, String> {
    let scheme = if dir.use_tls != 0 { "ldaps" } else { "ldap" };
    let url = format!("{}://{}:{}", scheme, dir.host, dir.port);

    let mut settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10));
    if dir.use_tls != 0 && dir.skip_tls_verify != 0 {
        settings = settings.set_no_tls_verify(true);
    }

    LdapConn::with_settings(settings, &url)
        .map_err(|e| format!("Connection failed: {}", e))
}

/// Try to bind to the directory using the service-account bind_dn + password.
/// Returns Ok(()) on success, Err with a human-readable reason on failure.
pub fn test_bind(dir: &Directory) -> Result<(), String> {
    let mut ldap = ldap_connect(dir)?;
    let r = if dir.bind_dn.is_empty() {
        // Anonymous bind
        ldap.simple_bind("", "")
    } else {
        ldap.simple_bind(&dir.bind_dn, &dir.bind_password)
    };
    let _ = ldap.unbind();
    match r {
        Ok(resp) => {
            if resp.rc == 0 {
                Ok(())
            } else {
                Err(format!("LDAP bind rejected (rc={}, msg='{}')", resp.rc, resp.text))
            }
        }
        Err(e) => Err(format!("LDAP error: {}", e)),
    }
}

/// Verify a user's credentials against an LDAP directory.
///   1. Bind as the service account
///   2. Search for the user under base_dn by user_attribute
///   3. Re-bind as the user's DN with the submitted password
/// Returns true if all three succeed.
pub fn verify_user(dir: &Directory, login: &str, password: &str) -> bool {
    if password.is_empty() {
        // Anonymous-bind-on-empty-password is a well-known LDAP footgun.
        return false;
    }
    let mut ldap = match ldap_connect(dir) {
        Ok(l) => l,
        Err(e) => { warn!("LDAP connect failed for '{}': {}", dir.name, e); return false; }
    };

    let svc_bind = if dir.bind_dn.is_empty() {
        ldap.simple_bind("", "")
    } else {
        ldap.simple_bind(&dir.bind_dn, &dir.bind_password)
    };
    if let Err(e) = svc_bind {
        warn!("LDAP service bind failed for '{}': {}", dir.name, e);
        let _ = ldap.unbind();
        return false;
    }

    let filter = format!("({}={})", dir.user_attribute, ldap_escape(login));
    let search = ldap.search(&dir.base_dn, Scope::Subtree, &filter, vec!["dn"]);
    let entries = match search {
        Ok(res) => res.0,
        Err(e) => {
            warn!("LDAP search failed for '{}' on '{}': {}", login, dir.name, e);
            let _ = ldap.unbind();
            return false;
        }
    };

    let user_dn = entries.into_iter().next().map(|e| SearchEntry::construct(e).dn);
    let _ = ldap.unbind();
    let user_dn = match user_dn {
        Some(dn) if !dn.is_empty() => dn,
        _ => {
            warn!("LDAP user '{}' not found in '{}' under '{}'", login, dir.name, dir.base_dn);
            return false;
        }
    };

    // Re-open + re-bind as the user.
    let mut ldap2 = match ldap_connect(dir) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let r = ldap2.simple_bind(&user_dn, password);
    let _ = ldap2.unbind();
    match r {
        Ok(resp) if resp.rc == 0 => true,
        Ok(_) => false,
        Err(_) => false,
    }
}

/// Minimal RFC 4515 escape for an LDAP filter value.
fn ldap_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*'  => out.push_str("\\2a"),
            '('  => out.push_str("\\28"),
            ')'  => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            other => out.push(other),
        }
    }
    out
}

// ============================================================
// DB lookups — public to auth.rs
// ============================================================

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Option<Directory> {
    sqlx::query_as::<_, Directory>("SELECT * FROM directories WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(reveal)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: reveal
// The directory with its bind password decrypted, for code that binds with
// it. An unreadable password reads as empty, so the bind fails and says so.
// ─────────────────────────────────────────────────────────────────────────────
fn reveal(mut dir: Directory) -> Directory {
    dir.bind_password = crate::secrets::open_or_empty(crate::secrets::COL_BIND_PASSWORD, &dir.bind_password);
    dir
}

// ============================================================
// HTTP handlers
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/directories
// List configured directories for the caller's tenant.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_view(
    auth: AuthSession,
    Query(q): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if is_saas_mode() { return saas_block_redirect().into_response(); }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir.into_response();
    }

    let rows = sqlx::query_as::<_, Directory>(
        "SELECT * FROM directories WHERE tenant_id = ? ORDER BY name ASC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    if let Some(m) = q.error_message { ctx.insert("error_message", &m); }
    if let Some(m) = q.success_message { ctx.insert("success_message", &m); }
    ctx.insert("directories", &rows);

    render_template(&tera, Some(&pool), "directories.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/directories/add — render the empty add form
// ─────────────────────────────────────────────────────────────────────────────
pub async fn add_form(
    auth: AuthSession,
    Query(q): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if is_saas_mode() { return saas_block_redirect().into_response(); }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir.into_response();
    }
    let mut ctx = Context::new();
    if let Some(m) = q.error_message { ctx.insert("error_message", &m); }
    ctx.insert("mode", "add");
    render_template(&tera, Some(&pool), "directories_form.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/directories/add
// ─────────────────────────────────────────────────────────────────────────────
pub async fn add_submit(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    Form(form): Form<DirectoryForm>,
) -> impl IntoResponse {
    if is_saas_mode() { return saas_block_redirect().into_response(); }
    if auth::authorize(&auth.role, UserRole::Admin).is_some() {
        return Redirect::to("/admin/directories?error_message=Access+denied").into_response();
    }
    let port: i64 = match form.port.parse() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => return Redirect::to("/admin/directories/add?error_message=Port+must+be+1-65535").into_response(),
    };
    if form.name.trim().is_empty() || form.host.trim().is_empty() || form.base_dn.trim().is_empty() {
        return Redirect::to("/admin/directories/add?error_message=Name%2C+host%2C+and+base+DN+are+required").into_response();
    }
    let use_tls = if form.use_tls.is_some() { 1i64 } else { 0 };
    let skip_verify = if form.skip_tls_verify.is_some() { 1i64 } else { 0 };

    let res = sqlx::query(
        "INSERT INTO directories
           (tenant_id, name, dir_type, host, port, use_tls, skip_tls_verify,
            base_dn, bind_dn, bind_password, user_attribute)
         VALUES (?, ?, 'ldap', ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(form.name.trim())
    .bind(form.host.trim())
    .bind(port)
    .bind(use_tls)
    .bind(skip_verify)
    .bind(form.base_dn.trim())
    .bind(form.bind_dn.trim())
    .bind(crate::secrets::seal(crate::secrets::COL_BIND_PASSWORD, &form.bind_password))
    .bind(if form.user_attribute.trim().is_empty() { "uid" } else { form.user_attribute.trim() })
    .execute(&pool)
    .await;

    match res {
        Ok(r) => {
            let new_id = r.last_insert_rowid();
            info!("Directory '{}' added by '{}'", form.name, auth.username);
            crate::audit::record(
                &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
                "directory.create",
                Some("directory"), Some(&new_id.to_string()),
                Some(serde_json::json!({"name": form.name})),
            ).await;
            Redirect::to("/admin/directories?success_message=Directory+added").into_response()
        }
        Err(e) => {
            error!("Directory insert failed: {}", e);
            let msg = urlencoding::encode(&format!("Add failed: {}", e)).to_string();
            Redirect::to(&format!("/admin/directories/add?error_message={}", msg)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/directories/edit/{id}
// ─────────────────────────────────────────────────────────────────────────────
pub async fn edit_form(
    auth: AuthSession,
    Path(id): Path<i64>,
    Query(q): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if is_saas_mode() { return saas_block_redirect().into_response(); }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir.into_response();
    }
    let dir = match sqlx::query_as::<_, Directory>(
        "SELECT * FROM directories WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&pool).await
    {
        Ok(Some(d)) => d,
        _ => return Redirect::to("/admin/directories?error_message=Not+found").into_response(),
    };

    let mut ctx = Context::new();
    if let Some(m) = q.error_message { ctx.insert("error_message", &m); }
    if let Some(m) = q.success_message { ctx.insert("success_message", &m); }
    ctx.insert("mode", "edit");
    ctx.insert("directory", &dir);
    // The password itself never goes back to the browser; the form only
    // says whether one is set, and a blank field keeps it.
    ctx.insert("has_bind_password", &!dir.bind_password.is_empty());

    render_template(&tera, Some(&pool), "directories_form.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/directories/edit/{id}
// ─────────────────────────────────────────────────────────────────────────────
pub async fn edit_submit(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    Form(form): Form<DirectoryForm>,
) -> impl IntoResponse {
    if is_saas_mode() { return saas_block_redirect().into_response(); }
    if auth::authorize(&auth.role, UserRole::Admin).is_some() {
        return Redirect::to("/admin/directories?error_message=Access+denied").into_response();
    }
    let port: i64 = match form.port.parse() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => return Redirect::to(&format!("/admin/directories/edit/{}?error_message=Port+must+be+1-65535", id)).into_response(),
    };
    if form.name.trim().is_empty() || form.host.trim().is_empty() || form.base_dn.trim().is_empty() {
        return Redirect::to(&format!("/admin/directories/edit/{}?error_message=Name%2C+host%2C+and+base+DN+are+required", id)).into_response();
    }
    let use_tls = if form.use_tls.is_some() { 1i64 } else { 0 };
    let skip_verify = if form.skip_tls_verify.is_some() { 1i64 } else { 0 };

    let res = sqlx::query(
        "UPDATE directories SET
            name=?, host=?, port=?, use_tls=?, skip_tls_verify=?,
            base_dn=?, bind_dn=?,
            bind_password = CASE WHEN ? = '' THEN bind_password ELSE ? END,
            user_attribute=?,
            updated_at=CURRENT_TIMESTAMP
         WHERE id=? AND tenant_id=?",
    )
    .bind(form.name.trim())
    .bind(form.host.trim())
    .bind(port)
    .bind(use_tls)
    .bind(skip_verify)
    .bind(form.base_dn.trim())
    .bind(form.bind_dn.trim())
    // Blank keeps the stored password (the edit form is never pre-filled).
    .bind(&form.bind_password)
    .bind(crate::secrets::seal(crate::secrets::COL_BIND_PASSWORD, &form.bind_password))
    .bind(if form.user_attribute.trim().is_empty() { "uid" } else { form.user_attribute.trim() })
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool).await;

    match res {
        Ok(_) => {
            crate::audit::record(
                &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
                "directory.update",
                Some("directory"), Some(&id.to_string()),
                None,
            ).await;
            Redirect::to("/admin/directories?success_message=Directory+updated").into_response()
        }
        Err(e) => {
            let msg = urlencoding::encode(&format!("Update failed: {}", e)).to_string();
            Redirect::to(&format!("/admin/directories/edit/{}?error_message={}", id, msg)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/directories/delete/{id} — refuses if any user references it
// ─────────────────────────────────────────────────────────────────────────────
pub async fn delete(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if is_saas_mode() { return saas_block_redirect().into_response(); }
    if auth::authorize(&auth.role, UserRole::Admin).is_some() {
        return Redirect::to("/admin/directories?error_message=Access+denied").into_response();
    }
    let in_use: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE directory_id = ?")
        .bind(id)
        .fetch_one(&pool).await.unwrap_or(0);
    if in_use > 0 {
        return Redirect::to(&format!(
            "/admin/directories?error_message={}+user(s)+still+linked+to+this+directory",
            in_use
        )).into_response();
    }

    let res = sqlx::query("DELETE FROM directories WHERE id = ? AND tenant_id = ?")
        .bind(id).bind(&auth.tenant_id)
        .execute(&pool).await;

    match res {
        Ok(_) => {
            crate::audit::record(
                &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
                "directory.delete",
                Some("directory"), Some(&id.to_string()),
                None,
            ).await;
            Redirect::to("/admin/directories?success_message=Directory+deleted").into_response()
        }
        Err(e) => {
            let msg = urlencoding::encode(&format!("Delete failed: {}", e)).to_string();
            Redirect::to(&format!("/admin/directories?error_message={}", msg)).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/directories/test/{id}
// Returns JSON {ok: bool, error: "..."}; spawned on a blocking thread because
// ldap3 is synchronous.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Serialize)]
pub struct TestResponse {
    pub ok: bool,
    pub error: Option<String>,
}

pub async fn test(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> Json<TestResponse> {
    if is_saas_mode() {
        return Json(TestResponse { ok: false, error: Some("LDAP directories are not available in SaaS mode".into()) });
    }
    if auth::authorize(&auth.role, UserRole::Admin).is_some() {
        return Json(TestResponse { ok: false, error: Some("Access denied".into()) });
    }
    let dir = match sqlx::query_as::<_, Directory>(
        "SELECT * FROM directories WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&pool).await
    {
        Ok(Some(d)) => reveal(d),
        _ => return Json(TestResponse { ok: false, error: Some("Directory not found".into()) }),
    };

    let dir_clone = dir.clone();
    let result = tokio::task::spawn_blocking(move || test_bind(&dir_clone))
        .await
        .unwrap_or_else(|e| Err(format!("spawn_blocking failed: {}", e)));

    let (ok, err) = match result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };

    let details_json = err.as_ref().map(|e| serde_json::json!({"error": e}));
    crate::audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        if ok { "directory.test_success" } else { "directory.test_failure" },
        Some("directory"), Some(&id.to_string()),
        details_json,
    ).await;

    Json(TestResponse { ok, error: err })
}
