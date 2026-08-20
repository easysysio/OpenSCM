// =============================================================================
// auth.rs — login, logout, session cookie management, AuthSession extractor
//
// All routes are public (no prior auth required). Session cookies are signed
// with the server's Ed25519-derived cookie key; tampering is rejected by Axum.
// =============================================================================

use axum::response::{Html, Redirect, IntoResponse, Response};
use axum::extract::{FromRef, FromRequestParts, Query, Extension, Form};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar, Key};
use axum::http::request::Parts;
use axum::http::StatusCode;
use std::sync::Arc;
use std::future::Future;
use sqlx::SqlitePool;
use sqlx::Row;
use bcrypt::verify;
use serde::Deserialize;
use serde_json::{json, Value};
use tera::{Tera, Context};
use tracing::{info, warn, error};

use crate::handlers::{render_template, add_notification};
use crate::models::{UserRole, ErrorQuery, AuthSession};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: authorize
// Checks if the current role meets the required level.
// Returns None if authorized, or a Redirect to / if unauthorized.
// ─────────────────────────────────────────────────────────────────────────────
pub fn authorize(current_role: &str, required: UserRole) -> Option<Response> {
    let user_level = UserRole::from(current_role);
    
    if user_level >= required {
        None
    } else {
        warn!("Unauthorized access attempt: Required {:?}, User has {}", required, current_role);
        let msg = format!("Unauthorized+access.+{:?}+role+required.", required);
        Some(Redirect::to(&format!("/?error_message={}", msg)).into_response())
    }
}



// ─────────────────────────────────────────────────────────────────────────────
// Helper: AuthSession — FromRequestParts extractor
// Reads and validates the signed session cookie; rejects with a /login
// redirect if the cookie is absent, tampered, or missing required fields.
// ─────────────────────────────────────────────────────────────────────────────
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync + 'static,
    Key: FromRef<S>, 
{
    type Rejection = Redirect;

    fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        state: &'b S, 
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let key = Key::from_ref(state);

        async move {
            let jar = SignedCookieJar::from_headers(&parts.headers, key);

            if let Some(cookie) = jar.get("session") {
                if let Ok(session_json) = serde_json::from_str::<Value>(cookie.value()) {
                    if let (Some(username), Some(userid_str), Some(tenant_id), Some(role)) = (
                        session_json.get("username").and_then(|v| v.as_str()),
                        session_json.get("userid").and_then(|v| v.as_str()),
                        session_json.get("tenant_id").and_then(|v| v.as_str()),
                        session_json.get("role").and_then(|v| v.as_str()),
                    ) {
                        let userid = match userid_str.parse::<i32>() {
                             Ok(id) => id,
                            Err(_) => return Err(Redirect::to("/login")),
                        };
                       

                        // Impersonation (SaaS support tooling): when present,
                        // tenant_id above is already the TARGET tenant, so every
                        // query scopes there with no handler changes. The role is
                        // forced to "viewer" rather than trusted from the cookie,
                        // so a stale or tampered cookie cannot retain privileges
                        // inside someone else's tenant.
                        let impersonating = session_json
                            .get("impersonating")
                            .and_then(|v| {
                                Some(crate::models::Impersonation {
                                    real_tenant_id: v.get("real_tenant_id")?.as_str()?.to_string(),
                                    real_role:      v.get("real_role")?.as_str()?.to_string(),
                                })
                            });

                        let effective_role = if impersonating.is_some() {
                            "viewer".to_string()
                        } else {
                            role.to_string()
                        };

                        return Ok(AuthSession {
                            username: username.to_string(),
                            userid, 
                            tenant_id: tenant_id.to_string(),
                            role: effective_role,
                            impersonating,
                        });
                    }
                }
            }

            // If anything fails (no cookie, bad signature, missing fields), redirect to login
            Err(Redirect::to("/login"))
        }
    }
}


// --- 4. HANDLERS ---

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    /// Optional — if provided, scopes the user lookup to that tenant (SaaS).
    /// CE/EE leave this field absent; the query falls back to matching by username only.
    organization: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /login
// Render the login page, forwarding any error/success query params.
// Role: Public
// ─────────────────────────────────────────────────────────────────────────────
pub async fn login(Query(query): Query<ErrorQuery>, tera: Extension<Arc<Tera>>) -> Result<Html<String>, StatusCode> {
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    if let Some(success_message) = query.success_message {
        context.insert("success_message", &success_message);
    }
    render_template(&tera, None, "login.html", context, None).await
}



// ─────────────────────────────────────────────────────────────────────────────
// POST /login
// Validate credentials, create a signed session cookie, and redirect to /.
// Uses a constant-time bcrypt path to resist timing attacks on unknown users.
// Role: Public
// ─────────────────────────────────────────────────────────────────────────────
pub async fn login_submit(
    jar: SignedCookieJar,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    Form(form): Form<LoginForm>,
) -> (SignedCookieJar, Redirect) {

    // Guard against empty credentials
    if form.username.is_empty() || form.password.is_empty() {
        return (jar, Redirect::to("/login?error_message=Invalid%20Credentials"));
    }

    // If an organization was supplied, derive the tenant_id and verify it exists
    let tenant_id_filter: Option<String> = if let Some(org) = form.organization.as_deref() {
        let org = org.trim();
        if org.is_empty() {
            None
        } else {
            let tid = org.to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '-' })
                .collect::<String>()
                .trim_matches('-')
                .to_string();

            // Read the status too, not just existence. Suspension previously set
            // tenants.status and nothing ever read it, so a suspended tenant
            // could still log in and use the product normally — the admin
            // Suspend button did nothing. Dormant-account suspension depends on
            // this actually being enforced.
            let row: Option<(i64, String)> = sqlx::query_as(
                "SELECT COUNT(*), COALESCE(MAX(status), 'active') FROM tenants WHERE id = ?",
            )
            .bind(&tid)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();

            let (exists, status) = row.unwrap_or((0, "active".to_string()));

            if exists == 0 {
                warn!("Login attempt for unknown organization: '{}'", org);
                return (jar, Redirect::to("/login?error_message=Organization+not+found."));
            }

            if status == "suspended" {
                warn!("Login attempt for suspended organization: '{}'", org);
                return (jar, Redirect::to(
                    "/login?error_message=This+organization+is+suspended.+Please+contact+support."));
            }

            Some(tid)
        }
    } else {
        None
    };

    let row = match &tenant_id_filter {
        Some(tid) => sqlx::query(
            "SELECT password, username, id, tenant_id, role, directory_id, external_username
             FROM users WHERE username = ? AND tenant_id = ?",
        )
        .bind(&form.username)
        .bind(tid)
        .fetch_optional(&pool)
        .await,
        None => sqlx::query(
            "SELECT password, username, id, tenant_id, role, directory_id, external_username
             FROM users WHERE username = ?",
        )
        .bind(&form.username)
        .fetch_optional(&pool)
        .await,
    };

    // Timing attack protection — always run bcrypt regardless of whether user exists.
    // For LDAP-backed users we still run bcrypt against the dummy hash to keep the
    // timing profile similar (the actual auth result comes from the LDAP bind below).
    const DUMMY_HASH: &str = "$2b$12$invalidhashfortimingprotectionXXXXXXXXXXXXXXXXXXXXXX";

    let (hash_to_check, maybe_row) = match row {
        Ok(Some(row)) => {
            let hash = row.get("password");
            (hash, Some(row))
        },
        Ok(None) => {
            warn!("Login attempt for non-existent user: '{}'", form.username);
            (DUMMY_HASH.to_string(), None)
        },
        Err(e) => {
            error!("Database error during login: {}", e);
            (DUMMY_HASH.to_string(), None)
        },
    };

    // For LDAP-backed users we bypass the bcrypt result; for local users (or non-
    // existent users), bcrypt is the authority.
    let directory_id: Option<i64> = maybe_row.as_ref()
        .and_then(|r| r.try_get::<Option<i64>, _>("directory_id").ok().flatten());

    let bcrypt_valid = verify(&form.password, &hash_to_check).unwrap_or(false);

    let password_valid = if let Some(dir_id) = directory_id {
        // LDAP path — look up the directory, bind as user. Bcrypt result is ignored
        // (it was run only for timing parity).
        let _ = bcrypt_valid;
        let external_login = maybe_row.as_ref()
            .and_then(|r| r.try_get::<Option<String>, _>("external_username").ok().flatten())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| form.username.clone());
        match crate::directories::get_by_id(&pool, dir_id).await {
            Some(dir) => {
                let pw = form.password.clone();
                tokio::task::spawn_blocking(move || crate::directories::verify_user(&dir, &external_login, &pw))
                    .await
                    .unwrap_or(false)
            }
            None => {
                warn!("LDAP login for '{}' references missing directory id {}", form.username, dir_id);
                false
            }
        }
    } else {
        bcrypt_valid
    };

    if password_valid {
        if let Some(row) = maybe_row {
            let username: String = row.get("username");
            let userid: i32 = row.get("id");
            let role: String = row.get("role");

            let tenant_id = row.try_get::<String, _>("tenant_id")
                .unwrap_or_else(|_| "default".to_string());

            let session_data = json!({
                "username": username,
                "userid": userid.to_string(),
                "tenant_id": tenant_id,
                "role": role
                // no "impersonating" key: a fresh login is always the real tenant
            }).to_string();

            let mut cookie = Cookie::new("session", session_data);
            cookie.set_path("/");
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);
            cookie.set_max_age(time::Duration::hours(8));
            // M4: set_secure(true) is the correct production setting; kept false here so that
            // plain-HTTP deployments behind a reverse proxy continue to work.
            // Set this to true when the server is directly exposed over HTTPS.
            cookie.set_secure(false);

            info!("User '{}' logged in successfully for tenant '{}'", username, tenant_id);
            crate::audit::record_raw(
                &pool, &tenant_id,
                Some(userid), &username,
                Some(ip.as_str()),
                "auth.login_success",
                Some("user"), Some(&userid.to_string()),
                None,
            ).await;
            return (jar.add(cookie), Redirect::to("/"));
        }
    } else {
        warn!("Failed login attempt for user: '{}'", form.username);

        // If user exists but password was wrong, notify them
        if let Some(row) = maybe_row {
            let userid_raw: i32 = row.get("id");
            let tenant_id: String = row.try_get::<String, _>("tenant_id")
                .unwrap_or_else(|_| "default".to_string());

            add_notification(
                &pool,
                &tenant_id,
                "warning",
                userid_raw,
                &format!("Failed login attempt for user '{}'", form.username),
            ).await;

            crate::audit::record_raw(
                &pool, &tenant_id,
                Some(userid_raw), &form.username,
                Some(ip.as_str()),
                "auth.login_failure",
                Some("user"), Some(&userid_raw.to_string()),
                Some("bad_password"),
            ).await;
        } else {
            // No matching user — record the attempt against the default tenant
            // so platform admins can still see brute-force patterns.
            crate::audit::record_raw(
                &pool, "default",
                None, &form.username,
                Some(ip.as_str()),
                "auth.login_failure",
                Some("user"), None,
                Some("unknown_user"),
            ).await;
        }


    }

    (jar, Redirect::to("/login?error_message=Invalid%20Credentials"))
}




// ─────────────────────────────────────────────────────────────────────────────
// GET /logout
// Remove the session cookie and redirect to /login.
// Role: Viewer (any authenticated user)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn logout(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    jar: SignedCookieJar,
) -> (SignedCookieJar, Redirect) {
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "auth.logout",
        Some("user"), Some(&auth.userid.to_string()),
        None,
    ).await;
    (jar.remove(Cookie::from("session")), Redirect::to("/login"))
}

