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
// Helper: dummy_hash
// A real bcrypt hash to verify against when the username does not exist, so an
// unknown user costs the same as a wrong password.
//
// This used to be a hand-written constant one character short of a valid
// bcrypt string. bcrypt::verify rejected it while parsing, before hashing
// anything, so unknown usernames were answered in microseconds and real ones
// in ~250 ms: a clean username-enumeration oracle behind a comment claiming
// the opposite. It is generated at the same cost as stored passwords
// (DEFAULT_COST) and forced when the router is built, so the first unknown
// login does not pay for it either.
// ─────────────────────────────────────────────────────────────────────────────
static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    bcrypt::hash("openscm-timing-parity", bcrypt::DEFAULT_COST).unwrap_or_default()
});

pub fn dummy_hash() -> &'static str {
    DUMMY_HASH.as_str()
}

// ─────────────────────────────────────────────────────────────────────────────
// Session lifetime
// A normal login lasts SESSION_TTL; SaaS impersonation passes its own, shorter
// TTL to issue_session_cookie.
// ─────────────────────────────────────────────────────────────────────────────
pub const SESSION_TTL: time::Duration = time::Duration::hours(8);

// ─────────────────────────────────────────────────────────────────────────────
// Helper: issue_session_cookie
// The ONE place a session cookie is built — login here, impersonation start
// and exit in SaaS.
//
// Adds, inside the signed value:
//   • iat / exp — issue and expiry time. The cookie's Max-Age is only an
//     instruction to the browser; a copied cookie used to be accepted forever,
//     since nothing in the signed value said when it stopped being valid.
//   • epoch — the user's session_epoch at issue. validate_session compares it
//     with the current value, so bumping it ends every session the user holds.
//
// `session` must carry userid and tenant_id, and impersonating.real_tenant_id
// when present; the epoch is looked up in the user's real tenant.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn issue_session_cookie(
    pool: &SqlitePool,
    mut session: Value,
    ttl: time::Duration,
) -> Cookie<'static> {
    let userid = session.get("userid").and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let real_tenant = session.get("impersonating")
        .and_then(|i| i.get("real_tenant_id")).and_then(|v| v.as_str())
        .or_else(|| session.get("tenant_id").and_then(|v| v.as_str()))
        .unwrap_or("default").to_string();

    let epoch: i64 = sqlx::query_scalar(
        "SELECT session_epoch FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(userid).bind(&real_tenant)
    .fetch_optional(pool).await.ok().flatten().unwrap_or(0);

    let now = chrono::Utc::now().timestamp();
    if let Some(obj) = session.as_object_mut() {
        obj.insert("iat".into(), json!(now));
        obj.insert("exp".into(), json!(now + ttl.whole_seconds()));
        obj.insert("epoch".into(), json!(epoch));
    }

    let mut cookie = Cookie::new("session", session.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(ttl);
    cookie.set_secure(cookie_should_be_secure(pool).await);
    cookie
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: cookie_should_be_secure
// Secure is derived from the configured public URL rather than hardcoded. A
// session cookie without it travels in clear text, but forcing it on would
// silently break plain-HTTP deployments behind a terminating proxy, where the
// browser never sees HTTPS. app_url is what the operator has told us they are
// reachable on, so it is the one honest signal available.
//
// app_url is a platform setting stored under the 'default' tenant (see
// email.rs). This used to be looked up under the user's own tenant, which in
// SaaS never matched — so no tenant's session cookie was ever Secure.
// ─────────────────────────────────────────────────────────────────────────────
async fn cookie_should_be_secure(pool: &SqlitePool) -> bool {
    let secure = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE skey = 'app_url' AND tenant_id = 'default'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|u| u.trim().to_lowercase().starts_with("https://"))
    .unwrap_or(false);
    if !secure {
        warn!(
            "Session cookie issued without the Secure flag — app_url is not https. \
             Set it under Settings so sessions are not sent in clear text."
        );
    }
    secure
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: revoke_sessions
// Ends every session the user holds, on every device, by bumping the epoch
// that validate_session checks. Called on password change and reset. A caller
// that wants to keep the *current* browser signed in re-issues its cookie
// afterwards with issue_session_cookie.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn revoke_sessions(pool: &SqlitePool, user_id: i64) {
    if let Err(e) = sqlx::query("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await
    {
        error!("Failed to revoke sessions for user {}: {}", user_id, e);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: validate_session
// Turns a verified cookie value into an AuthSession, or None.
//
// The signature only proves the server issued the cookie at some point. What
// the cookie *says* — the role above all — was trusted for as long as the
// browser kept it, so deleting, demoting or re-passwording a user, or
// suspending their organization, changed nothing for a session already open.
// This checks the present state on every request instead: one primary-key
// lookup, joined to the tenant.
//
// Rejected: no exp/epoch (issued before 0.9.4), expired, user gone, epoch
// bumped, email unverified, organization suspended, or — while impersonating —
// the real user no longer a Superuser. The role is taken from the database.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn validate_session(pool: &SqlitePool, session: &Value) -> Option<AuthSession> {
    let userid: i32 = session.get("userid")?.as_str()?.parse().ok()?;
    let tenant_id = session.get("tenant_id")?.as_str()?.to_string();
    let exp = session.get("exp")?.as_i64()?;
    let epoch = session.get("epoch")?.as_i64()?;

    if chrono::Utc::now().timestamp() >= exp {
        return None;
    }

    // Impersonation (SaaS support tooling): tenant_id above is already the
    // TARGET tenant, so every query scopes there with no handler changes.
    // The user row lives in the real tenant.
    let real_tenant = session.get("impersonating")
        .and_then(|i| i.get("real_tenant_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let row = sqlx::query(
        "SELECT u.username, u.role, u.session_epoch, u.email_verified,
                COALESCE(t.status, 'active') AS tenant_status
           FROM users u
           LEFT JOIN tenants t ON t.id = u.tenant_id
          WHERE u.id = ? AND u.tenant_id = ?",
    )
    .bind(userid)
    .bind(real_tenant.as_deref().unwrap_or(&tenant_id))
    .fetch_optional(pool)
    .await
    .map_err(|e| error!("Session lookup failed: {}", e))
    .ok()??;

    let username: String = row.try_get("username").ok()?;
    let db_role: String = row.try_get("role").ok()?;
    let db_epoch: i64 = row.try_get("session_epoch").unwrap_or(0);
    let verified: i64 = row.try_get("email_verified").unwrap_or(1);
    let tenant_status: String = row.try_get("tenant_status").unwrap_or_default();

    if db_epoch != epoch || verified == 0 || tenant_status == "suspended" {
        return None;
    }

    let (role, impersonating) = match real_tenant {
        Some(real_tenant_id) => {
            // Impersonation is a Superuser capability; if the operator has
            // since lost that role, so has the session. Inside the target
            // tenant the role is always forced to viewer.
            if UserRole::from(db_role.as_str()) < UserRole::Superuser {
                return None;
            }
            (
                "viewer".to_string(),
                Some(crate::models::Impersonation { real_tenant_id, real_role: db_role }),
            )
        }
        None => (db_role, None),
    };

    Some(AuthSession { username, userid, tenant_id, role, impersonating })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: AuthSession — FromRequestParts extractor
// Verifies the cookie signature, then validate_session checks it against the
// database. Anything missing or refused redirects to /login.
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
        let jar = SignedCookieJar::from_headers(&parts.headers, key);
        let session = jar.get("session")
            .and_then(|c| serde_json::from_str::<Value>(c.value()).ok());
        let pool = parts.extensions.get::<SqlitePool>().cloned();

        async move {
            let (Some(session), Some(pool)) = (session, pool) else {
                return Err(Redirect::to("/login"));
            };
            validate_session(&pool, &session).await.ok_or(Redirect::to("/login"))
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

    // SaaS: the organization is required. Without it the lookup below falls
    // back to username alone across every tenant, which skipped the suspension
    // check entirely — the login form marks the field required, but only the
    // browser enforced that, and a direct POST simply left it out.
    if crate::handlers::is_saas_mode()
        && form.organization.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return (jar, Redirect::to("/login?error_message=Organization+is+required."));
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
            "SELECT password, username, id, tenant_id, role, directory_id, external_username,
                    email_verified
             FROM users WHERE username = ? AND tenant_id = ?",
        )
        .bind(&form.username)
        .bind(tid)
        .fetch_optional(&pool)
        .await,
        None => sqlx::query(
            "SELECT password, username, id, tenant_id, role, directory_id, external_username,
                    email_verified
             FROM users WHERE username = ?",
        )
        .bind(&form.username)
        .fetch_optional(&pool)
        .await,
    };

    // Timing attack protection — always run bcrypt regardless of whether user exists.
    // For LDAP-backed users we still run bcrypt against the dummy hash to keep the
    // timing profile similar (the actual auth result comes from the LDAP bind below).
    let (hash_to_check, maybe_row) = match row {
        Ok(Some(row)) => {
            let hash = row.get("password");
            (hash, Some(row))
        },
        Ok(None) => {
            warn!("Login attempt for non-existent user: '{}'", form.username);
            (dummy_hash().to_string(), None)
        },
        Err(e) => {
            error!("Database error during login: {}", e);
            (dummy_hash().to_string(), None)
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

            // Account state is checked only AFTER the password has been
            // verified, so these messages tell nothing to someone who does not
            // hold the password.
            //
            // Suspension is read from the matched user's OWN tenant rather than
            // from the organization typed into the form, so no way of reaching
            // this row can skip it.
            let tenant_status: String = sqlx::query_scalar(
                "SELECT COALESCE(status, 'active') FROM tenants WHERE id = ?",
            )
            .bind(&tenant_id)
            .fetch_optional(&pool).await.ok().flatten()
            .unwrap_or_else(|| "active".to_string());
            if tenant_status == "suspended" {
                warn!("Login refused for '{}': organization '{}' is suspended", username, tenant_id);
                crate::audit::record_raw(
                    &pool, &tenant_id, Some(userid), &username, Some(ip.as_str()),
                    "auth.login_failure", Some("user"), Some(&userid.to_string()),
                    Some("tenant_suspended"),
                ).await;
                return (jar, Redirect::to(
                    "/login?error_message=This+organization+is+suspended.+Please+contact+support."));
            }

            // SaaS self-registration creates the account unverified and sends a
            // confirmation link; the flag was written but never read, so the
            // account worked immediately. CE/EE users default to verified.
            let verified: i64 = row.try_get("email_verified").unwrap_or(1);
            if verified == 0 {
                info!("Login refused for '{}': email address not yet confirmed", username);
                crate::audit::record_raw(
                    &pool, &tenant_id, Some(userid), &username, Some(ip.as_str()),
                    "auth.login_failure", Some("user"), Some(&userid.to_string()),
                    Some("email_unverified"),
                ).await;
                return (jar, Redirect::to(
                    "/login?error_message=Please+confirm+your+email+address+first.+\
                     Check+your+inbox+for+the+link,+or+request+a+new+one+below."));
            }

            let session_data = json!({
                "username": username,
                "userid": userid.to_string(),
                "tenant_id": tenant_id,
                "role": role
                // no "impersonating" key: a fresh login is always the real tenant
            });
            let cookie = issue_session_cookie(&pool, session_data, SESSION_TTL).await;

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


#[cfg(test)]
mod tests {
    use super::*;

    // The dummy must be a hash bcrypt actually computes against, not one it
    // rejects while parsing — that early rejection is the timing leak.
    #[test]
    fn dummy_hash_is_a_real_bcrypt_hash() {
        let h = dummy_hash();
        assert_eq!(h.len(), 60, "bcrypt hashes are 60 characters");
        assert_eq!(verify("not-the-password", h).expect("verify must hash, not error"), false);
    }

    // And it must cost what a stored password costs, or the timing still differs.
    #[test]
    fn dummy_hash_uses_the_stored_password_cost() {
        assert!(dummy_hash().starts_with(&format!("$2b${:02}$", bcrypt::DEFAULT_COST)));
    }
}
