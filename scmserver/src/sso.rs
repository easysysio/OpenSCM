// =============================================================================
// sso.rs — single sign-on: the tenant's OpenID Connect provider
//
// One provider per tenant (sso_providers). This file holds its configuration:
// the admin page, saving, testing and disabling. Signing in through the
// provider is built on top of this.
//
// Configuring a provider is Admin work: it holds a client secret, and it names
// a URL the server will fetch. That URL is tenant-supplied, so every request to
// it goes through net_guard (https, public addresses only, pinned, no
// redirects).
//
// SaaS ONLY in 0.10.0. The code is here, in the crate both editions share, but
// the routes answer only in SaaS mode (see `unavailable`). Community Edition
// has LDAP for directory sign-in; opening SSO to it later means removing that
// gate and adding its sign-in button. Withdrawing a feature people have
// configured is not possible in the same way, so it starts closed.
//
// Each handler is a thin entry point — edition, then role — around a function
// that takes the URL strictness as a parameter (save_provider, test_provider).
// In production that parameter is always "strict"; it exists so the logic can
// be tested against a provider on a local port.
//
// See docs/design/0.10.0-sso.md.
// =============================================================================

use axum::extract::{Extension, Query, RawForm};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use std::time::Duration;
use tera::{Context, Tera};
use tracing::{info, warn};

use crate::auth;
use crate::handlers::{is_saas_mode, parse_form_data, render_template, ClientIp};
use crate::models::{AuthSession, ErrorQuery, UserRole};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// A discovery document is a few kilobytes; anything much larger is not one.
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
/// The path the provider redirects back to after authenticating a user.
pub const CALLBACK_PATH: &str = "/auth/sso/callback";

// ─────────────────────────────────────────────────────────────────────────────
// Provider — a tenant's configured OpenID Connect provider
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize)]
pub struct Provider {
    pub id:         i64,
    pub tenant_id:  String,
    pub enabled:    bool,
    pub name:       String,
    pub issuer_url: String,
    pub client_id:  String,
    /// Use an email address from this provider for first-time matching even
    /// when the provider does not say it is verified. See sso_login::resolve_user.
    pub trust_email: bool,
    /// Never serialised: the secret must not reach a rendered page.
    #[serde(skip)]
    pub client_secret: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: load_provider
// The tenant's provider, if one is configured (enabled or not).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_provider(pool: &SqlitePool, tenant_id: &str) -> Option<Provider> {
    let r = sqlx::query(
        "SELECT id, tenant_id, enabled, name, issuer_url, client_id, client_secret, trust_email
           FROM sso_providers WHERE tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()??;
    Some(Provider {
        id:            r.try_get("id").ok()?,
        tenant_id:     r.try_get("tenant_id").ok()?,
        enabled:       r.try_get::<i64, _>("enabled").unwrap_or(0) != 0,
        name:          r.try_get("name").unwrap_or_default(),
        issuer_url:    r.try_get("issuer_url").unwrap_or_default(),
        client_id:     r.try_get("client_id").unwrap_or_default(),
        trust_email:   r.try_get::<i64, _>("trust_email").unwrap_or(0) != 0,
        // Unreadable reads as unset, so the admin page asks for it again.
        client_secret: crate::secrets::open_or_empty(
            crate::secrets::COL_SSO_SECRET,
            &r.try_get::<String, _>("client_secret").unwrap_or_default(),
        ),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: normalize_issuer
// An issuer is compared as an exact string, so it is stored in one form:
// trimmed, without a trailing slash.
// ─────────────────────────────────────────────────────────────────────────────
pub fn normalize_issuer(s: &str) -> String {
    s.trim().trim_end_matches('/').to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: redirect_uri
// The callback URL to register with the provider, built from the installation's
// App URL (a platform setting stored under the 'default' tenant). None when
// App URL is not set — the provider cannot send users back without it.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn redirect_uri(pool: &SqlitePool) -> Option<String> {
    let app_url: String = sqlx::query_scalar(
        "SELECT value FROM settings WHERE skey = 'app_url' AND tenant_id = 'default'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let base = app_url.trim().trim_end_matches('/');
    if base.is_empty() {
        None
    } else {
        Some(format!("{base}{CALLBACK_PATH}"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery — the parts of a provider's discovery document that are used
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// How the provider wants the client to authenticate at the token
    /// endpoint. Absent means client_secret_basic (OpenID Connect Discovery).
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// ID-token signature algorithms this server can verify — the asymmetric ones
/// jsonwebtoken implements on ring. Deliberately no HS* (a shared-secret
/// "signature" made with the client secret proves nothing about the provider)
/// and no "none".
pub const SUPPORTED_ALGS: [&str; 9] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

// ─────────────────────────────────────────────────────────────────────────────
// Helper: guarded_get
// GETs a tenant-supplied URL through net_guard and returns the body, capped.
// The DNS lookup inside check_url blocks, so it runs off the async threads.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) async fn guarded_get(url: &str, strict: bool, what: &'static str) -> Result<Vec<u8>, String> {
    let owned = url.to_string();
    let target = tokio::task::spawn_blocking(move || crate::net_guard::check_url(&owned, strict, what))
        .await
        .map_err(|e| format!("lookup failed: {e}"))??;
    let client = crate::net_guard::client_for(&target, HTTP_TIMEOUT)?;
    let mut resp = client
        .get(&target.url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                format!("{} did not answer within {} seconds", target.host, HTTP_TIMEOUT.as_secs())
            } else if e.is_connect() {
                format!("Could not connect to {}", target.host)
            } else {
                format!("Request to {} failed", target.host)
            }
        })?;
    if !resp.status().is_success() {
        return Err(format!("{} answered HTTP {}", target.host, resp.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| format!("Reading from {} failed", target.host))? {
        if body.len() + chunk.len() > MAX_DISCOVERY_BYTES {
            return Err(format!("{} sent an unexpectedly large reply", target.host));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: discover
// Fetches and checks a provider's discovery document
// (<issuer>/.well-known/openid-configuration).
//
//   • The document must name the SAME issuer it was fetched from. OpenID
//     Connect Discovery requires this; without it, a provider one tenant
//     controls could present itself as another issuer's.
//   • The endpoints it lists are themselves tenant-controlled addresses the
//     server (token, keys) or the browser (authorization) will be sent to, so
//     each is held to the same rules as the issuer URL.
//   • At least one signing algorithm must be one this server can verify, when
//     the document lists any.
//
// Err is a sentence fit to show the administrator.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn discover(issuer_url: &str, strict: bool) -> Result<Discovery, String> {
    let issuer = normalize_issuer(issuer_url);
    let url = format!("{issuer}/.well-known/openid-configuration");
    let body = guarded_get(&url, strict, "Issuer URL").await?;

    let doc: Discovery = serde_json::from_slice(&body).map_err(|_| {
        "The issuer did not return an OpenID Connect discovery document. \
         Check that the Issuer URL is the provider's issuer, not its sign-in page."
            .to_string()
    })?;

    if normalize_issuer(&doc.issuer) != issuer {
        return Err(format!(
            "The discovery document names a different issuer ({}). \
             The Issuer URL must match it exactly.",
            doc.issuer
        ));
    }

    for (what, endpoint) in [
        ("authorization endpoint", &doc.authorization_endpoint),
        ("token endpoint", &doc.token_endpoint),
        ("signing-key address", &doc.jwks_uri),
    ] {
        let e = endpoint.clone();
        tokio::task::spawn_blocking(move || crate::net_guard::check_url(&e, strict, "URL"))
            .await
            .map_err(|e| format!("lookup failed: {e}"))?
            .map_err(|e| format!("The provider's {what} is not acceptable: {e}"))?;
    }

    let algs = &doc.id_token_signing_alg_values_supported;
    if !algs.is_empty() && !algs.iter().any(|a| SUPPORTED_ALGS.contains(&a.as_str())) {
        return Err(format!(
            "The provider signs tokens with {}, which this server cannot verify.",
            algs.join(", ")
        ));
    }

    Ok(doc)
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery cache
//
// Signing in needs the provider's discovery document every time. Fetching it
// on every sign-in would be an outbound request per click of a public button,
// so a verified document is kept for CACHE_TTL. Saving a provider drops its
// entry, so a corrected configuration takes effect at once.
//
// Only the DOCUMENT is cached. The addresses in it are still checked by
// net_guard immediately before each request made to them.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) const CACHE_TTL: Duration = Duration::from_secs(600);

type DiscoveryCache = std::sync::Mutex<std::collections::HashMap<(String, bool), (std::time::Instant, Discovery)>>;
static DISCOVERY_CACHE: std::sync::LazyLock<DiscoveryCache> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

// ─────────────────────────────────────────────────────────────────────────────
// Public: discover_cached
// discover(), remembered for CACHE_TTL. Failures are not cached.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn discover_cached(issuer_url: &str, strict: bool) -> Result<Discovery, String> {
    let key = (normalize_issuer(issuer_url), strict);
    if let Ok(cache) = DISCOVERY_CACHE.lock() {
        if let Some((at, doc)) = cache.get(&key) {
            if at.elapsed() < CACHE_TTL {
                return Ok(doc.clone());
            }
        }
    }
    let doc = discover(issuer_url, strict).await?;
    if let Ok(mut cache) = DISCOVERY_CACHE.lock() {
        cache.insert(key, (std::time::Instant::now(), doc.clone()));
    }
    Ok(doc)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: forget_discovery
// Drops an issuer's cached document (both strictness variants).
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn forget_discovery(issuer_url: &str) {
    if let Ok(mut cache) = DISCOVERY_CACHE.lock() {
        let issuer = normalize_issuer(issuer_url);
        cache.retain(|(i, _), _| *i != issuer);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: back
// Redirect to the SSO page with a flash message.
// ─────────────────────────────────────────────────────────────────────────────
fn back(kind: &str, msg: &str) -> Response {
    Redirect::to(&format!("/admin/sso?{kind}_message={}", urlencoding::encode(msg))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: unavailable
// Single sign-on is offered in SaaS only (see the top of this file). In any
// other edition every route here answers with this, before looking at who is
// asking — the mirror image of how LDAP directories are closed in SaaS.
// ─────────────────────────────────────────────────────────────────────────────
fn unavailable() -> Option<Response> {
    if is_saas_mode() {
        None
    } else {
        Some(Redirect::to("/?error_message=Single+sign-on+is+not+available+in+this+edition").into_response())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/sso
// The provider configuration page.
// Role: Admin. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_page(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(r) = unavailable() {
        return r;
    }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let mut ctx = Context::new();
    if let Some(m) = query.error_message {
        ctx.insert("error_message", &m);
    }
    if let Some(m) = query.success_message {
        ctx.insert("success_message", &m);
    }
    if let Some(p) = load_provider(&pool, &auth.tenant_id).await {
        // Provider serialises without its secret; the page only learns that
        // one is stored.
        ctx.insert("has_secret", &!p.client_secret.is_empty());
        ctx.insert("provider", &p);
    }
    ctx.insert("redirect_uri", &redirect_uri(&pool).await);
    render_template(&tera, Some(&pool), "sso.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/sso/save
// Creates or updates the tenant's provider. See save_provider.
// Role: Admin. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
    raw: RawForm,
) -> impl IntoResponse {
    if let Some(r) = unavailable() {
        return r;
    }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let body = String::from_utf8_lossy(&raw.0).to_string();
    match save_provider(&pool, &auth, ip.as_str(), &body, true).await {
        Ok(msg) => back("success", msg),
        Err(msg) => back("error", &msg),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: save_provider
// Validates and stores the tenant's provider from a posted form body. Ok is the
// confirmation to show, Err the reason it was refused.
//
// A blank client secret means "leave it alone", not "clear it": the page never
// sends the stored value back, so an edit that does not retype it must not
// wipe it. Enabling requires that the provider can actually be reached and
// describes itself correctly — otherwise the sign-in page would offer a button
// that cannot work, to people who are not the one who mistyped the URL.
//
// `strict` selects the URL rules (see net_guard::check_url). The route always
// passes true. The caller has already checked the role.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn save_provider(
    pool: &SqlitePool,
    auth: &AuthSession,
    ip: &str,
    form_body: &str,
    strict: bool,
) -> Result<&'static str, String> {
    let form = parse_form_data(form_body);
    let get = |k: &str| form.get(k).and_then(|v| v.first()).map(|s| s.trim().to_string()).unwrap_or_default();

    let name = get("name");
    let issuer = normalize_issuer(&get("issuer_url"));
    let client_id = get("client_id");
    let new_secret = get("client_secret");
    let enabled = get("enabled") == "on";
    let trust_email = get("trust_email") == "on";

    if name.is_empty() || name.chars().count() > 100 {
        return Err("Give the provider a display name of up to 100 characters".into());
    }
    if client_id.is_empty() {
        return Err("The client ID is required".into());
    }
    let issuer_for_check = issuer.clone();
    tokio::task::spawn_blocking(move || crate::net_guard::check_url(&issuer_for_check, strict, "Issuer URL"))
        .await
        .map_err(|_| "The Issuer URL could not be checked".to_string())??;

    let existing = load_provider(pool, &auth.tenant_id).await;
    // A saved change must not be answered from a remembered document.
    forget_discovery(&issuer);
    if let Some(old) = &existing {
        forget_discovery(&old.issuer_url);
    }
    let secret = if !new_secret.is_empty() {
        new_secret
    } else {
        existing
            .as_ref()
            .map(|p| p.client_secret.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "The client secret is required".to_string())?
    };

    if enabled {
        // Without an App URL there is no callback address: the provider would
        // have nowhere to send a user back to, and sign-in could never finish.
        if redirect_uri(pool).await.is_none() {
            return Err("Not enabled — set the App URL (Settings → Email) first. \
                        It is the address your provider sends users back to.".into());
        }
        if let Err(e) = discover(&issuer, strict).await {
            return Err(format!(
                "Not enabled — the provider could not be verified. {e} Save it disabled, or correct it."
            ));
        }
    }

    sqlx::query(
        "INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret, trust_email)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id) DO UPDATE SET
             enabled = excluded.enabled, name = excluded.name, issuer_url = excluded.issuer_url,
             client_id = excluded.client_id, client_secret = excluded.client_secret,
             trust_email = excluded.trust_email,
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&auth.tenant_id)
    .bind(enabled)
    .bind(&name)
    .bind(&issuer)
    .bind(&client_id)
    .bind(crate::secrets::seal(crate::secrets::COL_SSO_SECRET, &secret))
    .bind(trust_email)
    .execute(pool)
    .await
    .map_err(|e| {
        warn!("Failed to save SSO provider for tenant '{}': {}", auth.tenant_id, e);
        "Could not save the provider".to_string()
    })?;

    info!("SSO provider saved for tenant '{}' by '{}' (enabled: {})", auth.tenant_id, auth.username, enabled);
    crate::audit::record(
        pool, &auth.tenant_id, Some(auth), Some(ip),
        "sso.provider_save", Some("sso_provider"), None,
        Some(serde_json::json!({ "issuer": issuer, "enabled": enabled, "trust_email": trust_email })),
    ).await;
    Ok(if enabled { "Provider saved and enabled" } else { "Provider saved (not enabled)" })
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/sso/test
// Contacts the saved provider and reports what it found. See test_provider.
// Role: Admin. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_test(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
    if let Some(r) = unavailable() {
        return r;
    }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    match test_provider(&pool, &auth, ip.as_str(), true).await {
        Ok(msg) => back("success", &msg),
        Err(msg) => back("error", &msg),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: test_provider
// Fetches the saved provider's discovery document and says what it found. A
// wrong issuer is otherwise invisible until someone cannot sign in — and that
// someone is not the person who typed it. Audited either way.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn test_provider(
    pool: &SqlitePool,
    auth: &AuthSession,
    ip: &str,
    strict: bool,
) -> Result<String, String> {
    let p = load_provider(pool, &auth.tenant_id)
        .await
        .ok_or_else(|| "Save a provider first".to_string())?;
    let result = discover(&p.issuer_url, strict).await;
    crate::audit::record(
        pool, &auth.tenant_id, Some(auth), Some(ip),
        if result.is_ok() { "sso.provider_test_success" } else { "sso.provider_test_failure" },
        Some("sso_provider"), Some(&p.id.to_string()),
        result.as_ref().err().map(|e| serde_json::json!({ "error": e })),
    ).await;
    let doc = result?;
    let host = |u: &str| reqwest::Url::parse(u).ok().and_then(|x| x.host_str().map(str::to_string)).unwrap_or_default();
    Ok(format!(
        "The provider answered and identifies itself as {}. Sign-in goes to {}; tokens come from {}.",
        doc.issuer, host(&doc.authorization_endpoint), host(&doc.token_endpoint)
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/sso/disable
// Turns single sign-on off for the tenant; the configuration is kept.
// Role: Admin. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_disable(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
    if let Some(r) = unavailable() {
        return r;
    }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let done = sqlx::query(
        "UPDATE sso_providers SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .execute(&*pool)
    .await;
    match done {
        Ok(r) if r.rows_affected() == 1 => {
            info!("SSO disabled for tenant '{}' by '{}'", auth.tenant_id, auth.username);
            crate::audit::record(
                &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
                "sso.provider_disable", Some("sso_provider"), None, None,
            ).await;
            back("success", "Single sign-on is disabled")
        }
        Ok(_) => back("error", "No provider is configured"),
        Err(_) => back("error", "Could not disable the provider"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /users/sso/unlink/{id}
// Clears a user's binding to their identity at the provider.
//
// The binding is made automatically, the first time someone signs in whose
// verified email matches the account. If that was the wrong person — a
// recycled address, a mistyped email on the account — this is how an admin
// undoes it without editing the database. The user's sessions end too, since
// one of them may be the wrong person's. Signing in with SSO again binds
// afresh, by the same rules.
//
// An admin unlinking THEIR OWN account keeps the browser they did it from:
// the session cookie is re-issued at the new epoch, as change_password does,
// so the other sessions end and this one does not.
// Role: Admin. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn user_unlink(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
    jar: axum_extra::extract::cookie::SignedCookieJar,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Response {
    if let Some(r) = unavailable() {
        return r;
    }
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let to = |kind: &str, msg: &str| {
        Redirect::to(&format!("/users/edit/{user_id}?{kind}_message={}", urlencoding::encode(msg))).into_response()
    };
    let done = sqlx::query(
        "UPDATE users SET sso_subject = NULL WHERE id = ? AND tenant_id = ? AND sso_subject IS NOT NULL",
    )
    .bind(user_id)
    .bind(&auth.tenant_id)
    .execute(&*pool)
    .await;
    match done {
        Ok(r) if r.rows_affected() == 1 => {
            auth::revoke_sessions(&pool, user_id).await;
            info!("SSO identity unlinked from user {} in tenant '{}' by '{}'", user_id, auth.tenant_id, auth.username);
            crate::audit::record(
                &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
                "sso.user_unlink", Some("user"), Some(&user_id.to_string()), None,
            ).await;
            if user_id == auth.userid as i64 && auth.impersonating.is_none() {
                let session = serde_json::json!({
                    "username": auth.username,
                    "userid": auth.userid.to_string(),
                    "tenant_id": auth.tenant_id,
                    "role": auth.role,
                });
                let cookie = auth::issue_session_cookie(&pool, session, auth::SESSION_TTL).await;
                return (
                    jar.add(cookie),
                    to("success", "Single sign-on identity unlinked. Your other sessions have been signed out."),
                ).into_response();
            }
            to("success", "Single sign-on identity unlinked. The user has been signed out.")
        }
        Ok(_) => to("error", "This user is not linked to a single sign-on identity"),
        Err(_) => to("error", "Could not unlink the user"),
    }
}
