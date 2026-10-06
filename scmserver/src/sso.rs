// =============================================================================
// sso.rs — single sign-on: the tenant's OpenID Connect provider
//
// One provider per tenant (sso_providers). This file holds its configuration:
// the admin page, saving, testing and disabling. Signing in through the
// provider is built on top of this.
//
// Configuring a provider is Admin work: it holds a client secret, and it names
// a URL the server will fetch. That URL is tenant-supplied, so in SaaS every
// request to it goes through net_guard (https, public addresses only, pinned,
// no redirects); a self-hosted server may federate with an internal provider.
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
        "SELECT id, tenant_id, enabled, name, issuer_url, client_id, client_secret
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
        client_secret: r.try_get("client_secret").unwrap_or_default(),
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
}

/// ID-token signature algorithms this server can verify.
pub const SUPPORTED_ALGS: [&str; 10] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA", "ES256K",
];

// ─────────────────────────────────────────────────────────────────────────────
// Helper: guarded_get
// GETs a tenant-supplied URL through net_guard and returns the body, capped.
// The DNS lookup inside check_url blocks, so it runs off the async threads.
// ─────────────────────────────────────────────────────────────────────────────
async fn guarded_get(url: &str, strict: bool, what: &'static str) -> Result<Vec<u8>, String> {
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
// Helper: back
// Redirect to the SSO page with a flash message.
// ─────────────────────────────────────────────────────────────────────────────
fn back(kind: &str, msg: &str) -> Response {
    Redirect::to(&format!("/admin/sso?{kind}_message={}", urlencoding::encode(msg))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/sso
// The provider configuration page.
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_page(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
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
    ctx.insert("strict_urls", &is_saas_mode());
    render_template(&tera, Some(&pool), "sso.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/sso/save
// Creates or updates the tenant's provider.
//
// A blank client secret means "leave it alone", not "clear it": the page never
// sends the stored value back, so an edit that does not retype it must not
// wipe it. Enabling requires that the provider can actually be reached and
// describes itself correctly — otherwise the sign-in page would offer a button
// that cannot work, to people who are not the one who mistyped the URL.
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
    raw: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let body = String::from_utf8_lossy(&raw.0).to_string();
    let form = parse_form_data(&body);
    let get = |k: &str| form.get(k).and_then(|v| v.first()).map(|s| s.trim().to_string()).unwrap_or_default();

    let name = get("name");
    let issuer = normalize_issuer(&get("issuer_url"));
    let client_id = get("client_id");
    let new_secret = get("client_secret");
    let enabled = get("enabled") == "on";
    let strict = is_saas_mode();

    if name.is_empty() || name.chars().count() > 100 {
        return back("error", "Give the provider a display name of up to 100 characters");
    }
    if client_id.is_empty() {
        return back("error", "The client ID is required");
    }
    let issuer_for_check = issuer.clone();
    let checked = tokio::task::spawn_blocking(move || {
        crate::net_guard::check_url(&issuer_for_check, strict, "Issuer URL")
    })
    .await;
    match checked {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return back("error", &e),
        Err(_) => return back("error", "The Issuer URL could not be checked"),
    }

    let existing = load_provider(&pool, &auth.tenant_id).await;
    let secret = if !new_secret.is_empty() {
        new_secret
    } else {
        match existing.as_ref().map(|p| p.client_secret.clone()).filter(|s| !s.is_empty()) {
            Some(kept) => kept,
            None => return back("error", "The client secret is required"),
        }
    };

    if enabled {
        // Without an App URL there is no callback address: the provider would
        // have nowhere to send a user back to, and sign-in could never finish.
        if redirect_uri(&pool).await.is_none() {
            return back(
                "error",
                "Not enabled — set the App URL (Settings → Email) first. It is the address your provider sends users back to.",
            );
        }
        if let Err(e) = discover(&issuer, strict).await {
            return back(
                "error",
                &format!("Not enabled — the provider could not be verified. {e} Save it disabled, or correct it."),
            );
        }
    }

    let saved = sqlx::query(
        "INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id) DO UPDATE SET
             enabled = excluded.enabled, name = excluded.name, issuer_url = excluded.issuer_url,
             client_id = excluded.client_id, client_secret = excluded.client_secret,
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&auth.tenant_id)
    .bind(enabled)
    .bind(&name)
    .bind(&issuer)
    .bind(&client_id)
    .bind(&secret)
    .execute(&*pool)
    .await;
    if let Err(e) = saved {
        warn!("Failed to save SSO provider for tenant '{}': {}", auth.tenant_id, e);
        return back("error", "Could not save the provider");
    }

    info!("SSO provider saved for tenant '{}' by '{}' (enabled: {})", auth.tenant_id, auth.username, enabled);
    crate::audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        "sso.provider_save", Some("sso_provider"), None,
        Some(&serde_json::json!({ "issuer": issuer, "enabled": enabled }).to_string()),
    ).await;
    back("success", if enabled { "Provider saved and enabled" } else { "Provider saved (not enabled)" })
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/sso/test
// Fetches the saved provider's discovery document and reports what it found.
// A wrong issuer is otherwise invisible until someone cannot sign in — and
// that someone is not the person who typed it.
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_test(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let Some(p) = load_provider(&pool, &auth.tenant_id).await else {
        return back("error", "Save a provider first");
    };
    let result = discover(&p.issuer_url, is_saas_mode()).await;
    crate::audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        if result.is_ok() { "sso.provider_test_success" } else { "sso.provider_test_failure" },
        Some("sso_provider"), Some(&p.id.to_string()),
        result.as_ref().err().map(|e| serde_json::json!({ "error": e }).to_string()).as_deref(),
    ).await;
    match result {
        Ok(doc) => {
            let host = |u: &str| reqwest::Url::parse(u).ok().and_then(|x| x.host_str().map(str::to_string)).unwrap_or_default();
            back(
                "success",
                &format!(
                    "The provider answered and identifies itself as {}. Sign-in goes to {}; tokens come from {}.",
                    doc.issuer, host(&doc.authorization_endpoint), host(&doc.token_endpoint)
                ),
            )
        }
        Err(e) => back("error", &e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/sso/disable
// Turns single sign-on off for the tenant; the configuration is kept.
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_disable(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
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
