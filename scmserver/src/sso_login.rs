// =============================================================================
// sso_login.rs — signing in through a tenant's OpenID Connect provider
//
// The authorization-code flow with PKCE:
//
//   POST /auth/sso/start      organization → that tenant's provider; remember a
//                             single-use state, nonce and PKCE verifier; send
//                             the browser to the provider.
//   GET  /auth/sso/callback   the provider sends the browser back with a code;
//                             exchange it, validate the ID token, find the
//                             user, issue the ordinary session cookie.
//
// Single sign-on AUTHENTICATES; it never creates an account or grants a role.
// Someone the provider vouches for who has no OpenSCM user is refused.
//
// Everything in here that fetches a URL does so through net_guard, because the
// URLs come from a tenant's configuration and a provider's own documents.
//
// SaaS only in 0.10.0 (see sso.rs). See docs/design/0.10.0-sso.md §4 for the
// checks and why each exists; tests/sso_login.rs shows each one refusing.
// =============================================================================

use axum::extract::{Extension, Form, Query};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::handlers::ClientIp;
use crate::sso::{self, Provider};

/// How long a sign-in may take between leaving for the provider and coming back.
const STATE_TTL_MINUTES: i64 = 10;
/// Clock difference tolerated between this server and the provider.
const CLOCK_LEEWAY_SECS: u64 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPLY_BYTES: usize = 256 * 1024;
/// The cookie that ties a sign-in to the browser that started it.
const FLOW_COOKIE: &str = "sso_flow";

// ─────────────────────────────────────────────────────────────────────────────
// SsoUrlRules — how strictly provider URLs are checked
//
// The routes look for this as a request extension and, finding none, are
// STRICT (https, public addresses only — net_guard). The production router
// never adds it. It exists so tests can run the real routes against a provider
// on a local port; there is no setting, flag or environment variable behind it.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug)]
pub struct SsoUrlRules {
    pub strict: bool,
}

fn strictness(rules: Option<Extension<SsoUrlRules>>) -> bool {
    rules.map(|Extension(r)| r.strict).unwrap_or(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// LoginFailure — why a sign-in did not complete
//
// `public` is shown on the sign-in page and says only what the person can act
// on. `reason` is the specific cause, for the server log and the audit log:
// telling a stranger "wrong audience" or "signature invalid" helps nobody who
// should be helped.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct LoginFailure {
    pub public: &'static str,
    pub reason: String,
    pub tenant_id: Option<String>,
}

const NOT_SET_UP: &str = "Single sign-on is not set up for this organization.";
const DID_NOT_COMPLETE: &str = "Single sign-on did not complete. Try again, or sign in with your password.";
const NO_ACCOUNT: &str = "Your provider signed you in, but there is no OpenSCM account for you in this organization. Ask an administrator to create one.";
const SUSPENDED: &str = "This organization is suspended. Please contact support.";
const CANCELLED: &str = "Sign-in was cancelled or refused at your provider.";

fn fail(public: &'static str, tenant_id: Option<&str>, reason: impl Into<String>) -> LoginFailure {
    LoginFailure { public, reason: reason.into(), tenant_id: tenant_id.map(str::to_string) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: random_token
// 32 random bytes, base64url — 43 characters, which is also a valid PKCE
// verifier (RFC 7636 asks for 43–128).
// ─────────────────────────────────────────────────────────────────────────────
fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: pkce_challenge
// The S256 code challenge for a verifier (RFC 7636).
// ─────────────────────────────────────────────────────────────────────────────
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A sign-in that has been started: where to send the browser, and the state
/// that will come back with it.
#[derive(Debug, Clone)]
pub struct Started {
    pub authorize_url: String,
    pub state: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: begin_login
// Starts a sign-in for an organization.
//
// An organization that does not exist and one with no enabled provider get the
// SAME answer, so this cannot be used to find out which organizations exist.
//
// Stores the single-use state, nonce and PKCE verifier server-side; they never
// travel through the browser except for `state` itself. State rows older than
// STATE_TTL are removed here, so abandoned sign-ins cannot accumulate.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn begin_login(pool: &SqlitePool, organization: &str, strict: bool) -> Result<Started, LoginFailure> {
    let tenant_id = crate::auth::tenant_id_for_organization(organization);
    if tenant_id.is_empty() {
        return Err(fail(NOT_SET_UP, None, "no organization given"));
    }
    let provider = match sso::load_provider(pool, &tenant_id).await {
        Some(p) if p.enabled => p,
        _ => return Err(fail(NOT_SET_UP, None, format!("no enabled provider for '{tenant_id}'"))),
    };
    let t = Some(tenant_id.as_str());
    let redirect_uri = sso::redirect_uri(pool)
        .await
        .ok_or_else(|| fail(DID_NOT_COMPLETE, t, "App URL is not set, so there is no callback address"))?;
    let doc = sso::discover_cached(&provider.issuer_url, strict)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("discovery failed: {e}")))?;

    let state = random_token();
    let nonce = random_token();
    let verifier = random_token();

    let _ = sqlx::query("DELETE FROM sso_login_state WHERE created_at < datetime('now', ?)")
        .bind(format!("-{STATE_TTL_MINUTES} minutes"))
        .execute(pool)
        .await;
    sqlx::query("INSERT INTO sso_login_state (state, tenant_id, nonce, pkce_verifier) VALUES (?, ?, ?, ?)")
        .bind(&state)
        .bind(&tenant_id)
        .bind(&nonce)
        .bind(&verifier)
        .execute(pool)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("could not store login state: {e}")))?;

    let mut url = reqwest::Url::parse(&doc.authorization_endpoint)
        .map_err(|_| fail(DID_NOT_COMPLETE, t, "authorization endpoint is not a URL"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256");

    Ok(Started { authorize_url: url.to_string(), state })
}

// The claims read from an ID token. iss, aud and exp are checked by
// jsonwebtoken; these are the ones this file decides on.
#[derive(Debug, Deserialize)]
struct IdClaims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    // A boolean per the specification; some providers send the string "true".
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    azp: Option<String>,
}

impl IdClaims {
    fn email_is_verified(&self) -> bool {
        match &self.email_verified {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
            _ => false, // absent means not verified
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: guarded_post_form
// POSTs a form to a provider URL through net_guard and returns (status, body),
// the body capped. Used for the token endpoint.
// ─────────────────────────────────────────────────────────────────────────────
async fn guarded_post_form(
    url: &str,
    strict: bool,
    basic: Option<(&str, &str)>,
    fields: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    let owned = url.to_string();
    let target = tokio::task::spawn_blocking(move || crate::net_guard::check_url(&owned, strict, "token endpoint"))
        .await
        .map_err(|e| format!("lookup failed: {e}"))??;
    let client = crate::net_guard::client_for(&target, HTTP_TIMEOUT)?;
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut req = client
        .post(&target.url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body);
    if let Some((id, secret)) = basic {
        // RFC 6749 §2.3.1: the id and secret are form-encoded before being
        // placed in the Basic credentials.
        req = req.basic_auth(urlencoding::encode(id), Some(urlencoding::encode(secret)));
    }
    let mut resp = req.send().await.map_err(|_| format!("request to {} failed", target.host))?;
    let status = resp.status().as_u16();
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| format!("reading from {} failed", target.host))? {
        if out.len() + chunk.len() > MAX_REPLY_BYTES {
            return Err(format!("{} sent an unexpectedly large reply", target.host));
        }
        out.extend_from_slice(&chunk);
    }
    Ok((status, out))
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing-key cache
//
// A provider's signing keys (its JWKS), kept for sso::CACHE_TTL. Providers
// rotate keys, so a token naming a key that is not in the cached set triggers
// one refetch — but at most once per KEY_REFETCH_EVERY, or anyone could make
// the server fetch on demand by sending tokens with invented key ids.
// ─────────────────────────────────────────────────────────────────────────────
const KEY_REFETCH_EVERY: Duration = Duration::from_secs(60);

type KeyCache = std::sync::Mutex<std::collections::HashMap<(String, bool), (Instant, Vec<Jwk>)>>;
static KEY_CACHE: std::sync::LazyLock<KeyCache> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

// Fetches and parses a key set. Keys this server cannot represent (an
// encryption key, a curve it does not know) are skipped, not fatal: one
// unusable key must not make a provider's usable ones unreadable.
async fn fetch_keys(jwks_uri: &str, strict: bool) -> Result<Vec<Jwk>, String> {
    let body = sso::guarded_get(jwks_uri, strict, "signing-key address").await?;
    let doc: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| "the provider's signing keys are not JSON".to_string())?;
    let keys = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| "the provider's signing keys have no \"keys\" list".to_string())?;
    Ok(keys.iter().filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok()).collect())
}

fn pick_key(keys: &[Jwk], kid: Option<&str>) -> Option<Jwk> {
    match kid {
        Some(kid) => keys.iter().find(|k| k.common.key_id.as_deref() == Some(kid)).cloned(),
        // A token with no key id is only acceptable when there is no choice.
        None if keys.len() == 1 => keys.first().cloned(),
        None => None,
    }
}

async fn signing_key(jwks_uri: &str, kid: Option<&str>, strict: bool) -> Result<Jwk, String> {
    let cache_key = (jwks_uri.to_string(), strict);
    let cached = KEY_CACHE.lock().ok().and_then(|c| c.get(&cache_key).cloned());
    if let Some((at, keys)) = &cached {
        if at.elapsed() < sso::CACHE_TTL {
            if let Some(k) = pick_key(keys, kid) {
                return Ok(k);
            }
            if at.elapsed() < KEY_REFETCH_EVERY {
                return Err("the token names a signing key the provider does not publish".into());
            }
        }
    }
    let keys = fetch_keys(jwks_uri, strict).await?;
    let found = pick_key(&keys, kid);
    if let Ok(mut c) = KEY_CACHE.lock() {
        c.insert(cache_key, (Instant::now(), keys));
    }
    found.ok_or_else(|| "the token names a signing key the provider does not publish".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: verify_id_token
// Checks an ID token and returns its claims. In order:
//
//   algorithm   asymmetric only. "none" is no signature, and HS256 would be a
//               "signature" made with the client secret, which proves nothing
//               about the provider.
//   signature   against a key the provider publishes.
//   iss         exactly the issuer this tenant configured — a valid token from
//               a different provider is not acceptable.
//   aud         contains our client id — a token minted for another
//               application at the same provider is not acceptable.
//   exp         not expired (CLOCK_LEEWAY_SECS of tolerance).
//   azp         when present, is our client id.
//   nonce       the one stored when THIS sign-in started — a token replayed
//               from another sign-in is not acceptable.
// ─────────────────────────────────────────────────────────────────────────────
async fn verify_id_token(
    token: &str,
    provider: &Provider,
    issuer: &str,
    jwks_uri: &str,
    expected_nonce: &str,
    strict: bool,
) -> Result<IdClaims, String> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| format!("unreadable token header: {e}"))?;
    let alg = header.alg;
    if !matches!(
        alg,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
            | Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512
            | Algorithm::ES256 | Algorithm::ES384 | Algorithm::EdDSA
    ) {
        return Err(format!("token signed with {alg:?}, which is not accepted"));
    }

    let jwk = signing_key(jwks_uri, header.kid.as_deref(), strict).await?;
    let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("unusable signing key: {e}"))?;

    let mut v = Validation::new(alg);
    v.leeway = CLOCK_LEEWAY_SECS;
    v.validate_exp = true;
    v.validate_nbf = true;
    v.set_issuer(&[issuer]);
    v.set_audience(&[provider.client_id.as_str()]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

    let claims = jsonwebtoken::decode::<IdClaims>(token, &key, &v)
        .map_err(|e| format!("token rejected: {e}"))?
        .claims;

    if let Some(azp) = &claims.azp {
        if azp != &provider.client_id {
            return Err("token was issued to a different application (azp)".into());
        }
    }
    match &claims.nonce {
        Some(n) if n == expected_nonce => {}
        Some(_) => return Err("nonce does not match this sign-in".into()),
        None => return Err("token carries no nonce".into()),
    }
    if claims.sub.trim().is_empty() {
        return Err("token has an empty subject".into());
    }
    Ok(claims)
}

/// The user a completed sign-in resolved to.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedIn {
    pub user_id: i32,
    pub username: String,
    pub role: String,
    pub tenant_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: resolve_user
// Who, in THIS tenant, the provider's identity is.
//
//   1. The user already bound to this subject.
//   2. Otherwise the ONE user with this email who is not bound to any subject —
//      and only if the provider says the address is verified. That user is
//      then bound to the subject, which is how an existing account becomes an
//      SSO account without an admin touching it.
//   3. Otherwise nobody: the sign-in is refused. No account is created.
//
// Without the verified-email rule, a provider that lets people set their own
// address would let anyone claim another user's account by typing their email.
//
// Some providers never send `email_verified` at all — Microsoft Entra ID's
// default ID token is one — and with the rule alone none of their users could
// ever be matched. A tenant can therefore mark its provider "trust email
// addresses" (sso_providers.trust_email): an address is then accepted when the
// claim is ABSENT. That is the tenant saying addresses in its directory are set
// by its administrators. An explicit `email_verified: false` is still refused:
// there the provider itself is saying the address is unconfirmed.
// Two users sharing the address is refused rather than guessed at. A user
// already bound to a DIFFERENT subject is never matched by email, so a second
// identity with the same address cannot take the account over.
// ─────────────────────────────────────────────────────────────────────────────
async fn resolve_user(
    pool: &SqlitePool,
    tenant_id: &str,
    claims: &IdClaims,
    trust_email: bool,
) -> Result<SignedIn, LoginFailure> {
    // Believed when the provider verified it, or — if the tenant trusts its
    // provider's addresses — when the provider is simply silent about it.
    let email_ok = claims.email_is_verified() || (trust_email && claims.email_verified.is_none());
    let t = Some(tenant_id);
    let row_to_user = |r: &sqlx::sqlite::SqliteRow| SignedIn {
        user_id: r.try_get("id").unwrap_or_default(),
        username: r.try_get("username").unwrap_or_default(),
        role: r.try_get::<Option<String>, _>("role").ok().flatten().unwrap_or_default(),
        tenant_id: tenant_id.to_string(),
    };

    let bound = sqlx::query("SELECT id, username, role, email FROM users WHERE tenant_id = ? AND sso_subject = ?")
        .bind(tenant_id)
        .bind(&claims.sub)
        .fetch_optional(pool)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("user lookup failed: {e}")))?;

    let (user, user_email) = if let Some(r) = bound {
        (row_to_user(&r), r.try_get::<Option<String>, _>("email").ok().flatten())
    } else {
        let email = claims.email.as_deref().map(str::trim).filter(|e| !e.is_empty());
        let Some(email) = email else {
            return Err(fail(NO_ACCOUNT, t, "no user is bound to this subject and the token has no email"));
        };
        if !email_ok {
            return Err(fail(NO_ACCOUNT, t, "no user is bound to this subject and the provider has not verified the email"));
        }
        let matches = sqlx::query(
            "SELECT id, username, role, email FROM users
              WHERE tenant_id = ? AND sso_subject IS NULL AND LOWER(email) = LOWER(?)",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_all(pool)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("user lookup failed: {e}")))?;
        match matches.len() {
            0 => return Err(fail(NO_ACCOUNT, t, "no user matches this subject or email")),
            1 => {}
            n => return Err(fail(DID_NOT_COMPLETE, t, format!("{n} users share this email; refusing to guess"))),
        }
        let user = row_to_user(&matches[0]);
        let bound = sqlx::query(
            "UPDATE users SET sso_subject = ? WHERE id = ? AND tenant_id = ? AND sso_subject IS NULL",
        )
        .bind(&claims.sub)
        .bind(user.user_id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("could not bind the subject: {e}")))?;
        if bound.rows_affected() != 1 {
            return Err(fail(DID_NOT_COMPLETE, t, "the user was bound to another identity meanwhile"));
        }
        info!("SSO: bound user '{}' (tenant '{}') to their provider identity on first sign-in", user.username, tenant_id);
        (user, matches[0].try_get::<Option<String>, _>("email").ok().flatten())
    };

    // The provider vouching for the address IS a verification of it. Without
    // this, a SaaS user who never clicked the confirmation link would sign in
    // here and be turned away by the session check on the next request.
    if email_ok {
        if let (Some(theirs), Some(ours)) = (claims.email.as_deref(), user_email.as_deref()) {
            if theirs.trim().eq_ignore_ascii_case(ours.trim()) {
                let _ = sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ? AND tenant_id = ?")
                    .bind(user.user_id)
                    .bind(tenant_id)
                    .execute(pool)
                    .await;
            }
        }
    }
    Ok(user)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: complete_login
// Finishes a sign-in: takes the state (single use), exchanges the code, checks
// the ID token and resolves the user.
//
// The state row is DELETED as it is read, before anything else happens, so a
// callback can never be replayed — whether or not it goes on to succeed.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn complete_login(pool: &SqlitePool, state: &str, code: &str, strict: bool) -> Result<SignedIn, LoginFailure> {
    let row = sqlx::query(
        "DELETE FROM sso_login_state WHERE state = ?
         RETURNING tenant_id, nonce, pkce_verifier,
                   CAST((julianday('now') - julianday(created_at)) * 1440 AS INTEGER) AS age_minutes",
    )
    .bind(state)
    .fetch_optional(pool)
    .await
    .map_err(|e| fail(DID_NOT_COMPLETE, None, format!("state lookup failed: {e}")))?
    .ok_or_else(|| fail(DID_NOT_COMPLETE, None, "unknown or already-used state"))?;

    let tenant_id: String = row.try_get("tenant_id").unwrap_or_default();
    let nonce: String = row.try_get("nonce").unwrap_or_default();
    let verifier: String = row.try_get("pkce_verifier").unwrap_or_default();
    let age: i64 = row.try_get("age_minutes").unwrap_or(i64::MAX);
    let t = Some(tenant_id.as_str());
    if age >= STATE_TTL_MINUTES {
        return Err(fail(DID_NOT_COMPLETE, t, format!("state expired ({age} minutes old)")));
    }
    if code.trim().is_empty() {
        return Err(fail(DID_NOT_COMPLETE, t, "callback carried no code"));
    }

    let provider = match sso::load_provider(pool, &tenant_id).await {
        Some(p) if p.enabled => p,
        _ => return Err(fail(NOT_SET_UP, t, "provider was disabled or removed during sign-in")),
    };
    let redirect_uri = sso::redirect_uri(pool)
        .await
        .ok_or_else(|| fail(DID_NOT_COMPLETE, t, "App URL is not set"))?;
    let doc = sso::discover_cached(&provider.issuer_url, strict)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("discovery failed: {e}")))?;

    // client_secret_basic unless the provider says it only takes the secret
    // in the form (OpenID Connect Core §9).
    let methods = &doc.token_endpoint_auth_methods_supported;
    let in_form = !methods.is_empty()
        && !methods.iter().any(|m| m == "client_secret_basic")
        && methods.iter().any(|m| m == "client_secret_post");
    let mut fields = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let basic = if in_form {
        fields.push(("client_id", provider.client_id.as_str()));
        fields.push(("client_secret", provider.client_secret.as_str()));
        None
    } else {
        Some((provider.client_id.as_str(), provider.client_secret.as_str()))
    };
    let (status, body) = guarded_post_form(&doc.token_endpoint, strict, basic, &fields)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, format!("token exchange failed: {e}")))?;
    if !(200..300).contains(&status) {
        // The provider's error code is logged; its body is not shown to anyone.
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_default();
        return Err(fail(DID_NOT_COMPLETE, t, format!("token endpoint answered HTTP {status} {code}")));
    }
    let reply: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| fail(DID_NOT_COMPLETE, t, "token endpoint did not return JSON"))?;
    let id_token = reply
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| fail(DID_NOT_COMPLETE, t, "token endpoint returned no id_token"))?;

    let claims = verify_id_token(id_token, &provider, &doc.issuer, &doc.jwks_uri, &nonce, strict)
        .await
        .map_err(|e| fail(DID_NOT_COMPLETE, t, e))?;

    // Checked after authentication, as for a password: the message is only
    // given to someone the provider has vouched for.
    let status: String = sqlx::query_scalar("SELECT COALESCE(status, 'active') FROM tenants WHERE id = ?")
        .bind(&tenant_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "active".to_string());
    if status == "suspended" {
        return Err(fail(SUSPENDED, t, "tenant is suspended"));
    }

    resolve_user(pool, &tenant_id, &claims, provider.trust_email).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: to_login
// Back to the sign-in page with a message.
// ─────────────────────────────────────────────────────────────────────────────
fn to_login(message: &str) -> Redirect {
    Redirect::to(&format!("/login?error_message={}", urlencoding::encode(message)))
}

#[derive(Deserialize)]
pub struct StartForm {
    #[serde(default)]
    organization: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/sso/start
// Begins a sign-in and sends the browser to the organization's provider.
//
// Also sets the flow cookie: the state, signed, readable only by this server.
// The callback requires it to match. Without it an attacker could start a
// sign-in themselves and hand a victim the finished callback link, leaving the
// victim signed in to the ATTACKER's account (login CSRF) — the state alone
// proves the flow was started here, not that it was started by this browser.
// Role: Public. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_start(
    jar: SignedCookieJar,
    Extension(pool): Extension<SqlitePool>,
    rules: Option<Extension<SsoUrlRules>>,
    Form(form): Form<StartForm>,
) -> Response {
    if !crate::handlers::is_saas_mode() {
        return to_login("Single sign-on is not available in this edition").into_response();
    }
    match begin_login(&pool, &form.organization, strictness(rules)).await {
        Ok(started) => {
            let mut cookie = Cookie::new(FLOW_COOKIE, started.state.clone());
            cookie.set_path("/auth/sso");
            cookie.set_http_only(true);
            // Lax: the provider sends the browser back with a top-level GET,
            // which Lax allows and Strict would not.
            cookie.set_same_site(SameSite::Lax);
            cookie.set_max_age(time::Duration::minutes(STATE_TTL_MINUTES));
            cookie.set_secure(crate::auth::cookie_should_be_secure(&pool).await);
            (jar.add(cookie), Redirect::to(&started.authorize_url)).into_response()
        }
        Err(f) => {
            warn!("SSO start refused for organization {:?}: {}", form.organization, f.reason);
            to_login(f.public).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /auth/sso/callback
// Where the provider sends the browser back. Completes the sign-in and issues
// the same session cookie a password sign-in does (auth::issue_session_cookie),
// so the session has the same lifetime and the same per-request checks.
// Role: Public. SaaS only.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sso_callback(
    jar: SignedCookieJar,
    Extension(pool): Extension<SqlitePool>,
    rules: Option<Extension<SsoUrlRules>>,
    ip: ClientIp,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if !crate::handlers::is_saas_mode() {
        return to_login("Single sign-on is not available in this edition").into_response();
    }
    // The flow cookie is spent whatever happens next.
    let flow = jar.get(FLOW_COOKIE).map(|c| c.value().to_string());
    let mut gone = Cookie::from(FLOW_COOKIE);
    gone.set_path("/auth/sso");
    let jar = jar.remove(gone);

    let state = q.state.unwrap_or_default();
    let outcome = if state.is_empty() || flow.as_deref() != Some(state.as_str()) {
        // Not the browser that started this sign-in (or no sign-in at all).
        // The state row is left alone: it is not this browser's to spend.
        Err(fail(DID_NOT_COMPLETE, None, "callback state does not match this browser's sign-in"))
    } else if let Some(err) = q.error {
        // The provider declined (the user cancelled, or is not assigned to the
        // application). Spend the state so the link cannot be reused.
        let tenant: Option<String> = sqlx::query_scalar("DELETE FROM sso_login_state WHERE state = ? RETURNING tenant_id")
            .bind(&state)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();
        Err(fail(CANCELLED, tenant.as_deref(), format!("provider returned error '{err}'")))
    } else {
        complete_login(&pool, &state, q.code.as_deref().unwrap_or(""), strictness(rules)).await
    };

    match outcome {
        Ok(user) => {
            let session = serde_json::json!({
                "username": user.username,
                "userid": user.user_id.to_string(),
                "tenant_id": user.tenant_id,
                "role": user.role,
            });
            let cookie = crate::auth::issue_session_cookie(&pool, session, crate::auth::SESSION_TTL).await;
            info!("User '{}' signed in through SSO for tenant '{}'", user.username, user.tenant_id);
            crate::audit::record_raw(
                &pool, &user.tenant_id, Some(user.user_id), &user.username, Some(ip.as_str()),
                "auth.login_success", Some("user"), Some(&user.user_id.to_string()), Some(serde_json::json!({"method": "sso"})),
            ).await;
            (jar.add(cookie), Redirect::to("/")).into_response()
        }
        Err(f) => {
            warn!("SSO sign-in failed (tenant {:?}): {}", f.tenant_id, f.reason);
            if let Some(tenant) = &f.tenant_id {
                crate::audit::record_raw(
                    &pool, tenant, None, "(sso)", Some(ip.as_str()),
                    "auth.login_failure", Some("user"), None,
                    Some(serde_json::json!({"method": "sso", "reason": f.reason})),
                ).await;
            }
            (jar, to_login(f.public)).into_response()
        }
    }
}
