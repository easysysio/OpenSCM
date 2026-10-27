// =============================================================================
// api/mod.rs — the REST API, /api/v1beta1
//
// Token-authenticated JSON for integrations: CI jobs, dashboards, SIEMs. The
// design and its decisions are in docs/design/0.12.0-rest-api.md.
//
//   • ApiAuth   — the extractor every endpoint takes. Reads
//                 `Authorization: Bearer oscm_api_…` (never the session
//                 cookie), checks the token against the CURRENT state of its
//                 owner and organization on every request, applies the
//                 per-token rate limit, and yields the organization and the
//                 effective role.
//   • ApiError  — the one error shape: {"error": {"code", "message"}} with
//                 the matching HTTP status.
//   • router()  — merged into create_core_router, so CE and SaaS both serve it.
// =============================================================================

use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::{request::Parts, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{error, warn};

use crate::handlers::ClientIp;
use crate::models::{AuthSession, UserRole};
use crate::rate_limit::Limiter;

pub mod read;

pub const PREFIX: &str = "/api/v1beta1";
pub const TOKEN_PREFIX: &str = "oscm_api_";

// 600 requests a minute per token; past that, refused for the rest of a minute.
pub const RATE_PER_MINUTE: usize = 600;
static RATE: LazyLock<Limiter> = LazyLock::new(|| {
    Limiter::new(RATE_PER_MINUTE, Duration::from_secs(60), Duration::from_secs(60))
});

// ─────────────────────────────────────────────────────────────────────────────
// ApiError — {"error": {"code": "...", "message": "..."}} and a status.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into(), retry_after: None }
    }
    pub fn unauthorized(m: impl Into<String>) -> Self { Self::new(StatusCode::UNAUTHORIZED, "unauthorized", m) }
    pub fn forbidden(m: impl Into<String>) -> Self { Self::new(StatusCode::FORBIDDEN, "forbidden", m) }
    pub fn not_found(m: impl Into<String>) -> Self { Self::new(StatusCode::NOT_FOUND, "not_found", m) }
    pub fn bad_request(m: impl Into<String>) -> Self { Self::new(StatusCode::BAD_REQUEST, "invalid_request", m) }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "Something went wrong on the server")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (self.status, Json(json!({"error": {"code": self.code, "message": self.message}})))
            .into_response();
        if let Some(secs) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: hash_token / generate_token
// Tokens are "oscm_api_" + 32 random bytes, base64url (no padding). Only the
// SHA-256 is stored; `prefix` (the first 12 characters after "oscm_api_") is
// kept for display. A distinct prefix from enrollment tokens ("oscm_") so the
// two cannot be confused, and secret scanners can tell them apart.
// ─────────────────────────────────────────────────────────────────────────────
pub fn hash_token(raw: &str) -> String {
    crate::enrollment::hash_token(raw)
}

pub fn generate_token() -> (String, String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let raw = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let prefix = raw[..TOKEN_PREFIX.len() + 12].to_string();
    let hash = hash_token(&raw);
    (raw, hash, prefix)
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiAuth — who is calling, as established from the token.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct ApiAuth {
    pub token_id: i64,
    pub token_name: String,
    pub token_expires_at: Option<String>,
    pub tenant_id: String,
    pub user_id: i64,
    pub username: String,
    /// The token's role, lowered to the owner's current role if that is less.
    pub role: UserRole,
    pub ip: String,
}

impl ApiAuth {
    // ─────────────────────────────────────────────────────────────────────────
    // require — 403 unless the effective role reaches `min`.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn require(&self, min: UserRole) -> Result<(), ApiError> {
        if self.role >= min {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!(
                "This needs the {} role; this token acts as {}",
                role_name(&min), role_name(&self.role)
            )))
        }
    }

    // The caller as an AuthSession, for code shared with the pages (audit
    // log, report builders). Never a superuser, never impersonating.
    pub fn as_session(&self) -> AuthSession {
        AuthSession {
            username: self.username.clone(),
            userid: self.user_id as i32,
            tenant_id: self.tenant_id.clone(),
            role: role_name(&self.role).to_string(),
            impersonating: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: role_name — the lower-case name stored in users.role.
// ─────────────────────────────────────────────────────────────────────────────
pub fn role_name(r: &UserRole) -> &'static str {
    match r {
        UserRole::Viewer => "viewer",
        UserRole::Runner => "runner",
        UserRole::Editor => "editor",
        UserRole::Admin => "admin",
        UserRole::Superuser => "superuser",
    }
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: i64,
    tenant_id: String,
    user_id: i64,
    name: String,
    role: String,
    expires_at: Option<String>,
    expired: i64,
    revoked: i64,
    username: String,
    user_role: Option<String>,
    email_verified: i64,
    tenant_status: String,
}

impl<S> FromRequestParts<S> for ApiAuth
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Only the Authorization header. A session cookie is deliberately not
        // accepted here (design D1): no cookie, no cross-site request forgery.
        let raw = parts.headers.get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| v.trim().to_string())
            .ok_or_else(|| ApiError::unauthorized(
                "Missing API token. Send it as: Authorization: Bearer oscm_api_…",
            ))?;
        if !raw.starts_with(TOKEN_PREFIX) {
            return Err(ApiError::unauthorized("That is not an OpenSCM API token (they start with oscm_api_)"));
        }
        let pool = parts.extensions.get::<SqlitePool>().cloned().ok_or_else(ApiError::internal)?;
        let token_hash = hash_token(&raw);
        let ip = ClientIp::from_request_parts(parts, state).await.map(|c| c.0).unwrap_or_default();

        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT t.id, t.tenant_id, t.user_id, t.name, t.role, t.expires_at,
                    COALESCE(t.expires_at <= CURRENT_TIMESTAMP, 0) AS expired,
                    t.revoked_at IS NOT NULL AS revoked,
                    u.username, u.role AS user_role, u.email_verified,
                    COALESCE(tn.status, 'active') AS tenant_status
               FROM api_tokens t
               JOIN users u ON u.id = t.user_id AND u.tenant_id = t.tenant_id
               LEFT JOIN tenants tn ON tn.id = t.tenant_id
              WHERE t.token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!("API token lookup failed: {}", e); ApiError::internal() })?;

        // Unknown, or its owner was deleted (the JOIN finds nothing).
        let Some(t) = row else {
            return Err(ApiError::unauthorized("Unknown API token"));
        };
        if t.revoked != 0 {
            return Err(ApiError::unauthorized("This API token has been revoked"));
        }
        if t.expired != 0 {
            return Err(ApiError::unauthorized("This API token has expired"));
        }
        if t.tenant_status == "suspended" {
            return Err(ApiError::forbidden("This organization is suspended"));
        }
        if t.email_verified == 0 {
            return Err(ApiError::forbidden("The token's owner has not confirmed their email address"));
        }

        // The effective role: the token's, lowered to the owner's current role,
        // and never above Admin (no platform-wide API in v1beta1).
        let owner = UserRole::from(t.user_role.as_deref().unwrap_or("viewer"));
        let token_role = UserRole::from(t.role.as_str());
        let role = token_role.min(owner).min(UserRole::Admin);

        // Keyed by the token's hash: unique across organizations and databases.
        let key = token_hash.clone();
        if let Some(left) = RATE.locked(&key) {
            let mut e = ApiError::new(
                StatusCode::TOO_MANY_REQUESTS, "rate_limited",
                format!("More than {RATE_PER_MINUTE} requests a minute with this token"),
            );
            e.retry_after = Some(left.as_secs().max(1));
            return Err(e);
        }
        if RATE.record(&key) {
            warn!("API token {} ('{}', tenant '{}') hit its rate limit", t.id, t.name, t.tenant_id);
        }

        // At most one write a minute per token, not one per request.
        let _ = sqlx::query(
            "UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ?
              WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-60 seconds'))",
        )
        .bind(&ip).bind(t.id).execute(&pool).await;

        Ok(ApiAuth {
            token_id: t.id,
            token_name: t.name,
            token_expires_at: t.expires_at,
            tenant_id: t.tenant_id,
            user_id: t.user_id,
            username: t.username,
            role,
            ip,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1beta1/me — who this token acts as. The first call to make when
// setting up an integration.
// ─────────────────────────────────────────────────────────────────────────────
async fn me(auth: ApiAuth) -> Json<serde_json::Value> {
    Json(json!({
        "user": {"id": auth.user_id, "username": auth.username},
        "organization": auth.tenant_id,
        "role": role_name(&auth.role),
        "token": {"name": auth.token_name, "expires_at": auth.token_expires_at.map(|t| iso(&t))},
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: iso — SQLite's "YYYY-MM-DD HH:MM:SS" (UTC) as ISO 8601 with Z.
// ─────────────────────────────────────────────────────────────────────────────
pub fn iso(sqlite_ts: &str) -> String {
    let t = sqlite_ts.trim();
    if t.ends_with('Z') { return t.to_string(); }
    format!("{}Z", t.replacen(' ', "T", 1))
}

// ─────────────────────────────────────────────────────────────────────────────
// Page — cursor pagination for list endpoints (design D4).
//   ?limit=N (default 100, at most 1000) & ?cursor=… (from the last page's
//   next_cursor). The cursor is the last row's id, base64url — opaque to
//   callers, and stable while rows are added, unlike an offset.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, serde::Deserialize)]
pub struct Page {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

impl Page {
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(100).clamp(1, 1000)
    }
    // The id rows must be greater than; 0 for the first page.
    pub fn after(&self) -> Result<i64, ApiError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        match self.cursor.as_deref().filter(|c| !c.is_empty()) {
            None => Ok(0),
            Some(c) => URL_SAFE_NO_PAD.decode(c).ok()
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| ApiError::bad_request("Invalid cursor")),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: page_of — {"data": [...], "next_cursor": …} from up to limit+1 rows
// fetched in id order: the extra row only says whether there is a next page.
// ─────────────────────────────────────────────────────────────────────────────
pub fn page_of(mut rows: Vec<serde_json::Value>, ids: Vec<i64>, limit: i64) -> Json<serde_json::Value> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more {
        ids.get(limit as usize - 1).map(|id| URL_SAFE_NO_PAD.encode(id.to_string()))
    } else {
        None
    };
    Json(json!({"data": rows, "next_cursor": next}))
}

// Any other path under /api: a JSON 404 rather than the HTML one.
async fn not_found() -> ApiError {
    ApiError::not_found("No such API endpoint. See /docs for the API reference.")
}

// ─────────────────────────────────────────────────────────────────────────────
// router — every API route, merged into create_core_router.
// ─────────────────────────────────────────────────────────────────────────────
pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    let p = |path: &str| format!("{PREFIX}{path}");
    Router::new()
        .route(&p("/me"), get(me))
        .route(&p("/systems"), get(read::systems_list))
        .route(&p("/systems/{id}"), get(read::systems_get))
        .route(&p("/systems/{id}/compliance"), get(read::systems_compliance))
        .route(&p("/groups"), get(read::groups_list))
        .route(&p("/groups/{id}"), get(read::groups_get))
        .route(&p("/tests"), get(read::tests_list))
        .route(&p("/tests/{id}"), get(read::tests_get))
        .route(&p("/policies"), get(read::policies_list))
        .route(&p("/policies/{id}"), get(read::policies_get))
        .route(&p("/policies/{id}/compliance"), get(read::policies_compliance))
        .route(&p("/reports/{kind}"), get(read::reports_list))
        .route(&p("/reports/{kind}/{id}"), get(read::reports_get))
        .route(&p("/reports/{kind}/{id}/pdf"), get(read::reports_pdf))
        .route(&p("/audit-log"), get(read::audit_log))
        .route("/api/{*rest}", axum::routing::any(not_found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_random_and_stored_only_hashed() {
        let (raw, hash, prefix) = generate_token();
        assert!(raw.starts_with(TOKEN_PREFIX));
        assert_eq!(raw.len(), TOKEN_PREFIX.len() + 43, "32 bytes, base64url");
        assert!(raw.starts_with(&prefix) && prefix.len() < raw.len());
        assert_eq!(hash, hash_token(&raw));
        assert_ne!(generate_token().0, raw);
    }

    #[test]
    fn iso_marks_utc() {
        assert_eq!(iso("2026-10-27 09:00:00"), "2026-10-27T09:00:00Z");
        assert_eq!(iso("2026-10-27T09:00:00Z"), "2026-10-27T09:00:00Z");
    }
}
