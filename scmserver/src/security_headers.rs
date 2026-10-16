// =============================================================================
// security_headers.rs — browser security headers on every response
//
// One middleware, applied outermost in create_core_router and again by the
// SaaS binary around its own routes. A header a handler already set is left
// alone, so applying it twice is harmless.
//
// Content-Security-Policy keeps 'unsafe-inline' for scripts and styles: the
// templates carry inline <script> blocks, inline event handlers and style
// attributes, and a policy without it would break most pages. What the policy
// does buy is that nothing is loaded from any origin but this server (plus
// Google Fonts), the page cannot be framed, <base> cannot be repointed and
// plugins are off. Moving the inline code out is what would let
// 'unsafe-inline' go.
//
// form-action is deliberately absent: browsers apply it to the redirect that
// follows a form post, and /auth/sso/start answers its POST with a redirect to
// the customer's identity provider, which no fixed list could name.
// =============================================================================

use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::SqlitePool;

pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
script-src 'self' 'unsafe-inline'; \
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
font-src 'self' https://fonts.gstatic.com data:; \
img-src 'self' data: blob:; \
connect-src 'self'; \
object-src 'none'; \
base-uri 'self'; \
frame-ancestors 'none'";

// One year. Sent only while the App URL is https, see https_cached.
pub const HSTS: &str = "max-age=31536000";

// How long the App URL answer is reused before the settings row is read again.
const HTTPS_CACHE_TTL: Duration = Duration::from_secs(60);

static HTTPS_CACHE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

// ─────────────────────────────────────────────────────────────────────────────
// Middleware: security_headers
// Adds the headers below to the response unless the handler set them itself.
// Strict-Transport-Security follows the same signal as the session cookie's
// Secure flag (auth::cookie_should_be_secure): the platform App URL. A server
// reached over plain HTTP must not send it, and browsers ignore it there
// anyway.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn security_headers(
    State(pool): State<SqlitePool>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let https = https_cached(&pool).await;
    let headers = response.headers_mut();

    let mut set = |name: HeaderName, value: &'static str| {
        headers.entry(name).or_insert(HeaderValue::from_static(value));
    };
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "same-origin");
    set(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY);
    if https {
        set(header::STRICT_TRANSPORT_SECURITY, HSTS);
    }
    response
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: https_cached
// Whether the platform App URL (settings 'app_url' under the 'default' tenant)
// is https. Cached for HTTPS_CACHE_TTL so a page load with dozens of asset
// requests does not cost dozens of queries; a changed App URL takes effect
// within a minute. Before install the settings table does not exist, the
// query fails, and the answer is false.
// ─────────────────────────────────────────────────────────────────────────────
async fn https_cached(pool: &SqlitePool) -> bool {
    if let Some((at, value)) = *HTTPS_CACHE.lock().unwrap() {
        if at.elapsed() < HTTPS_CACHE_TTL {
            return value;
        }
    }
    let value = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE skey = 'app_url' AND tenant_id = 'default'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|u| u.trim().to_lowercase().starts_with("https://"))
    .unwrap_or(false);
    *HTTPS_CACHE.lock().unwrap() = Some((Instant::now(), value));
    value
}
