// =============================================================================
// enrollment.rs — golden enrollment tokens
//
// Admin-minted tokens that auto-approve enrolling systems: a system whose
// agent presents a valid token comes up `active` instead of `pending`,
// skipping the manual Approve click. This is an APPROVAL bypass, not an AUTH
// bypass — the ed25519 handshake still happens; the token only sets the
// initial status. See docs/design/0.6.0-enrollment-tokens.md.
//
// Secrets are stored as SHA-256 hashes; the raw token is shown once at
// creation. `validate_and_consume_token` is called from the registration path
// in client.rs inside the registration transaction.
//
// Management UI lives at /systems/tokens (linked from the Systems page).
// All handlers are Admin-gated.
// =============================================================================

use axum::extract::{Extension, Path, RawForm};
use axum::response::{IntoResponse, Redirect};
use sqlx::{SqlitePool, Sqlite, Transaction, Row};
use std::sync::Arc;
use tera::{Tera, Context};
use tracing::{info, error};
use bytes::Bytes;

use crate::auth;
use crate::audit;
use crate::handlers::{render_template, parse_form_data, ClientIp};
use crate::models::{AuthSession, UserRole};

// ─────────────────────────────────────────────────────────────────────────────
// Helper — hash_token
// SHA-256 hex of the raw token string (prefix included).  Validation hashes
// the presented token the same way and matches against token_hash.
// ─────────────────────────────────────────────────────────────────────────────
pub fn hash_token(raw: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    format!("{:x}", h.finalize())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — generate_token
// Returns (raw, hash, display_prefix).  raw is shown once; hash + prefix are
// persisted.  Format: "oscm_" + 32 hex chars (16 random bytes).
// ─────────────────────────────────────────────────────────────────────────────
fn generate_token() -> (String, String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let raw = format!("oscm_{}", hex);
    let hash = hash_token(&raw);
    // Non-secret display id: "oscm_" + first 7 hex chars.
    let prefix = format!("oscm_{}", &hex[..7]);
    (raw, hash, prefix)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — validate_and_consume_token
// Called from the registration path (client.rs) inside the registration
// transaction.  Returns Ok(true) if the token is valid for this tenant — and,
// as a side effect, increments use_count + stamps last_used_at.  A token is
// valid iff: enabled, not expired, and uses remaining.
//
// On any DB error or no-match, returns Ok(false) — the caller treats that as
// "no auto-approval" and registers the system as pending (lenient).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn validate_and_consume_token(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    raw_token: &str,
) -> Result<bool, sqlx::Error> {
    match find_valid_token(tx, tenant_id, raw_token).await? {
        Some(token_id) => {
            consume_token(tx, tenant_id, token_id).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: find_valid_token
// The id of the enabled, unexpired, not-used-up token matching `raw_token`.
// ─────────────────────────────────────────────────────────────────────────────
async fn find_valid_token(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    raw_token: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let hash = hash_token(raw_token);
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let row = sqlx::query(
        "SELECT id FROM enrollment_tokens
         WHERE tenant_id = ?
           AND token_hash = ?
           AND enabled = 1
           AND (expires_at IS NULL OR expires_at > ?)
           AND (max_uses   IS NULL OR use_count < max_uses)
         LIMIT 1"
    )
    .bind(tenant_id)
    .bind(&hash)
    .bind(&now)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|r| r.try_get("id").unwrap_or(0)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: consume_token
// Records one use of a token.
// ─────────────────────────────────────────────────────────────────────────────
async fn consume_token(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    token_id: i64,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query(
        "UPDATE enrollment_tokens
         SET use_count = use_count + 1, last_used_at = ?
         WHERE id = ? AND tenant_id = ?"
    )
    .bind(&now)
    .bind(token_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// What presenting an enrollment token at registration led to.
#[derive(Debug, PartialEq)]
pub enum TokenOutcome {
    /// Valid token, a use consumed: the system comes up active.
    Approved,
    /// No such token, or disabled, expired or used up.
    Invalid,
    /// Valid token, but the plan has no room for another active system. The
    /// token is NOT consumed and the system stays pending.
    PlanLimit(crate::plan::LimitReached),
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — approve_with_token
// The registration path's entry point: validates the token and, if the tenant's
// plan has room for another active system, consumes one use.
//
// A token auto-approves a system, and approving a system is what the plan's
// system limit counts. The limit is enforced by SaaS middleware on the approve
// buttons, which agent registration does not pass through, so tokens used to
// activate systems past it. The token is validated FIRST: only a genuine token
// can reach the plan check, so a stranger posting junk tokens cannot make the
// server announce that a plan is full.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn approve_with_token(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    raw_token: &str,
) -> Result<TokenOutcome, sqlx::Error> {
    let Some(token_id) = find_valid_token(tx, tenant_id, raw_token).await? else {
        return Ok(TokenOutcome::Invalid);
    };
    if let Some(limit) = crate::plan::limit_reached(tx, tenant_id, "systems").await {
        return Ok(TokenOutcome::PlanLimit(limit));
    }
    consume_token(tx, tenant_id, token_id).await?;
    Ok(TokenOutcome::Approved)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — load_tokens
// Loads the tenant's tokens with a derived status string for display.
// ─────────────────────────────────────────────────────────────────────────────
async fn load_tokens(pool: &SqlitePool, tenant_id: &str) -> Vec<serde_json::Value> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let rows = sqlx::query(
        "SELECT id, name, token_prefix, enabled, expires_at, max_uses, use_count,
                created_by, created_at, last_used_at
         FROM enrollment_tokens
         WHERE tenant_id = ?
         ORDER BY created_at DESC"
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter().map(|r| {
        let enabled: i64 = r.try_get("enabled").unwrap_or(0);
        let expires_at: Option<String> = r.try_get("expires_at").ok().flatten();
        let max_uses: Option<i64> = r.try_get("max_uses").ok().flatten();
        let use_count: i64 = r.try_get("use_count").unwrap_or(0);

        let expired = expires_at.as_deref().map(|e| e <= now.as_str()).unwrap_or(false);
        let used_up = max_uses.map(|m| use_count >= m).unwrap_or(false);
        let status = if enabled == 0 { "Disabled" }
                     else if expired { "Expired" }
                     else if used_up { "Used up" }
                     else { "Active" };

        serde_json::json!({
            "id":           r.try_get::<i64, _>("id").unwrap_or(0),
            "name":         r.try_get::<String, _>("name").unwrap_or_default(),
            "token_prefix": r.try_get::<Option<String>, _>("token_prefix").ok().flatten().unwrap_or_default(),
            "status":       status,
            "enabled":      enabled == 1,
            "expires_at":   expires_at.unwrap_or_default(),
            "max_uses":     max_uses,
            "use_count":    use_count,
            "created_by":   r.try_get::<Option<String>, _>("created_by").ok().flatten().unwrap_or_default(),
            "created_at":   r.try_get::<Option<String>, _>("created_at").ok().flatten().unwrap_or_default(),
            "last_used_at": r.try_get::<Option<String>, _>("last_used_at").ok().flatten().unwrap_or_default(),
        })
    }).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/tokens
// Render the enrollment-token management page. Role: Admin.
// `new_token` (the raw secret) is only present immediately after a create.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_page(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let tokens = load_tokens(&pool, &auth.tenant_id).await;
    let mut ctx = Context::new();
    ctx.insert("tokens", &tokens);
    render_template(&tera, Some(&pool), "enrollment_tokens.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/tokens/create
// Mint a new token. Renders the page with the raw secret shown ONCE.
// Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_create(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
    ip: ClientIp,
    raw_form: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let raw_string = String::from_utf8_lossy(&Bytes::from(raw_form.0)).to_string();
    let form = parse_form_data(&raw_string);

    let name = match form.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => return Redirect::to("/systems/tokens?error_message=Token+name+is+required").into_response(),
    };

    // Optional expiry: a date (YYYY-MM-DD) → stored as end-of-day.
    let expires_at: Option<String> = form.get("expires_at")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|d| format!("{} 23:59:59", d));

    // Optional max-uses: positive integer, else NULL (unlimited).
    let max_uses: Option<i64> = form.get("max_uses")
        .and_then(|v| v.first())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|n| *n > 0);

    let (raw, hash, prefix) = generate_token();

    let res = sqlx::query(
        "INSERT INTO enrollment_tokens
            (tenant_id, name, token_hash, token_prefix, enabled, expires_at, max_uses, created_by)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?)"
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&hash)
    .bind(&prefix)
    .bind(&expires_at)
    .bind(max_uses)
    .bind(&auth.username)
    .execute(&*pool)
    .await;

    if let Err(e) = res {
        error!("Failed to create enrollment token: {}", e);
        return Redirect::to("/systems/tokens?error_message=Could+not+create+token").into_response();
    }

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        "enrollment.token_create",
        Some("enrollment_token"),
        Some(&prefix),
        Some(&format!("name={:?} expires={:?} max_uses={:?}", name, expires_at, max_uses)),
    ).await;
    info!("Enrollment token '{}' ({}) created by '{}'.", name, prefix, auth.username);

    // Render the page with the raw secret shown once.
    let tokens = load_tokens(&pool, &auth.tenant_id).await;
    let mut ctx = Context::new();
    ctx.insert("tokens", &tokens);
    ctx.insert("new_token", &raw);
    ctx.insert("new_token_name", &name);
    render_template(&tera, Some(&pool), "enrollment_tokens.html", ctx, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/tokens/toggle/{id}
// Flip enabled. Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_toggle(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let _ = sqlx::query(
        "UPDATE enrollment_tokens SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END
         WHERE id = ? AND tenant_id = ?"
    )
    .bind(id).bind(&auth.tenant_id)
    .execute(&pool).await;

    let now_enabled: i64 = sqlx::query_scalar(
        "SELECT enabled FROM enrollment_tokens WHERE id = ? AND tenant_id = ?"
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&pool).await.unwrap_or(None).unwrap_or(0);

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        if now_enabled == 1 { "enrollment.token_enable" } else { "enrollment.token_disable" },
        Some("enrollment_token"), Some(&id.to_string()), None,
    ).await;
    Redirect::to("/systems/tokens").into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/tokens/delete/{id}
// Delete a token. Role: Admin.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_delete(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }
    let _ = sqlx::query(
        "DELETE FROM enrollment_tokens WHERE id = ? AND tenant_id = ?"
    )
    .bind(id).bind(&auth.tenant_id)
    .execute(&pool).await;

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        "enrollment.token_delete",
        Some("enrollment_token"), Some(&id.to_string()), None,
    ).await;
    Redirect::to("/systems/tokens").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_64_hex() {
        let h1 = hash_token("oscm_deadbeef");
        let h2 = hash_token("oscm_deadbeef");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);                       // SHA-256 hex
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(h1, hash_token("oscm_deadbee0"));     // different input → different hash
    }

    #[test]
    fn generated_token_shape() {
        let (raw, hash, prefix) = generate_token();
        assert!(raw.starts_with("oscm_"));
        assert_eq!(raw.len(), 5 + 32);                  // "oscm_" + 32 hex
        assert_eq!(hash, hash_token(&raw));             // hash matches the raw
        assert!(prefix.starts_with("oscm_"));
        assert_eq!(prefix.len(), 5 + 7);                // display prefix
        assert!(raw.starts_with(&prefix));              // prefix is a true prefix of raw
        // The hash must NOT be derivable from the stored prefix alone.
        assert_ne!(hash, hash_token(&prefix));
    }

    #[test]
    fn tokens_are_unique() {
        let (a, _, _) = generate_token();
        let (b, _, _) = generate_token();
        assert_ne!(a, b);
    }
}
