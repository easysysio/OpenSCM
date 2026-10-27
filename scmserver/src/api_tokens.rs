// =============================================================================
// api_tokens.rs — the API tokens page (/api-tokens)
//
// Where people create, see and revoke the tokens the REST API accepts
// (api/mod.rs). Every signed-in user manages their own; an Admin also sees and
// may revoke every token in the organization. A token's role is chosen at
// creation, at most the creator's own; its secret is shown once.
// See docs/design/0.12.0-rest-api.md, D1.
// =============================================================================

use std::sync::Arc;

use axum::extract::{Extension, Path, RawForm};
use axum::response::{IntoResponse, Redirect};
use serde::Serialize;
use sqlx::SqlitePool;
use tera::{Context, Tera};
use tracing::{error, info};

use crate::api::{generate_token, role_name};
use crate::audit;
use crate::auth;
use crate::handlers::{parse_form_data, render_template, ClientIp};
use crate::models::{AuthSession, UserRole};

#[derive(Serialize, sqlx::FromRow)]
struct TokenView {
    id: i64,
    name: String,
    prefix: String,
    role: String,
    owner: String,
    created_at: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    last_used_ip: Option<String>,
    status: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: load_tokens
// The caller's tokens, or every token in the organization for an Admin.
// Status is computed: Active / Expired / Revoked.
// ─────────────────────────────────────────────────────────────────────────────
async fn load_tokens(pool: &SqlitePool, auth: &AuthSession) -> Vec<TokenView> {
    let all = UserRole::from(auth.role.as_str()) >= UserRole::Admin;
    sqlx::query_as::<_, TokenView>(
        "SELECT t.id, t.name, t.prefix, t.role, COALESCE(u.username, '?') AS owner,
                t.created_at, t.expires_at, t.last_used_at, t.last_used_ip,
                CASE WHEN t.revoked_at IS NOT NULL THEN 'Revoked'
                     WHEN t.expires_at IS NOT NULL AND t.expires_at <= CURRENT_TIMESTAMP THEN 'Expired'
                     ELSE 'Active' END AS status
           FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
          WHERE t.tenant_id = ? AND (? OR t.user_id = ?)
          ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC",
    )
    .bind(&auth.tenant_id)
    .bind(all)
    .bind(auth.userid)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| { error!("Failed to load API tokens: {}", e); Vec::new() })
}

// The roles a token may be given: up to the creator's own, never above Admin.
fn grantable_roles(auth: &AuthSession) -> Vec<&'static str> {
    let own = UserRole::from(auth.role.as_str());
    [UserRole::Viewer, UserRole::Runner, UserRole::Editor, UserRole::Admin]
        .into_iter()
        .filter(|r| *r <= own)
        .map(|r| role_name(&r))
        .collect()
}

async fn render_page(
    tera: &Tera, pool: &SqlitePool, auth: AuthSession, new_token: Option<(String, String)>, error: Option<&str>,
) -> axum::response::Response {
    let mut ctx = Context::new();
    ctx.insert("tokens", &load_tokens(pool, &auth).await);
    ctx.insert("roles", &grantable_roles(&auth));
    ctx.insert("show_owner", &(UserRole::from(auth.role.as_str()) >= UserRole::Admin));
    if let Some((raw, name)) = new_token {
        ctx.insert("new_token", &raw);
        ctx.insert("new_token_name", &name);
    }
    if let Some(e) = error {
        ctx.insert("error_message", e);
    }
    render_template(tera, Some(pool), "api_tokens.html", ctx, Some(auth)).await.into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api-tokens
// Role: Viewer (any signed-in user).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_page(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
    axum::extract::Query(q): axum::extract::Query<crate::models::ErrorQuery>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir.into_response();
    }
    render_page(&tera, &pool, auth, None, q.error_message.as_deref()).await
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api-tokens/create
// Fields: name, role (at most the creator's), expiry ("30" | "90" | "365" |
// "never"; default 90 days). Renders the page with the secret shown ONCE —
// never in a redirect URL.
// Role: Viewer.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_create(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
    ip: ClientIp,
    RawForm(body): RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir.into_response();
    }
    let form = parse_form_data(&String::from_utf8_lossy(&body));
    let get = |k: &str| form.get(k).and_then(|v| v.first()).map(|s| s.trim().to_string()).unwrap_or_default();

    let name = get("name");
    if name.is_empty() || name.chars().count() > 100 {
        return render_page(&tera, &pool, auth, None, Some("Give the token a name of up to 100 characters")).await;
    }
    let role = get("role");
    if !grantable_roles(&auth).contains(&role.as_str()) {
        return render_page(&tera, &pool, auth, None, Some("A token can't have a higher role than yours")).await;
    }
    let expires_modifier = match get("expiry").as_str() {
        "30" => Some("+30 days"),
        "365" => Some("+365 days"),
        "never" => None,
        _ => Some("+90 days"),
    };

    let (raw, hash, prefix) = generate_token();
    let res = sqlx::query(
        "INSERT INTO api_tokens (tenant_id, user_id, name, prefix, token_hash, role, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', ?) END)",
    )
    .bind(&auth.tenant_id)
    .bind(auth.userid)
    .bind(&name)
    .bind(&prefix)
    .bind(&hash)
    .bind(&role)
    .bind(expires_modifier)
    .bind(expires_modifier)
    .execute(&pool)
    .await;
    if let Err(e) = res {
        error!("Failed to create API token: {}", e);
        return render_page(&tera, &pool, auth, None, Some("Could not create the token")).await;
    }

    audit::record(
        &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
        "api_token.create", Some("api_token"), Some(&prefix),
        Some(&format!("{{\"name\":{},\"role\":\"{}\",\"expires\":\"{}\"}}",
                      serde_json::to_string(&name).unwrap_or_default(), role,
                      expires_modifier.unwrap_or("never"))),
    ).await;
    info!("API token '{}' ({}) created by '{}' with role {}.", name, prefix, auth.username, role);

    render_page(&tera, &pool, auth, Some((raw, name)), None).await
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api-tokens/revoke/{id}
// The token's owner, or an Admin of the same organization. Revoked tokens
// stay listed (greyed) so the record of what existed remains.
// Role: Viewer (own tokens) / Admin (any in the organization).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tokens_revoke(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir.into_response();
    }
    let admin = UserRole::from(auth.role.as_str()) >= UserRole::Admin;
    let done = sqlx::query(
        "UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP
          WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL AND (? OR user_id = ?)",
    )
    .bind(id).bind(&auth.tenant_id).bind(admin).bind(auth.userid)
    .execute(&pool)
    .await;
    match done {
        Ok(r) if r.rows_affected() == 1 => {
            audit::record(
                &pool, &auth.tenant_id, Some(&auth), Some(ip.as_str()),
                "api_token.revoke", Some("api_token"), Some(&id.to_string()), None,
            ).await;
            Redirect::to("/api-tokens?success_message=Token+revoked").into_response()
        }
        Ok(_) => Redirect::to("/api-tokens?error_message=No+such+token").into_response(),
        Err(e) => {
            error!("Failed to revoke API token {}: {}", id, e);
            Redirect::to("/api-tokens?error_message=Could+not+revoke+the+token").into_response()
        }
    }
}
