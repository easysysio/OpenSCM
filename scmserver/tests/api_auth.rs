// api_auth.rs — who may call the REST API, and as what.
//
// docs/design/0.12.0-rest-api.md, D1: a Bearer token, never the session
// cookie; checked on every request against the owner's and the
// organization's CURRENT state; a role of its own, at most the owner's.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum_extra::extract::cookie::Key;
use scmserver::api::{generate_token, RATE_PER_MINUTE};
use scmserver::models::AuthSession;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::{atomic::AtomicBool, Arc};
use tower::ServiceExt;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (10, 'acme', 'alice', 'x', 'admin')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (11, 'acme', 'bob', 'x', 'viewer')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (12, 'default', 'root', 'x', 'superuser')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    pool
}

// A token for `user` with `role`, expiring per `expires` (SQL modifier or None).
async fn token(pool: &SqlitePool, tenant: &str, user: i64, role: &str, expires: Option<&str>) -> String {
    let (raw, hash, prefix) = generate_token();
    sqlx::query(
        "INSERT INTO api_tokens (tenant_id, user_id, name, prefix, token_hash, role, expires_at)
         VALUES (?, ?, 'test', ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', ?) END)",
    )
    .bind(tenant).bind(user).bind(prefix).bind(hash).bind(role).bind(expires).bind(expires)
    .execute(pool).await.unwrap();
    raw
}

fn app(pool: &SqlitePool, installed: bool) -> axum::Router {
    let (sync_tx, _rx) = tokio::sync::mpsc::channel(1);
    scmserver::create_core_router(
        scmserver::AppState {
            pool: pool.clone(),
            tera: Arc::new(scmserver::init_tera().unwrap()),
            config: Arc::new(scmserver::config::Config::default()),
            sync_tx,
            is_initialized: Arc::new(AtomicBool::new(installed)),
        },
        Key::from(&[7u8; 64]),
    )
}

async fn call(app: axum::Router, path: &str, header: Option<(&str, String)>) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut req = Request::get(path);
    if let Some((k, v)) = header { req = req.header(k, v); }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null), headers)
}

async fn me(pool: &SqlitePool, tok: &str) -> (StatusCode, Value) {
    me_on(&app(pool, true), tok).await
}

// Building the router parses every template; reuse one for many requests.
async fn me_on(app: &axum::Router, tok: &str) -> (StatusCode, Value) {
    let (s, v, _) = call(app.clone(), "/api/v1beta1/me", Some(("authorization", format!("Bearer {tok}")))).await;
    (s, v)
}

#[tokio::test]
async fn a_valid_token_says_who_it_is() {
    let pool = db().await;
    let tok = token(&pool, "acme", 10, "runner", Some("+90 days")).await;
    let (s, v) = me(&pool, &tok).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["user"]["username"], "alice");
    assert_eq!(v["organization"], "acme");
    assert_eq!(v["role"], "runner", "the token's own role, below its Admin owner");
    assert!(v["token"]["expires_at"].as_str().unwrap().ends_with('Z'));
}

#[tokio::test]
async fn no_token_or_a_foreign_one_is_refused_in_json() {
    let pool = db().await;
    let (s, v, _) = call(app(&pool, true), "/api/v1beta1/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "unauthorized");
    let (s, _) = me(&pool, "oscm_abc123").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "an enrollment token is not an API token");
    let (s, _) = me(&pool, "oscm_api_not-a-real-one").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_session_cookie_is_not_accepted() {
    let pool = db().await;
    let (s, _, _) = call(app(&pool, true), "/api/v1beta1/me", Some(("cookie", "session=anything".into()))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_and_revoked_tokens_stop_working() {
    let pool = db().await;
    let expired = token(&pool, "acme", 10, "viewer", Some("-1 minute")).await;
    assert_eq!(me(&pool, &expired).await.0, StatusCode::UNAUTHORIZED);
    let tok = token(&pool, "acme", 10, "viewer", None).await;
    assert_eq!(me(&pool, &tok).await.0, StatusCode::OK, "no expiry");
    sqlx::query("UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP").execute(&pool).await.unwrap();
    assert_eq!(me(&pool, &tok).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn changes_to_the_owner_and_organization_apply_at_once() {
    let pool = db().await;
    let tok = token(&pool, "acme", 10, "admin", None).await;
    sqlx::query("UPDATE users SET role = 'viewer' WHERE id = 10").execute(&pool).await.unwrap();
    assert_eq!(me(&pool, &tok).await.1["role"], "viewer", "the token shrinks with its owner");
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = 'acme'").execute(&pool).await.unwrap();
    assert_eq!(me(&pool, &tok).await.0, StatusCode::FORBIDDEN);
    sqlx::query("UPDATE tenants SET status = 'active' WHERE id = 'acme'").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM users WHERE id = 10").execute(&pool).await.unwrap();
    assert_eq!(me(&pool, &tok).await.0, StatusCode::UNAUTHORIZED, "deleted owner");
}

#[tokio::test]
async fn no_token_acts_above_admin() {
    let pool = db().await;
    let tok = token(&pool, "default", 12, "superuser", None).await;
    assert_eq!(me(&pool, &tok).await.1["role"], "admin");
}

#[tokio::test]
async fn too_many_requests_get_429_with_retry_after() {
    let pool = db().await;
    let tok = token(&pool, "acme", 10, "viewer", None).await;
    let app = app(&pool, true);
    for i in 0..RATE_PER_MINUTE {
        assert_eq!(me_on(&app, &tok).await.0, StatusCode::OK, "request {i}");
    }
    let (s, v, h) = call(app.clone(), "/api/v1beta1/me", Some(("authorization", format!("Bearer {tok}")))).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"]["code"], "rate_limited");
    assert!(h.get("retry-after").is_some());
}

#[tokio::test]
async fn unknown_paths_and_an_uninstalled_server_answer_in_json() {
    let pool = db().await;
    let (s, v, _) = call(app(&pool, true), "/api/v1beta1/nope", None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
    let (s, v, _) = call(app(&pool, false), "/api/v1beta1/me", None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("not_installed")));
}

// ── The API tokens page ──────────────────────────────────────────────────────

fn user(id: i32, role: &str) -> AuthSession {
    AuthSession { username: format!("u{id}"), userid: id, tenant_id: "acme".into(), role: role.into(), impersonating: None }
}

async fn create(pool: &SqlitePool, who: AuthSession, form: &str) -> String {
    let resp = scmserver::api_tokens::tokens_create(
        who, axum::Extension(pool.clone()), axum::Extension(Arc::new(scmserver::init_tera().unwrap())),
        scmserver::handlers::ClientIp("127.0.0.1".into()), axum::extract::RawForm(form.to_string().into()),
    ).await.into_response();
    String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn a_new_token_is_shown_once_stored_hashed_and_capped_at_the_creators_role() {
    let pool = db().await;
    let html = create(&pool, user(11, "viewer"), "name=dash&role=admin&expiry=90").await;
    assert!(html.contains("higher role than yours"), "a Viewer cannot mint an Admin token");
    let html = create(&pool, user(11, "viewer"), "name=dash&role=viewer&expiry=90").await;
    let raw = regex::Regex::new(r"oscm_api_[A-Za-z0-9_-]{43}").unwrap()
        .find(&html).expect("the new token is on the page").as_str().to_string();
    let stored: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM api_tokens").fetch_all(&pool).await.unwrap();
    assert_eq!(stored, vec![scmserver::api::hash_token(&raw)], "only the hash is kept");
    assert_eq!(me(&pool, &raw).await.1["role"], "viewer");
    let days: i64 = sqlx::query_scalar("SELECT CAST(julianday(expires_at) - julianday('now') + 0.5 AS INTEGER) FROM api_tokens")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(days, 90);
}

#[tokio::test]
async fn people_revoke_their_own_tokens_and_admins_any() {
    let pool = db().await;
    let bobs = token(&pool, "acme", 11, "viewer", None).await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM api_tokens").fetch_one(&pool).await.unwrap();
    let revoke = |who: AuthSession| {
        let pool = pool.clone();
        async move {
            let _ = scmserver::api_tokens::tokens_revoke(
                who, axum::extract::Path(id), axum::Extension(pool), scmserver::handlers::ClientIp("127.0.0.1".into()),
            ).await.into_response();
        }
    };
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES (13, 'acme', 'carol', 'x', 'editor')")
        .execute(&pool).await.unwrap();
    revoke(user(13, "editor")).await;
    assert_eq!(me(&pool, &bobs).await.0, StatusCode::OK, "another non-admin user cannot revoke it");
    revoke(user(10, "admin")).await;
    assert_eq!(me(&pool, &bobs).await.0, StatusCode::UNAUTHORIZED, "an Admin can");
}
