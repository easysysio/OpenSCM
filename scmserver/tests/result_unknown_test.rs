// result_unknown_test.rs — a result for a test that no longer exists.
//
// Deleting a test while a scan is running leaves agents holding results for
// it. The server used to fail the INSERT on the foreign key and answer 500
// "Storage Error", logging an ERROR for an ordinary race. It now answers 404
// and stores nothing.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Extension, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::SqlitePool;
use tower::ServiceExt;

async fn setup() -> (SqlitePool, SigningKey) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    sqlx::query("INSERT INTO systems (id, tenant_id, key, name, status) VALUES (1, 'default', ?, 'web1', 'active')")
        .bind(STANDARD.encode(key.verifying_key().to_bytes())).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO tests (id, tenant_id, name, severity, filter, app_filter) VALUES (1, 'default', 't', 'low', 'all', 'all')")
        .execute(&pool).await.unwrap();
    (pool, key)
}

// Posts one signed result; returns (status, body).
async fn submit(pool: &SqlitePool, key: &SigningKey, test_id: i64) -> (StatusCode, serde_json::Value) {
    let payload = serde_json::json!({ "client_id": 1, "organization": "", "test_id": test_id, "result": "PASS" }).to_string();
    let signature = STANDARD.encode(key.sign(payload.as_bytes()).to_bytes());
    let body = format!(r#"{{"payload":{payload},"signature":"{signature}"}}"#);
    let (tx, _rx) = tokio::sync::mpsc::channel::<()>(8);
    let app = Router::new()
        .route("/result", post(scmserver::client::receive_result))
        .layer(Extension(pool.clone()))
        .layer(Extension(tx));
    let resp = app
        .oneshot(Request::post("/result").header("content-type", "application/json").body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

async fn stored(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM results").fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn a_result_for_a_missing_test_is_not_found_not_a_server_error() {
    let (pool, key) = setup().await;
    let (status, body) = submit(&pool, &key, 9999).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "Unknown test");
    assert_eq!(stored(&pool).await, 0);
}

#[tokio::test]
async fn a_result_for_a_test_deleted_mid_scan_is_not_found() {
    let (pool, key) = setup().await;
    assert_eq!(submit(&pool, &key, 1).await.0, StatusCode::OK);
    sqlx::query("DELETE FROM tests WHERE id = 1").execute(&pool).await.unwrap();
    assert_eq!(submit(&pool, &key, 1).await.0, StatusCode::NOT_FOUND);
}

// Another tenant's test id is "unknown" too — no cross-tenant write.
#[tokio::test]
async fn a_test_in_another_tenant_is_unknown() {
    let (pool, key) = setup().await;
    sqlx::query("INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO tests (id, tenant_id, name, severity, filter, app_filter) VALUES (2, 'acme', 't', 'low', 'all', 'all')")
        .execute(&pool).await.unwrap();
    assert_eq!(submit(&pool, &key, 2).await.0, StatusCode::NOT_FOUND);
    assert_eq!(stored(&pool).await, 0);
}

#[tokio::test]
async fn a_result_for_a_real_test_is_still_stored() {
    let (pool, key) = setup().await;
    let (status, _) = submit(&pool, &key, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored(&pool).await, 1);
}
