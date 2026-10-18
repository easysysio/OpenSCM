// key_rotation.rs — rotating the signing key hands agents the new key in a
// reply signed by the key they already trust.
//
// Agents from 0.10.4 pin the server key and refuse any reply it did not sign
// (docs/design/0.11.0-agent-protocol.md, D1). So for a rotation to reach
// them, the previous key must keep signing for agents that still hold it, and
// say what the new key is (D2). Before 0.10.4 the old key was dropped at once
// and agents were expected to trust whatever key came next.

use axum::body::Body;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Router};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use scmserver::handlers::ClientIp;
use scmserver::models::AuthSession;
use serde_json::Value;
use sqlx::SqlitePool;
use tower::ServiceExt;

fn agent_key() -> SigningKey { SigningKey::from_bytes(&[42u8; 32]) }
fn b64(bytes: &[u8]) -> String { general_purpose::STANDARD.encode(bytes) }

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO systems (id, tenant_id, name, status, key, ver, os, arch, ip)
                 VALUES (1, 'default', 'web1', 'active', ?, '0.10.4', 'Debian 12', 'x86_64', '10.0.0.9')")
        .bind(b64(agent_key().verifying_key().as_bytes()))
        .execute(&pool).await.unwrap();
    pool
}

async fn active_key(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT public_key FROM tenant_keys WHERE tenant_id = 'default' AND is_active = 1")
        .fetch_one(pool).await.unwrap()
}

async fn rotate(pool: &SqlitePool) {
    let admin = AuthSession {
        username: "alice".into(), userid: 1, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    };
    scmserver::settings::settings_rotate_keys(admin, Extension(pool.clone()), ClientIp("127.0.0.1".into()))
        .await.into_response();
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: heartbeat
// A signed heartbeat from agent 1 naming `server_key` (None: an agent from
// before 0.10.4). Returns the reply's payload and signature.
// ─────────────────────────────────────────────────────────────────────────────
async fn heartbeat(pool: &SqlitePool, server_key: Option<&str>) -> (Value, String) {
    let mut payload = serde_json::json!({
        "id": "1", "organization": "default", "hostname": "web1", "ver": "0.10.4",
        "ip": "10.0.0.9", "os": "Debian 12", "arch": "x86_64", "timestamp": "0", "public_key": null,
    });
    if let Some(k) = server_key { payload["server_key"] = Value::from(k); }
    let raw = serde_json::to_string(&payload).unwrap();
    let sig = b64(&agent_key().sign(raw.as_bytes()).to_bytes());
    let body = format!(r#"{{"payload":{raw},"signature":"{sig}"}}"#);

    let app = Router::new()
        .route("/send", post(scmserver::client::send))
        .layer(Extension(pool.clone()));
    let resp = app.oneshot(
        Request::post("/send").header("content-type", "application/json").body(Body::from(body)).unwrap(),
    ).await.unwrap();
    assert!(resp.status().is_success(), "heartbeat refused: {}", resp.status());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    (v["payload"].clone(), v["signature"].as_str().unwrap().to_string())
}

// Verified exactly as the agent verifies: serde_json bytes of the payload.
fn signed_by(payload: &Value, sig: &str, key_b64: &str) -> bool {
    let vk = VerifyingKey::from_bytes(&general_purpose::STANDARD.decode(key_b64).unwrap().try_into().unwrap()).unwrap();
    let sig = Signature::from_slice(&general_purpose::STANDARD.decode(sig).unwrap()).unwrap();
    vk.verify(&serde_json::to_vec(payload).unwrap(), &sig).is_ok()
}

#[tokio::test]
async fn an_agent_on_the_old_key_is_handed_the_new_one_by_the_old_one() {
    let pool = db().await;
    let k1 = active_key(&pool).await;

    let (p, s) = heartbeat(&pool, Some(&k1)).await;
    assert!(signed_by(&p, &s, &k1));
    assert!(p.get("next_server_public_key").is_none(), "nothing to hand over yet");

    rotate(&pool).await;
    let k2 = active_key(&pool).await;
    assert_ne!(k1, k2);

    // Still holding the old key: signed with it, and told the new one.
    let (p, s) = heartbeat(&pool, Some(&k1)).await;
    assert!(signed_by(&p, &s, &k1), "the agent could not verify this reply");
    assert_eq!(p["next_server_public_key"], Value::from(k2.clone()));

    // Switched: signed with the new key, nothing more to hand over.
    let (p, s) = heartbeat(&pool, Some(&k2)).await;
    assert!(signed_by(&p, &s, &k2));
    assert!(p.get("next_server_public_key").is_none());

    let held: String = sqlx::query_scalar("SELECT agent_server_key FROM systems WHERE id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(held, k2, "the server records which key the agent holds");
}

#[tokio::test]
async fn agents_before_0_10_4_are_signed_for_with_the_active_key() {
    let pool = db().await;
    rotate(&pool).await;
    let k2 = active_key(&pool).await;
    let (p, s) = heartbeat(&pool, None).await;
    assert!(signed_by(&p, &s, &k2));
    assert!(p.get("next_server_public_key").is_none());
}

#[tokio::test]
async fn after_the_grace_period_the_old_key_signs_nothing() {
    let pool = db().await;
    let k1 = active_key(&pool).await;
    rotate(&pool).await;
    let k2 = active_key(&pool).await;
    sqlx::query("UPDATE tenant_keys SET retire_after = datetime('now', '-1 minute') WHERE is_active = 0")
        .execute(&pool).await.unwrap();

    let (p, s) = heartbeat(&pool, Some(&k1)).await;
    assert!(!signed_by(&p, &s, &k1), "a key past its grace period must not sign");
    assert!(signed_by(&p, &s, &k2));
    assert!(p.get("next_server_public_key").is_none());
}

#[tokio::test]
async fn a_key_the_server_never_had_gets_nothing_signed_with_it() {
    let pool = db().await;
    let stranger = b64(SigningKey::from_bytes(&[9u8; 32]).verifying_key().as_bytes());
    let k1 = active_key(&pool).await;
    let (p, s) = heartbeat(&pool, Some(&stranger)).await;
    assert!(signed_by(&p, &s, &k1));
    assert!(p.get("next_server_public_key").is_none());
}

#[tokio::test]
async fn rotating_twice_keeps_the_first_keys_own_deadline() {
    let pool = db().await;
    let k1 = active_key(&pool).await;
    rotate(&pool).await;
    sqlx::query("UPDATE tenant_keys SET retire_after = datetime('now', '+2 days') WHERE public_key = ?")
        .bind(&k1).execute(&pool).await.unwrap();
    rotate(&pool).await;
    // Not reset to 30 days by the second rotation.
    let days: i64 = sqlx::query_scalar(
        "SELECT CAST(julianday(retire_after) - julianday('now') AS INTEGER) FROM tenant_keys WHERE public_key = ?")
        .bind(&k1).fetch_one(&pool).await.unwrap();
    assert!(days <= 2, "first key's grace was extended to {days} days");
    let in_grace: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_keys WHERE is_active = 0 AND retire_after > CURRENT_TIMESTAMP")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(in_grace, 2);
}
