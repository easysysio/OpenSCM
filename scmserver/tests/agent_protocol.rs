// agent_protocol.rs — agent protocol 1: freshness, versions, registration.
//
// docs/design/0.11.0-agent-protocol.md, D3, D5 and D6. Before 0.11.0 a signed
// heartbeat or result could be recorded and replayed at will (the timestamp
// was never checked), a reply was not tied to its request, and a registration
// was accepted whatever it was signed with.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use tower::ServiceExt;

fn b64(bytes: &[u8]) -> String { general_purpose::STANDARD.encode(bytes) }
fn agent_key() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }
fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO systems (id, tenant_id, name, status, ver, os, arch, ip, key)
         VALUES (1, 'default', 'web1', 'active', '0.11.0', 'Debian 12', 'x86_64', '10.0.0.9', ?)",
        "INSERT INTO tests (id, tenant_id, name) VALUES (5, 'default', 'ssh root login')",
    ] {
        let mut s = sqlx::query(q);
        if q.contains('?') { s = s.bind(b64(agent_key().verifying_key().as_bytes())); }
        s.execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: call
// POSTs `payload` signed by `key` to `path`, as a connection from `from`.
// Returns the status and the JSON body.
// ─────────────────────────────────────────────────────────────────────────────
async fn call(pool: &SqlitePool, path: &str, payload: &Value, key: &SigningKey, from: &str) -> (StatusCode, Value) {
    let raw = payload.to_string();
    let sig = b64(&key.sign(raw.as_bytes()).to_bytes());
    let body = format!(r#"{{"payload":{raw},"signature":"{sig}"}}"#);
    let (tx, _rx) = tokio::sync::mpsc::channel::<()>(64);
    let app = Router::new()
        .route("/send", axum::routing::post(scmserver::client::send))
        .route("/result", axum::routing::post(scmserver::client::receive_result))
        .layer(Extension(tx))
        .layer(Extension(pool.clone()));
    let mut req = Request::post(path).header("content-type", "application/json").body(Body::from(body)).unwrap();
    req.extensions_mut().insert(ConnectInfo(format!("{from}:40000").parse::<SocketAddr>().unwrap()));
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn heartbeat(protocol: Option<i64>, sent_at_ms: Option<i64>, nonce: &str) -> Value {
    let mut p = json!({
        "id": "1", "organization": "default", "hostname": "web1", "ver": "0.11.0",
        "ip": "10.0.0.9", "os": "Debian 12", "arch": "x86_64", "timestamp": "0",
    });
    if let Some(v) = protocol { p["protocol"] = json!(v); }
    if let Some(t) = sent_at_ms { p["sent_at_ms"] = json!(t); }
    p["nonce"] = json!(nonce);
    p
}

fn result(protocol: Option<i64>, sent_at_ms: Option<i64>) -> Value {
    let mut p = json!({"client_id": 1, "organization": "default", "test_id": 5, "result": "PASS"});
    if let Some(v) = protocol { p["protocol"] = json!(v); }
    if let Some(t) = sent_at_ms { p["sent_at_ms"] = json!(t); }
    p
}

#[tokio::test]
async fn a_protocol_1_reply_carries_the_requests_nonce() {
    let pool = db().await;
    let (s, body) = call(&pool, "/send", &heartbeat(Some(1), Some(now_ms()), "n-123"), &agent_key(), "10.0.0.9").await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["nonce"], json!("n-123"));
    assert_eq!(body["payload"]["protocol"], json!(1));
    let proto: Option<i64> = sqlx::query_scalar("SELECT agent_protocol FROM systems WHERE id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(proto, Some(1));
}

#[tokio::test]
async fn a_recorded_heartbeat_cannot_be_replayed() {
    let pool = db().await;
    let hb = heartbeat(Some(1), Some(now_ms()), "n-1");
    assert_eq!(call(&pool, "/send", &hb, &agent_key(), "10.0.0.9").await.0, StatusCode::OK);
    let (s, body) = call(&pool, "/send", &hb, &agent_key(), "10.0.0.9").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the same request twice: {body}");
    // Nor an older one, nor one far from the server's clock.
    let older = heartbeat(Some(1), Some(now_ms() - 10_000), "n-2");
    assert_eq!(call(&pool, "/send", &older, &agent_key(), "10.0.0.9").await.0, StatusCode::UNAUTHORIZED);
    let stale = heartbeat(Some(1), Some(now_ms() + 6 * 60 * 1000), "n-3");
    let (s, body) = call(&pool, "/send", &stale, &agent_key(), "10.0.0.9").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().unwrap().contains("clock"), "the agent is told why: {body}");
}

#[tokio::test]
async fn a_recorded_result_cannot_be_replayed() {
    let pool = db().await;
    let r = result(Some(1), Some(now_ms()));
    assert_eq!(call(&pool, "/result", &r, &agent_key(), "10.0.0.9").await.0, StatusCode::OK);
    assert_eq!(call(&pool, "/result", &r, &agent_key(), "10.0.0.9").await.0, StatusCode::UNAUTHORIZED);
    // Results and heartbeats share one clock: a heartbeat sent after a result
    // is newer than it.
    assert_eq!(call(&pool, "/send", &heartbeat(Some(1), Some(now_ms() + 1), "n"), &agent_key(), "10.0.0.9").await.0, StatusCode::OK);
}

#[tokio::test]
async fn old_format_requests_keep_working_until_the_agent_speaks_protocol_1() {
    let pool = db().await;
    // An agent from before protocol 1: no checks, no nonce in the reply.
    let (s, body) = call(&pool, "/send", &heartbeat(None, None, "x"), &agent_key(), "10.0.0.9").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body["payload"].get("nonce").is_none());
    assert_eq!(call(&pool, "/result", &result(None, None), &agent_key(), "10.0.0.9").await.0, StatusCode::OK);

    // Once it has spoken protocol 1, an old-format request can only be a recording.
    assert_eq!(call(&pool, "/send", &heartbeat(Some(1), Some(now_ms()), "y"), &agent_key(), "10.0.0.9").await.0, StatusCode::OK);
    assert_eq!(call(&pool, "/send", &heartbeat(None, None, "z"), &agent_key(), "10.0.0.9").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&pool, "/result", &result(None, None), &agent_key(), "10.0.0.9").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unknown_protocol_version_is_refused_with_a_reason() {
    let pool = db().await;
    let (s, body) = call(&pool, "/send", &heartbeat(Some(2), Some(now_ms()), "n"), &agent_key(), "10.0.0.9").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("protocol"), "{body}");
}

fn registration(key: &SigningKey, token: Option<&str>) -> Value {
    let mut p = json!({
        "id": "0", "organization": "default", "hostname": "new-host", "ver": "0.11.0",
        "ip": "10.0.0.20", "os": "Debian 12", "arch": "x86_64", "timestamp": "0",
        "public_key": b64(key.verifying_key().as_bytes()),
        "protocol": 1, "sent_at_ms": now_ms(), "nonce": "r",
    });
    if let Some(t) = token { p["enrollment_token"] = json!(t); }
    p
}

#[tokio::test]
async fn a_registration_must_be_signed_by_the_key_it_presents() {
    let pool = db().await;
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let other = SigningKey::from_bytes(&[12u8; 32]);
    let (s, _) = call(&pool, "/send", &registration(&key, None), &other, "198.51.100.1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "signed with a different key");
    let (s, body) = call(&pool, "/send", &registration(&key, None), &key, "198.51.100.1").await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["command"], json!("REGISTER"));

    // Someone who knows only an existing system's PUBLIC key learns nothing.
    let mut probe = registration(&agent_key(), None);
    probe["hostname"] = json!("probe");
    let (s, _) = call(&pool, "/send", &probe, &other, "198.51.100.1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn one_address_cannot_flood_the_pending_queue() {
    let pool = db().await;
    let max = scmserver::rate_limit::REGISTER_PENDING_MAX;
    // A distinct key per registration, each signing its own request.
    let key_n = |i: usize| SigningKey::from_bytes(&{ let mut b = [0u8; 32]; b[0] = 200; b[1] = i as u8; b[2] = (i >> 8) as u8; b });
    for i in 0..max {
        let k = key_n(i);
        let (s, body) = call(&pool, "/send", &registration(&k, None), &k, "203.0.113.77").await;
        assert_eq!(s, StatusCode::OK, "registration {i}: {body}");
    }
    let k = SigningKey::from_bytes(&[250u8; 32]);
    let (s, body) = call(&pool, "/send", &registration(&k, None), &k, "203.0.113.77").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    // Another address is not affected.
    let (s, _) = call(&pool, "/send", &registration(&k, None), &k, "203.0.113.78").await;
    assert_eq!(s, StatusCode::OK);
}
