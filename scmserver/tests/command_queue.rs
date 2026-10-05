// command_queue.rs — a heartbeat removes from the queue only what it sent.
//
// A heartbeat dispatches at most 500 queued tests. It then deleted every TEST
// command the system had, so with more than 500 queued the remainder was
// discarded without ever being sent: those tests never ran, and nothing was
// logged. Any system whose policies add up to more than 500 tests was affected
// on every scan.
//
// These drive the real /send handler with a correctly signed heartbeat.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Extension, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::SqlitePool;
use std::collections::HashSet;
use tower::ServiceExt;

struct Agent {
    key: SigningKey,
    id: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: setup
// An approved system (id 1) holding `queued` TEST commands, each for its own
// test with one condition.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup(queued: usize) -> (SqlitePool, Agent) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();

    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let public = STANDARD.encode(key.verifying_key().to_bytes());
    sqlx::query("INSERT INTO systems (id, tenant_id, key, name, status) VALUES (1, 'default', ?, 'big1', 'active')")
        .bind(&public).execute(&pool).await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    for i in 1..=queued as i64 {
        sqlx::query("INSERT INTO tests (id, tenant_id, name, severity, filter, app_filter)
                     VALUES (?, 'default', ?, 'low', 'all', 'all')")
            .bind(i).bind(format!("test {i}")).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO test_conditions (tenant_id, test_id, type, element, input, selement, condition, sinput)
                     VALUES ('default', ?, 'condition', 'FILE', '/etc/x', 'EXISTS', '', '')")
            .bind(i).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO commands (tenant_id, system_id, test_id, command_type) VALUES ('default', 1, ?, 'TEST')")
            .bind(i).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    (pool, Agent { key, id: 1 })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: heartbeat
// Sends one signed heartbeat; returns (command, ids of the tests delivered).
// ─────────────────────────────────────────────────────────────────────────────
async fn heartbeat(pool: &SqlitePool, agent: &Agent) -> (String, Vec<i64>) {
    let payload = serde_json::json!({
        "id": agent.id.to_string(), "organization": "", "hostname": "big1", "ver": "0.9.5",
        "ip": "10.0.0.20", "os": "Linux", "arch": "x86_64", "timestamp": "2026-10-05T12:00:00Z"
    }).to_string();
    let signature = STANDARD.encode(agent.key.sign(payload.as_bytes()).to_bytes());
    // The payload is embedded verbatim: the server verifies the signature
    // over these exact bytes.
    let body = format!(r#"{{"payload":{payload},"signature":"{signature}"}}"#);

    let app = Router::new()
        .route("/send", post(scmserver::client::send))
        .layer(Extension(pool.clone()));
    let resp = app
        .oneshot(Request::post("/send").header("content-type", "application/json").body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "heartbeat rejected");
    let bytes = axum::body::to_bytes(resp.into_body(), 64 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let p = &v["payload"];
    let ids = p["data"].as_array().map(|a| a.iter().map(|t| t["id"].as_i64().unwrap()).collect()).unwrap_or_default();
    (p["command"].as_str().unwrap_or("").to_string(), ids)
}

async fn queue_len(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM commands WHERE system_id = 1 AND command_type = 'TEST'")
        .fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn tests_beyond_the_per_heartbeat_cap_are_kept_for_the_next_one() {
    let (pool, agent) = setup(603).await;

    let (cmd, first) = heartbeat(&pool, &agent).await;
    assert_eq!(cmd, "TEST");
    assert_eq!(first.len(), 500, "one heartbeat carries at most 500 tests");
    assert_eq!(queue_len(&pool).await, 103, "the tests that were not sent must stay queued");

    let (cmd, second) = heartbeat(&pool, &agent).await;
    assert_eq!(cmd, "TEST");
    assert_eq!(second.len(), 103);
    assert_eq!(queue_len(&pool).await, 0);

    // Every test exactly once, across both.
    let all: HashSet<i64> = first.iter().chain(&second).copied().collect();
    assert_eq!(all.len(), 603, "a test was delivered twice or not at all");
    assert_eq!(all, (1..=603).collect::<HashSet<i64>>());

    let (cmd, third) = heartbeat(&pool, &agent).await;
    assert_eq!((cmd.as_str(), third.len()), ("NONE", 0), "nothing is re-sent once the queue is empty");
}

#[tokio::test]
async fn a_queue_within_the_cap_drains_in_one_heartbeat() {
    let (pool, agent) = setup(7).await;
    let (cmd, ids) = heartbeat(&pool, &agent).await;
    assert_eq!(cmd, "TEST");
    assert_eq!(ids, (1..=7).collect::<Vec<i64>>(), "delivered in a stable order");
    assert_eq!(queue_len(&pool).await, 0);
}

// An upgrade takes priority and sends no tests; they must all still be there
// for the heartbeat after the agent restarts.
#[tokio::test]
async fn an_upgrade_dispatch_keeps_every_queued_test() {
    let (pool, agent) = setup(5).await;
    sqlx::query("INSERT INTO agent_packages (platform, version, sha256, url) VALUES ('x86_64-linux', '9.9.9', 'abc', '/agents/x')")
        .execute(&pool).await.unwrap();
    // UPGRADE rows carry no test; the primary key allows one per system.
    sqlx::query("INSERT INTO commands (tenant_id, system_id, test_id, command_type) VALUES ('default', 1, NULL, 'UPGRADE')")
        .execute(&pool).await.unwrap();

    let (cmd, ids) = heartbeat(&pool, &agent).await;
    assert_eq!(cmd, "UPGRADE");
    assert!(ids.is_empty());
    assert_eq!(queue_len(&pool).await, 5, "tests wait for the upgraded agent");

    let (cmd, ids) = heartbeat(&pool, &agent).await;
    assert_eq!((cmd.as_str(), ids.len()), ("TEST", 5));
    assert_eq!(queue_len(&pool).await, 0);
}
