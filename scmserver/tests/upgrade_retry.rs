// upgrade_retry.rs — a queued upgrade survives a failed download.
//
// The UPGRADE row used to be deleted the moment it was handed to the agent, so
// when the download failed (an agent on a slow link hit its 15-second timeout)
// the upgrade was never tried again and the system stayed on its old agent.

use axum::body::Body;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::{Extension, Router};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use scmserver::client::UPGRADE_MAX_ATTEMPTS;
use scmserver::handlers::ClientIp;
use scmserver::models::AuthSession;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;

fn key() -> SigningKey { SigningKey::from_bytes(&[21u8; 32]) }

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO systems (id, tenant_id, name, status, ver, os, arch, ip, key)
                 VALUES (1, 'default', 'pi', 'active', '0.11.2', 'Debian 12', 'aarch64', '10.0.0.9', ?)")
        .bind(general_purpose::STANDARD.encode(key().verifying_key().as_bytes()))
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO agent_packages (platform, version, sha256, url)
                 VALUES ('aarch64-linux', '0.11.3', 'abc', '/agents/scmclient-aarch64-linux')")
        .execute(&pool).await.unwrap();
    pool
}

async fn queue_all(pool: &SqlitePool) {
    let admin = AuthSession {
        username: "alice".into(), userid: 1, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    };
    scmserver::systems::systems_upgrade_all(admin, Extension(pool.clone()), ClientIp("127.0.0.1".into()))
        .await.into_response();
}

// A heartbeat from the agent reporting `ver`; returns the command it is given.
async fn heartbeat(pool: &SqlitePool, ver: &str) -> String {
    let payload = json!({
        "id": "1", "organization": "default", "hostname": "pi", "ver": ver,
        "ip": "10.0.0.9", "os": "Debian 12", "arch": "aarch64", "timestamp": "0",
    });
    let raw = payload.to_string();
    let sig = general_purpose::STANDARD.encode(key().sign(raw.as_bytes()).to_bytes());
    let app = Router::new()
        .route("/send", axum::routing::post(scmserver::client::send))
        .layer(Extension(pool.clone()));
    let resp = app.oneshot(
        Request::post("/send").header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"payload":{raw},"signature":"{sig}"}}"#))).unwrap(),
    ).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["payload"]["command"].as_str().unwrap_or("?").to_string()
}

async fn queued(pool: &SqlitePool) -> Option<i64> {
    sqlx::query_scalar("SELECT attempts FROM commands WHERE system_id = 1 AND command_type = 'UPGRADE'")
        .fetch_optional(pool).await.unwrap()
}

#[tokio::test]
async fn a_failed_download_is_retried_an_hour_later_and_cleared_once_done() {
    let pool = db().await;
    queue_all(&pool).await;

    assert_eq!(heartbeat(&pool, "0.11.2").await, "UPGRADE");
    assert_eq!(queued(&pool).await, Some(1), "kept after hand-out");

    // The download failed; the agent checks in again on the old version.
    assert_ne!(heartbeat(&pool, "0.11.2").await, "UPGRADE", "not re-sent at every check-in");
    assert_eq!(queued(&pool).await, Some(1));

    // An hour later it is tried again.
    sqlx::query("UPDATE commands SET dispatched_at = datetime('now', '-61 minutes')")
        .execute(&pool).await.unwrap();
    assert_eq!(heartbeat(&pool, "0.11.2").await, "UPGRADE");
    assert_eq!(queued(&pool).await, Some(2));

    // It worked: the agent reports the new version and the row goes.
    assert_ne!(heartbeat(&pool, "0.11.3").await, "UPGRADE");
    assert_eq!(queued(&pool).await, None);
}

#[tokio::test]
async fn a_host_that_never_manages_is_given_up_on() {
    let pool = db().await;
    queue_all(&pool).await;
    sqlx::query("UPDATE commands SET attempts = ?, dispatched_at = datetime('now', '-2 hours')")
        .bind(UPGRADE_MAX_ATTEMPTS).execute(&pool).await.unwrap();
    assert_ne!(heartbeat(&pool, "0.11.2").await, "UPGRADE");
    assert_eq!(queued(&pool).await, None, "dropped after the last attempt");
}

#[tokio::test]
async fn queueing_again_means_try_now() {
    let pool = db().await;
    queue_all(&pool).await;
    assert_eq!(heartbeat(&pool, "0.11.2").await, "UPGRADE");
    // Within the hour, the admin clicks Upgrade All again.
    queue_all(&pool).await;
    assert_eq!(queued(&pool).await, Some(0));
    assert_eq!(heartbeat(&pool, "0.11.2").await, "UPGRADE", "handed out at once, not in an hour");
}
