// backup_alerts.rs — the "Server backups / a backup fails" alert trigger.
//
// A failed backup queues a delivery for every action of every enabled
// backup_failed rule, with its own event name and text; the outbox delivers
// it like any other alert. Only superusers create, change, switch off or
// delete such rules.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, RawForm};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use scmserver::backup::Paths;
use scmserver::backup_jobs::{Backups, Trigger};
use scmserver::models::AuthSession;
use sqlx::SqlitePool;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES
                 (1, 'default', 'root', 'x', 'superuser'), (2, 'default', 'alice', 'x', 'admin')")
        .execute(&pool).await.unwrap();
    pool
}

fn su() -> AuthSession {
    AuthSession { username: "root".into(), userid: 1, tenant_id: "default".into(), role: "superuser".into(), impersonating: None }
}
fn admin() -> AuthSession {
    AuthSession { username: "alice".into(), userid: 2, tenant_id: "default".into(), role: "admin".into(), impersonating: None }
}

async fn save(pool: &SqlitePool, who: AuthSession, id: Option<i64>, body: &str) -> String {
    let r = scmserver::alerts_admin::alerts_save(who, Extension(pool.clone()), id.map(Path), RawForm(Bytes::from(body.to_string())))
        .await.into_response();
    r.headers().get("location").map(|l| l.to_str().unwrap().to_string()).unwrap_or_default()
}

async fn rules(pool: &SqlitePool) -> Vec<(i64, String, String, Option<i64>, f64, i64)> {
    sqlx::query_as("SELECT id, scope_type, trigger_type, policy_id, threshold, enabled FROM alerts ORDER BY id")
        .fetch_all(pool).await.unwrap()
}

const BACKUP_RULE: &str = "name=backups&enabled=on&scope_type=server&trigger_type=drop&threshold=10&action_notify=on";

#[tokio::test]
async fn superusers_create_backup_rules_and_admins_cannot_touch_them() {
    let pool = db().await;

    let loc = save(&pool, admin(), None, BACKUP_RULE).await;
    assert!(loc.contains("Only+superusers") || loc.contains("Only%20superusers"), "{loc}");
    assert!(rules(&pool).await.is_empty());

    save(&pool, su(), None, BACKUP_RULE).await;
    let r = rules(&pool).await;
    assert_eq!(r.len(), 1);
    let (id, scope, trigger, policy, threshold, enabled) = r[0].clone();
    assert_eq!((scope.as_str(), trigger.as_str(), policy, threshold, enabled),
               ("server", "backup_failed", None, 0.0, 1), "trigger and threshold come from the scope, not the form");

    // An admin may not edit, switch off or delete it.
    let loc = save(&pool, admin(), Some(id), "name=mine&enabled=on&scope_type=all_policies&trigger_type=drop&threshold=5&action_notify=on").await;
    assert!(loc.contains("Only+superusers"), "{loc}");
    let r = scmserver::alerts_admin::alerts_toggle(admin(), Extension(pool.clone()), Path(id)).await.into_response();
    assert!(r.headers()["location"].to_str().unwrap().contains("Only+superusers"));
    let r = scmserver::alerts_admin::alerts_delete(admin(), Extension(pool.clone()), Path(id)).await.into_response();
    assert!(r.headers()["location"].to_str().unwrap().contains("Only+superusers"));
    assert_eq!(rules(&pool).await, vec![(id, "server".into(), "backup_failed".into(), None, 0.0, 1)]);

    // The superuser can.
    let _ = scmserver::alerts_admin::alerts_toggle(su(), Extension(pool.clone()), Path(id)).await.into_response();
    assert_eq!(rules(&pool).await[0].5, 0);

    // The form offers "Server backups" to superusers only.
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let form = |who: AuthSession| {
        let (pool, tera) = (pool.clone(), tera.clone());
        async move {
            let q = Query(serde_json::from_value(serde_json::json!({})).unwrap());
            let r = scmserver::alerts_admin::alerts_form(who, q, Extension(pool), Extension(tera), None).await.into_response();
            String::from_utf8(axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
        }
    };
    assert!(form(su()).await.contains("value=\"server\""));
    assert!(!form(admin()).await.contains("value=\"server\""));
}

// A failed backup reaches the rule's actions with its own text: the bell, and
// a webhook carrying event "backup.failed". Score rules do not fire.
#[tokio::test]
async fn a_failed_backup_is_delivered_by_its_rules() {
    // As main.rs: rustls is built without a default provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = db().await;

    // A webhook receiver on loopback (allowed outside SaaS).
    let got: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
    let sink = got.clone();
    let app = Router::new().route("/hook", post(move |Json(v): Json<serde_json::Value>| {
        let sink = sink.clone();
        async move { sink.lock().unwrap().push(v); "ok" }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    save(&pool, su(), None, &format!("{BACKUP_RULE}&action_webhook=on&target_webhook={}", urlencoding::encode(&url))).await;
    // A score rule beside it, which a backup must not set off.
    sqlx::query("INSERT INTO policies (id, tenant_id, name) VALUES (1, 'default', 'CIS')").execute(&pool).await.unwrap();
    save(&pool, su(), None, "name=cis&enabled=on&scope_type=policy&policy_id=1&trigger_type=drop&threshold=5&action_notify=on").await;
    assert_eq!(rules(&pool).await.len(), 2);

    // A backup that fails: no passphrase file.
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    std::fs::write(keys.join("k"), general_purpose::STANDARD.encode(sk.to_bytes())).unwrap();
    let jobs = Backups::new(Paths {
        db: dir.path().join("scm.db"), private_key: keys.join("k"), public_key: keys.join("p"),
        config: dir.path().join("c"),
    }, dir.path().join("missing.passphrase"));
    assert!(jobs.run(&pool, Trigger::Scheduled).await.is_err());

    let queued: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT action, event, COALESCE(summary,''), alert_name FROM alert_deliveries ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(queued.len(), 2, "notify + webhook of the backup rule only: {queued:?}");
    assert!(queued.iter().all(|q| q.1 == "backup.failed" && q.2.starts_with("Backup failed: ") && q.3 == "backups"));

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notify").fetch_one(&pool).await.unwrap();
    scmserver::alert_delivery::deliver_pending(&pool).await;
    let status: Vec<String> = sqlx::query_scalar("SELECT status || ':' || COALESCE(last_error,'') FROM alert_deliveries ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(status, vec!["sent:", "sent:"]);

    let bell: Vec<String> = sqlx::query_scalar("SELECT message FROM notify ORDER BY id").fetch_all(&pool).await.unwrap();
    assert!(bell.len() as i64 > before);
    assert!(bell.iter().any(|m| m.starts_with("backups — Backup failed:")), "{bell:?}");

    let hooks = got.lock().unwrap().clone();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0]["event"], "backup.failed");
    assert_eq!(hooks[0]["alert"]["name"], "backups");
    assert!(hooks[0]["message"].as_str().unwrap().contains("set-passphrase"));
    assert!(hooks[0].get("score").is_none());
}
