// fix_runs.rs — queued fix scripts reach the agent and its report is kept
// (1.1.0 remediation, step 2; docs/design/1.1.0-remediation.md §4).
//
// Drives the real /send and /fix_result handlers with signed requests:
//   • the heartbeat stores the agent's cmd_enabled / ps_enabled
//   • a queued fix goes out once, with its hash, timeout and test
//   • agents before 1.1.0 (no settings reported) are never sent fixes
//   • a fix nobody picks up expires after 24 hours
//   • only the system a fix was sent to can report it, once, signed

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Extension, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::SqlitePool;
use tower::ServiceExt;

const SCRIPT: &str = "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n";

// ─────────────────────────────────────────────────────────────────────────────
// Helper: setup
// Active systems 1 and 2 (keys returned in that order) and test 7 with one
// condition and one applicability rule.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup() -> (SqlitePool, SigningKey, SigningKey) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let mut keys = Vec::new();
    for id in [1, 2] {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        sqlx::query("INSERT INTO systems (id, tenant_id, key, name, status) VALUES (?, 'default', ?, ?, 'active')")
            .bind(id).bind(STANDARD.encode(key.verifying_key().to_bytes())).bind(format!("host{id}"))
            .execute(&pool).await.unwrap();
        keys.push(key);
    }
    sqlx::query("INSERT INTO tests (id, tenant_id, name, severity, filter, app_filter, fix_sh)
                 VALUES (7, 'default', 'SSH root login off', 'High', 'all', 'all', ?)")
        .bind(SCRIPT).execute(&pool).await.unwrap();
    for (kind, element) in [("condition", "FILE"), ("applicability", "OS")] {
        sqlx::query("INSERT INTO test_conditions (tenant_id, test_id, type, element, input, selement, condition, sinput)
                     VALUES ('default', 7, ?, ?, '/etc/ssh/sshd_config', 'CONTENT', 'contains', 'PermitRootLogin no')")
            .bind(kind).bind(element).execute(&pool).await.unwrap();
    }
    let k2 = keys.pop().unwrap();
    (pool, keys.pop().unwrap(), k2)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: queue
// Queues the test's shell script for `system`, as the Fix button will.
// ─────────────────────────────────────────────────────────────────────────────
async fn queue(pool: &SqlitePool, system: i64) -> i64 {
    sqlx::query("INSERT INTO fix_runs (tenant_id, system_id, test_id, kind, script, script_sha256, requested_by)
                 VALUES ('default', ?, 7, 'sh', ?, ?, 1)")
        .bind(system).bind(SCRIPT).bind(scmserver::fixes::script_sha256(SCRIPT))
        .execute(pool).await.unwrap()
        .last_insert_rowid()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: post_signed
// POSTs `payload` signed by `key` to `path`; returns status and JSON body.
// ─────────────────────────────────────────────────────────────────────────────
async fn post_signed(pool: &SqlitePool, path: &str, key: &SigningKey, payload: serde_json::Value)
    -> (StatusCode, serde_json::Value)
{
    let payload = payload.to_string();
    let signature = STANDARD.encode(key.sign(payload.as_bytes()).to_bytes());
    let body = format!(r#"{{"payload":{payload},"signature":"{signature}"}}"#);
    let app = Router::new()
        .route("/send", post(scmserver::client::send))
        .route("/fix_result", post(scmserver::client::receive_fix_result))
        .layer(Extension(pool.clone()));
    let resp = app
        .oneshot(Request::post(path).header("content-type", "application/json").body(Body::from(body)).unwrap())
        .await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: heartbeat
// One heartbeat from `system`; `settings` adds cmd_enabled / ps_enabled the
// way a 1.1.0 agent sends them. Returns the signed reply's payload.
// ─────────────────────────────────────────────────────────────────────────────
async fn heartbeat(pool: &SqlitePool, system: i64, key: &SigningKey, settings: Option<(bool, bool)>) -> serde_json::Value {
    let mut p = serde_json::json!({
        "id": system.to_string(), "organization": "", "hostname": format!("host{system}"), "ver": "1.1.0",
        "ip": "10.0.0.20", "os": "Linux", "arch": "x86_64", "timestamp": "2026-11-07T12:00:00Z"
    });
    if let Some((cmd, ps)) = settings {
        p["cmd_enabled"] = cmd.into();
        p["ps_enabled"] = ps.into();
    }
    let (status, body) = post_signed(pool, "/send", key, p).await;
    assert_eq!(status, StatusCode::OK, "heartbeat rejected: {body}");
    body["payload"].clone()
}

fn report(system: i64, fix_id: i64, status: &str) -> serde_json::Value {
    serde_json::json!({
        "client_id": system, "organization": "", "fix_id": fix_id,
        "status": status, "exit_code": 0, "output": "reloaded sshd"
    })
}

async fn status_of(pool: &SqlitePool, fix_id: i64) -> String {
    sqlx::query_scalar("SELECT status FROM fix_runs WHERE id = ?").bind(fix_id).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn the_heartbeat_stores_what_the_agent_allows() {
    let (pool, k1, _) = setup().await;
    heartbeat(&pool, 1, &k1, Some((true, false))).await;
    let flags: (Option<bool>, Option<bool>) = sqlx::query_as("SELECT cmd_enabled, ps_enabled FROM systems WHERE id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(flags, (Some(true), Some(false)));

    // An agent before 1.1.0 reports nothing: unknown again.
    heartbeat(&pool, 1, &k1, None).await;
    let flags: (Option<bool>, Option<bool>) = sqlx::query_as("SELECT cmd_enabled, ps_enabled FROM systems WHERE id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(flags, (None, None));
}

#[tokio::test]
async fn a_queued_fix_goes_out_once_with_its_hash_and_test() {
    let (pool, k1, _) = setup().await;
    let reply = heartbeat(&pool, 1, &k1, Some((true, false))).await;
    assert!(reply.get("fixes").is_none(), "no `fixes` field when nothing is queued: {reply}");

    let id = queue(&pool, 1).await;
    let reply = heartbeat(&pool, 1, &k1, Some((true, false))).await;
    let fixes = reply["fixes"].as_array().expect("fixes");
    assert_eq!(fixes.len(), 1);
    let f = &fixes[0];
    assert_eq!(f["id"], id);
    assert_eq!(f["kind"], "sh");
    assert_eq!(f["script"], SCRIPT);
    assert_eq!(f["sha256"], scmserver::fixes::script_sha256(SCRIPT));
    assert_eq!(f["timeout_secs"], 300);
    assert_eq!(f["test"]["id"], 7);
    assert_eq!(f["test"]["conditions"].as_array().unwrap().len(), 1);
    assert_eq!(f["test"]["applicability"].as_array().unwrap().len(), 1);
    assert_eq!(status_of(&pool, id).await, "sent");

    let reply = heartbeat(&pool, 1, &k1, Some((true, false))).await;
    assert!(reply.get("fixes").is_none(), "sent twice: {reply}");
}

#[tokio::test]
async fn an_agent_before_1_1_is_never_sent_a_fix() {
    let (pool, k1, _) = setup().await;
    let id = queue(&pool, 1).await;
    let reply = heartbeat(&pool, 1, &k1, None).await;
    assert!(reply.get("fixes").is_none(), "{reply}");
    assert_eq!(status_of(&pool, id).await, "queued");
}

#[tokio::test]
async fn a_fix_nobody_picks_up_expires_after_a_day() {
    let (pool, k1, _) = setup().await;
    let id = queue(&pool, 1).await;
    sqlx::query("UPDATE fix_runs SET requested_at = datetime('now', '-25 hours') WHERE id = ?")
        .bind(id).execute(&pool).await.unwrap();
    let reply = heartbeat(&pool, 1, &k1, Some((true, false))).await;
    assert!(reply.get("fixes").is_none(), "{reply}");
    assert_eq!(status_of(&pool, id).await, "expired");
}

#[tokio::test]
async fn the_agents_report_is_stored_and_audited() {
    let (pool, k1, _) = setup().await;
    let id = queue(&pool, 1).await;
    heartbeat(&pool, 1, &k1, Some((true, false))).await;

    let (status, body) = post_signed(&pool, "/fix_result", &k1, report(1, id, "done")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let row: (String, Option<i64>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, exit_code, output, finished_at FROM fix_runs WHERE id = ?",
    ).bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!((row.0.as_str(), row.1, row.2.as_deref()), ("done", Some(0), Some("reloaded sshd")));
    assert!(row.3.is_some(), "finished_at set");

    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'fix.result'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(audited, 1);

    // Once only.
    let (status, _) = post_signed(&pool, "/fix_result", &k1, report(1, id, "failed")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(status_of(&pool, id).await, "done");
}

#[tokio::test]
async fn only_the_system_a_fix_was_sent_to_can_report_it() {
    let (pool, k1, k2) = setup().await;
    let id = queue(&pool, 1).await;

    // Not sent yet: nobody can report it.
    let (status, _) = post_signed(&pool, "/fix_result", &k1, report(1, id, "done")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    heartbeat(&pool, 1, &k1, Some((true, false))).await;
    // Another system, correctly signed with its own key.
    let (status, _) = post_signed(&pool, "/fix_result", &k2, report(2, id, "done")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // System 1's id, signed with another key.
    let (status, _) = post_signed(&pool, "/fix_result", &k2, report(1, id, "done")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A status that is not an outcome.
    let (status, _) = post_signed(&pool, "/fix_result", &k1, report(1, id, "queued")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert_eq!(status_of(&pool, id).await, "sent");
}
