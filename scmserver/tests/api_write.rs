// api_write.rs — the write endpoints of /api/v1beta1.
//
// Each does what its page button does, through the same function, with the
// same role; enforces SaaS plan limits like the pages; and records the write
// in the audit log as coming from the API. docs/design/0.12.0-rest-api.md,
// D3, D5, D6.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum_extra::extract::cookie::Key;
use scmserver::api::generate_token;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::{atomic::AtomicBool, Arc};
use tower::ServiceExt;

struct Fx { app: axum::Router, pool: SqlitePool, tok: std::collections::HashMap<&'static str, String> }

async fn fixture() -> Fx {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("DELETE FROM plan_limits").execute(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name, plan) VALUES ('acme', 'Acme', 'free'), ('globex', 'Globex', 'free')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (10, 'acme', 'alice', 'x', 'admin')",
        "INSERT INTO systems (id, tenant_id, name, status, ver, os, arch) VALUES
            (1, 'acme', 'web1', 'active', '0.9.0', 'Debian 12', 'x86_64'),
            (2, 'acme', 'new1', 'pending', '0.9.0', 'Debian 12', 'x86_64'),
            (9, 'globex', 'theirs', 'pending', '0.9.0', 'Debian 12', 'x86_64')",
        "INSERT INTO system_groups (id, tenant_id, name, auto_managed) VALUES (1, 'acme', 'web', 0), (2, 'acme', 'db', 0), (3, 'acme', 'auto', 1)",
        "INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES ('acme', 1, 1), ('acme', 1, 3)",
        "INSERT INTO tests (id, tenant_id, name) VALUES (5, 'acme', 'ssh')",
        "INSERT INTO policies (id, tenant_id, name, version) VALUES (7, 'acme', 'CIS', '1')",
        "INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('acme', 7, 5)",
        "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('acme', 7, 1)",
        "INSERT INTO results (tenant_id, system_id, test_id, result, last_updated, excluded) VALUES ('acme', 1, 5, 'FAIL', datetime('now'), 0)",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    let mut tok = std::collections::HashMap::new();
    for role in ["viewer", "runner", "editor", "admin"] {
        let (raw, hash, prefix) = generate_token();
        sqlx::query("INSERT INTO api_tokens (tenant_id, user_id, name, prefix, token_hash, role) VALUES ('acme', 10, ?, ?, ?, ?)")
            .bind(format!("{role}-token")).bind(prefix).bind(hash).bind(role).execute(&pool).await.unwrap();
        tok.insert(role, raw);
    }
    let (sync_tx, _rx) = tokio::sync::mpsc::channel(64);
    let app = scmserver::create_core_router(
        scmserver::AppState {
            pool: pool.clone(), tera: Arc::new(scmserver::init_tera().unwrap()),
            config: Arc::new(scmserver::config::Config::default()), sync_tx,
            is_initialized: Arc::new(AtomicBool::new(true)),
        },
        Key::from(&[7u8; 64]),
    );
    Fx { app, pool, tok }
}

async fn call(fx: &Fx, role: &str, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(format!("/api/v1beta1{path}"))
        .header("authorization", format!("Bearer {}", fx.tok[role]));
    let body = match body {
        Some(b) => { req = req.header("content-type", "application/json"); Body::from(b.to_string()) }
        None => Body::empty(),
    };
    let resp = fx.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let s = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn scalar(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&fx.pool).await.unwrap()
}

#[tokio::test]
async fn approving_needs_editor_is_audited_as_api_and_respects_the_plan() {
    let fx = fixture().await;
    assert_eq!(call(&fx, "runner", "POST", "/systems/2/approve", None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(call(&fx, "editor", "POST", "/systems/9/approve", None).await.0, StatusCode::NOT_FOUND, "another organization's");

    // The free plan allows one active system, and web1 is already active.
    sqlx::query("INSERT INTO plan_limits (plan, resource, max_count) VALUES ('free', 'systems', 1)").execute(&fx.pool).await.unwrap();
    let (s, v) = call(&fx, "editor", "POST", "/systems/2/approve", None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("plan_limit")), "{v}");
    sqlx::query("DELETE FROM plan_limits").execute(&fx.pool).await.unwrap();

    let (s, v) = call(&fx, "editor", "POST", "/systems/2/approve", None).await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("active")));
    let details: String = sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'system.approve'")
        .fetch_one(&fx.pool).await.unwrap();
    let d: Value = serde_json::from_str(&details).unwrap();
    assert_eq!((d["via"].as_str(), d["token"].as_str()), (Some("api"), Some("editor-token")));
}

#[tokio::test]
async fn deleting_a_system() {
    let fx = fixture().await;
    assert_eq!(call(&fx, "editor", "DELETE", "/systems/2", None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(scalar(&fx, "SELECT COUNT(*) FROM systems WHERE id = 2").await, 0);
    assert_eq!(call(&fx, "editor", "DELETE", "/systems/9", None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(scalar(&fx, "SELECT COUNT(*) FROM systems WHERE id = 9").await, 1, "another organization's is untouched");
}

#[tokio::test]
async fn setting_groups_replaces_manual_membership_only() {
    let fx = fixture().await;
    let (s, v) = call(&fx, "editor", "PUT", "/systems/1/groups", Some(json!({"groups": [2]}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let groups: Vec<i64> = sqlx::query_scalar("SELECT group_id FROM systems_in_groups WHERE system_id = 1 ORDER BY group_id")
        .fetch_all(&fx.pool).await.unwrap();
    assert_eq!(groups, [2, 3], "manual web → db; the automatic group stays");
    let (s, v) = call(&fx, "editor", "PUT", "/systems/1/groups", Some(json!({"groups": [3]}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = call(&fx, "editor", "PUT", "/systems/1/groups", Some(json!({"nope": 1}))).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_request")), "{v}");
}

#[tokio::test]
async fn queueing_an_upgrade_needs_admin_and_an_agent_to_offer() {
    let fx = fixture().await;
    assert_eq!(call(&fx, "editor", "POST", "/systems/1/upgrade", None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(call(&fx, "admin", "POST", "/systems/1/upgrade", None).await.0, StatusCode::CONFLICT, "nothing bundled");
    sqlx::query("INSERT INTO agent_packages (platform, version, sha256, url) VALUES ('x86_64-linux', '0.12.0', 'x', '/agents/a')")
        .execute(&fx.pool).await.unwrap();
    let (s, v) = call(&fx, "admin", "POST", "/systems/1/upgrade", None).await;
    assert_eq!((s, v["upgrade_to"].as_str()), (StatusCode::ACCEPTED, Some("0.12.0")));
    assert_eq!(scalar(&fx, "SELECT COUNT(*) FROM commands WHERE system_id = 1 AND command_type = 'UPGRADE'").await, 1);
}

#[tokio::test]
async fn excluding_and_restoring_a_finding() {
    let fx = fixture().await;
    let (s, v) = call(&fx, "editor", "PUT", "/systems/1/results/5/exclusion", Some(json!({"reason": "accepted risk"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (ex, reason): (i64, Option<String>) = sqlx::query_as("SELECT excluded, excluded_reason FROM results WHERE system_id = 1")
        .fetch_one(&fx.pool).await.unwrap();
    assert_eq!((ex, reason.as_deref()), (1, Some("accepted risk")));
    assert_eq!(call(&fx, "editor", "DELETE", "/systems/1/results/5/exclusion", None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(scalar(&fx, "SELECT excluded FROM results WHERE system_id = 1").await, 0);
    assert_eq!(call(&fx, "editor", "PUT", "/systems/2/results/5/exclusion", Some(json!({}))).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn running_a_policy_queues_its_tests() {
    let fx = fixture().await;
    assert_eq!(call(&fx, "viewer", "POST", "/policies/7/run", None).await.0, StatusCode::FORBIDDEN);
    let (s, _) = call(&fx, "runner", "POST", "/policies/7/run", None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(scalar(&fx, "SELECT COUNT(*) FROM commands WHERE system_id = 1 AND command_type = 'TEST' AND test_id = 5").await, 1);
    assert_eq!(call(&fx, "runner", "POST", "/policies/99/run", None).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn importing_a_policy_export() {
    let fx = fixture().await;
    let export = json!({
        "format_version": 3,
        "policy": {"external_id": "api-test-1", "name": "From the API", "version": "1.0", "description": null},
        "tests": [{"external_id": "t-1", "name": "nginx is not running", "description": null, "rational": null,
                   "remediation": null, "severity": "low", "filter": null, "app_filter": null,
                   "conditions": [{"type": "condition", "element": "PROCESS", "input": "nginx", "selement": "NAME",
                                   "condition": "NOT CONTAINS", "sinput": "nginx"}]}]
    });
    assert_eq!(call(&fx, "runner", "POST", "/policies/import", Some(export.clone())).await.0, StatusCode::FORBIDDEN);
    let (s, v) = call(&fx, "editor", "POST", "/policies/import", Some(export.clone())).await;
    assert_eq!((s, v["action"].as_str()), (StatusCode::CREATED, Some("imported")), "{v}");
    let (s, v) = call(&fx, "editor", "POST", "/policies/import", Some(export)).await;
    assert_eq!((s, v["action"].as_str()), (StatusCode::OK, Some("updated")), "{v}");
    let (s, v) = call(&fx, "editor", "POST", "/policies/import", Some(json!({"format_version": 99}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn saving_reports() {
    let fx = fixture().await;
    let (s, v) = call(&fx, "runner", "POST", "/reports/policy", Some(json!({"policy_id": 7}))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let id = v["id"].as_i64().unwrap();
    assert_eq!(call(&fx, "viewer", "GET", &format!("/reports/policy/{id}"), None).await.1["policy"]["name"], "CIS");
    let (s, v) = call(&fx, "runner", "POST", "/reports/system", Some(json!({"system_id": 1}))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(call(&fx, "runner", "POST", "/reports/system", Some(json!({"system_id": 9}))).await.0, StatusCode::NOT_FOUND);
    sqlx::query("INSERT INTO plan_limits (plan, resource, max_count) VALUES ('free', 'reports', 1)").execute(&fx.pool).await.unwrap();
    assert_eq!(call(&fx, "runner", "POST", "/reports/policy", Some(json!({"policy_id": 7}))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
}
