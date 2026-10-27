// api_read.rs — the read endpoints of /api/v1beta1.
//
// Lists page by cursor; nothing from another organization is ever visible
// (it is 404, not 403, so ids cannot be probed); compliance is the same data
// the pages and saved reports use. docs/design/0.12.0-rest-api.md, D2–D4.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum_extra::extract::cookie::Key;
use scmserver::api::generate_token;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::{atomic::AtomicBool, Arc};
use tower::ServiceExt;

struct Fx { app: axum::Router, viewer: String, admin: String }

async fn fixture() -> Fx {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme'), ('globex', 'Globex')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (10, 'acme', 'alice', 'x', 'admin')",
        "INSERT INTO systems (id, tenant_id, name, status, ver, os, arch, last_seen, compliance_score) VALUES
            (1, 'acme', 'web1', 'active', '0.12.0', 'Debian 12', 'x86_64', datetime('now'), 80.0),
            (2, 'acme', 'web2', 'active', '0.12.0', 'Debian 12', 'x86_64', datetime('now', '-3 hours'), 50.0),
            (3, 'acme', 'new1', 'pending', '0.12.0', 'Debian 12', 'x86_64', NULL, NULL),
            (9, 'globex', 'theirs', 'active', '0.12.0', 'Debian 12', 'x86_64', datetime('now'), 10.0)",
        "INSERT INTO system_groups (id, tenant_id, name) VALUES (1, 'acme', 'web'), (9, 'globex', 'g')",
        "INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES ('acme', 1, 1), ('acme', 2, 1)",
        "INSERT INTO tests (id, tenant_id, name, severity) VALUES (5, 'acme', 'ssh root login', 'high'), (95, 'globex', 'x', 'low')",
        "INSERT INTO test_conditions (tenant_id, test_id, `type`, element, input, selement, condition, sinput) VALUES
            ('acme', 5, 'condition', 'FILE', '/etc/ssh/sshd_config', 'CONTENT', 'CONTAINS', 'PermitRootLogin no'),
            ('acme', 5, 'applicability', 'OS', 'linux', 'NAME', 'CONTAINS', 'Linux')",
        "INSERT INTO policies (id, tenant_id, name, version) VALUES (7, 'acme', 'CIS', '1'), (97, 'globex', 'P', '1')",
        "INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('acme', 7, 5)",
        "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('acme', 7, 1)",
        "INSERT INTO results (tenant_id, system_id, test_id, result, last_updated, excluded) VALUES
            ('acme', 1, 5, 'PASS', datetime('now'), 0), ('acme', 2, 5, 'FAIL', datetime('now'), 0)",
        "INSERT INTO reports (id, tenant_id, policy_name, policy_version, submitter_name, tests_metadata, report_results)
            VALUES (4, 'acme', 'CIS', '1', 'alice', '[]', '[]')",
        "INSERT INTO audit_log (tenant_id, actor_username, action) VALUES ('acme', 'alice', 'system.approve'), ('acme', 'alice', 'auth.logout'), ('globex', 'eve', 'system.approve')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    // A saved system report, built the way the Save button builds it.
    let data = scmserver::systems::fetch_system_report_data(1, "acme", &pool).await.unwrap();
    sqlx::query("INSERT INTO system_reports (id, tenant_id, system_id, system_name, submitter_name, report_data)
                 VALUES (6, 'acme', 1, 'web1', 'alice', ?)")
        .bind(serde_json::to_string(&data).unwrap()).execute(&pool).await.unwrap();

    let mut toks = Vec::new();
    for role in ["viewer", "admin"] {
        let (raw, hash, prefix) = generate_token();
        sqlx::query("INSERT INTO api_tokens (tenant_id, user_id, name, prefix, token_hash, role) VALUES ('acme', 10, ?, ?, ?, ?)")
            .bind(role).bind(prefix).bind(hash).bind(role).execute(&pool).await.unwrap();
        toks.push(raw);
    }
    let (sync_tx, _rx) = tokio::sync::mpsc::channel(1);
    let app = scmserver::create_core_router(
        scmserver::AppState {
            pool, tera: Arc::new(scmserver::init_tera().unwrap()),
            config: Arc::new(scmserver::config::Config::default()), sync_tx,
            is_initialized: Arc::new(AtomicBool::new(true)),
        },
        Key::from(&[7u8; 64]),
    );
    Fx { app, viewer: toks.remove(0), admin: toks.remove(0) }
}

async fn get(fx: &Fx, tok: &str, path: &str) -> (StatusCode, Value, Vec<u8>) {
    let resp = fx.app.clone().oneshot(
        Request::get(format!("/api/v1beta1{path}")).header("authorization", format!("Bearer {tok}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null), bytes)
}

fn names(v: &Value) -> Vec<String> {
    v["data"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap_or("").to_string()).collect()
}

#[tokio::test]
async fn systems_page_by_cursor_and_only_this_organizations() {
    let fx = fixture().await;
    let (s, p1, _) = get(&fx, &fx.viewer, "/systems?limit=2").await;
    assert_eq!(s, StatusCode::OK, "{p1}");
    assert_eq!(names(&p1), ["web1", "web2"]);
    let cursor = p1["next_cursor"].as_str().expect("a second page");
    let (_, p2, _) = get(&fx, &fx.viewer, &format!("/systems?limit=2&cursor={cursor}")).await;
    assert_eq!(names(&p2), ["new1"], "and nothing from globex");
    assert!(p2["next_cursor"].is_null());

    assert_eq!(get(&fx, &fx.viewer, "/systems/9").await.0, StatusCode::NOT_FOUND, "another organization's system");
    assert_eq!(get(&fx, &fx.viewer, "/systems?cursor=%%%").await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn system_filters_and_fields() {
    let fx = fixture().await;
    assert_eq!(names(&get(&fx, &fx.viewer, "/systems?status=pending").await.1), ["new1"]);
    assert_eq!(names(&get(&fx, &fx.viewer, "/systems?group=1").await.1), ["web1", "web2"]);
    assert_eq!(get(&fx, &fx.viewer, "/systems?status=bogus").await.0, StatusCode::BAD_REQUEST);
    let (_, s1, _) = get(&fx, &fx.viewer, "/systems/1").await;
    assert_eq!(s1["online"], true);
    assert_eq!(s1["groups"][0]["name"], "web");
    assert_eq!(s1["compliance"]["score"], 80.0);
    assert!(s1["last_seen"].as_str().unwrap().ends_with('Z'));
    assert_eq!(get(&fx, &fx.viewer, "/systems/2").await.1["online"], false, "3 hours > 60 minutes");
    assert_eq!(get(&fx, &fx.viewer, "/systems/3").await.1["online"], true, "never seen is not offline");
}

#[tokio::test]
async fn compliance_is_the_report_data() {
    let fx = fixture().await;
    let (s, sys, _) = get(&fx, &fx.viewer, "/systems/1/compliance").await;
    assert_eq!(s, StatusCode::OK, "{sys}");
    assert_eq!(sys["system_name"], "web1");
    assert_eq!(sys["policy_groups"][0]["results"][0]["status"], "PASS", "{sys}");
    let (s, pol, _) = get(&fx, &fx.viewer, "/policies/7/compliance").await;
    assert_eq!(s, StatusCode::OK, "{pol}");
    let systems: Vec<&str> = pol["system_reports"].as_array().unwrap().iter()
        .map(|r| r["system_name"].as_str().unwrap()).collect();
    assert_eq!(systems.len(), 2, "{pol}");
    assert_eq!(get(&fx, &fx.viewer, "/policies/97/compliance").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn groups_tests_and_policies_carry_their_relations() {
    let fx = fixture().await;
    let (_, g, _) = get(&fx, &fx.viewer, "/groups/1").await;
    assert_eq!(g["member_count"], 2);
    assert_eq!(g["policies"][0]["name"], "CIS");
    let (_, t, _) = get(&fx, &fx.viewer, "/tests/5").await;
    assert_eq!(t["conditions"][0]["element"], "FILE");
    assert_eq!(t["applicability"][0]["element"], "OS");
    let (_, p, _) = get(&fx, &fx.viewer, "/policies/7").await;
    assert_eq!(p["tests"][0]["name"], "ssh root login");
    assert_eq!(p["groups"][0]["name"], "web");
    assert_eq!(names(&get(&fx, &fx.viewer, "/tests").await.1), ["ssh root login"]);
    assert_eq!(names(&get(&fx, &fx.viewer, "/groups").await.1), ["web"]);
    assert_eq!(get(&fx, &fx.viewer, "/tests/95").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn saved_reports_list_get_and_pdf() {
    let fx = fixture().await;
    let (_, pl, _) = get(&fx, &fx.viewer, "/reports/policy").await;
    assert_eq!(pl["data"][0]["policy"]["name"], "CIS");
    let (_, sl, _) = get(&fx, &fx.viewer, "/reports/system").await;
    assert_eq!(sl["data"][0]["system"]["name"], "web1");
    let (_, one, _) = get(&fx, &fx.viewer, "/reports/system/6").await;
    assert_eq!(one["report"]["system_name"], "web1");
    let (s, _, pdf) = get(&fx, &fx.viewer, "/reports/system/6/pdf").await;
    assert_eq!(s, StatusCode::OK);
    assert!(pdf.starts_with(b"%PDF"));
    let (s, _, pdf) = get(&fx, &fx.viewer, "/reports/policy/4/pdf").await;
    assert_eq!(s, StatusCode::OK);
    assert!(pdf.starts_with(b"%PDF"));
    assert_eq!(get(&fx, &fx.viewer, "/reports/bogus").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_audit_log_needs_admin_and_filters() {
    let fx = fixture().await;
    let (s, v, _) = get(&fx, &fx.viewer, "/audit-log").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v, _) = get(&fx, &fx.admin, "/audit-log?action=system.").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let actions: Vec<&str> = v["data"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["system.approve"], "filtered, and nothing from globex");
}
