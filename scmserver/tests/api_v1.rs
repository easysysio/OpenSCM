// api_v1.rs — /api/v1 (docs/design/1.0.0-api-v1.md).
//
// v1 serves the same routes as v1beta1 with answers an integration can use
// without decoding twice or guessing: scores rounded or null, one timestamp
// format, evidence as JSON, checked_at on every live result, both kinds of
// policy count, audit details always an object, a resume point on every
// list, and the policy id of a saved report. v1beta1 keeps answering exactly
// as before, marked deprecated.

use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum_extra::extract::cookie::Key;
use scmserver::api::generate_token;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::{atomic::AtomicBool, Arc};
use tower::ServiceExt;

struct Fx {
    app: axum::Router,
    pool: SqlitePool,
    tokens: BTreeMap<&'static str, String>,
    policy_report: i64,
    system_report: i64,
}

const EVIDENCE: &str = r#"[{"phase":"condition","element":"FILE","input":"/etc/ssh/sshd_config","selement":"CONTENT","operator":"CONTAINS","expected":"PermitRootLogin no","result":"PASS","note":"found"}]"#;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: fixture
// Organization acme: policy 7 (tests 5, 6, 7) over group 1 (web1, web2),
// a pending system, a container on web1, audit entries with text, JSON and
// no details, and one saved report of each kind. Globex holds things acme
// must never see.
//   web1 — t5 PASS, t6 FAIL, t7 FAIL     → 33.33, failing; container t5 FAIL
//   web2 — t5 FAIL excluded, t6 PASS     → compliant; t7 never reported
// ─────────────────────────────────────────────────────────────────────────────
async fn fixture() -> Fx {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme'), ('globex', 'Globex')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (10, 'acme', 'alice', 'x', 'admin')",
        "INSERT INTO systems (id, tenant_id, name, status, ver, os, arch, last_seen) VALUES
            (1, 'acme', 'web1', 'active', '0.13.0', 'Debian 12', 'x86_64', datetime('now')),
            (2, 'acme', 'web2', 'active', '0.13.0', 'Debian 12', 'x86_64', datetime('now', '-3 hours')),
            (3, 'acme', 'new1', 'pending', '0.13.0', 'Debian 12', 'x86_64', NULL),
            (9, 'globex', 'theirs', 'active', '0.13.0', 'Debian 12', 'x86_64', datetime('now'))",
        "INSERT INTO containers (id, tenant_id, host_system_id, runtime, runtime_id, name, image)
            VALUES (1, 'acme', 1, 'docker', 'abc123', 'nginx', 'nginx:1.27')",
        "INSERT INTO system_groups (id, tenant_id, name) VALUES (1, 'acme', 'web')",
        "INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES ('acme', 1, 1), ('acme', 2, 1), ('acme', 3, 1)",
        "INSERT INTO tests (id, tenant_id, name, severity, rational) VALUES
            (5, 'acme', 'ssh root login', 'high', 'Root over SSH is a shared account'),
            (6, 'acme', 'firewall', 'high', NULL), (7, 'acme', 'auditd', 'medium', '')",
        "INSERT INTO policies (id, tenant_id, name, version, description) VALUES (7, 'acme', 'CIS', '1', 'Baseline')",
        "INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('acme', 7, 5), ('acme', 7, 6), ('acme', 7, 7)",
        "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('acme', 7, 1)",
        "INSERT INTO results (tenant_id, system_id, test_id, container_id, result, last_updated, excluded, excluded_reason, evidence) VALUES
            ('acme', 1, 5, 0, 'PASS', '2026-10-29T19:43:00', 0, NULL, '__EVIDENCE__'),
            ('acme', 1, 6, 0, 'FAIL', '2026-10-29T19:43:05', 0, NULL, NULL),
            ('acme', 1, 7, 0, 'FAIL', '2026-10-29T19:43:06', 0, NULL, NULL),
            ('acme', 1, 5, 1, 'FAIL', '2026-10-29T19:44:00', 0, NULL, NULL),
            ('acme', 2, 5, 0, 'FAIL', '2026-10-29T19:45:00', 1, 'Bastion host', NULL),
            ('acme', 2, 6, 0, 'PASS', '2026-10-29T19:45:01', 0, NULL, NULL)",
        "INSERT INTO audit_log (id, tenant_id, actor_username, action, details) VALUES
            (1, 'acme', 'alice', 'auth.login', 'Logged in from the web'),
            (2, 'acme', 'alice', 'system.approve', '{\"via\":\"api\",\"token\":\"ci\"}'),
            (3, 'acme', 'alice', 'auth.logout', NULL),
            (4, 'globex', 'eve', 'auth.login', 'theirs')",
        // Saved before v51: no policy id on record.
        "INSERT INTO reports (id, tenant_id, policy_name, policy_version, submitter_name, tests_metadata, report_results)
            VALUES (1, 'acme', 'Gone', '1', 'alice', '[]', '[]')",
    ] {
        let q = q.replace("__EVIDENCE__", EVIDENCE);
        sqlx::query(&q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    scmserver::scheduler::recalculate_current_compliance(&pool).await.unwrap();
    let policy_report = scmserver::reports::save_policy_report(7, &pool, "acme", "alice").await.unwrap().unwrap();
    let (system_report, _) = scmserver::reports::save_system_report(1, &pool, "acme", "alice").await.unwrap().unwrap();

    let mut tokens = BTreeMap::new();
    for role in ["viewer", "runner", "admin"] {
        let (raw, hash, prefix) = generate_token();
        sqlx::query("INSERT INTO api_tokens (tenant_id, user_id, name, prefix, token_hash, role) VALUES ('acme', 10, ?, ?, ?, ?)")
            .bind(role).bind(prefix).bind(hash).bind(role).execute(&pool).await.unwrap();
        tokens.insert(role, raw);
    }
    let (sync_tx, _rx) = tokio::sync::mpsc::channel(8);
    let app = scmserver::create_core_router(
        scmserver::AppState {
            pool: pool.clone(), tera: Arc::new(scmserver::init_tera().unwrap()),
            config: Arc::new(scmserver::config::Config::default()), sync_tx,
            is_initialized: Arc::new(AtomicBool::new(true)),
        },
        Key::from(&[7u8; 64]),
    );
    Fx { app, pool, tokens, policy_report, system_report }
}

async fn call(fx: &Fx, role: &str, method: &str, url: &str) -> (StatusCode, HeaderMap, Value) {
    let resp = fx.app.clone().oneshot(
        Request::builder().method(method).uri(url)
            .header("authorization", format!("Bearer {}", fx.tokens[role]))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn v1(fx: &Fx, role: &str, path: &str) -> Value {
    let (s, h, v) = call(fx, role, "GET", &format!("/api/v1{path}")).await;
    assert_eq!(s, StatusCode::OK, "{path}: {v}");
    assert!(h.get("deprecation").is_none(), "{path}: v1 is not deprecated");
    v
}

async fn beta(fx: &Fx, role: &str, path: &str) -> Value {
    let (s, h, v) = call(fx, role, "GET", &format!("/api/v1beta1{path}")).await;
    assert_eq!(s, StatusCode::OK, "{path}: {v}");
    assert_eq!(h.get("deprecation").map(|v| v.to_str().unwrap()), Some("true"), "{path}");
    assert!(h.get("link").unwrap().to_str().unwrap().contains("rel=\"deprecation\""), "{path}");
    v
}

// The GET routes of api::router, read the same way tests/api_spec.rs does.
fn get_routes() -> BTreeSet<String> {
    let src = include_str!("../src/api/mod.rs");
    let body = &src[src.find("pub fn router").unwrap()..];
    let route = regex::Regex::new(r#"\.route\(&p\("([^"]+)"\),\s*get\("#).unwrap();
    route.captures_iter(body).map(|c| c[1].to_string()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: sweep
// Walks a response and fails on anything v1 promises not to do (D3–D5, D8).
// Returns how many timestamps and scores it checked.
// ─────────────────────────────────────────────────────────────────────────────
fn sweep(path: &str, key: &str, v: &Value, seen: &mut (usize, usize)) {
    let iso = regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$").unwrap();
    let datey = regex::Regex::new(r"\d{4}-\d\d-\d\d").unwrap();
    if key.ends_with("_at") {
        assert!(v.is_null() || v.as_str().is_some_and(|s| iso.is_match(s)), "{path}: {key} = {v}");
        if !v.is_null() { seen.0 += 1; }
    } else if let Some(s) = v.as_str() {
        assert!(!datey.is_match(s), "{path}: {key} holds a date but is not named *_at: {s}");
    }
    if key.contains("score") && !v.is_object() {
        if let Some(n) = v.as_f64() {
            assert!(n >= 0.0, "{path}: {key} = {n}: not scanned must be null");
            assert!(((n * 100.0).round() - n * 100.0).abs() < 1e-6, "{path}: {key} = {n}: more than 2 decimals");
            seen.1 += 1;
        } else {
            assert!(v.is_null(), "{path}: {key} = {v}");
        }
    }
    if key == "evidence" { assert!(v.is_null() || v.is_array(), "{path}: evidence = {v}"); }
    if key == "details" { assert!(v.is_null() || v.is_object(), "{path}: details = {v}"); }
    match v {
        Value::Object(o) => for (k, x) in o { sweep(path, k, x, seen) },
        // Elements are checked as values, not as the field that holds them.
        Value::Array(a) => for x in a { sweep(path, "[]", x, seen) },
        _ => {}
    }
}

#[tokio::test]
async fn every_v1_read_keeps_the_format_promises() {
    let fx = fixture().await;
    let (pr, sr) = (fx.policy_report.to_string(), fx.system_report.to_string());
    let concrete: BTreeMap<&str, String> = [
        ("/me", "/me".to_string()),
        ("/systems", "/systems".into()),
        ("/systems/{id}", "/systems/1".into()),
        ("/systems/{id}/compliance", "/systems/1/compliance".into()),
        ("/groups", "/groups".into()),
        ("/groups/{id}", "/groups/1".into()),
        ("/tests", "/tests".into()),
        ("/tests/{id}", "/tests/5".into()),
        ("/policies", "/policies".into()),
        ("/policies/{id}", "/policies/7".into()),
        ("/policies/{id}/compliance", "/policies/7/compliance".into()),
        ("/reports/{kind}", "/reports/policy".into()),
        ("/reports/{kind}/{id}", format!("/reports/policy/{pr}")),
        ("/audit-log", "/audit-log".into()),
    ].into_iter().collect();
    // A GET route added later must be added here too.
    let routes = get_routes();
    let expected: BTreeSet<String> = routes.iter().filter(|r| !r.ends_with("/pdf")).cloned().collect();
    let covered: BTreeSet<String> = concrete.keys().map(|k| k.to_string()).collect();
    assert_eq!(covered, expected, "every JSON GET route is swept");

    let mut seen = (0, 0);
    let mut paths: Vec<String> = concrete.values().cloned().collect();
    paths.extend(["/systems/2/compliance".into(), "/systems/3".into(), "/reports/system".into(),
                  format!("/reports/system/{sr}")]);
    for path in paths {
        let v = v1(&fx, "admin", &path).await;
        sweep(&path, "", &v, &mut seen);
    }
    assert!(seen.0 >= 20 && seen.1 >= 10, "the sweep saw too little to mean anything: {seen:?}");
}

#[tokio::test]
async fn scores_are_rounded_and_not_scanned_is_null() {
    let fx = fixture().await;
    let raw: f64 = sqlx::query_scalar("SELECT compliance_score FROM systems WHERE id = 1").fetch_one(&fx.pool).await.unwrap();
    assert!((raw - 33.333).abs() < 0.01, "fixture: web1 scores 1 of 3, got {raw}");
    assert_eq!(v1(&fx, "viewer", "/systems/1").await["compliance"]["score"], 33.33);
    assert!(v1(&fx, "viewer", "/systems/3").await["compliance"]["score"].is_null(), "pending, never scanned");
    assert_eq!(v1(&fx, "viewer", "/systems/1/compliance").await["compliance_score"], 33.33);
    assert_eq!(v1(&fx, "viewer", "/policies/7").await["compliance"]["score"], 50.0);
}

#[tokio::test]
async fn results_carry_evidence_as_json_and_when_they_were_checked() {
    let fx = fixture().await;
    let sys = v1(&fx, "viewer", "/systems/1/compliance").await;
    assert!(sys["generated_at"].is_string());
    assert!(sys["last_seen_at"].is_string() && sys.get("last_seen").is_none(), "{sys}");
    let results = sys["policy_groups"][0]["results"].as_array().unwrap();
    let t5 = results.iter().find(|r| r["test_id"] == 5).unwrap();
    assert_eq!(t5["evidence"][0]["result"], "PASS", "{t5}");
    assert_eq!(t5["checked_at"], "2026-10-29T19:43:00Z");
    assert!(t5.get("is_excludable").is_none(), "a page-only hint");
    let t6 = results.iter().find(|r| r["test_id"] == 6).unwrap();
    assert!(t6["evidence"].is_null() && t6["excluded_reason"].is_null(), "present even when empty: {t6}");
    assert_eq!(t6["checked_at"], "2026-10-29T19:43:05Z");
    let c = &sys["containers"][0]["results"][0];
    assert_eq!(c["checked_at"], "2026-10-29T19:44:00Z", "container results by their own row: {c}");

    let web2 = v1(&fx, "viewer", "/systems/2/compliance").await;
    let r2 = web2["policy_groups"][0]["results"].as_array().unwrap();
    let t7 = r2.iter().find(|r| r["test_id"] == 7).unwrap();
    assert_eq!(t7["status"], "NOT_SCANNED");
    assert!(t7.as_object().unwrap().contains_key("checked_at") && t7["checked_at"].is_null(), "{t7}");
    let t5 = r2.iter().find(|r| r["test_id"] == 5).unwrap();
    assert_eq!((t5["is_excluded"].clone(), t5["excluded_reason"].clone()), (Value::from(true), Value::from("Bastion host")));

    // The live policy report: the same per-host lookup.
    let pol = v1(&fx, "viewer", "/policies/7/compliance").await;
    let web1 = pol["system_reports"].as_array().unwrap().iter().find(|s| s["system_name"] == "web1").unwrap();
    assert_eq!(web1["system_id"], 1);
    let t6 = web1["results"].as_array().unwrap().iter().find(|r| r["test_id"] == 6).unwrap();
    assert_eq!(t6["checked_at"], "2026-10-29T19:43:05Z");

    // Saved snapshots never stored it: absent, not null.
    let saved = v1(&fx, "viewer", &format!("/reports/system/{}", fx.system_report)).await;
    assert!(saved["report"]["policy_groups"][0]["results"].as_array().unwrap().iter().all(|r| r.get("checked_at").is_none()));
    let saved = v1(&fx, "viewer", &format!("/reports/policy/{}", fx.policy_report)).await;
    assert!(saved["systems"].as_array().unwrap().iter()
        .flat_map(|s| s["results"].as_array().unwrap()).all(|r| r.get("checked_at").is_none()), "{saved}");
}

#[tokio::test]
async fn the_live_policy_report_has_no_submitter_and_names_ids() {
    let fx = fixture().await;
    let pol = v1(&fx, "viewer", "/policies/7/compliance").await;
    assert!(pol.get("submitter_name").is_none() && pol.get("submission_date").is_none(), "{pol}");
    assert!(pol["generated_at"].is_string());
    assert_eq!(pol["tests_metadata"][0]["rationale"], "Root over SSH is a shared account");
    assert!(pol["tests_metadata"][0].get("rational").is_none());
    assert!(pol["system_reports"].as_array().unwrap().iter().all(|s| s["system_id"].is_i64()), "{pol}");
}

#[tokio::test]
async fn policy_counts_say_what_they_count_in_either_mode() {
    let fx = fixture().await;
    for mode in ["test", "system"] {
        sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('acme', 'policy_compliance_mode', ?)")
            .bind(mode).execute(&fx.pool).await.unwrap();
        scmserver::scheduler::recalculate_current_compliance(&fx.pool).await.unwrap();
        let c = v1(&fx, "viewer", "/policies/7").await["compliance"].clone();
        assert_eq!(c["scoring_mode"], mode);
        assert_eq!((c["systems"]["passed"].clone(), c["systems"]["failed"].clone()), (1.into(), 1.into()), "{mode}: {c}");
        assert_eq!((c["tests"]["passed"].clone(), c["tests"]["failed"].clone()), (2.into(), 2.into()), "{mode}: {c}");
        assert!(c.get("systems_passed").is_none());
        let listed = v1(&fx, "viewer", "/policies").await;
        assert_eq!(listed["data"][0]["compliance"], c);
    }
    let t = v1(&fx, "viewer", "/tests/6").await["compliance"].clone();
    assert_eq!((t["systems"]["passed"].clone(), t["systems"]["failed"].clone()), (1.into(), 1.into()), "{t}");
}

#[tokio::test]
async fn audit_details_are_always_an_object() {
    let fx = fixture().await;
    let log = v1(&fx, "admin", "/audit-log").await;
    let d: Vec<&Value> = log["data"].as_array().unwrap().iter().map(|e| &e["details"]).collect();
    assert_eq!(d[0]["message"], "Logged in from the web");
    assert_eq!(d[1]["via"], "api");
    assert!(d[2].is_null());
    assert_eq!(d.len(), 3, "nothing from globex");
    assert!(log["data"][0]["created_at"].is_string() && log["data"][0].get("at").is_none());
}

#[tokio::test]
async fn resume_cursor_returns_only_what_is_new() {
    let fx = fixture().await;
    let first = v1(&fx, "admin", "/audit-log?limit=2").await;
    assert!(first["next_cursor"].is_string());
    let all = v1(&fx, "admin", "/audit-log").await;
    assert!(all["next_cursor"].is_null());
    let resume = all["resume_cursor"].as_str().expect("present on the last page").to_string();

    // Nothing new: an empty page that hands back the same resume point.
    let none = v1(&fx, "admin", &format!("/audit-log?cursor={resume}")).await;
    assert_eq!(none["data"].as_array().unwrap().len(), 0);
    assert_eq!(none["resume_cursor"], resume.as_str());

    sqlx::query("INSERT INTO audit_log (tenant_id, actor_username, action) VALUES ('acme', 'alice', 'policy.run')")
        .execute(&fx.pool).await.unwrap();
    let new = v1(&fx, "admin", &format!("/audit-log?cursor={resume}")).await;
    let actions: Vec<&str> = new["data"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["policy.run"]);
    assert_ne!(new["resume_cursor"], resume.as_str());

    // Every list has one, even with nothing in it.
    assert!(v1(&fx, "viewer", "/systems?status=active&group=99").await["resume_cursor"].is_string());
    for path in ["/systems", "/groups", "/tests", "/policies", "/reports/policy", "/reports/system"] {
        assert!(v1(&fx, "viewer", path).await["resume_cursor"].is_string(), "{path}");
    }
}

#[tokio::test]
async fn a_run_says_when_it_was_queued_and_where() {
    let fx = fixture().await;
    let (s, _, v) = call(&fx, "runner", "POST", "/api/v1/policies/7/run").await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let queued_at = v["queued_at"].as_str().unwrap();
    assert!(regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$").unwrap().is_match(queued_at));
    let systems: Vec<(i64, bool)> = v["systems"].as_array().unwrap().iter()
        .map(|s| (s["id"].as_i64().unwrap(), s["online"].as_bool().unwrap())).collect();
    assert_eq!(systems, [(1, true), (2, false)], "active systems in scope; the pending one is not reached");

    // Older results are older than the run, by plain string comparison.
    let sys = v1(&fx, "viewer", "/systems/1/compliance").await;
    let checked = sys["policy_groups"][0]["results"][0]["checked_at"].as_str().unwrap().to_string();
    assert!(checked.as_str() < queued_at);
    // A verdict received from now on counts as this run's.
    sqlx::query("UPDATE results SET last_updated = strftime('%Y-%m-%dT%H:%M:%S', 'now') WHERE system_id = 1 AND test_id = 5 AND container_id = 0")
        .execute(&fx.pool).await.unwrap();
    let sys = v1(&fx, "viewer", "/systems/1/compliance").await;
    let t5 = sys["policy_groups"][0]["results"].as_array().unwrap().iter().find(|r| r["test_id"] == 5).unwrap().clone();
    assert!(t5["checked_at"].as_str().unwrap() >= queued_at, "{t5} vs {queued_at}");
}

#[tokio::test]
async fn saved_policy_reports_name_their_policy() {
    let fx = fixture().await;
    let list = v1(&fx, "viewer", "/reports/policy").await;
    let ids: Vec<Value> = list["data"].as_array().unwrap().iter().map(|r| r["policy"]["id"].clone()).collect();
    assert_eq!(ids, [Value::Null, Value::from(7)], "the pre-v51 report has none on record");
    let one = v1(&fx, "viewer", &format!("/reports/policy/{}", fx.policy_report)).await;
    assert_eq!(one["policy"]["id"], 7);
    assert!(one["tests"][0].get("rationale").is_some(), "{one}");
}

// A policy report saved now names each result's system and test; one saved
// before 1.0 has no ids on record; the beta's answer does not change.
#[tokio::test]
async fn saved_policy_reports_name_systems_and_tests() {
    let fx = fixture().await;
    let one = v1(&fx, "viewer", &format!("/reports/policy/{}", fx.policy_report)).await;
    let mut seen = Vec::new();
    for s in one["systems"].as_array().unwrap() {
        let sid = &s["system_id"];
        for r in s["results"].as_array().unwrap() {
            assert_eq!(&r["system_id"], sid, "{s}");
            seen.push((r["system_id"].as_i64().unwrap(), r["test_id"].as_i64().unwrap(), r["status"].as_str().unwrap().to_string()));
        }
    }
    seen.sort();
    assert_eq!(seen, [(1, 5, "PASS".into()), (1, 6, "FAIL".into()), (1, 7, "FAIL".into()),
                      (2, 5, "FAIL".into()), (2, 6, "PASS".into())], "{one}");

    // Saved before 1.0: the snapshot has names only.
    sqlx::query("UPDATE reports SET report_results = ? WHERE id = 1")
        .bind(r#"[{"system_name":"web1","results":[{"test_name":"ssh root login","status":"PASS"}],"is_passed":true}]"#)
        .execute(&fx.pool).await.unwrap();
    let old = v1(&fx, "viewer", "/reports/policy/1").await;
    assert!(old["systems"][0]["system_id"].is_null() && old["systems"][0]["results"][0]["test_id"].is_null(), "{old}");

    let b = beta(&fx, "viewer", &format!("/reports/policy/{}", fx.policy_report)).await;
    for r in b["systems"].as_array().unwrap().iter().flat_map(|s| s["results"].as_array().unwrap()) {
        assert!(r.get("system_id").is_none() && r.get("test_id").is_none(), "{r}");
    }
}

// The compliance answer's last_seen_at is to the second, as on /systems/{id};
// the report data it is built from holds it to the minute.
#[tokio::test]
async fn the_compliance_answer_gives_last_seen_to_the_second() {
    let fx = fixture().await;
    sqlx::query("UPDATE systems SET last_seen = strftime('%Y-%m-%d %H:%M:42', 'now', '-1 minutes') WHERE id = 1")
        .execute(&fx.pool).await.unwrap();
    let sys = v1(&fx, "viewer", "/systems/1").await;
    assert!(sys["last_seen_at"].as_str().unwrap().ends_with(":42Z"), "{sys}");
    assert_eq!(v1(&fx, "viewer", "/systems/1/compliance").await["last_seen_at"], sys["last_seen_at"]);
    assert!(beta(&fx, "viewer", "/systems/1/compliance").await["last_seen"].as_str().unwrap().ends_with("UTC"),
            "the beta keeps the page's text");
}

// Empty test text is null in every v1 answer, whether stored as NULL (test 6)
// or "" (test 7); text that is there is kept (test 5).
#[tokio::test]
async fn empty_test_text_is_null_everywhere() {
    let fx = fixture().await;
    let empty = |t: &Value| ["description", "rationale", "remediation"].iter().all(|k| t[*k].is_null());
    for id in [6, 7] {
        let t = v1(&fx, "viewer", &format!("/tests/{id}")).await;
        assert!(empty(&t), "{t}");
    }
    assert_eq!(v1(&fx, "viewer", "/tests/5").await["rationale"], "Root over SSH is a shared account");
    for t in v1(&fx, "viewer", "/tests").await["data"].as_array().unwrap() {
        assert_eq!(empty(t), t["id"] != 5, "{t}");
    }
    let live = v1(&fx, "viewer", "/policies/7/compliance").await["tests_metadata"].clone();
    let saved = v1(&fx, "viewer", &format!("/reports/policy/{}", fx.policy_report)).await["tests"].clone();
    for metas in [live, saved] {
        let metas = metas.as_array().unwrap();
        assert_eq!(metas.len(), 3);
        for m in metas {
            if m["name"] == "ssh root login" {
                assert_eq!(m["rationale"], "Root over SSH is a shared account");
            } else {
                assert!(empty(m), "{m}");
            }
        }
    }
    assert_eq!(beta(&fx, "viewer", "/tests/7").await["rationale"], "", "the beta passes the stored value through");
}

#[tokio::test]
async fn v1beta1_answers_as_before_and_says_it_is_deprecated() {
    let fx = fixture().await;
    let s = beta(&fx, "viewer", "/systems/1").await;
    assert!(s["compliance"]["score"].as_f64().unwrap() != 33.33, "unrounded, as 0.12.0 shipped it");
    assert!(s.get("last_seen").is_some() && s.get("last_seen_at").is_none());
    assert!(beta(&fx, "viewer", "/systems").await.get("resume_cursor").is_none());
    let sys = beta(&fx, "viewer", "/systems/1/compliance").await;
    let t5 = sys["policy_groups"][0]["results"].as_array().unwrap().iter().find(|r| r["test_id"] == 5).unwrap().clone();
    assert!(t5["evidence"].is_string() && t5.get("checked_at").is_none(), "{t5}");
    assert!(sys["last_seen"].as_str().unwrap().ends_with("UTC"));
    let pol = beta(&fx, "viewer", "/policies/7/compliance").await;
    assert!(pol.get("submitter_name").is_some() && pol.get("generated_at").is_none());
    let p = beta(&fx, "viewer", "/policies/7").await;
    assert!(p["compliance"].get("systems_passed").is_some() && p["compliance"].get("tests").is_none());
    let log = beta(&fx, "admin", "/audit-log").await;
    assert_eq!(log["data"][0]["details"], "Logged in from the web");
    assert!(log["data"][0].get("at").is_some());
    assert!(beta(&fx, "viewer", "/reports/policy").await["data"][1]["policy"].get("id").is_none());
    let (s, h, v) = call(&fx, "runner", "POST", "/api/v1beta1/policies/7/run").await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v, serde_json::json!({"policy_id": 7, "queued": true}));
    assert!(h.get("deprecation").is_some());
}
