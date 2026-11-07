// test_delete.rs — deleting a test that is in policies (1.1.0).
//
// Deleting a test removes it from every policy it is in. The delete dialog
// (tests list and edit page) names those policies first, and the deletion is
// recorded in the audit log as test.delete with the policies it left.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use scmserver::auth::{issue_session_cookie, SESSION_TTL};
use scmserver::tests::delete_warning;
use sqlx::SqlitePool;
use std::sync::{atomic::AtomicBool, Arc};
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────────
// fixture — test 5 in policies "CIS" and "Patch <&> Mgmt", test 6 in none;
// returns the router, the pool and an admin session cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn fixture() -> (axum::Router, SqlitePool, String) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')",
        "INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'CIS', '1'), (2, 'default', 'Patch <&> Mgmt', '1')",
        "INSERT INTO tests (id, tenant_id, name, severity, filter, app_filter) VALUES (5, 'default', 'ssh root', 'High', 'all', 'all'), (6, 'default', 'lonely', 'Low', 'all', 'all')",
        "INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('default', 1, 5), ('default', 2, 5)",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap();
    }
    let key = Key::from(&[7u8; 64]);
    let session = serde_json::json!({ "username": "admin", "userid": "1", "tenant_id": "default", "role": "admin" });
    let cookie = issue_session_cookie(&pool, session, SESSION_TTL).await;
    let signed = (SignedCookieJar::new(key.clone()).add(cookie), "").into_response();
    let cookie = signed.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let (sync_tx, _rx) = tokio::sync::mpsc::channel(8);
    let app = scmserver::create_core_router(
        scmserver::AppState {
            pool: pool.clone(), tera: Arc::new(scmserver::init_tera().unwrap()),
            config: Arc::new(scmserver::config::Config::default()), sync_tx,
            is_initialized: Arc::new(AtomicBool::new(true)),
        },
        key,
    );
    (app, pool, cookie)
}

async fn send(app: &axum::Router, cookie: &str, method: &str, path: &str) -> (StatusCode, String) {
    let resp = app.clone().oneshot(
        Request::builder().method(method).uri(path).header("cookie", cookie).body(Body::empty()).unwrap(),
    ).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[test]
fn the_warning_names_the_policies() {
    assert_eq!(delete_warning(&[]),
        "Delete this test? It is not in any policy. Its results on every system are lost. This cannot be undone.");
    assert_eq!(delete_warning(&[(1, "CIS".into())]),
        "This test is in 1 policy: CIS. Deleting it removes it from that policy. Its results on every system are lost. This cannot be undone.");
    assert!(delete_warning(&[(1, "A".into()), (2, "B".into())])
        .starts_with("This test is in 2 policies: A, B. Deleting it removes it from them."));
}

// Both dialogs carry the warning in data-confirm (escaped, set as text by
// confirmAction), not inside the onclick JavaScript.
#[tokio::test]
async fn both_delete_dialogs_name_the_policies() {
    let (app, _pool, cookie) = fixture().await;
    let (s, list) = send(&app, &cookie, "GET", "/tests").await;
    assert_eq!(s, StatusCode::OK);
    assert!(list.contains("This test is in 2 policies: CIS, Patch &lt;&amp;&gt; Mgmt."), "names escaped");
    assert!(list.contains("It is not in any policy."), "test 6");
    assert!(list.contains("this.dataset.confirm); return false;"));
    let (s, edit) = send(&app, &cookie, "GET", "/tests/edit/5").await;
    assert_eq!(s, StatusCode::OK);
    assert!(edit.contains(r#"data-confirm="This test is in 2 policies: CIS, Patch &lt;&amp;&gt; Mgmt."#));
}

#[tokio::test]
async fn deleting_is_audited_with_the_policies_it_left() {
    let (app, pool, cookie) = fixture().await;
    let (s, _) = send(&app, &cookie, "POST", "/tests/delete/5").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tests_in_policy WHERE test_id = 5")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(left, 0, "removed from its policies");
    let (actor, target, details): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT actor_username, target_id, details FROM audit_log WHERE action = 'test.delete'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!((actor.as_str(), target.as_deref()), ("admin", Some("5")));
    let d: serde_json::Value = serde_json::from_str(&details.unwrap()).unwrap();
    assert_eq!(d, serde_json::json!({"name": "ssh root", "removed_from_policies": [
        {"id": 1, "name": "CIS"}, {"id": 2, "name": "Patch <&> Mgmt"}]}));

    // A test that does not exist (or another organization's) leaves no entry.
    send(&app, &cookie, "POST", "/tests/delete/999").await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'test.delete'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(n, 1);
}

// Bulk delete: each checkbox carries its test's policies for the dialog, and
// every deleted test gets its own audit entry.
#[tokio::test]
async fn bulk_delete_warns_and_audits_each_test() {
    let (app, pool, cookie) = fixture().await;
    let (_, list) = send(&app, &cookie, "GET", "/tests").await;
    assert!(list.contains(r#"value="5" title="Select" data-policies="[&quot;CIS&quot;,&quot;Patch &lt;&amp;&gt; Mgmt&quot;]""#), "escaped JSON");
    assert!(list.contains(r#"value="6" title="Select" data-policies="[]""#));

    let resp = app.clone().oneshot(
        Request::post("/tests/bulk/delete").header("cookie", &cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("ids=5&ids=6&ids=999")).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(resp.headers()["location"].to_str().unwrap().contains("2%20test%28s%29%20deleted"), "999 is not counted");
    let rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT target_id FROM audit_log WHERE action = 'test.delete' ORDER BY target_id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(rows, vec![(Some("5".into()),), (Some("6".into()),)]);
}
