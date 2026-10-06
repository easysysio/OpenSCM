// report_diff_params.rs — the comparison pages cope with a bad query string.
//
// /reports/diff and /reports/system/diff take ?a=<id>&b=<id>. Opened without
// them, or with something that is not a number, the request was rejected
// before the handler ran and the user saw a bare "400 Bad Request" page. They
// are now sent back to the Reports list with a message.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use axum::response::IntoResponse;
use scmserver::auth::{issue_session_cookie, SESSION_TTL};
use sqlx::SqlitePool;
use std::sync::Arc;
use tower::ServiceExt;

async fn get_page(path: &str) -> (StatusCode, String) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')")
        .execute(&pool).await.unwrap();

    let key = Key::from(&[7u8; 64]);
    let session = serde_json::json!({ "username": "admin", "userid": "1", "tenant_id": "default", "role": "admin" });
    let cookie = issue_session_cookie(&pool, session, SESSION_TTL).await;
    let signed = (SignedCookieJar::new(key.clone()).add(cookie), "").into_response();
    let cookie_header = signed.headers().get("set-cookie").unwrap().to_str().unwrap()
        .split(';').next().unwrap().to_string();

    let app = Router::new()
        .route("/reports/diff", get(scmserver::reports::reports_diff))
        .route("/reports/system/diff", get(scmserver::reports::system_reports_diff))
        .layer(Extension(pool))
        .layer(Extension(Arc::new(scmserver::init_tera().unwrap())))
        .with_state(key);
    let resp = app
        .oneshot(Request::get(path).header("cookie", cookie_header).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let to = resp.headers().get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    (resp.status(), to)
}

#[tokio::test]
async fn a_missing_or_malformed_pair_returns_to_the_reports_list() {
    for base in ["/reports/diff", "/reports/system/diff"] {
        for query in ["", "?a=1", "?b=2", "?a=one&b=two", "?a=1&b=", "?a=1.5&b=2"] {
            let (status, to) = get_page(&format!("{base}{query}")).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "{base}{query}");
            assert!(to.starts_with("/reports?error_message=Pick+two+snapshots"), "{base}{query} → {to}");
        }
    }
}

// The messages that already existed are unchanged.
#[tokio::test]
async fn the_existing_cases_still_answer_as_before() {
    for base in ["/reports/diff", "/reports/system/diff"] {
        let (_, to) = get_page(&format!("{base}?a=1&b=1")).await;
        assert!(to.contains("two+different+snapshots"), "{to}");
        let (status, to) = get_page(&format!("{base}?a=1&b=2")).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(to.contains("error_message"), "two ids that do not exist: {to}");
    }
}
