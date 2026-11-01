// download_filenames.rs — free text never breaks a download's filename.
//
// The policy export put the policy's version straight into the
// Content-Disposition header. A version with a line break (possible through
// import or the API) made the header invalid, the response builder's unwrap
// panicked, and the download died with a dropped connection. Versions and
// system names now go through handlers::filename_part.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use scmserver::auth::{issue_session_cookie, SESSION_TTL};
use sqlx::SqlitePool;
use tower::ServiceExt;

fn key() -> Key { Key::from(&[7u8; 64]) }

// ─────────────────────────────────────────────────────────────────────────────
// Helper: export_disposition
// Exports a policy with the given version; the status and the
// Content-Disposition header.
// ─────────────────────────────────────────────────────────────────────────────
async fn export_disposition(version: &str) -> (StatusCode, String) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'CIS Linux', ?)")
        .bind(version).execute(&pool).await.unwrap();

    let session = serde_json::json!({ "username": "admin", "userid": "1", "tenant_id": "default", "role": "admin" });
    let cookie = issue_session_cookie(&pool, session, SESSION_TTL).await;
    let signed = (SignedCookieJar::new(key()).add(cookie), "").into_response();
    let cookie = signed.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    let app = Router::new()
        .route("/policies/export/{id}", get(scmserver::policies::policies_export))
        .layer(Extension(pool.clone()))
        .with_state(key());
    let resp = app
        .oneshot(Request::get("/policies/export/1").header("cookie", cookie).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let disposition = resp.headers().get("content-disposition")
        .map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    (resp.status(), disposition)
}

#[tokio::test]
async fn a_plain_version_keeps_its_filename() {
    let (status, disposition) = export_disposition("1.0.2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(disposition, r#"attachment; filename="cis-linux-1.0.2.json""#);
}

#[tokio::test]
async fn a_version_with_a_line_break_or_quote_still_exports() {
    let (status, disposition) = export_disposition("1.0\nbeta \"x\"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(disposition, r#"attachment; filename="cis-linux-1.0_beta__x_.json""#);
}
