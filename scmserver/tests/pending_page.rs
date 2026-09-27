// pending_page.rs — the Pending Systems page renders.
//
// systems_pending renders systems.html but never supplied `groups`, which the
// page's bulk "Add to Group" dialog has looped over since 0.1.9. Tera fails on
// an undefined variable, so /systems/pending returned 500 on every install.
// These call the real handlers and require a rendered page.

use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use scmserver::models::AuthSession;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')",
        "INSERT INTO systems (id, tenant_id, name, status) VALUES (1, 'default', 'waiting-host', 'pending')",
        "INSERT INTO systems (id, tenant_id, name, status) VALUES (2, 'default', 'running-host', 'active')",
        "INSERT INTO system_groups (id, tenant_id, name) VALUES (1, 'default', 'Web servers')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    pool
}

fn admin() -> AuthSession {
    AuthSession {
        username: "admin".into(), userid: 1, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    }
}

async fn body(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn the_pending_page_renders_with_its_systems_and_the_group_picker() {
    let pool = db().await;
    let tera = Arc::new(scmserver::init_tera().unwrap());

    let resp = scmserver::systems::systems_pending(
        admin(),
        Query(serde_json::from_value(serde_json::json!({})).unwrap()),
        Extension(pool.clone()),
        Extension(tera),
    ).await.into_response();

    let (status, html) = body(resp).await;
    assert_eq!(status, StatusCode::OK, "pending page failed to render");
    assert!(html.contains("waiting-host"), "the pending system must be listed");
    assert!(!html.contains("running-host"), "an active system is not pending");
    assert!(html.contains("Web servers"), "the Add to Group dialog must list manual groups");
}

// The main list shares the template; keep it rendering too.
#[tokio::test]
async fn the_systems_page_still_renders() {
    let pool = db().await;
    let tera = Arc::new(scmserver::init_tera().unwrap());

    let resp = scmserver::systems::systems(
        admin(),
        Query(HashMap::new()),
        Extension(pool.clone()),
        Extension(tera),
    ).await.into_response();

    let (status, html) = body(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("running-host"));
    assert!(html.contains("Web servers"));
}
