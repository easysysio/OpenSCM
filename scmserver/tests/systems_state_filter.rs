// systems_state_filter.rs — Systems page: show online or offline systems (1.1.5).
//
// The Systems Inventory gets a "Show" list (All / Online / Offline). Each row
// carries data-state from the server, by the same offline threshold as the
// Offline badge; pending systems are neither. Bulk actions take every ticked
// system the filter shows, not only the page on screen.

use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use scmserver::models::AuthSession;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: page
// Renders /systems with three systems: one seen a minute ago, one seen two
// hours ago (threshold 60 minutes), one pending. Returns the HTML.
// ─────────────────────────────────────────────────────────────────────────────
async fn page() -> String {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')",
        "INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'offline_threshold', '60')",
        "INSERT INTO systems (id, tenant_id, name, status, last_seen) VALUES (1, 'default', 'up-host', 'active', datetime('now', '-1 minutes'))",
        "INSERT INTO systems (id, tenant_id, name, status, last_seen) VALUES (2, 'default', 'gone-host', 'active', datetime('now', '-2 hours'))",
        "INSERT INTO systems (id, tenant_id, name, status) VALUES (3, 'default', 'new-host', 'pending')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    let admin = AuthSession { username: "admin".into(), userid: 1, tenant_id: "default".into(),
                              role: "admin".into(), impersonating: None };
    let resp = scmserver::systems::systems(
        admin, Query(HashMap::new()), Extension(pool), Extension(Arc::new(scmserver::init_tera().unwrap())),
    ).await.into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

// The data-state of the row for system `id`.
fn state_of(html: &str, id: i64) -> String {
    let row = html.split("<tr ").find(|r| r.contains(&format!("data-system-id=\"{id}\""))).expect("row");
    row.split("data-state=\"").nth(1).unwrap().split('"').next().unwrap().to_string()
}

#[tokio::test]
async fn each_row_says_whether_the_system_is_online() {
    let html = page().await;
    assert_eq!(state_of(&html, 1), "online");
    assert_eq!(state_of(&html, 2), "offline");
    assert_eq!(state_of(&html, 3), "pending", "a pending system is neither online nor offline");
}

#[tokio::test]
async fn the_page_offers_the_filter_and_bulk_actions_see_every_page() {
    let html = page().await;
    for opt in [r#"<select id="state-filter""#, r#"<option value="online">Online</option>"#,
                r#"<option value="offline">Offline</option>"#] {
        assert!(html.contains(opt), "missing {opt}");
    }
    assert!(html.contains("table.rows({ search: 'applied' }).nodes()).find('.row-checkbox:checked')"),
            "bulk actions must take the ticked rows of every page");
    assert!(!html.contains("return $('.row-checkbox:checked')"), "the page-only selector is back");
}
