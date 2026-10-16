// common/headers.rs — shared router harness for the security header tests.

use axum::body::Body;
use axum::http::Request;
use axum_extra::extract::cookie::Key;
use sqlx::SqlitePool;
use std::sync::{atomic::AtomicBool, Arc};
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: app
// The full CE router over an installed in-memory database whose App URL is
// the given value.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn app(app_url: &str) -> axum::Router {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', ?)")
        .bind(app_url).execute(&pool).await.unwrap();
    let (sync_tx, _rx) = tokio::sync::mpsc::channel(1);
    let state = scmserver::AppState {
        pool,
        tera: Arc::new(scmserver::init_tera().unwrap()),
        config: Arc::new(scmserver::config::Config::default()),
        sync_tx,
        is_initialized: Arc::new(AtomicBool::new(true)),
    };
    scmserver::create_core_router(state, Key::from(&[7u8; 64]))
}

pub async fn headers(app: axum::Router, path: &str) -> axum::http::HeaderMap {
    app.oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await.unwrap().headers().clone()
}
