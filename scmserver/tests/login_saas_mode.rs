// login_saas_mode.rs — in SaaS, login requires the organization.
//
// Kept in its own test binary: SaaS mode is a process-wide switch with no way
// back, and would change the behaviour of every CE-mode test sharing a process.

use axum::body::Body;
use axum::http::Request;
use axum::routing::post;
use axum::{Extension, Router};
use axum_extra::extract::cookie::Key;
use sqlx::SqlitePool;
use tower::ServiceExt;

async fn location(pool: &SqlitePool, form: &str) -> String {
    let app = Router::new()
        .route("/login", post(scmserver::auth::login_submit))
        .layer(Extension(pool.clone()))
        .with_state(Key::from(&[7u8; 64]));
    let resp = app
        .oneshot(
            Request::post("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
}

#[tokio::test]
async fn saas_login_requires_the_organization() {
    scmserver::handlers::enable_saas_mode();

    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES (20, 'acme', 'bob', ?, 'admin')")
        .bind(bcrypt::hash("correct-horse", 4).unwrap())
        .execute(&pool).await.unwrap();

    for form in ["username=bob&password=correct-horse", "organization=+&username=bob&password=correct-horse"] {
        let to = location(&pool, form).await;
        assert!(to.contains("Organization+is+required"), "{form:?} → {to}");
    }
    assert_eq!(location(&pool, "organization=Acme&username=bob&password=correct-horse").await, "/");
}
