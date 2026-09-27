// login_account_state.rs — the password is not the only thing login checks.
//
// Before 0.9.4, login_submit only checked an organization's suspension when
// the form named that organization. Leaving the field out fell back to a
// username-only lookup that skipped the check, so a suspended SaaS
// organization could still sign in with a direct POST. And the
// email_verified flag written at SaaS registration was never read at all.
// This file also checks the timing fix: an unknown username must cost as much
// as a wrong password.

use axum::body::Body;
use axum::http::Request;
use axum::routing::post;
use axum::{Extension, Router};
use axum_extra::extract::cookie::Key;
use sqlx::SqlitePool;
use std::time::Instant;
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// alice (default tenant) and bob (tenant 'acme'), both with password
// "correct-horse". Cost 4 keeps the tests quick where timing is not measured.
// ─────────────────────────────────────────────────────────────────────────────
async fn db(cost: u32) -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let hash = bcrypt::hash("correct-horse", cost).unwrap();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')")
        .execute(&pool).await.unwrap();
    for (id, tenant, user) in [(10, "default", "alice"), (20, "acme", "bob")] {
        sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES (?, ?, ?, ?, 'admin')")
            .bind(id).bind(tenant).bind(user).bind(&hash)
            .execute(&pool).await.unwrap();
    }
    pool
}

struct Outcome {
    location: String,
    session_cookie: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: login
// POSTs the login form through the real handler.
// ─────────────────────────────────────────────────────────────────────────────
async fn login(pool: &SqlitePool, form: &str) -> Outcome {
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
    Outcome {
        location: resp.headers().get("location").unwrap().to_str().unwrap().to_string(),
        session_cookie: resp.headers().get_all("set-cookie").iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("session=")),
    }
}

#[tokio::test]
async fn a_valid_login_is_accepted() {
    let pool = db(4).await;
    let o = login(&pool, "username=alice&password=correct-horse").await;
    assert_eq!(o.location, "/");
    assert!(o.session_cookie);
}

#[tokio::test]
async fn a_wrong_password_is_refused() {
    let pool = db(4).await;
    let o = login(&pool, "username=alice&password=wrong").await;
    assert!(o.location.contains("Invalid"));
    assert!(!o.session_cookie);
}

// The bypass: no organization field → username-only lookup → no suspension check.
#[tokio::test]
async fn a_suspended_organization_cannot_sign_in_by_omitting_the_organization() {
    let pool = db(4).await;
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = 'acme'")
        .execute(&pool).await.unwrap();

    let without = login(&pool, "username=bob&password=correct-horse").await;
    assert!(without.location.contains("suspended"), "got {}", without.location);
    assert!(!without.session_cookie, "no session may be issued");

    let with = login(&pool, "organization=Acme&username=bob&password=correct-horse").await;
    assert!(with.location.contains("suspended"), "got {}", with.location);
    assert!(!with.session_cookie);
}

#[tokio::test]
async fn an_unverified_email_cannot_sign_in() {
    let pool = db(4).await;
    sqlx::query("UPDATE users SET email_verified = 0 WHERE id = 20").execute(&pool).await.unwrap();

    let o = login(&pool, "organization=Acme&username=bob&password=correct-horse").await;
    assert!(o.location.contains("confirm"), "got {}", o.location);
    assert!(!o.session_cookie);
}

// Account state is only disclosed to someone holding the password.
#[tokio::test]
async fn account_state_is_not_disclosed_without_the_password() {
    let pool = db(4).await;
    sqlx::query("UPDATE users SET email_verified = 0 WHERE id = 20").execute(&pool).await.unwrap();
    let o = login(&pool, "organization=Acme&username=bob&password=wrong").await;
    assert!(o.location.contains("Invalid"), "got {}", o.location);
    assert!(!o.location.contains("confirm"));
}

// An unknown username must cost roughly what a wrong password costs. The
// malformed dummy hash answered unknown users ~1000x faster.
#[tokio::test]
async fn unknown_users_take_as_long_as_wrong_passwords() {
    let pool = db(bcrypt::DEFAULT_COST).await;
    let _ = scmserver::auth::dummy_hash(); // as create_core_router does

    let t = Instant::now();
    login(&pool, "username=alice&password=wrong").await;
    let known = t.elapsed();

    let t = Instant::now();
    login(&pool, "username=nobody&password=wrong").await;
    let unknown = t.elapsed();

    assert!(
        unknown.as_secs_f64() > known.as_secs_f64() * 0.5,
        "unknown user answered in {unknown:?} vs {known:?} for a wrong password"
    );
}
