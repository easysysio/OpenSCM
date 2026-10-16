// login_rate_limit.rs — repeated failed sign-ins lock the account and the
// address.
//
// The limits are process-wide, and every test in this file shares the
// process, so each test uses its own usernames and client addresses.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::routing::post;
use axum::{Extension, Router};
use axum_extra::extract::cookie::Key;
use scmserver::rate_limit::{Limiter, LOGIN_ACCOUNT_MAX, LOGIN_ADDRESS_MAX};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// Users named in `users`, all in the default tenant, password
// "correct-horse" at bcrypt cost 4.
// ─────────────────────────────────────────────────────────────────────────────
async fn db(users: &[&str]) -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let hash = bcrypt::hash("correct-horse", 4).unwrap();
    for u in users {
        sqlx::query("INSERT INTO users (tenant_id, username, password, role) VALUES ('default', ?, ?, 'admin')")
            .bind(u).bind(&hash).execute(&pool).await.unwrap();
    }
    pool
}

struct Outcome {
    location: String,
    signed_in: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: login
// POSTs the login form through the real handler, as a connection from `from`.
// ─────────────────────────────────────────────────────────────────────────────
async fn login(pool: &SqlitePool, from: &str, user: &str, password: &str) -> Outcome {
    let app = Router::new()
        .route("/login", post(scmserver::auth::login_submit))
        .layer(Extension(pool.clone()))
        .with_state(Key::from(&[7u8; 64]));
    let mut req = Request::post("/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("username={user}&password={password}")))
        .unwrap();
    let addr: SocketAddr = format!("{from}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    let resp = app.oneshot(req).await.unwrap();
    Outcome {
        location: resp.headers().get("location").unwrap().to_str().unwrap().to_string(),
        signed_in: resp.headers().get_all("set-cookie").iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("session=")),
    }
}

fn is_rate_limited(o: &Outcome) -> bool {
    o.location.contains("Too%20many%20failed%20sign-in%20attempts")
}

async fn locks(pool: &SqlitePool, details: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login_locked' AND details = ?")
        .bind(details).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn an_account_locks_after_repeated_wrong_passwords_even_from_new_addresses() {
    let pool = db(&["carol"]).await;
    for i in 0..LOGIN_ACCOUNT_MAX {
        // A different address each time: the account limit must not care.
        let o = login(&pool, &format!("198.51.100.{}", i + 1), "carol", "wrong").await;
        assert!(!is_rate_limited(&o), "attempt {i} refused too early");
    }
    let o = login(&pool, "198.51.100.200", "carol", "correct-horse").await;
    assert!(is_rate_limited(&o), "the right password got through a lock: {}", o.location);
    assert!(!o.signed_in);
    assert_eq!(locks(&pool, "account").await, 1, "the lock is logged once");
}

#[tokio::test]
async fn an_address_locks_after_failures_across_many_usernames() {
    let pool = db(&["dave"]).await;
    for i in 0..LOGIN_ADDRESS_MAX {
        // Unknown usernames: spraying names must count too.
        let o = login(&pool, "203.0.113.50", &format!("nobody{i}"), "wrong").await;
        assert!(!is_rate_limited(&o), "attempt {i} refused too early");
    }
    let o = login(&pool, "203.0.113.50", "dave", "correct-horse").await;
    assert!(is_rate_limited(&o), "{}", o.location);
    assert_eq!(locks(&pool, "address").await, 1);

    // The same user from somewhere else is fine.
    let o = login(&pool, "203.0.113.51", "dave", "correct-horse").await;
    assert!(o.signed_in, "{}", o.location);
}

#[tokio::test]
async fn a_successful_sign_in_resets_the_account_count() {
    let pool = db(&["erin"]).await;
    for _ in 0..LOGIN_ACCOUNT_MAX - 1 {
        login(&pool, "192.0.2.10", "erin", "wrong").await;
    }
    assert!(login(&pool, "192.0.2.10", "erin", "correct-horse").await.signed_in);
    for _ in 0..LOGIN_ACCOUNT_MAX - 1 {
        login(&pool, "192.0.2.10", "erin", "wrong").await;
    }
    let o = login(&pool, "192.0.2.10", "erin", "correct-horse").await;
    assert!(o.signed_in, "count was not reset by the earlier success: {}", o.location);
}

#[test]
fn a_lock_ends_after_the_lockout_and_counting_starts_again() {
    let l = Limiter::new(3, Duration::from_secs(60), Duration::from_secs(300));
    let t0 = Instant::now();
    assert!(!l.record_at("k", t0));
    assert!(!l.record_at("k", t0 + Duration::from_secs(1)));
    assert!(l.record_at("k", t0 + Duration::from_secs(2)), "third event locks");
    assert!(l.locked_at("k", t0 + Duration::from_secs(10)).is_some());
    assert!(l.locked_at("k", t0 + Duration::from_secs(303)).is_none(), "lock ends");
    // A fresh count after the lock: one event does not re-lock.
    assert!(!l.record_at("k", t0 + Duration::from_secs(303)));
    assert!(l.locked_at("k", t0 + Duration::from_secs(304)).is_none());
}

#[test]
fn old_events_fall_out_of_the_window() {
    let l = Limiter::new(3, Duration::from_secs(60), Duration::from_secs(300));
    let t0 = Instant::now();
    l.record_at("k", t0);
    l.record_at("k", t0 + Duration::from_secs(1));
    // The first two are more than a minute old by now.
    assert!(!l.record_at("k", t0 + Duration::from_secs(120)));
    assert!(l.locked_at("k", t0 + Duration::from_secs(121)).is_none());
}

#[test]
fn spellings_of_one_organization_share_a_count() {
    use scmserver::rate_limit::login_account_key;
    assert_eq!(login_account_key(Some("Acme Inc"), "bob"), login_account_key(Some("acme-inc"), "bob"));
    assert_ne!(login_account_key(Some("acme"), "bob"), login_account_key(Some("acme"), "Bob"));
}

#[test]
fn the_retry_message_rounds_up() {
    use scmserver::rate_limit::retry_message;
    assert_eq!(retry_message("x", Duration::from_secs(1)), "Too many x. Try again in 1 minute.");
    assert_eq!(retry_message("x", Duration::from_secs(61)), "Too many x. Try again in 2 minutes.");
}
