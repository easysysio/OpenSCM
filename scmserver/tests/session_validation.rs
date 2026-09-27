// session_validation.rs — a session is only as good as the account behind it.
//
// Sessions are signed cookies. Before 0.9.4 the signature was the only check:
// the role inside the cookie was trusted, nothing in the signed value said
// when it expired (Max-Age only instructs the browser), and nothing consulted
// the database. Deleting, demoting or re-passwording a user, or suspending
// their organization, changed nothing for a session already open, and a copied
// cookie worked indefinitely.
//
// These tests drive the real AuthSession extractor through a small router, so
// they cover the whole path: signature, then validate_session against the
// database, then the role the handler actually sees.

use axum::body::Body;
use axum::extract::{Extension, Form, Path};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use scmserver::auth::{issue_session_cookie, revoke_sessions, SESSION_TTL};
use scmserver::models::AuthSession;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// A default-tenant admin (id 10), a second tenant 'acme' with an admin (id 20),
// and a default-tenant superuser (id 30) for impersonation.
// ─────────────────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (10, 'default', 'alice', 'x', 'admin')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (20, 'acme', 'bob', 'x', 'admin')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (30, 'default', 'root', 'x', 'superuser')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap();
    }
    pool
}

fn key() -> Key {
    Key::from(&[7u8; 64])
}

fn login(userid: i64, tenant: &str) -> Value {
    json!({ "username": "whoever", "userid": userid.to_string(), "tenant_id": tenant, "role": "admin" })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: signed
// Signs a cookie the way the server does and returns the Cookie header value.
// ─────────────────────────────────────────────────────────────────────────────
fn signed(cookie: Cookie<'static>) -> String {
    let resp = (SignedCookieJar::new(key()).add(cookie), "").into_response();
    let set = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    set.split(';').next().unwrap().to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: whoami
// Requests a route guarded by AuthSession; Some("user:role:tenant") if let in,
// None if redirected to /login.
// ─────────────────────────────────────────────────────────────────────────────
async fn whoami(pool: &SqlitePool, cookie_header: &str) -> Option<String> {
    async fn me(a: AuthSession) -> String {
        format!("{}:{}:{}", a.username, a.role, a.tenant_id)
    }
    let app = Router::new()
        .route("/me", get(me))
        .layer(Extension(pool.clone()))
        .with_state(key());
    let resp = app
        .oneshot(Request::get("/me").header("cookie", cookie_header).body(Body::empty()).unwrap())
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        return None;
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    Some(String::from_utf8(bytes.to_vec()).unwrap())
}

async fn fresh(pool: &SqlitePool, userid: i64, tenant: &str) -> String {
    signed(issue_session_cookie(pool, login(userid, tenant), SESSION_TTL).await)
}

#[tokio::test]
async fn a_fresh_session_is_accepted_with_the_database_identity() {
    let pool = db().await;
    let c = fresh(&pool, 10, "default").await;
    // Username and role come from the users row, not the cookie.
    assert_eq!(whoami(&pool, &c).await.as_deref(), Some("alice:admin:default"));
}

// A cookie from before 0.9.4 carries no expiry or epoch; it must not be
// grandfathered in, or the fix does nothing for cookies already stolen.
#[tokio::test]
async fn a_pre_094_cookie_is_refused() {
    let pool = db().await;
    let old = Cookie::new("session", login(10, "default").to_string());
    assert_eq!(whoami(&pool, &signed(old)).await, None);
}

#[tokio::test]
async fn an_expired_session_is_refused_even_though_the_signature_is_valid() {
    let pool = db().await;
    let mut v = login(10, "default");
    let now = chrono::Utc::now().timestamp();
    v["iat"] = json!(now - 9 * 3600);
    v["exp"] = json!(now - 3600);
    v["epoch"] = json!(0);
    assert_eq!(whoami(&pool, &signed(Cookie::new("session", v.to_string()))).await, None);
}

#[tokio::test]
async fn deleting_the_user_ends_their_session() {
    let pool = db().await;
    let c = fresh(&pool, 10, "default").await;
    sqlx::query("DELETE FROM users WHERE id = 10").execute(&pool).await.unwrap();
    assert_eq!(whoami(&pool, &c).await, None);
}

// The cookie still says "admin"; the database now says "viewer", and wins.
#[tokio::test]
async fn demoting_the_user_takes_effect_on_the_next_request() {
    let pool = db().await;
    let c = fresh(&pool, 10, "default").await;
    sqlx::query("UPDATE users SET role = 'viewer' WHERE id = 10").execute(&pool).await.unwrap();
    assert_eq!(whoami(&pool, &c).await.as_deref(), Some("alice:viewer:default"));
}

#[tokio::test]
async fn revoking_sessions_ends_every_existing_cookie() {
    let pool = db().await;
    let laptop = fresh(&pool, 10, "default").await;
    let phone = fresh(&pool, 10, "default").await;
    revoke_sessions(&pool, 10).await;
    assert_eq!(whoami(&pool, &laptop).await, None);
    assert_eq!(whoami(&pool, &phone).await, None);
    // A login after the revocation works normally.
    let again = fresh(&pool, 10, "default").await;
    assert!(whoami(&pool, &again).await.is_some());
}

#[tokio::test]
async fn suspending_the_organization_ends_its_sessions() {
    let pool = db().await;
    let c = fresh(&pool, 20, "acme").await;
    assert!(whoami(&pool, &c).await.is_some());
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = 'acme'").execute(&pool).await.unwrap();
    assert_eq!(whoami(&pool, &c).await, None);
}

#[tokio::test]
async fn an_unverified_email_is_not_a_session() {
    let pool = db().await;
    sqlx::query("UPDATE users SET email_verified = 0 WHERE id = 20").execute(&pool).await.unwrap();
    let c = fresh(&pool, 20, "acme").await;
    assert_eq!(whoami(&pool, &c).await, None);
}

// A cookie naming one tenant cannot be pointed at a user in another.
#[tokio::test]
async fn the_user_must_belong_to_the_cookies_tenant() {
    let pool = db().await;
    let c = fresh(&pool, 20, "default").await; // bob is in acme, not default
    assert_eq!(whoami(&pool, &c).await, None);
}

#[tokio::test]
async fn impersonation_is_viewer_and_requires_a_current_superuser() {
    let pool = db().await;
    let imp = json!({
        "username": "root", "userid": "30", "tenant_id": "acme", "role": "viewer",
        "impersonating": { "real_tenant_id": "default", "real_role": "superuser" }
    });
    let c = signed(issue_session_cookie(&pool, imp, time::Duration::hours(1)).await);
    assert_eq!(whoami(&pool, &c).await.as_deref(), Some("root:viewer:acme"));

    // No longer a superuser → the impersonation session is gone too.
    sqlx::query("UPDATE users SET role = 'admin' WHERE id = 30").execute(&pool).await.unwrap();
    assert_eq!(whoami(&pool, &c).await, None);
}

// app_url lives under the 'default' tenant. It used to be looked up under the
// user's own tenant, so in SaaS no tenant's cookie was ever Secure.
#[tokio::test]
async fn secure_follows_the_platform_app_url_for_every_tenant() {
    let pool = db().await;
    let c = issue_session_cookie(&pool, login(20, "acme"), SESSION_TTL).await;
    assert_eq!(c.secure(), Some(false), "no app_url configured → not Secure");

    sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', 'https://scm.example.com')")
        .execute(&pool).await.unwrap();
    let c = issue_session_cookie(&pool, login(20, "acme"), SESSION_TTL).await;
    assert_eq!(c.secure(), Some(true), "an https app_url must make every tenant's cookie Secure");
}

// ─────────────────────────────────────────────────────────────────────────────
// Password change through the real handler: the other sessions end, the
// browser that made the change stays signed in, and it is audited.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn changing_your_password_ends_your_other_sessions_but_not_this_one() {
    let pool = db().await;
    let other_device = fresh(&pool, 10, "default").await;

    let me = AuthSession {
        username: "alice".into(), userid: 10, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    };
    let form = scmserver::users::ChangePasswordForm {
        password1: "correct-horse-battery".into(),
        password2: "correct-horse-battery".into(),
    };
    let resp = scmserver::users::change_password(
        me,
        Extension(pool.clone()),
        scmserver::handlers::ClientIp("127.0.0.1".into()),
        SignedCookieJar::new(key()),
        Path(10),
        Form(form),
    ).await;

    assert_eq!(whoami(&pool, &other_device).await, None, "the other device must be signed out");

    let set = resp.headers().get("set-cookie").expect("this browser must get a re-issued cookie")
        .to_str().unwrap();
    let this_browser = set.split(';').next().unwrap();
    assert!(whoami(&pool, this_browser).await.is_some(), "the changing browser must stay signed in");

    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'user.password_change'",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(audited, 1, "a password change must be audited");
}
