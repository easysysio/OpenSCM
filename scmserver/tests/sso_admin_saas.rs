// sso_admin_saas.rs — in SaaS, a tenant's provider must be a public https address.
//
// The issuer URL is typed by a tenant and fetched by the server, which is the
// same exposure as an alert webhook: pointed at an internal address it reads
// the operator's network. In its own test binary because SaaS mode is a
// process-wide switch with no way back.

use axum::extract::{Extension, RawForm};
use axum::response::IntoResponse;
use scmserver::handlers::ClientIp;
use scmserver::models::AuthSession;
use sqlx::SqlitePool;

async fn save(pool: &SqlitePool, issuer: &str, enabled: bool) -> String {
    let who = AuthSession {
        username: "bob".into(), userid: 20, tenant_id: "acme".into(), role: "admin".into(), impersonating: None,
    };
    let mut body = format!("name=P&client_id=id&client_secret=s&issuer_url={}", urlencoding::encode(issuer));
    if enabled { body.push_str("&enabled=on"); }
    let resp = scmserver::sso::sso_save(who, Extension(pool.clone()), ClientIp("127.0.0.1".into()), RawForm(body.into()))
        .await
        .into_response();
    urlencoding::decode(resp.headers().get("location").unwrap().to_str().unwrap()).unwrap().into_owned()
}

#[tokio::test]
async fn saas_refuses_internal_and_plain_http_issuers_even_when_saved_disabled() {
    scmserver::handlers::enable_saas_mode();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')").execute(&pool).await.unwrap();

    for (issuer, expect) in [
        ("http://login.example.com", "must use https"),
        ("https://127.0.0.1/realms/x", "not a public address"),
        ("https://10.0.0.5", "not a public address"),
        ("https://169.254.169.254/latest", "not a public address"),
        ("https://[::ffff:169.254.169.254]/", "not a public address"),
        ("https://localhost:8443", "not a public address"),
        ("https://user@192.168.1.10/", "not a public address"),
    ] {
        for enabled in [false, true] {
            let to = save(&pool, issuer, enabled).await;
            assert!(to.contains("error_message") && to.contains(expect), "{issuer} (enabled={enabled}) → {to}");
        }
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_providers").fetch_one(&pool).await.unwrap();
    assert_eq!(n, 0, "nothing may be stored for a refused issuer");

    // A public https literal address passes the address rules and is stored (disabled: nothing is contacted).
    let to = save(&pool, "https://8.8.8.8/realms/x", false).await;
    assert!(to.contains("success_message"), "{to}");
}
