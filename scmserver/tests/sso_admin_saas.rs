// sso_admin_saas.rs — the single sign-on routes, as SaaS serves them.
//
// Single sign-on is SaaS-only in 0.10.0. This process runs in SaaS mode, so
// the routes are open and are tested as they really behave: who may use them,
// what the page shows (and never shows), that a tenant's provider must be a
// public https address, and disabling. SaaS mode is a process-wide switch with
// no way back, which is why these are not in sso_admin.rs — that file runs in
// Community Edition mode and tests the logic, plus CE turning the routes away.

use axum::extract::{Extension, Query, RawForm};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use scmserver::handlers::ClientIp;
use scmserver::models::AuthSession;
use scmserver::sso;
use serde_json::json;
use sqlx::SqlitePool;
use std::sync::Arc;

// ── fixtures ────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    scmserver::handlers::enable_saas_mode();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO tenants (id, name) VALUES ('globex', 'Globex')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (20, 'acme', 'bob', 'x', 'admin')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (30, 'globex', 'gina', 'x', 'admin')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap();
    }
    pool
}

fn user(tenant: &str, role: &str) -> AuthSession {
    AuthSession {
        username: format!("{tenant}-{role}"),
        userid: if tenant == "acme" { 20 } else { 30 },
        tenant_id: tenant.into(),
        role: role.into(),
        impersonating: None,
    }
}
fn admin(tenant: &str) -> AuthSession { user(tenant, "admin") }
fn ip() -> ClientIp { ClientIp("127.0.0.1".into()) }

fn location(resp: axum::response::Response) -> String {
    let raw = resp.headers().get("location").expect("a redirect").to_str().unwrap().to_string();
    // '+' is a space in a query string.
    urlencoding::decode(&raw.replace('+', " ")).unwrap().into_owned()
}

async fn save(pool: &SqlitePool, who: AuthSession, fields: &[(&str, &str)]) -> String {
    let body = fields.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&");
    location(sso::sso_save(who, Extension(pool.clone()), ip(), RawForm(body.into())).await.into_response())
}

async fn page_with(pool: &SqlitePool, who: AuthSession, query: serde_json::Value) -> (StatusCode, String) {
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let resp = sso::sso_page(who, Query(serde_json::from_value(query).unwrap()), Extension(pool.clone()), Extension(tera))
        .await
        .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}
async fn page(pool: &SqlitePool, who: AuthSession) -> (StatusCode, String) {
    page_with(pool, who, json!({})).await
}

// A stored provider, placed directly: enabling through the route needs a real
// public https provider, which a test does not have.
async fn put_provider(pool: &SqlitePool, tenant: &str, enabled: bool, secret: &str) {
    sqlx::query("INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret)
                 VALUES (?, ?, ?, 'https://login.example.com/v2.0', 'abc-123', ?)")
        .bind(tenant).bind(enabled).bind(format!("{tenant} IdP")).bind(secret)
        .execute(pool).await.unwrap();
}

async fn stored(pool: &SqlitePool, tenant: &str) -> Option<(i64, String, String)> {
    sqlx::query_as("SELECT enabled, issuer_url, client_secret FROM sso_providers WHERE tenant_id = ?")
        .bind(tenant).fetch_optional(pool).await.unwrap()
}

/// A public https address that passes the URL rules without a DNS lookup.
const PUBLIC: &str = "https://8.8.8.8/realms/acme";

// ── the page ────────────────────────────────────────────────────────────────
#[tokio::test]
async fn the_page_renders_before_anything_is_configured() {
    let pool = db().await;
    let (status, html) = page(&pool, admin("acme")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Not configured"));
    assert!(html.contains("reachable from the internet"), "the https rule is stated");
    // No App URL yet: there is no callback address to give the provider.
    assert!(html.contains("App URL") && html.contains("is not set"), "missing App URL warning");

    sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', 'https://scm.example.com/')")
        .execute(&pool).await.unwrap();
    let (_, html) = page(&pool, admin("acme")).await;
    assert!(html.contains("https:&#x2F;&#x2F;scm.example.com&#x2F;auth&#x2F;sso&#x2F;callback")
            || html.contains("https://scm.example.com/auth/sso/callback"),
            "the redirect URI comes from the platform App URL, for every tenant");
}

#[tokio::test]
async fn the_page_shows_the_configuration_but_never_the_secret() {
    let pool = db().await;
    let to = save(&pool, admin("acme"), &[("name", "Acme Entra ID"), ("issuer_url", PUBLIC), ("client_id", "abc-123"), ("client_secret", "s3cr3t-VALUE-9f2")]).await;
    assert!(to.contains("success_message") && to.contains("not enabled"), "{to}");

    let (_, html) = page(&pool, admin("acme")).await;
    assert!(!html.contains("s3cr3t-VALUE-9f2"), "the secret must never appear in the page");
    assert!(html.contains("leave blank to keep the stored secret"));
    assert!(html.contains("abc-123") && html.contains("Acme Entra ID"), "the rest of the configuration is shown");
    assert!(html.contains("Saved, not enabled"));

    // Saving again with the secret left blank keeps it.
    let to = save(&pool, admin("acme"), &[("name", "Renamed"), ("issuer_url", PUBLIC), ("client_id", "abc-123"), ("client_secret", "")]).await;
    assert!(to.contains("success_message"), "{to}");
    assert_eq!(stored(&pool, "acme").await.unwrap().2, "s3cr3t-VALUE-9f2");
}

#[tokio::test]
async fn the_page_offers_trust_email_with_its_warning_and_shows_its_state() {
    let pool = db().await;
    let (_, html) = page(&pool, admin("acme")).await;
    assert!(html.contains("Trust email addresses from this provider"));
    assert!(html.contains("your own company directory"), "the condition for using it is stated");
    assert!(html.contains("be signed in as them"), "and so is the risk");
    let ticked = |h: &str| h.split("id=\"trust_email\"").nth(1).unwrap().split('>').next().unwrap().contains("checked");
    assert!(!ticked(&html), "off by default");

    let to = save(&pool, admin("acme"), &[("name", "P"), ("issuer_url", PUBLIC), ("client_id", "id"), ("client_secret", "s"), ("trust_email", "on")]).await;
    assert!(to.contains("success_message"), "{to}");
    let (_, html) = page(&pool, admin("acme")).await;
    assert!(ticked(&html), "the page shows it is on");
}

// Through the real handler, not a hand-built context (the Alerts pages once
// rendered their banner in a template test while the handlers never passed
// the message along).
#[tokio::test]
async fn flash_messages_in_the_url_reach_the_page() {
    let pool = db().await;
    for (param, class) in [("error_message", "alert-danger"), ("success_message", "alert-success")] {
        let (_, html) = page_with(&pool, admin("acme"), json!({ param: "PROBE-7c1 was shown" })).await;
        assert!(html.contains("PROBE-7c1 was shown") && html.contains(class), "{param} not rendered");
    }
}

// ── the URL rules ───────────────────────────────────────────────────────────
// The issuer URL is typed by a tenant and fetched by the server — the same
// exposure as an alert webhook.
#[tokio::test]
async fn a_provider_must_be_a_public_https_address() {
    let pool = db().await;
    for (issuer, expect) in [
        ("http://login.example.com", "must use https"),
        ("https://127.0.0.1/realms/x", "not a public address"),
        ("https://10.0.0.5", "not a public address"),
        ("https://169.254.169.254/latest", "not a public address"),
        ("https://[::ffff:169.254.169.254]/", "not a public address"),
        ("https://localhost:8443", "not a public address"),
        ("https://user@192.168.1.10/", "not a public address"),
        ("login.example.com", "Issuer URL must start with"),
        ("file:///etc/passwd", "Issuer URL must start with"),
    ] {
        // Refused whether or not it is being enabled: nothing is contacted,
        // and nothing is stored.
        for enabled in [false, true] {
            let mut fields = vec![("name", "P"), ("issuer_url", issuer), ("client_id", "id"), ("client_secret", "s")];
            if enabled { fields.push(("enabled", "on")); }
            let to = save(&pool, admin("acme"), &fields).await;
            assert!(to.contains("error_message") && to.contains(expect), "{issuer} (enabled={enabled}) → {to}");
        }
    }
    assert!(stored(&pool, "acme").await.is_none(), "nothing may be stored for a refused issuer");

    let to = save(&pool, admin("acme"), &[("name", "P"), ("issuer_url", PUBLIC), ("client_id", "id"), ("client_secret", "s")]).await;
    assert!(to.contains("success_message"), "{to}");
    assert_eq!(stored(&pool, "acme").await.unwrap().1, PUBLIC);
}

// Enabling contacts the provider; with no App URL it is refused before that.
#[tokio::test]
async fn enabling_through_the_route_requires_the_app_url() {
    let pool = db().await;
    let to = save(&pool, admin("acme"), &[("name", "P"), ("issuer_url", PUBLIC), ("client_id", "id"), ("client_secret", "s"), ("enabled", "on")]).await;
    assert!(to.contains("error_message") && to.contains("set the App URL"), "{to}");
    assert!(stored(&pool, "acme").await.is_none());
}

// ── test + disable ──────────────────────────────────────────────────────────
#[tokio::test]
async fn test_and_disable_need_a_provider_to_act_on() {
    let pool = db().await;
    let to = location(sso::sso_test(admin("acme"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("Save a provider first"), "{to}");
    let to = location(sso::sso_disable(admin("acme"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("No provider is configured"), "{to}");
}

#[tokio::test]
async fn disabling_turns_it_off_and_keeps_the_configuration() {
    let pool = db().await;
    put_provider(&pool, "acme", true, "acme-secret").await;
    let (_, html) = page(&pool, admin("acme")).await;
    assert!(html.contains(">Enabled<") && html.contains("/admin/sso/disable"));

    let to = location(sso::sso_disable(admin("acme"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("success_message") && to.contains("disabled"), "{to}");
    assert_eq!(stored(&pool, "acme").await.unwrap(), (0, "https://login.example.com/v2.0".into(), "acme-secret".into()));

    let (_, html) = page(&pool, admin("acme")).await;
    assert!(html.contains("Saved, not enabled") && !html.contains("/admin/sso/disable"), "no Disable button once off");
    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'sso.provider_disable' AND tenant_id = 'acme'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(audited, 1);
}

// ── who may do this, and to whom ────────────────────────────────────────────
#[tokio::test]
async fn one_tenant_cannot_see_or_change_anothers_provider() {
    let pool = db().await;
    put_provider(&pool, "acme", true, "acme-secret").await;

    let (_, html) = page(&pool, admin("globex")).await;
    assert!(html.contains("Not configured") && !html.contains("acme IdP") && !html.contains("abc-123"),
            "globex must not see acme's provider");

    // globex disabling "its" provider must not touch acme's.
    let to = location(sso::sso_disable(admin("globex"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("No provider is configured"), "{to}");
    // globex saving creates its own row.
    save(&pool, admin("globex"), &[("name", "Globex"), ("issuer_url", PUBLIC), ("client_id", "g"), ("client_secret", "globex-secret")]).await;

    assert_eq!(stored(&pool, "acme").await.unwrap(), (1, "https://login.example.com/v2.0".into(), "acme-secret".into()),
               "acme's provider is untouched and still enabled");
    assert_eq!(stored(&pool, "globex").await.unwrap().2, "globex-secret");
}

#[tokio::test]
async fn only_an_admin_may_configure_single_sign_on() {
    let pool = db().await;
    put_provider(&pool, "acme", true, "acme-secret").await;
    for role in ["viewer", "runner", "editor"] {
        let who = || user("acme", role);
        let (status, _) = page(&pool, who()).await;
        assert!(status.is_redirection(), "{role} must not see the page");
        let to = save(&pool, who(), &[("name", "P"), ("issuer_url", PUBLIC), ("client_id", "id"), ("client_secret", "stolen")]).await;
        assert!(to.contains("Unauthorized"), "{role} save → {to}");
        assert!(location(sso::sso_test(who(), Extension(pool.clone()), ip()).await.into_response()).contains("Unauthorized"));
        assert!(location(sso::sso_disable(who(), Extension(pool.clone()), ip()).await.into_response()).contains("Unauthorized"));
    }
    assert_eq!(stored(&pool, "acme").await.unwrap(), (1, "https://login.example.com/v2.0".into(), "acme-secret".into()),
               "nothing a non-admin did may have changed it");
}

// A platform operator viewing a customer's tenant is read-only (the session is
// forced to Viewer), so cannot read or alter the customer's SSO settings.
#[tokio::test]
async fn an_impersonating_operator_cannot_touch_a_tenants_provider() {
    let pool = db().await;
    put_provider(&pool, "acme", true, "acme-secret").await;
    let operator = AuthSession {
        username: "root".into(), userid: 1, tenant_id: "acme".into(), role: "viewer".into(),
        impersonating: Some(scmserver::models::Impersonation { real_tenant_id: "default".into(), real_role: "superuser".into() }),
    };
    let (status, _) = page(&pool, operator.clone()).await;
    assert!(status.is_redirection());
    let to = location(sso::sso_disable(operator, Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("Unauthorized"), "{to}");
    assert_eq!(stored(&pool, "acme").await.unwrap().0, 1);
}
