// sso_admin.rs — configuring a tenant's single sign-on provider.
//
// The provider page holds a client secret and names a URL the server will
// fetch, so the things pinned here are: who may touch it, that one tenant
// cannot reach another's, that the secret never comes back out, and that a
// provider is only switched on once it has answered and described itself
// correctly — checked against a fake provider running inside the test.
//
// The SaaS-only URL rules are in sso_admin_saas.rs (SaaS mode is process-wide).

use axum::extract::{Extension, Query, RawForm};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use scmserver::handlers::ClientIp;
use scmserver::models::AuthSession;
use scmserver::sso;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::Arc;

// ── fixtures ────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    // Outbound requests need the TLS provider the server installs at startup.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (10, 'default', 'alice', 'x', 'admin')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (20, 'acme', 'bob', 'x', 'admin')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap();
    }
    pool
}

fn user(tenant: &str, role: &str) -> AuthSession {
    AuthSession {
        username: format!("{tenant}-{role}"),
        userid: if tenant == "acme" { 20 } else { 10 },
        tenant_id: tenant.into(),
        role: role.into(),
        impersonating: None,
    }
}
fn admin(tenant: &str) -> AuthSession { user(tenant, "admin") }
fn ip() -> ClientIp { ClientIp("127.0.0.1".into()) }

fn location(resp: axum::response::Response) -> String {
    let raw = resp.headers().get("location").expect("a redirect").to_str().unwrap().to_string();
    urlencoding::decode(&raw).unwrap().into_owned()
}

async fn save(pool: &SqlitePool, who: AuthSession, fields: &[(&str, &str)]) -> String {
    let body = fields.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&");
    location(sso::sso_save(who, Extension(pool.clone()), ip(), RawForm(body.into())).await.into_response())
}

async fn page(pool: &SqlitePool, who: AuthSession) -> (axum::http::StatusCode, String) {
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let resp = sso::sso_page(who, Query(serde_json::from_value(json!({})).unwrap()), Extension(pool.clone()), Extension(tera))
        .await
        .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn stored(pool: &SqlitePool, tenant: &str) -> Option<(i64, String, String, String, String)> {
    sqlx::query_as("SELECT enabled, name, issuer_url, client_id, client_secret FROM sso_providers WHERE tenant_id = ?")
        .bind(tenant).fetch_optional(pool).await.unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: fake_provider
// A provider on a local port. `doc` builds its discovery document from its own
// base URL; None serves something that is not a discovery document.
// ─────────────────────────────────────────────────────────────────────────────
async fn fake_provider(doc: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let body = doc(&base).unwrap_or_else(|| "<html>Sign in</html>".to_string());
    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get(move || { let b = body.clone(); async move { b } }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

fn good_doc(base: &str) -> Value {
    json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/keys"),
        "id_token_signing_alg_values_supported": ["RS256"]
    })
}

async fn good_provider() -> String {
    fake_provider(|b| Some(good_doc(b).to_string())).await
}

/// A local address nothing is listening on.
async fn dead_address() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    drop(l);
    url
}

// ── the page ────────────────────────────────────────────────────────────────
#[tokio::test]
async fn the_page_renders_before_anything_is_configured() {
    let pool = db().await;
    let (status, html) = page(&pool, admin("default")).await;
    assert_eq!(status, 200);
    assert!(html.contains("Not configured"));
    // No App URL yet: there is no callback address to give the provider.
    assert!(html.contains("App URL") && html.contains("is not set"), "missing App URL warning");

    sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', 'https://scm.example.com/')")
        .execute(&pool).await.unwrap();
    let (_, html) = page(&pool, admin("default")).await;
    assert!(html.contains("https:&#x2F;&#x2F;scm.example.com&#x2F;auth&#x2F;sso&#x2F;callback")
            || html.contains("https://scm.example.com/auth/sso/callback"), "redirect URI not shown");
}

// The redirect URI comes from the platform App URL for every tenant.
#[tokio::test]
async fn the_redirect_uri_is_the_installations_for_every_tenant() {
    let pool = db().await;
    assert_eq!(sso::redirect_uri(&pool).await, None);
    sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', ' https://scm.example.com ')")
        .execute(&pool).await.unwrap();
    assert_eq!(sso::redirect_uri(&pool).await.as_deref(), Some("https://scm.example.com/auth/sso/callback"));
}

// ── saving ──────────────────────────────────────────────────────────────────
#[tokio::test]
async fn the_client_secret_is_stored_and_never_sent_back() {
    let pool = db().await;
    let to = save(&pool, admin("default"), &[
        ("name", "Acme Entra ID"), ("issuer_url", "https://login.example.com/tenant/v2.0/"),
        ("client_id", "abc-123"), ("client_secret", "s3cr3t-VALUE-9f2"),
    ]).await;
    assert!(to.contains("success_message"), "{to}");

    let row = stored(&pool, "default").await.unwrap();
    assert_eq!(row, (0, "Acme Entra ID".into(), "https://login.example.com/tenant/v2.0".into(),
                     "abc-123".into(), "s3cr3t-VALUE-9f2".into()),
               "stored disabled, issuer without its trailing slash");

    let (_, html) = page(&pool, admin("default")).await;
    assert!(!html.contains("s3cr3t-VALUE-9f2"), "the secret must never appear in the page");
    assert!(html.contains("leave blank to keep the stored secret"));
    assert!(html.contains("abc-123") && html.contains("Acme Entra ID"), "the rest of the configuration is shown");
    assert!(html.contains("Saved, not enabled"));
}

#[tokio::test]
async fn a_blank_secret_keeps_the_stored_one_and_a_new_one_replaces_it() {
    let pool = db().await;
    let base = [("name", "P"), ("issuer_url", "https://login.example.com"), ("client_id", "id")];
    let with = |secret: &'static str| { let mut v = base.to_vec(); v.push(("client_secret", secret)); v };

    save(&pool, admin("default"), &with("first")).await;
    let to = save(&pool, admin("default"), &[("name", "Renamed"), ("issuer_url", "https://login.example.com"), ("client_id", "id2"), ("client_secret", "")]).await;
    assert!(to.contains("success_message"), "{to}");
    let row = stored(&pool, "default").await.unwrap();
    assert_eq!((row.1.as_str(), row.3.as_str(), row.4.as_str()), ("Renamed", "id2", "first"));

    save(&pool, admin("default"), &with("second")).await;
    assert_eq!(stored(&pool, "default").await.unwrap().4, "second");
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sso_providers").fetch_one(&pool).await.unwrap(), 1,
               "one provider per tenant — saving updates it");
}

#[tokio::test]
async fn incomplete_or_malformed_input_is_refused() {
    let pool = db().await;
    let cases: [(&[(&str, &str)], &str); 5] = [
        (&[("name", ""), ("issuer_url", "https://x.example.com"), ("client_id", "id"), ("client_secret", "s")], "display name"),
        (&[("name", "P"), ("issuer_url", "https://x.example.com"), ("client_id", ""), ("client_secret", "s")], "client ID"),
        (&[("name", "P"), ("issuer_url", "https://x.example.com"), ("client_id", "id"), ("client_secret", "")], "client secret is required"),
        (&[("name", "P"), ("issuer_url", "login.example.com"), ("client_id", "id"), ("client_secret", "s")], "Issuer URL must start with"),
        (&[("name", "P"), ("issuer_url", "file:///etc/passwd"), ("client_id", "id"), ("client_secret", "s")], "Issuer URL must start with"),
    ];
    for (fields, expect) in cases {
        let to = save(&pool, admin("default"), fields).await;
        assert!(to.contains("error_message") && to.contains(expect), "{fields:?} → {to}");
    }
    assert!(stored(&pool, "default").await.is_none(), "nothing may be stored from a refused form");
}

// ── enabling ────────────────────────────────────────────────────────────────
async fn set_app_url(pool: &SqlitePool) {
    sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', 'https://scm.example.com')")
        .execute(pool).await.unwrap();
}

// Without an App URL there is no callback address to send users back to.
#[tokio::test]
async fn enabling_requires_the_app_url() {
    let pool = db().await;
    let idp = good_provider().await;
    let to = save(&pool, admin("default"), &enable(&idp)).await;
    assert!(to.contains("error_message") && to.contains("set the App URL"), "{to}");
    assert!(stored(&pool, "default").await.is_none());

    set_app_url(&pool).await;
    let to = save(&pool, admin("default"), &enable(&idp)).await;
    assert!(to.contains("success_message"), "{to}");
    assert_eq!(stored(&pool, "default").await.unwrap().0, 1);
}

fn enable(issuer: &str) -> Vec<(&str, &str)> {
    vec![("name", "P"), ("issuer_url", issuer), ("client_id", "id"), ("client_secret", "s"), ("enabled", "on")]
}

#[tokio::test]
async fn a_provider_that_answers_correctly_can_be_enabled() {
    let pool = db().await;
    set_app_url(&pool).await;
    let idp = good_provider().await;
    let to = save(&pool, admin("default"), &enable(&idp)).await;
    assert!(to.contains("success_message") && to.contains("enabled"), "{to}");
    assert_eq!(stored(&pool, "default").await.unwrap().0, 1);
    let (_, html) = page(&pool, admin("default")).await;
    assert!(html.contains(">Enabled<"));
}

#[tokio::test]
async fn a_provider_that_cannot_be_verified_is_not_enabled() {
    let pool = db().await;
    set_app_url(&pool).await;
    let dead = dead_address().await;
    let to = save(&pool, admin("default"), &enable(&dead)).await;
    assert!(to.contains("error_message") && to.contains("Not enabled") && to.contains("Could not connect"), "{to}");
    assert!(stored(&pool, "default").await.is_none(), "an unverifiable provider is not saved as enabled");

    // The same provider can be saved DISABLED — nothing is contacted.
    let mut off = enable(&dead);
    off.pop();
    let to = save(&pool, admin("default"), &off).await;
    assert!(to.contains("success_message"), "{to}");
    assert_eq!(stored(&pool, "default").await.unwrap().0, 0);

    // And enabling it later is still refused, leaving it as it was.
    let to = save(&pool, admin("default"), &enable(&dead)).await;
    assert!(to.contains("Not enabled"), "{to}");
    assert_eq!(stored(&pool, "default").await.unwrap().0, 0);
}

// ── discovery ───────────────────────────────────────────────────────────────
#[tokio::test]
async fn discovery_accepts_a_correct_document() {
    let _ = db().await;
    let idp = good_provider().await;
    let doc = sso::discover(&format!("{idp}/"), false).await.expect("good document");
    assert_eq!(doc.issuer, idp);
    assert_eq!(doc.token_endpoint, format!("{idp}/token"));
    assert_eq!(doc.jwks_uri, format!("{idp}/keys"));

    // A provider that writes its own issuer with a trailing slash still matches.
    let slashed = fake_provider(|b| { let mut d = good_doc(b); d["issuer"] = json!(format!("{b}/")); Some(d.to_string()) }).await;
    assert!(sso::discover(&slashed, false).await.is_ok());
}

#[tokio::test]
async fn discovery_refuses_a_document_that_names_another_issuer() {
    let _ = db().await;
    let idp = fake_provider(|b| { let mut d = good_doc(b); d["issuer"] = json!("https://accounts.victim.example"); Some(d.to_string()) }).await;
    let e = sso::discover(&idp, false).await.unwrap_err();
    assert!(e.contains("different issuer") && e.contains("accounts.victim.example"), "{e}");
}

#[tokio::test]
async fn discovery_refuses_things_that_are_not_a_discovery_document() {
    let _ = db().await;
    // A sign-in page, not JSON.
    let html = fake_provider(|_| None).await;
    assert!(sso::discover(&html, false).await.unwrap_err().contains("did not return an OpenID Connect discovery document"));
    // JSON with a required endpoint missing.
    let partial = fake_provider(|b| { let mut d = good_doc(b); d.as_object_mut().unwrap().remove("jwks_uri"); Some(d.to_string()) }).await;
    assert!(sso::discover(&partial, false).await.unwrap_err().contains("did not return"));
    // Nothing at that path.
    let dead = dead_address().await;
    assert!(sso::discover(&dead, false).await.unwrap_err().contains("Could not connect"));
    // An oversized reply.
    let huge = fake_provider(|_| Some("x".repeat(400 * 1024))).await;
    assert!(sso::discover(&huge, false).await.unwrap_err().contains("unexpectedly large"));
}

// The endpoints a document lists are addresses too; a browser or this server
// will be sent to them.
#[tokio::test]
async fn discovery_refuses_unacceptable_endpoints_and_unverifiable_algorithms() {
    let _ = db().await;
    for (field, value, expect) in [
        ("authorization_endpoint", "javascript:alert(1)", "authorization endpoint"),
        ("token_endpoint", "file:///etc/passwd", "token endpoint"),
        ("jwks_uri", "not a url", "signing-key address"),
    ] {
        let idp = fake_provider(move |b| { let mut d = good_doc(b); d[field] = json!(value); Some(d.to_string()) }).await;
        let e = sso::discover(&idp, false).await.unwrap_err();
        assert!(e.contains(expect) && e.contains("not acceptable"), "{field}: {e}");
    }
    let hs = fake_provider(|b| { let mut d = good_doc(b); d["id_token_signing_alg_values_supported"] = json!(["HS256", "none"]); Some(d.to_string()) }).await;
    let e = sso::discover(&hs, false).await.unwrap_err();
    assert!(e.contains("HS256") && e.contains("cannot verify"), "{e}");
    // A document that lists no algorithms is not refused for that.
    let silent = fake_provider(|b| { let mut d = good_doc(b); d.as_object_mut().unwrap().remove("id_token_signing_alg_values_supported"); Some(d.to_string()) }).await;
    assert!(sso::discover(&silent, false).await.is_ok());
}

// Strict mode (SaaS) holds the issuer to https and public addresses, here too.
#[tokio::test]
async fn strict_discovery_refuses_internal_and_plain_http_issuers() {
    let _ = db().await;
    let idp = good_provider().await; // http://127.0.0.1:port
    assert!(sso::discover(&idp, true).await.unwrap_err().contains("https"));
    for internal in ["https://127.0.0.1", "https://10.0.0.5/realms/x", "https://169.254.169.254", "https://[::ffff:10.0.0.5]"] {
        let e = sso::discover(internal, true).await.unwrap_err();
        assert!(e.contains("not a public address"), "{internal}: {e}");
    }
}

// ── test + disable ──────────────────────────────────────────────────────────
#[tokio::test]
async fn test_connection_reports_what_the_provider_said() {
    let pool = db().await;
    let to = location(sso::sso_test(admin("default"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("Save a provider first"), "{to}");

    let idp = good_provider().await;
    let mut off = enable(&idp);
    off.pop();
    save(&pool, admin("default"), &off).await;
    let to = location(sso::sso_test(admin("default"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("success_message") && to.contains(&idp) && to.contains("127.0.0.1"), "{to}");
    assert_eq!(stored(&pool, "default").await.unwrap().0, 0, "testing does not enable");

    // Point it at nothing and test again.
    let dead = dead_address().await;
    sqlx::query("UPDATE sso_providers SET issuer_url = ?").bind(&dead).execute(&pool).await.unwrap();
    let to = location(sso::sso_test(admin("default"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("error_message") && to.contains("Could not connect"), "{to}");

    let audited: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'sso.%' ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(audited, ["sso.provider_save", "sso.provider_test_success", "sso.provider_test_failure"]);
}

#[tokio::test]
async fn disabling_turns_it_off_and_keeps_the_configuration() {
    let pool = db().await;
    set_app_url(&pool).await;
    let to = location(sso::sso_disable(admin("default"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("No provider is configured"), "{to}");

    let idp = good_provider().await;
    save(&pool, admin("default"), &enable(&idp)).await;
    let to = location(sso::sso_disable(admin("default"), Extension(pool.clone()), ip()).await.into_response());
    assert!(to.contains("success_message"), "{to}");
    let row = stored(&pool, "default").await.unwrap();
    assert_eq!((row.0, row.2.as_str(), row.4.as_str()), (0, idp.as_str(), "s"));
}

// ── who may do this, and to whom ────────────────────────────────────────────
#[tokio::test]
async fn one_tenant_cannot_see_or_change_anothers_provider() {
    let pool = db().await;
    set_app_url(&pool).await;
    let idp = good_provider().await;
    let mut acme = enable(&idp);
    acme[3] = ("client_secret", "acme-secret");
    save(&pool, admin("acme"), &acme).await;

    let (_, html) = page(&pool, admin("default")).await;
    assert!(html.contains("Not configured") && !html.contains(&idp), "default must not see acme's provider");

    // default's save creates its own row and leaves acme's alone.
    save(&pool, admin("default"), &[("name", "Mine"), ("issuer_url", "https://login.example.com"), ("client_id", "d"), ("client_secret", "default-secret")]).await;
    location(sso::sso_disable(admin("default"), Extension(pool.clone()), ip()).await.into_response());
    let a = stored(&pool, "acme").await.unwrap();
    assert_eq!((a.0, a.2.as_str(), a.4.as_str()), (1, idp.as_str(), "acme-secret"), "acme's provider is untouched and still enabled");
    assert_eq!(stored(&pool, "default").await.unwrap().4, "default-secret");
}

#[tokio::test]
async fn only_an_admin_may_configure_single_sign_on() {
    let pool = db().await;
    for role in ["viewer", "runner", "editor"] {
        let who = || user("default", role);
        let (status, _) = page(&pool, who()).await;
        assert!(status.is_redirection(), "{role} must not see the page");
        let to = save(&pool, who(), &[("name", "P"), ("issuer_url", "https://login.example.com"), ("client_id", "id"), ("client_secret", "s")]).await;
        assert!(to.contains("Unauthorized"), "{role} save → {to}");
        assert!(location(sso::sso_test(who(), Extension(pool.clone()), ip()).await.into_response()).contains("Unauthorized"));
        assert!(location(sso::sso_disable(who(), Extension(pool.clone()), ip()).await.into_response()).contains("Unauthorized"));
    }
    assert!(stored(&pool, "default").await.is_none());
}

// Through the real handler, not a hand-built context: a message in the URL
// must reach the page. (The Alerts pages rendered their banner correctly in a
// template test while the handlers never passed the message along.)
#[tokio::test]
async fn flash_messages_in_the_url_reach_the_page() {
    let pool = db().await;
    let tera = Arc::new(scmserver::init_tera().unwrap());
    for (param, class) in [("error_message", "alert-danger"), ("success_message", "alert-success")] {
        let q = serde_json::from_value(json!({ param: "PROBE-7c1 was shown" })).unwrap();
        let resp = sso::sso_page(admin("default"), Query(q), Extension(pool.clone()), Extension(tera.clone())).await.into_response();
        let html = String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap()).to_string();
        assert!(html.contains("PROBE-7c1 was shown") && html.contains(class), "{param} not rendered");
    }
}
