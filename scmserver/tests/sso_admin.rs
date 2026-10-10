// sso_admin.rs — the logic of configuring a single sign-on provider.
//
// Single sign-on is SaaS-only in 0.10.0, so its routes answer only in SaaS
// mode, where a provider must be a public https address. A test cannot stand
// up one of those. The routes are therefore thin entry points around
// save_provider / test_provider / discover, which take the URL strictness as a
// parameter, and THIS file tests that logic with the relaxed rules against a
// fake provider on a local port: what is stored, that a blank secret keeps the
// old one, that one tenant's provider is not another's, and that a provider is
// only switched on once it has answered and described itself correctly.
//
// This process runs in Community Edition mode, so it also holds the test that
// CE turns every SSO route away. The routes themselves — roles, the page, the
// strict URL rules — are tested in sso_admin_saas.rs (SaaS mode is a
// process-wide switch).

use axum::extract::{Extension, Query, RawForm};
use axum::http::StatusCode;
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
    // '+' is a space in a query string.
    urlencoding::decode(&raw.replace('+', " ")).unwrap().into_owned()
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields.iter().map(|(k, v)| format!("{k}={}", urlencoding::encode(v))).collect::<Vec<_>>().join("&")
}

// save_provider with the relaxed URL rules. The result is rendered the way the
// route renders it — "success_message: …" / "error_message: …" — so the
// assertions read the same as they would against the route.
async fn save(pool: &SqlitePool, who: AuthSession, fields: &[(&str, &str)]) -> String {
    match sso::save_provider(pool, &who, "127.0.0.1", &form_body(fields), false).await {
        Ok(m) => format!("success_message: {m}"),
        Err(m) => format!("error_message: {m}"),
    }
}

async fn test(pool: &SqlitePool, who: AuthSession) -> String {
    match sso::test_provider(pool, &who, "127.0.0.1", false).await {
        Ok(m) => format!("success_message: {m}"),
        Err(m) => format!("error_message: {m}"),
    }
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
async fn the_client_secret_is_stored_and_never_serialised() {
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

    // What a page is built from carries no secret at all.
    let p = sso::load_provider(&pool, "default").await.unwrap();
    let shown = serde_json::to_string(&p).unwrap();
    assert!(!shown.contains("s3cr3t-VALUE-9f2") && !shown.contains("client_secret"), "{shown}");
    assert!(shown.contains("abc-123") && shown.contains("Acme Entra ID"));
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

// "Trust email addresses" is a checkbox: on when ticked, and — like any
// checkbox — off again when a later save does not include it.
#[tokio::test]
async fn the_trust_email_setting_is_stored_and_can_be_switched_off() {
    let pool = db().await;
    let base = [("name", "P"), ("issuer_url", "https://login.example.com"), ("client_id", "id"), ("client_secret", "s")];
    let trust = |pool: &SqlitePool| { let pool = pool.clone(); async move {
        sqlx::query_scalar::<_, i64>("SELECT trust_email FROM sso_providers WHERE tenant_id = 'default'").fetch_one(&pool).await.unwrap()
    }};

    save(&pool, admin("default"), &base).await;
    assert_eq!(trust(&pool).await, 0, "off unless asked for");
    assert!(!sso::load_provider(&pool, "default").await.unwrap().trust_email);

    let mut on = base.to_vec();
    on.push(("trust_email", "on"));
    save(&pool, admin("default"), &on).await;
    assert_eq!(trust(&pool).await, 1);
    assert!(sso::load_provider(&pool, "default").await.unwrap().trust_email);

    save(&pool, admin("default"), &base).await;
    assert_eq!(trust(&pool).await, 0, "unticking it turns it off");

    // The change is in the audit log: it widens who can be matched.
    let details: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'sso.provider_save' ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert!(details[1].contains("\"trust_email\":true") && details[2].contains("\"trust_email\":false"), "{details:?}");
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
    assert!(sso::load_provider(&pool, "default").await.unwrap().enabled);
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

// ── test connection ─────────────────────────────────────────────────────────
#[tokio::test]
async fn test_connection_reports_what_the_provider_said() {
    let pool = db().await;
    assert!(test(&pool, admin("default")).await.contains("Save a provider first"));

    let idp = good_provider().await;
    let mut off = enable(&idp);
    off.pop();
    save(&pool, admin("default"), &off).await;
    let said = test(&pool, admin("default")).await;
    assert!(said.contains("success_message") && said.contains(&idp) && said.contains("127.0.0.1"), "{said}");
    assert_eq!(stored(&pool, "default").await.unwrap().0, 0, "testing does not enable");

    // Point it at nothing and test again.
    let dead = dead_address().await;
    sqlx::query("UPDATE sso_providers SET issuer_url = ?").bind(&dead).execute(&pool).await.unwrap();
    let said = test(&pool, admin("default")).await;
    assert!(said.contains("error_message") && said.contains("Could not connect"), "{said}");

    let audited: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'sso.%' ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(audited, ["sso.provider_save", "sso.provider_test_success", "sso.provider_test_failure"]);
}

// ── one tenant, one provider ────────────────────────────────────────────────
#[tokio::test]
async fn one_tenants_provider_is_not_anothers() {
    let pool = db().await;
    set_app_url(&pool).await;
    let idp = good_provider().await;
    let mut acme = enable(&idp);
    acme[3] = ("client_secret", "acme-secret");
    save(&pool, admin("acme"), &acme).await;

    assert!(sso::load_provider(&pool, "default").await.is_none(), "default has no provider");
    assert!(test(&pool, admin("default")).await.contains("Save a provider first"), "and cannot test acme's");

    // default's save creates its own row and leaves acme's alone.
    save(&pool, admin("default"), &[("name", "Mine"), ("issuer_url", "https://login.example.com"), ("client_id", "d"), ("client_secret", "default-secret")]).await;
    let a = stored(&pool, "acme").await.unwrap();
    assert_eq!((a.0, a.2.as_str(), a.4.as_str()), (1, idp.as_str(), "acme-secret"), "acme's provider is untouched and still enabled");
    let d = stored(&pool, "default").await.unwrap();
    assert_eq!((d.0, d.4.as_str()), (0, "default-secret"));
    // A blank secret on default's form keeps DEFAULT's secret, never acme's.
    save(&pool, admin("default"), &[("name", "Mine"), ("issuer_url", "https://login.example.com"), ("client_id", "d"), ("client_secret", "")]).await;
    assert_eq!(stored(&pool, "default").await.unwrap().4, "default-secret");
}

// ── Community Edition ───────────────────────────────────────────────────────
// Single sign-on is offered in SaaS only. In CE every route turns the request
// away — for an administrator too — and changes nothing.
#[tokio::test]
async fn community_edition_turns_every_sso_route_away() {
    let pool = db().await;
    assert!(!scmserver::handlers::is_saas_mode(), "this test file must run in CE mode");
    // A provider row, as if left over from a SaaS database or a future edition.
    sqlx::query("INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret)
                 VALUES ('default', 1, 'Leftover', 'https://login.example.com', 'id', 'leftover-secret')")
        .execute(&pool).await.unwrap();
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let not_here = "not available in this edition";

    let resp = sso::sso_page(admin("default"), Query(serde_json::from_value(json!({})).unwrap()),
                             Extension(pool.clone()), Extension(tera)).await.into_response();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "the page must not render in CE");
    assert!(location(resp).contains(not_here));

    let body = form_body(&[("name", "P"), ("issuer_url", "https://8.8.8.8"), ("client_id", "x"), ("client_secret", "new-secret")]);
    let to = location(sso::sso_save(admin("default"), Extension(pool.clone()), ip(), RawForm(body.into())).await.into_response());
    assert!(to.contains(not_here), "{to}");
    assert!(location(sso::sso_test(admin("default"), Extension(pool.clone()), ip()).await.into_response()).contains(not_here));
    assert!(location(sso::sso_disable(admin("default"), Extension(pool.clone()), ip()).await.into_response()).contains(not_here));

    let row = stored(&pool, "default").await.unwrap();
    assert_eq!((row.0, row.1.as_str(), row.4.as_str()), (1, "Leftover", "leftover-secret"), "nothing may change");
    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'sso.%'").fetch_one(&pool).await.unwrap();
    assert_eq!(audited, 0);
}

// Signing in through a provider, and unlinking a user, are closed in CE too —
// including the public routes, which have no role check to fall back on.
#[tokio::test]
async fn community_edition_turns_the_sign_in_routes_away() {
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    let pool = db().await;
    assert!(!scmserver::handlers::is_saas_mode());
    // An enabled provider and a bound user, as if left from a SaaS database.
    sqlx::query("INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret)
                 VALUES ('default', 1, 'Leftover', 'https://login.example.com', 'id', 's')").execute(&pool).await.unwrap();
    sqlx::query("UPDATE users SET sso_subject = 'bound' WHERE id = 10").execute(&pool).await.unwrap();
    set_app_url(&pool).await;

    let app = || axum::Router::new()
        .route("/auth/sso/start", post(scmserver::sso_login::sso_start))
        .route("/auth/sso/callback", get(scmserver::sso_login::sso_callback))
        .layer(Extension(pool.clone()))
        // Even with the relaxed URL rules a test may add, the edition gate holds.
        .layer(Extension(scmserver::sso_login::SsoUrlRules { strict: false }))
        .with_state(axum_extra::extract::cookie::Key::from(&[7u8; 64]));

    let start = app().oneshot(Request::post("/auth/sso/start")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("organization=default")).unwrap()).await.unwrap();
    let to = location(start);
    assert!(to.starts_with("/login?") && to.contains("not available in this edition"), "{to}");

    let cb = app().oneshot(Request::get("/auth/sso/callback?code=c&state=s").body(Body::empty()).unwrap()).await.unwrap();
    assert!(cb.headers().get_all("set-cookie").iter().all(|c| !c.to_str().unwrap().starts_with("session=")), "no session in CE");
    assert!(location(cb).contains("not available in this edition"));
    let states: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_login_state").fetch_one(&pool).await.unwrap();
    assert_eq!(states, 0, "no sign-in was started");

    let to = location(sso::user_unlink(admin("default"), Extension(pool.clone()), ip(),
        axum_extra::extract::cookie::SignedCookieJar::new(axum_extra::extract::cookie::Key::from(&[7u8; 64])),
        axum::extract::Path(10)).await);
    assert!(to.contains("not available in this edition"), "{to}");
    let still: Option<String> = sqlx::query_scalar("SELECT sso_subject FROM users WHERE id = 10").fetch_one(&pool).await.unwrap();
    assert_eq!(still.as_deref(), Some("bound"));
}
