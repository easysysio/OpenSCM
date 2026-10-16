// secrets_at_rest.rs — credentials OpenSCM must use are stored encrypted.
//
// Before 0.10.1 the tenants' agent-signing keys, the SSO client secret, the
// LDAP bind password, the SMTP password and webhook secrets sat in the
// database as plaintext, so any copy of the database file held all of them.
// The LDAP edit form also sent the bind password back to the browser.

use axum::extract::{Form, Path, Query};
use axum::response::IntoResponse;
use axum::Extension;
use axum_extra::extract::cookie::Key;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use scmserver::directories::{self, DirectoryForm};
use scmserver::handlers::ClientIp;
use scmserver::models::{AuthSession, ErrorQuery};
use scmserver::secrets::{self, *};
use sqlx::SqlitePool;
use std::sync::Arc;

fn key() {
    secrets::init_from_cookie_key(&Key::from(&[3u8; 64]));
}

async fn db() -> SqlitePool {
    key();
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    pool
}

fn admin() -> AuthSession {
    AuthSession {
        username: "alice".into(), userid: 1, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    }
}

async fn raw(pool: &SqlitePool, sql: &str) -> String {
    sqlx::query_scalar::<_, String>(sql).fetch_one(pool).await.unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: signs_for
// sign_response works for the tenant and its signature checks out against
// the tenant's public key.
// ─────────────────────────────────────────────────────────────────────────────
async fn signs_for(pool: &SqlitePool, tenant: &str) {
    let signed = scmserver::client::sign_response(pool, tenant, serde_json::json!({"t": tenant}))
        .await
        .unwrap_or_else(|e| panic!("signing for {tenant}: {e}"));
    let public: String = sqlx::query_scalar("SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1")
        .bind(tenant).fetch_one(pool).await.unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        &general_purpose::STANDARD.decode(public).unwrap().try_into().unwrap(),
    ).unwrap();
    let sig = Signature::from_slice(&general_purpose::STANDARD.decode(&signed.signature).unwrap()).unwrap();
    vk.verify(&serde_json::to_vec(&signed.payload).unwrap(), &sig).expect("signature verifies");
}

#[test]
fn a_sealed_value_hides_the_plaintext_and_opens_again() {
    key();
    let sealed = seal(COL_SSO_SECRET, "hunter2-client-secret");
    assert!(sealed.starts_with(PREFIX), "{sealed}");
    assert!(!sealed.contains("hunter2"));
    assert_ne!(sealed, seal(COL_SSO_SECRET, "hunter2-client-secret"), "fresh nonce every time");
    assert_eq!(open(COL_SSO_SECRET, &sealed).unwrap(), "hunter2-client-secret");
    assert_eq!(seal(COL_SSO_SECRET, ""), "", "unset stays unset");
}

#[test]
fn plaintext_from_before_encryption_still_reads() {
    key();
    assert_eq!(open(COL_SMTP_PASSWORD, "old-plain").unwrap(), "old-plain");
}

#[test]
fn a_value_moved_to_another_column_or_altered_does_not_open() {
    key();
    let sealed = seal(COL_BIND_PASSWORD, "pw");
    assert!(open(COL_SMTP_PASSWORD, &sealed).is_err(), "bound to its column");
    let mut bytes = general_purpose::STANDARD.decode(sealed.strip_prefix(PREFIX).unwrap()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let tampered = format!("{PREFIX}{}", general_purpose::STANDARD.encode(bytes));
    assert!(open(COL_BIND_PASSWORD, &tampered).is_err());
    assert_eq!(open_or_empty(COL_BIND_PASSWORD, &tampered), "");
}

#[tokio::test]
async fn existing_plaintext_secrets_are_encrypted_at_startup_and_still_work() {
    let pool = db().await;
    let acme_key = SigningKey::from_bytes(&[5u8; 32]);
    for (sql, binds) in [
        ("INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')", vec![]),
        ("INSERT INTO tenant_keys (tenant_id, public_key, private_key, is_active) VALUES ('acme', ?, ?, 1)",
         vec![general_purpose::STANDARD.encode(acme_key.verifying_key().to_bytes()),
              general_purpose::STANDARD.encode(acme_key.to_bytes())]),
        ("INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret)
          VALUES ('acme', 0, 'IdP', 'https://idp.example', 'cid', 'sso-plain')", vec![]),
        ("INSERT INTO directories (tenant_id, name, dir_type, host, port, base_dn, bind_dn, bind_password)
          VALUES ('default', 'AD', 'ldap', 'ldap.example', 389, 'dc=x', 'cn=svc', 'ldap-plain')", vec![]),
        ("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'smtp_password', 'smtp-plain')", vec![]),
        ("INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'P', '1')", vec![]),
        ("INSERT INTO alerts (id, tenant_id, name, scope_type, policy_id, trigger_type, threshold, score_axis, cooldown_minutes)
          VALUES (1, 'default', 'r', 'policy', 1, 'drop', 10, 'test', 60)", vec![]),
        ("INSERT INTO alert_actions (alert_id, action, target, target_secret)
          VALUES (1, 'webhook', 'https://hook.example', 'Bearer hook-plain')", vec![]),
    ] {
        let mut q = sqlx::query(sql);
        for b in binds { q = q.bind(b); }
        q.execute(&pool).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    encrypt_existing(&pool).await;
    encrypt_existing(&pool).await; // a second start changes nothing

    let leftover: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM tenant_keys WHERE private_key NOT LIKE 'enc:v1:%')
              + (SELECT COUNT(*) FROM sso_providers WHERE client_secret NOT LIKE 'enc:v1:%')
              + (SELECT COUNT(*) FROM directories WHERE bind_password NOT LIKE 'enc:v1:%')
              + (SELECT COUNT(*) FROM settings WHERE skey = 'smtp_password' AND value != '' AND value NOT LIKE 'enc:v1:%')
              + (SELECT COUNT(*) FROM alert_actions WHERE target_secret NOT LIKE 'enc:v1:%')",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(leftover, 0, "plaintext secrets left in the database");

    signs_for(&pool, "acme").await;
    signs_for(&pool, "default").await;
    assert_eq!(scmserver::sso::load_provider(&pool, "acme").await.unwrap().client_secret, "sso-plain");
    let dir_id: i64 = sqlx::query_scalar("SELECT id FROM directories").fetch_one(&pool).await.unwrap();
    assert_eq!(directories::get_by_id(&pool, dir_id).await.unwrap().bind_password, "ldap-plain");
    let smtp = raw(&pool, "SELECT value FROM settings WHERE tenant_id = 'default' AND skey = 'smtp_password'").await;
    assert_eq!(open(COL_SMTP_PASSWORD, &smtp).unwrap(), "smtp-plain");
    let hook = raw(&pool, "SELECT target_secret FROM alert_actions").await;
    assert_eq!(open(COL_WEBHOOK_SECRET, &hook).unwrap(), "Bearer hook-plain");
}

#[tokio::test]
async fn new_signing_keys_are_stored_encrypted() {
    let pool = db().await;
    // initialize_database's default-tenant key.
    assert!(raw(&pool, "SELECT private_key FROM tenant_keys WHERE tenant_id = 'default'").await.starts_with(PREFIX));
    scmserver::settings::settings_rotate_keys(admin(), Extension(pool.clone()), ClientIp("127.0.0.1".into()))
        .await.into_response();
    assert!(raw(&pool, "SELECT private_key FROM tenant_keys WHERE tenant_id = 'default' AND is_active = 1").await
        .starts_with(PREFIX));
    signs_for(&pool, "default").await;
}

fn dir_form(bind_password: &str) -> DirectoryForm {
    DirectoryForm {
        name: "AD".into(), host: "ldap.example".into(), port: "389".into(),
        use_tls: None, skip_tls_verify: None, base_dn: "dc=x".into(),
        bind_dn: "cn=svc".into(), bind_password: bind_password.into(), user_attribute: "uid".into(),
    }
}

#[tokio::test]
async fn the_ldap_password_is_encrypted_never_sent_back_and_kept_when_left_blank() {
    let pool = db().await;
    let ip = || ClientIp("127.0.0.1".into());
    directories::add_submit(admin(), Extension(pool.clone()), ip(), Form(dir_form("first-pw"))).await.into_response();
    let stored = raw(&pool, "SELECT bind_password FROM directories").await;
    assert!(stored.starts_with(PREFIX) && !stored.contains("first-pw"), "{stored}");
    let id: i64 = sqlx::query_scalar("SELECT id FROM directories").fetch_one(&pool).await.unwrap();

    let tera = Arc::new(scmserver::init_tera().unwrap());
    let q = Query::<ErrorQuery>::try_from_uri(&"/x".parse().unwrap()).unwrap();
    let page = directories::edit_form(admin(), Path(id), q, Extension(pool.clone()), Extension(tera))
        .await.into_response();
    let body = axum::body::to_bytes(page.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("bind_password"), "the edit form rendered");
    assert!(!html.contains("first-pw"), "the password went back to the browser");
    assert!(html.contains("unchanged if left blank"));

    directories::edit_submit(admin(), Path(id), Extension(pool.clone()), ip(), Form(dir_form(""))).await.into_response();
    assert_eq!(directories::get_by_id(&pool, id).await.unwrap().bind_password, "first-pw", "blank keeps it");

    directories::edit_submit(admin(), Path(id), Extension(pool.clone()), ip(), Form(dir_form("second-pw"))).await.into_response();
    assert_eq!(directories::get_by_id(&pool, id).await.unwrap().bind_password, "second-pw");
    assert!(raw(&pool, "SELECT bind_password FROM directories").await.starts_with(PREFIX));
}

#[tokio::test]
async fn a_saved_webhook_secret_is_encrypted_and_kept_when_left_blank() {
    let pool = db().await;
    sqlx::query("INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'P', '1')")
        .execute(&pool).await.unwrap();
    let save = |id: Option<i64>, secret: &str| {
        let body = format!(
            "name=r&scope_type=policy&policy_id=1&trigger_type=drop&threshold=10\
             &score_axis=test&cooldown_minutes=60&enabled=on\
             &action_webhook=on&target_webhook=https%3A%2F%2Fhook.example%2Fx&secret_webhook={}",
            urlencoding::encode(secret)
        );
        let pool = pool.clone();
        async move {
            let r = scmserver::alerts_admin::alerts_save(
                admin(), Extension(pool), id.map(Path), axum::extract::RawForm(body.into()),
            ).await.into_response();
            r.headers().get("location").unwrap().to_str().unwrap().to_string()
        }
    };
    let to = save(None, "Bearer abc123").await;
    let stored = raw(&pool, "SELECT target_secret FROM alert_actions").await;
    assert!(stored.starts_with(PREFIX) && !stored.contains("abc123"), "{to} / {stored}");
    assert_eq!(open(COL_WEBHOOK_SECRET, &stored).unwrap(), "Bearer abc123");

    let id: i64 = sqlx::query_scalar("SELECT id FROM alerts").fetch_one(&pool).await.unwrap();
    save(Some(id), "").await;
    let kept = raw(&pool, "SELECT target_secret FROM alert_actions").await;
    assert_eq!(open(COL_WEBHOOK_SECRET, &kept).unwrap(), "Bearer abc123", "blank keeps it");
}

#[tokio::test]
async fn a_saved_sso_client_secret_is_encrypted() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = db().await;
    // Saved disabled: nothing is fetched from the issuer.
    let form = "name=IdP&issuer_url=http%3A%2F%2F127.0.0.1%3A9%2F&client_id=cid&client_secret=very-secret";
    scmserver::sso::save_provider(&pool, &admin(), "127.0.0.1", form, false).await.unwrap();
    let stored = raw(&pool, "SELECT client_secret FROM sso_providers").await;
    assert!(stored.starts_with(PREFIX) && !stored.contains("very-secret"), "{stored}");
    assert_eq!(scmserver::sso::load_provider(&pool, "default").await.unwrap().client_secret, "very-secret");
}

#[tokio::test]
async fn a_webhook_delivery_sends_the_decrypted_secret() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = db().await;

    // A one-shot HTTP endpoint that reports the Authorization header it got.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let auth = req.lines()
            .find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: ")))
            .unwrap_or("").to_string();
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        let _ = tx.send(auth);
    });

    let target = format!("http://127.0.0.1:{port}/hook");
    for (sql, bind) in [
        ("INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'P', '1')", None),
        ("INSERT INTO alerts (id, tenant_id, name, scope_type, policy_id, trigger_type, threshold, score_axis, cooldown_minutes)
          VALUES (1, 'default', 'r', 'policy', 1, 'drop', 10, 'test', 60)", None),
        ("INSERT INTO alert_actions (id, alert_id, action, target, target_secret) VALUES (7, 1, 'webhook', ?, ?)",
         Some(seal(COL_WEBHOOK_SECRET, "Bearer abc123"))),
    ] {
        let mut q = sqlx::query(sql);
        if let Some(secret) = bind { q = q.bind(&target).bind(secret); }
        q.execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO alert_deliveries
                   (tenant_id, alert_id, action_id, policy_id, alert_name, policy_name,
                    old_score, new_score, action, target, status)
                 VALUES ('default', 1, 7, 1, 'r', 'P', 94.0, 61.0, 'webhook', ?, 'pending')")
        .bind(&target).execute(&pool).await.unwrap();

    scmserver::alert_delivery::deliver_pending(&pool).await;
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await
        .expect("the webhook was called").unwrap();
    assert_eq!(got, "Bearer abc123");
}
