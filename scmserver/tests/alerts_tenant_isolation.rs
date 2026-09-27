// alerts_tenant_isolation.rs — an admin can only change their own tenant's alerts.
//
// alerts_save updated the rule with `WHERE id = ? AND tenant_id = ?` but then
// rewrote alert_actions whenever the UPDATE merely *succeeded* — and an UPDATE
// that matches no row succeeds. An admin in one SaaS tenant could therefore
// post to another tenant's (sequential) alert id and replace its destinations;
// because a blank secret means "keep the stored one", the victim's alerts then
// went to the attacker's webhook signed with the victim's own secret.

use axum::extract::{Path, RawForm};
use axum::response::IntoResponse;
use axum::Extension;
use scmserver::models::AuthSession;
use sqlx::SqlitePool;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// Two tenants, each with a policy; the default tenant owns alert 1, which has
// a webhook action carrying a stored secret.
// ─────────────────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'Victim policy', '1')",
        "INSERT INTO policies (id, tenant_id, name, version) VALUES (2, 'acme', 'Acme policy', '1')",
        "INSERT INTO alerts (id, tenant_id, name, scope_type, policy_id, trigger_type, threshold,
                             score_axis, cooldown_minutes)
         VALUES (1, 'default', 'victim rule', 'policy', 1, 'drop', 10, 'test', 60)",
        "INSERT INTO alert_actions (alert_id, action, target, target_secret)
         VALUES (1, 'webhook', 'https://victim.example/hook', 's3cret')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap();
    }
    pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: admin
// ─────────────────────────────────────────────────────────────────────────────
fn admin(tenant: &str) -> AuthSession {
    AuthSession {
        username: format!("{tenant}-admin"),
        userid: 1,
        tenant_id: tenant.to_string(),
        role: "admin".to_string(),
        impersonating: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: save
// Posts the alert form and returns the redirect target.
// ─────────────────────────────────────────────────────────────────────────────
async fn save(pool: &SqlitePool, who: &str, id: Option<i64>, policy: i64, hook: &str) -> String {
    let body = format!(
        "name=renamed&scope_type=policy&policy_id={policy}&trigger_type=drop&threshold=10\
         &score_axis=test&cooldown_minutes=60&enabled=on\
         &action_webhook=on&target_webhook={}&secret_webhook=",
        urlencoding::encode(hook)
    );
    let resp = scmserver::alerts_admin::alerts_save(
        admin(who),
        Extension(pool.clone()),
        id.map(Path),
        RawForm(body.into()),
    )
    .await
    .into_response();
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
}

async fn victim_actions(pool: &SqlitePool) -> Vec<(String, Option<String>, Option<String>)> {
    sqlx::query_as("SELECT action, target, target_secret FROM alert_actions WHERE alert_id = 1")
        .fetch_all(pool).await.unwrap()
}

#[tokio::test]
async fn another_tenant_cannot_rewrite_an_alerts_actions() {
    let pool = db().await;

    let to = save(&pool, "acme", Some(1), 2, "https://attacker.example/steal").await;
    assert!(to.contains("error_message"), "the foreign update must be refused, got {to}");

    assert_eq!(
        victim_actions(&pool).await,
        vec![("webhook".into(), Some("https://victim.example/hook".into()), Some("s3cret".into()))],
        "the victim's destination and secret must be untouched"
    );
    let name: String = sqlx::query_scalar("SELECT name FROM alerts WHERE id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(name, "victim rule");
}

// The fix must not break the owner's own edit — including the rule that a
// blank secret keeps the stored one.
#[tokio::test]
async fn the_owner_can_still_edit_and_keeps_the_stored_secret() {
    let pool = db().await;

    let to = save(&pool, "default", Some(1), 1, "https://victim.example/new").await;
    assert!(to.contains("success_message"), "owner edit refused: {to}");
    assert_eq!(
        victim_actions(&pool).await,
        vec![("webhook".into(), Some("https://victim.example/new".into()), Some("s3cret".into()))],
    );
}

// A rule may only point at the caller's own policies.
#[tokio::test]
async fn a_rule_cannot_reference_another_tenants_policy() {
    let pool = db().await;

    let to = save(&pool, "acme", None, 1, "https://acme.example/hook").await;
    assert!(to.contains("error_message"), "a foreign policy id must be refused, got {to}");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE tenant_id = 'acme'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(n, 0, "no rule may be created");

    // And with its own policy, creation works.
    let to = save(&pool, "acme", None, 2, "https://acme.example/hook").await;
    assert!(to.contains("success_message"), "own-policy create refused: {to}");
}
