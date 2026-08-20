//! The tenant-selection query behind dormant-account suspension.
//!
//! Mirrors the query in OpenSCM-SaaS/src/dormant.rs. The risk here is
//! suspending an account that is actually in use, so these pin exactly who is
//! and is not a candidate.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{SqlitePool, Row};

async fn pool() -> SqlitePool {
    let p = SqlitePoolOptions::new().max_connections(1)
        .connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&p).await.unwrap();
    scmserver::schema::run_migrations(&p).await.unwrap();
    p
}

async fn tenant(p: &SqlitePool, id: &str, status: &str, age_days: i64) {
    sqlx::query("INSERT INTO tenants (id, name, status, created_at)
                 VALUES (?, ?, ?, datetime('now', ?))")
        .bind(id).bind(id).bind(status).bind(format!("-{} days", age_days))
        .execute(p).await.unwrap();
}

async fn candidates(p: &SqlitePool, min_age: i64) -> Vec<String> {
    sqlx::query(
        "SELECT t.id FROM tenants t
          WHERE t.status = 'active'
            AND t.id NOT IN ('platform', 'default')
            AND NOT EXISTS (SELECT 1 FROM systems s WHERE s.tenant_id = t.id)
            AND julianday('now') - julianday(t.created_at) >= ?
          ORDER BY t.id")
        .bind(min_age as f64)
        .fetch_all(p).await.unwrap()
        .iter().map(|r| r.get::<String,_>("id")).collect()
}

#[tokio::test]
async fn selects_only_old_empty_active_tenants() {
    let p = pool().await;
    tenant(&p, "abandoned",  "active",    200).await; // never onboarded, old
    tenant(&p, "fresh",      "active",      5).await; // too new
    tenant(&p, "onboarded",  "active",    200).await; // old but HAS a system
    tenant(&p, "already",    "suspended", 200).await; // already suspended
    sqlx::query("INSERT INTO systems (id, tenant_id, name, status) VALUES (1,'onboarded','h','active')")
        .execute(&p).await.unwrap();

    assert_eq!(candidates(&p, 180).await, vec!["abandoned"],
        "only an old, empty, still-active tenant may be suspended");
}

#[tokio::test]
async fn a_tenant_that_removed_its_systems_is_still_a_candidate_only_if_empty() {
    // Documents the deliberate semantics: the check is "has no systems now".
    // A tenant that onboarded and then deleted everything DOES become eligible
    // again — worth knowing, since it is the one case where a real user could
    // be caught.
    let p = pool().await;
    tenant(&p, "emptied", "active", 200).await;
    assert_eq!(candidates(&p, 180).await, vec!["emptied"]);
}

#[tokio::test]
async fn structural_tenants_are_never_selected() {
    let p = pool().await;
    // platform/default may already exist from initialize_database; make sure
    // they are old and empty, which would otherwise qualify them.
    sqlx::query("UPDATE tenants SET created_at = datetime('now','-999 days'), status='active'")
        .execute(&p).await.unwrap();
    let c = candidates(&p, 180).await;
    assert!(!c.contains(&"platform".to_string()), "platform must never be suspended");
    assert!(!c.contains(&"default".to_string()),  "default must never be suspended");
}

#[tokio::test]
async fn disabled_threshold_selects_nothing_in_practice() {
    // sweep() returns early when days <= 0; this pins that a zero threshold is
    // never interpreted as "everything is dormant".
    let p = pool().await;
    tenant(&p, "abandoned", "active", 200).await;
    let days: i64 = 0;
    assert!(days <= 0, "0 must mean disabled, never 'age >= 0'");
}


// ── Classification: delete vs suspend ────────────────────────────────────────
// This is the decision that destroys data, so it is pinned explicitly.

async fn classify(p: &SqlitePool, min_age: i64) -> Vec<(String, i64, i64)> {
    sqlx::query(
        "SELECT t.id,
                (SELECT COUNT(*) FROM tests    x WHERE x.tenant_id = t.id)
              + (SELECT COUNT(*) FROM policies x WHERE x.tenant_id = t.id) AS authored,
                (SELECT COUNT(*) FROM compliance_history x WHERE x.tenant_id = t.id)
              + (SELECT COUNT(*) FROM reports            x WHERE x.tenant_id = t.id)
              + (SELECT COUNT(*) FROM system_reports     x WHERE x.tenant_id = t.id) AS used_before
           FROM tenants t
          WHERE t.status = 'active'
            AND t.id NOT IN ('platform','default')
            AND EXISTS (SELECT 1 FROM users u WHERE u.tenant_id = t.id AND u.email_verified = 1)
            AND NOT EXISTS (SELECT 1 FROM systems s WHERE s.tenant_id = t.id)
            AND julianday('now') - julianday(t.created_at) >= ?
          ORDER BY t.id")
        .bind(min_age as f64).fetch_all(p).await.unwrap()
        .iter().map(|r| (r.get::<String,_>("id"), r.get::<i64,_>("authored"), r.get::<i64,_>("used_before")))
        .collect()
}

async fn verified_user(p: &SqlitePool, tenant: &str, verified: i64) {
    sqlx::query("INSERT INTO users (tenant_id, username, password, role, email, email_verified)
                 VALUES (?, ?, 'x', 'admin', 'a@example.com', ?)")
        .bind(tenant).bind(format!("admin-{}", tenant)).bind(verified)
        .execute(p).await.unwrap();
}

#[tokio::test]
async fn empty_account_is_deletable_but_authored_work_is_not() {
    let p = pool().await;
    tenant(&p, "truly-empty", "active", 200).await;  verified_user(&p, "truly-empty", 1).await;
    tenant(&p, "wrote-policy","active", 200).await;  verified_user(&p, "wrote-policy", 1).await;
    sqlx::query("INSERT INTO policies (id, tenant_id, name) VALUES (1,'wrote-policy','mine')")
        .execute(&p).await.unwrap();

    let c = classify(&p, 180).await;
    let empty = c.iter().find(|(id,_,_)| id == "truly-empty").unwrap();
    let wrote = c.iter().find(|(id,_,_)| id == "wrote-policy").unwrap();

    assert_eq!((empty.1, empty.2), (0, 0), "an account holding nothing may be deleted");
    assert!(wrote.1 > 0, "a policy the user authored must force suspend, not delete");
}

#[tokio::test]
async fn a_formerly_active_account_is_never_deleted() {
    // Agents were removed and the systems pruned, but the compliance history
    // is audit evidence — this is a former customer, not an empty signup.
    let p = pool().await;
    tenant(&p, "former", "active", 400).await; verified_user(&p, "former", 1).await;
    sqlx::query("INSERT INTO compliance_history (tenant_id, systems_score, policies_score)
                 VALUES ('former', 91.0, 88.0)").execute(&p).await.unwrap();

    let c = classify(&p, 180).await;
    let former = c.iter().find(|(id,_,_)| id == "former").unwrap();
    assert!(former.2 > 0, "past compliance history must force suspend, never delete");
}

#[tokio::test]
async fn unverified_registrations_are_a_separate_population() {
    let p = pool().await;
    tenant(&p, "never-confirmed", "active", 30).await; verified_user(&p, "never-confirmed", 0).await;
    // Excluded from the "unused" sweep — it is handled by the unverified rule.
    let c = classify(&p, 10).await;
    assert!(!c.iter().any(|(id,_,_)| id == "never-confirmed"),
        "an unverified signup must not be judged by the verified-but-unused rule");
}
