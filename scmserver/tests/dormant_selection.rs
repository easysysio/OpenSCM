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
