// offline_threshold_default.rs — a system is offline after 60 minutes.
//
// Every fresh install since schema v16 ended up with 1 minute: the setting
// was seeded as 60 (minutes) and then the v15 → v16 step, which every fresh
// database runs, divided it by 60 as if it were seconds. With agents checking
// in every 5 minutes, systems showed offline most of the time. SaaS seeded
// new organizations with 3600 — meant as seconds, read as minutes.

use sqlx::SqlitePool;

async fn threshold(pool: &SqlitePool, tenant: &str) -> String {
    sqlx::query_scalar("SELECT value FROM settings WHERE tenant_id = ? AND skey = 'offline_threshold'")
        .bind(tenant).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn a_fresh_install_gets_60_minutes() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    assert_eq!(threshold(&pool, "default").await, "60");
}

#[tokio::test]
async fn values_nobody_chose_are_repaired_and_real_choices_kept() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme'), ('globex', 'Globex'), ('initech', 'Initech')",
        // The fresh-install bug, on the default tenant.
        "UPDATE settings SET value = '1' WHERE tenant_id = 'default' AND skey = 'offline_threshold'",
        // The SaaS seed: 3600 'seconds', read as minutes.
        "INSERT INTO settings (tenant_id, skey, value) VALUES ('acme', 'offline_threshold', '3600')",
        // Real choices: an organization that wants 1 minute, and one with 15.
        "INSERT INTO settings (tenant_id, skey, value) VALUES ('globex', 'offline_threshold', '1')",
        "INSERT INTO settings (tenant_id, skey, value) VALUES ('initech', 'offline_threshold', '15')",
        "UPDATE schema_info SET version = 46",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    scmserver::schema::run_migrations(&pool).await.unwrap();
    assert_eq!(threshold(&pool, "default").await, "60");
    assert_eq!(threshold(&pool, "acme").await, "60");
    assert_eq!(threshold(&pool, "globex").await, "1", "outside the default tenant, 1 can be a real choice");
    assert_eq!(threshold(&pool, "initech").await, "15");
}
