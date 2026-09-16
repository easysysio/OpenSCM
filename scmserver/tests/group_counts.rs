// group_counts.rs — the Systems column on the groups page.
//
// The list query LEFT JOINs groups to their members, so an EMPTY group still
// produces one row. Counting rows would report it as 1; this pins that it is 0.

use sqlx::SqlitePool;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for (id, name) in [(1, "web-1"), (2, "web-2"), (3, "db-1")] {
        sqlx::query("INSERT INTO systems (id, tenant_id, name, status) VALUES (?, 'default', ?, 'active')")
            .bind(id).bind(name).execute(&pool).await.unwrap();
    }
    for (id, name) in [(10, "Web"), (11, "Empty"), (12, "Everything")] {
        sqlx::query("INSERT INTO system_groups (id, tenant_id, name) VALUES (?, 'default', ?)")
            .bind(id).bind(name).execute(&pool).await.unwrap();
    }
    for (g, s) in [(10, 1), (10, 2), (12, 1), (12, 2), (12, 3)] {
        sqlx::query("INSERT INTO systems_in_groups (tenant_id, group_id, system_id) VALUES ('default', ?, ?)")
            .bind(g).bind(s).execute(&pool).await.unwrap();
    }
    pool
}

#[tokio::test]
async fn each_group_reports_its_own_member_count() {
    let pool = db().await;
    let groups = scmserver::groups::load_system_groups(&pool, "default").await.unwrap();
    let count = |n: &str| groups.iter().find(|g| g.name == n).unwrap().system_count;

    assert_eq!(count("Web"), 2);
    assert_eq!(count("Empty"), 0, "an empty group must show 0, not the 1 a row count gives");
    assert_eq!(count("Everything"), 3, "a system in several groups counts once in each");
}

#[tokio::test]
async fn another_tenants_groups_are_not_listed() {
    let pool = db().await;
    sqlx::query("INSERT OR IGNORE INTO tenants (id, name) VALUES ('other', 'other')")
        .execute(&pool).await.unwrap();
    let groups = scmserver::groups::load_system_groups(&pool, "other").await.unwrap();
    assert!(groups.is_empty());
}
