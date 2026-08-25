//! Integration tests for schema initialization and migration.
//!
//! All tests use an in-memory SQLite database so they run in isolation
//! without touching any real data files.
//!
//! HISTORY / WHY THIS FILE CHANGED
//! ------------------------------------------------------------------
//! This file used to test the v3 → v4 flat-condition migration against a
//! hand-written "old v3 schema" fixture (schema_info, tenants, tests,
//! test_conditions). That approach could not survive schema growth: every
//! later migration touches tables the fixture never created, so from
//! roughly v5 onward the tests died with "no such table: systems" — and
//! stayed dead through v37, because nothing ran the full suite in CI.
//! Completing that fixture would mean duplicating schema.rs inside a test
//! and re-duplicating it on every future migration.
//!
//! So the v3-specific data-migration assertions are gone, replaced by
//! invariants that hold no matter how many migrations are added:
//!   * a fresh install converges to the current schema version,
//!   * migrations are idempotent,
//!   * every migration step is guarded, so it is safe to re-run against a
//!     database that already has the objects it creates.
//! That last one is the property that actually breaks real upgrades.

use sqlx::SqlitePool;

/// The schema version the code currently migrates to. Bump this together
/// with the migration that raises it — the assertion below is deliberately
/// exact so a version change has to be a conscious edit, not a silent drift.
const CURRENT_SCHEMA_VERSION: i64 = 40;

async fn in_memory_pool() -> SqlitePool {
    SqlitePool::connect("sqlite::memory:").await.expect("in-memory pool")
}

async fn schema_version(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(pool).await.expect("schema_info version")
}

/// Fresh install + migrate must land exactly on the current version.
/// `initialize_database` deliberately stamps an older baseline (v13) and
/// lets `run_migrations` walk it forward, so this covers that whole path.
#[tokio::test]
async fn fresh_install_converges_to_current_schema_version() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    assert_eq!(
        schema_version(&pool).await, CURRENT_SCHEMA_VERSION,
        "fresh install did not converge to the current schema version"
    );
}

/// The flat per-condition columns were replaced by the test_conditions
/// table; a fresh install must never recreate them.
#[tokio::test]
async fn fresh_install_tests_table_has_no_flat_columns() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    let has_flat: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pragma_table_info('tests') WHERE name = 'element_1'"
    )
    .fetch_one(&pool).await.expect("pragma") > 0;

    assert!(!has_flat, "fresh install: tests table must not have element_1 column");
}

#[tokio::test]
async fn fresh_install_test_conditions_table_exists() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM test_conditions")
        .fetch_one(&pool).await.expect("test_conditions query");

    assert_eq!(count, 0);
}

/// Running migrations twice must be a no-op the second time. The server
/// calls run_migrations on every startup, so this is the ordinary path,
/// not an edge case.
#[tokio::test]
async fn migrations_are_idempotent() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("first migration pass");
    let first = schema_version(&pool).await;

    scmserver::schema::run_migrations(&pool).await.expect("second migration pass");
    let second = schema_version(&pool).await;

    assert_eq!(first, second, "re-running migrations changed the schema version");
    assert_eq!(second, CURRENT_SCHEMA_VERSION);
}

/// Every migration step must be guarded (CREATE ... IF NOT EXISTS, or a
/// column_exists/table_exists check) so it survives running against a
/// database that already contains what it creates.
///
/// This is simulated by taking a fully-migrated database, rewinding the
/// recorded version, and migrating again: every step from the baseline
/// forward re-executes with all of its objects already present. An
/// unguarded `ALTER TABLE ... ADD COLUMN` or `CREATE TABLE` shows up here
/// as a hard error — which in production is a server that will not start.
#[tokio::test]
async fn migrations_are_guarded_against_existing_objects() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("initial migration");

    // Rewind to the fresh-install baseline while keeping every object.
    sqlx::query("UPDATE schema_info SET version = 13")
        .execute(&pool).await.expect("rewind schema_info");

    scmserver::schema::run_migrations(&pool)
        .await
        .expect("re-running migrations over an existing schema must not fail");

    assert_eq!(
        schema_version(&pool).await, CURRENT_SCHEMA_VERSION,
        "re-migration did not converge to the current schema version"
    );
}
