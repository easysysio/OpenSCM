// fresh_install_file_db.rs — a fresh install must migrate all the way, on a
// real database file.
//
// From 0.5.0 to 0.9.3 every fresh install stopped at schema v25. The v25 → v26
// rebuild of `results` ran DROP TABLE and then RENAME on whatever connections
// the pool handed out; on a file database in WAL mode the RENAME saw a stale
// `results`, failed, and left the database with no `results` table. /install
// logged it and continued; the next start could not migrate and exited.
//
// Every other migration test uses `sqlite::memory:`, where sqlx's shared-cache
// in-memory database does not behave this way — which is how it went unseen.
// These tests use a file, WAL, and a multi-connection pool configured like
// main.rs, and fail on the pre-0.9.4 run_migrations.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: file_pool
// A fresh database file, with the pool settings main.rs uses.
// ─────────────────────────────────────────────────────────────────────────────
async fn file_pool(tag: &str) -> (SqlitePool, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "openscm-{tag}-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::File::create(&path).unwrap();
    let pool = SqlitePoolOptions::new()
        .after_connect(|conn, _| Box::pin(async move {
            use sqlx::Executor;
            conn.execute("PRAGMA journal_mode = WAL").await?;
            conn.execute("PRAGMA synchronous = NORMAL").await?;
            conn.execute("PRAGMA busy_timeout = 10000").await?;
            conn.execute("PRAGMA foreign_keys = ON").await?;
            Ok(())
        }))
        .connect(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    (pool, path)
}

async fn cleanup(pool: SqlitePool, path: PathBuf) {
    pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
    }
}

async fn version(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT version FROM schema_info").fetch_one(pool).await.unwrap()
}

async fn has_table(pool: &SqlitePool, t: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?")
        .bind(t).fetch_one(pool).await.unwrap() > 0
}

// The /install sequence: initialize, create the admin, migrate.
#[tokio::test]
async fn a_fresh_install_on_a_file_database_reaches_the_current_version() {
    let (pool, path) = file_pool("fresh").await;

    scmserver::schema::initialize_database(&pool).await.unwrap();
    sqlx::query("INSERT OR IGNORE INTO users (id, tenant_id, username, password, role)
                 VALUES (1, 'default', 'admin', 'x', 'superuser')")
        .execute(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.expect("fresh-install migrations must succeed");

    assert_eq!(version(&pool).await, 42);
    for t in ["results", "alerts", "alert_actions", "alert_deliveries", "containers"] {
        assert!(has_table(&pool, t).await, "table {t} missing after a fresh install");
    }
    assert!(!has_table(&pool, "results_new").await, "the rebuild's temporary table must be gone");

    // A second start (main.rs runs migrations every time) is a no-op.
    scmserver::schema::run_migrations(&pool).await.expect("re-running migrations must succeed");
    assert_eq!(version(&pool).await, 42);

    cleanup(pool, path).await;
}

// A database left behind by a failed 0.9.3 install: `results` dropped, its
// rows in results_new, version stuck at 25. The next start must recover it
// rather than fail forever — and keep the rows.
#[tokio::test]
async fn a_database_stuck_at_v25_recovers_on_the_next_start() {
    let (pool, path) = file_pool("stuck").await;

    scmserver::schema::initialize_database(&pool).await.unwrap();
    // Migrate to just before v26 the way 0.9.3 got there, then reproduce the
    // state its failed rebuild left: rows copied into results_new, results
    // dropped, version 25.
    sqlx::query("UPDATE schema_info SET version = 25").execute(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    for q in [
        "INSERT INTO systems (id, tenant_id, name, status) VALUES (1, 'default', 'web1', 'active')",
        "INSERT INTO tests (id, tenant_id, name) VALUES (1, 'default', 'ssh root login')",
        "INSERT INTO results (tenant_id, system_id, test_id, result) VALUES ('default', 1, 1, 'PASS')",
        "ALTER TABLE results RENAME TO results_new",
    ] {
        sqlx::query(q).execute(&mut *conn).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    drop(conn);
    assert!(!has_table(&pool, "results").await);

    scmserver::schema::run_migrations(&pool).await.expect("a stuck database must recover");

    assert_eq!(version(&pool).await, 42);
    assert!(has_table(&pool, "results").await);
    assert!(!has_table(&pool, "results_new").await);
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM results WHERE system_id = 1 AND test_id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(kept, 1, "the rows copied before the failure must survive recovery");

    cleanup(pool, path).await;
}
