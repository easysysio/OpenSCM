// =============================================================================
// startup_guards.rs — the server refuses a newer database and a second server
//
// Step 1 of docs/design/1.0.0-backup-restore.md:
//   D6  a database stamped with a schema newer than this build is refused,
//       before anything in it is changed;
//   D4  one server per database, through an exclusive lock file.
// =============================================================================

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::path::PathBuf;

use scmserver::schema::{initialize_database, run_migrations, SCHEMA_VERSION};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: temp_dir
// A fresh, empty directory for one test.
// ─────────────────────────────────────────────────────────────────────────────
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "openscm-{tag}-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: file_pool
// A database file in `dir`, with the pool settings main.rs uses.
// ─────────────────────────────────────────────────────────────────────────────
async fn file_pool(dir: &PathBuf) -> SqlitePool {
    let path = dir.join("scm.db");
    std::fs::File::create(&path).unwrap();
    SqlitePoolOptions::new()
        .after_connect(|conn, _| Box::pin(async move {
            use sqlx::Executor;
            conn.execute("PRAGMA journal_mode = WAL").await?;
            conn.execute("PRAGMA foreign_keys = ON").await?;
            Ok(())
        }))
        .connect(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: schema_dump
// Every object's SQL plus the stamped version: equal dumps mean nothing in the
// schema changed.
// ─────────────────────────────────────────────────────────────────────────────
async fn schema_dump(pool: &SqlitePool) -> (Vec<String>, i64) {
    let sql: Vec<String> = sqlx::query_scalar(
        "SELECT type || ':' || name || ':' || COALESCE(sql, '') FROM sqlite_master ORDER BY type, name"
    ).fetch_all(pool).await.unwrap();
    let v: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(pool).await.unwrap();
    (sql, v)
}

// The constant the guard compares against must be the version the migration
// chain actually reaches; otherwise the server would refuse its own database
// on the next start.
#[tokio::test]
async fn schema_version_constant_matches_the_migration_chain() {
    let dir = temp_dir("schema-const");
    let pool = file_pool(&dir).await;
    initialize_database(&pool).await.unwrap();
    run_migrations(&pool).await.unwrap();
    assert_eq!(schema_dump(&pool).await.1, SCHEMA_VERSION,
        "SCHEMA_VERSION must equal the version the last migration stamps");
    // A second start on the same database is accepted.
    run_migrations(&pool).await.expect("restart on a current database");
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn database_from_a_newer_openscm_is_refused_untouched() {
    let dir = temp_dir("schema-newer");
    let pool = file_pool(&dir).await;
    initialize_database(&pool).await.unwrap();
    run_migrations(&pool).await.unwrap();
    // Pretend a newer OpenSCM migrated it one step further.
    sqlx::query("UPDATE schema_info SET version = ?")
        .bind(SCHEMA_VERSION + 1).execute(&pool).await.unwrap();
    let before = schema_dump(&pool).await;

    let err = run_migrations(&pool).await.expect_err("a newer database must be refused");
    let msg = err.to_string();
    assert!(msg.contains(&format!("schema version {}", SCHEMA_VERSION + 1)), "{msg}");
    assert!(msg.contains(&format!("up to version {}", SCHEMA_VERSION)), "{msg}");

    assert_eq!(schema_dump(&pool).await, before, "the refused database was changed");
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn second_server_on_the_same_database_is_refused() {
    let dir = temp_dir("instance-lock");
    let db = dir.join("scm.db");
    let db = db.to_str().unwrap();

    let first = scmserver::instance_lock::acquire(db).expect("first server takes the lock");
    let pid = std::fs::read_to_string(scmserver::instance_lock::lock_path(db)).unwrap();
    assert_eq!(pid.trim(), std::process::id().to_string());

    let err = scmserver::instance_lock::acquire(db).expect_err("second server must be refused");
    assert!(err.contains("already using this database"), "{err}");
    // The refused attempt must not wipe the running server's PID.
    let still = std::fs::read_to_string(scmserver::instance_lock::lock_path(db)).unwrap();
    assert_eq!(still, pid);

    drop(first);
    scmserver::instance_lock::acquire(db).expect("lock is free once the first server exits");
    let _ = std::fs::remove_dir_all(&dir);
}
