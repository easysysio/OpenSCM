// backup_jobs.rs — scheduled backups, "Back up now", retention, status, and
// Settings → Backup (src/backup_jobs.rs, src/settings.rs).
//
// Each test builds its own server in a temporary directory and its own
// `Backups` runner, so nothing touches the installed server and tests do not
// share the "already running" flag.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Form, Query};
use axum::response::IntoResponse;
use axum::Extension;
use base64::{engine::general_purpose, Engine as _};
use chrono::NaiveDateTime;
use scmserver::backup::Paths;
use scmserver::backup_jobs::{self, BackupSettings, Backups, Trigger};
use scmserver::handlers::ClientIp;
use scmserver::models::AuthSession;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const PASS: &str = "correct horse battery";

struct Server {
    _dir: tempfile::TempDir,
    pool: SqlitePool,
    jobs: Arc<Backups>,
    pass_file: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: server
// A migrated WAL database with a superuser and an admin, a key pair, and a
// passphrase file (owner-only) — the runner's backups/ is next to the DB.
// ─────────────────────────────────────────────────────────────────────────────
async fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("scm.db");
    std::fs::File::create(&db).unwrap();
    let pool = SqlitePoolOptions::new()
        .after_connect(|conn, _| Box::pin(async move {
            use sqlx::Executor;
            conn.execute("PRAGMA journal_mode = WAL").await?;
            conn.execute("PRAGMA busy_timeout = 10000").await?;
            Ok(())
        }))
        .connect(&format!("sqlite://{}?mode=rwc", db.display())).await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, role) VALUES
                 (1, 'default', 'root', 'x', 'superuser'), (2, 'default', 'alice', 'x', 'admin')")
        .execute(&pool).await.unwrap();

    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let private_key = keys.join("scmserver.key");
    let public_key = keys.join("scmserver.pub");
    std::fs::write(&private_key, general_purpose::STANDARD.encode(sk.to_bytes())).unwrap();
    std::fs::write(&public_key, general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())).unwrap();
    let config = dir.path().join("scmserver.config");
    std::fs::write(&config, "[server]\n").unwrap();

    let pass_file = dir.path().join("backup.passphrase");
    backup_jobs::write_passphrase_file(&pass_file, PASS, &private_key).unwrap();
    let jobs = Arc::new(Backups::new(Paths { db, private_key, public_key, config }, pass_file.clone()).with_work_factor(10));
    Server { pool, jobs, pass_file, _dir: dir }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).map(|rd| rd.map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();
    v.sort();
    v
}

async fn audit(pool: &SqlitePool, action: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT COALESCE(details,'') FROM audit_log WHERE action = ? ORDER BY id")
        .bind(action).fetch_all(pool).await.unwrap()
}

fn su() -> AuthSession {
    AuthSession { username: "root".into(), userid: 1, tenant_id: "default".into(), role: "superuser".into(), impersonating: None }
}
fn admin() -> AuthSession {
    AuthSession { username: "alice".into(), userid: 2, tenant_id: "default".into(), role: "admin".into(), impersonating: None }
}

fn t(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
}

// v50 seeds the settings: off, 02:00 UTC daily, keep 7.
#[tokio::test]
async fn settings_default_to_off_and_validate() {
    let s = server().await;
    let d = backup_jobs::load_settings(&s.pool).await;
    assert_eq!(d, BackupSettings { enabled: false, schedule: "0 2 * * *".into(), keep: 7 });

    let bad = BackupSettings { enabled: true, schedule: "every night".into(), keep: 7 };
    assert!(backup_jobs::save_settings(&s.pool, &bad).await.unwrap_err().contains("Schedule"));
    let bad = BackupSettings { enabled: true, schedule: "0 3 * * *".into(), keep: 0 };
    assert!(backup_jobs::save_settings(&s.pool, &bad).await.unwrap_err().contains("Keep"));
    assert_eq!(backup_jobs::load_settings(&s.pool).await, d, "a refused save changes nothing");

    let good = BackupSettings { enabled: true, schedule: "30 1 * * 0".into(), keep: 3 };
    backup_jobs::save_settings(&s.pool, &good).await.unwrap();
    assert_eq!(backup_jobs::load_settings(&s.pool).await, good);
}

#[tokio::test]
async fn the_passphrase_file_must_exist_be_long_and_be_private() {
    let s = server().await;
    assert_eq!(backup_jobs::read_passphrase_file(&s.pass_file).unwrap(), PASS);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&s.pass_file).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&s.pass_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(backup_jobs::read_passphrase_file(&s.pass_file).unwrap_err().contains("chmod 600"));
        std::fs::set_permissions(&s.pass_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&s.pass_file, "short\n").unwrap();
    assert!(backup_jobs::read_passphrase_file(&s.pass_file).unwrap_err().contains("shorter than 12"));
    std::fs::write(&s.pass_file, format!("{PASS}\r\n")).unwrap();
    assert_eq!(backup_jobs::read_passphrase_file(&s.pass_file).unwrap(), PASS, "one trailing newline dropped");
    std::fs::remove_file(&s.pass_file).unwrap();
    assert!(backup_jobs::read_passphrase_file(&s.pass_file).unwrap_err().contains("set-passphrase"));
    assert!(backup_jobs::write_passphrase_file(&s.pass_file, "short", &s.pass_file).is_err());
}

// A run writes a verified backup, records it, and keeps the newest `keep`.
#[tokio::test]
async fn runs_write_verify_record_and_keep_the_newest() {
    let s = server().await;
    backup_jobs::save_settings(&s.pool, &BackupSettings { enabled: true, schedule: "0 2 * * *".into(), keep: 2 }).await.unwrap();
    let dir = s.jobs.dir().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("notes.txt"), b"not a backup").unwrap();

    let mut made = Vec::new();
    for _ in 0..3 {
        let r = s.jobs.run(&s.pool, Trigger::Manual { user_id: 1, username: "root".into() }).await.expect("run");
        made.push(r.path.file_name().unwrap().to_string_lossy().to_string());
    }
    let left = names(&dir);
    assert_eq!(left.len(), 3, "two backups and the unrelated file: {left:?}");
    assert!(left.contains(&"notes.txt".to_string()), "retention touches only backups");
    assert!(!left.contains(&made[0]), "the oldest went: {left:?}");
    assert!(left.contains(&made[1]) && left.contains(&made[2]));

    let st = s.jobs.status(&s.pool).await;
    assert_eq!(st.last_result.as_deref(), Some("ok"));
    assert_eq!(st.last_file.as_deref(), Some(made[2].as_str()));
    assert_eq!(st.last_trigger.as_deref(), Some("manual"));
    assert_eq!(st.files.len(), 2);
    assert!(st.passphrase_problem.is_none());
    let a = audit(&s.pool, "backup.create").await;
    assert_eq!(a.len(), 3);
    assert!(a[2].contains("verified") && a[2].contains("deleted 1 older"), "{}", a[2]);
    assert!(s.jobs.dashboard_notice(&s.pool).await.is_none(), "all is well: no banner");
}

// A failed run deletes nothing, is recorded, and reaches superusers.
#[tokio::test]
async fn a_failed_run_keeps_everything_and_tells_superusers() {
    let s = server().await;
    backup_jobs::save_settings(&s.pool, &BackupSettings { enabled: true, schedule: "0 2 * * *".into(), keep: 1 }).await.unwrap();
    let good = s.jobs.run(&s.pool, Trigger::Scheduled).await.unwrap();
    std::fs::remove_file(&s.pass_file).unwrap();

    let e = s.jobs.run(&s.pool, Trigger::Scheduled).await.unwrap_err();
    assert!(e.contains("set-passphrase"), "{e}");
    assert_eq!(names(s.jobs.dir()), vec![good.path.file_name().unwrap().to_string_lossy().to_string()]);

    let st = s.jobs.status(&s.pool).await;
    assert_eq!(st.last_result.as_deref(), Some("failed"));
    assert!(st.last_error.unwrap().contains("set-passphrase"));
    assert!(st.last_ok_at.is_some(), "the last good backup is still shown");
    assert_eq!(audit(&s.pool, "backup.failed").await.len(), 1);
    let bell: Vec<(i32, String)> = sqlx::query_as("SELECT owner_id, message FROM notify").fetch_all(&s.pool).await.unwrap();
    assert_eq!(bell.len(), 1, "the superuser only, not the admin: {bell:?}");
    assert_eq!(bell[0].0, 1);
    assert!(bell[0].1.starts_with("Backup failed"));
    assert!(s.jobs.dashboard_notice(&s.pool).await.unwrap().contains("cannot run"));
}

#[tokio::test]
async fn two_runs_never_overlap() {
    let s = server().await;
    let (a, b) = tokio::join!(
        s.jobs.run(&s.pool, Trigger::Scheduled),
        s.jobs.run(&s.pool, Trigger::Scheduled),
    );
    let errs: Vec<String> = [a, b].into_iter().filter_map(|r| r.err()).collect();
    assert_eq!(errs, vec!["A backup is already running.".to_string()]);
    assert!(!s.jobs.is_running());
}

// The schedule: due from the last attempt (so a run missed while the server
// was down happens at the next tick), advanced at once, off when disabled.
#[tokio::test]
async fn the_schedule_runs_when_due_and_catches_up() {
    let s = server().await;
    assert!(s.jobs.tick(&s.pool, t("2026-10-29 12:00:00")).await.is_none(), "off by default");

    backup_jobs::save_settings(&s.pool, &BackupSettings { enabled: true, schedule: "0 2 * * *".into(), keep: 7 }).await.unwrap();
    sqlx::query("INSERT INTO settings (tenant_id, skey, value) VALUES ('default', 'backup_last_at', '2026-10-27 02:00:05')")
        .execute(&s.pool).await.unwrap();
    // The 28th's run was missed; at noon on the 29th it is overdue.
    assert_eq!(s.jobs.next_run(&s.pool, t("2026-10-29 12:00:00")).await, Some(t("2026-10-28 02:00:00")));
    let h = s.jobs.tick(&s.pool, t("2026-10-29 12:00:00")).await.expect("overdue: runs");
    h.await.unwrap();
    assert_eq!(audit(&s.pool, "backup.create").await.len(), 1);
    assert!(audit(&s.pool, "backup.create").await[0].starts_with("scheduled"));
    // Advanced to the next slot; nothing more until then.
    assert_eq!(s.jobs.next_run(&s.pool, t("2026-10-29 12:01:00")).await, Some(t("2026-10-30 02:00:00")));
    assert!(s.jobs.tick(&s.pool, t("2026-10-29 12:01:00")).await.is_none());
    assert!(s.jobs.tick(&s.pool, t("2026-10-30 01:59:00")).await.is_none());

    // A new schedule takes effect without a restart.
    backup_jobs::save_settings(&s.pool, &BackupSettings { enabled: true, schedule: "0 * * * *".into(), keep: 7 }).await.unwrap();
    assert!(s.jobs.next_run(&s.pool, t("2026-10-29 12:01:00")).await.unwrap() <= t("2026-10-29 13:00:00"));

    backup_jobs::save_settings(&s.pool, &BackupSettings { enabled: false, schedule: "0 * * * *".into(), keep: 7 }).await.unwrap();
    assert!(s.jobs.next_run(&s.pool, t("2026-10-29 12:01:00")).await.is_none());
    assert!(s.jobs.dashboard_notice(&s.pool).await.unwrap().contains("off"));
}

// Settings → Backup: only superusers see it or change anything.
#[tokio::test]
async fn only_superusers_manage_backups() {
    let s = server().await;
    let save = |who: AuthSession| {
        let pool = s.pool.clone();
        async move {
            let mut f = std::collections::HashMap::new();
            f.insert("backup_enabled".to_string(), "1".to_string());
            f.insert("backup_schedule".to_string(), "15 3 * * *".to_string());
            f.insert("backup_keep".to_string(), "5".to_string());
            scmserver::settings::settings_backup_save(who, Extension(pool), ClientIp("10.0.0.1".into()), Form(f))
                .await.into_response()
        }
    };
    let loc = |r: &axum::response::Response| r.headers().get("location").unwrap().to_str().unwrap().to_string();

    let r = save(admin()).await;
    assert!(loc(&r).contains("Access"), "{}", loc(&r));
    assert!(!backup_jobs::load_settings(&s.pool).await.enabled);
    let r = scmserver::settings::settings_backup_run(admin(), Extension(s.pool.clone())).await.into_response();
    assert!(loc(&r).contains("Access"));

    let r = save(su()).await;
    assert!(loc(&r).contains("success_message") && loc(&r).ends_with("#backup"), "{}", loc(&r));
    assert_eq!(backup_jobs::load_settings(&s.pool).await,
               BackupSettings { enabled: true, schedule: "15 3 * * *".into(), keep: 5 });
    assert_eq!(audit(&s.pool, "backup.settings").await.len(), 1);

    // The page: the tab and its contents for the superuser, nothing for an admin.
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let page = |who: AuthSession| {
        let (pool, tera) = (s.pool.clone(), tera.clone());
        async move {
            let q = Query(serde_json::from_value(serde_json::json!({})).unwrap());
            let r = scmserver::settings::settings(who, q, Extension(pool), Extension(tera)).await.into_response();
            String::from_utf8(axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
        }
    };
    let html = page(su()).await;
    assert!(html.contains("id=\"backup-tab\"") && html.contains("/settings/backup/run") && html.contains("15 3 * * *"));
    assert!(!html.to_lowercase().contains("type=\"password\" name=\"backup"), "no passphrase field");
    let html = page(admin()).await;
    assert!(!html.contains("backup-tab") && !html.contains("/settings/backup/"));
}
