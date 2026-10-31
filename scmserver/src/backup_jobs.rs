// =============================================================================
// backup_jobs.rs — scheduled backups, "Back up now", retention and status
//
// The settings (on/off, schedule, how many to keep) are platform-wide rows in
// `settings` under the 'default' tenant, edited by superusers on
// Settings → Backup. Two things are deliberately not settings:
//
//   - the passphrase: a file beside the config (config::backup_passphrase_path),
//     written by `scmserver backup set-passphrase` from the server's shell.
//     A session that could set it could make every later backup readable to
//     its holder: the server key and every stored secret.
//   - the folder: always `backups/` next to the database
//     (backup::default_dir). A web-settable path would let a session make the
//     server write wherever its account can.
//
// Every run writes a backup (backup::create), verifies it (backup::verify),
// and only then prunes the folder to the newest `keep` files. A failed run
// deletes nothing older. Outcomes go to `settings` (status), the audit log,
// and on failure to superusers' bell and the `backup_failed` alert trigger.
//
// Design: docs/design/1.0.0-backup-restore.md, D3 and D9.
// =============================================================================

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::SqlitePool;
use tracing::{error, info, warn};

use crate::backup::{self, Paths, MIN_PASSPHRASE_LEN};

pub const DEFAULT_SCHEDULE: &str = "0 2 * * *";
pub const DEFAULT_KEEP: u32 = 7;
pub const MAX_KEEP: u32 = 365;
const STATUS_TIME: &str = "%Y-%m-%d %H:%M:%S";

/// The editable settings.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BackupSettings {
    pub enabled: bool,
    pub schedule: String,
    pub keep: u32,
}

/// One backup file in the folder.
#[derive(Debug, Clone, Serialize)]
pub struct BackupFile {
    pub name: String,
    pub size: String,
    pub modified: String,
}

/// Everything Settings → Backup shows.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub settings: BackupSettings,
    pub dir: String,
    pub passphrase_path: String,
    pub passphrase_problem: Option<String>,
    pub schedule_problem: Option<String>,
    pub running: bool,
    pub next_run: Option<String>,
    pub last_at: Option<String>,
    pub last_result: Option<String>,
    pub last_trigger: Option<String>,
    pub last_file: Option<String>,
    pub last_size: Option<String>,
    pub last_error: Option<String>,
    pub last_ok_at: Option<String>,
    pub files: Vec<BackupFile>,
}

/// Who started a run, for the audit log.
#[derive(Debug, Clone)]
pub enum Trigger {
    Scheduled,
    Manual { user_id: i32, username: String },
}

impl Trigger {
    fn label(&self) -> &'static str {
        match self {
            Trigger::Scheduled => "scheduled",
            Trigger::Manual { .. } => "manual",
        }
    }
}

/// A successful run.
#[derive(Debug)]
pub struct RunResult {
    pub path: PathBuf,
    pub size: u64,
    pub pruned: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct: Backups
// The job runner for one server. `installed()` for the real server; tests
// build their own with temporary paths.
// ─────────────────────────────────────────────────────────────────────────────
pub struct Backups {
    paths: Paths,
    passphrase_file: PathBuf,
    dir: PathBuf,
    running: AtomicBool,
    /// (schedule it was computed from, next run in UTC)
    next: Mutex<Option<(String, NaiveDateTime)>>,
    work_factor: Option<u8>,
}

static GLOBAL: OnceLock<Arc<Backups>> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// Function: global
// The server's runner, created on first use from the installed paths.
// ─────────────────────────────────────────────────────────────────────────────
pub fn global() -> Arc<Backups> {
    GLOBAL.get_or_init(|| Arc::new(Backups::installed())).clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: setting / set_setting
// Platform-wide rows under the 'default' tenant.
// ─────────────────────────────────────────────────────────────────────────────
async fn setting(pool: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM settings WHERE tenant_id = 'default' AND skey = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .filter(|v: &String| !v.is_empty())
}

async fn set_setting(pool: &SqlitePool, key: &str, value: &str) {
    if let Err(e) = sqlx::query(
        "INSERT INTO settings (tenant_id, skey, value) VALUES ('default', ?, ?)
         ON CONFLICT (tenant_id, skey) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    {
        error!("Cannot save backup setting {key}: {e}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: load_settings
// Defaults for anything missing.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_settings(pool: &SqlitePool) -> BackupSettings {
    BackupSettings {
        enabled: setting(pool, "backup_enabled").await.as_deref() == Some("1"),
        schedule: setting(pool, "backup_schedule").await.unwrap_or_else(|| DEFAULT_SCHEDULE.into()),
        keep: setting(pool, "backup_keep").await.and_then(|k| k.parse().ok()).unwrap_or(DEFAULT_KEEP),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: validate_settings
// A message fit to show beside the form, or Ok.
// ─────────────────────────────────────────────────────────────────────────────
pub fn validate_settings(s: &BackupSettings, now: NaiveDateTime) -> Result<(), String> {
    crate::schedule::validate_cron(s.schedule.trim(), now).map_err(|e| format!("Schedule: {e}"))?;
    if s.keep < 1 || s.keep > MAX_KEEP {
        return Err(format!("Keep must be between 1 and {MAX_KEEP}."));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: save_settings
// ─────────────────────────────────────────────────────────────────────────────
pub async fn save_settings(pool: &SqlitePool, s: &BackupSettings) -> Result<(), String> {
    validate_settings(s, chrono::Utc::now().naive_utc())?;
    set_setting(pool, "backup_enabled", if s.enabled { "1" } else { "0" }).await;
    set_setting(pool, "backup_schedule", s.schedule.trim()).await;
    set_setting(pool, "backup_keep", &s.keep.to_string()).await;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: read_passphrase_file
// The passphrase, or why it cannot be used: missing, too short, or readable
// by group or others on Unix.
// ─────────────────────────────────────────────────────────────────────────────
pub fn read_passphrase_file(path: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!(
            "No backup passphrase is set. On the server, run: scmserver backup set-passphrase ({} is missing).",
            path.display()
        ),
        _ => format!("Cannot read {}: {}", path.display(), e),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map(|m| m.permissions().mode()).unwrap_or(0);
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} can be read by other accounts (mode {:o}); make it readable by its owner only (chmod 600).",
                path.display(),
                mode & 0o777
            ));
        }
    }
    let p = raw.strip_suffix('\n').map(|s| s.strip_suffix('\r').unwrap_or(s)).unwrap_or(&raw).to_string();
    if p.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "The backup passphrase in {} is shorter than {MIN_PASSPHRASE_LEN} characters.",
            path.display()
        ));
    }
    Ok(p)
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: write_passphrase_file
// For `scmserver backup set-passphrase`: owner-only, owned like the server's
// private key (the service account reads both), replaced atomically.
// ─────────────────────────────────────────────────────────────────────────────
pub fn write_passphrase_file(path: &Path, passphrase: &str, owner_like: &Path) -> Result<(), String> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!("The passphrase must be at least {MIN_PASSPHRASE_LEN} characters."));
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let staging = dir.join(".backup.passphrase.tmp");
    let result = (|| -> std::io::Result<()> {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        use std::io::Write;
        let mut f = o.open(&staging)?;
        f.write_all(passphrase.as_bytes())?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            let like = std::fs::metadata(owner_like).ok();
            let t = backup::owner_template(like.as_ref(), dir, 0o600)?;
            backup::apply_owner(&staging, (t.0, t.1, 0o600))?;
        }
        #[cfg(not(unix))]
        let _ = owner_like;
        std::fs::rename(&staging, path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&staging);
        return Err(format!("Cannot write {}: {}", path.display(), e));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: backup_files
// The backups in a folder, newest first (by modification time). Only files
// named like ours: retention never touches anything else.
// ─────────────────────────────────────────────────────────────────────────────
pub fn backup_files(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v: Vec<_> = rd
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("openscm-") && n.ends_with(&format!(".{}", backup::EXTENSION))
        })
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| (e.path(), m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)))
        })
        .collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.0.cmp(&a.0)));
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: prune
// Deletes all but the newest `keep` backups. Returns the names deleted.
// ─────────────────────────────────────────────────────────────────────────────
pub fn prune(dir: &Path, keep: u32) -> Vec<String> {
    let mut deleted = Vec::new();
    for (path, _, _) in backup_files(dir).into_iter().skip(keep.max(1) as usize) {
        match std::fs::remove_file(&path) {
            Ok(()) => deleted.push(path.file_name().unwrap_or_default().to_string_lossy().to_string()),
            Err(e) => warn!("Cannot delete old backup {}: {e}", path.display()),
        }
    }
    deleted
}

impl Backups {
    // ─────────────────────────────────────────────────────────────────────────
    // Function: Backups::new / installed / with_work_factor
    // ─────────────────────────────────────────────────────────────────────────
    pub fn new(paths: Paths, passphrase_file: PathBuf) -> Self {
        let dir = backup::default_dir(&paths.db);
        Backups {
            paths,
            passphrase_file,
            dir,
            running: AtomicBool::new(false),
            next: Mutex::new(None),
            work_factor: None,
        }
    }

    pub fn installed() -> Self {
        Self::new(Paths::installed(), crate::config::backup_passphrase_path())
    }

    /// Tests only: a lower scrypt cost.
    pub fn with_work_factor(mut self, n: u8) -> Self {
        self.work_factor = Some(n);
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Function: Backups::next_run
    // The next scheduled run, computed from the last attempt (so a run missed
    // while the server was down happens at the first tick after it starts),
    // or from `now` when there has been none. Recomputed when the schedule
    // changes. None when scheduled backups are off or the schedule is bad.
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn next_run(&self, pool: &SqlitePool, now: NaiveDateTime) -> Option<NaiveDateTime> {
        let s = load_settings(pool).await;
        if !s.enabled {
            *self.next.lock().unwrap() = None;
            return None;
        }
        if let Some((sched, at)) = self.next.lock().unwrap().clone() {
            if sched == s.schedule {
                return Some(at);
            }
        }
        let base = setting(pool, "backup_last_at")
            .await
            .and_then(|t| NaiveDateTime::parse_from_str(&t, STATUS_TIME).ok())
            .filter(|t| *t <= now)
            .unwrap_or(now);
        let at = crate::schedule::next_cron_run(s.schedule.trim(), base)
            .ok()
            .and_then(|t| NaiveDateTime::parse_from_str(&t, crate::schedule::FMT).ok())?;
        *self.next.lock().unwrap() = Some((s.schedule.clone(), at));
        Some(at)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Function: Backups::tick
    // Called every minute by the scheduler. Starts a run in the background
    // when one is due, so the scheduler never waits on it.
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn tick(self: &Arc<Self>, pool: &SqlitePool, now: NaiveDateTime) -> Option<tokio::task::JoinHandle<()>> {
        let at = self.next_run(pool, now).await?;
        if now < at || self.is_running() {
            return None;
        }
        // Advance first, so a slow or failing run is not restarted every tick.
        let sched = load_settings(pool).await.schedule;
        let following = crate::schedule::next_cron_run(sched.trim(), now)
            .ok()
            .and_then(|t| NaiveDateTime::parse_from_str(&t, crate::schedule::FMT).ok());
        *self.next.lock().unwrap() = following.map(|t| (sched, t));

        let me = self.clone();
        let pool = pool.clone();
        Some(tokio::spawn(async move {
            let _ = me.run(&pool, Trigger::Scheduled).await;
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Function: Backups::run
    // One backup: write, verify, prune, record. Refused while another run is
    // in progress.
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn run(&self, pool: &SqlitePool, trigger: Trigger) -> Result<RunResult, String> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err("A backup is already running.".into());
        }
        let result = self.run_inner(pool).await;
        self.record(pool, &trigger, &result).await;
        self.running.store(false, Ordering::SeqCst);
        result
    }

    async fn run_inner(&self, pool: &SqlitePool) -> Result<RunResult, String> {
        let pass = read_passphrase_file(&self.passphrase_file)?;
        backup::create_private_dir(&self.dir)?;
        // Two runs in the same second (a scheduled one and "Back up now")
        // would get the same name: number the second one.
        let name = backup::default_file_name(&backup::this_host(), chrono::Utc::now());
        let mut out = self.dir.join(&name);
        let stem = name.trim_end_matches(&format!(".{}", backup::EXTENSION)).to_string();
        let mut n = 2;
        while out.exists() || out.with_extension(format!("{}.partial", backup::EXTENSION)).exists() {
            out = self.dir.join(format!("{stem}-{n}.{}", backup::EXTENSION));
            n += 1;
        }
        let created = backup::create(&self.paths, &out, &pass, self.work_factor).await?;
        if let Err(e) = backup::verify(&out, &pass, Some(&self.paths.public_key)).await {
            let _ = std::fs::remove_file(&out);
            return Err(format!("The backup was written but did not verify ({e}); it was deleted."));
        }
        let keep = load_settings(pool).await.keep;
        let pruned = prune(&self.dir, keep);
        Ok(RunResult { path: created.path, size: created.size, pruned })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper: Backups::record
    // Status rows, audit entry, and on failure the bell and the alert trigger.
    // ─────────────────────────────────────────────────────────────────────────
    async fn record(&self, pool: &SqlitePool, trigger: &Trigger, result: &Result<RunResult, String>) {
        let now = chrono::Utc::now().naive_utc().format(STATUS_TIME).to_string();
        set_setting(pool, "backup_last_at", &now).await;
        set_setting(pool, "backup_last_trigger", trigger.label()).await;
        let (actor_id, actor_name) = match trigger {
            Trigger::Scheduled => (None, "system".to_string()),
            Trigger::Manual { user_id, username } => (Some(*user_id), username.clone()),
        };
        match result {
            Ok(r) => {
                let name = r.path.file_name().unwrap_or_default().to_string_lossy().to_string();
                set_setting(pool, "backup_last_result", "ok").await;
                set_setting(pool, "backup_last_ok_at", &now).await;
                set_setting(pool, "backup_last_file", &name).await;
                set_setting(pool, "backup_last_size", &r.size.to_string()).await;
                set_setting(pool, "backup_last_error", "").await;
                let details = format!(
                    "{} backup {} ({}), verified{}",
                    trigger.label(),
                    name,
                    backup::human_size(r.size),
                    if r.pruned.is_empty() { String::new() } else { format!("; deleted {} older", r.pruned.len()) }
                );
                info!("Backup: {details}");
                crate::audit::record_raw(pool, "default", actor_id, &actor_name, None, "backup.create",
                                         Some("backup"), Some(&name),
                                         Some(serde_json::json!({"trigger": trigger.label(), "file": name, "size_bytes": r.size,
                                                    "verified": true, "pruned": r.pruned.len()}))).await;
            }
            Err(e) => {
                set_setting(pool, "backup_last_result", "failed").await;
                set_setting(pool, "backup_last_error", e).await;
                error!("Backup ({}) failed: {e}", trigger.label());
                crate::audit::record_raw(pool, "default", actor_id, &actor_name, None, "backup.failed",
                                         Some("backup"), None, Some(serde_json::json!({"trigger": trigger.label(), "error": e}))).await;
                notify_superusers(pool, &format!("Backup failed: {e}")).await;
                crate::alerts::fire_backup_failed(pool, e).await;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Function: Backups::status
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn status(&self, pool: &SqlitePool) -> Status {
        let now = chrono::Utc::now().naive_utc();
        let settings = load_settings(pool).await;
        let schedule_problem = validate_settings(&settings, now).err();
        let next_run = self.next_run(pool, now).await.map(|t| format!("{} UTC", t.format("%Y-%m-%d %H:%M")));
        let files = backup_files(&self.dir)
            .into_iter()
            .map(|(p, size, m)| BackupFile {
                name: p.file_name().unwrap_or_default().to_string_lossy().to_string(),
                size: backup::human_size(size),
                modified: chrono::DateTime::<chrono::Utc>::from(m).format("%Y-%m-%d %H:%M UTC").to_string(),
            })
            .collect();
        Status {
            dir: self.dir.display().to_string(),
            passphrase_path: self.passphrase_file.display().to_string(),
            passphrase_problem: read_passphrase_file(&self.passphrase_file).err(),
            schedule_problem,
            running: self.is_running(),
            next_run,
            last_at: setting(pool, "backup_last_at").await,
            last_result: setting(pool, "backup_last_result").await,
            last_trigger: setting(pool, "backup_last_trigger").await,
            last_file: setting(pool, "backup_last_file").await,
            last_size: setting(pool, "backup_last_size").await.and_then(|s| s.parse().ok()).map(backup::human_size),
            last_error: setting(pool, "backup_last_error").await,
            last_ok_at: setting(pool, "backup_last_ok_at").await,
            files,
            settings,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Function: Backups::dashboard_notice
    // For superusers' dashboard: why backups need attention, or None.
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn dashboard_notice(&self, pool: &SqlitePool) -> Option<String> {
        let s = load_settings(pool).await;
        if !s.enabled {
            return Some("Scheduled backups are off. Without them, a lost disk loses every result, report and the server key.".into());
        }
        if let Err(e) = read_passphrase_file(&self.passphrase_file) {
            return Some(format!("Scheduled backups cannot run: {e}"));
        }
        if let Err(e) = validate_settings(&s, chrono::Utc::now().naive_utc()) {
            return Some(format!("Scheduled backups cannot run: {e}"));
        }
        if setting(pool, "backup_last_result").await.as_deref() == Some("failed") {
            let at = setting(pool, "backup_last_at").await.unwrap_or_default();
            let err = setting(pool, "backup_last_error").await.unwrap_or_default();
            return Some(format!("The last backup failed ({at} UTC): {err}"));
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: notify_superusers
// A bell notification for every superuser, in their own organization.
// ─────────────────────────────────────────────────────────────────────────────
async fn notify_superusers(pool: &SqlitePool, msg: &str) {
    let rows: Vec<(i32, String)> = sqlx::query_as("SELECT id, tenant_id FROM users WHERE role = 'superuser'")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for (uid, tenant) in rows {
        crate::handlers::add_notification(pool, &tenant, "warning", uid, msg).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: record_cli_backup
// `scmserver backup` on the command line writes its audit entry straight into
// the live database (WAL: safe beside the running server). Best effort.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record_cli_backup(db: &Path, file: &Path, size: u64) {
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(false)
        .busy_timeout(std::time::Duration::from_secs(10));
    let Ok(pool) = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(opts).await else { return };
    let name = file.file_name().unwrap_or_default().to_string_lossy().to_string();
    crate::audit::record_raw(&pool, "default", None, "command line", None, "backup.create", Some("backup"),
                             Some(&name), Some(serde_json::json!({"trigger": "cli", "file": name, "size_bytes": size}))).await;
    pool.close().await;
}
