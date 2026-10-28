// =============================================================================
// instance_lock.rs — one server process per database
//
// The server takes an exclusive lock on `scmserver.lock`, next to the
// database, for as long as it runs. A second server pointed at the same
// database (a second service, a second container on the same volume) stops
// at startup instead of running every scheduled job twice. The 1.0.0
// `scmserver restore` command takes the same lock, so it cannot replace the
// database under a running server (docs/design/1.0.0-backup-restore.md, D4).
//
// The lock is the operating system's (flock / LockFileEx through fs2): it is
// released when the process exits, even after a crash, so a stale lock file
// never blocks a restart. The file's contents (the PID) are only a hint for
// operators.
// =============================================================================

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: lock_path
// The lock file for a database: `scmserver.lock` in the database's directory.
// ─────────────────────────────────────────────────────────────────────────────
pub fn lock_path(db_path: &str) -> PathBuf {
    Path::new(db_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("scmserver.lock")
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: acquire
// Takes the lock for `db_path`. Keep the returned File alive for the life of
// the process; dropping it releases the lock. Errors name the lock file and
// say what to do.
// ─────────────────────────────────────────────────────────────────────────────
pub fn acquire(db_path: &str) -> Result<File, String> {
    let path = lock_path(db_path);
    // Not truncated on open: the file is emptied only once we hold the lock,
    // so a refused second process never wipes the running one's PID.
    let mut file = OpenOptions::new()
        .create(true).read(true).write(true).truncate(false)
        .open(&path)
        .map_err(|e| format!("Cannot open lock file {}: {}", path.display(), e))?;
    if file.try_lock_exclusive().is_err() {
        return Err(format!(
            "Another OpenSCM server is already using this database (lock held on {}). \
             Stop it first; only one server may run per database.",
            path.display()
        ));
    }
    let _ = file.set_len(0);
    let _ = file.seek(SeekFrom::Start(0));
    let _ = writeln!(file, "{}", std::process::id());
    Ok(file)
}
