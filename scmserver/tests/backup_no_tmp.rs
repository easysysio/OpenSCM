// ─────────────────────────────────────────────────────────────────────────────
// backup_no_tmp.rs — a backup run must not need the system temp folder.
//
// The Docker image is built FROM scratch and has no /tmp. A run writes the
// backup and then verifies it; when that verify unpacked into /tmp, every
// scheduled and "Back up now" backup in Docker failed and was deleted.
//
// Its own test binary: it points TMPDIR at a folder that does not exist,
// which is process-wide, so it must not share a process with other tests.
// ─────────────────────────────────────────────────────────────────────────────

use base64::{engine::general_purpose, Engine as _};
use scmserver::backup::{self, Paths};
use scmserver::backup_jobs::{self, Backups, Trigger};
use sqlx::sqlite::SqlitePoolOptions;

const PASS: &str = "correct horse battery";

// ─────────────────────────────────────────────────────────────────────────────
// Test: a run succeeds with no usable system temp folder
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn backup_run_works_without_a_system_temp_folder() {
    // Built before TMPDIR is broken: tempdir() itself uses it.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("scm.db");
    std::fs::File::create(&db).unwrap();
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{}?mode=rwc", db.display())).await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();

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
    let jobs = Backups::new(Paths { db, private_key, public_key, config }, pass_file)
        .with_work_factor(10);

    // Like the Docker image: the system temp folder does not exist.
    // SAFETY: the only test in this binary, and no other thread reads the
    // environment at this point.
    unsafe { std::env::set_var("TMPDIR", dir.path().join("no-such-tmp")) };
    assert!(tempfile::tempdir().is_err(), "the system temp folder should be unusable here");

    let result = jobs.run(&pool, Trigger::Scheduled).await;
    let run = result.expect("the backup run should succeed without /tmp");
    assert!(run.path.exists(), "the verified backup is kept");
    assert!(backup::verify_in(&run.path, PASS, None, jobs.dir()).await.is_ok());
}
