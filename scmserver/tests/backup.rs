// backup.rs — `scmserver backup` / `backup verify` (src/backup.rs).
//
// Every test builds its own server layout in a temporary directory (a WAL file
// database migrated to the current schema, a key pair, a config) and passes
// explicit paths, so nothing touches the installed server. The scrypt work
// factor is lowered to keep the tests fast; the format is the same.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use base64::{engine::general_purpose, Engine as _};
use scmserver::backup::{self, Paths};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const PASS: &str = "correct horse battery";
const WF: Option<u8> = Some(10);

struct Server {
    _dir: tempfile::TempDir,
    paths: Paths,
    out_dir: PathBuf,
    pool: SqlitePool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: server
// A migrated WAL database with `systems` rows, a matching key pair and a
// config. Auto-checkpointing is off on the pool, so the rows stay in the WAL
// file — a backup that copied only scm.db would miss them.
// ─────────────────────────────────────────────────────────────────────────────
async fn server(systems: i64) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("scm.db");
    std::fs::File::create(&db).unwrap();
    let pool = SqlitePoolOptions::new()
        .after_connect(|conn, _| Box::pin(async move {
            use sqlx::Executor;
            conn.execute("PRAGMA journal_mode = WAL").await?;
            conn.execute("PRAGMA wal_autocheckpoint = 0").await?;
            conn.execute("PRAGMA busy_timeout = 10000").await?;
            conn.execute("PRAGMA foreign_keys = ON").await?;
            Ok(())
        }))
        .connect(&format!("sqlite://{}?mode=rwc", db.display()))
        .await
        .unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for i in 1..=systems {
        sqlx::query("INSERT INTO systems (tenant_id, name, status) VALUES ('default', ?, 'active')")
            .bind(format!("host{i}")).execute(&pool).await.unwrap();
    }

    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let private_key = keys.join("scmserver.key");
    let public_key = keys.join("scmserver.pub");
    std::fs::write(&private_key, general_purpose::STANDARD.encode(sk.to_bytes())).unwrap();
    std::fs::write(&public_key, general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())).unwrap();
    let config = dir.path().join("scmserver.config");
    std::fs::write(&config, "[server]\nport = 8000\n").unwrap();

    let out_dir = dir.path().join("backups");
    std::fs::create_dir(&out_dir).unwrap();
    Server { paths: Paths { db, private_key, public_key, config }, out_dir, pool, _dir: dir }
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    v.sort();
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: rewrap
// Decrypts a backup, lets the test change its entries, and encrypts it again
// with the same passphrase — a backup that decrypts fine but lies.
// ─────────────────────────────────────────────────────────────────────────────
fn rewrap(file: &Path, change: impl FnOnce(&mut Vec<(String, Vec<u8>)>)) {
    let d = age::Decryptor::new(std::fs::File::open(file).unwrap()).unwrap();
    let id = age::scrypt::Identity::new(SecretString::from(PASS.to_owned()));
    let r = d.decrypt(std::iter::once(&id as &dyn age::Identity)).unwrap();
    let mut a = tar::Archive::new(flate2::read::GzDecoder::new(r));
    let mut entries = Vec::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        let name = e.path().unwrap().to_string_lossy().to_string();
        let mut b = Vec::new();
        e.read_to_end(&mut b).unwrap();
        entries.push((name, b));
    }
    change(&mut entries);

    let mut rcp = age::scrypt::Recipient::new(SecretString::from(PASS.to_owned()));
    rcp.set_work_factor(10);
    let enc = age::Encryptor::with_recipients(std::iter::once(&rcp as &dyn age::Recipient)).unwrap();
    let w = enc.wrap_output(std::fs::File::create(file).unwrap()).unwrap();
    let mut t = tar::Builder::new(flate2::write::GzEncoder::new(w, flate2::Compression::fast()));
    for (name, b) in &entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(b.len() as u64);
        h.set_mode(0o600);
        t.append_data(&mut h, name, b.as_slice()).unwrap();
    }
    t.into_inner().unwrap().finish().unwrap().finish().unwrap().flush().unwrap();
}

fn hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

// The whole round trip: rows still in the WAL are in the backup, the key pair
// and config are there, the file is owner-only, and nothing is left behind.
#[tokio::test]
async fn a_backup_holds_everything_and_verifies() {
    let s = server(25).await;
    let wal = PathBuf::from(format!("{}-wal", s.paths.db.display()));
    assert!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) > 0, "rows must still be in the WAL");

    let out = s.out_dir.join("b.oscm-backup");
    let c = backup::create(&s.paths, &out, PASS, WF).await.expect("backup");
    assert_eq!(c.manifest.schema_version, scmserver::schema::SCHEMA_VERSION);
    assert_eq!(c.manifest.format, backup::FORMAT);
    assert_eq!(c.manifest.files.len(), 4, "db, key, pub, config: {:?}", c.manifest.files.keys());
    assert_eq!(files_in(&s.out_dir), vec!["b.oscm-backup"], "no .partial or temporary directory left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let v = backup::verify(&out, PASS, Some(&s.paths.public_key)).await.expect("verify");
    assert_eq!(v.manifest, c.manifest);
    assert!(v.counts.contains(&("Systems", Some(25))), "{:?}", v.counts);
    assert_eq!(v.matches_this_server, Some(true));
    assert!(!v.newer_than_this_server);
    assert!(v.key_fingerprint.starts_with("SHA256:"));

    // A different server's key is reported as different.
    let other = s.out_dir.join("other.pub");
    let osk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    std::fs::write(&other, general_purpose::STANDARD.encode(osk.verifying_key().to_bytes())).unwrap();
    let v = backup::verify(&out, PASS, Some(&other)).await.unwrap();
    assert_eq!(v.matches_this_server, Some(false));
    s.pool.close().await;
}

// The server keeps writing while the backup runs; the snapshot is consistent.
#[tokio::test]
async fn a_backup_taken_while_the_server_writes_is_consistent() {
    let s = server(5).await;
    let pool = s.pool.clone();
    let writer = tokio::spawn(async move {
        for i in 0..400 {
            sqlx::query("INSERT INTO systems (tenant_id, name, status) VALUES ('default', ?, 'active')")
                .bind(format!("busy{i}")).execute(&pool).await.unwrap();
        }
    });
    let out = s.out_dir.join("busy.oscm-backup");
    backup::create(&s.paths, &out, PASS, WF).await.expect("backup during writes");
    writer.await.unwrap();
    let v = backup::verify(&out, PASS, None).await.expect("verify");
    let n = v.counts.iter().find(|(l, _)| *l == "Systems").unwrap().1.unwrap();
    assert!((5..=405).contains(&n), "{n}");
    s.pool.close().await;
}

#[tokio::test]
async fn the_wrong_passphrase_is_refused() {
    let s = server(1).await;
    let out = s.out_dir.join("b.oscm-backup");
    backup::create(&s.paths, &out, PASS, WF).await.unwrap();
    let e = backup::verify(&out, "not the passphrase", None).await.unwrap_err();
    assert!(e.contains("Wrong passphrase"), "{e}");
    s.pool.close().await;
}

// A changed byte anywhere in the encrypted body fails authentication.
#[tokio::test]
async fn a_changed_byte_is_refused() {
    let s = server(1).await;
    let out = s.out_dir.join("b.oscm-backup");
    backup::create(&s.paths, &out, PASS, WF).await.unwrap();
    let mut bytes = std::fs::read(&out).unwrap();
    let mid = bytes.len() * 2 / 3;
    bytes[mid] ^= 0x01;
    std::fs::write(&out, &bytes).unwrap();
    let e = backup::verify(&out, PASS, None).await.unwrap_err();
    assert!(e.contains("damaged") || e.contains("Wrong passphrase"), "{e}");

    // So does a cut-off file.
    std::fs::write(&out, &bytes[..bytes.len() - 100]).unwrap();
    assert!(backup::verify(&out, PASS, None).await.is_err());
    s.pool.close().await;
}

// Decrypts fine but its contents do not match the manifest: refused.
#[tokio::test]
async fn contents_that_do_not_match_the_manifest_are_refused() {
    let s = server(1).await;
    let out = s.out_dir.join("b.oscm-backup");
    backup::create(&s.paths, &out, PASS, WF).await.unwrap();

    let changed = s.out_dir.join("changed.oscm-backup");
    std::fs::copy(&out, &changed).unwrap();
    rewrap(&changed, |e| {
        let cfg = e.iter_mut().find(|(n, _)| n == "scmserver.config").unwrap();
        cfg.1 = b"[server]\nport = 1\n".to_vec();
    });
    let err = backup::verify(&changed, PASS, None).await.unwrap_err();
    assert!(err.contains("checksum"), "{err}");

    let extra = s.out_dir.join("extra.oscm-backup");
    std::fs::copy(&out, &extra).unwrap();
    rewrap(&extra, |e| e.push(("evil.sh".into(), b"rm -rf /".to_vec())));
    let err = backup::verify(&extra, PASS, None).await.unwrap_err();
    assert!(err.contains("unexpected entry"), "{err}");

    // A key swapped for another pair, with the manifest updated to match:
    // hashes agree, but the pair no longer belongs together.
    let swapped = s.out_dir.join("swapped.oscm-backup");
    std::fs::copy(&out, &swapped).unwrap();
    rewrap(&swapped, |e| {
        let other = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let k = general_purpose::STANDARD.encode(other.to_bytes()).into_bytes();
        let h = hex(&k);
        e.iter_mut().find(|(n, _)| n == "keys/scmserver.key").unwrap().1 = k;
        let m = e.iter_mut().find(|(n, _)| n == "manifest.json").unwrap();
        let mut j: serde_json::Value = serde_json::from_slice(&m.1).unwrap();
        j["files"]["keys/scmserver.key"] = h.into();
        m.1 = serde_json::to_vec(&j).unwrap();
    });
    let err = backup::verify(&swapped, PASS, None).await.unwrap_err();
    assert!(err.contains("do not belong together"), "{err}");
    s.pool.close().await;
}

// Refusals before anything is written leave the directory as it was.
#[tokio::test]
async fn bad_requests_write_nothing() {
    let s = server(1).await;
    let out = s.out_dir.join("b.oscm-backup");

    let e = backup::create(&s.paths, &out, "short", WF).await.unwrap_err();
    assert!(e.contains("at least 12"), "{e}");
    assert!(files_in(&s.out_dir).is_empty());

    let mut broken = s.paths.clone();
    broken.private_key = s.out_dir.join("missing.key");
    let e = backup::create(&broken, &out, PASS, WF).await.unwrap_err();
    assert!(e.contains("server key"), "{e}");
    assert!(files_in(&s.out_dir).is_empty(), "the snapshot must be cleaned up: {:?}", files_in(&s.out_dir));

    std::fs::write(&out, b"keep me").unwrap();
    let e = backup::create(&s.paths, &out, PASS, WF).await.unwrap_err();
    assert!(e.contains("already exists"), "{e}");
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
    s.pool.close().await;
}

// No config file (Windows keeps it in the registry): the backup is still
// complete without it.
#[tokio::test]
async fn a_missing_config_file_is_left_out() {
    let s = server(1).await;
    let mut p = s.paths.clone();
    p.config = s.out_dir.join("no-such.config");
    let out = s.out_dir.join("b.oscm-backup");
    let c = backup::create(&p, &out, PASS, WF).await.unwrap();
    assert!(!c.manifest.files.contains_key("scmserver.config"));
    backup::verify(&out, PASS, None).await.expect("verifies without a config");
    s.pool.close().await;
}

// A backup of a database from a newer OpenSCM verifies, flagged: restore will
// refuse it, and verify says so up front.
#[tokio::test]
async fn a_backup_with_a_newer_schema_is_flagged() {
    let s = server(1).await;
    sqlx::query("UPDATE schema_info SET version = version + 1").execute(&s.pool).await.unwrap();
    let out = s.out_dir.join("b.oscm-backup");
    backup::create(&s.paths, &out, PASS, WF).await.unwrap();
    let v = backup::verify(&out, PASS, None).await.unwrap();
    assert_eq!(v.manifest.schema_version, scmserver::schema::SCHEMA_VERSION + 1);
    assert!(v.newer_than_this_server);
    s.pool.close().await;
}

#[test]
fn default_names_are_dated_and_safe() {
    let t = chrono::DateTime::parse_from_rfc3339("2026-10-29T08:05:09Z").unwrap().with_timezone(&chrono::Utc);
    assert_eq!(backup::default_file_name("web 1/prod", t), "openscm-web_1_prod-20261029T080509Z.oscm-backup");
    assert_eq!(backup::default_dir(Path::new("/var/lib/openscm/scm.db")), PathBuf::from("/var/lib/openscm/backups"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Restore
// ─────────────────────────────────────────────────────────────────────────────

async fn count_systems(db: &Path) -> i64 {
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{}?mode=ro", db.display())).await.unwrap();
    let n = sqlx::query_scalar("SELECT COUNT(*) FROM systems").fetch_one(&pool).await.unwrap();
    pool.close().await;
    n
}

fn pre_restore_dirs(db: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(db.parent().unwrap()).unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("pre-restore-"))
        .collect()
}

/// A backup of a 25-system server, and a second, different server (2 systems,
/// another key, another config) stopped and ready to restore onto.
async fn source_and_target() -> (Server, PathBuf, Server) {
    let a = server(25).await;
    let file = a.out_dir.join("a.oscm-backup");
    backup::create(&a.paths, &file, PASS, WF).await.unwrap();
    let b = server(2).await;
    let osk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    std::fs::write(&b.paths.private_key, general_purpose::STANDARD.encode(osk.to_bytes())).unwrap();
    std::fs::write(&b.paths.public_key, general_purpose::STANDARD.encode(osk.verifying_key().to_bytes())).unwrap();
    std::fs::write(&b.paths.config, "[server]\nport = 9999\n").unwrap();
    b.pool.close().await; // the server is stopped
    (a, file, b)
}

// The whole restore: data and key are the backup's, the config is untouched,
// the old files are kept, and the next start records it in the audit log once.
#[tokio::test]
async fn a_restore_brings_back_the_backup_and_keeps_the_old_files() {
    let (a, file, b) = source_and_target().await;
    let old_key = std::fs::read(&b.paths.private_key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&b.paths.private_key, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    let mut asked = false;
    let r = backup::restore(&b.paths, &file, PASS, false, |v| {
        asked = true;
        assert!(v.counts.contains(&("Systems", Some(25))));
        assert_eq!(v.matches_this_server, Some(false), "a different server's key");
        true
    }).await.expect("restore");
    assert!(asked, "restore must ask before changing anything");
    assert!(!r.config_restored);

    assert_eq!(count_systems(&b.paths.db).await, 25);
    assert_eq!(std::fs::read(&b.paths.private_key).unwrap(), std::fs::read(&a.paths.private_key).unwrap());
    assert_eq!(std::fs::read(&b.paths.public_key).unwrap(), std::fs::read(&a.paths.public_key).unwrap());
    assert_eq!(std::fs::read_to_string(&b.paths.config).unwrap(), "[server]\nport = 9999\n", "config untouched");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&b.paths.private_key).unwrap().permissions().mode() & 0o777, 0o640,
                   "the restored key keeps the replaced file's mode");
    }

    // The replaced files, whole: the old database (with its WAL) and key.
    assert_eq!(count_systems(&r.pre_restore.join("scm.db")).await, 2);
    assert_eq!(std::fs::read(r.pre_restore.join("keys/scmserver.key")).unwrap(), old_key);
    // Nothing else left lying around.
    let dir = b.paths.db.parent().unwrap();
    for name in files_in(dir) {
        assert!(!name.starts_with(".oscm-restore-") && !name.ends_with(".restore-tmp"), "left behind: {name}");
    }

    // Next start: migrations, then one audit entry, then the note is gone.
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{}?mode=rwc", b.paths.db.display())).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let db = b.paths.db.to_string_lossy().to_string();
    assert!(dir.join(backup::RESTORE_NOTE).exists());
    backup::record_restore(&pool, &db).await;
    backup::record_restore(&pool, &db).await;
    let (n, target, details): (i64, String, String) = sqlx::query_as(
        "SELECT COUNT(*), MAX(target_id), MAX(details) FROM audit_log WHERE action = 'backup.restored'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(n, 1);
    assert_eq!(target, "a.oscm-backup");
    assert!(details.contains("pre-restore-"), "{details}");
    assert!(!dir.join(backup::RESTORE_NOTE).exists());
    pool.close().await;
    a.pool.close().await;
}

#[tokio::test]
async fn include_config_restores_the_config() {
    let (a, file, b) = source_and_target().await;
    let r = backup::restore(&b.paths, &file, PASS, true, |_| true).await.unwrap();
    assert!(r.config_restored);
    assert_eq!(std::fs::read(&b.paths.config).unwrap(), std::fs::read(&a.paths.config).unwrap());
    assert_eq!(std::fs::read_to_string(r.pre_restore.join("scmserver.config")).unwrap(), "[server]\nport = 9999\n");
    a.pool.close().await;
}

// Every refusal leaves the target exactly as it was.
async fn assert_untouched(b: &Server, key: &[u8]) {
    assert_eq!(count_systems(&b.paths.db).await, 2);
    assert_eq!(std::fs::read(&b.paths.private_key).unwrap(), key);
    assert!(pre_restore_dirs(&b.paths.db).is_empty());
    assert!(!b.paths.db.parent().unwrap().join(backup::RESTORE_NOTE).exists());
}

#[tokio::test]
async fn a_restore_is_refused_while_the_server_runs() {
    let (a, file, b) = source_and_target().await;
    let key = std::fs::read(&b.paths.private_key).unwrap();
    let _running = scmserver::instance_lock::acquire(&b.paths.db.to_string_lossy()).unwrap();
    let e = backup::restore(&b.paths, &file, PASS, false, |_| true).await.unwrap_err();
    assert!(e.contains("must be stopped"), "{e}");
    assert_untouched(&b, &key).await;
    a.pool.close().await;
}

#[tokio::test]
async fn a_restore_of_a_newer_schema_is_refused() {
    let a = server(1).await;
    sqlx::query("UPDATE schema_info SET version = version + 1").execute(&a.pool).await.unwrap();
    let file = a.out_dir.join("new.oscm-backup");
    backup::create(&a.paths, &file, PASS, WF).await.unwrap();
    let b = server(2).await;
    b.pool.close().await;
    let key = std::fs::read(&b.paths.private_key).unwrap();
    let e = backup::restore(&b.paths, &file, PASS, false, |_| true).await.unwrap_err();
    assert!(e.contains("or later first"), "{e}");
    assert_untouched(&b, &key).await;
    a.pool.close().await;
}

// The test binary runs as Community Edition: a SaaS backup is refused.
#[tokio::test]
async fn a_restore_across_editions_is_refused() {
    let (a, file, b) = source_and_target().await;
    rewrap(&file, |e| {
        let m = e.iter_mut().find(|(n, _)| n == "manifest.json").unwrap();
        let mut j: serde_json::Value = serde_json::from_slice(&m.1).unwrap();
        j["edition"] = "SaaS Edition".into();
        m.1 = serde_json::to_vec(&j).unwrap();
    });
    let key = std::fs::read(&b.paths.private_key).unwrap();
    let e = backup::restore(&b.paths, &file, PASS, false, |_| true).await.unwrap_err();
    assert!(e.contains("cannot be restored onto"), "{e}");
    assert_untouched(&b, &key).await;
    a.pool.close().await;
}

#[tokio::test]
async fn saying_no_changes_nothing() {
    let (a, file, b) = source_and_target().await;
    let key = std::fs::read(&b.paths.private_key).unwrap();
    let e = backup::restore(&b.paths, &file, PASS, false, |_| false).await.unwrap_err();
    assert!(e.contains("Cancelled"), "{e}");
    assert_untouched(&b, &key).await;
    // Nor does a wrong passphrase.
    assert!(backup::restore(&b.paths, &file, "wrong passphrase", false, |_| true).await.is_err());
    assert_untouched(&b, &key).await;
    a.pool.close().await;
}

// A failure while replacing files puts the old ones back.
#[tokio::test]
async fn a_failure_partway_puts_the_old_files_back() {
    let (a, file, b) = source_and_target().await;
    let key = std::fs::read(&b.paths.private_key).unwrap();
    let mut paths = b.paths.clone();
    // The public key is written last of the key pair; make that impossible.
    let blocker = b.out_dir.join("not-a-dir");
    std::fs::write(&blocker, b"x").unwrap();
    paths.public_key = blocker.join("scmserver.pub");
    let e = backup::restore(&paths, &file, PASS, false, |_| true).await.unwrap_err();
    assert!(e.contains("put back"), "{e}");
    assert_eq!(count_systems(&b.paths.db).await, 2, "the old database is back");
    assert_eq!(std::fs::read(&b.paths.private_key).unwrap(), key, "the old key is back");
    assert!(!b.paths.db.parent().unwrap().join(backup::RESTORE_NOTE).exists());
    a.pool.close().await;
}

// A backup from an older OpenSCM (schema 48 here) restores, and the next
// start migrates it forward like an upgrade.
#[tokio::test]
async fn an_older_backup_is_migrated_on_the_next_start() {
    let a = server(3).await;
    sqlx::query("DROP TABLE api_tokens").execute(&a.pool).await.unwrap();
    sqlx::query("UPDATE schema_info SET version = 48").execute(&a.pool).await.unwrap();
    let file = a.out_dir.join("old.oscm-backup");
    backup::create(&a.paths, &file, PASS, WF).await.unwrap();
    let b = server(2).await;
    b.pool.close().await;
    backup::restore(&b.paths, &file, PASS, false, |v| v.manifest.schema_version == 48).await.unwrap();

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{}?mode=rwc", b.paths.db.display())).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let v: i64 = sqlx::query_scalar("SELECT version FROM schema_info").fetch_one(&pool).await.unwrap();
    assert_eq!(v, scmserver::schema::SCHEMA_VERSION);
    let t: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name = 'api_tokens'").fetch_one(&pool).await.unwrap();
    assert_eq!(t, 1);
    pool.close().await;
    assert_eq!(count_systems(&b.paths.db).await, 3);
    a.pool.close().await;
}

// `sudo scmserver backup` must not leave root-owned files the service account
// cannot use: the backups folder it creates and every backup file get the
// database's owner and group. Tested with a group change, which needs no root:
// the database is moved to another of this user's groups, and the folder and
// file must follow it.
#[cfg(unix)]
#[tokio::test]
async fn backups_are_owned_like_the_database() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let s = server(1).await;
    let primary = std::fs::metadata(&s.paths.db).unwrap().gid();
    let out = std::process::Command::new("id").arg("-G").output().unwrap();
    let Some(other) = String::from_utf8_lossy(&out.stdout).split_whitespace()
        .filter_map(|g| g.parse::<u32>().ok()).find(|g| *g != primary) else {
        eprintln!("skipped: this user belongs to only one group");
        return;
    };
    std::os::unix::fs::chown(&s.paths.db, None, Some(other)).unwrap();

    // resolve_out with no --out creates backups/ next to the database.
    let dir = backup::default_dir(&s.paths.db);
    std::fs::remove_dir(&dir).unwrap(); // server() made it; start without one
    assert!(!dir.exists());
    let target = backup::resolve_out(None, &s.paths.db).unwrap();
    let d = std::fs::metadata(&dir).unwrap();
    assert_eq!(d.gid(), other, "the folder takes the database's group");
    assert_eq!(d.permissions().mode() & 0o777, 0o700);

    let c = backup::create(&s.paths, &target, PASS, WF).await.unwrap();
    let f = std::fs::metadata(&c.path).unwrap();
    assert_eq!(f.gid(), other, "the backup takes the database's group");
    assert_eq!(f.permissions().mode() & 0o777, 0o600);

    // --out into a folder of another group: on BSD/macOS a new file takes
    // the folder's group, so only the fix gives it the database's.
    let elsewhere = s.out_dir.parent().unwrap().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::chown(&elsewhere, None, Some(primary)).unwrap();
    let c = backup::create(&s.paths, &elsewhere.join("x.oscm-backup"), PASS, WF).await.unwrap();
    assert_eq!(std::fs::metadata(&c.path).unwrap().gid(), other);
    s.pool.close().await;
}
