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
