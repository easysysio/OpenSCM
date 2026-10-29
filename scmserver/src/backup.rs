// =============================================================================
// backup.rs — `scmserver backup` and `scmserver backup verify`
//
// A backup is one file, `openscm-<host>-<UTC time>.oscm-backup`: a tar.gz of
//
//     manifest.json          version, edition, schema, time, host, SHA-256s
//     scm.db                 consistent snapshot (VACUUM INTO)
//     keys/scmserver.key     server key pair — agents pin it, and every
//     keys/scmserver.pub     stored secret is derived from it
//     scmserver.config       when the config is a file (not on Windows)
//
// encrypted with age using a passphrase (scrypt), so it can also be opened
// with the standalone `age` tool. It is always encrypted: it holds the
// server's private key.
//
// Backups are taken while the server runs. VACUUM INTO reads the database in
// one transaction, WAL included, and writes a consistent copy; the server
// keeps serving. Nothing here takes the server's instance lock.
//
// Verify decrypts into a temporary directory, checks every entry against the
// manifest, checks the key pair, runs integrity_check on the copy, and
// reports. It never opens the live database.
//
// Design: docs/design/1.0.0-backup-restore.md (D1, D2, D3, D5). Restore is a
// later step.
// =============================================================================

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use age::secrecy::SecretString;
use base64::{engine::general_purpose, Engine as _};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::{ConnectOptions, Connection};

/// Version of the archive layout. Verify refuses a higher one.
pub const FORMAT: u32 = 1;
pub const EXTENSION: &str = "oscm-backup";
pub const MIN_PASSPHRASE_LEN: usize = 12;
pub const PASSPHRASE_ENV: &str = "OPENSCM_BACKUP_PASSPHRASE";

const MANIFEST: &str = "manifest.json";
const DB_ENTRY: &str = "scm.db";
const KEY_ENTRY: &str = "keys/scmserver.key";
const PUB_ENTRY: &str = "keys/scmserver.pub";
const CONFIG_ENTRY: &str = "scmserver.config";
const REQUIRED: [&str; 3] = [DB_ENTRY, KEY_ENTRY, PUB_ENTRY];
const ALLOWED: [&str; 5] = [MANIFEST, DB_ENTRY, KEY_ENTRY, PUB_ENTRY, CONFIG_ENTRY];
const MAX_SMALL_ENTRY: u64 = 1 << 20;

/// Where the server's files are. `installed()` for the real server; tests
/// pass their own.
#[derive(Debug, Clone)]
pub struct Paths {
    pub db: PathBuf,
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub config: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub format: u32,
    pub openscm_version: String,
    pub edition: String,
    pub schema_version: i64,
    pub created_at: String,
    pub host: String,
    /// Entry name → SHA-256 (hex) of its contents.
    pub files: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct Created {
    pub path: PathBuf,
    pub size: u64,
    pub manifest: Manifest,
}

#[derive(Debug)]
pub struct Verified {
    pub manifest: Manifest,
    /// (label, count); None when the table does not exist in that schema.
    pub counts: Vec<(&'static str, Option<i64>)>,
    pub key_fingerprint: String,
    /// Some(true/false) when this machine's public key could be read.
    pub matches_this_server: Option<bool>,
    /// The backup's schema is newer than this OpenSCM: restore will refuse it.
    pub newer_than_this_server: bool,
}

enum Source {
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl Paths {
    // ─────────────────────────────────────────────────────────────────────────
    // Function: Paths::installed
    // The fixed locations of this platform (config.rs).
    // ─────────────────────────────────────────────────────────────────────────
    pub fn installed() -> Self {
        Paths {
            db: crate::config::db_path().into(),
            private_key: crate::config::private_key_path().into(),
            public_key: crate::config::public_key_path().into(),
            config: crate::config::config_path().into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: default_dir
// `backups/` next to the database — also where scheduled backups will go.
// ─────────────────────────────────────────────────────────────────────────────
pub fn default_dir(db: &Path) -> PathBuf {
    db.parent().unwrap_or_else(|| Path::new(".")).join("backups")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: default_file_name
// openscm-<host>-<YYYYMMDDTHHMMSSZ>.oscm-backup, host reduced to safe chars.
// ─────────────────────────────────────────────────────────────────────────────
pub fn default_file_name(host: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let host: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    let host = if host.is_empty() { "openscm".to_string() } else { host };
    format!("openscm-{}-{}.{}", host, now.format("%Y%m%dT%H%M%SZ"), EXTENSION)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: this_host
// ─────────────────────────────────────────────────────────────────────────────
fn this_host() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "openscm".into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: resolve_out
// Where `--out` points: nothing → the default directory (created, owner-only);
// an existing directory → a default name inside it; anything else → that file.
// ─────────────────────────────────────────────────────────────────────────────
pub fn resolve_out(out: Option<&Path>, db: &Path) -> Result<PathBuf, String> {
    let name = default_file_name(&this_host(), chrono::Utc::now());
    match out {
        None => {
            let dir = default_dir(db);
            create_private_dir(&dir)?;
            Ok(dir.join(name))
        }
        Some(p) if p.is_dir() => Ok(p.join(name)),
        Some(p) => Ok(p.to_path_buf()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create_private_dir
// mkdir -p, readable by the owner only on Unix.
// ─────────────────────────────────────────────────────────────────────────────
fn create_private_dir(dir: &Path) -> Result<(), String> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| format!("Cannot create backup directory {}: {}", dir.display(), e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: open_private_file
// Creates (or truncates) a file readable by the owner only on Unix.
// ─────────────────────────────────────────────────────────────────────────────
fn open_private_file(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: sha256_hex / sha256_file
// ─────────────────────────────────────────────────────────────────────────────
fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    Ok(hex_lower(&h.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: key_fingerprint
// Checks the private key belongs to the public key (both base64 files, as the
// server writes them) and returns `SHA256:<base64>` of the public key.
// ─────────────────────────────────────────────────────────────────────────────
pub fn key_fingerprint(private_b64: &str, public_b64: &str) -> Result<String, String> {
    let priv_bytes = general_purpose::STANDARD
        .decode(private_b64.trim())
        .map_err(|_| "The private key is not valid base64.".to_string())?;
    let priv_arr: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "The private key is not 32 bytes.".to_string())?;
    let pub_bytes = public_key_bytes(public_b64)?;
    let derived = ed25519_dalek::SigningKey::from_bytes(&priv_arr).verifying_key();
    if derived.as_bytes()[..] != pub_bytes[..] {
        return Err("The private and public keys do not belong together.".into());
    }
    Ok(fingerprint_of(&pub_bytes))
}

fn public_key_bytes(public_b64: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(public_b64.trim())
        .map_err(|_| "The public key is not valid base64.".to_string())
}

fn fingerprint_of(pub_bytes: &[u8]) -> String {
    format!("SHA256:{}", general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(pub_bytes)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: open_db
// One connection, no journal_mode change (sqlx leaves it alone unless asked),
// so opening the live WAL database here does not disturb the server.
// ─────────────────────────────────────────────────────────────────────────────
async fn open_db(path: &Path) -> Result<SqliteConnection, String> {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("Cannot open database {}: {}", path.display(), e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_snapshot
// integrity_check, then the schema version. On a copy, never the live file.
// ─────────────────────────────────────────────────────────────────────────────
async fn check_snapshot(conn: &mut SqliteConnection) -> Result<i64, String> {
    let rows: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("integrity_check failed to run: {e}"))?;
    if rows.len() != 1 || rows[0] != "ok" {
        return Err(format!(
            "The database copy failed integrity_check: {}",
            rows.into_iter().take(5).collect::<Vec<_>>().join("; ")
        ));
    }
    sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| "The database has no schema version: OpenSCM was never set up on it.".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: create
// Writes a backup of `paths` to `out` (which must not exist). The work factor
// is for tests only; None lets age pick about one second.
// The file appears only when complete: it is written as `<out>.partial` and
// renamed. On failure nothing is left behind.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn create(
    paths: &Paths,
    out: &Path,
    passphrase: &str,
    work_factor: Option<u8>,
) -> Result<Created, String> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!("The passphrase must be at least {MIN_PASSPHRASE_LEN} characters."));
    }
    if out.exists() {
        return Err(format!("{} already exists; not overwriting it.", out.display()));
    }
    if !paths.db.is_file() {
        return Err(format!("No database at {}.", paths.db.display()));
    }
    let out_dir = match out.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !out_dir.is_dir() {
        return Err(format!("The directory {} does not exist.", out_dir.display()));
    }

    // The snapshot goes next to the output: same disk, and /tmp may be small.
    let tmp = tempfile::Builder::new()
        .prefix(".oscm-backup-")
        .tempdir_in(&out_dir)
        .map_err(|e| format!("Cannot create a temporary directory in {}: {}", out_dir.display(), e))?;
    let snapshot = tmp.path().join(DB_ENTRY);

    // 1. Consistent copy of the live database.
    {
        let mut live = open_db(&paths.db).await?;
        sqlx::query("VACUUM INTO ?")
            .bind(snapshot.to_string_lossy().to_string())
            .execute(&mut live)
            .await
            .map_err(|e| format!("Snapshot of the database failed: {e}"))?;
        let _ = live.close().await;
    }
    let schema_version = {
        let mut conn = open_db(&snapshot).await?;
        let v = check_snapshot(&mut conn).await;
        let _ = conn.close().await;
        v?
    };

    // 2. Keys and config, read once into memory, so what is hashed is what is
    //    archived.
    let key = fs::read(&paths.private_key)
        .map_err(|e| format!("Cannot read the server key {}: {}", paths.private_key.display(), e))?;
    let pubkey = fs::read(&paths.public_key)
        .map_err(|e| format!("Cannot read the server public key {}: {}", paths.public_key.display(), e))?;
    key_fingerprint(&String::from_utf8_lossy(&key), &String::from_utf8_lossy(&pubkey))?;
    let config = if paths.config.is_file() {
        Some(fs::read(&paths.config)
            .map_err(|e| format!("Cannot read the config {}: {}", paths.config.display(), e))?)
    } else {
        None
    };

    // 3. Manifest.
    let mut files = BTreeMap::new();
    files.insert(DB_ENTRY.to_string(), sha256_file(&snapshot).map_err(|e| e.to_string())?);
    files.insert(KEY_ENTRY.to_string(), sha256_hex(&key));
    files.insert(PUB_ENTRY.to_string(), sha256_hex(&pubkey));
    if let Some(c) = &config {
        files.insert(CONFIG_ENTRY.to_string(), sha256_hex(c));
    }
    let now = chrono::Utc::now();
    let manifest = Manifest {
        format: FORMAT,
        openscm_version: crate::app_version().to_string(),
        edition: crate::app_edition().to_string(),
        schema_version,
        created_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        host: this_host(),
        files,
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;

    let mut entries: Vec<(&str, Source)> = vec![
        (DB_ENTRY, Source::File(snapshot.clone())),
        (KEY_ENTRY, Source::Bytes(key)),
        (PUB_ENTRY, Source::Bytes(pubkey)),
    ];
    if let Some(c) = config {
        entries.push((CONFIG_ENTRY, Source::Bytes(c)));
    }

    // 4. Encrypted archive, then rename into place.
    let mut partial = out.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let written = write_archive(&partial, &manifest_json, &entries, passphrase, work_factor, now.timestamp());
    if let Err(e) = written {
        let _ = fs::remove_file(&partial);
        return Err(format!("Writing the backup failed: {e}"));
    }
    if let Err(e) = fs::rename(&partial, out) {
        let _ = fs::remove_file(&partial);
        return Err(format!("Cannot move the backup into place at {}: {}", out.display(), e));
    }
    let size = fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    Ok(Created { path: out.to_path_buf(), size, manifest })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: write_archive
// manifest.json first, then the entries; tar → gzip → age → file, fsynced.
// ─────────────────────────────────────────────────────────────────────────────
fn write_archive(
    path: &Path,
    manifest: &[u8],
    entries: &[(&str, Source)],
    passphrase: &str,
    work_factor: Option<u8>,
    mtime: i64,
) -> io::Result<()> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    if let Some(n) = work_factor {
        recipient.set_work_factor(n);
    }
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(io::Error::other)?;

    let file = open_private_file(path)?;
    let age_w = encryptor.wrap_output(BufWriter::new(file))?;
    let mut tar = tar::Builder::new(GzEncoder::new(age_w, Compression::default()));

    let header = |size: u64| {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(size);
        h.set_mode(0o600);
        h.set_mtime(mtime.max(0) as u64);
        h
    };
    tar.append_data(&mut header(manifest.len() as u64), MANIFEST, manifest)?;
    for (name, src) in entries {
        match src {
            Source::Bytes(b) => tar.append_data(&mut header(b.len() as u64), name, b.as_slice())?,
            Source::File(p) => {
                let f = File::open(p)?;
                let len = f.metadata()?.len();
                tar.append_data(&mut header(len), name, f)?
            }
        }
    }
    let gz = tar.into_inner()?;
    let age_w = gz.finish()?;
    let buf = age_w.finish()?;
    let file = buf.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: extract
// Decrypts `file` into `dir`. Returns the manifest bytes and the SHA-256 of
// every other entry. Refuses unknown, duplicate or non-file entries, and reads
// to the end so a cut-off file is noticed.
// ─────────────────────────────────────────────────────────────────────────────
fn extract(file: &Path, passphrase: &str, dir: &Path) -> Result<(Vec<u8>, BTreeMap<String, String>), String> {
    let f = File::open(file).map_err(|e| format!("Cannot open {}: {}", file.display(), e))?;
    let decryptor = age::Decryptor::new_buffered(BufReader::new(f))
        .map_err(|_| format!("{} is not an OpenSCM backup (not an age file).", file.display()))?;
    if !decryptor.is_scrypt() {
        return Err(format!("{} is not an OpenSCM backup (not passphrase-encrypted).", file.display()));
    }
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                "Wrong passphrase, or the file was changed.".to_string()
            }
            age::DecryptError::ExcessiveWork { .. } => {
                "The file asks for more decryption work than this machine allows; it was not made by OpenSCM on a comparable machine.".to_string()
            }
            other => format!("Cannot decrypt the backup: {other}"),
        })?;

    let damaged = |e: io::Error| format!("The backup is damaged or was changed: {e}");
    let mut archive = tar::Archive::new(GzDecoder::new(reader));
    let mut manifest: Option<Vec<u8>> = None;
    let mut hashes = BTreeMap::new();

    for entry in archive.entries().map_err(damaged)? {
        let mut entry = entry.map_err(damaged)?;
        let name = entry.path().map_err(damaged)?.to_string_lossy().to_string();
        if !ALLOWED.contains(&name.as_str()) {
            return Err(format!("The backup contains an unexpected entry '{name}'."));
        }
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(format!("The backup entry '{name}' is not a regular file."));
        }
        if name == MANIFEST {
            if manifest.is_some() {
                return Err("The backup contains two manifests.".into());
            }
            let mut buf = Vec::new();
            (&mut entry).take(MAX_SMALL_ENTRY).read_to_end(&mut buf).map_err(damaged)?;
            manifest = Some(buf);
            continue;
        }
        if hashes.contains_key(&name) {
            return Err(format!("The backup contains '{name}' twice."));
        }
        let dest = dir.join(&name);
        if let Some(parent) = dest.parent() {
            create_private_dir(parent)?;
        }
        let mut out = open_private_file(&dest).map_err(|e| format!("Cannot write {}: {}", dest.display(), e))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = entry.read(&mut buf).map_err(damaged)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(|e| format!("Cannot write {}: {}", dest.display(), e))?;
        }
        hashes.insert(name, hex_lower(&hasher.finalize()));
    }
    // Drain to the end: the gzip trailer and the last age chunk are checked
    // only when read.
    let mut rest = archive.into_inner();
    io::copy(&mut rest, &mut io::sink()).map_err(damaged)?;

    let manifest = manifest.ok_or("The backup has no manifest.")?;
    Ok((manifest, hashes))
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: verify
// Checks a backup end to end without touching the live server.
// `live_public_key` is this machine's key, to say whether the backup is of
// this server; None or unreadable → not compared.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn verify(file: &Path, passphrase: &str, live_public_key: Option<&Path>) -> Result<Verified, String> {
    let tmp = tempfile::Builder::new()
        .prefix("oscm-verify-")
        .tempdir()
        .map_err(|e| format!("Cannot create a temporary directory: {e}"))?;
    let (manifest_bytes, hashes) = extract(file, passphrase, tmp.path())?;

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("The backup's manifest is not readable: {e}"))?;
    if manifest.format > FORMAT {
        return Err(format!(
            "This backup was made by a newer OpenSCM ({}, format {}). Verify it with that version or later.",
            manifest.openscm_version, manifest.format
        ));
    }
    for name in REQUIRED {
        if !manifest.files.contains_key(name) {
            return Err(format!("The backup has no '{name}'."));
        }
    }
    for (name, want) in &manifest.files {
        match hashes.get(name) {
            None => return Err(format!("The manifest lists '{name}' but the backup does not contain it.")),
            Some(got) if got != want => return Err(format!("'{name}' does not match its checksum in the manifest.")),
            Some(_) => {}
        }
    }
    if let Some(extra) = hashes.keys().find(|n| !manifest.files.contains_key(*n)) {
        return Err(format!("The backup contains '{extra}', which the manifest does not list."));
    }

    let read = |name: &str| fs::read_to_string(tmp.path().join(name)).map_err(|e| format!("{name}: {e}"));
    let pub_b64 = read(PUB_ENTRY)?;
    let key_fingerprint = key_fingerprint(&read(KEY_ENTRY)?, &pub_b64)?;

    let (schema, counts) = {
        let mut conn = open_db(&tmp.path().join(DB_ENTRY)).await?;
        let schema = check_snapshot(&mut conn).await;
        let mut counts = Vec::new();
        if schema.is_ok() {
            for (label, table) in [("Organizations", "tenants"), ("Systems", "systems"),
                                   ("Results", "results"), ("Saved reports", "reports")] {
                let n: Option<i64> = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(&mut conn).await.ok();
                counts.push((label, n));
            }
        }
        let _ = conn.close().await;
        (schema?, counts)
    };
    if schema != manifest.schema_version {
        return Err(format!(
            "The manifest says schema {} but the database is at {}.",
            manifest.schema_version, schema
        ));
    }

    let matches_this_server = live_public_key
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| public_key_bytes(&s).ok())
        .map(|live| fingerprint_of(&live) == key_fingerprint);

    Ok(Verified {
        newer_than_this_server: manifest.schema_version > crate::schema::SCHEMA_VERSION,
        manifest,
        counts,
        key_fingerprint,
        matches_this_server,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Command line
// ─────────────────────────────────────────────────────────────────────────────

fn print_usage() {
    println!(
        r#"
USAGE:
    scmserver backup [--out PATH] [--passphrase-file FILE]
    scmserver backup verify FILE [--passphrase-file FILE]

Writes an encrypted backup of the database, the server key pair and the
config while the server runs. --out is a file, or a directory to write a
dated file into (default: {}).

The passphrase is read from --passphrase-file, then the
{} variable, then asked for. It must be at least {} characters. Without it a backup
cannot be restored: keep it somewhere other than the backups.

`verify` decrypts a backup, checks every file and the database copy, and
prints what it holds. It does not touch the running server.
"#,
        default_dir(Path::new(crate::config::db_path())).display(),
        PASSPHRASE_ENV,
        MIN_PASSPHRASE_LEN
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: read_passphrase
// --passphrase-file (one trailing newline dropped), then the environment,
// then a prompt (asked twice for a new backup).
// ─────────────────────────────────────────────────────────────────────────────
fn read_passphrase(file: Option<&Path>, confirm: bool) -> Result<String, String> {
    if let Some(p) = file {
        let s = fs::read_to_string(p).map_err(|e| format!("Cannot read {}: {}", p.display(), e))?;
        let s = s.strip_suffix('\n').map(|s| s.strip_suffix('\r').unwrap_or(s)).unwrap_or(&s).to_string();
        if s.is_empty() {
            return Err(format!("{} is empty.", p.display()));
        }
        return Ok(s);
    }
    if let Ok(s) = std::env::var(PASSPHRASE_ENV) {
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let p = rpassword::prompt_password("Backup passphrase: ")
        .map_err(|e| format!("Cannot ask for the passphrase ({e}); use --passphrase-file or {PASSPHRASE_ENV}."))?;
    if confirm {
        if p.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(format!("The passphrase must be at least {MIN_PASSPHRASE_LEN} characters."));
        }
        let again = rpassword::prompt_password("Again: ").map_err(|e| e.to_string())?;
        if again != p {
            return Err("The passphrases do not match.".into());
        }
    }
    Ok(p)
}

fn human_size(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", units[i]) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: run_cli
// `scmserver backup …`; `args` are the words after "backup". Returns the
// process exit code.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_cli(args: &[String]) -> i32 {
    match run_cli_inner(args).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

async fn run_cli_inner(args: &[String]) -> Result<(), String> {
    let mut verify_file: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut pass_file: Option<PathBuf> = None;
    let mut it = args.iter();
    let is_verify = args.first().map(|a| a == "verify").unwrap_or(false);
    if is_verify {
        it.next();
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "--out" if !is_verify => {
                out = Some(it.next().ok_or("--out needs a path")?.into());
            }
            "--passphrase-file" => {
                pass_file = Some(it.next().ok_or("--passphrase-file needs a path")?.into());
            }
            s if is_verify && verify_file.is_none() && !s.starts_with('-') => verify_file = Some(s.into()),
            s => return Err(format!("unknown argument '{s}' (see scmserver backup --help)")),
        }
    }

    let paths = Paths::installed();
    if is_verify {
        let file = verify_file.ok_or("verify needs the backup file (see scmserver backup --help)")?;
        let pass = read_passphrase(pass_file.as_deref(), false)?;
        let v = verify(&file, &pass, Some(&paths.public_key)).await?;
        let m = &v.manifest;
        println!("Backup OK: {}", file.display());
        println!("  Made        {} on {}", m.created_at, m.host);
        println!("  OpenSCM     {} ({}), schema {}", m.openscm_version, m.edition, m.schema_version);
        for (label, n) in &v.counts {
            println!("  {:<12}{}", label, n.map(|n| n.to_string()).unwrap_or_else(|| "-".into()));
        }
        println!("  Server key  {}", v.key_fingerprint);
        match v.matches_this_server {
            Some(true) => println!("              the same key as this server"),
            Some(false) => println!("              a different key from this server"),
            None => {}
        }
        println!("  Config      {}", if m.files.contains_key(CONFIG_ENTRY) { "included" } else { "not included" });
        if v.newer_than_this_server {
            println!(
                "\nWarning: this backup's schema ({}) is newer than this OpenSCM {} understands ({}).\nRestoring it needs OpenSCM {} or later.",
                m.schema_version, crate::app_version(), crate::schema::SCHEMA_VERSION, m.openscm_version
            );
        }
        return Ok(());
    }

    let target = resolve_out(out.as_deref(), &paths.db)?;
    let pass = read_passphrase(pass_file.as_deref(), true)?;
    let c = create(&paths, &target, &pass, None).await?;
    println!("Backup written: {} ({})", c.path.display(), human_size(c.size));
    println!(
        "  OpenSCM {} ({}), schema {}{}",
        c.manifest.openscm_version,
        c.manifest.edition,
        c.manifest.schema_version,
        if c.manifest.files.contains_key(CONFIG_ENTRY) { "" } else { ", config not included (not a file on this platform)" }
    );
    println!("Check it with: scmserver backup verify {}", c.path.display());
    println!("Without the passphrase it cannot be restored. Copy it off this server.");
    Ok(())
}
