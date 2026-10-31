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
pub(crate) fn this_host() -> String {
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
            let existed = dir.is_dir();
            create_private_dir(&dir)?;
            // Created by `sudo scmserver backup`, it would be root's alone
            // and scheduled backups (the service account) could not use it.
            if !existed {
                match_owner(db, &dir, 0o700)
                    .map_err(|e| format!("Cannot give {} the database's owner: {}", dir.display(), e))?;
            }
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
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), String> {
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
// Helper: match_owner
// Gives `path` the owner and group of `like` (the database) and `mode`.
// A no-op when they already match, as for the service account's own runs.
// Unix only; Windows files inherit the folder's permissions.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn match_owner(like: &Path, path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(like)?;
        apply_owner(path, (m.uid(), m.gid(), mode))?;
    }
    #[cfg(not(unix))]
    let _ = (like, path, mode);
    Ok(())
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
    // Owned like the database, so the service account can prune it later
    // even when it was written with sudo.
    if let Err(e) = match_owner(&paths.db, out, 0o600) {
        tracing::warn!("Cannot give {} the database's owner: {e}", out.display());
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
    check(file, passphrase, tmp.path(), live_public_key).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check
// The work of verify, unpacking into `dir` (left there for restore to use).
// ─────────────────────────────────────────────────────────────────────────────
async fn check(file: &Path, passphrase: &str, dir: &Path, live_public_key: Option<&Path>) -> Result<Verified, String> {
    let (manifest_bytes, hashes) = extract(file, passphrase, dir)?;

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

    let read = |name: &str| fs::read_to_string(dir.join(name)).map_err(|e| format!("{name}: {e}"));
    let pub_b64 = read(PUB_ENTRY)?;
    let key_fingerprint = key_fingerprint(&read(KEY_ENTRY)?, &pub_b64)?;

    let (schema, counts) = {
        let mut conn = open_db(&dir.join(DB_ENTRY)).await?;
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
// Restore
// ─────────────────────────────────────────────────────────────────────────────

/// Written next to the database by restore; the next server start turns it
/// into a `backup.restored` audit entry and deletes it.
pub const RESTORE_NOTE: &str = "restored.json";

#[derive(Debug)]
pub struct Restored {
    pub verified: Verified,
    /// Where the replaced files were moved.
    pub pre_restore: PathBuf,
    pub config_restored: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct RestoreNote {
    backup_file: String,
    backup_created_at: String,
    backup_host: String,
    backup_version: String,
    backup_schema: i64,
    restored_at: String,
    pre_restore: String,
    config_restored: bool,
}

/// One file restore replaces: moved aside to `pre/aside`, then replaced by
/// `src` (None: only moved aside, e.g. the old database's -wal and -shm).
struct Swap {
    target: PathBuf,
    src: Option<PathBuf>,
    aside: &'static str,
    /// Mode for a new file when there was none to copy it from.
    default_mode: u32,
}

/// What restore has done so far, to undo it on failure.
struct Done {
    target: PathBuf,
    moved_aside: Option<PathBuf>,
    placed: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: is_saas
// SaaS databases carry tables CE and EE do not have (and the other way round
// matters as well: a CE database has no plans or tenants to serve SaaS).
// ─────────────────────────────────────────────────────────────────────────────
fn is_saas(edition: &str) -> bool {
    edition.contains("SaaS")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: move_file
// rename, or copy + remove when the destination is on another file system
// (/etc and /var/lib can be).
// ─────────────────────────────────────────────────────────────────────────────
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to)?;
    fs::remove_file(from)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: owner_template
// Owner, group and mode for a restored file: those of the file it replaces,
// else the directory's owner with `default_mode`. A restore run with sudo
// must not leave root-owned files the service account cannot read.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
pub(crate) fn owner_template(existing: Option<&fs::Metadata>, dir: &Path, default_mode: u32) -> io::Result<(u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    match existing {
        Some(m) => Ok((m.uid(), m.gid(), m.mode() & 0o7777)),
        None => {
            let d = fs::metadata(dir)?;
            Ok((d.uid(), d.gid(), default_mode))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: apply_owner
// chown + chmod. A chown that fails is an error only when it was needed.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
pub(crate) fn apply_owner(path: &Path, (uid, gid, mode): (u32, u32, u32)) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = fs::metadata(path)?;
    if (m.uid(), m.gid()) != (uid, gid) {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: place
// Copies `src` next to `target` (same directory, so the final rename is
// atomic), gives it the template's owner and mode, renames it into place.
// ─────────────────────────────────────────────────────────────────────────────
fn place(src: &Path, target: &Path, existing: Option<&fs::Metadata>, default_mode: u32) -> io::Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let staging = dir.join(format!(".{name}.restore-tmp"));
    let result = (|| {
        fs::copy(src, &staging)?;
        #[cfg(unix)]
        apply_owner(&staging, owner_template(existing, dir, default_mode)?)?;
        #[cfg(not(unix))]
        let _ = (existing, default_mode);
        File::open(&staging)?.sync_all()?;
        fs::rename(&staging, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: undo
// Puts back what restore moved aside, newest first.
// ─────────────────────────────────────────────────────────────────────────────
fn undo(done: Vec<Done>) {
    for d in done.into_iter().rev() {
        if d.placed {
            let _ = fs::remove_file(&d.target);
        }
        if let Some(a) = d.moved_aside {
            let _ = move_file(&a, &d.target);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: restore
// Replaces this server's database and key pair (and config, with
// `include_config`) with a backup's. Takes the server's instance lock, so it
// cannot run under a running server. `confirm` sees what will be restored and
// returns false to stop. Nothing changes until it has said yes and every
// check has passed; a failure while replacing puts the old files back.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn restore(
    paths: &Paths,
    file: &Path,
    passphrase: &str,
    include_config: bool,
    confirm: impl FnOnce(&Verified) -> bool,
) -> Result<Restored, String> {
    let db_str = paths.db.to_string_lossy().to_string();
    let _lock = crate::instance_lock::acquire(&db_str).map_err(|e| {
        format!("{e}\nThe server must be stopped for a restore. Nothing was changed.")
    })?;
    let db_dir = paths.db.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();

    // Unpack next to the database: same file system as the target.
    let tmp = tempfile::Builder::new()
        .prefix(".oscm-restore-")
        .tempdir_in(&db_dir)
        .map_err(|e| format!("Cannot create a temporary directory in {}: {}", db_dir.display(), e))?;
    let v = check(file, passphrase, tmp.path(), Some(&paths.public_key)).await?;
    let m = &v.manifest;

    if v.newer_than_this_server {
        return Err(format!(
            "This backup is from OpenSCM {} (schema {}); this OpenSCM {} knows up to schema {}. Install OpenSCM {} or later first. Nothing was changed.",
            m.openscm_version, m.schema_version, crate::app_version(), crate::schema::SCHEMA_VERSION, m.openscm_version
        ));
    }
    if is_saas(&m.edition) != is_saas(crate::app_edition()) {
        return Err(format!(
            "This is a backup of OpenSCM {}; it cannot be restored onto OpenSCM {}. Nothing was changed.",
            m.edition, crate::app_edition()
        ));
    }
    if include_config && !m.files.contains_key(CONFIG_ENTRY) {
        return Err("--include-config: this backup has no config file. Nothing was changed.".into());
    }
    if !confirm(&v) {
        return Err("Cancelled. Nothing was changed.".into());
    }

    let ts = chrono::Utc::now();
    let pre = db_dir.join(format!("pre-restore-{}", ts.format("%Y%m%dT%H%M%SZ")));
    create_private_dir(&pre.join("keys"))?;

    let with_suffix = |p: &Path, s: &str| { let mut o = p.as_os_str().to_owned(); o.push(s); PathBuf::from(o) };
    let mut swaps = vec![
        // The old -wal and -shm go first: they must never sit next to the
        // restored database.
        Swap { target: with_suffix(&paths.db, "-wal"), src: None, aside: "scm.db-wal", default_mode: 0o600 },
        Swap { target: with_suffix(&paths.db, "-shm"), src: None, aside: "scm.db-shm", default_mode: 0o600 },
        Swap { target: paths.db.clone(), src: Some(tmp.path().join(DB_ENTRY)), aside: "scm.db", default_mode: 0o600 },
        Swap { target: paths.private_key.clone(), src: Some(tmp.path().join(KEY_ENTRY)), aside: KEY_ENTRY, default_mode: 0o600 },
        Swap { target: paths.public_key.clone(), src: Some(tmp.path().join(PUB_ENTRY)), aside: PUB_ENTRY, default_mode: 0o644 },
    ];
    if include_config {
        swaps.push(Swap { target: paths.config.clone(), src: Some(tmp.path().join(CONFIG_ENTRY)), aside: CONFIG_ENTRY, default_mode: 0o600 });
    }

    let mut done: Vec<Done> = Vec::new();
    for s in &swaps {
        let existing = fs::metadata(&s.target).ok();
        let mut d = Done { target: s.target.clone(), moved_aside: None, placed: false };
        if existing.is_some() {
            let aside = pre.join(s.aside);
            if let Err(e) = move_file(&s.target, &aside) {
                undo(done);
                return Err(format!("Cannot move {} aside: {}. The old files were put back.", s.target.display(), e));
            }
            d.moved_aside = Some(aside);
        }
        if let Some(src) = &s.src {
            if let Some(parent) = s.target.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(e) = place(src, &s.target, existing.as_ref(), s.default_mode) {
                done.push(d);
                undo(done);
                return Err(format!("Cannot write {}: {}. The old files were put back.", s.target.display(), e));
            }
            d.placed = true;
        }
        done.push(d);
    }

    // The note for the audit log. Failing to write it does not undo a
    // restore that has otherwise succeeded.
    let note = RestoreNote {
        backup_file: file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        backup_created_at: m.created_at.clone(),
        backup_host: m.host.clone(),
        backup_version: m.openscm_version.clone(),
        backup_schema: m.schema_version,
        restored_at: ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        pre_restore: pre.display().to_string(),
        config_restored: include_config,
    };
    if let Ok(json) = serde_json::to_vec_pretty(&note) {
        let note_path = db_dir.join(RESTORE_NOTE);
        if fs::write(&note_path, json).is_ok() {
            #[cfg(unix)]
            if let Ok(t) = owner_template(fs::metadata(&paths.db).ok().as_ref(), &db_dir, 0o600) {
                let _ = apply_owner(&note_path, t);
            }
        }
    }

    Ok(Restored { verified: v, pre_restore: pre, config_restored: include_config })
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: record_restore
// At server start, after migrations: turns the note restore left into a
// `backup.restored` audit entry, then deletes it, so it is recorded once.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record_restore(pool: &sqlx::SqlitePool, db_path: &str) {
    let path = Path::new(db_path).parent().unwrap_or(Path::new(".")).join(RESTORE_NOTE);
    let Ok(raw) = fs::read_to_string(&path) else { return };
    let (target, message, details) = match serde_json::from_str::<RestoreNote>(&raw) {
        Ok(n) => (
            n.backup_file.clone(),
            format!(
                "Restored from {} (made {} on {}, OpenSCM {}, schema {}){}; replaced files kept in {}",
                n.backup_file, n.backup_created_at, n.backup_host, n.backup_version, n.backup_schema,
                if n.config_restored { ", config included" } else { "" }, n.pre_restore
            ),
            serde_json::json!({
                "backup_file": n.backup_file, "backup_created_at": n.backup_created_at,
                "backup_host": n.backup_host, "backup_version": n.backup_version,
                "backup_schema": n.backup_schema, "config_restored": n.config_restored,
                "pre_restore": n.pre_restore,
            }),
        ),
        Err(_) => (
            String::new(),
            format!("Restored from a backup ({})", raw.trim()),
            serde_json::json!({"message": "Restored from a backup", "note": raw.trim()}),
        ),
    };
    crate::audit::record_raw(pool, "default", None, "system", None, "backup.restored",
                             Some("backup"), Some(&target), Some(details)).await;
    tracing::info!("{message}");
    if let Err(e) = fs::remove_file(&path) {
        tracing::warn!("Cannot remove {}: {e}", path.display());
    }
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
    scmserver backup set-passphrase

Writes an encrypted backup of the database, the server key pair and the
config while the server runs. --out is a file, or a directory to write a
dated file into (default: {}).

The passphrase is read from --passphrase-file, then the
{} variable, then the server's passphrase file
({}), then asked for. It must be at least {} characters.
Without it a backup cannot be restored: keep a copy somewhere other than the
backups.

`set-passphrase` sets the server's passphrase file, used by scheduled
backups and Settings → Backup. Only from the server's shell: the web
interface never sets it.

`verify` decrypts a backup, checks every file and the database copy, and
prints what it holds. It does not touch the running server.
"#,
        default_dir(Path::new(crate::config::db_path())).display(),
        PASSPHRASE_ENV,
        crate::config::backup_passphrase_path().display(),
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
    // The server's own passphrase file (set-passphrase), when there is one.
    let server_file = crate::config::backup_passphrase_path();
    if server_file.exists() {
        return crate::backup_jobs::read_passphrase_file(&server_file);
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

pub(crate) fn human_size(n: u64) -> String {
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
// Helper: print_summary
// What a backup holds, for verify and for restore's confirmation.
// ─────────────────────────────────────────────────────────────────────────────
fn print_summary(v: &Verified) {
    let m = &v.manifest;
    println!("  Made           {} on {}", m.created_at, m.host);
    println!("  OpenSCM        {} ({}), schema {}", m.openscm_version, m.edition, m.schema_version);
    for (label, n) in &v.counts {
        println!("  {:<15}{}", label, n.map(|n| n.to_string()).unwrap_or_else(|| "-".into()));
    }
    println!("  Server key     {}", v.key_fingerprint);
    match v.matches_this_server {
        Some(true) => println!("                 the same key as this server"),
        Some(false) => println!("                 a different key from this server"),
        None => {}
    }
    println!("  Config         {}", if m.files.contains_key(CONFIG_ENTRY) { "included" } else { "not included" });
    if v.newer_than_this_server {
        println!(
            "\nWarning: this backup's schema ({}) is newer than this OpenSCM {} understands ({}).\nRestoring it needs OpenSCM {} or later.",
            m.schema_version, crate::app_version(), crate::schema::SCHEMA_VERSION, m.openscm_version
        );
    }
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
    if args.first().map(|a| a == "set-passphrase").unwrap_or(false) {
        if let Some(a) = args.get(1) {
            if a == "-h" || a == "--help" {
                print_usage();
                return Ok(());
            }
            return Err(format!("unknown argument '{a}' (see scmserver backup --help)"));
        }
        return set_passphrase().await;
    }
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
        println!("Backup OK: {}", file.display());
        print_summary(&v);
        return Ok(());
    }

    let target = resolve_out(out.as_deref(), &paths.db)?;
    let pass = read_passphrase(pass_file.as_deref(), true)?;
    let c = create(&paths, &target, &pass, None).await?;
    crate::backup_jobs::record_cli_backup(&paths.db, &c.path, c.size).await;
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

// ─────────────────────────────────────────────────────────────────────────────
// Helper: set_passphrase
// `scmserver backup set-passphrase`: asks twice, writes the server's
// passphrase file owner-only, owned like the server key.
// ─────────────────────────────────────────────────────────────────────────────
async fn set_passphrase() -> Result<(), String> {
    let path = crate::config::backup_passphrase_path();
    let replacing = path.exists();
    let p = rpassword::prompt_password("New backup passphrase: ")
        .map_err(|e| format!("Cannot ask for the passphrase: {e}"))?;
    if p.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!("The passphrase must be at least {MIN_PASSPHRASE_LEN} characters."));
    }
    let again = rpassword::prompt_password("Again: ").map_err(|e| e.to_string())?;
    if again != p {
        return Err("The passphrases do not match.".into());
    }
    crate::backup_jobs::write_passphrase_file(&path, &p, Path::new(crate::config::private_key_path()))?;
    println!("Backup passphrase saved to {}.", path.display());
    if replacing {
        println!("Backups made before now still need the old passphrase.");
    }
    println!("Keep a copy somewhere other than this server: without it, no backup can be restored.");
    Ok(())
}

fn print_restore_usage() {
    println!(
        r#"
USAGE:
    scmserver restore FILE [--include-config] [--passphrase-file FILE] [--yes]

Replaces this server's database and key pair with those in a backup made by
`scmserver backup`. The server must be stopped.

The backup is checked first; one from a newer OpenSCM, or from another
edition (SaaS vs Community/Enterprise), is refused. An older one is fine: the
next server start upgrades it. The current files are moved to
pre-restore-<time>/ next to the database, so a restore can be undone.

--include-config   also restore scmserver.config (leave it out when moving
                   to a machine with other TLS paths or addresses)
--yes              do not ask for confirmation
"#
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Function: run_restore_cli
// `scmserver restore …`; `args` are the words after "restore". Returns the
// process exit code.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_restore_cli(args: &[String]) -> i32 {
    match run_restore_cli_inner(args).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

async fn run_restore_cli_inner(args: &[String]) -> Result<(), String> {
    let mut file: Option<PathBuf> = None;
    let mut pass_file: Option<PathBuf> = None;
    let mut include_config = false;
    let mut yes = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_restore_usage();
                return Ok(());
            }
            "--include-config" => include_config = true,
            "--yes" | "-y" => yes = true,
            "--passphrase-file" => pass_file = Some(it.next().ok_or("--passphrase-file needs a path")?.into()),
            s if file.is_none() && !s.starts_with('-') => file = Some(s.into()),
            s => return Err(format!("unknown argument '{s}' (see scmserver restore --help)")),
        }
    }
    let file = file.ok_or("restore needs the backup file (see scmserver restore --help)")?;
    let paths = Paths::installed();
    let pass = read_passphrase(pass_file.as_deref(), false)?;

    let r = restore(&paths, &file, &pass, include_config, |v| {
        println!("Restoring {}", file.display());
        print_summary(v);
        println!("\nThis replaces the database and server key{} of this server:", if include_config { ", and the config," } else { "" });
        println!("  {}", paths.db.display());
        println!("  {}", paths.private_key.display());
        if include_config {
            println!("  {}", paths.config.display());
        }
        if yes {
            return true;
        }
        print!("The current files are kept. Type 'restore' to continue: ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line).is_ok() && line.trim() == "restore"
    })
    .await?;

    let m = &r.verified.manifest;
    println!("\nRestored the backup made {} on {} (OpenSCM {}, schema {}).", m.created_at, m.host, m.openscm_version, m.schema_version);
    println!("The replaced files are in {}.", r.pre_restore.display());
    if !r.config_restored {
        println!("The config was not changed{}.", if m.files.contains_key(CONFIG_ENTRY) { " (use --include-config to restore it too)" } else { "" });
    }
    println!("\nNext:");
    if m.schema_version < crate::schema::SCHEMA_VERSION {
        println!("  - Start the server. It upgrades the database from schema {} to {} on start.", m.schema_version, crate::schema::SCHEMA_VERSION);
    } else {
        println!("  - Start the server.");
    }
    match r.verified.matches_this_server {
        Some(true) => println!("  - The server key is unchanged: agents reconnect on their own."),
        _ => println!("  - The server key is now the backup's. Agents that were enrolled with this\n    backup's server reconnect on their own; agents that pinned a different key\n    need `scmclient --reset-server-key`."),
    }
    println!("  - To undo: stop the server and move the files in {} back.", r.pre_restore.display());
    Ok(())
}
