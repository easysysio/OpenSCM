// =============================================================================
// secrets.rs — encryption of secrets stored in the database
//
// Credentials OpenSCM has to use, not just check, cannot be hashed: the
// tenants' agent-signing keys, the SSO client secret, the LDAP bind password,
// the SMTP password and webhook signing secrets. They are stored encrypted
// with ChaCha20-Poly1305 under a key derived from the server's key file, so a
// copy of the database alone (a leaked backup, a disk image) does not hold
// them. Someone with the database AND the key file, or running on the server,
// can still read them; this is not a defence against that.
//
// Stored form:  enc:v1:<base64 of 12-byte nonce || ciphertext || tag>
// The associated data is the column's name (COL_*), so a value copied into a
// different column does not decrypt. It is not bound to the row: copying a
// tenant's key row to another tenant, as tests and tooling do, still works.
//
// A value without the prefix is plaintext from before encryption and is
// returned as-is, so upgrades read old rows; encrypt_existing() rewrites them
// at startup.
//
// The key: HKDF-SHA256 over the session-cookie key, which is itself derived
// from the server's private key file. create_core_router sets it, so every
// edition has it before serving. Changing the key file, or the cookie key's
// derivation, makes every stored secret unreadable: see open().
// =============================================================================

use std::sync::OnceLock;

use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use sqlx::SqlitePool;
use tracing::{error, info, warn};

pub const PREFIX: &str = "enc:v1:";

pub const COL_TENANT_KEY: &str = "tenant_keys.private_key";
pub const COL_SSO_SECRET: &str = "sso_providers.client_secret";
pub const COL_BIND_PASSWORD: &str = "directories.bind_password";
pub const COL_SMTP_PASSWORD: &str = "settings.smtp_password";
pub const COL_WEBHOOK_SECRET: &str = "alert_actions.target_secret";

static KEY: OnceLock<LessSafeKey> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// Helper: init_from_cookie_key
// Sets the process's secrets key, once; later calls are ignored. The label
// separates it from every other key derived from the same material.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init_from_cookie_key(cookie_key: &axum_extra::extract::cookie::Key) {
    if KEY.get().is_some() {
        return;
    }
    let mut bytes = [0u8; 32];
    Hkdf::<Sha256>::new(None, cookie_key.master())
        .expand(b"oscm-secrets-at-rest-v1", &mut bytes)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &bytes).expect("32-byte ChaCha20-Poly1305 key"),
    );
    let _ = KEY.set(key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: seal
// Encrypts `plaintext` for storage in column `col`. An empty value stays
// empty: "" means "not set" everywhere these columns are read.
//
// Without a key (a test or tool that calls a handler without going through
// create_core_router) the value is stored as plaintext and logged; the next
// server start encrypts it. A serving server always has the key.
// ─────────────────────────────────────────────────────────────────────────────
pub fn seal(col: &str, plaintext: &str) -> String {
    if plaintext.is_empty() {
        return String::new();
    }
    let Some(key) = KEY.get() else {
        warn!("{}: no secrets key set; stored unencrypted until the next server start", col);
        return plaintext.to_string();
    };
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).expect("system random number generator");
    let mut buf = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(col.as_bytes()),
        &mut buf,
    )
    .expect("ChaCha20-Poly1305 seal");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    format!("{PREFIX}{}", general_purpose::STANDARD.encode(out))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: open
// The plaintext of a value read from column `col`. Values without the prefix
// are returned unchanged (stored before encryption existed).
//
// Fails when the value was sealed under another key — the server's key file
// was replaced or lost — or was altered. The secret then has to be entered
// again; for a tenant signing key, Settings → Danger Zone → Rotate Signing Key
// issues a new one.
// ─────────────────────────────────────────────────────────────────────────────
pub fn open(col: &str, stored: &str) -> Result<String, String> {
    let Some(b64) = stored.strip_prefix(PREFIX) else {
        return Ok(stored.to_string());
    };
    let key = KEY.get().ok_or_else(|| format!("{col}: no secrets key set"))?;
    let raw = general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| format!("{col}: stored secret is not valid base64"))?;
    if raw.len() < NONCE_LEN {
        return Err(format!("{col}: stored secret is truncated"));
    }
    let (nonce, sealed) = raw.split_at(NONCE_LEN);
    let mut buf = sealed.to_vec();
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| format!("{col}: bad nonce"))?;
    let plain = key
        .open_in_place(nonce, Aad::from(col.as_bytes()), &mut buf)
        .map_err(|_| {
            format!(
                "{col}: stored secret cannot be decrypted. The server's key file has changed \
                 since it was saved; enter the secret again"
            )
        })?;
    String::from_utf8(plain.to_vec()).map_err(|_| format!("{col}: decrypted secret is not UTF-8"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: open_or_empty
// open() for callers that treat a missing secret and an unreadable one alike:
// the failure is logged and the secret reads as not set.
// ─────────────────────────────────────────────────────────────────────────────
pub fn open_or_empty(col: &str, stored: &str) -> String {
    open(col, stored).unwrap_or_else(|e| {
        error!("{}", e);
        String::new()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: encrypt_existing
// Rewrites every plaintext secret still in the database in encrypted form.
// Run at startup, after migrations; safe to run again, since sealed values
// are skipped. Each value is replaced only if it is still the one read, so a
// concurrent save is not overwritten.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn encrypt_existing(pool: &SqlitePool) {
    if KEY.get().is_none() {
        error!("Stored secrets not encrypted: no secrets key set");
        return;
    }
    // (column label, table, value column, extra WHERE)
    let targets: [(&str, &str, &str, &str); 5] = [
        (COL_TENANT_KEY, "tenant_keys", "private_key", ""),
        (COL_SSO_SECRET, "sso_providers", "client_secret", ""),
        (COL_BIND_PASSWORD, "directories", "bind_password", ""),
        (COL_SMTP_PASSWORD, "settings", "value", "AND skey = 'smtp_password'"),
        (COL_WEBHOOK_SECRET, "alert_actions", "target_secret", ""),
    ];
    let mut total = 0u64;
    for (col, table, column, extra) in targets {
        let select = format!(
            "SELECT rowid, {column} FROM {table}
             WHERE {column} IS NOT NULL AND {column} != '' AND {column} NOT LIKE 'enc:v1:%' {extra}"
        );
        let rows: Vec<(i64, String)> = match sqlx::query_as(&select).fetch_all(pool).await {
            Ok(r) => r,
            Err(e) => {
                // A table this edition or version does not have.
                warn!("Encrypting {}: {}", col, e);
                continue;
            }
        };
        for (rowid, value) in rows {
            let update = format!("UPDATE {table} SET {column} = ? WHERE rowid = ? AND {column} = ?");
            match sqlx::query(&update)
                .bind(seal(col, &value)).bind(rowid).bind(&value)
                .execute(pool).await
            {
                Ok(r) => total += r.rows_affected(),
                Err(e) => error!("Encrypting {} row {}: {}", col, rowid, e),
            }
        }
    }
    if total > 0 {
        info!("Encrypted {} stored secret(s) that were still in plaintext", total);
    }
}
