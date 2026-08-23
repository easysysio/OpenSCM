// =============================================================================
// agents.rs — client-agent binary distribution and auto-upgrade support
//
// Agent binaries are embedded into the server binary at compile time via
// include_dir! in lib.rs (under `static/agents/`). At runtime they are served
// by the regular `/static/<file>` route — no separate download handler is
// needed, and there is no on-disk agents directory to manage. The trade-off
// is a bigger server binary in exchange for a single-file deployment.
//
// startup_scan
//   Called once after DB migrations on server startup. Iterates the embedded
//   `static/agents/` directory, computes SHA256 over each binary's in-memory
//   bytes, and upserts agent_packages. The agent version is read from the
//   bundled `agents/VERSION` file. It used to be the server's own
//   CARGO_PKG_VERSION on the reasoning that agents ship alongside the server
//   "so the two are guaranteed to match" — they are not, and when they diverge
//   the upgrade silently loops forever. See startup_scan. If the directory is
//   empty (e.g. a dev build with no bundled agents) the scan is skipped.
// =============================================================================

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tracing::{error, info, warn};

use crate::STATIC_FILES_DIR;


// ─────────────────────────────────────────────────────────────────────────────
// Helper: derive_platform
// Converts the raw arch + os strings from the agent heartbeat into a normalised
// "{arch}-{os_type}" string (e.g. "x86_64-linux", "aarch64-linux",
// "x86_64-windows") that matches the filenames in the agents directory and the
// keys in the agent_packages table.
// ─────────────────────────────────────────────────────────────────────────────
pub fn derive_platform(arch: &str, os: &str) -> String {
    // os_info reports macOS as "Mac OS 14.4.1" (with a space) — collapse all
    // whitespace before substring matching so "mac os" and "macos" both hit.
    let os_norm: String = os
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let os_type = if os_norm.contains("windows") {
        "windows"
    } else if os_norm.contains("darwin")
        || os_norm.contains("macos")
        || os_norm.contains("osx")
        || os_norm.contains("apple")
    {
        "macos"
    } else if os_norm.contains("freebsd") {
        "freebsd"
    } else {
        "linux"
    };
    format!("{}-{}", arch, os_type)
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: platform_from_filename
// Extracts the platform string from a filename such as:
//   scmclient-x86_64-linux         →  "x86_64-linux"
//   scmclient-aarch64-linux        →  "aarch64-linux"
//   scmclient-x86_64-windows.exe   →  "x86_64-windows"
// Returns None if the name does not match the expected pattern.
// ─────────────────────────────────────────────────────────────────────────────
fn platform_from_filename(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".exe").unwrap_or(name);
    let platform = stem.strip_prefix("scmclient-")?;
    if platform.is_empty() {
        return None;
    }
    Some(platform.to_string())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: version_from_binary
// Reads an agent's version out of the binary itself.
//
// The client embeds `<<OPENSCM_AGENT_VERSION:x.y.z>>` as a contiguous, linker-
// retained byte string (see scmclient/src/main.rs). Finding it is a plain byte
// scan with no executable-format parsing, so one implementation covers Mach-O,
// ELF — little and big endian — and PE alike. Verified on macOS aarch64, Linux
// x86_64/aarch64/riscv64 musl, s390x gnu and Windows x86_64.
//
// This makes the advertised version an OBSERVATION of the payload rather than
// an assertion about it, which is what the whole upgrade path depends on: a
// version that does not match its binary produces upgrades that apply cleanly,
// report success, and change nothing, forever.
// ─────────────────────────────────────────────────────────────────────────────
fn version_from_binary(bytes: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"<<OPENSCM_AGENT_VERSION:";
    const SUFFIX: &[u8] = b">>";
    const MAX_LEN: usize = 32; // "255.255.255-something" and then some

    let start = bytes
        .windows(PREFIX.len())
        .position(|w| w == PREFIX)?
        + PREFIX.len();
    let tail = &bytes[start..bytes.len().min(start + MAX_LEN)];
    let end = tail.windows(SUFFIX.len()).position(|w| w == SUFFIX)?;
    let v = std::str::from_utf8(&tail[..end]).ok()?.trim();
    if v.is_empty() { None } else { Some(v.to_string()) }
}

// ─────────────────────────────────────────────────────────────────────────────
// startup_scan
// Walks the embedded `static/agents/` directory and upserts agent_packages
// for every recognised client binary found there.
//
// The advertised version comes from the `VERSION` file the CI workflow bundles
// alongside the binaries — NOT from the server's own version.
//
// This used to stamp env!("CARGO_PKG_VERSION"), i.e. whatever the SERVER was
// built as. When server and bundled agent are built from the same tag those
// agree and the bug is invisible, which is why it survived so long. When they
// diverge — a stale bundle, a hand-placed binary, a dev build — the server
// advertises an upgrade to a version the payload does not contain. The agent
// then does everything right: downloads, verifies the SHA, replaces itself,
// restarts... and reports the SAME version it had before, so the server offers
// the upgrade again, forever, with no error anywhere. Every log line says
// success.
//
// Reading the version from the payload's own metadata makes the advertised
// version an observation rather than an assumption.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn startup_scan(pool: &SqlitePool) {
    let agents_dir = match STATIC_FILES_DIR.get_dir("agents") {
        Some(d) => d,
        None => {
            // Dev builds typically don't bundle client binaries; the directory
            // is absent or empty and the upgrade feature is simply unavailable.
            info!("No bundled agents directory — upgrade packages unavailable.");
            return;
        }
    };

    // Falls back to the server's version only if the bundle predates the
    // VERSION file, and says so loudly — that fallback is the broken behaviour.
    let version: String = match agents_dir.get_file("agents/VERSION") {
        Some(f) => match std::str::from_utf8(f.contents()) {
            Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => {
                warn!("agents/VERSION is unreadable — falling back to the server version.");
                env!("CARGO_PKG_VERSION").to_string()
            }
        },
        None => {
            warn!(
                "Bundled agents have no VERSION file — advertising the server version ({}). \
                 If the bundled agents are not that version, upgrades will appear to succeed \
                 and never take effect.",
                env!("CARGO_PKG_VERSION")
            );
            env!("CARGO_PKG_VERSION").to_string()
        }
    };

    let mut count: u32 = 0;

    for file in agents_dir.files() {
        // file.path() returns "agents/scmclient-x86_64-linux" — we want the
        // bare filename.
        let name = match file.path().file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        let platform = match platform_from_filename(name) {
            Some(p) => p,
            None => continue, // VERSION file and anything else
        };

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(file.contents());
            format!("{:x}", hasher.finalize())
        };

        // Relative URL — served by the catch-all route which forwards to
        // STATIC_FILES_DIR.get_file("agents/<name>"). The client prepends the
        // server base URL before fetching.
        let url = format!("/agents/{}", name);

        // Prefer what the binary says about itself; fall back to the bundle's
        // VERSION file, then to the server's version (the historically broken
        // behaviour, kept only so older bundles still function).
        let file_version = version_from_binary(file.contents()).unwrap_or_else(|| {
            warn!(
                "{} carries no embedded version marker — falling back to {}. \
                 If that is not this binary's real version, upgrades to it will \
                 apply cleanly and never take effect.",
                name, version
            );
            version.clone()
        });

        match sqlx::query(
            "INSERT INTO agent_packages (platform, version, sha256, url, updated_at)
             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(platform) DO UPDATE SET
               version    = excluded.version,
               sha256     = excluded.sha256,
               url        = excluded.url,
               updated_at = excluded.updated_at",
        )
        .bind(&platform)
        .bind(&file_version)
        .bind(&sha256)
        .bind(&url)
        .execute(pool)
        .await
        {
            Ok(_) => {
                info!(
                    "Agent package registered: {} v{} sha256={}…",
                    platform,
                    version,
                    &sha256[..12]
                );
                count += 1;
            }
            Err(e) => error!("Failed to upsert agent_packages for {}: {}", platform, e),
        }
    }

    if count > 0 {
        info!(
            "Agent scan complete: {} platform(s) registered at v{}.",
            count, version
        );
    }
}
