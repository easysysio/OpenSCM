// =============================================================================
// containers.rs — host-side container discovery (Linux only)
//
// Detects locally-installed app-container runtimes (Docker, Podman in 0.5.0)
// and enumerates their containers with enough metadata to:
//   1. Ship in the heartbeat payload so the server can render the inventory
//      UI (Systems-list expand chevron + container detail modal).
//   2. Be passed back to compliance::evaluate() when running per-container
//      tests (IMAGE / NETWORK), one evaluate() call per container.
// Designed to be cheap enough to run on every heartbeat tick:
//
//   - Runtime detection is a single `which`-style check
//   - `ps` is one shell-out per runtime
//   - `inspect` is one shell-out per container but only requests the JSON
//     blob the engine already keeps in memory — fast
//
// All operations soft-fail: if a runtime isn't installed, or the agent doesn't
// have permission (rootless / no docker group), we silently skip that runtime
// and the heartbeat continues. Never let container discovery break the agent.
//
// On non-Linux platforms `enumerate()` returns an empty Vec without any
// shell-outs — Docker / Podman on Windows and macOS run in a hidden Linux VM
// the host agent can't reach, and our LXC/LXD policy is "install the agent
// inside the OS container" (design doc §2).
// =============================================================================

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use tracing::debug;

/// One discovered container, ready to ship in the heartbeat payload.
/// Mirrors the columns of the `containers` table 1-to-1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredContainer {
    pub runtime:         String,              // "docker" | "podman"
    pub runtime_id:      String,
    pub name:            String,
    pub image:           Option<String>,
    pub image_digest:    Option<String>,
    pub status:          Option<String>,
    pub ip:              Option<String>,
    pub is_privileged:   Option<bool>,
    pub run_user:        Option<String>,
    pub network_mode:    Option<String>,
    /// Stored as a JSON-encoded string for compact transit + cheap server-side storage.
    pub exposed_ports:   Option<String>,
    pub mounts:          Option<String>,
    pub capabilities_add: Option<String>,
    pub read_only_fs:    Option<bool>,
    pub restart_policy:  Option<String>,
    pub health_check:    Option<bool>,
}

// ============================================================
// Public entry point
// ============================================================

/// Enumerate running containers across every detected runtime.
///
/// Returns:
///   • `None`         — no signal: non-Linux, no runtime installed, or every
///                      installed runtime's `ps` failed (daemon down / no
///                      permission). The server leaves existing inventory rows
///                      untouched, so a transient daemon outage never wipes the
///                      inventory.
///   • `Some(vec)`    — authoritative current set from at least one runtime
///                      whose `ps` succeeded. May be EMPTY, which means "this
///                      host has a working runtime with zero running
///                      containers" → the server prunes all of the host's rows.
///
/// This distinction is what makes "stop the last container → it disappears from
/// inventory" work: empty-but-known (Some([])) must be sent, not None.
pub fn enumerate() -> Option<Vec<DiscoveredContainer>> {
    #[cfg(not(target_os = "linux"))]
    {
        None
    }

    #[cfg(target_os = "linux")]
    {
        let mut any_ok = false;
        let mut out = Vec::new();
        for runtime in ["docker", "podman"] {
            if detect(runtime) {
                // ps succeeded (even with zero rows) → authoritative; a failed
                // ps (daemon down) yields None and is skipped so we don't
                // falsely report "no containers".
                if let Some(found) = enumerate_runtime(runtime) {
                    any_ok = true;
                    out.extend(found);
                }
            }
        }
        if any_ok {
            debug!("Discovered {} running container(s)", out.len());
            Some(out)
        } else {
            None
        }
    }
}

// ============================================================
// Internals
// ============================================================

#[cfg(target_os = "linux")]
fn detect(runtime: &str) -> bool {
    // `<runtime> --version` exits 0 iff the CLI is on PATH and at least
    // partially usable. Doesn't prove the daemon is reachable / we have
    // permission — `ps` below will fail soft if not.
    Command::new(runtime)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
// Returns None when the `ps` command itself fails (daemon unreachable, no
// permission, spawn error) — the caller must NOT treat that as "zero
// containers", or a transient daemon outage would wipe the inventory. Returns
// Some(vec) (possibly empty) when `ps` succeeded: that's an authoritative
// "these are the running containers right now".
fn enumerate_runtime(runtime: &str) -> Option<Vec<DiscoveredContainer>> {
    // `ps` (NOT `ps -a`) lists only RUNNING containers (running + paused).
    // We deliberately exclude stopped/exited/created containers: inventory
    // tracks the live set, and dropping a container from the report is how the
    // server prunes it (ingest_containers straggler-delete). Using `-a` here
    // kept exited containers in the report forever, so their last_seen never
    // went stale and they were never removed from the inventory after being
    // stopped. Both Docker and Podman emit NDJSON (one container per line);
    // for Podman this is compatibility-mode output, for Docker it's native.
    let out = match Command::new(runtime)
        .args(["ps", "--format", "{{json .}}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            debug!("{} ps failed (rc={:?}): {}", runtime, o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim());
            return None;
        }
        Err(e) => {
            debug!("{} ps spawn failed: {}", runtime, e);
            return None;
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut containers = Vec::new();

    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                debug!("{} ps row parse failed: {}", runtime, e);
                continue;
            }
        };

        // Field names from `docker ps --format json`:
        //   ID, Names, Image, Status, ...
        // Podman uses the same names in compatibility mode.
        let id = row.get("ID").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if id.is_empty() { continue; }

        let name = row.get("Names").and_then(|v| v.as_str())
            // `docker ps` returns "name1,name2"; we take the first.
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .unwrap_or_else(|| id.clone());

        let image  = row.get("Image").and_then(|v| v.as_str()).map(String::from);
        let status = row.get("Status").and_then(|v| v.as_str()).map(String::from);

        let mut c = DiscoveredContainer {
            runtime: runtime.to_string(),
            runtime_id: id.clone(),
            name,
            image,
            image_digest: None,
            status,
            ip: None,
            is_privileged: None,
            run_user: None,
            network_mode: None,
            exposed_ports: None,
            mounts: None,
            capabilities_add: None,
            read_only_fs: None,
            restart_policy: None,
            health_check: None,
        };

        enrich(runtime, &id, &mut c);
        containers.push(c);
    }

    Some(containers)
}

/// Pulls the detailed metadata via `<runtime> inspect <id>`. Soft-fails —
/// the container still gets reported with whatever we already had from `ps`.
#[cfg(target_os = "linux")]
fn enrich(runtime: &str, id: &str, c: &mut DiscoveredContainer) {
    let out = match Command::new(runtime).args(["inspect", id]).output() {
        Ok(o) if o.status.success() => o,
        _ => return,
    };

    // `inspect` returns a JSON array with exactly one element.
    let parsed: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => return,
    };
    let root = parsed.get(0).unwrap_or(&Value::Null);
    if root.is_null() { return; }

    // Image digest — Docker stores it under "Image" as "sha256:..."
    c.image_digest = root.get("Image").and_then(|v| v.as_str()).map(String::from);

    // IPv4 address. Prefer NetworkSettings.IPAddress (legacy default-bridge);
    // fall back to the first network's IPAddress under NetworkSettings.Networks.
    if let Some(ns) = root.get("NetworkSettings") {
        let primary = ns.get("IPAddress").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        c.ip = primary.map(String::from)
            .or_else(|| ns.get("Networks").and_then(Value::as_object).and_then(|nets| {
                nets.values().find_map(|n| n.get("IPAddress").and_then(|v| v.as_str()))
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            }));

        // Exposed/published ports — collect "port/proto" strings.
        if let Some(ports) = ns.get("Ports").and_then(Value::as_object) {
            let list: Vec<String> = ports.keys().cloned().collect();
            if !list.is_empty() {
                c.exposed_ports = serde_json::to_string(&list).ok();
            }
        }
    }

    if let Some(hc) = root.get("HostConfig") {
        c.is_privileged   = hc.get("Privileged").and_then(Value::as_bool);
        c.network_mode    = hc.get("NetworkMode").and_then(|v| v.as_str()).map(String::from);
        c.read_only_fs    = hc.get("ReadonlyRootfs").and_then(Value::as_bool);
        c.restart_policy  = hc.get("RestartPolicy").and_then(|rp| rp.get("Name"))
                              .and_then(|v| v.as_str()).map(String::from);

        if let Some(caps) = hc.get("CapAdd").and_then(Value::as_array)
            && !caps.is_empty()
        {
            let list: Vec<String> = caps.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            c.capabilities_add = serde_json::to_string(&list).ok();
        }

        // Mounts — prefer the structured Mounts array, fall back to legacy Binds.
        if let Some(mounts) = root.get("Mounts").and_then(Value::as_array) {
            let list: Vec<serde_json::Value> = mounts.iter().map(|m| {
                serde_json::json!({
                    "src":  m.get("Source").and_then(|v| v.as_str()).unwrap_or(""),
                    "dst":  m.get("Destination").and_then(|v| v.as_str()).unwrap_or(""),
                    "type": m.get("Type").and_then(|v| v.as_str()).unwrap_or(""),
                    "ro":   !m.get("RW").and_then(Value::as_bool).unwrap_or(true),
                })
            }).collect();
            if !list.is_empty() {
                c.mounts = serde_json::to_string(&list).ok();
            }
        }
    }

    if let Some(cfg) = root.get("Config") {
        // Config.User is "" when the Dockerfile has no explicit USER
        // directive — which means the container runs as the image's
        // built-in default user. In practice that's almost always
        // root (uid 0). Reporting empty as "root" makes
        // `RUN_USER CONTAINS root` checks actually flag the case the
        // test author expects, rather than returning NA for every
        // unconfigured container.
        c.run_user = Some(
            cfg.get("User").and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| "root".to_string())
        );
        c.health_check = Some(cfg.get("Healthcheck").is_some());
    }
}
