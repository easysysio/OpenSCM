use tracing::{debug, error, warn};
use std::path::Path;
use std::fs;
use semver::Version;
use sysinfo::System;
use std::process::Command;
use std::net::TcpStream;
use std::io::{BufRead, BufReader};


// ============================================================
// EVAL RESULT
// ============================================================

#[derive(Debug, PartialEq)]
pub enum EvalResult {
    Pass,
    Fail,
    Na,
}

// Tiny sugar — `boolean(check())` reads better than the same if/else everywhere.
#[inline]
fn boolean(passed: bool) -> EvalResult {
    if passed { EvalResult::Pass } else { EvalResult::Fail }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared file/directory metadata checks. Both `file/owner|group|permission`
// and `directory/owner|group|permission` route through these helpers.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn check_path_owner(path: &str, sinput: &str) -> EvalResult {
    use std::os::unix::fs::MetadataExt;
    let uid = match fs::metadata(path) {
        Ok(m)  => m.uid(),
        Err(_) => return EvalResult::Fail,
    };
    let name_matches = get_user_name_from_uid(uid)
        .map(|n| n == sinput)
        .unwrap_or(false);
    boolean(name_matches || uid.to_string() == sinput)
}

#[cfg(not(unix))]
fn check_path_owner(_path: &str, _sinput: &str) -> EvalResult { EvalResult::Na }

#[cfg(unix)]
fn check_path_group(path: &str, condition: &str, sinput: &str) -> EvalResult {
    use std::os::unix::fs::MetadataExt;
    let gid = match fs::metadata(path) {
        Ok(m)  => m.gid(),
        Err(_) => return EvalResult::Fail,
    };
    let name = get_group_name_from_gid(gid).unwrap_or_default();
    boolean(
        apply_string_condition(&name, condition, sinput) ||
        apply_string_condition(&gid.to_string(), condition, sinput)
    )
}

#[cfg(not(unix))]
fn check_path_group(_p: &str, _c: &str, _s: &str) -> EvalResult { EvalResult::Na }

#[cfg(unix)]
fn check_path_permission(path: &str, condition: &str, sinput: &str) -> EvalResult {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    let expected = u32::from_str_radix(sinput, 8).unwrap_or(0);
    let passed = match condition.trim().to_lowercase().as_str() {
        "equal" | "equals" => mode == expected,
        "more than"        => mode >= expected,
        "less than"        => mode <= expected,
        _                  => false,
    };
    boolean(passed)
}

#[cfg(not(unix))]
fn check_path_permission(_p: &str, _c: &str, _s: &str) -> EvalResult { EvalResult::Na }


// ============================================================
// HELPERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: service_is_active / service_is_enabled
// Cross-platform query of a managed service's runtime / boot state.
// Returns Some(true|false) when the state is determined, None when we can't
// figure it out (no init system available, command missing, parse failure).
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// Helper: systemd_unit_state (Linux only)
// Returns both ActiveState and UnitFileState in a single `systemctl show`
// invocation, cached briefly (300 ms TTL) so a SERVICE.ACTIVE test followed
// by SERVICE.ENABLED on the same unit costs one shell-out instead of two.
// The short TTL keeps cross-scan freshness intact while still amortizing
// the common case of two checks in the same test.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct SystemdUnit { active: bool, enabled: bool }

#[cfg(target_os = "linux")]
fn systemd_unit_state(name: &str) -> Option<SystemdUnit> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static CACHE: Mutex<Option<(Instant, HashMap<String, SystemdUnit>)>> = Mutex::new(None);
    const TTL: Duration = Duration::from_millis(300);

    let mut guard = CACHE.lock().ok()?;
    let now = Instant::now();

    // Reuse cached result if still fresh and the unit is present.
    if let Some((cached_at, map)) = guard.as_ref() {
        if now.duration_since(*cached_at) < TTL {
            if let Some(s) = map.get(name) {
                return Some(*s);
            }
        }
    }

    let out = Command::new("systemctl")
        .args(["show", name, "-p", "ActiveState", "-p", "UnitFileState"])
        .output().ok()?;
    let txt = String::from_utf8_lossy(&out.stdout);

    let mut active_state  = "";
    let mut unit_file_state = "";
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix("ActiveState=")   { active_state    = v; }
        if let Some(v) = line.strip_prefix("UnitFileState=") { unit_file_state = v; }
    }

    let state = SystemdUnit {
        active:  active_state.eq_ignore_ascii_case("active"),
        enabled: matches!(unit_file_state.to_lowercase().as_str(),
                          "enabled" | "alias" | "enabled-runtime"),
    };

    // Refresh the cache; if we'd just exceeded the TTL, drop the old map.
    match guard.as_mut() {
        Some((cached_at, map)) if now.duration_since(*cached_at) < TTL => {
            map.insert(name.to_string(), state);
        }
        _ => {
            let mut new_map = HashMap::new();
            new_map.insert(name.to_string(), state);
            *guard = Some((now, new_map));
        }
    }

    Some(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: image_part — parse a Docker-style image reference into
//   reference  := [SOURCE/]NAME[:TAG][@DIGEST]
//   SOURCE     := registry host  (default "docker.io" when no '/' before name)
//   NAME       := optional namespace + repo (e.g. "library/nginx")
//   TAG        := tag after ':'  (default "latest" when absent)
// First path component is SOURCE only if it contains '.' or ':' or is
// "localhost" — matches standard Docker reference parsing rules.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Clone, Copy)]
enum ImagePart { Source, Name, Tag }

fn image_part(reference: &str, part: ImagePart) -> String {
    let no_digest = reference.split('@').next().unwrap_or(reference);

    let (source, rest) = match no_digest.split_once('/') {
        Some((head, rest)) if head.contains('.') || head.contains(':') || head == "localhost" => {
            (head.to_string(), rest.to_string())
        }
        _ => ("docker.io".to_string(), no_digest.to_string()),
    };

    let (name, tag) = match rest.rsplit_once(':') {
        Some((n, t)) if !t.contains('/') => (n.to_string(), t.to_string()),
        _ => (rest, "latest".to_string()),
    };

    match part {
        ImagePart::Source => source,
        ImagePart::Name   => name,
        ImagePart::Tag    => tag,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: bool_selement
// Apply an EXISTS / NOT EXISTS selement to a boolean flag (e.g. is_privileged,
// read_only_fs, health_check). Centralises the truth-table so every per-
// container boolean element has identical semantics.
// ─────────────────────────────────────────────────────────────────────────────
fn bool_selement(selement_l: &str, flag: bool, raw_selement: &str) -> EvalResult {
    match selement_l {
        "exists"     => if flag  { EvalResult::Pass } else { EvalResult::Fail },
        "not exists" => if !flag { EvalResult::Pass } else { EvalResult::Fail },
        _ => {
            error!("Unsupported boolean selement: '{}'. Use 'exists' or 'not exists'.", raw_selement);
            EvalResult::Na
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: container_mount_matches
// Returns true iff any bind mount on the container has a `src` containing the
// caller-supplied path substring. The mounts field is a JSON array of
// {src, dst, type, ro} objects produced at discovery time by containers.rs.
// Path-style match is case-sensitive (Linux paths are).
// ─────────────────────────────────────────────────────────────────────────────
fn container_mount_matches(c: &crate::containers::DiscoveredContainer, needle: &str) -> bool {
    let needle = needle.trim();
    if needle.is_empty() { return false; }
    let mounts_json = match c.mounts.as_deref() { Some(s) => s, None => return false };
    let arr: serde_json::Value = match serde_json::from_str(mounts_json) {
        Ok(v) => v, Err(_) => return false,
    };
    arr.as_array().map(|items| {
        items.iter().any(|m| {
            m.get("src").and_then(|v| v.as_str())
                .map(|src| src.contains(needle))
                .unwrap_or(false)
        })
    }).unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: container_exposed_ports
// Returns the list of "port/proto" strings published by the container
// (parsed from the cached exposed_ports JSON array). Empty list if the
// container had no ports published or the JSON was malformed.
// ─────────────────────────────────────────────────────────────────────────────
fn container_exposed_ports(c: &crate::containers::DiscoveredContainer) -> Vec<String> {
    let json = match c.exposed_ports.as_deref() { Some(s) => s, None => return Vec::new() };
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v, Err(_) => return Vec::new(),
    };
    parsed.as_array().map(|items| {
        items.iter().filter_map(|v| v.as_str().map(String::from)).collect()
    }).unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: container_runtime_present
// True iff either the `docker` or `podman` CLI is callable on $PATH —
// `--version` is the cheapest possible probe (no daemon connection, no
// container enumeration). Used by the CONTAINER EXISTS / NOT EXISTS test
// element. Works on any platform; on Windows/macOS hosts with Docker
// Desktop running, the CLI is on PATH and this returns true.
// ─────────────────────────────────────────────────────────────────────────────
fn container_runtime_present() -> bool {
    let probe = |bin: &str| -> bool {
        Command::new(bin).arg("--version").output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    probe("docker") || probe("podman")
}

fn service_is_active(name: &str) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // One `systemctl show -p ActiveState -p UnitFileState` call returns
        // both bits we need; we cache it briefly so a SERVICE.ACTIVE test
        // immediately followed by SERVICE.ENABLED on the same unit costs
        // exactly one shell-out, not two.
        return systemd_unit_state(name).map(|s| s.active);
    }
    #[cfg(target_os = "macos")]
    {
        // launchctl print system/<name> — running services include a "state = running" line.
        let out = Command::new("launchctl")
            .args(["print", &format!("system/{}", name)])
            .output().ok()?;
        if !out.status.success() { return Some(false); }
        let txt = String::from_utf8_lossy(&out.stdout).to_lowercase();
        return Some(txt.contains("state = running"));
    }
    #[cfg(target_os = "windows")]
    {
        // sc query <name> — "STATE : 4 RUNNING" when active.
        let out = Command::new("sc").args(["query", name]).output().ok()?;
        let txt = String::from_utf8_lossy(&out.stdout).to_uppercase();
        return Some(txt.contains("RUNNING"));
    }
    #[cfg(target_os = "freebsd")]
    {
        // service <name> status — exit 0 if running.
        let out = Command::new("service").args([name, "status"]).output().ok()?;
        return Some(out.status.success());
    }
    #[allow(unreachable_code)]
    None
}

fn service_is_enabled(name: &str) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // Reuses the cached `systemctl show` result from service_is_active.
        return systemd_unit_state(name).map(|s| s.enabled);
    }
    #[cfg(target_os = "macos")]
    {
        // launchctl print system/<name> — when present and not in disabled list,
        // launchd will load it at boot. Disabled jobs are tracked separately.
        let out = Command::new("launchctl")
            .args(["print-disabled", "system"])
            .output().ok()?;
        let txt = String::from_utf8_lossy(&out.stdout);
        let needle = format!("\"{}\" => disabled", name);
        return Some(!txt.contains(&needle));
    }
    #[cfg(target_os = "windows")]
    {
        // sc qc <name> — "START_TYPE : 2 AUTO_START" means enabled at boot.
        let out = Command::new("sc").args(["qc", name]).output().ok()?;
        let txt = String::from_utf8_lossy(&out.stdout).to_uppercase();
        return Some(txt.contains("AUTO_START"));
    }
    #[cfg(target_os = "freebsd")]
    {
        // sysrc -n <name>_enable — returns "YES" / "NO".
        let out = Command::new("sysrc").args(["-n", &format!("{}_enable", name)]).output().ok()?;
        let txt = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
        return Some(txt == "YES");
    }
    #[allow(unreachable_code)]
    None
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: dpkg_lookup
// Parses /var/lib/dpkg/status (RFC822-like format) into an in-memory map of
// package -> {installed, version}. The file is cached and re-parsed only
// when its mtime changes — package state on a typical system is stable for
// hours, so subsequent PACKAGE tests in the same scan run amortize to ~0.
// Native read is ~10x faster than spawning dpkg-query for the first call
// and effectively free for every call after.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(all(unix, not(target_os = "macos")))]
#[derive(Clone)]
pub(crate) struct DpkgEntry {
    pub installed: bool,
    pub version:   String,
}

#[cfg(all(unix, not(target_os = "macos")))]
fn dpkg_lookup(package: &str) -> Option<DpkgEntry> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::SystemTime;

    static CACHE: Mutex<Option<(SystemTime, HashMap<String, DpkgEntry>)>> =
        Mutex::new(None);

    const DPKG_STATUS: &str = "/var/lib/dpkg/status";

    let mtime = fs::metadata(DPKG_STATUS).ok()?.modified().ok()?;

    let mut guard = CACHE.lock().ok()?;

    let needs_refresh = match guard.as_ref() {
        Some((cached_mtime, _)) => *cached_mtime != mtime,
        None => true,
    };

    if needs_refresh {
        let contents = fs::read_to_string(DPKG_STATUS).ok()?;
        let mut map: HashMap<String, DpkgEntry> = HashMap::new();
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut installed = false;
        for raw in contents.lines().chain(std::iter::once("")) {
            if raw.is_empty() {
                // Blank line terminates a stanza.
                if let (Some(n), Some(v)) = (name.take(), version.take()) {
                    map.insert(n, DpkgEntry { installed, version: v });
                }
                installed = false;
                continue;
            }
            if let Some(rest) = raw.strip_prefix("Package: ") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = raw.strip_prefix("Version: ") {
                version = Some(rest.trim().to_string());
            } else if let Some(rest) = raw.strip_prefix("Status: ") {
                installed = rest.contains("install ok installed");
            }
        }
        *guard = Some((mtime, map));
    }

    guard.as_ref().and_then(|(_, m)| m.get(package).cloned())
}

fn parse_to_semver(v: &str) -> Option<Version> {
    let parts: Vec<_> = v.split('.').collect();
    let normalized = match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => v.to_string(),
    };
    Version::parse(&normalized).ok()
}


#[cfg(unix)]
fn get_user_name_from_uid(uid: u32) -> Option<String> {
    uzers::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

#[cfg(unix)]
fn get_group_name_from_gid(gid: u32) -> Option<String> {
    uzers::get_group_by_gid(gid).map(|g| g.name().to_string_lossy().into_owned())
}


fn check_user_exists(user: &str) -> bool {
    let users = sysinfo::Users::new_with_refreshed_list();
    users.iter().any(|u| u.name() == user)
}


#[cfg(unix)]
fn check_group_exists(group: &str) -> bool {
    uzers::get_group_by_name(group).is_some()
}

#[cfg(windows)]
fn check_group_exists(group: &str) -> bool {
    Command::new("net")
        .args(["localgroup", group])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}


#[cfg(unix)]
fn is_user_in_group(user: &str, group: &str) -> bool {
    let output = Command::new("id")
        .args(["-Gn", user])
        .output()
        .ok();
    output
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == group)
        })
        .unwrap_or(false)
}


fn check_port_open(port: &str) -> bool {
    let addr_str = format!("127.0.0.1:{}", port);
    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => {
            warn!("Invalid port value: '{}'", port);
            return false;
        }
    };
    TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)).is_ok()
}


#[cfg(target_os = "macos")]
fn check_package_exists(package: &str) -> bool {
    use std::process::Stdio;

    // Try Homebrew formula
    let brew_formula = Command::new("brew")
        .args(["list", "--formula", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if brew_formula { return true; }

    // Try Homebrew cask
    let brew_cask = Command::new("brew")
        .args(["list", "--cask", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if brew_cask { return true; }

    // Try native macOS pkgutil — scan the full package list for a match
    if let Ok(output) = Command::new("pkgutil").args(["--pkgs"]).output() {
        let list = String::from_utf8_lossy(&output.stdout);
        if list.lines().any(|line| line == package || line.contains(package)) {
            return true;
        }
    }

    false
}

#[cfg(all(unix, not(target_os = "macos")))]
fn check_package_exists(package: &str) -> bool {
    use std::process::Stdio;

    // Debian/Ubuntu — native /var/lib/dpkg/status parse (with mtime cache).
    // Avoids forking dpkg-query for every PACKAGE test.
    if let Some(info) = dpkg_lookup(package) {
        if info.installed { return true; }
    }

    // RHEL/Fedora/openSUSE — rpm. Native RPM DB parsing is a follow-up
    // (the DB format varies across distro versions); shell-out for now.
    let rpm = Command::new("rpm")
        .args(["-q", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if rpm { return true; }

    // Arch — pacman. Native /var/lib/pacman/local parsing is also a follow-up.
    Command::new("pacman")
        .args(["-Q", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn check_package_exists(package: &str) -> bool {
    win_installed_packages()
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(package)
            || name.to_lowercase().contains(&package.to_lowercase()))
}



#[cfg(target_os = "macos")]
fn get_package_version(package: &str) -> Option<String> {
    // Try Homebrew formula
    let output = Command::new("brew")
        .args(["list", "--formula", "--versions", package])
        .output()
        .ok();

    if let Some(o) = output {
        if o.status.success() {
            // "brew list --versions <pkg>" returns "package version" e.g. "nginx 1.25.3"
            let out = String::from_utf8_lossy(&o.stdout);
            if let Some(ver) = out.split_whitespace().nth(1) {
                return Some(ver.to_string());
            }
        }
    }

    // Try Homebrew cask
    let output_cask = Command::new("brew")
        .args(["list", "--cask", "--versions", package])
        .output()
        .ok();

    if let Some(o) = output_cask {
        if o.status.success() {
            let out = String::from_utf8_lossy(&o.stdout);
            if let Some(ver) = out.split_whitespace().nth(1) {
                return Some(ver.to_string());
            }
        }
    }

    // Try pkgutil — find matching package ID then fetch its version
    if let Ok(list_output) = Command::new("pkgutil").args(["--pkgs"]).output() {
        let list = String::from_utf8_lossy(&list_output.stdout);
        if let Some(pkg_id) = list.lines().find(|l| *l == package || l.contains(package)) {
            if let Ok(info) = Command::new("pkgutil").args(["--pkg-info", pkg_id]).output() {
                let info_str = String::from_utf8_lossy(&info.stdout);
                for line in info_str.lines() {
                    if let Some(ver) = line.strip_prefix("version: ") {
                        return Some(ver.trim().to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_package_version(package: &str) -> Option<String> {
    // Debian/Ubuntu — native dpkg status parse (with mtime cache).
    if let Some(info) = dpkg_lookup(package) {
        if info.installed {
            // Strip the epoch prefix "1:" if present (matches dpkg-query semantics).
            let v = info.version.split(':').last().unwrap_or(&info.version).to_string();
            return Some(v);
        }
    }

    // Try rpm (RHEL/Fedora/openSUSE — zypper uses rpm under the hood)
    let output_rpm = Command::new("rpm")
        .args(["-q", "--queryformat", "%{VERSION}", package])
        .output()
        .ok();

    if let Some(o) = output_rpm {
        if o.status.success() {
            return Some(String::from_utf8_lossy(&o.stdout).trim().to_string());
        }
    }

    // Try pacman (Arch Linux)
    let output_pacman = Command::new("pacman")
        .args(["-Q", package])
        .output()
        .ok();

    if let Some(o) = output_pacman {
        if o.status.success() {
            // pacman -Q returns "package version" e.g. "nginx 1.24.0-1"
            let out = String::from_utf8_lossy(&o.stdout);
            if let Some(ver) = out.split_whitespace().nth(1) {
                return Some(ver.to_string());
            }
        }
    }

    None
}


#[cfg(windows)]
fn get_package_version(package: &str) -> Option<String> {
    win_installed_packages()
        .into_iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(package)
            || name.to_lowercase().contains(&package.to_lowercase()))
        .and_then(|(_, ver)| ver)
}

#[cfg(windows)]
/// Walks the two standard "Uninstall" registry keys (64-bit + 32-bit views)
/// and returns every installed product as (DisplayName, DisplayVersion).
/// Native registry reads are ~150x faster than spawning powershell.exe.
fn win_installed_packages() -> Vec<(String, Option<String>)> {
    use winreg::enums::*;
    use winreg::RegKey;

    const UNINSTALL_PATHS: &[&str] = &[
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut out: Vec<(String, Option<String>)> = Vec::new();

    for base in UNINSTALL_PATHS {
        let key = match hklm.open_subkey(base) {
            Ok(k) => k,
            Err(_) => continue,
        };
        for sub_name in key.enum_keys().flatten() {
            if let Ok(sub) = key.open_subkey(&sub_name) {
                let name: Option<String> = sub.get_value("DisplayName").ok();
                if let Some(n) = name {
                    let v: Option<String> = sub.get_value("DisplayVersion").ok();
                    out.push((n, v));
                }
            }
        }
    }
    out
}


#[cfg(unix)]
fn get_system_domain() -> Option<String> {
    dns_lookup::get_hostname().ok().and_then(|h| {
        if h.contains('.') {
            h.splitn(2, '.').nth(1).map(|s| s.to_string())
        } else {
            None
        }
    })
}

#[cfg(windows)]
fn get_system_domain() -> Option<String> {
    let host = dns_lookup::get_hostname().ok()?;
    // getaddrinfo yields an iterator of Result<AddrInfo, _>; both layers can
    // fail. Use `.ok()?` on each rather than `.unwrap()` to keep the function
    // panic-free when DNS misbehaves.
    let addr_info = dns_lookup::getaddrinfo(Some(&host), None, None).ok()?.next()?.ok()?;
    let fqdn = addr_info.canonname?;
    fqdn.splitn(2, '.').nth(1).map(|s| s.to_string())
}


fn check_file_content(path: &str, condition: &str, expected: &str) -> bool {
    // Guard: file does not exist — not an error, just no match
    if !Path::new(path).exists() {
        debug!("File '{}' does not exist — content check returns false.", path);
        return false;
    }

    // Guard: reject directories
    if Path::new(path).is_dir() {
        // Search all files in directory for the content
        let dir = match fs::read_dir(path) {
            Ok(d) => d,
            Err(e) => {
                error!("Could not read directory {}: {}", path, e);
                return false;
            }
        };
        for entry in dir.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                // Skip entries whose paths are not valid UTF-8; passing an
                // empty string to check_file_content would silently open ""
                // (which fails) rather than skipping the entry cleanly.
                if let Some(path_str) = path.to_str() {
                    if check_file_content(path_str, condition, expected) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            error!("Could not open file {}: {}", path, e);
            return false;
        }
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(content) = line {
            if apply_string_condition(&content, condition, expected) {
                return true;
            }
        }
    }
    false
}



// Generic streaming file hash. Used for both SHA1 and SHA256 by binding the
// type parameter at the call site (`calculate_hash::<Sha1>(...)` etc.).
// Returns the digest as a lowercase hex string.
fn calculate_hash<H: sha2::digest::Digest>(path: &str) -> Result<String, std::io::Error> {
    use std::fs::File;
    use std::io::Read;

    let mut file   = File::open(path)?;
    let mut hasher = H::new();
    let mut buffer = [0u8; 4096];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}


fn apply_string_condition(actual: &str, condition: &str, expected: &str) -> bool {
    match condition.trim().to_lowercase().as_str() {
        "contains"                   => actual.to_lowercase().contains(&expected.to_lowercase()),
        "not contains"               => !actual.to_lowercase().contains(&expected.to_lowercase()),
        "equals" | "equal"           => actual.to_lowercase() == expected.to_lowercase(),
        "not equals" | "not equal"   => actual.to_lowercase() != expected.to_lowercase(),
        "regular expression" | "regex" => {
            // M3: The `regex` crate guarantees linear-time matching (no ReDoS).
            // size_limit caps automaton memory; dfa_size_limit caps DFA cache growth.
            match regex::RegexBuilder::new(expected)
                .multi_line(true)
                .size_limit(1_000_000)
                .dfa_size_limit(500_000)
                .build()
            {
                Ok(re) => re.is_match(actual),
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", expected, e);
                    false
                }
            }
        }
        _ => {
            error!("Unknown string condition: '{}'", condition);
            false
        }
    }
}


fn apply_version_condition(actual_str: &str, condition: &str, target_str: &str) -> bool {
    let actual = parse_to_semver(actual_str);
    let target = parse_to_semver(target_str);

    if let (Some(a), Some(t)) = (actual, target) {
        match condition.trim().to_lowercase().as_str() {
            "equal" | "equals" | "==" => a == t,
            "not equal" | "not equals" | "!=" => a != t,
            "more than" | "greater than" | ">" => a > t,
            "less than" | "<" => a < t,
            _ => {
                error!("Unknown version condition: '{}'", condition);
                false
            }
        }
    } else {
        match condition.trim().to_lowercase().as_str() {
            "equal" | "equals" => actual_str == target_str,
            "contains"         => actual_str.contains(target_str),
            _ => false,
        }
    }
}


// ============================================================
// MAIN EVALUATE FUNCTION
// ============================================================

/// Returns true for elements whose conditions are evaluated once per
/// discovered container (yielding one result per container) rather than
/// once per host. The agent's dispatch loop uses this to decide whether
/// to iterate the container inventory for a given test.
pub fn is_per_container_element(name: &str) -> bool {
    matches!(
        name.trim().to_uppercase().as_str(),
        "IMAGE" | "NETWORK" | "PRIVILEGED" | "RUN_USER" | "MOUNT"
            | "EXPOSED_PORT" | "READ_ONLY_FS" | "HEALTH_CHECK" | "EXEC"
    )
}

/// Combine per-condition EvalResults into a test-level verdict string
/// ("PASS" | "FAIL" | "NA") using the test's `filter` field. Same
/// semantics for host tests (one call per test) and per-container tests
/// (one call per container). Shared between agent.rs and runner.rs so
/// both code paths apply identical filter logic.
pub fn combine_verdict(results: &[EvalResult], filter: &str) -> String {
    if results.is_empty() { return "NA".to_string(); }
    match filter {
        "any" => {
            if results.iter().any(|r| *r == EvalResult::Pass) { "PASS".to_string() }
            else if results.iter().all(|r| *r == EvalResult::Na) { "NA".to_string() }
            else { "FAIL".to_string() }
        }
        _ => {
            if results.iter().any(|r| *r == EvalResult::Fail) { "FAIL".to_string() }
            else if results.iter().all(|r| *r == EvalResult::Na) { "NA".to_string() }
            else { "PASS".to_string() }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence — "why did this test (not) pass?"
//
// One ConditionOutcome per evaluated condition. PRIVACY: this carries ONLY the
// admin-authored test spec (element / parameter / sub-element / operator /
// expected value) plus the per-condition verdict and a GENERIC note. It never
// includes host-observed content (file bytes, command output, etc.) — see the
// 0.6.4 evidence design. The note explains the outcome in match-only terms.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(serde::Serialize)]
pub struct ConditionOutcome {
    pub phase:    String,   // "condition" | "applicability"
    pub element:  String,
    pub input:    String,
    pub selement: String,
    pub operator: String,
    pub expected: String,
    pub result:   String,   // "PASS" | "FAIL" | "NA"
    pub note:     String,
}

fn result_str(r: &EvalResult) -> &'static str {
    match r { EvalResult::Pass => "PASS", EvalResult::Fail => "FAIL", EvalResult::Na => "NA" }
}

/// Generic, content-free explanation for one condition outcome. Uses only the
/// operator + admin-authored expected value — never anything observed on the
/// host.
fn condition_note(phase: &str, operator: &str, expected: &str, r: &EvalResult) -> String {
    match r {
        EvalResult::Pass => "matched".to_string(),
        EvalResult::Fail => {
            let op = if operator.trim().is_empty() { "match" } else { operator.trim() };
            if expected.trim().is_empty() {
                format!("did not satisfy '{}'", op)
            } else {
                format!("expected to {} '{}' — not satisfied", op, expected.trim())
            }
        }
        EvalResult::Na => {
            if phase == "applicability" {
                "applicability condition not met".to_string()
            } else {
                "not applicable / not evaluable on this system".to_string()
            }
        }
    }
}

/// Build the evidence JSON for a set of conditions paired 1:1 with their
/// EvalResults. Returns None for an empty set (so the field is omitted).
/// `phase` is "condition" for the test body or "applicability" for the gate.
pub fn build_evidence(
    phase: &str,
    conds: &[&crate::models::TestCondition],
    results: &[EvalResult],
) -> Option<String> {
    if conds.is_empty() || conds.len() != results.len() { return None; }
    let outcomes: Vec<ConditionOutcome> = conds.iter().zip(results.iter()).map(|(c, r)| {
        let operator = c.condition.as_deref().unwrap_or("");
        let expected = c.sinput.as_deref().unwrap_or("");
        ConditionOutcome {
            phase:    phase.to_string(),
            element:  c.element.clone(),
            input:    c.input.clone(),
            selement: c.selement.clone(),
            operator: operator.to_string(),
            expected: expected.to_string(),
            result:   result_str(r).to_string(),
            note:     condition_note(phase, operator, expected, r),
        }
    }).collect();
    serde_json::to_string(&outcomes).ok()
}

pub fn evaluate(
    element: &str,
    input: &str,
    selement: &str,
    condition: &str,
    sinput: &str,
    cmd_enabled: bool,
    ps_enabled:  bool,
    container: Option<&crate::containers::DiscoveredContainer>,
) -> EvalResult {
    let element_l   = element.trim().to_lowercase();
    let selement_l  = selement.trim().to_lowercase();
    let sinput_trim = sinput.trim();

    // Inside a container, only the per-container elements (EXEC + the metadata
    // elements IMAGE, PRIVILEGED, …) have meaning. Anything else (FILE, PACKAGE,
    // CMD, SERVICE, USER, …) has no container semantics → return NA rather than
    // silently evaluating against the host. Use EXEC to run a command inside a
    // container.
    if container.is_some() && !is_per_container_element(element) {
        return EvalResult::Na;
    }

    match element_l.as_str() {

        // =========================================================
        // AGENT
        // =========================================================
        "agent" => match selement_l.as_str() {
            "version" => {
                if apply_version_condition(env!("CARGO_PKG_VERSION"), condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            "content" => {
                if apply_string_condition(env!("CARGO_PKG_VERSION"), condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported agent selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // ARCHITECTURE
        // =========================================================
        "architecture" => match selement_l.as_str() {
            "content" => {
                if apply_string_condition(std::env::consts::ARCH, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported architecture selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // DIRECTORY
        // =========================================================
        "directory" => match selement_l.as_str() {
            "exists"     => if Path::new(input).is_dir() { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !Path::new(input).is_dir() { EvalResult::Pass } else { EvalResult::Fail },
            "content"    => {
                let result = fs::read_dir(input)
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .any(|e| e.file_name() == sinput_trim)
                    })
                    .unwrap_or(false);
                if result { EvalResult::Pass } else { EvalResult::Fail }
            }
            "owner"                       => check_path_owner(input, sinput_trim),
            "group"                       => check_path_group(input, condition, sinput_trim),
            "permission" | "permissions"  => check_path_permission(input, condition, sinput_trim),
            _ => {
                error!("Unsupported directory selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // DOMAIN
        // =========================================================
        "domain" => match selement_l.as_str() {
            "content" => {
                let actual = get_system_domain().unwrap_or_else(|| "local".to_string());
                if apply_string_condition(&actual, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported domain selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // FILE
        // =========================================================
        "file" => match selement_l.as_str() {
            "exists"     => if Path::new(input).is_file() { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !Path::new(input).is_file() { EvalResult::Pass } else { EvalResult::Fail },
            "content"    => {
                if check_file_content(input, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            "owner"                       => check_path_owner(input, sinput_trim),
            "group"                       => check_path_group(input, condition, sinput_trim),
            "permission" | "permissions"  => check_path_permission(input, condition, sinput_trim),
            "sha1" => {
                match calculate_hash::<sha1::Sha1>(input) {
                    Ok(actual_hash) => {
                        let actual   = actual_hash.to_lowercase();
                        let expected = sinput_trim.to_lowercase();
                        debug!("SHA1 Check - File: {} | Actual: {} | Expected: {}", input, actual, expected);
                        if apply_string_condition(&actual, condition, &expected) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        error!("Failed to calculate SHA1 for '{}': {}", input, e);
                        EvalResult::Fail
                    }
                }
            }
            "sha2" | "sha256" => {
                match calculate_hash::<sha2::Sha256>(input) {
                    Ok(actual_hash) => {
                        let actual   = actual_hash.to_lowercase();
                        let expected = sinput_trim.to_lowercase();
                        debug!("SHA256 Check - File: {} | Actual: {} | Expected: {}", input, actual, expected);
                        if apply_string_condition(&actual, condition, &expected) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        error!("Failed to calculate SHA256 for '{}': {}", input, e);
                        EvalResult::Fail
                    }
                }
            }
            _ => {
                error!("Unsupported file selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // GROUP
        // =========================================================
        "group" => match selement_l.as_str() {
            "exists"     => if check_group_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_group_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "content"    => {
                #[cfg(unix)]
                {
                    if is_user_in_group(sinput_trim, input) {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            _ => {
                error!("Unsupported group selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // HOSTNAME
        // =========================================================
        "hostname" => match selement_l.as_str() {
            "content" => {
                let actual = gethostname::gethostname().to_string_lossy().to_string();
                if apply_string_condition(&actual, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported hostname selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // IP
        // =========================================================
        "ip" => match selement_l.as_str() {
            "exists" => {
                match local_ip_address::list_afinet_netifas() {
                    Ok(interfaces) => {
                        if interfaces.iter().any(|(_, ip)| ip.to_string() == input) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        warn!("Failed to list network interfaces: {}", e);
                        EvalResult::Fail
                    }
                }
            }
            "content" => {
                match local_ip_address::list_afinet_netifas() {
                    Ok(interfaces) => {
                        if interfaces.iter().any(|(_, ip)| apply_string_condition(&ip.to_string(), condition, sinput_trim)) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        warn!("Failed to list network interfaces: {}", e);
                        EvalResult::Fail
                    }
                }
            }
            _ => {
                error!("Unsupported ip selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // OS
        // =========================================================
        "os" => match selement_l.as_str() {
            "content" => {
                let actual = os_info::get().os_type().to_string();
                debug!("OS actual value: '{}'", actual);
                if apply_string_condition(&actual, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            "version" => {
                let actual_str = os_info::get().version().to_string();
                if apply_version_condition(&actual_str, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported os selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // PACKAGE
        // =========================================================
        "package" => match selement_l.as_str() {
            "exists"     => if check_package_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_package_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "version"    => {
                match get_package_version(input) {
                    Some(actual_ver) => {
                        if apply_version_condition(&actual_ver, condition, sinput_trim) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    None => {
                        debug!("Package '{}' not installed — version check fails.", input);
                        EvalResult::Fail
                    }
                }
            }
            _ => {
                error!("Unsupported package selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // PORT
        // =========================================================
        "port" => match selement_l.as_str() {
            "exists"     => if check_port_open(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_port_open(input) { EvalResult::Pass } else { EvalResult::Fail },
            _ => {
                error!("Unsupported port selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // PROCESS
        // =========================================================
        "process" => {
            // Only name() and user_id() are read below, so refresh just those.
            // The default refresh_processes() also loads each process's command
            // line, environment, cwd and disk usage — on a container host that
            // means every process in every container, allocated and thrown away
            // for fields nobody looks at.
            let mut sys = System::new();
            sys.refresh_processes_specifics(
                sysinfo::ProcessRefreshKind::new()
                    .with_user(sysinfo::UpdateKind::OnlyIfNotSet),
            );

            let needle = input.to_lowercase();
            let matching: Vec<_> = sys
                .processes()
                .values()
                .filter(|p| p.name().to_lowercase().contains(&needle))
                .collect();
            let is_running = !matching.is_empty();

            match selement_l.as_str() {
                "exists"     => if is_running  { EvalResult::Pass } else { EvalResult::Fail },
                "not exists" => if !is_running { EvalResult::Pass } else { EvalResult::Fail },

                "count" => {
                    let count = matching.len().to_string();
                    debug!("PROCESS '{}' count: {}", input, count);
                    if apply_string_condition(&count, condition, sinput_trim) {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }

                "owner" => {
                    if !is_running {
                        debug!("PROCESS '{}' owner check: process not running", input);
                        return EvalResult::Fail;
                    }
                    // Look up the username for the first matching process.
                    let users = sysinfo::Users::new_with_refreshed_list();
                    let owner = matching.first()
                        .and_then(|p| p.user_id())
                        .and_then(|uid| users.iter().find(|u| u.id() == uid))
                        .map(|u| u.name().to_string())
                        .unwrap_or_default();
                    debug!("PROCESS '{}' owner: '{}'", input, owner);
                    if apply_string_condition(&owner, condition, sinput_trim) {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }

                _ => {
                    error!("Unsupported process selement: '{}'. Use 'exists', 'not exists', 'count', or 'owner'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // SERVICE — cross-platform service state via shell-out.
        // Sub-elements: ACTIVE | INACTIVE | ENABLED | DISABLED
        // Input = service name (e.g. "sshd", "auditd", "firewalld").
        // =========================================================
        // CONTAINER — host-level "does a container runtime exist here?"
        // PASS for EXISTS iff `docker` or `podman` is on $PATH.
        // PASS for NOT EXISTS iff neither is on $PATH.
        // Input / condition / sinput are ignored.
        // =========================================================
        "container" => {
            let runtime_present = container_runtime_present();
            match selement_l.as_str() {
                "exists"     => if runtime_present  { EvalResult::Pass } else { EvalResult::Fail },
                "not exists" => if !runtime_present { EvalResult::Pass } else { EvalResult::Fail },
                _ => {
                    error!("Unsupported container selement: '{}'. Use 'exists' or 'not exists'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // IMAGE — per-container check against the container's image
        // reference. Caller (agent.rs::process_compliance_tests) iterates
        // discovered containers and invokes evaluate() once per container
        // with `container = Some(&c)`. Sub-elements:
        //   NAME   — image name without tag/registry
        //   TAG    — tag after ':' ("latest" when absent)
        //   DIGEST — pulled image digest (sha256:...)
        //   SOURCE — registry host (docker.io if implicit)
        // =========================================================
        "image" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            let target: Option<String> = match selement_l.as_str() {
                "name"   => c.image.as_deref().map(|s| image_part(s, ImagePart::Name)),
                "tag"    => c.image.as_deref().map(|s| image_part(s, ImagePart::Tag)),
                "source" => c.image.as_deref().map(|s| image_part(s, ImagePart::Source)),
                "digest" => c.image_digest.clone(),
                _ => {
                    error!("Unsupported image selement: '{}'", selement);
                    return EvalResult::Na;
                }
            };
            match target {
                Some(v) if apply_string_condition(&v, condition, sinput_trim) => EvalResult::Pass,
                Some(_) => EvalResult::Fail,
                None    => EvalResult::Na,
            }
        }

        // =========================================================
        // NETWORK — per-container check against the container's network
        // configuration. Sub-elements:
        //   MODE — host / bridge / none / container:<id> / named network
        // =========================================================
        "network" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            let target: Option<String> = match selement_l.as_str() {
                "mode" => c.network_mode.clone(),
                _ => {
                    error!("Unsupported network selement: '{}'", selement);
                    return EvalResult::Na;
                }
            };
            match target {
                Some(v) if apply_string_condition(&v, condition, sinput_trim) => EvalResult::Pass,
                Some(_) => EvalResult::Fail,
                None    => EvalResult::Na,
            }
        }

        // =========================================================
        // PRIVILEGED — per-container --privileged flag (CIS Docker 5.4).
        // EXISTS PASSes iff the container was started with --privileged.
        // No input / condition / sinput needed.
        // =========================================================
        "privileged" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            match c.is_privileged {
                Some(true)  => bool_selement(&selement_l, true,  selement),
                Some(false) => bool_selement(&selement_l, false, selement),
                None        => EvalResult::Na,
            }
        }

        // =========================================================
        // RUN_USER — per-container "what user is the container running
        // as" (CIS Docker 4.1). Sub-element CONTENT compares the user
        // string with the standard string conditions (EQUALS, NOT
        // EQUALS, CONTAINS, REGEX).
        // =========================================================
        "run_user" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            if selement_l.as_str() != "content" {
                error!("Unsupported run_user selement: '{}'. Use 'content'.", selement);
                return EvalResult::Na;
            }
            match &c.run_user {
                Some(v) if apply_string_condition(v, condition, sinput_trim) => EvalResult::Pass,
                Some(_) => EvalResult::Fail,
                None    => EvalResult::Na,
            }
        }

        // =========================================================
        // MOUNT — per-container "is this host path bind-mounted into
        // the container" (CIS Docker 5.5). Input = host path to check
        // (e.g. /var/run/docker.sock). Matches against the `src` field
        // of each mount in the cached mounts JSON (case-sensitive —
        // paths are).
        // =========================================================
        "mount" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            let any_match = container_mount_matches(c, input);
            match selement_l.as_str() {
                "exists"     => if any_match  { EvalResult::Pass } else { EvalResult::Fail },
                "not exists" => if !any_match { EvalResult::Pass } else { EvalResult::Fail },
                _ => {
                    error!("Unsupported mount selement: '{}'. Use 'exists' or 'not exists'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // EXPOSED_PORT — per-container "is this port published to the
        // host" check. Input = port spec (substring match against
        // "port/proto" entries — e.g. "22" matches "22/tcp" and
        // "22/udp", "443/tcp" matches only that exact entry). Sub-
        // elements:
        //   EXISTS / NOT EXISTS — any/no matching port published
        //   COUNT               — numeric condition on total exposed ports
        //                         (input is ignored; condition+sinput drive it)
        // =========================================================
        "exposed_port" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            let ports = container_exposed_ports(c);
            match selement_l.as_str() {
                "exists" => {
                    let n = input.to_lowercase();
                    let any = ports.iter().any(|p| p.to_lowercase().contains(&n));
                    if any { EvalResult::Pass } else { EvalResult::Fail }
                }
                "not exists" => {
                    let n = input.to_lowercase();
                    let any = ports.iter().any(|p| p.to_lowercase().contains(&n));
                    if !any { EvalResult::Pass } else { EvalResult::Fail }
                }
                "count" => {
                    let n = ports.len().to_string();
                    if apply_string_condition(&n, condition, sinput_trim) {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                _ => {
                    error!("Unsupported exposed_port selement: '{}'. Use 'exists', 'not exists', or 'count'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // READ_ONLY_FS — per-container --read-only flag (CIS Docker
        // 5.12). EXISTS PASSes iff the root filesystem is mounted r/o.
        // =========================================================
        "read_only_fs" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            match c.read_only_fs {
                Some(true)  => bool_selement(&selement_l, true,  selement),
                Some(false) => bool_selement(&selement_l, false, selement),
                None        => EvalResult::Na,
            }
        }

        // =========================================================
        // HEALTH_CHECK — per-container "is a HEALTHCHECK defined".
        // Observability hygiene. EXISTS PASSes iff Config.Healthcheck
        // is present in the inspect output.
        // =========================================================
        "health_check" => {
            let c = match container { Some(c) => c, None => return EvalResult::Na };
            match c.health_check {
                Some(true)  => bool_selement(&selement_l, true,  selement),
                Some(false) => bool_selement(&selement_l, false, selement),
                None        => EvalResult::Na,
            }
        }

        // =========================================================
        // No sinput / condition needed — sub-elements are boolean.
        // =========================================================
        "service" => {
            // service_is_active and service_is_enabled return Option<bool>:
            //   Some(true)  — confirmed active/enabled
            //   Some(false) — confirmed inactive/disabled
            //   None        — could not determine (no init system, command missing, etc.)
            let svc = input.trim();
            if svc.is_empty() {
                error!("SERVICE element requires a service name in 'input'.");
                return EvalResult::Na;
            }

            match selement_l.as_str() {
                "active" => match service_is_active(svc) {
                    Some(true)  => EvalResult::Pass,
                    Some(false) => EvalResult::Fail,
                    None        => EvalResult::Na,
                },
                "inactive" => match service_is_active(svc) {
                    Some(true)  => EvalResult::Fail,
                    Some(false) => EvalResult::Pass,
                    None        => EvalResult::Na,
                },
                "enabled" => match service_is_enabled(svc) {
                    Some(true)  => EvalResult::Pass,
                    Some(false) => EvalResult::Fail,
                    None        => EvalResult::Na,
                },
                "disabled" => match service_is_enabled(svc) {
                    Some(true)  => EvalResult::Fail,
                    Some(false) => EvalResult::Pass,
                    None        => EvalResult::Na,
                },
                _ => {
                    error!("Unsupported service selement: '{}'. Use 'active', 'inactive', 'enabled', or 'disabled'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // REGISTRY (Windows Only)
        // =========================================================
        "registry" => match selement_l.as_str() {
            "exists" => {
                #[cfg(windows)]
                {
                    let cmd = format!("Test-Path 'HKLM:\\{}'", input);
                    if Command::new("powershell")
                        .args(["-Command", &cmd])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                    {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(windows))]
                { EvalResult::Na }
            }
            "not exists" => {
                #[cfg(windows)]
                {
                    let cmd = format!("Test-Path 'HKLM:\\{}'", input);
                    if !Command::new("powershell")
                        .args(["-Command", &cmd])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(true)
                    {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(windows))]
                { EvalResult::Na }
            }
            "content" => {
                #[cfg(windows)]
                {
                    let parts: Vec<&str> = input.splitn(2, '|').collect();
                    if parts.len() != 2 {
                        error!(
                            "Registry content check requires 'path|ValueName' format, got: '{}'",
                            input
                        );
                        return EvalResult::Fail;
                    }
                    let reg_path   = parts[0];
                    let value_name = parts[1];
                    let cmd = format!(
                        "(Get-ItemProperty -Path 'HKLM:\\{}' -Name '{}').{}",
                        reg_path, value_name, value_name
                    );
                    let output = Command::new("powershell")
                        .args(["-Command", &cmd])
                        .output()
                        .ok();
                    match output {
                        Some(o) => {
                            let actual = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            if apply_string_condition(&actual, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        None => EvalResult::Fail,
                    }
                }
                #[cfg(not(windows))]
                { EvalResult::Na }
            }
            _ => {
                error!("Unsupported registry selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // USER
        // =========================================================
        "user" => match selement_l.as_str() {
            "exists"     => if check_user_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_user_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            _ => {
                error!("Unsupported user selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // CMD
        // =========================================================
        "cmd" => {
            if !cmd_enabled {
                warn!(
                    "CMD element is disabled. Set 'cmd_enabled = true' in [client] config to enable it."
                );
                return EvalResult::Na;
            }
            // CMD runs on the HOST. To run a command inside a container, use the
            // EXEC element instead (it execs via the container runtime).
            match selement_l.as_str() {
                "output" => {
                    #[cfg(unix)]
                    let output = Command::new("sh").args(["-c", input]).output();
                    #[cfg(windows)]
                    let output = Command::new("cmd").args(["/C", input]).output();

                    match output {
                        Ok(o) => {
                            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                            // Some commands (e.g. softwareupdate) write to stderr instead of stdout.
                            // Combine both so conditions match regardless of which stream is used.
                            let combined = match (stdout.is_empty(), stderr.is_empty()) {
                                (false, false) => format!("{}\n{}", stdout, stderr),
                                (true,  false) => stderr,
                                (_,      _   ) => stdout,
                            };
                            debug!("CMD '{}' output: '{}'", input, combined);
                            if apply_string_condition(&combined, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        Err(e) => {
                            error!("Failed to execute command '{}': {}", input, e);
                            EvalResult::Fail
                        }
                    }
                }
                "exit code" => {
                    #[cfg(unix)]
                    let output = Command::new("sh").args(["-c", input]).output();
                    #[cfg(windows)]
                    let output = Command::new("cmd").args(["/C", input]).output();

                    match output {
                        Ok(o) => {
                            let code = o.status.code().unwrap_or(-1).to_string();
                            debug!("CMD '{}' exit_code: {}", input, code);
                            if apply_string_condition(&code, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        Err(e) => {
                            error!("Failed to execute command '{}': {}", input, e);
                            EvalResult::Fail
                        }
                    }
                }
                _ => {
                    error!("Unsupported cmd selement: '{}'. Use 'output' or 'exit code'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // EXEC — run a command INSIDE a container via `<runtime> exec`.
        // A per-container element (see is_per_container_element): the dispatcher
        // calls this once per container with that container's context. Requires
        // cmd_enabled (it executes arbitrary commands). No-shell images
        // (scratch/distroless) make `exec` fail → FAIL with a clear log.
        // =========================================================
        "exec" => {
            if !cmd_enabled {
                warn!("EXEC element is disabled. Set 'cmd_enabled = true' in [client] config to enable it.");
                return EvalResult::Na;
            }
            let c = match container {
                Some(c) => c,
                // EXEC only has meaning inside a container; never run on the host.
                None => return EvalResult::Na,
            };
            let run = |inp: &str| -> std::io::Result<std::process::Output> {
                Command::new(&c.runtime).args(["exec", &c.runtime_id, "sh", "-c", inp]).output()
            };
            match selement_l.as_str() {
                "output" => {
                    match run(input) {
                        Ok(o) => {
                            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                            let combined = match (stdout.is_empty(), stderr.is_empty()) {
                                (false, false) => format!("{}\n{}", stdout, stderr),
                                (true,  false) => stderr,
                                (_,      _   ) => stdout,
                            };
                            debug!("EXEC [{}] '{}' output: '{}'", c.name, input, combined);
                            if apply_string_condition(&combined, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        Err(e) => {
                            error!("Failed to exec in container '{}': {}", c.name, e);
                            EvalResult::Fail
                        }
                    }
                }
                "exit code" => {
                    match run(input) {
                        Ok(o) => {
                            let code = o.status.code().unwrap_or(-1).to_string();
                            debug!("EXEC [{}] '{}' exit_code: {}", c.name, input, code);
                            if apply_string_condition(&code, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        Err(e) => {
                            error!("Failed to exec in container '{}': {}", c.name, e);
                            EvalResult::Fail
                        }
                    }
                }
                _ => {
                    error!("Unsupported exec selement: '{}'. Use 'output' or 'exit code'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // POWERSHELL — Windows only; returns NA on non-Windows platforms.
        // Requires ps_enabled = true in [client] config.
        // =========================================================
        "powershell" => {
            // On non-Windows platforms PowerShell is not a standard compliance
            // tool — use the cmd element with sh instead.
            #[cfg(not(target_os = "windows"))]
            {
                let _ = ps_enabled; // suppress unused-variable warning
                return EvalResult::Na;
            }

            #[cfg(target_os = "windows")]
            {
                if !ps_enabled {
                    warn!(
                        "PowerShell element is disabled. Set 'ps_enabled = true' in the registry to enable it."
                    );
                    return EvalResult::Na;
                }

                match selement_l.as_str() {
                    "output" => {
                        // Try powershell.exe first (Windows PowerShell 5.x, always present on
                        // modern Windows), then fall back to pwsh (PowerShell Core 7+).
                        let output = Command::new("powershell.exe")
                            .args(["-NonInteractive", "-NoProfile", "-Command", input])
                            .output()
                            .or_else(|_| {
                                Command::new("pwsh")
                                    .args(["-NonInteractive", "-NoProfile", "-Command", input])
                                    .output()
                            });

                        match output {
                            Ok(o) => {
                                let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                                let combined = match (stdout.is_empty(), stderr.is_empty()) {
                                    (false, false) => format!("{}\n{}", stdout, stderr),
                                    (true,  false) => stderr,
                                    (_,      _   ) => stdout,
                                };
                                debug!("PowerShell '{}' output: '{}'", input, combined);
                                if apply_string_condition(&combined, condition, sinput_trim) {
                                    EvalResult::Pass
                                } else {
                                    EvalResult::Fail
                                }
                            }
                            Err(e) => {
                                error!("Failed to execute PowerShell command '{}': {}", input, e);
                                EvalResult::Fail
                            }
                        }
                    }
                    "exit code" => {
                        let output = Command::new("powershell.exe")
                            .args(["-NonInteractive", "-NoProfile", "-Command", input])
                            .output()
                            .or_else(|_| {
                                Command::new("pwsh")
                                    .args(["-NonInteractive", "-NoProfile", "-Command", input])
                                    .output()
                            });

                        match output {
                            Ok(o) => {
                                let code = o.status.code().unwrap_or(-1).to_string();
                                debug!("PowerShell '{}' exit_code: {}", input, code);
                                if apply_string_condition(&code, condition, sinput_trim) {
                                    EvalResult::Pass
                                } else {
                                    EvalResult::Fail
                                }
                            }
                            Err(e) => {
                                error!("Failed to execute PowerShell command '{}': {}", input, e);
                                EvalResult::Fail
                            }
                        }
                    }
                    _ => {
                        error!("Unsupported powershell selement: '{}'. Use 'output' or 'exit code'.", selement);
                        EvalResult::Na
                    }
                }
            }
        }

        // =========================================================
        // UNKNOWN
        // =========================================================
        _ => {
            error!("Unknown element type: '{}'", element);
            EvalResult::Na
        }
    }
}
