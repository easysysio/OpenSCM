use tracing::{debug, error, warn};
use std::path::Path;
use std::fs;
use sysinfo::System;
use std::process::Command;
use std::net::TcpStream;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use std::sync::Mutex;


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

// ─────────────────────────────────────────────────────────────────────────────
// Helper: split_negation
// (is_negative, positive form) of a string operator. NOT CONTAINS and
// NOT EQUALS are the negations of CONTAINS and EQUALS; everything else is
// returned unchanged.
// ─────────────────────────────────────────────────────────────────────────────
fn split_negation(condition: &str) -> (bool, String) {
    let c = condition.trim().to_lowercase();
    match c.as_str() {
        "not contains"             => (true, "contains".to_string()),
        "not equals" | "not equal" => (true, "equals".to_string()),
        _                          => (false, c),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: matches_across
// Applies a string operator to a check that looks at SEVERAL values — the
// lines of a file, a group's name and numeric id, a host's addresses.
//
// A positive operator passes when ANY value matches. A negative one passes
// only when NONE does. Before 0.9.5 negatives were applied value by value and
// OR-ed, so "NOT CONTAINS x" passed as soon as one line lacked x — true of
// almost any file, including one that contains x. A file with
// `PermitRootLogin yes` passed "NOT CONTAINS PermitRootLogin yes".
// ─────────────────────────────────────────────────────────────────────────────
fn matches_across<I, S>(values: I, condition: &str, expected: &str) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let (negative, positive) = split_negation(condition);
    let any = values
        .into_iter()
        .any(|v| apply_string_condition(v.as_ref(), &positive, expected));
    any != negative
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_path_owner
// EQUALS (the default for any operator but NOT EQUALS) passes when the owner's
// name or numeric uid is `sinput`. The operator used to be ignored, so
// NOT EQUALS was evaluated as EQUALS — exactly backwards.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
fn check_path_owner(path: &str, condition: &str, sinput: &str) -> EvalResult {
    use std::os::unix::fs::MetadataExt;
    let uid = match fs::metadata(path) {
        Ok(m)  => m.uid(),
        Err(_) => return EvalResult::Fail,
    };
    let is_owner = get_user_name_from_uid(uid)
        .map(|n| n == sinput)
        .unwrap_or(false)
        || uid.to_string() == sinput;
    let (negative, _) = split_negation(condition);
    boolean(is_owner != negative)
}

#[cfg(not(unix))]
fn check_path_owner(_path: &str, _condition: &str, _sinput: &str) -> EvalResult { EvalResult::Na }

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_path_group
// Matches against the group's name and its numeric gid (see matches_across:
// NOT EQUALS means neither is `sinput`).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
fn check_path_group(path: &str, condition: &str, sinput: &str) -> EvalResult {
    use std::os::unix::fs::MetadataExt;
    let gid = match fs::metadata(path) {
        Ok(m)  => m.gid(),
        Err(_) => return EvalResult::Fail,
    };
    let name = get_group_name_from_gid(gid).unwrap_or_default();
    boolean(matches_across([name, gid.to_string()], condition, sinput))
}

#[cfg(not(unix))]
fn check_path_group(_p: &str, _c: &str, _s: &str) -> EvalResult { EvalResult::Na }

// ─────────────────────────────────────────────────────────────────────────────
// Helper: parse_octal_mode
// "644", "0644", "0o644", "1777" → the mode. None for anything that is not an
// octal permission value. Unix-only (and tests): its one caller is the unix
// check_path_permission, and an unused function is a warning on Windows.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(any(unix, test))]
fn parse_octal_mode(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix("0o").unwrap_or(t);
    if t.is_empty() || t.len() > 5 {
        return None;
    }
    u32::from_str_radix(t, 8).ok().filter(|m| *m <= 0o7777)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: permission_matches
// Permissions are sets of bits, so "more restrictive" is a subset test, not a
// numeric one. Compared as numbers, 0477 (group and other: rwx) is "less than"
// 0644 — which is how a world-writable file passed "644 or more restrictive".
//
//   EQUALS      exactly this mode
//   NOT EQUALS  any other mode
//   LESS THAN   grants nothing beyond `expected` (so `expected` itself passes)
//   MORE THAN   grants at least everything in `expected`
//
// None for an operator that has no meaning here.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(any(unix, test))]
fn permission_matches(mode: u32, condition: &str, expected: u32) -> Option<bool> {
    match condition.trim().to_lowercase().as_str() {
        "equal" | "equals"          => Some(mode == expected),
        "not equal" | "not equals"  => Some(mode != expected),
        "less than"                 => Some(mode & !expected == 0),
        "more than" | "greater than" => Some(expected & !mode == 0),
        _                           => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_path_permission
// A path that cannot be read fails (it used to be treated as mode 000, which
// passed every "LESS THAN" check). An expected value that is not octal is NA
// with an error in the log rather than being read as 000. The setuid, setgid
// and sticky bits are part of the mode, so `EQUALS 1777` works on /tmp.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
fn check_path_permission(path: &str, condition: &str, sinput: &str) -> EvalResult {
    use std::os::unix::fs::PermissionsExt;
    let mode = match fs::metadata(path) {
        Ok(m)  => m.permissions().mode() & 0o7777,
        Err(_) => return EvalResult::Fail,
    };
    let Some(expected) = parse_octal_mode(sinput) else {
        error!("Permission check on '{}': '{}' is not an octal mode such as 644", path, sinput);
        return EvalResult::Na;
    };
    match permission_matches(mode, condition, expected) {
        Some(passed) => boolean(passed),
        None => {
            error!("Unsupported permission operator: '{}'", condition);
            EvalResult::Fail
        }
    }
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

// ─────────────────────────────────────────────────────────────────────────────
// Version comparison
//
// Package versions are not semver. The previous comparison parsed both sides as
// strict X.Y.Z and, when that failed, answered "false" to every ordering
// question — so `openssh-server MORE THAN 8.0` failed on a host running
// 8.9p1-3ubuntu0.6, and 3.0.2-0ubuntu1.15 was not EQUAL to 3.0.2.
//
// A version here is  [epoch:]upstream[-revision] :
//   • The upstream part is split on '.', and parts are compared pairwise;
//     a missing part counts as 0, so 1.2 == 1.2.0.
//   • Within a part, runs of digits compare as numbers and runs of other
//     characters as text ('~' sorts before everything, as in dpkg), so
//     9p1 > 9 > 9~rc1 and 10 > 9.
//   • The epoch and the revision of the installed version are only taken into
//     account when the EXPECTED value has them too. Someone who writes "8.0"
//     means the upstream version.
// ─────────────────────────────────────────────────────────────────────────────
struct VersionParts<'a> {
    epoch:    Option<&'a str>,
    upstream: &'a str,
    revision: Option<&'a str>,
}

fn split_version(v: &str) -> VersionParts<'_> {
    let v = v.trim();
    let v = match v.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => v,
    };
    let (epoch, rest) = match v.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (Some(e), rest),
        _ => (None, v),
    };
    let (upstream, revision) = match rest.rsplit_once('-') {
        Some((u, r)) if !u.is_empty() => (u, Some(r)),
        _ => (rest, None),
    };
    VersionParts { epoch, upstream, revision }
}

// Orders two runs of digits as numbers without parsing them (no overflow).
fn cmp_digits(a: &str, b: &str) -> std::cmp::Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

// dpkg's character order for the non-digit runs: '~' first, then end of
// string, then letters, then everything else.
fn char_rank(c: Option<char>) -> i32 {
    match c {
        Some('~')                          => -1,
        None                               => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c)                            => c as i32 + 256,
    }
}

// Compares one dot-separated part: alternating non-digit and digit runs.
fn cmp_version_part(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::Equal;
    let (mut a, mut b) = (a, b);
    while !a.is_empty() || !b.is_empty() {
        let an = a.find(|c: char| c.is_ascii_digit()).unwrap_or(a.len());
        let bn = b.find(|c: char| c.is_ascii_digit()).unwrap_or(b.len());
        let (mut ac, mut bc) = (a[..an].chars(), b[..bn].chars());
        loop {
            let (x, y) = (ac.next(), bc.next());
            if x.is_none() && y.is_none() { break; }
            let o = char_rank(x).cmp(&char_rank(y));
            if o != Equal { return o; }
        }
        a = &a[an..];
        b = &b[bn..];
        let ad = a.find(|c: char| !c.is_ascii_digit()).unwrap_or(a.len());
        let bd = b.find(|c: char| !c.is_ascii_digit()).unwrap_or(b.len());
        let o = cmp_digits(&a[..ad], &b[..bd]);
        if o != Equal { return o; }
        a = &a[ad..];
        b = &b[bd..];
    }
    Equal
}

// Compares two dotted strings part by part; a missing part counts as 0.
fn cmp_dotted(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut ai, mut bi) = (a.split('.'), b.split('.'));
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (x, y) => {
                let o = cmp_version_part(x.unwrap_or("0"), y.unwrap_or("0"));
                if o != std::cmp::Ordering::Equal { return o; }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: compare_versions
// Orders an installed version against an expected one (see the block above).
// ─────────────────────────────────────────────────────────────────────────────
fn compare_versions(actual: &str, expected: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::Equal;
    let (a, e) = (split_version(actual), split_version(expected));
    if let Some(ee) = e.epoch {
        let o = cmp_digits(a.epoch.unwrap_or("0"), ee);
        if o != Equal { return o; }
    }
    let o = cmp_dotted(a.upstream, e.upstream);
    if o != Equal { return o; }
    match e.revision {
        Some(er) => cmp_dotted(a.revision.unwrap_or("0"), er),
        None     => Equal,
    }
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


// ─────────────────────────────────────────────────────────────────────────────
// Helper: any_line_matches
// Whether any line of the file — or of any file directly inside a directory —
// satisfies a POSITIVE operator. Err when something could not be read, so the
// caller can tell "no match" from "could not look".
// ─────────────────────────────────────────────────────────────────────────────
fn any_line_matches(path: &str, positive: &str, expected: &str) -> Result<bool, ()> {
    if Path::new(path).is_dir() {
        let dir = fs::read_dir(path).map_err(|e| {
            error!("Could not read directory {}: {}", path, e);
        })?;
        let mut unreadable = false;
        for entry in dir.filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            if !entry_path.is_file() {
                continue;
            }
            // Entries whose paths are not valid UTF-8 are skipped.
            let Some(p) = entry_path.to_str() else { continue };
            match any_line_matches(p, positive, expected) {
                Ok(true)  => return Ok(true),
                Ok(false) => {}
                Err(())   => unreadable = true,
            }
        }
        return if unreadable { Err(()) } else { Ok(false) };
    }

    let file = fs::File::open(path).map_err(|e| {
        error!("Could not open file {}: {}", path, e);
    })?;
    // Lines are read as bytes and decoded leniently, so a stray non-UTF-8 byte
    // neither hides the line it is on nor stops the scan. A read error part-way
    // through means the rest was not examined.
    for chunk in BufReader::new(file).split(b'\n') {
        let bytes = chunk.map_err(|e| {
            error!("Could not read file {}: {}", path, e);
        })?;
        let line = String::from_utf8_lossy(&bytes);
        let line = line.strip_suffix('\r').unwrap_or(&line);
        if apply_string_condition(line, positive, expected) {
            return Ok(true);
        }
    }
    Ok(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_file_content
// CONTAINS / EQUALS / REGEX pass when some line matches. NOT CONTAINS and
// NOT EQUALS pass when NO line does — see matches_across for why that
// distinction matters. A path that does not exist has no lines: it fails a
// positive check and passes a negative one. A path that exists but cannot be
// read fails either way, because nothing was verified.
// ─────────────────────────────────────────────────────────────────────────────
fn check_file_content(path: &str, condition: &str, expected: &str) -> bool {
    let (negative, positive) = split_negation(condition);
    if !Path::new(path).exists() {
        debug!("'{}' does not exist — content check is {}.", path, negative);
        return negative;
    }
    match any_line_matches(path, &positive, expected) {
        Ok(found) => found != negative,
        Err(())   => false,
    }
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
        // Numeric comparison, for values that are numbers: a process COUNT, a
        // command's output or exit code. These operators are offered for every
        // sub-element but were never handled here, so "COUNT MORE THAN 0"
        // always failed. Strict, as documented; not a number → fails.
        op @ ("more than" | "greater than" | ">" | "less than" | "<") => {
            match (actual.trim().parse::<f64>(), expected.trim().parse::<f64>()) {
                (Ok(a), Ok(e)) => if op.starts_with("less") || op == "<" { a < e } else { a > e },
                _ => {
                    error!("Numeric comparison needs two numbers (got '{}' and '{}')", actual, expected);
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
    use std::cmp::Ordering::{Equal, Greater, Less};
    let cond = condition.trim().to_lowercase();
    // Text operators look at the version as a string.
    if matches!(cond.as_str(), "contains" | "not contains" | "regex" | "regular expression") {
        return apply_string_condition(actual_str, condition, target_str);
    }
    if actual_str.trim().is_empty() || target_str.trim().is_empty() {
        error!("Version comparison needs two versions (got '{}' and '{}')", actual_str, target_str);
        return false;
    }
    let ord = compare_versions(actual_str, target_str);
    match cond.as_str() {
        "equal" | "equals" | "=="               => ord == Equal,
        "not equal" | "not equals" | "!="       => ord != Equal,
        "more than" | "greater than" | ">"      => ord == Greater,
        "less than" | "<"                       => ord == Less,
        _ => {
            error!("Unknown version condition: '{}'", condition);
            false
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
// CMD output cache — scoped to one scan.
//
// A policy commonly asks several questions of the same command: the CIS
// Debian profile runs `sshd -T` twenty times to check twenty different sshd
// settings, and re-runs findmnt, lsmod and nft for each option they cover.
// That is 84 process spawns per scan where 60 would do, and `sshd -T` is one
// of the more expensive things to spawn — it parses the config, initialises
// crypto and resolves the hostname on every invocation.
//
// So each distinct command runs once per scan and every later condition reads
// the stored result. The cache is cleared by reset_cmd_cache() at the start of
// each scan rather than expiring on a timer: a remediation applied between two
// scans must be visible in the next one, and a timer could silently hide it.
// Within a single scan, reusing one result is also more correct — every check
// then describes the same instant instead of a drifting one.
// ─────────────────────────────────────────────────────────────────────────────
static CMD_CACHE: Mutex<Option<HashMap<String, (String, i32)>>> = Mutex::new(None);

/// Drop everything cached from the previous scan. Called once per scan.
pub fn reset_cmd_cache() {
    if let Ok(mut g) = CMD_CACHE.lock() {
        *g = Some(HashMap::new());
    }
}

/// Run `input` through the shell, or return the result already recorded for it
/// in this scan. Returns (combined stdout+stderr, exit code); an exit code of
/// -1 means the command could not be spawned at all.
fn run_cmd_cached(input: &str) -> Option<(String, i32)> {
    if let Ok(g) = CMD_CACHE.lock() {
        if let Some(map) = g.as_ref() {
            if let Some(hit) = map.get(input) {
                debug!("CMD '{}' served from scan cache", input);
                return Some(hit.clone());
            }
        }
    }

    #[cfg(unix)]
    let output = Command::new("sh").args(["-c", input]).output();
    #[cfg(windows)]
    let output = Command::new("cmd").args(["/C", input]).output();

    let result = match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            // Some commands (e.g. softwareupdate) write to stderr instead of
            // stdout. Combine both so conditions match either way.
            let combined = match (stdout.is_empty(), stderr.is_empty()) {
                (false, false) => format!("{}\n{}", stdout, stderr),
                (true,  false) => stderr,
                (_,      _   ) => stdout,
            };
            (combined, o.status.code().unwrap_or(-1))
        }
        Err(e) => {
            error!("Failed to execute command '{}': {}", input, e);
            return None;
        }
    };

    if let Ok(mut g) = CMD_CACHE.lock() {
        g.get_or_insert_with(HashMap::new)
         .insert(input.to_string(), result.clone());
    }
    Some(result)
}


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
                // "Does this directory hold an entry with this name?" The
                // operator used to be ignored; NOT CONTAINS / NOT EQUALS now
                // mean it must not. A directory that does not exist holds
                // nothing; one that cannot be listed fails either way.
                let (negative, _) = split_negation(condition);
                if !Path::new(input).exists() {
                    boolean(negative)
                } else {
                    match fs::read_dir(input) {
                        Ok(entries) => {
                            let found = entries
                                .filter_map(|e| e.ok())
                                .any(|e| e.file_name() == sinput_trim);
                            boolean(found != negative)
                        }
                        Err(_) => EvalResult::Fail,
                    }
                }
            }
            "owner"                       => check_path_owner(input, condition, sinput_trim),
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
            "owner"                       => check_path_owner(input, condition, sinput_trim),
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
                        // NOT EQUALS means no interface has the address.
                        boolean(matches_across(
                            interfaces.iter().map(|(_, ip)| ip.to_string()),
                            condition,
                            sinput_trim,
                        ))
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
                    match run_cmd_cached(input) {
                        Some((combined, _)) => {
                            debug!("CMD '{}' output: '{}'", input, combined);
                            if apply_string_condition(&combined, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        None => EvalResult::Fail,
                    }
                }
                "exit code" => {
                    match run_cmd_cached(input) {
                        Some((_, code)) => {
                            let code = code.to_string();
                            debug!("CMD '{}' exit_code: {}", input, code);
                            if apply_string_condition(&code, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        None => EvalResult::Fail,
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


// ============================================================
// TESTS
//
// What these pin is the meaning of a verdict. A wrong answer here is a host
// reported compliant when it is not (or the reverse), on every system, with
// nothing else in the product able to notice.
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    // ── fixtures ────────────────────────────────────────────────────────────
    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn file(name: &str, content: &[u8]) -> Tmp {
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "oscm-test-{}-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                name
            ));
            fs::write(&p, content).unwrap();
            Tmp(p)
        }
        fn path(&self) -> &str { self.0.to_str().unwrap() }
        #[cfg(unix)]
        fn mode(self, mode: u32) -> Tmp {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.0, fs::Permissions::from_mode(mode)).unwrap();
            self
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
    }

    const MISSING: &str = "/nonexistent/openscm/test/path";

    fn ev(element: &str, input: &str, selement: &str, condition: &str, sinput: &str) -> EvalResult {
        evaluate(element, input, selement, condition, sinput, false, false, None)
    }

    // ── file content ────────────────────────────────────────────────────────
    #[test]
    fn not_contains_fails_when_any_line_contains_the_text() {
        // The original bug: this passed, because the other lines lack the text.
        let f = Tmp::file("sshd", b"Port 22\nPermitRootLogin yes\nX11Forwarding no\n");
        assert_eq!(ev("FILE", f.path(), "CONTENT", "NOT CONTAINS", "PermitRootLogin yes"), EvalResult::Fail);
        assert_eq!(ev("FILE", f.path(), "CONTENT", "NOT CONTAINS", "PermitEmptyPasswords yes"), EvalResult::Pass);
    }

    #[test]
    fn not_equals_fails_when_any_line_equals_the_text() {
        let f = Tmp::file("lines", b"Port 22\nPermitRootLogin yes\n");
        assert_eq!(ev("FILE", f.path(), "CONTENT", "NOT EQUALS", "Port 22"), EvalResult::Fail);
        assert_eq!(ev("FILE", f.path(), "CONTENT", "NOT EQUALS", "Port 2222"), EvalResult::Pass);
    }

    #[test]
    fn an_empty_or_missing_file_contains_nothing() {
        let empty = Tmp::file("empty", b"");
        assert_eq!(ev("FILE", empty.path(), "CONTENT", "NOT CONTAINS", "x"), EvalResult::Pass);
        assert_eq!(ev("FILE", empty.path(), "CONTENT", "CONTAINS", "x"), EvalResult::Fail);
        assert_eq!(ev("FILE", MISSING, "CONTENT", "NOT CONTAINS", "x"), EvalResult::Pass);
        assert_eq!(ev("FILE", MISSING, "CONTENT", "CONTAINS", "x"), EvalResult::Fail);
    }

    // Unchanged behaviour of the positive operators.
    #[test]
    fn positive_content_operators_match_any_line() {
        let f = Tmp::file("pos", b"Port 22\r\nPermitRootLogin no\n");
        assert_eq!(ev("FILE", f.path(), "CONTENT", "CONTAINS", "permitrootlogin NO"), EvalResult::Pass, "case-insensitive");
        assert_eq!(ev("FILE", f.path(), "CONTENT", "EQUALS", "Port 22"), EvalResult::Pass, "CRLF is not part of the line");
        assert_eq!(ev("FILE", f.path(), "CONTENT", "REGEX", r"^PermitRootLogin\s+no$"), EvalResult::Pass);
        assert_eq!(ev("FILE", f.path(), "CONTENT", "REGEX", r"^PermitRootLogin\s+yes$"), EvalResult::Fail);
        assert_eq!(ev("FILE", f.path(), "CONTENT", "REGEX", "(unclosed"), EvalResult::Fail, "invalid regex");
    }

    // A non-UTF-8 byte must not hide its own line or stop the scan.
    #[test]
    fn invalid_utf8_does_not_hide_later_lines() {
        let f = Tmp::file("latin1", b"caf\xe9 owner\nPermitRootLogin yes\n");
        assert_eq!(ev("FILE", f.path(), "CONTENT", "CONTAINS", "PermitRootLogin yes"), EvalResult::Pass);
        assert_eq!(ev("FILE", f.path(), "CONTENT", "NOT CONTAINS", "PermitRootLogin yes"), EvalResult::Fail);
        assert_eq!(ev("FILE", f.path(), "CONTENT", "CONTAINS", "owner"), EvalResult::Pass);
    }

    #[test]
    fn directory_content_looks_across_its_files() {
        let dir = std::env::temp_dir().join(format!("oscm-test-dir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.conf"), "alpha\n").unwrap();
        fs::write(dir.join("b.conf"), "nullok here\n").unwrap();
        let d = dir.to_str().unwrap();
        // FILE CONTENT pointed at a directory scans every file in it.
        assert_eq!(ev("FILE", d, "CONTENT", "CONTAINS", "nullok"), EvalResult::Pass);
        assert_eq!(ev("FILE", d, "CONTENT", "NOT CONTAINS", "nullok"), EvalResult::Fail);
        assert_eq!(ev("FILE", d, "CONTENT", "NOT CONTAINS", "absent"), EvalResult::Pass);
        // DIRECTORY CONTENT asks about entry names.
        assert_eq!(ev("DIRECTORY", d, "CONTENT", "CONTAINS", "a.conf"), EvalResult::Pass);
        assert_eq!(ev("DIRECTORY", d, "CONTENT", "", "a.conf"), EvalResult::Pass, "operator defaults to 'has'");
        assert_eq!(ev("DIRECTORY", d, "CONTENT", "NOT CONTAINS", "a.conf"), EvalResult::Fail);
        assert_eq!(ev("DIRECTORY", d, "CONTENT", "NOT CONTAINS", "z.conf"), EvalResult::Pass);
        assert_eq!(ev("DIRECTORY", MISSING, "CONTENT", "NOT CONTAINS", "z.conf"), EvalResult::Pass);
        assert_eq!(ev("DIRECTORY", MISSING, "CONTENT", "CONTAINS", "z.conf"), EvalResult::Fail);
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── matches_across ──────────────────────────────────────────────────────
    #[test]
    fn negative_operators_require_no_value_to_match() {
        let v = ["staff", "20"];
        assert!(matches_across(v, "EQUALS", "staff"));
        assert!(matches_across(v, "EQUALS", "20"));
        assert!(!matches_across(v, "NOT EQUALS", "staff"), "the name matches");
        assert!(!matches_across(v, "NOT EQUALS", "20"), "the id matches");
        assert!(matches_across(v, "NOT EQUALS", "wheel"));
        assert!(matches_across(["10.0.0.5", "127.0.0.1"], "CONTAINS", "10.0."));
        assert!(!matches_across(["10.0.0.5", "127.0.0.1"], "NOT CONTAINS", "127."));
        assert!(!matches_across(Vec::<String>::new(), "EQUALS", "x"));
        assert!(matches_across(Vec::<String>::new(), "NOT EQUALS", "x"));
    }

    // ── permissions ─────────────────────────────────────────────────────────
    #[test]
    fn less_than_means_no_bit_beyond_the_expected_mode() {
        // 0477 is numerically below 0644 but grants group and other rwx.
        assert_eq!(permission_matches(0o477, "LESS THAN", 0o644), Some(false));
        assert_eq!(permission_matches(0o600, "LESS THAN", 0o644), Some(true));
        assert_eq!(permission_matches(0o644, "LESS THAN", 0o644), Some(true), "inclusive");
        assert_eq!(permission_matches(0o640, "LESS THAN", 0o644), Some(true));
        assert_eq!(permission_matches(0o664, "LESS THAN", 0o644), Some(false), "group write");
        assert_eq!(permission_matches(0o000, "LESS THAN", 0o644), Some(true));
        assert_eq!(permission_matches(0o4755, "LESS THAN", 0o755), Some(false), "setuid is extra");
    }

    #[test]
    fn more_than_means_at_least_the_expected_bits() {
        assert_eq!(permission_matches(0o755, "MORE THAN", 0o644), Some(true));
        assert_eq!(permission_matches(0o644, "MORE THAN", 0o644), Some(true));
        assert_eq!(permission_matches(0o600, "MORE THAN", 0o644), Some(false));
    }

    #[test]
    fn permission_equality_and_unknown_operators() {
        assert_eq!(permission_matches(0o644, "EQUALS", 0o644), Some(true));
        assert_eq!(permission_matches(0o644, "equal", 0o640), Some(false));
        assert_eq!(permission_matches(0o644, "NOT EQUALS", 0o777), Some(true));
        assert_eq!(permission_matches(0o644, "NOT EQUALS", 0o644), Some(false));
        assert_eq!(permission_matches(0o1777, "EQUALS", 0o1777), Some(true));
        assert_eq!(permission_matches(0o644, "CONTAINS", 0o644), None);
    }

    #[test]
    fn octal_modes_parse_and_junk_does_not() {
        assert_eq!(parse_octal_mode("644"), Some(0o644));
        assert_eq!(parse_octal_mode(" 0644 "), Some(0o644));
        assert_eq!(parse_octal_mode("0o640"), Some(0o640));
        assert_eq!(parse_octal_mode("1777"), Some(0o1777));
        assert_eq!(parse_octal_mode("0"), Some(0));
        for junk in ["", "rw-r--r--", "888", "64 4", "77777", "-644"] {
            assert_eq!(parse_octal_mode(junk), None, "{junk:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn permission_checks_on_real_files() {
        let loose = Tmp::file("loose", b"x").mode(0o477);
        let tight = Tmp::file("tight", b"x").mode(0o600);
        let exact = Tmp::file("exact", b"x").mode(0o644);
        assert_eq!(ev("FILE", loose.path(), "PERMISSION", "LESS THAN", "644"), EvalResult::Fail);
        assert_eq!(ev("FILE", tight.path(), "PERMISSION", "LESS THAN", "644"), EvalResult::Pass);
        assert_eq!(ev("FILE", exact.path(), "PERMISSIONS", "EQUALS", "0644"), EvalResult::Pass);
        assert_eq!(ev("FILE", exact.path(), "PERMISSION", "NOT EQUALS", "777"), EvalResult::Pass);
        // A file that is not there has no acceptable permissions.
        assert_eq!(ev("FILE", MISSING, "PERMISSION", "LESS THAN", "644"), EvalResult::Fail);
        assert_eq!(ev("FILE", MISSING, "PERMISSION", "EQUALS", "000"), EvalResult::Fail);
        // An expected value that is not a mode is a broken test, not a result.
        assert_eq!(ev("FILE", exact.path(), "PERMISSION", "MORE THAN", "rw-r--r--"), EvalResult::Na);
    }

    // ── owner / group ───────────────────────────────────────────────────────
    #[cfg(unix)]
    #[test]
    fn owner_and_group_honour_not_equals() {
        use std::os::unix::fs::MetadataExt;
        let f = Tmp::file("owned", b"x");
        let meta = fs::metadata(f.path()).unwrap();
        let (uid, gid) = (meta.uid().to_string(), meta.gid().to_string());

        assert_eq!(ev("FILE", f.path(), "OWNER", "EQUALS", &uid), EvalResult::Pass);
        assert_eq!(ev("FILE", f.path(), "OWNER", "", &uid), EvalResult::Pass, "no operator still means equals");
        assert_eq!(ev("FILE", f.path(), "OWNER", "NOT EQUALS", &uid), EvalResult::Fail);
        assert_eq!(ev("FILE", f.path(), "OWNER", "NOT EQUALS", "no-such-user-xyz"), EvalResult::Pass);
        assert_eq!(ev("FILE", f.path(), "OWNER", "EQUALS", "no-such-user-xyz"), EvalResult::Fail);
        if let Some(name) = get_user_name_from_uid(meta.uid()) {
            assert_eq!(ev("FILE", f.path(), "OWNER", "EQUALS", &name), EvalResult::Pass);
            assert_eq!(ev("FILE", f.path(), "OWNER", "NOT EQUALS", &name), EvalResult::Fail);
        }

        assert_eq!(ev("FILE", f.path(), "GROUP", "EQUALS", &gid), EvalResult::Pass);
        assert_eq!(ev("FILE", f.path(), "GROUP", "NOT EQUALS", &gid), EvalResult::Fail);
        assert_eq!(ev("FILE", f.path(), "GROUP", "NOT EQUALS", "no-such-group-xyz"), EvalResult::Pass);
        if let Some(name) = get_group_name_from_gid(meta.gid()) {
            assert_eq!(ev("FILE", f.path(), "GROUP", "NOT EQUALS", &name), EvalResult::Fail);
        }

        assert_eq!(ev("FILE", MISSING, "OWNER", "NOT EQUALS", "root"), EvalResult::Fail);
        assert_eq!(ev("FILE", MISSING, "GROUP", "NOT EQUALS", "root"), EvalResult::Fail);
    }

    // ── string + numeric operators ──────────────────────────────────────────
    #[test]
    fn string_operators() {
        assert!(apply_string_condition("OpenSSH_8.9", "contains", "openssh"));
        assert!(apply_string_condition("abc", "NOT CONTAINS", "x"));
        assert!(apply_string_condition("Abc", "Equals", "aBC"));
        assert!(apply_string_condition("abc", "not equal", "abd"));
        assert!(!apply_string_condition("abc", "", "abc"), "an empty operator matches nothing");
        assert!(!apply_string_condition("abc", "bogus", "abc"));
    }

    #[test]
    fn numeric_operators_compare_numbers() {
        assert!(apply_string_condition("3", "MORE THAN", "2"));
        assert!(!apply_string_condition("2", "MORE THAN", "2"), "strict");
        assert!(apply_string_condition("3", "LESS THAN", "5"));
        assert!(apply_string_condition("10", "MORE THAN", "9"), "numbers, not text");
        assert!(apply_string_condition(" 0 \n", "LESS THAN", "1"), "command output has whitespace");
        assert!(apply_string_condition("1.5", "greater than", "1.25"));
        assert!(!apply_string_condition("many", "MORE THAN", "2"));
        assert!(!apply_string_condition("3", "MORE THAN", ""));
    }

    // ── versions ────────────────────────────────────────────────────────────
    #[test]
    fn clean_versions_compare_as_before() {
        assert_eq!(compare_versions("1.2.3", "1.2.3"), Equal);
        assert_eq!(compare_versions("1.2", "1.2.0"), Equal);
        assert_eq!(compare_versions("1", "1.0.0"), Equal);
        assert_eq!(compare_versions("10.0", "9.5"), Greater);
        assert_eq!(compare_versions("1.10.0", "1.9.0"), Greater);
        assert_eq!(compare_versions("0.9.4", "0.10.0"), Less);
        assert_eq!(compare_versions("v1.2.3", "1.2.3"), Equal);
        assert_eq!(compare_versions("22.04", "20.04"), Greater);
    }

    #[test]
    fn distribution_versions_compare_on_their_upstream_part() {
        assert_eq!(compare_versions("8.9p1-3ubuntu0.6", "8.0"), Greater);
        assert_eq!(compare_versions("8.9p1-3ubuntu0.6", "8.9"), Greater, "p1 is after 8.9");
        assert_eq!(compare_versions("8.9p1-3ubuntu0.6", "8.9p1"), Equal, "revision ignored");
        assert_eq!(compare_versions("8.9p1-3ubuntu0.6", "9.0"), Less);
        assert_eq!(compare_versions("3.0.2-0ubuntu1.15", "3.0.2"), Equal);
        assert_eq!(compare_versions("3.0.2-0ubuntu1.15", "3.0.1"), Greater);
        assert_eq!(compare_versions("1:2.3.4-1", "2.0"), Greater, "epoch ignored unless asked for");
        assert_eq!(compare_versions("2.36-9+deb12u4", "2.30"), Greater);
        assert_eq!(compare_versions("5.14.0-362.el9", "6.0"), Less);
        assert_eq!(compare_versions("1.1.1.1", "1.0"), Greater);
        assert_eq!(compare_versions("1.1.1w-0+deb11u1", "1.1.1k"), Greater);
        assert_eq!(compare_versions("2.4.57", "2.4.6"), Greater, "57 > 6");
    }

    #[test]
    fn epoch_and_revision_count_when_the_expected_value_has_them() {
        assert_eq!(compare_versions("1:2.3.4-1", "1:2.3.4"), Equal);
        assert_eq!(compare_versions("2.3.4-1", "1:1.0"), Less, "no epoch is epoch 0");
        assert_eq!(compare_versions("2:1.0-1", "1:9.0"), Greater);
        assert_eq!(compare_versions("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.15"), Equal);
        assert_eq!(compare_versions("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.9"), Greater);
        assert_eq!(compare_versions("3.0.2-0ubuntu1.2", "3.0.2-0ubuntu1.15"), Less);
        assert_eq!(compare_versions("1.0~rc1", "1.0"), Less, "~ sorts before the release");
    }

    #[test]
    fn version_conditions() {
        assert!(apply_version_condition("8.9p1-3ubuntu0.6", "MORE THAN", "8.0"));
        assert!(!apply_version_condition("8.9p1-3ubuntu0.6", "LESS THAN", "8.0"));
        assert!(apply_version_condition("3.0.2-0ubuntu1.15", "EQUALS", "3.0.2"));
        assert!(apply_version_condition("3.0.2", "NOT EQUALS", "3.0.3"));
        assert!(!apply_version_condition("2.0", "MORE THAN", "2.0"), "strict");
        assert!(apply_version_condition("8.9p1-3ubuntu0.6", "CONTAINS", "ubuntu"), "text operators see the string");
        assert!(!apply_version_condition("", "MORE THAN", "1.0"));
        assert!(!apply_version_condition("1.0", "bogus", "1.0"));
    }

    // ── verdict + dispatch (unchanged behaviour) ────────────────────────────
    #[test]
    fn verdicts_combine_by_filter() {
        use EvalResult::{Fail, Na, Pass};
        assert_eq!(combine_verdict(&[Pass, Pass], "all"), "PASS");
        assert_eq!(combine_verdict(&[Pass, Fail], "all"), "FAIL");
        assert_eq!(combine_verdict(&[Pass, Na], "all"), "PASS");
        assert_eq!(combine_verdict(&[Na, Na], "all"), "NA");
        assert_eq!(combine_verdict(&[Fail, Pass], "any"), "PASS");
        assert_eq!(combine_verdict(&[Fail, Na], "any"), "FAIL");
        assert_eq!(combine_verdict(&[Na], "any"), "NA");
        assert_eq!(combine_verdict(&[], "all"), "NA");
    }

    #[test]
    fn unknown_and_disabled_checks_are_not_applicable() {
        assert_eq!(ev("BOGUS", "x", "EXISTS", "", ""), EvalResult::Na);
        assert_eq!(ev("FILE", "/etc/hosts", "BOGUS", "", ""), EvalResult::Na);
        // CMD is off unless the operator enables it on the agent.
        assert_eq!(ev("CMD", "echo hi", "OUTPUT", "CONTAINS", "hi"), EvalResult::Na);
        assert_eq!(ev("AGENT", "", "VERSION", "MORE THAN", "0.0.1"), EvalResult::Pass);
    }

    #[test]
    fn file_and_directory_existence() {
        let f = Tmp::file("exists", b"x");
        assert_eq!(ev("FILE", f.path(), "EXISTS", "", ""), EvalResult::Pass);
        assert_eq!(ev("FILE", MISSING, "EXISTS", "", ""), EvalResult::Fail);
        assert_eq!(ev("FILE", MISSING, "NOT EXISTS", "", ""), EvalResult::Pass);
        let tmp = std::env::temp_dir();
        assert_eq!(ev("DIRECTORY", tmp.to_str().unwrap(), "EXISTS", "", ""), EvalResult::Pass);
        assert_eq!(ev("DIRECTORY", MISSING, "NOT EXISTS", "", ""), EvalResult::Pass);
    }
}
