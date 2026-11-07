// startup_access.rs — the server stops with the fix when it cannot use its
// folders (1.1.0: the Docker image runs as user 65532, not root).
//
// Volumes made by an older image belong to root; the new image could not open
// its database or keys and failed with a SQLite or key error that did not say
// why. scmserver::access_problem catches it first and names the fix.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

// Root ignores file modes, so there is nothing to check when tests run as root.
fn running_as_root(dir: &Path) -> bool {
    let probe = dir.join("probe");
    fs::create_dir(&probe).unwrap();
    chmod(&probe, 0o500);
    let root = fs::write(probe.join("x"), b"").is_ok();
    chmod(&probe, 0o700);
    root
}

#[test]
fn usable_folders_and_files_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, db) = (dir.path().join("scmserver.config"), dir.path().join("scm.db"));
    fs::write(&cfg, b"").unwrap();
    fs::write(&db, b"").unwrap();
    let missing = dir.path().join("scm.db-wal");
    assert_eq!(scmserver::access_problem(&[dir.path()], &[&cfg], &[&db, &missing]), None);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2, "the probe file is removed");
}

#[test]
fn a_folder_it_cannot_write_to_stops_it_with_the_fix() {
    let dir = tempfile::tempdir().unwrap();
    if running_as_root(dir.path()) { return; }
    let data = dir.path().join("data");
    fs::create_dir(&data).unwrap();
    chmod(&data, 0o555);
    let msg = scmserver::access_problem(&[&data], &[], &[]).expect("refused");
    chmod(&data, 0o755);
    println!("{msg}");
    assert!(msg.contains("cannot write to") && msg.contains("data"), "{msg}");
    assert!(msg.contains("busybox chown -R 65532:65532 /etc/openscm /var/lib/openscm"), "{msg}");
    assert!(msg.contains("--user 0"), "{msg}");
}

#[test]
fn files_it_cannot_open_are_named() {
    let dir = tempfile::tempdir().unwrap();
    if running_as_root(dir.path()) { return; }
    let key = dir.path().join("scmserver.key");
    fs::write(&key, b"k").unwrap();
    chmod(&key, 0o200);
    let msg = scmserver::access_problem(&[], &[&key], &[]).expect("unreadable key");
    assert!(msg.contains("cannot read") && msg.contains("scmserver.key"), "{msg}");

    let db = dir.path().join("scm.db");
    fs::write(&db, b"").unwrap();
    chmod(&db, 0o400);
    let msg = scmserver::access_problem(&[], &[], &[&db]).expect("read-only database");
    assert!(msg.contains("cannot write to") && msg.contains("scm.db"), "{msg}");
    chmod(&key, 0o600);
}

#[test]
fn the_error_prints_as_plain_text() {
    let e = scmserver::StartupError("line one\nline \"two\"".into());
    assert_eq!(format!("{e:?}"), "line one\nline \"two\"");
}
