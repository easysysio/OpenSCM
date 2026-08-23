// agent_version.rs — the version the server advertises for bundled agents.
//
// This guards a bug that produced an infinite, entirely silent upgrade loop.
// startup_scan used to stamp the SERVER's CARGO_PKG_VERSION on every bundled
// agent, on the reasoning that agents ship alongside the server so the two
// "are guaranteed to match". When they diverge — a stale bundle, a dev build —
// the server advertises an upgrade to a version the payload does not contain.
// The agent downloads it, verifies the SHA, replaces itself and restarts, all
// successfully, then reports the SAME version. The server offers the upgrade
// again. Forever. Every log line on both sides says success.
//
// The advertised version must therefore come from the bundle, never from the
// server's own build.

// The bundle's version must be read from agents/VERSION, not assumed.
#[test]
fn advertised_version_is_not_hardcoded_to_the_server_version() {
    let src = include_str!("../src/agents.rs");
    let scan = src
        .split("pub async fn startup_scan")
        .nth(1)
        .expect("startup_scan must exist");
    let body = &scan[..scan.find("\n}\n").unwrap_or(scan.len())];

    assert!(
        body.contains("VERSION"),
        "startup_scan must read the bundled agents/VERSION file"
    );
    // The fallback is allowed, but only as a fallback: it must be paired with a
    // warning, because silently advertising the wrong version is the bug.
    if body.contains("CARGO_PKG_VERSION") {
        assert!(
            body.contains("warn!"),
            "falling back to the server version must warn — that fallback is the broken path"
        );
    }
}

// The VERSION file must not be mistaken for an agent binary.
#[test]
fn the_version_file_is_not_treated_as_a_platform() {
    let src = include_str!("../src/agents.rs");
    assert!(
        src.contains("strip_prefix(\"scmclient-\")"),
        "platform detection must require the scmclient- prefix so VERSION is skipped"
    );
}

// CI must actually write the file the server now depends on. Without this the
// server falls back and the bug returns, in release builds.
#[test]
fn ci_writes_the_version_file_into_the_bundle() {
    let wf = include_str!("../../.github/workflows/build_stable.yml");
    assert!(
        wf.contains("build/agents/VERSION"),
        "the stable workflow must write build/agents/VERSION alongside the binaries"
    );
}
