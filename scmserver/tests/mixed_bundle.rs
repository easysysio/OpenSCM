// A bundle whose agents are at DIFFERENT versions must be described per
// platform, and each client offered only its own platform's upgrade.
//
// Before the version came from the payload, every agent in a bundle was
// advertised at one version — the server's — so a mixed bundle was described
// uniformly and wrongly. Versions are now resolved per binary.
use semver::Version;

#[tokio::test]
async fn each_platform_is_offered_its_own_upgrade() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    scmserver::agents::startup_scan(&pool).await;

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT platform, version FROM agent_packages ORDER BY platform")
            .fetch_all(&pool).await.unwrap();
    if rows.len() < 2 {
        eprintln!("needs a multi-platform bundle — skipping");
        return;
    }
    for (p, v) in &rows { eprintln!("  bundle: {p} -> {v}"); }

    // Two clients, same version, different platforms. derive_platform is what
    // maps a heartbeat's (arch, os) onto a bundle key.
    for (arch, os, want_platform) in [
        ("aarch64", "Mac OS 26.6.2", "aarch64-macos"),
        ("aarch64", "Ubuntu 24.04",  "aarch64-linux"),
    ] {
        let platform = scmserver::agents::derive_platform(arch, os);
        assert_eq!(platform, want_platform, "{arch}/{os} mapped to the wrong bundle key");

        let pkg = rows.iter().find(|(p, _)| p == &platform)
            .unwrap_or_else(|| panic!("no bundled agent for {platform}"));

        let current = Version::parse("0.9.0").unwrap();
        let available = Version::parse(&pkg.1).unwrap();
        assert!(available > current, "{platform}: {available} should be offered over 0.9.0");
        eprintln!("  client {platform} @0.9.0  ->  offered {available}");
    }

    // The decisive property: the two platforms are offered DIFFERENT versions.
    let mac = rows.iter().find(|(p, _)| p == "aarch64-macos").map(|r| r.1.clone());
    let lnx = rows.iter().find(|(p, _)| p == "aarch64-linux").map(|r| r.1.clone());
    assert_ne!(mac, lnx, "a mixed bundle must not be described with one version");
}
