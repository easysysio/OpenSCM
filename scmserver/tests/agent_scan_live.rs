// What the server advertises must equal what the payload says about itself.
//
// This is the property the version-source change exists to provide, and the
// one whose absence caused upgrades to apply cleanly, report success and
// change nothing, forever. Stated as "advertised == the marker inside the
// binary", it holds whether or not the bundled agent happens to share the
// server's version — an earlier version of this test asserted they DIFFER,
// which passed only by coincidence and broke the moment the bundle was
// legitimately rebuilt at the server's own version.

// Reads the version the client stamped into itself.
fn marker_version(bytes: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"<<OPENSCM_AGENT_VERSION:";
    let start = bytes.windows(PREFIX.len()).position(|w| w == PREFIX)? + PREFIX.len();
    let tail = &bytes[start..(start + 32).min(bytes.len())];
    let end = tail.windows(2).position(|w| w == b">>")?;
    Some(std::str::from_utf8(&tail[..end]).ok()?.to_string())
}

#[tokio::test]
async fn advertised_version_equals_the_version_inside_the_binary() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();

    scmserver::agents::startup_scan(&pool).await;

    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT platform, version, url FROM agent_packages ORDER BY platform")
            .fetch_all(&pool).await.unwrap();

    if rows.is_empty() {
        eprintln!("no bundled agents here (CI supplies these) — skipping");
        return;
    }

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/static/agents/");
    let mut checked = 0;
    for (platform, advertised, url) in &rows {
        let name = url.rsplit('/').next().unwrap();
        let Ok(bytes) = std::fs::read(format!("{dir}{name}")) else { continue };
        let Some(actual) = marker_version(&bytes) else { continue };
        eprintln!("  {platform}: advertised {advertised}, binary says {actual}");
        assert_eq!(
            advertised, &actual,
            "{platform}: the server advertises {advertised} for a binary that is {actual} — \
             upgrades to it would apply and never take effect"
        );
        checked += 1;
    }
    assert!(checked > 0, "no bundled agent carried a version marker to verify against");
}
