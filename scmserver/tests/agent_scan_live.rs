// Does a hand-placed newer agent get advertised by an OLDER server?
//
// This is the question the whole version-source change exists to answer: the
// advertised version must come from the payload, so dropping a newer client
// into the bundle is enough — the server's own version is not consulted.
#[tokio::test]
async fn a_newer_hand_placed_agent_is_advertised_by_an_older_server() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();

    scmserver::agents::startup_scan(&pool).await;

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT platform, version FROM agent_packages ORDER BY platform")
            .fetch_all(&pool)
            .await
            .unwrap();

    if rows.is_empty() {
        eprintln!("no bundled agents here (CI supplies these) — skipping");
        return;
    }
    for (platform, version) in &rows {
        eprintln!("  advertised: {platform} -> {version}");
    }
    let server_version = env!("CARGO_PKG_VERSION");
    assert!(
        rows.iter().any(|(_, v)| v != server_version),
        "every advertised version equals the server's ({server_version}) — \
         the version is being asserted, not read from the payload"
    );
}
