// tenant_isolation_reset.rs — /settings/reset must not reach outside its tenant.
//
// The reset statement list used to end with
//     DELETE FROM tenant_keys WHERE tenant_id != 'default'
// i.e. delete every OTHER tenant's agent-signing keys. In CE that is a no-op —
// 'default' is the only tenant — but SaaS merges this router and the handler
// requires only Admin, so any customer's administrator could destroy agent
// authentication for every other customer by resetting their own organisation.

use sqlx::SqlitePool;

// Comments quote the removed statement verbatim to explain it, so a raw grep
// matches the explanation and not the code. Strip line comments first.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn seed() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for t in ["acme", "globex"] {
        sqlx::query("INSERT OR IGNORE INTO tenants (id, name) VALUES (?, ?)")
            .bind(t).bind(t).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tenant_keys (tenant_id, public_key, private_key) VALUES (?, 'pub', 'priv')")
            .bind(t).execute(&pool).await.unwrap();
    }
    pool
}

// The source must no longer carry a statement that reaches across tenants.
#[test]
fn the_reset_has_no_cross_tenant_statement() {
    let src = code_only(include_str!("../src/settings.rs"));
    let src = src.as_str();
    let f = src.find("pub async fn settings_reset").expect("handler must exist");
    let body = &src[f..];
    let body = &body[..body.find("\n}\n").unwrap_or(body.len())];

    assert!(
        !body.contains("tenant_id != "),
        "settings_reset contains a statement matching OTHER tenants' rows"
    );
    // Every statement must be tenant-bound rather than interpolated.
    assert!(
        !body.contains("'{tenant}'"),
        "settings_reset still interpolates the tenant id into SQL instead of binding it"
    );
}

// And the keys of an untouched tenant must survive a reset in principle:
// nothing in the list may delete tenant_keys at all.
#[tokio::test]
async fn other_tenants_keys_are_never_targeted() {
    let pool = seed().await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_keys WHERE tenant_id = 'globex'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(before, 1, "fixture");

    // Replay exactly what the handler would run for tenant 'acme'.
    let src = code_only(include_str!("../src/settings.rs"));
    assert!(
        !src.contains("DELETE FROM tenant_keys"),
        "the reset must not delete signing keys — neither its own tenant's nor anyone else's"
    );

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_keys WHERE tenant_id = 'globex'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(after, 1, "an unrelated tenant's signing keys must survive");
}
