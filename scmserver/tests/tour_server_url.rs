// tour_server_url.rs — the tour's install command names the real server.
//
// App URL is an installation-wide setting stored under the 'default' tenant.
// The tour read it under the viewer's own tenant, which never exists in SaaS,
// so every SaaS organization saw the placeholder https://your-openscm-server
// in the agent install command instead of the actual address.

use scmserver::models::AuthSession;
use sqlx::SqlitePool;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (20, 'acme', 'bob', 'x', 'admin')",
        "INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', 'https://scm.example.com')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    pool
}

#[tokio::test]
async fn an_organization_sees_the_installation_app_url() {
    let pool = db().await;
    let bob = AuthSession {
        username: "bob".into(), userid: 20, tenant_id: "acme".into(),
        role: "admin".into(), impersonating: None,
    };
    let info = scmserver::tour::tour_info(&pool, &bob, true).await.expect("tour must be offered");
    assert_eq!(info.server_url, "https://scm.example.com");
}
