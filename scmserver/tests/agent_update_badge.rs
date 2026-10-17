// agent_update_badge.rs — the sidebar counts systems waiting for an agent
// update.
//
// The count, the Systems page's Upgrade buttons and Upgrade All share one
// check (agents::available_upgrade), so the badge cannot promise an update the
// page does not offer, or miss one it does.

use scmserver::agents::{available_upgrade, systems_awaiting_update};
use scmserver::models::{AgentPackage, AuthSession};
use sqlx::SqlitePool;
use std::collections::HashMap;

fn pkgs() -> HashMap<String, AgentPackage> {
    [("x86_64-linux", "0.10.2"), ("aarch64-macos", "0.10.2")]
        .into_iter()
        .map(|(p, v)| (p.to_string(), AgentPackage {
            platform: p.into(), version: v.into(), sha256: "x".into(), url: "x".into(),
        }))
        .collect()
}

#[test]
fn an_older_agent_on_a_bundled_platform_can_upgrade() {
    let p = pkgs();
    assert_eq!(available_upgrade(&p, "0.9.6", "x86_64", "Ubuntu 22.04").as_deref(), Some("0.10.2"));
    assert_eq!(available_upgrade(&p, "0.10.1", "aarch64", "Mac OS 14.4.1").as_deref(), Some("0.10.2"));
}

#[test]
fn nothing_to_offer_is_not_an_upgrade() {
    let p = pkgs();
    assert_eq!(available_upgrade(&p, "0.10.2", "x86_64", "Debian 12"), None, "already current");
    assert_eq!(available_upgrade(&p, "0.11.0", "x86_64", "Debian 12"), None, "newer than bundled");
    assert_eq!(available_upgrade(&p, "0.9.0", "riscv64", "Debian 12"), None, "no agent bundled for it");
    assert_eq!(available_upgrade(&p, "NA", "x86_64", "Debian 12"), None, "version not reported");
    assert_eq!(available_upgrade(&p, "0.9.0", "NA", "NA"), None, "platform not reported");
    assert_eq!(available_upgrade(&p, "old-build", "x86_64", "Debian 12"), None, "not semver");
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// The default tenant has five systems, two of them waiting for an update;
// 'acme' has one more that must not leak into the default tenant's count.
// ─────────────────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')",
        "INSERT INTO agent_packages (platform, version, sha256, url) VALUES ('x86_64-linux', '0.10.2', 'x', 'x')",
        // Waiting: an old agent.
        "INSERT INTO systems (id, tenant_id, name, status, ver, arch, os) VALUES (1, 'default', 'old', 'active', '0.9.6', 'x86_64', 'Ubuntu 22.04')",
        // Waiting: upgrade already queued, agent not upgraded yet.
        "INSERT INTO systems (id, tenant_id, name, status, ver, arch, os) VALUES (2, 'default', 'queued', 'active', '0.10.0', 'x86_64', 'Rocky Linux 9')",
        "INSERT INTO commands (tenant_id, system_id, test_id, command_type) VALUES ('default', 2, NULL, 'UPGRADE')",
        // Not waiting: current, not approved yet, or no agent bundled for it.
        "INSERT INTO systems (id, tenant_id, name, status, ver, arch, os) VALUES (3, 'default', 'current', 'active', '0.10.2', 'x86_64', 'Debian 12')",
        "INSERT INTO systems (id, tenant_id, name, status, ver, arch, os) VALUES (4, 'default', 'pending', 'pending', '0.9.6', 'x86_64', 'Debian 12')",
        "INSERT INTO systems (id, tenant_id, name, status, ver, arch, os) VALUES (5, 'default', 'riscv', 'active', '0.9.6', 'riscv64', 'Debian 12')",
        // Another organization's.
        "INSERT INTO systems (id, tenant_id, name, status, ver, arch, os) VALUES (6, 'acme', 'theirs', 'active', '0.9.6', 'x86_64', 'Debian 12')",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    pool
}

#[tokio::test]
async fn the_count_is_old_approved_agents_in_this_organization_only() {
    let pool = db().await;
    assert_eq!(systems_awaiting_update(&pool, "default").await, 2);
    assert_eq!(systems_awaiting_update(&pool, "acme").await, 1);
    assert_eq!(systems_awaiting_update(&pool, "nobody").await, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: sidebar
// The sidebar as base.html renders it for an admin of `tenant`.
// ─────────────────────────────────────────────────────────────────────────────
async fn sidebar(pool: &SqlitePool, tenant: &str) -> String {
    let mut tera = scmserver::init_tera().unwrap();
    tera.add_raw_template("probe.html", "{% extends \"base.html\" %}").unwrap();
    let auth = AuthSession {
        username: "alice".into(), userid: 1, tenant_id: tenant.into(),
        role: "admin".into(), impersonating: None,
    };
    scmserver::handlers::render_template(&tera, Some(pool), "probe.html", tera::Context::new(), Some(auth))
        .await.unwrap().0
}

#[tokio::test]
async fn the_badge_shows_on_systems_and_on_the_inventory_heading() {
    let pool = db().await;
    let html = sidebar(&pool, "default").await;
    let badge = "<span class=\"badge badge-warning right\" title=\"2 system(s) waiting for an agent update\">2</span>";
    assert_eq!(html.matches(badge).count(), 2, "expected the badge twice:\n{html}");
}

#[tokio::test]
async fn no_badge_when_every_agent_is_current() {
    let pool = db().await;
    sqlx::query("UPDATE systems SET ver = '0.10.2'").execute(&pool).await.unwrap();
    let html = sidebar(&pool, "default").await;
    assert!(!html.contains("waiting for an agent update"));
}
