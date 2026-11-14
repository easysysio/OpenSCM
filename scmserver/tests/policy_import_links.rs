// policy_import_links.rs — a policy update keeps the tests you added (1.1.3).
//
// Until 1.1.2, importing a newer file of a policy (Policy import or a Policy
// Store update) removed every test in the policy that the file did not have,
// including tests the organization had added to it itself. Now only links an
// import made (tests_in_policy.imported = 1) are removed:
//   • a test the file dropped is unlinked; a test added by hand stays
//   • a hand-added test the file later lists becomes the import's
//   • saving the policy edit form keeps which links came from an import
//   • links that existed before the upgrade are treated as added by hand

use axum::extract::{Extension, Path, RawForm};
use axum::response::IntoResponse;
use scmserver::models::{AuthSession, PolicyExport};
use sqlx::SqlitePool;

const POLICY_XID: &str = "b564a1afc4b6009ec0f32d1daa8a1913";

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: file
// A policy file at `version` holding the tests named by external id.
// ─────────────────────────────────────────────────────────────────────────────
fn file(version: &str, test_xids: &[&str]) -> PolicyExport {
    let tests: Vec<serde_json::Value> = test_xids.iter().map(|x| serde_json::json!({
        "external_id": x, "name": format!("test {x}"), "description": null, "rational": null,
        "remediation": null, "severity": "High", "filter": "all", "app_filter": "all",
        "conditions": [{"type": "condition", "element": "CMD", "input": "true", "selement": "OUTPUT",
                        "condition": "EQUALS", "sinput": ""}],
    })).collect();
    serde_json::from_value(serde_json::json!({
        "format_version": 3,
        "policy": {"external_id": POLICY_XID, "name": "Patch Management", "version": version},
        "tests": tests,
    })).unwrap()
}

async fn import(pool: &SqlitePool, version: &str, test_xids: &[&str]) -> scmserver::models::PolicyImportSummary {
    scmserver::policies::apply_policy_import(pool, "default", file(version, test_xids)).await.unwrap()
}

async fn policy_id(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT id FROM policies WHERE external_id = ?").bind(POLICY_XID)
        .fetch_one(pool).await.unwrap()
}

async fn test_id(pool: &SqlitePool, xid: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM tests WHERE external_id = ?").bind(xid)
        .fetch_one(pool).await.unwrap()
}

// The organization's own test, added to the policy by hand.
async fn add_own_test(pool: &SqlitePool, xid: &str) -> i64 {
    let id = sqlx::query("INSERT INTO tests (tenant_id, name, severity, filter, app_filter, external_id)
                          VALUES ('default', 'Debian Missing Security Patches', 'High', 'all', 'all', ?)")
        .bind(xid).execute(pool).await.unwrap().last_insert_rowid();
    sqlx::query("INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('default', ?, ?)")
        .bind(policy_id(pool).await).bind(id).execute(pool).await.unwrap();
    id
}

// External ids of the tests in the policy, sorted.
async fn linked(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT t.external_id FROM tests_in_policy tip JOIN tests t ON t.id = tip.test_id
                         WHERE tip.policy_id = ? ORDER BY t.external_id")
        .bind(policy_id(pool).await).fetch_all(pool).await.unwrap()
}

#[tokio::test]
async fn an_update_drops_what_the_file_dropped_and_keeps_your_own_tests() {
    let pool = db().await;
    import(&pool, "1.0.0", &["ubuntu", "fedora"]).await;
    add_own_test(&pool, "debian").await;

    let s = import(&pool, "1.0.1", &["ubuntu"]).await;
    assert_eq!(s.unlinked_tests, 1, "only fedora, which the file dropped");
    assert_eq!(linked(&pool).await, ["debian", "ubuntu"]);

    // The dropped test is unlinked, not deleted.
    test_id(&pool, "fedora").await;
}

#[tokio::test]
async fn a_test_you_added_that_the_file_later_lists_becomes_the_imports() {
    let pool = db().await;
    import(&pool, "1.0.0", &["ubuntu"]).await;
    add_own_test(&pool, "debian").await;

    import(&pool, "1.0.1", &["ubuntu", "debian"]).await;
    import(&pool, "1.0.2", &["ubuntu"]).await;
    assert_eq!(linked(&pool).await, ["ubuntu"], "the file took it over, so its next version can drop it");
}

#[tokio::test]
async fn saving_the_policy_form_keeps_which_links_came_from_an_import() {
    let pool = db().await;
    import(&pool, "1.0.0", &["ubuntu", "fedora", "arch"]).await;
    let pid = policy_id(&pool).await;
    let own = add_own_test(&pool, "debian").await;
    let (ubuntu, fedora) = (test_id(&pool, "ubuntu").await, test_id(&pool, "fedora").await);

    // Untick arch, keep the rest.
    let body = format!("name=Patch+Management&version=1.0.0&tests={ubuntu}&tests={fedora}&tests={own}");
    let (tx, _rx) = tokio::sync::mpsc::channel::<()>(8);
    let admin = AuthSession { username: "admin".into(), userid: 1, tenant_id: "default".into(),
                              role: "admin".into(), impersonating: None };
    let resp = scmserver::policies::policies_edit_save(
        admin, Path(pid as i32), Extension(pool.clone()), Extension(tx), RawForm(body.into()),
    ).await.into_response();
    let to = resp.headers().get("location").map(|l| l.to_str().unwrap().to_string()).unwrap_or_default();
    assert!(!to.contains("error_message"), "edit refused: {to}");
    assert_eq!(linked(&pool).await, ["debian", "fedora", "ubuntu"]);

    // Fedora is still the import's, Debian still yours.
    import(&pool, "1.0.1", &["ubuntu"]).await;
    assert_eq!(linked(&pool).await, ["debian", "ubuntu"]);
}

#[tokio::test]
async fn links_from_before_the_upgrade_count_as_added_by_hand() {
    let pool = db().await;
    import(&pool, "1.0.0", &["ubuntu", "fedora"]).await;
    // What v53 leaves on an existing database: every link at the default.
    sqlx::query("UPDATE tests_in_policy SET imported = 0").execute(&pool).await.unwrap();

    let s = import(&pool, "1.0.1", &["ubuntu"]).await;
    assert_eq!(s.unlinked_tests, 0, "an upgrade must never remove a test from a policy");
    assert_eq!(linked(&pool).await, ["fedora", "ubuntu"]);
}
