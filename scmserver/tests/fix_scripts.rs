// fix_scripts.rs — tests keep optional fix scripts (1.1.0 remediation, step 1).
//
// docs/design/1.1.0-remediation.md: a test may carry a shell and a PowerShell
// fix script. These tests cover where the scripts are stored and carried:
//   • the test form: CRLF from the browser becomes LF, a blank box is NULL
//   • policy import: scripts in the file are stored; a file without any
//     (older exports, Policy Store installs) keeps the test's own scripts
//   • the TEST payload sent to agents never includes a script

use std::collections::HashMap;
use sqlx::SqlitePool;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// A migrated in-memory database with tenant 'acme'.
// ─────────────────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')")
        .execute(&pool).await.unwrap();
    pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: export
// A one-test policy file; `fix` adds "fix_sh"/"fix_ps" to the test.
// ─────────────────────────────────────────────────────────────────────────────
fn export(fix: Option<(&str, &str)>) -> scmserver::models::PolicyExport {
    let mut test = serde_json::json!({
        "external_id": "t1", "name": "SSH root login off",
        "description": null, "rational": null, "remediation": "Set PermitRootLogin no",
        "severity": "High", "filter": "all", "app_filter": "all",
    });
    if let Some((sh, ps)) = fix {
        test["fix_sh"] = sh.into();
        test["fix_ps"] = ps.into();
    }
    serde_json::from_value(serde_json::json!({
        "format_version": 1,
        "policy": { "external_id": "p1", "name": "Baseline", "version": "1", "description": null },
        "tests": [test]
    })).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: scripts
// The stored (fix_sh, fix_ps) of the test with external_id 't1'.
// ─────────────────────────────────────────────────────────────────────────────
async fn scripts(pool: &SqlitePool) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT fix_sh, fix_ps FROM tests WHERE tenant_id = 'acme' AND external_id = 't1'")
        .fetch_one(pool).await.unwrap()
}

#[test]
fn the_form_turns_crlf_into_lf_and_a_blank_box_into_none() {
    let mut form: HashMap<String, Vec<String>> = HashMap::new();
    form.insert("fix_sh".into(), vec!["sed -i 's/yes/no/' /etc/ssh/sshd_config\r\nsystemctl reload sshd\r\n".into()]);
    form.insert("fix_ps".into(), vec!["  \r\n ".into()]);
    let (sh, ps) = scmserver::tests::extract_fix_scripts(&form);
    assert_eq!(sh.as_deref(), Some("sed -i 's/yes/no/' /etc/ssh/sshd_config\nsystemctl reload sshd\n"));
    assert_eq!(ps, None);

    assert_eq!(scmserver::tests::extract_fix_scripts(&HashMap::new()), (None, None));
}

#[tokio::test]
async fn an_import_stores_the_scripts_in_the_file() {
    let pool = db().await;
    scmserver::policies::apply_policy_import(&pool, "acme", export(Some(("echo sh", "echo ps")))).await.unwrap();
    assert_eq!(scripts(&pool).await, (Some("echo sh".into()), Some("echo ps".into())));

    // Re-importing a newer file replaces them.
    scmserver::policies::apply_policy_import(&pool, "acme", export(Some(("echo sh2", "echo ps2")))).await.unwrap();
    assert_eq!(scripts(&pool).await, (Some("echo sh2".into()), Some("echo ps2".into())));
}

#[tokio::test]
async fn an_import_without_scripts_keeps_the_tests_own() {
    let pool = db().await;
    scmserver::policies::apply_policy_import(&pool, "acme", export(Some(("echo sh", "echo ps")))).await.unwrap();

    // An older export, or a Policy Store install (which strips scripts).
    scmserver::policies::apply_policy_import(&pool, "acme", export(None)).await.unwrap();
    assert_eq!(scripts(&pool).await, (Some("echo sh".into()), Some("echo ps".into())));
}

#[test]
fn an_export_without_scripts_has_no_script_fields() {
    let json = serde_json::to_value(export(None)).unwrap();
    let test = json["tests"][0].as_object().unwrap();
    assert!(!test.contains_key("fix_sh") && !test.contains_key("fix_ps"), "{test:?}");
}

#[tokio::test]
async fn the_test_payload_sent_to_agents_has_no_script() {
    let pool = db().await;
    scmserver::policies::apply_policy_import(&pool, "acme", export(Some(("echo sh", "echo ps")))).await.unwrap();

    // The heartbeat reads tests with `SELECT t.*`, so the columns are in the row.
    let test: scmserver::models::Test = sqlx::query_as("SELECT * FROM tests WHERE external_id = 't1'")
        .fetch_one(&pool).await.unwrap();
    let payload = scmserver::models::TestPayload::from(scmserver::models::TestWithConditions {
        test, conditions: vec![], applicability: None,
    });
    let json = serde_json::to_string(&payload).unwrap();
    assert!(!json.contains("fix_") && !json.contains("echo sh"), "{json}");
}
