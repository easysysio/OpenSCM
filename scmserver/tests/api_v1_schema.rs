// api_v1_schema.rs — schema v51 for REST API v1 (docs/design/1.0.0-api-v1.md,
// D7 and D10).
//
// A policy's systems_passed/_failed mean test results in "test" mode and
// systems in "system" mode, so the API cannot say what they count. v51 adds
// tests_passed/_failed and compliant_/failing_systems, filled the same way in
// both modes. It also records which policy a saved report is of, and gives
// old reports that id where the policy's name leaves no doubt.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};

// max_connections(1) so every query hits the SAME in-memory database.
async fn fresh_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new().max_connections(1)
        .connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    pool
}

async fn exec(pool: &SqlitePool, sql: &str) {
    sqlx::query(sql).execute(pool).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: seed
// Policy 1 over group 1 with tests 1 and 2, and four systems:
//   web1 — PASS, PASS                 → compliant
//   web2 — PASS, FAIL                 → failing
//   web3 — FAIL excluded, NA          → neither (nothing scored)
//   old1 — FAIL, FAIL but inactive    → not counted at all
// So: 3 test passes, 1 test failure, 1 compliant system, 1 failing system.
// ─────────────────────────────────────────────────────────────────────────────
async fn seed(pool: &SqlitePool) {
    exec(pool, "INSERT INTO systems (id, tenant_id, name, status) VALUES
                  (1,'default','web1','active'), (2,'default','web2','active'),
                  (3,'default','web3','active'), (4,'default','old1','inactive')").await;
    exec(pool, "INSERT INTO tests (id, tenant_id, name) VALUES (1,'default','t1'), (2,'default','t2')").await;
    exec(pool, "INSERT INTO system_groups (id, tenant_id, name) VALUES (1,'default','g1')").await;
    exec(pool, "INSERT INTO policies (id, tenant_id, name) VALUES (1,'default','Baseline')").await;
    exec(pool, "INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES
                  ('default',1,1), ('default',2,1), ('default',3,1), ('default',4,1)").await;
    exec(pool, "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('default',1,1)").await;
    exec(pool, "INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('default',1,1), ('default',1,2)").await;
    exec(pool, "INSERT INTO results (tenant_id, system_id, test_id, container_id, result, excluded) VALUES
                  ('default',1,1,0,'PASS',0), ('default',1,2,0,'PASS',0),
                  ('default',2,1,0,'PASS',0), ('default',2,2,0,'FAIL',0),
                  ('default',3,1,0,'FAIL',1), ('default',3,2,0,'NA',0),
                  ('default',4,1,0,'FAIL',0), ('default',4,2,0,'FAIL',0)").await;
}

async fn counts(pool: &SqlitePool) -> [i64; 6] {
    let r = sqlx::query("SELECT tests_passed, tests_failed, compliant_systems, failing_systems,
                                systems_passed, systems_failed FROM policies WHERE id = 1")
        .fetch_one(pool).await.unwrap();
    ["tests_passed", "tests_failed", "compliant_systems", "failing_systems", "systems_passed", "systems_failed"]
        .map(|c| r.get::<i64, _>(c))
}

#[tokio::test]
async fn policy_counts_mean_the_same_in_both_compliance_modes() {
    for mode in ["test", "system"] {
        let pool = fresh_pool().await;
        seed(&pool).await;
        sqlx::query("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'policy_compliance_mode', ?)")
            .bind(mode).execute(&pool).await.unwrap();
        scmserver::scheduler::recalculate_current_compliance(&pool).await.unwrap();

        let [tp, tf, cs, fs, sp, sf] = counts(&pool).await;
        assert_eq!((tp, tf), (3, 1), "{mode} mode: test results passed/failed");
        assert_eq!((cs, fs), (1, 1), "{mode} mode: compliant/failing systems");
        // The pages' columns keep their mode-dependent meaning.
        let expected = if mode == "test" { (3, 1) } else { (1, 1) };
        assert_eq!((sp, sf), expected, "{mode} mode: systems_passed/_failed changed meaning");
    }
}

#[tokio::test]
async fn a_saved_policy_report_records_its_policy_id() {
    let pool = fresh_pool().await;
    seed(&pool).await;
    // A second policy, so the id cannot be right by accident.
    exec(&pool, "INSERT INTO policies (id, tenant_id, name) VALUES (7,'default','Other')").await;
    exec(&pool, "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('default',7,1)").await;
    scmserver::scheduler::recalculate_current_compliance(&pool).await.unwrap();

    let id = scmserver::reports::save_policy_report(7, &pool, "default", "alice").await.unwrap()
        .expect("report saved");
    let policy_id: Option<i64> = sqlx::query_scalar("SELECT policy_id FROM reports WHERE id = ?")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(policy_id, Some(7));
}

#[tokio::test]
async fn upgrading_from_v50_names_the_policy_of_old_reports_only_when_certain() {
    // A v51 database taken back to v50: the new columns dropped, version 50.
    let pool = fresh_pool().await;
    exec(&pool, "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme') ON CONFLICT DO NOTHING").await;
    exec(&pool, "INSERT INTO policies (id, tenant_id, name) VALUES
                  (1,'default','Baseline'), (2,'default','Twin'), (3,'default','Twin'),
                  (4,'acme','Baseline')").await;
    for col in ["tests_passed", "tests_failed", "compliant_systems", "failing_systems"] {
        exec(&pool, &format!("ALTER TABLE policies DROP COLUMN {col}")).await;
    }
    exec(&pool, "ALTER TABLE reports DROP COLUMN policy_id").await;
    exec(&pool, "UPDATE schema_info SET version = 50").await;
    exec(&pool, "INSERT INTO reports (id, tenant_id, policy_name, tests_metadata, report_results) VALUES
                  (10,'default','Baseline','[]','[]'),   -- one match
                  (11,'default','Twin','[]','[]'),       -- two policies share the name
                  (12,'default','Deleted','[]','[]'),    -- policy gone
                  (13,'acme','Baseline','[]','[]')       -- same name, other organization").await;

    scmserver::schema::run_migrations(&pool).await.unwrap();

    let ids: Vec<(i64, Option<i64>)> = sqlx::query_as("SELECT id, policy_id FROM reports ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(ids, vec![(10, Some(1)), (11, None), (12, None), (13, Some(4))]);
    for col in ["tests_passed", "tests_failed", "compliant_systems", "failing_systems"] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT {col} FROM policies WHERE id = 1"))
            .fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0, "{col} added with default 0");
    }
    let v: i64 = sqlx::query_scalar("SELECT version FROM schema_info").fetch_one(&pool).await.unwrap();
    assert_eq!(v, 51);
}
