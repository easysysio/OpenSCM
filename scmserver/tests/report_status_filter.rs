// report_status_filter.rs — policy report: report-wide status filter and the
// "Results by Test" card.
//
// The policy report lists results one card per system. These check that the
// results are also summarised per test (worst first, with the systems behind
// each count), and that the live report and a saved snapshot both render the
// filter bar, the per-test card, and a data-status on every result row the
// filter acts on (host and container rows).

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use scmserver::models::{AuthSession, IndividualResult, SystemReport, TestMeta};
use sqlx::SqlitePool;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// db — one policy, three systems in its group, three tests:
//   "Patches"  fails on alpha and beta, passes on gamma
//   "SSH root" passes on alpha and beta, excluded on gamma
//   "GDM"      NA everywhere
// ─────────────────────────────────────────────────────────────────────────────
async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let mut qs = vec![
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')".to_string(),
        "INSERT INTO policies (id, tenant_id, name, version, description) VALUES (1, 'default', 'Baseline', '1.0', 'd')".into(),
        "INSERT INTO system_groups (id, tenant_id, name) VALUES (1, 'default', 'Servers')".into(),
        "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('default', 1, 1)".into(),
    ];
    for (id, name) in [(1, "alpha"), (2, "beta"), (3, "gamma")] {
        qs.push(format!("INSERT INTO systems (id, tenant_id, name, status) VALUES ({id}, 'default', '{name}', 'active')"));
        qs.push(format!("INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES ('default', {id}, 1)"));
    }
    for (id, name) in [(1, "Patches"), (2, "SSH root"), (3, "GDM")] {
        qs.push(format!("INSERT INTO tests (id, tenant_id, name, description, rational, remediation) VALUES ({id}, 'default', '{name}', 'd', 'r', 'm')"));
        qs.push(format!("INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('default', 1, {id})"));
    }
    for (sys, test, res, excl) in [
        (1, 1, "FAIL", 0), (2, 1, "FAIL", 0), (3, 1, "PASS", 0),
        (1, 2, "PASS", 0), (2, 2, "PASS", 0), (3, 2, "FAIL", 1),
        (1, 3, "NA", 0),   (2, 3, "NA", 0),   (3, 3, "NA", 0),
    ] {
        qs.push(format!("INSERT INTO results (tenant_id, system_id, test_id, result, excluded) VALUES ('default', {sys}, {test}, '{res}', {excl})"));
    }
    for q in qs {
        sqlx::query(&q).execute(&pool).await.unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    pool
}

fn admin() -> AuthSession {
    AuthSession {
        username: "admin".into(), userid: 1, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    }
}

async fn body(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn res(test: &str, status: &str, excluded: bool) -> IndividualResult {
    IndividualResult { test_name: test.into(), status: status.into(), is_excluded: excluded, ..Default::default() }
}

fn sys(name: &str, results: Vec<IndividualResult>) -> SystemReport {
    SystemReport {
        system_name: name.into(), results, is_passed: false,
        pass_count: 0, fail_count: 0, na_count: 0, excluded_count: 0, containers: vec![],
    }
}

// The snapshot's rows, as the seed above, for the saved-report check.
fn snapshot() -> Vec<SystemReport> {
    vec![
        sys("alpha", vec![res("Patches", "FAIL", false), res("SSH root", "PASS", false), res("GDM", "NA", false)]),
        sys("beta",  vec![res("Patches", "FAIL", false), res("SSH root", "PASS", false), res("GDM", "NA", false)]),
        sys("gamma", vec![res("Patches", "PASS", false), res("SSH root", "FAIL", true),  res("GDM", "NA", false)]),
    ]
}

#[test]
fn results_are_summarised_per_test_worst_first() {
    let meta = vec![TestMeta { name: "Patches".into(), description: "d".into(), rational: "r".into(), remediation: "m".into() }];
    let s = scmserver::policies::summarize_by_test(&snapshot(), &meta);

    let order: Vec<(&str, &str)> = s.iter().map(|t| (t.test_name.as_str(), t.verdict)).collect();
    assert_eq!(order, vec![("Patches", "fail"), ("SSH root", "pass"), ("GDM", "na")]);

    assert_eq!(s[0].failed_on, vec!["alpha", "beta"]);
    assert_eq!(s[0].passed_on, vec!["gamma"]);
    assert!(s[0].meta.is_some(), "test details come along for the details window");

    // An excluded result counts only as excluded, never as the failure it was.
    assert!(s[1].failed_on.is_empty());
    assert_eq!(s[1].excluded_on, vec!["gamma"]);
    assert_eq!(s[2].na_on.len(), 3);
    assert!(s[2].meta.is_none());
}

fn assert_filterable(html: &str) {
    assert!(html.contains("id=\"report-filter-bar\""), "filter bar missing");
    for f in ["fail", "pass", "na", "excluded"] {
        assert!(html.contains(&format!("data-report-filter=\"{f}\"")), "no {f} filter");
    }
    assert!(html.contains("id=\"results-by-test\""), "Results by Test card missing");
    assert!(html.contains("class=\"by-test-row\" data-verdict=\"fail\" data-excluded=\"0\""));
    assert!(html.contains("class=\"by-test-row\" data-verdict=\"pass\" data-excluded=\"1\""));
    assert!(html.contains("Failed on:</strong> alpha, beta"));
    // Every host result row carries the status the filter matches on.
    assert_eq!(html.matches("class=\"report-row").count(), 9, "9 results, 9 filterable rows");
}

#[tokio::test]
async fn the_live_report_has_the_filter_and_the_per_test_card() {
    let pool = db().await;
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let resp = scmserver::policies::policies_report(
        admin(), Path(1),
        Query(serde_json::from_value(serde_json::json!({})).unwrap()),
        Extension(pool.clone()), Extension(tera),
    ).await.into_response();
    let (status, html) = body(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_filterable(&html);
}

#[tokio::test]
async fn a_saved_report_has_the_filter_and_the_per_test_card() {
    let pool = db().await;
    let results = serde_json::to_string(&snapshot()).unwrap();
    sqlx::query("INSERT INTO reports (id, tenant_id, policy_name, policy_version, submitter_name, tests_metadata, report_results)
                 VALUES (1, 'default', 'Baseline', '1.0', 'admin', '[]', ?)")
        .bind(results).execute(&pool).await.unwrap();
    let tera = Arc::new(scmserver::init_tera().unwrap());
    let resp = scmserver::reports::reports_view(
        admin(), Path(1),
        Query(serde_json::from_value(serde_json::json!({})).unwrap()),
        Extension(pool.clone()), Extension(tera),
    ).await.into_response();
    let (status, html) = body(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_filterable(&html);
}

// Container results nested under a host join the same filter.
#[test]
fn container_rows_carry_a_status() {
    let tpl = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/policies_report.html")).unwrap();
    assert!(tpl.contains("<tr class=\"report-row\" data-status=\"{{ c_status }}\">"));
}
