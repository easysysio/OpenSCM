// fix_button.rs — the Fix button on the live reports (1.1.0 remediation, step 3).
//
// docs/design/1.1.0-remediation.md §2–3. Pins three things:
//   • rendering: each state on both live reports, and the script reaching
//     the page escaped (it is shown, never interpreted)
//   • gating (fixes::annotate_results): a button only on a failed, not
//     excluded result whose test has a script for the system's OS; gray when
//     the agent is too old, its switch is off, or the user is below Editor
//   • queue / cancel (fixes::queue_fix, cancel_fix) check it all again

use scmserver::fixes::{annotate_results, cancel_fix, queue_fix, FixView, LastFix};
use scmserver::models::{AuthSession, IndividualResult};
use sqlx::SqlitePool;
use tera::Context;

// ── rendering ───────────────────────────────────────────────────────────────

fn render(tpl: &str, is_editor: bool, fix: Option<FixView>) -> String {
    let tera = scmserver::init_tera().expect("templates parse");
    let mut c = Context::new();
    for (k, v) in [("is_viewer", true), ("is_admin", false), ("is_runner", false), ("is_superuser", false),
                   ("is_saas", false), ("impersonating", false), ("show_tour", false)] {
        c.insert(k, &v);
    }
    c.insert("is_editor", &is_editor);
    for (k, v) in [("username", "tester"), ("role", "editor"), ("version", "test"), ("edition", "CE"),
                   ("tenant_name", ""), ("tenant_id", "default")] {
        c.insert(k, v);
    }
    c.insert("userid", &1);
    c.insert("notify_count", &0);
    c.insert("notifications", &Vec::<u8>::new());
    c.insert("store_updates", &0);
    c.insert("pending_count", &0);
    c.insert("trend_labels", &Vec::<String>::new());
    c.insert("compliance_sat", &0);
    let res = IndividualResult {
        test_name: "Ensure root login is off".into(), status: "FAIL".into(),
        is_excludable: true, system_id: Some(7), test_id: Some(42), fix, ..Default::default()
    };
    let res = serde_json::to_value(&res).unwrap();
    let sys = serde_json::json!({
        "system_id": 7, "system_name": "host-1", "os": "Ubuntu", "arch": "x86_64",
        "ip": "10.0.0.1", "compliance_score": 50.0, "last_seen": "now",
        "total_pass": 0, "total_fail": 1, "total_na": 0, "containers": [],
        "policy_groups": [{
            "policy_id": 1, "policy_name": "P", "policy_version": "1", "policy_description": null,
            "results": [res.clone()], "is_passed": false,
            "pass_count": 0, "fail_count": 1, "na_count": 0, "excluded_count": 0,
        }],
    });
    let policy = serde_json::json!({
        "policy_id": 3, "policy_name": "P", "version": "1", "description": "",
        "submission_date": "now", "submitter_name": "t", "tests_metadata": [],
        "system_reports": [{
            "system_name": "host-1", "results": [res], "is_passed": false,
            "pass_count": 0, "fail_count": 1, "na_count": 0, "excluded_count": 0, "containers": [],
        }],
        "total_pass": 0, "total_fail": 1, "total_na": 0, "total_excluded": 0, "compliance_score": 0.0,
    });
    c.insert("report", if tpl == "systems_report.html" { &sys } else { &policy });
    c.insert("tests_metadata", &Vec::<u8>::new());
    c.insert("system", &serde_json::json!({"id": 7, "name": "host-1"}));
    let h = tera.render(tpl, &c).unwrap_or_else(|e| format!("RENDER_ERROR: {e:?}"));
    assert!(!h.starts_with("RENDER_ERROR"), "{tpl}: {}", &h[..h.len().min(600)]);
    // Tera escapes '/' in output; a browser reads it back as '/'.
    h.replace("&#x2F;", "/")
}

const PAGES: [&str; 2] = ["systems_report.html", "policies_report.html"];

fn view(state: &str) -> FixView {
    FixView { state: Some(state.into()), kind: Some("sh".into()), ..Default::default() }
}

#[test]
fn a_ready_button_carries_the_escaped_script_and_the_queue_url() {
    let fix = FixView { script: Some("echo '<script>alert(1)</script>'".into()), ..view("ready") };
    for (tpl, url) in PAGES.iter().zip(["/systems/report/7/fix/42", "/policies/report/3/fix/7/42"]) {
        let h = render(tpl, true, Some(fix.clone()));
        assert!(h.contains("btn btn-outline-primary btn-xs ml-2 fix-open"), "{tpl}");
        assert!(h.contains(&format!(r#"data-action="{url}""#)), "{tpl}: queue URL");
        assert!(h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{tpl}: script must be escaped");
        assert!(!h.contains("<script>alert(1)"), "{tpl}: raw script on the page");
        assert!(h.contains(r#"id="fixModal""#), "{tpl}: confirm dialog");
    }
}

#[test]
fn a_disabled_button_says_why_and_cannot_be_clicked() {
    let fix = FixView { reason: Some("Fix scripts are off on this system: set cmd_enabled = true".into()), ..view("disabled") };
    for tpl in PAGES {
        let h = render(tpl, true, Some(fix.clone()));
        assert!(h.contains("fix-disabled disabled\"") && h.contains(r#"aria-disabled="true""#), "{tpl}");
        assert!(!h.contains(r#"tabindex="0""#), "{tpl}: no tabindex on a non-interactive wrapper");
        assert!(h.contains("set cmd_enabled = true"), "{tpl}: reason in the tooltip");
        assert!(!h.contains("fix-open\""), "{tpl}");
    }
}

#[test]
fn a_queued_fix_can_be_cancelled_by_an_editor_only() {
    for (tpl, url) in PAGES.iter().zip(["/systems/report/7/fix/42/cancel", "/policies/report/3/fix/7/42/cancel"]) {
        let h = render(tpl, true, Some(view("queued")));
        assert!(h.contains("Fix queued"), "{tpl}");
        assert!(h.contains(&format!(r#"action="{url}""#)), "{tpl}: cancel form");
        let h = render(tpl, false, Some(view("queued")));
        assert!(h.contains("Fix queued") && !h.contains("fix-cancel"), "{tpl}: viewer cannot cancel");
        assert!(!h.contains(r#"id="fixModal""#), "{tpl}: no dialog for a viewer");
    }
}

#[test]
fn a_running_fix_and_the_last_outcome_are_shown() {
    for tpl in PAGES {
        assert!(render(tpl, true, Some(view("sent"))).contains("Fixing…"), "{tpl}");
        let last = FixView { last: Some(LastFix {
            status: "failed".into(), exit_code: Some(2), output: Some("sed: cannot read file".into()),
            finished_at: Some("2026-11-07 12:00:00".into()),
        }), ..Default::default() };
        let h = render(tpl, true, Some(last));
        assert!(h.contains("Last fix:") && h.contains("exit code 2") && h.contains("sed: cannot read file"), "{tpl}");
    }
}

#[test]
fn no_fix_no_controls() {
    for tpl in PAGES {
        let h = render(tpl, true, None);
        assert!(!h.contains("fix-open\"") && !h.contains("fix-disabled") && !h.contains("Last fix:"), "{tpl}");
    }
}

// ── gating and queueing ─────────────────────────────────────────────────────

// Systems: 1 Linux (cmd on), 2 Linux (cmd off), 3 Linux (agent before 1.1),
// 4 Windows (ps on), 5 Linux pending. Test 10 has only a shell script, 11 none.
// Every system failed test 10; system 1 also failed 11.
async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    for (id, os, status, cmd, ps) in [
        (1, "Ubuntu 24.04", "active", Some(true),  Some(false)),
        (2, "Ubuntu 24.04", "active", Some(false), Some(false)),
        (3, "Ubuntu 24.04", "active", None,        None),
        (4, "Windows 11",   "active", Some(false), Some(true)),
        (5, "Ubuntu 24.04", "pending", Some(true), Some(false)),
    ] {
        sqlx::query("INSERT INTO systems (id, tenant_id, key, name, os, status, cmd_enabled, ps_enabled)
                     VALUES (?, 'default', ?, ?, ?, ?, ?, ?)")
            .bind(id).bind(format!("k{id}")).bind(format!("host{id}")).bind(os).bind(status).bind(cmd).bind(ps)
            .execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO tests (id, tenant_id, name, fix_sh) VALUES (10, 'default', 'ten', 'echo fix'), (11, 'default', 'eleven', NULL)")
        .execute(&pool).await.unwrap();
    for s in 1..=5 {
        fail(&pool, s, 10).await;
    }
    fail(&pool, 1, 11).await;
    pool
}

async fn fail(pool: &SqlitePool, system: i64, test: i64) {
    sqlx::query("INSERT INTO results (tenant_id, system_id, test_id, container_id, result) VALUES ('default', ?, ?, 0, 'FAIL')")
        .bind(system).bind(test).execute(pool).await.unwrap();
}

fn row(system: i64, test: i64, status: &str) -> IndividualResult {
    IndividualResult { test_name: "t".into(), status: status.into(), system_id: Some(system), test_id: Some(test), ..Default::default() }
}

async fn annotate(pool: &SqlitePool, is_editor: bool, mut rows: Vec<IndividualResult>) -> Vec<Option<FixView>> {
    annotate_results(pool, "default", is_editor, rows.iter_mut()).await;
    rows.into_iter().map(|r| r.fix).collect()
}

fn state(v: &Option<FixView>) -> Option<&str> { v.as_ref().and_then(|v| v.state.as_deref()) }
fn reason(v: &Option<FixView>) -> &str { v.as_ref().and_then(|v| v.reason.as_deref()).unwrap_or("") }

fn editor() -> AuthSession {
    AuthSession { username: "eve".into(), userid: 5, tenant_id: "default".into(), role: "editor".into(), impersonating: None }
}

#[tokio::test]
async fn the_button_appears_only_where_a_fix_can_run() {
    let pool = db().await;
    let v = annotate(&pool, true, vec![
        row(1, 10, "FAIL"), row(2, 10, "FAIL"), row(3, 10, "FAIL"), row(4, 10, "FAIL"),
        row(1, 11, "FAIL"), row(1, 10, "PASS"),
    ]).await;
    assert_eq!(state(&v[0]), Some("ready"));
    assert_eq!(v[0].as_ref().unwrap().script.as_deref(), Some("echo fix"));
    assert_eq!(state(&v[1]), Some("disabled"));
    assert!(reason(&v[1]).contains("cmd_enabled"), "{}", reason(&v[1]));
    assert_eq!(state(&v[2]), Some("disabled"));
    assert!(reason(&v[2]).contains("older than 1.1.0"), "{}", reason(&v[2]));
    assert_eq!(v[3], None, "a Windows system with only a shell script gets no button");
    assert_eq!(v[4], None, "a test without a script gets no button");
    assert_eq!(v[5], None, "a passing result gets no button");

    let mut excluded = row(1, 10, "FAIL");
    excluded.is_excluded = true;
    assert_eq!(annotate(&pool, true, vec![excluded]).await[0], None, "an excluded finding gets no button");

    let viewer = annotate(&pool, false, vec![row(1, 10, "FAIL")]).await;
    assert_eq!(state(&viewer[0]), Some("disabled"));
    assert!(reason(&viewer[0]).contains("Editors"));
    assert_eq!(viewer[0].as_ref().unwrap().script, None, "no script on the page for a viewer");
}

#[tokio::test]
async fn queueing_checks_everything_again() {
    let pool = db().await;
    let e = editor();
    for (system, test, why) in [
        (2, 10, "cmd_enabled"),
        (3, 10, "older than 1.1.0"),
        (4, 10, "no fix script"),
        (5, 10, "not active"),
        (1, 11, "no fix script"),
        (1, 99, "failed result"),
    ] {
        let err = queue_fix(&pool, &e, "127.0.0.1", system, test).await.unwrap_err();
        assert!(err.contains(why), "system {system} test {test}: {err}");
    }
    let viewer = AuthSession { role: "viewer".into(), ..editor() };
    assert!(queue_fix(&pool, &viewer, "127.0.0.1", 1, 10).await.unwrap_err().contains("Editors"));

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fix_runs").fetch_one(&pool).await.unwrap();
    assert_eq!(n, 0, "nothing queued by a refused request");
}

#[tokio::test]
async fn a_queued_fix_copies_the_script_once_and_can_be_cancelled() {
    let pool = db().await;
    let e = editor();
    queue_fix(&pool, &e, "127.0.0.1", 1, 10).await.unwrap();
    let (kind, script, sha, by, status): (String, String, String, i64, String) = sqlx::query_as(
        "SELECT kind, script, script_sha256, requested_by, status FROM fix_runs WHERE system_id = 1 AND test_id = 10",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!((kind.as_str(), script.as_str(), by, status.as_str()), ("sh", "echo fix", 5, "queued"));
    assert_eq!(sha, scmserver::fixes::script_sha256("echo fix"));

    assert!(queue_fix(&pool, &e, "127.0.0.1", 1, 10).await.unwrap_err().contains("already queued"));
    assert_eq!(state(&annotate(&pool, true, vec![row(1, 10, "FAIL")]).await[0]), Some("queued"));

    // Editing the test afterwards does not change the queued fix.
    sqlx::query("UPDATE tests SET fix_sh = 'echo changed' WHERE id = 10").execute(&pool).await.unwrap();
    let script: String = sqlx::query_scalar("SELECT script FROM fix_runs").fetch_one(&pool).await.unwrap();
    assert_eq!(script, "echo fix");

    cancel_fix(&pool, &e, "127.0.0.1", 1, 10).await.unwrap();
    assert!(cancel_fix(&pool, &e, "127.0.0.1", 1, 10).await.is_err(), "nothing left to cancel");
    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'fix.%' ORDER BY id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(actions, ["fix.queue", "fix.cancel"]);

    // After a cancel the button is back, with no "last fix" line.
    let v = annotate(&pool, true, vec![row(1, 10, "FAIL")]).await;
    assert_eq!(state(&v[0]), Some("ready"));
    assert_eq!(v[0].as_ref().unwrap().last, None);
}

#[tokio::test]
async fn a_fix_already_sent_cannot_be_cancelled_and_its_outcome_is_shown() {
    let pool = db().await;
    let e = editor();
    queue_fix(&pool, &e, "127.0.0.1", 1, 10).await.unwrap();
    sqlx::query("UPDATE fix_runs SET status = 'sent'").execute(&pool).await.unwrap();
    assert!(cancel_fix(&pool, &e, "127.0.0.1", 1, 10).await.unwrap_err().contains("already have been sent"));
    assert_eq!(state(&annotate(&pool, true, vec![row(1, 10, "FAIL")]).await[0]), Some("sent"));

    sqlx::query("UPDATE fix_runs SET status = 'done', exit_code = 0, output = 'ok', finished_at = '2026-11-07 12:00:00'")
        .execute(&pool).await.unwrap();
    let v = annotate(&pool, true, vec![row(1, 10, "PASS")]).await;
    let v = v[0].as_ref().expect("last fix shown on the now-passing result");
    assert_eq!(v.state, None);
    assert_eq!(v.last.as_ref().map(|l| (l.status.as_str(), l.exit_code)), Some(("done", Some(0))));
}
