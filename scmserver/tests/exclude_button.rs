// exclude_button.rs — the visible exclude control on the live reports.
//
// Exclusion was right-click-only, which has no affordance and does not exist
// on touch devices at all. These pin the visible button's gating, which is the
// part that is easy to get subtly wrong: it must appear exactly where the
// right-click menu already worked, and nowhere else.
use tera::Context;

fn render(tpl: &str, is_editor: bool, excludable: bool, excluded: bool, status: &str) -> String {
    let tera = scmserver::init_tera().expect("templates parse");
    let mut c = Context::new();
    c.insert("is_editor", &is_editor);
    c.insert("is_viewer", &true);
    c.insert("is_admin", &false);
    c.insert("is_runner", &false);
    c.insert("is_superuser", &false);
    c.insert("is_saas", &false);
    c.insert("impersonating", &false);
    c.insert("username", "tester");
    c.insert("userid", &1);
    c.insert("role", "editor");
    c.insert("version", "test");
    c.insert("edition", "CE");
    c.insert("tenant_name", "");
    c.insert("tenant_id", "default");
    c.insert("notify_count", &0);
    c.insert("notifications", &Vec::<u8>::new());
    c.insert("store_updates", &0);
    c.insert("show_tour", &false);
    c.insert("pending_count", &0);
    c.insert("trend_labels", &Vec::<String>::new());
    c.insert("compliance_sat", &0);

    let res = serde_json::json!({
        "test_name": "Ensure /etc/passwd permissions",
        "status": status,
        "is_excluded": excluded,
        "is_excludable": excludable,
        "system_id": 7,
        "test_id": 42,
        "evidence": serde_json::Value::Null,
    });
    let sys = serde_json::json!({
        "system_id": 7, "system_name": "host-1", "os": "Ubuntu", "arch": "x86_64",
        "ip": "10.0.0.1", "compliance_score": 50.0, "last_seen": "now",
        "total_pass": 1, "total_fail": 1, "total_na": 0, "containers": [],
        "policy_groups": [{
            "policy_id": 1, "policy_name": "P", "policy_version": "1",
            "policy_description": serde_json::Value::Null,
            "results": [res.clone()], "is_passed": false,
            "pass_count": 1, "fail_count": 1, "na_count": 0, "excluded_count": 0,
        }],
    });
    let policy_report = serde_json::json!({
        "policy_id": 1, "policy_name": "P", "version": "1", "description": "",
        "submission_date": "now", "submitter_name": "t",
        "tests_metadata": [], "system_reports": [{
            "system_name": "host-1", "results": [res], "is_passed": false,
            "pass_count": 1, "fail_count": 1, "na_count": 0, "excluded_count": 0,
            "containers": [],
        }],
        "total_pass": 1, "total_fail": 1, "total_na": 0, "total_excluded": 0,
        "compliance_score": 50.0,
    });
    if tpl == "systems_report.html" { c.insert("report", &sys); }
    else                            { c.insert("report", &policy_report); }
    c.insert("tests_metadata", &Vec::<u8>::new());
    c.insert("system", &serde_json::json!({"id": 7, "name": "host-1"}));
    tera.render(tpl, &c).unwrap_or_else(|e| format!("RENDER_ERROR: {e:?}"))
}

fn count(h: &str) -> usize {
    assert!(!h.starts_with("RENDER_ERROR"), "{}", &h[..h.len().min(400)]);
    // Match the BUTTON markup specifically. Counting "exclude-toggle" alone
    // also matches the `closest('.exclude-toggle')` selector in the page's own
    // JavaScript, which renders for any editor and would mask the gating.
    h.matches("exclude-toggle text-muted").count()
}

#[test]
fn editor_sees_the_button_on_both_live_reports() {
    for tpl in ["systems_report.html", "policies_report.html"] {
        let h = render(tpl, true, true, false, "FAIL");
        assert!(!h.starts_with("RENDER_ERROR"), "{tpl}: {}", &h[..h.len().min(400)]);
        assert!(count(&h) >= 1, "{tpl}: editor must get a visible exclude button");
        assert!(h.contains("fa-ban"), "{tpl}: unexcluded row should offer 'exclude'");
    }
}

#[test]
fn an_excluded_row_offers_to_put_it_back() {
    for tpl in ["systems_report.html", "policies_report.html"] {
        let h = render(tpl, true, true, true, "FAIL");
        assert!(count(&h) >= 1, "{tpl}");
        assert!(h.contains("fa-rotate-left"), "{tpl}: excluded row should offer 'include again'");
    }
}

// The button must never appear where the action would be rejected: non-editors,
// and archived snapshots (is_excludable = false).
#[test]
fn non_editors_and_archived_snapshots_get_no_button() {
    for tpl in ["systems_report.html", "policies_report.html"] {
        assert_eq!(count(&render(tpl, false, true, false, "FAIL")), 0, "{tpl}: viewer");
        assert_eq!(count(&render(tpl, true, false, false, "FAIL")), 0, "{tpl}: archived");
    }
}

// A never-scanned result has nothing to exclude; the system report gates on it.
#[test]
fn not_scanned_rows_get_no_button_on_the_system_report() {
    assert_eq!(count(&render("systems_report.html", true, true, false, "NOT_SCANNED")), 0);
}
