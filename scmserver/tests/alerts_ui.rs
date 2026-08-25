// alerts_ui.rs — the Alerts pages render, and are gated correctly.
use tera::Context;

fn base_ctx(is_admin: bool) -> Context {
    let mut c = Context::new();
    for (k, v) in [("is_admin", is_admin), ("is_editor", is_admin), ("is_runner", true),
                   ("is_viewer", true), ("is_superuser", false), ("is_saas", false),
                   ("impersonating", false), ("show_tour", false)] {
        c.insert(k, &v);
    }
    c.insert("username", "tester");
    c.insert("userid", &1);
    c.insert("role", "admin");
    c.insert("version", "test");
    c.insert("edition", "CE");
    c.insert("tenant_name", "");
    c.insert("tenant_id", "default");
    c.insert("notify_count", &0);
    c.insert("notifications", &Vec::<u8>::new());
    c.insert("store_updates", &0);
    c.insert("pending_count", &0);
    c
}

fn render(tpl: &str, ctx: Context) -> String {
    let tera = scmserver::init_tera().expect("templates parse");
    tera.render(tpl, &ctx).unwrap_or_else(|e| format!("RENDER_ERROR: {e:?}"))
}

#[test]
fn the_empty_state_explains_what_alerts_are_for() {
    let mut c = base_ctx(true);
    c.insert("alerts", &Vec::<u8>::new());
    let h = render("alerts.html", c);
    assert!(!h.starts_with("RENDER_ERROR"), "{}", &h[..h.len().min(400)]);
    assert!(h.contains("No alerts yet"));
    assert!(h.contains("New alert"), "an admin must be offered the create button");
}

// A Viewer may read the list but must not be offered management controls.
#[test]
fn viewers_get_no_management_controls() {
    let mut c = base_ctx(false);
    c.insert("alerts", &serde_json::json!([{
        "id": 1, "name": "prod drop", "enabled": true, "scope_type": "policy",
        "policy_id": 1, "policy_name": "CIS", "trigger_type": "drop", "threshold": 10.0,
        "score_axis": "test", "action": "notify", "target": "", "cooldown_minutes": 60,
        "last_fired_at": serde_json::Value::Null,
        "condition": "test compliance drops by 10 points or more"
    }]));
    let h = render("alerts.html", c);
    assert!(!h.starts_with("RENDER_ERROR"), "{}", &h[..h.len().min(400)]);
    assert!(h.contains("prod drop"), "a viewer can still read the rules");
    assert!(!h.contains("/alerts/new"), "but must not be offered create");
    // Specific to this page's own routes: base.html's postTo() comment mentions
    // "/systems/delete/42" as an example, so a bare "/delete" matches prose.
    assert!(!h.contains("/alerts/1/delete"), "nor delete");
    assert!(!h.contains("/alerts/1/toggle"), "nor enable/disable");
}

#[test]
fn the_form_renders_for_create_and_edit() {
    let mut c = base_ctx(true);
    c.insert("policies", &vec![(1i64, "CIS Ubuntu".to_string())]);
    let create = render("alerts_form.html", c.clone());
    assert!(!create.starts_with("RENDER_ERROR"), "{}", &create[..create.len().min(400)]);
    assert!(create.contains("/alerts/create"));

    c.insert("alert", &serde_json::json!({
        "id": 7, "name": "prod drop", "enabled": true, "scope_type": "policy",
        "policy_id": 1, "policy_name": "CIS", "trigger_type": "below", "threshold": 80.0,
        "score_axis": "system", "action": "webhook", "target": "https://hooks.example.com/x",
        "cooldown_minutes": 30, "last_fired_at": serde_json::Value::Null, "condition": "x"
    }));
    let edit = render("alerts_form.html", c);
    assert!(edit.contains("/alerts/7/update"), "edit must post to the update route");
    // Tera escapes '/' as &#x2F; inside attributes, so match on the host,
    // which survives escaping unchanged.
    assert!(edit.contains("hooks.example.com"), "existing target must be shown");
}

// The secret must never be rendered back into the page.
#[test]
fn the_webhook_secret_is_never_echoed() {
    let mut c = base_ctx(true);
    c.insert("policies", &vec![(1i64, "CIS".to_string())]);
    c.insert("alert", &serde_json::json!({
        "id": 7, "name": "n", "enabled": true, "scope_type": "policy", "policy_id": 1,
        "policy_name": "CIS", "trigger_type": "drop", "threshold": 10.0, "score_axis": "test",
        "action": "webhook", "target": "https://x/y", "cooldown_minutes": 60,
        "last_fired_at": serde_json::Value::Null, "condition": "x",
        "target_secret": "Bearer SUPERSECRET"
    }));
    let h = render("alerts_form.html", c);
    assert!(!h.contains("SUPERSECRET"), "a stored webhook secret must not be sent back to the browser");
}

#[test]
fn history_shows_the_failure_reason() {
    let mut c = base_ctx(true);
    c.insert("deliveries", &serde_json::json!([{
        "id": 1, "fired_at": "2026-08-23 10:00:00", "alert_name": "prod drop",
        "policy_name": "CIS", "old_score": 94.0, "new_score": 61.0, "action": "webhook",
        "target": "https://hooks.example.com/x", "status": "failed", "attempts": 3,
        "last_error": "HTTP 502"
    }]));
    let h = render("alerts_history.html", c);
    assert!(!h.starts_with("RENDER_ERROR"), "{}", &h[..h.len().min(400)]);
    assert!(h.contains("HTTP 502"), "a failed delivery must show why, not just 'failed'");
}
