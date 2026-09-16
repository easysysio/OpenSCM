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
        "score_axis": "test", "actions": [{"action":"notify","target":"","has_secret":false}], "cooldown_minutes": 60,
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
    c.insert("policies", &vec![(1i64, "CIS Ubuntu".to_string(), 87.0f64, 50.0f64)]);
    let create = render("alerts_form.html", c.clone());
    assert!(!create.starts_with("RENDER_ERROR"), "{}", &create[..create.len().min(400)]);
    assert!(create.contains("/alerts/create"));

    c.insert("alert", &serde_json::json!({
        "id": 7, "name": "prod drop", "enabled": true, "scope_type": "policy",
        "policy_id": 1, "policy_name": "CIS", "trigger_type": "below", "threshold": 80.0,
        "score_axis": "system",
        "actions": [{"action":"webhook","target":"https://hooks.example.com/x","has_secret":true},
                    {"action":"notify","target":"","has_secret":false}],
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
    c.insert("policies", &vec![(1i64, "CIS".to_string(), 87.0f64, 50.0f64)]);
    c.insert("alert", &serde_json::json!({
        "id": 7, "name": "n", "enabled": true, "scope_type": "policy", "policy_id": 1,
        "policy_name": "CIS", "trigger_type": "drop", "threshold": 10.0, "score_axis": "test",
        "actions": [{"action":"webhook","target":"https://x/y","has_secret":true,
                     "target_secret":"Bearer SUPERSECRET"}],
        "cooldown_minutes": 60,
        "last_fired_at": serde_json::Value::Null, "condition": "x"
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

// AdminLTE offsets page content past the fixed sidebar with .content-wrapper.
// Without it a page renders UNDERNEATH the sidebar and its left edge is
// unreachable — which is exactly how the Alerts pages first shipped, because
// nothing in Tera or the browser complains about a missing layout div.
#[test]
fn every_page_is_offset_past_the_sidebar() {
    for (name, body) in [
        ("alerts.html",         include_str!("../templates/alerts.html")),
        ("alerts_form.html",    include_str!("../templates/alerts_form.html")),
        ("alerts_history.html", include_str!("../templates/alerts_history.html")),
    ] {
        assert!(
            body.contains(r#"<div class="content-wrapper">"#),
            "{name} has no .content-wrapper — it will render under the sidebar"
        );
    }
}

// The handlers redirect with ?success_message= / ?error_message=. Without a
// block rendering them the messages are parsed, placed in the context and
// silently dropped — so a rejected webhook URL or a failed save looks exactly
// like nothing happening.
#[test]
fn pages_render_flash_messages() {
    for tpl in ["alerts.html", "alerts_history.html"] {
        let mut c = base_ctx(true);
        c.insert("alerts", &Vec::<u8>::new());
        c.insert("deliveries", &Vec::<u8>::new());
        c.insert("error_message", "Webhook URL must use https://");
        let h = render(tpl, c);
        assert!(!h.starts_with("RENDER_ERROR"), "{tpl}");
        assert!(h.contains("alert-danger"), "{tpl} does not render error_message");
        assert!(h.contains("must use https"), "{tpl} drops the message text");
    }
}

// A stray closing tag in a title block is invisible to Tera and to the tests
// above, but shows up in the browser tab and leaves the layout unclosed.
#[test]
fn title_blocks_contain_no_markup() {
    for (name, body) in [
        ("alerts.html",         include_str!("../templates/alerts.html")),
        ("alerts_form.html",    include_str!("../templates/alerts_form.html")),
        ("alerts_history.html", include_str!("../templates/alerts_history.html")),
    ] {
        let line = body.lines().find(|l| l.contains("block title")).expect("title block");
        assert!(!line.contains("</"), "{name}: closing tag inside the title block: {line}");
    }
}


// The form must carry each policy's current scores, so it can say where the
// policy stands and warn when a threshold rule is already past its line — the
// case where "falls below 100%" on a policy at 87% silently never fires.
#[test]
fn the_form_carries_current_scores_and_the_warning_slots() {
    let mut c = base_ctx(true);
    c.insert("policies", &vec![
        (1i64, "Patch Management".to_string(), 87.0f64, 40.0f64),
        (2i64, "Never Scanned".to_string(), -1.0f64, -1.0f64),
    ]);
    let h = render("alerts_form.html", c);
    assert!(!h.starts_with("RENDER_ERROR"), "{}", &h[..h.len().min(400)]);
    assert!(h.contains(r#"data-test="87""#), "test-axis score missing from the option");
    assert!(h.contains(r#"data-system="40""#), "system-axis score missing from the option");
    assert!(h.contains(r#"data-test="-1""#), "never-scanned policies must be marked");
    assert!(h.contains(r#"id="rule-current""#) && h.contains(r#"id="rule-warning""#));
}
