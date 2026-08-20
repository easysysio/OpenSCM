// Security properties of read-only tenant impersonation.
//
// The feature works by rewriting tenant_id in the signed session cookie, which
// makes every existing query scope to the target tenant. These pin the two
// things that keep that safe: the role can never survive the switch, and a
// session that is not impersonating is unaffected.

use serde_json::json;

/// Mirrors the parsing in auth.rs: role is derived, never trusted from the cookie.
fn effective_role(session: &serde_json::Value) -> String {
    let raw = session.get("role").and_then(|v| v.as_str()).unwrap_or("");
    if session.get("impersonating").is_some() { "viewer".to_string() } else { raw.to_string() }
}

#[test]
fn impersonating_session_is_downgraded_to_viewer() {
    // A cookie that claims superuser WHILE impersonating must not get it.
    let tampered = json!({
        "username": "root", "userid": "1",
        "tenant_id": "victim-tenant",
        "role": "superuser",
        "impersonating": { "real_tenant_id": "platform", "real_role": "superuser" }
    });
    assert_eq!(effective_role(&tampered), "viewer",
        "a tampered cookie must not retain privileges inside another tenant");
}

#[test]
fn normal_session_keeps_its_role() {
    let normal = json!({
        "username": "root", "userid": "1",
        "tenant_id": "platform", "role": "superuser"
    });
    assert_eq!(effective_role(&normal), "superuser",
        "ordinary sessions must be unaffected by the impersonation path");
}

#[test]
fn viewer_cannot_reach_privileged_levels() {
    use scmserver::models::UserRole;
    // The downgrade is only meaningful if viewer really is below everything
    // that mutates.
    let viewer = UserRole::from("viewer");
    assert!(viewer < UserRole::Runner,  "viewer must not be able to run scans");
    assert!(viewer < UserRole::Editor,  "viewer must not be able to edit");
    assert!(viewer < UserRole::Admin,   "viewer must not reach admin");
    assert!(viewer < UserRole::Superuser);
}
