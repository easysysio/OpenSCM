// no_mutating_gets.rs — state-changing routes must not be reachable by GET.
//
// A GET that mutates is reachable by anything that follows a URL. SameSite=Lax
// attaches the session cookie to top-level navigation, so a link clicked from
// any other site performed the action; and mail security scanners, chat
// unfurlers and browser prefetchers fetch URLs unprompted, so a link to
// /systems/delete/42 in an email could delete a system with nobody clicking it.
//
// GET /systems/approve/{id} was the sharpest: one click approved an attacker's
// pending agent into the fleet.

// Routes whose handler mutates state must be registered with post().
#[test]
fn destructive_routes_are_post_only() {
    let lib = include_str!("../src/lib.rs");
    const MUST_BE_POST: [&str; 11] = [
        "/notifications/clear",
        "/users/delete/{id}",
        "/systems/delete/{id}",
        "/systems/tokens/delete/{id}",
        "/systems/approve/{id}",
        "/system_groups/delete/{id}",
        "/tests/delete/{id}",
        "/policies/delete/{id}",
        "/policies/run/{id}",
        "/reports/delete/{id}",
        "/reports/system/delete/{id}",
    ];
    for route in MUST_BE_POST {
        let needle = format!(".route(\"{route}\", ");
        let at = lib.find(&needle).unwrap_or_else(|| panic!("{route} is not registered"));
        let decl = &lib[at..(at + needle.len() + 12).min(lib.len())];
        assert!(
            decl.contains("post("),
            "{route} is still reachable by GET — a link to it mutates state"
        );
    }
}

// A broader net: nothing whose handler name says it destroys or changes things
// may be wired to get(). Catches the next one added, which is the point.
#[test]
fn no_get_route_looks_destructive() {
    let lib = include_str!("../src/lib.rs");
    let mut offenders = Vec::new();
    for line in lib.lines() {
        let l = line.trim();
        if !l.starts_with(".route(") || !l.contains(" get(") {
            continue;
        }
        // "add"/"edit" GETs render forms; the verbs below act.
        for verb in ["delete", "approve", "reject", "clear", "reset", "purge",
                     "revoke", "disable", "enable", "upgrade", "/run/"] {
            if l.contains(verb) {
                offenders.push(l.to_string());
                break;
            }
        }
    }
    assert!(offenders.is_empty(), "GET routes that appear to mutate:\n{}", offenders.join("\n"));
}

// The templates must reach them through the POST helper, not an href.
#[test]
fn templates_do_not_link_to_destructive_routes() {
    for (name, body) in [
        ("systems.html",   include_str!("../templates/systems.html")),
        ("users.html",     include_str!("../templates/users.html")),
        ("policies.html",  include_str!("../templates/policies.html")),
        ("reports.html",   include_str!("../templates/reports.html")),
        ("base.html",      include_str!("../templates/base.html")),
    ] {
        for route in ["/systems/delete/", "/systems/approve/", "/users/delete/",
                      "/policies/delete/", "/reports/delete/", "/notifications/clear"] {
            let bad = format!("href=\"{route}");
            assert!(
                !body.contains(&bad),
                "{name} still links to {route} with href — it must go through postTo()"
            );
        }
    }
}
