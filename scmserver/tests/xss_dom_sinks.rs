// xss_dom_sinks.rs — values built into markup on the client must be escaped.
//
// jQuery's .data() returns an attribute value already HTML-decoded, so Tera's
// autoescape does not survive the trip into .html()/.append(). The Pending
// Systems "View" modal did exactly that with the system name, which is the
// hostname an agent sends at its UNAUTHENTICATED first registration: anyone
// who could reach /send could plant `<img src=x onerror=...>` and have it run
// in the admin's session on a single click. Group names, member hostnames and
// test conditions (carried by imported policy files) had the same shape.
//
// These are source scans — the tests cannot execute browser JavaScript — so
// they check the invariant the fix relies on: every value concatenated into a
// DOM sink goes through window.escapeHtml (defined once in base.html).

use std::fs;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: templates
// Every template's (name, source), walking subdirectories.
// ─────────────────────────────────────────────────────────────────────────────
fn templates() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().map(|e| e == "html").unwrap_or(false) {
                out.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("templates"), &mut out);
    assert!(out.len() > 20, "template scan found almost nothing — wrong directory?");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: read_template
// ─────────────────────────────────────────────────────────────────────────────
fn read_template(f: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("templates").join(f)).unwrap()
}

const SINKS: [&str; 4] = [".html(", ".append(", ".prepend(", "innerHTML"];

// A .data() value placed straight into a sink is the original bug.
#[test]
fn no_data_attribute_reaches_a_dom_sink_unescaped() {
    let mut bad = Vec::new();
    for (name, src) in templates() {
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("{#") {
                continue;
            }
            if SINKS.iter().any(|s| line.contains(s))
                && line.contains(".data(")
                && !line.contains("escapeHtml(")
            {
                bad.push(format!("{}:{}: {}", name, i + 1, line.trim()));
            }
        }
    }
    assert!(bad.is_empty(), "unescaped .data() in a DOM sink:\n{}", bad.join("\n"));
}

// A template literal handed to a sink may only interpolate escaped values.
#[test]
fn template_literals_in_dom_sinks_escape_every_interpolation() {
    let mut bad = Vec::new();
    let mut scanned = 0;
    for (name, src) in templates() {
        for sink in [".html(`", ".append(`", ".prepend(`"] {
            let mut rest = src.as_str();
            while let Some(start) = rest.find(sink) {
                let body_start = start + sink.len();
                let Some(len) = rest[body_start..].find('`') else { break };
                let body = &rest[body_start..body_start + len];
                scanned += 1;
                let mut b = body;
                while let Some(p) = b.find("${") {
                    if !b[p..].starts_with("${escapeHtml(") {
                        let end = b[p..].find('}').map(|e| p + e + 1).unwrap_or(b.len());
                        bad.push(format!("{}: {}", name, &b[p..end]));
                    }
                    b = &b[p + 2..];
                }
                rest = &rest[body_start + len + 1..];
            }
        }
    }
    // tests.html builds its condition rows this way; if the scan finds none
    // it has stopped looking at the right thing and would pass vacuously.
    assert!(scanned > 0, "no template-literal sinks found — scanner is broken");
    assert!(bad.is_empty(), "unescaped ${{…}} in a DOM sink:\n{}", bad.join("\n"));
}

// The multi-line member-badge append in the group modal slipped past a
// line-based grep in the review, so pin the specific sites explicitly.
#[test]
fn the_reported_sites_are_escaped() {
    let systems = read_template("systems.html");
    assert!(systems.contains("escapeHtml(btn.data('name'))"), "system modal title");

    let groups = read_template("system_groups.html");
    assert!(groups.contains("escapeHtml(name)"), "group modal title");
    assert!(groups.contains("escapeHtml(sName.trim())"), "group member badges");

    let tests = read_template("tests.html");
    assert!(tests.contains("escapeHtml(b.data('name'))"), "test modal title");

    // The SMTP test result reflects the mail server's error text.
    let settings = read_template("settings.html");
    assert!(settings.contains("escapeHtml(data.message)"), "test-email success/fail text");
    assert!(settings.contains("escapeHtml(msg)"), "test-email error text");
}

// The helper itself must exist and cover the characters that matter.
#[test]
fn base_defines_escape_html() {
    let base = read_template("base.html");
    let def = base.find("window.escapeHtml").expect("escapeHtml not defined in base.html");
    let body = &base[def..(def + 600).min(base.len())];
    for needle in ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"] {
        assert!(body.contains(needle), "escapeHtml does not produce {needle}");
    }
    // Page scripts use it, so it must be defined before the scripts block.
    let scripts = base.find("{% block scripts %}").expect("no scripts block");
    assert!(def < scripts, "escapeHtml must be defined before page scripts load");
}
