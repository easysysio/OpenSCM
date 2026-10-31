// api_spec.rs — the published OpenAPI files and the API routes agree.
//
// docs/api/openapi.yaml (/api/v1) and docs/api/openapi-v1beta1.yaml are
// hand-written (0.12.0 design D7, 1.0.0 design D11). Both versions serve the
// same route list, so this fails when a route exists in src/api/mod.rs but
// not in either spec, or the other way round: the documentation cannot drift
// from what the server answers.
//
// Both sides are read as text by layout, not parsed: routes are the
// `.route(&p("/path"), get(..).post(..))` calls in api::router; the spec
// lists each path at two spaces of indentation under `paths:` and each method
// at four (the file's header says so).

use std::collections::BTreeSet;

fn routes() -> BTreeSet<(String, String)> {
    let src = include_str!("../src/api/mod.rs");
    let start = src.find("pub fn router").expect("api::router");
    let body = &src[start..];
    let route = regex::Regex::new(r#"\.route\(&p\("([^"]+)"\)"#).unwrap();
    let method = regex::Regex::new(r"\b(get|post|put|delete|patch)\(").unwrap();
    let starts: Vec<(usize, String)> = route.captures_iter(body)
        .map(|c| (c.get(0).unwrap().end(), c[1].to_string())).collect();
    let mut out = BTreeSet::new();
    for (i, (at, path)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map(|n| n.0).unwrap_or(body.len());
        for m in method.captures_iter(&body[*at..end]) {
            out.insert((m[1].to_string(), path.clone()));
        }
    }
    assert!(out.len() > 20, "found only {} routes — is the reader out of date?", out.len());
    out
}

fn spec(yaml: &str) -> BTreeSet<(String, String)> {
    let path_re = regex::Regex::new(r"^  (/\S*):\s*$").unwrap();
    let method_re = regex::Regex::new(r"^    (get|post|put|delete|patch):").unwrap();
    let mut out = BTreeSet::new();
    let mut in_paths = false;
    let mut current: Option<String> = None;
    for line in yaml.lines() {
        if line.starts_with("paths:") { in_paths = true; continue; }
        if in_paths && !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') { break; }
        if !in_paths { continue; }
        if let Some(c) = path_re.captures(line) { current = Some(c[1].to_string()); continue; }
        if let (Some(c), Some(p)) = (method_re.captures(line), &current) {
            out.insert((c[1].to_string(), p.clone()));
        }
    }
    out
}

#[test]
fn every_route_is_documented_and_every_documented_route_exists() {
    let routes = routes();
    for (file, yaml) in [
        ("openapi.yaml", include_str!("../../docs/api/openapi.yaml")),
        ("openapi-v1beta1.yaml", include_str!("../../docs/api/openapi-v1beta1.yaml")),
    ] {
        let spec = spec(yaml);
        let undocumented: Vec<_> = routes.difference(&spec).collect();
        let phantom: Vec<_> = spec.difference(&routes).collect();
        assert!(undocumented.is_empty(), "routes missing from docs/api/{file}: {undocumented:?}");
        assert!(phantom.is_empty(), "documented in {file} but not served: {phantom:?}");
    }
}

// The v1 file describes /api/v1 and the beta file the deprecated beta, with
// every beta operation marked deprecated.
#[test]
fn each_file_names_its_version() {
    let v1 = include_str!("../../docs/api/openapi.yaml");
    let beta = include_str!("../../docs/api/openapi-v1beta1.yaml");
    assert!(v1.contains("\n  - url: https://your-openscm-server/api/v1\n") && v1.contains("\n  version: v1\n"));
    assert!(!v1.contains("deprecated: true"));
    assert!(beta.contains("\n  - url: https://your-openscm-server/api/v1beta1\n"));
    assert_eq!(beta.matches("      deprecated: true").count(), spec(beta).len(), "every beta operation is deprecated");
}
