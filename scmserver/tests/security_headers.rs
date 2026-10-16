// security_headers.rs — every response carries the browser security headers.
//
// Driven through create_core_router so the test fails if the middleware is
// written but not wired in. The App URL here is plain http, so
// Strict-Transport-Security must be absent; security_headers_https.rs covers
// the https case. They are separate files because the App URL answer is
// cached for the life of the process, and each test file is its own process.

mod common { pub mod headers; }
use common::headers::{app, headers};

#[tokio::test]
async fn pages_redirects_assets_and_404s_carry_the_headers() {
    // /login renders a page, / redirects to /login, the CSS is a static
    // asset, and the last path does not exist.
    for path in ["/login", "/", "/dist/css/adminlte.min.css", "/no/such/page"] {
        let h = headers(app("http://scm.example.com").await, path).await;
        let get = |n: &str| h.get(n).map(|v| v.to_str().unwrap().to_string());
        assert_eq!(get("x-content-type-options").as_deref(), Some("nosniff"), "{path}");
        assert_eq!(get("x-frame-options").as_deref(), Some("DENY"), "{path}");
        assert_eq!(get("referrer-policy").as_deref(), Some("same-origin"), "{path}");
        let csp = get("content-security-policy").unwrap_or_else(|| panic!("{path}: no CSP"));
        assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
        assert!(csp.contains("object-src 'none'"), "{path}: {csp}");
        assert!(csp.starts_with("default-src 'self'"), "{path}: {csp}");
        assert!(get("strict-transport-security").is_none(), "{path}: HSTS over plain http");
    }
}
