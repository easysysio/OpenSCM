// security_headers_https.rs — Strict-Transport-Security when the App URL is
// https. See security_headers.rs for why this is a file of its own.

mod common { pub mod headers; }
use common::headers::{app, headers};

#[tokio::test]
async fn hsts_is_sent_when_the_app_url_is_https() {
    let h = headers(app("https://scm.example.com").await, "/login").await;
    assert_eq!(
        h.get("strict-transport-security").map(|v| v.to_str().unwrap()),
        Some(scmserver::security_headers::HSTS)
    );
}
