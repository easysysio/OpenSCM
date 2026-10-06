// alerts_flash.rs — the Alerts pages show the result of what you just did.
//
// Saving, deleting or testing an alert redirects back with ?success_message=
// or ?error_message=. 0.9.2 added the banner to the templates but the handlers
// never read the query string, so nothing was ever shown: a saved alert and a
// refused one looked the same. The 0.9.2 test rendered the template with the
// message inserted by hand and so passed anyway.
//
// These make real requests to the real handlers, and follow a real redirect.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Router};
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use scmserver::alerts_admin as a;
use scmserver::auth::{issue_session_cookie, SESSION_TTL};
use sqlx::SqlitePool;
use std::sync::Arc;
use tower::ServiceExt;

struct App {
    pool: SqlitePool,
    cookie: String,
}

impl App {
    async fn new() -> App {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        scmserver::schema::initialize_database(&pool).await.unwrap();
        scmserver::schema::run_migrations(&pool).await.unwrap();
        for q in [
            "INSERT INTO users (id, tenant_id, username, password, role) VALUES (1, 'default', 'admin', 'x', 'admin')",
            "INSERT INTO policies (id, tenant_id, name, version) VALUES (1, 'default', 'CIS', '1')",
        ] {
            sqlx::query(q).execute(&pool).await.unwrap();
        }
        let session = serde_json::json!({ "username": "admin", "userid": "1", "tenant_id": "default", "role": "admin" });
        let cookie = issue_session_cookie(&pool, session, SESSION_TTL).await;
        let signed = (SignedCookieJar::new(key()).add(cookie), "").into_response();
        let cookie = signed.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
        App { pool, cookie }
    }

    fn router(&self) -> Router {
        Router::new()
            .route("/alerts", get(a::alerts_page))
            .route("/alerts/history", get(a::alerts_history))
            .route("/alerts/new", get(a::alerts_form))
            .route("/alerts/{id}/edit", get(a::alerts_form))
            .route("/alerts/create", post(a::alerts_save))
            .route("/alerts/{id}/delete", post(a::alerts_delete))
            .route("/alerts/{id}/test", post(a::alerts_test))
            .layer(Extension(self.pool.clone()))
            .layer(Extension(Arc::new(scmserver::init_tera().unwrap())))
            .with_state(key())
    }

    // (status, body, redirect target)
    async fn send(&self, req: axum::http::request::Builder, body: &str) -> (StatusCode, String, String) {
        let resp = self.router()
            .oneshot(req.header("cookie", &self.cookie).body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let to = resp.headers().get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string(), to)
    }
    async fn get(&self, path: &str) -> (StatusCode, String, String) {
        self.send(Request::get(path), "").await
    }
    async fn post(&self, path: &str, form: &str) -> (StatusCode, String, String) {
        self.send(Request::post(path).header("content-type", "application/x-www-form-urlencoded"), form).await
    }
}

fn key() -> Key { Key::from(&[7u8; 64]) }

#[tokio::test]
async fn every_alerts_page_shows_a_message_from_the_url() {
    let app = App::new().await;
    for path in ["/alerts", "/alerts/history", "/alerts/new"] {
        for (param, class) in [("error_message", "alert-danger"), ("success_message", "alert-success")] {
            let (status, html, _) = app.get(&format!("{path}?{param}=PROBE+4e9+was+shown")).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(html.contains("PROBE 4e9 was shown"), "{path} did not show its {param}");
            assert!(html.contains(class), "{path}: {param} not in a {class} banner");
        }
        // And nothing is shown when there is nothing to say.
        let (_, html, _) = app.get(path).await;
        assert!(!html.contains("alert-dismissible"), "{path} shows a banner with no message");
    }
}

// The round trip a person makes: act, get redirected, read the result.
#[tokio::test]
async fn saving_deleting_and_refused_input_each_report_back() {
    let app = App::new().await;
    let form = "name=prod+drop&scope_type=policy&policy_id=1&trigger_type=drop&threshold=10\
                &score_axis=test&cooldown_minutes=60&enabled=on&action_notify=on";

    let (status, _, to) = app.post("/alerts/create", form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, html, _) = app.get(&to).await;
    assert!(html.contains("Alert saved") && html.contains("alert-success"), "no confirmation after saving (→ {to})");
    assert!(html.contains("prod drop"));

    // Refused: a webhook action with nothing to post to.
    let bad = "name=x&scope_type=policy&policy_id=1&trigger_type=drop&threshold=10&score_axis=test&action_webhook=on&target_webhook=";
    let (_, _, to) = app.post("/alerts/create", bad).await;
    let (_, html, _) = app.get(&to).await;
    assert!(html.contains("alert-danger") && html.contains("needs a destination"), "no error shown for refused input (→ {to})");

    // Test: lands on the history page, which must say it was queued.
    let (_, _, to) = app.post("/alerts/1/test", "").await;
    let (_, html, _) = app.get(&to).await;
    assert!(html.contains("alert-success") && html.contains("Test queued"), "no confirmation after a test (→ {to})");

    let (_, _, to) = app.post("/alerts/1/delete", "").await;
    let (_, html, _) = app.get(&to).await;
    assert!(html.contains("Alert deleted") && html.contains("alert-success"), "no confirmation after deleting (→ {to})");
}

// A message is text. Tera escapes it; nothing typed into the URL becomes markup.
#[tokio::test]
async fn a_message_in_the_url_cannot_inject_markup() {
    let app = App::new().await;
    let (_, html, _) = app.get("/alerts?error_message=%3Cscript%3Ealert(1)%3C%2Fscript%3E").await;
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
}

// A Location header must be ASCII. One redirect carried a raw em dash, which
// browsers usually tolerate and nothing guarantees. Messages with other
// characters are fine — percent-encoded.
#[test]
fn no_redirect_target_contains_a_raw_non_ascii_character() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut bad = Vec::new();
    let mut scanned = 0;
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            let Some(at) = line.find("Redirect::to(") else { continue };
            scanned += 1;
            // Only the string literal handed to Redirect::to, if there is one.
            let rest = &line[at..];
            if let Some(start) = rest.find('"') {
                let lit = &rest[start + 1..];
                let lit = &lit[..lit.find('"').unwrap_or(lit.len())];
                if !lit.is_ascii() {
                    bad.push(format!("{}:{}: {}", path.file_name().unwrap().to_string_lossy(), i + 1, lit));
                }
            }
        }
    }
    assert!(scanned > 100, "scanner found only {scanned} redirects — it is not looking at the source");
    assert!(bad.is_empty(), "non-ASCII in a redirect target:\n{}", bad.join("\n"));
}
