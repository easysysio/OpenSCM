// sso_login.rs — signing in through a tenant's OpenID Connect provider.
//
// A fake provider runs inside the test: it serves a discovery document and its
// public keys, and its token endpoint issues whatever ID token the test asks
// for — correctly signed, or wrong in exactly one way. The real routes run
// against it and each test plays the browser: POST /auth/sso/start, follow to
// the "provider", come back to /auth/sso/callback.
//
// Every check in docs/design/0.10.0-sso.md §4.1 has a test here in which a
// token or callback that violates it is refused. Getting one of them wrong is
// not a bug, it is a way to sign in as someone else.
//
// Single sign-on is SaaS-only, so this process runs in SaaS mode. The routes
// are given the relaxed URL rules through the SsoUrlRules extension, which is
// how they can talk to a provider on a local port; in production that
// extension is never present and the rules are strict.

use axum::body::Body;
use axum::extract::{Extension, Form, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Key;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use scmserver::models::AuthSession;
use scmserver::sso_login::{pkce_challenge, SsoUrlRules};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const RSA_DER_B64: &str = include_str!("fixtures/sso_test_rsa_key.der.b64");
const RSA_MODULUS: &str = include_str!("fixtures/sso_test_rsa_modulus.txt");
const CLIENT_ID: &str = "openscm-client";
const CLIENT_SECRET: &str = "client+secret/with=odd chars";
const APP_URL: &str = "http://scm.test";

// ── the fake provider ───────────────────────────────────────────────────────
#[derive(Clone, Copy, PartialEq, Debug)]
enum Signer {
    Rsa,
    Ed,
    /// An Ed25519 key the provider does NOT publish, under the published key id.
    Forged,
    /// A key id the provider does not publish at all.
    UnknownKid,
    /// HMAC with the client secret — the classic algorithm-confusion attack.
    Hs256,
    /// {"alg":"none"} and no signature.
    Unsigned,
}

struct IdpState {
    claims: Value,
    signer: Signer,
    expected_challenge: String,
    token_status: u16,
    omit_id_token: bool,
    token_calls: usize,
    last_form: HashMap<String, String>,
    last_authorization: Option<String>,
}

#[derive(Clone)]
struct Idp {
    base: String,
    state: Arc<Mutex<IdpState>>,
    ed_seed: [u8; 32],
}

fn ed_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    // PKCS#8 v1 wrapper for an Ed25519 seed.
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(seed);
    der
}

impl Idp {
    fn sign(&self, claims: &Value, signer: Signer) -> String {
        let with = |alg, kid: &str, key: EncodingKey| {
            let mut h = Header::new(alg);
            h.kid = Some(kid.to_string());
            jsonwebtoken::encode(&h, claims, &key).unwrap()
        };
        match signer {
            Signer::Rsa => with(Algorithm::RS256, "rsa-1", EncodingKey::from_rsa_der(&STANDARD.decode(RSA_DER_B64.trim()).unwrap())),
            Signer::Ed => with(Algorithm::EdDSA, "ed-1", EncodingKey::from_ed_der(&ed_pkcs8(&self.ed_seed))),
            Signer::Forged => with(Algorithm::EdDSA, "ed-1", EncodingKey::from_ed_der(&ed_pkcs8(&[9u8; 32]))),
            Signer::UnknownKid => with(Algorithm::EdDSA, "ghost", EncodingKey::from_ed_der(&ed_pkcs8(&self.ed_seed))),
            Signer::Hs256 => with(Algorithm::HS256, "rsa-1", EncodingKey::from_secret(CLIENT_SECRET.as_bytes())),
            Signer::Unsigned => format!(
                "{}.{}.",
                URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            ),
        }
    }
}

async fn idp_token(State(idp): State<Idp>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    let mut s = idp.state.lock().unwrap();
    s.token_calls += 1;
    s.last_authorization = headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
    s.last_form = form.clone();
    // A real provider verifies PKCE: the verifier must hash to the challenge
    // it was given when the sign-in started.
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if pkce_challenge(&verifier) != s.expected_challenge {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant", "error_description": "PKCE" })));
    }
    if s.token_status != 200 {
        return (StatusCode::from_u16(s.token_status).unwrap(), Json(json!({ "error": "invalid_client" })));
    }
    let mut reply = json!({ "access_token": "at", "token_type": "Bearer", "expires_in": 300 });
    if !s.omit_id_token {
        reply["id_token"] = json!(idp.sign(&s.claims, s.signer));
    }
    (StatusCode::OK, Json(reply))
}

// Starts a provider. `auth_methods` is what it advertises for the token endpoint.
async fn start_idp(auth_methods: Option<Vec<&'static str>>) -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let ed_seed = rand::random::<[u8; 32]>();
    let ed_public = ed25519_dalek::SigningKey::from_bytes(&ed_seed).verifying_key().to_bytes();
    let idp = Idp {
        base: base.clone(),
        ed_seed,
        state: Arc::new(Mutex::new(IdpState {
            claims: json!({}), signer: Signer::Rsa, expected_challenge: String::new(), token_status: 200,
            omit_id_token: false, token_calls: 0, last_form: HashMap::new(), last_authorization: None,
        })),
    };
    let mut doc = json!({
        "issuer": base, "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/keys"),
        "id_token_signing_alg_values_supported": ["RS256", "EdDSA"]
    });
    if let Some(m) = auth_methods {
        doc["token_endpoint_auth_methods_supported"] = json!(m);
    }
    let keys = json!({ "keys": [
        { "kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256", "n": RSA_MODULUS.trim(), "e": "AQAB" },
        { "kty": "OKP", "crv": "Ed25519", "kid": "ed-1", "use": "sig", "alg": "EdDSA", "x": URL_SAFE_NO_PAD.encode(ed_public) },
        // A key this server cannot represent must not hide the usable ones.
        { "kty": "RSA", "kid": "enc-1", "use": "enc", "alg": "RSA-OAEP-512", "n": RSA_MODULUS.trim(), "e": "AQAB" },
        { "kty": "weird", "kid": "w-1" }
    ]});
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(move || { let d = doc.clone(); async move { Json(d) } }))
        .route("/keys", get(move || { let k = keys.clone(); async move { Json(k) } }))
        .route("/token", post(idp_token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

// ── the server under test ───────────────────────────────────────────────────
struct World {
    pool: SqlitePool,
    idp: Idp,
}

fn key() -> Key { Key::from(&[7u8; 64]) }

async fn world_with(auth_methods: Option<Vec<&'static str>>) -> World {
    scmserver::handlers::enable_saas_mode();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    let idp = start_idp(auth_methods).await;
    for q in [
        "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme')".to_string(),
        "INSERT INTO tenants (id, name) VALUES ('globex', 'Globex')".to_string(),
        "INSERT INTO users (id, tenant_id, username, password, role, email) VALUES (20, 'acme', 'bob', 'x', 'admin', 'Bob@Acme.example')".to_string(),
        "INSERT INTO users (id, tenant_id, username, password, role, email) VALUES (21, 'acme', 'carol', 'x', 'viewer', 'carol@acme.example')".to_string(),
        "INSERT INTO users (id, tenant_id, username, password, role, email) VALUES (30, 'globex', 'gina', 'x', 'admin', 'gina@globex.example')".to_string(),
        format!("INSERT OR REPLACE INTO settings (tenant_id, skey, value) VALUES ('default', 'app_url', '{APP_URL}')"),
    ] {
        sqlx::query(&q).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret) VALUES ('acme', 1, 'Acme IdP', ?, ?, ?)")
        .bind(&idp.base).bind(CLIENT_ID).bind(CLIENT_SECRET).execute(&pool).await.unwrap();
    World { pool, idp }
}
async fn world() -> World { world_with(None).await }

async fn me(a: AuthSession) -> String {
    format!("{}:{}:{}", a.username, a.role, a.tenant_id)
}

impl World {
    fn app(&self) -> Router {
        Router::new()
            .route("/auth/sso/start", post(scmserver::sso_login::sso_start))
            .route("/auth/sso/callback", get(scmserver::sso_login::sso_callback))
            .route("/me", get(me))
            .layer(Extension(self.pool.clone()))
            // Relaxed URL rules: the provider is on a local port. Never present in production.
            .layer(Extension(SsoUrlRules { strict: false }))
            .with_state(key())
    }

    async fn send(&self, req: Request<Body>) -> Reply {
        let resp = self.app().oneshot(req).await.unwrap();
        let status = resp.status();
        let location = resp.headers().get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        let mut cookies = HashMap::new();
        for c in resp.headers().get_all("set-cookie") {
            let first = c.to_str().unwrap().split(';').next().unwrap();
            let (k, v) = first.split_once('=').unwrap();
            cookies.insert(k.to_string(), v.to_string());
        }
        let body = String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap()).to_string();
        Reply { status, location, cookies, body }
    }

    async fn start(&self, organization: &str) -> Reply {
        self.send(Request::post("/auth/sso/start")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("organization={}", urlencoding::encode(organization)))).unwrap()).await
    }

    async fn callback(&self, query: &str, flow_cookie: Option<&str>) -> Reply {
        let mut req = Request::get(format!("/auth/sso/callback?{query}"));
        if let Some(c) = flow_cookie {
            req = req.header("cookie", format!("sso_flow={c}"));
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    async fn whoami(&self, session: &str) -> Option<String> {
        let r = self.send(Request::get("/me").header("cookie", format!("session={session}")).body(Body::empty()).unwrap()).await;
        (r.status == StatusCode::OK).then_some(r.body)
    }

    // The claims a well-behaved provider would issue for this sign-in.
    fn good_claims(&self, nonce: &str) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "iss": self.idp.base, "aud": CLIENT_ID, "sub": "idp-subject-bob", "iat": now, "exp": now + 300,
            "nonce": nonce, "email": "bob@acme.example", "email_verified": true
        })
    }

    // A whole sign-in for 'Acme'. `edit` alters the claims the provider issues.
    async fn sign_in_as(&self, signer: Signer, edit: impl FnOnce(&mut Value)) -> Reply {
        let started = self.start("Acme").await;
        assert_eq!(started.status, StatusCode::SEE_OTHER, "start failed: {}", started.location);
        let params = query_of(&started.location);
        let flow = started.cookies.get("sso_flow").expect("the flow cookie is set").clone();
        {
            let mut s = self.idp.state.lock().unwrap();
            let mut claims = self.good_claims(&params["nonce"]);
            edit(&mut claims);
            s.claims = claims;
            s.signer = signer;
            s.expected_challenge = params["code_challenge"].clone();
        }
        self.callback(&format!("code=the-code&state={}", params["state"]), Some(&flow)).await
    }
    async fn sign_in(&self, edit: impl FnOnce(&mut Value)) -> Reply {
        self.sign_in_as(Signer::Rsa, edit).await
    }

    // Refused, AND for the stated reason. "Refused" alone proves little: a
    // token can be turned away for a reason other than the one under test, and
    // the test would pass while the check it names did nothing. The server
    // records the specific cause of every failed sign-in in the audit log.
    async fn refused(&self, r: &Reply, why: &str, reason: &str) {
        r.assert_refused(why);
        let recorded: String = sqlx::query_scalar(
            "SELECT COALESCE(details, '') FROM audit_log WHERE action = 'auth.login_failure' ORDER BY id DESC LIMIT 1",
        ).fetch_optional(&self.pool).await.unwrap().unwrap_or_default();
        let d: serde_json::Value = serde_json::from_str(&recorded).unwrap_or_default();
        assert_eq!(d["method"], "sso", "{why}: {recorded}");
        assert!(d["reason"].as_str().unwrap_or("").contains(reason),
                "{why}: refused, but for the wrong reason.\n  expected: {reason}\n  recorded: {recorded}");
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }
    async fn subject_of(&self, user_id: i64) -> Option<String> {
        sqlx::query_scalar("SELECT sso_subject FROM users WHERE id = ?").bind(user_id).fetch_one(&self.pool).await.unwrap()
    }
}

struct Reply {
    status: StatusCode,
    location: String,
    cookies: HashMap<String, String>,
    body: String,
}

impl Reply {
    fn signed_in(&self) -> bool {
        self.location == "/" && self.cookies.get("session").is_some_and(|v| !v.is_empty())
    }
    fn message(&self) -> String {
        urlencoding::decode(&self.location).unwrap().into_owned()
    }
    // Refused: back at the sign-in page, with no session.
    fn assert_refused(&self, why: &str) {
        assert!(self.location.starts_with("/login?error_message="), "{why}: expected a refusal, got {}", self.location);
        assert!(!self.cookies.contains_key("session"), "{why}: a session cookie was issued");
    }
}

fn query_of(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url).unwrap().query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}

const GENERIC: &str = "Single sign-on did not complete";

// ── the happy path ──────────────────────────────────────────────────────────
#[tokio::test]
async fn a_valid_sign_in_creates_a_session_for_the_matching_user() {
    let w = world().await;
    let r = w.sign_in(|_| {}).await;
    assert!(r.signed_in(), "expected to be signed in, got {}", r.message());

    // The session is a normal one: the user and role come from the database.
    assert_eq!(w.whoami(&r.cookies["session"]).await.as_deref(), Some("bob:admin:acme"));
    // First sign-in bound the provider's subject to bob (matched by verified email, any letter case).
    assert_eq!(w.subject_of(20).await.as_deref(), Some("idp-subject-bob"));
    assert_eq!(w.count("SELECT COUNT(*) FROM sso_login_state").await, 0, "the state is spent");
    assert!(r.cookies.get("sso_flow").is_some_and(|v| v.is_empty()), "the flow cookie is cleared");
    assert_eq!(w.count("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login_success' AND json_extract(details, '$.method') = 'sso' AND tenant_id = 'acme'").await, 1);
}

#[tokio::test]
async fn the_browser_is_sent_to_the_provider_with_the_right_request() {
    let w = world().await;
    let started = w.start("  ACME ").await;
    assert_eq!(started.status, StatusCode::SEE_OTHER);
    assert!(started.location.starts_with(&format!("{}/authorize?", w.idp.base)));
    let p = query_of(&started.location);
    assert_eq!(p["response_type"], "code");
    assert_eq!(p["client_id"], CLIENT_ID);
    assert_eq!(p["redirect_uri"], format!("{APP_URL}/auth/sso/callback"));
    assert_eq!(p["code_challenge_method"], "S256");
    assert!(p["scope"].split(' ').any(|s| s == "openid") && p["scope"].contains("email"));
    assert!(p["state"].len() >= 43 && p["nonce"].len() >= 43 && p["code_challenge"].len() == 43);
    assert_ne!(p["state"], p["nonce"]);
    // The secrets of the flow stay on the server.
    assert!(!started.location.contains(CLIENT_SECRET));
    let (nonce, verifier): (String, String) = sqlx::query_as("SELECT nonce, pkce_verifier FROM sso_login_state WHERE state = ?")
        .bind(&p["state"]).fetch_one(&w.pool).await.unwrap();
    assert_eq!(nonce, p["nonce"]);
    assert_eq!(pkce_challenge(&verifier), p["code_challenge"]);
    assert!(!started.location.contains(&verifier), "the PKCE verifier must not leave the server");
    assert_eq!(started.cookies["sso_flow"].is_empty(), false);
}

#[tokio::test]
async fn the_code_is_exchanged_with_pkce_and_the_client_secret() {
    let w = world().await;
    assert!(w.sign_in(|_| {}).await.signed_in());
    let s = w.idp.state.lock().unwrap();
    assert_eq!(s.token_calls, 1);
    assert_eq!(s.last_form["grant_type"], "authorization_code");
    assert_eq!(s.last_form["code"], "the-code");
    assert_eq!(s.last_form["redirect_uri"], format!("{APP_URL}/auth/sso/callback"));
    assert_eq!(pkce_challenge(&s.last_form["code_verifier"]), s.expected_challenge, "the verifier matches the challenge");
    // client_secret_basic by default: form-encoded, then Basic.
    let expect = format!("Basic {}", STANDARD.encode(format!("{}:{}", urlencoding::encode(CLIENT_ID), urlencoding::encode(CLIENT_SECRET))));
    assert_eq!(s.last_authorization.as_deref(), Some(expect.as_str()));
    assert!(!s.last_form.contains_key("client_secret"), "the secret goes in the header, not also the body");
}

#[tokio::test]
async fn a_provider_that_only_takes_the_secret_in_the_form_gets_it_there() {
    let w = world_with(Some(vec!["client_secret_post"])).await;
    assert!(w.sign_in(|_| {}).await.signed_in());
    let s = w.idp.state.lock().unwrap();
    assert_eq!(s.last_form["client_id"], CLIENT_ID);
    assert_eq!(s.last_form["client_secret"], CLIENT_SECRET);
    assert!(s.last_authorization.is_none());
}

#[tokio::test]
async fn an_eddsa_signed_token_is_accepted_and_later_sign_ins_match_by_subject() {
    let w = world().await;
    assert!(w.sign_in_as(Signer::Ed, |_| {}).await.signed_in());
    // The address changes at the provider; the subject does not.
    let r = w.sign_in_as(Signer::Ed, |c| { c["email"] = json!("robert@acme.example"); c["email_verified"] = json!(false); }).await;
    assert!(r.signed_in(), "{}", r.message());
    assert_eq!(w.whoami(&r.cookies["session"]).await.as_deref(), Some("bob:admin:acme"));
}

// ── §4.1: every check, refusing ─────────────────────────────────────────────
#[tokio::test]
async fn a_token_for_another_application_is_refused() {
    let w = world().await;
    let r = w.sign_in(|c| c["aud"] = json!("some-other-client")).await;
    w.refused(&r, "wrong aud", "InvalidAudience").await;
    assert!(r.message().contains(GENERIC));
    // One of several audiences is fine only if we are among them…
    assert!(w.sign_in(|c| c["aud"] = json!(["another", CLIENT_ID])).await.signed_in());
    // …and the token was issued TO us.
    w.refused(&w.sign_in(|c| { c["aud"] = json!(["another", CLIENT_ID]); c["azp"] = json!("another"); }).await, "azp", "different application (azp)").await;
}

#[tokio::test]
async fn a_token_from_another_issuer_is_refused() {
    let w = world().await;
    w.refused(&w.sign_in(|c| c["iss"] = json!("https://accounts.attacker.example")).await, "wrong iss", "InvalidIssuer").await;
    let base = w.idp.base.clone();
    w.refused(&w.sign_in(move |c| c["iss"] = json!(format!("{base}/"))).await, "iss must match exactly", "InvalidIssuer").await;
}

#[tokio::test]
async fn an_expired_or_not_yet_valid_token_is_refused() {
    let w = world().await;
    let now = chrono::Utc::now().timestamp();
    w.refused(&w.sign_in(move |c| c["exp"] = json!(now - 600)).await, "expired", "ExpiredSignature").await;
    w.refused(&w.sign_in(move |c| c["nbf"] = json!(now + 600)).await, "not yet valid", "ImmatureSignature").await;
    w.refused(&w.sign_in(|c| { c.as_object_mut().unwrap().remove("exp"); }).await, "no exp", "exp").await;
    // A few seconds of clock difference is tolerated.
    assert!(w.sign_in(move |c| c["exp"] = json!(now - 5)).await.signed_in());
}

#[tokio::test]
async fn a_token_the_provider_did_not_sign_is_refused() {
    let w = world().await;
    w.refused(&w.sign_in_as(Signer::Forged, |_| {}).await, "signed with a key the provider does not hold", "InvalidSignature").await;
    w.refused(&w.sign_in_as(Signer::UnknownKid, |_| {}).await, "names a key the provider does not publish", "does not publish").await;
    // The provider's real keys still work afterwards.
    assert!(w.sign_in_as(Signer::Ed, |_| {}).await.signed_in());
}

// "Signed" with the client secret, or not at all: both are attacks, not tokens.
#[tokio::test]
async fn symmetric_and_unsigned_tokens_are_refused() {
    let w = world().await;
    w.refused(&w.sign_in_as(Signer::Hs256, |_| {}).await, "HS256", "HS256, which is not accepted").await;
    w.refused(&w.sign_in_as(Signer::Unsigned, |_| {}).await, "alg none", "unreadable token header").await;
    assert_eq!(w.subject_of(20).await, None, "nothing was bound by a refused token");
}

#[tokio::test]
async fn a_token_from_a_different_sign_in_is_refused() {
    let w = world().await;
    w.refused(&w.sign_in(|c| c["nonce"] = json!("a-nonce-from-some-other-sign-in")).await, "wrong nonce", "nonce does not match").await;
    w.refused(&w.sign_in(|c| { c.as_object_mut().unwrap().remove("nonce"); }).await, "no nonce", "carries no nonce").await;
    w.refused(&w.sign_in(|c| c["sub"] = json!("")).await, "empty subject", "empty subject").await;
}

// ── state: single use, time-limited, and tied to the browser ────────────────
#[tokio::test]
async fn a_callback_cannot_be_replayed() {
    let w = world().await;
    let started = w.start("Acme").await;
    let p = query_of(&started.location);
    let flow = started.cookies["sso_flow"].clone();
    {
        let mut s = w.idp.state.lock().unwrap();
        s.claims = w.good_claims(&p["nonce"]);
        s.expected_challenge = p["code_challenge"].clone();
    }
    let q = format!("code=the-code&state={}", p["state"]);
    assert!(w.callback(&q, Some(&flow)).await.signed_in());
    // The very same link and cookie, again.
    w.callback(&q, Some(&flow)).await.assert_refused("replayed callback");
    assert_eq!(w.idp.state.lock().unwrap().token_calls, 1, "the replay never reached the provider");
}

#[tokio::test]
async fn an_unknown_or_expired_state_is_refused() {
    let w = world().await;
    // The signed cookie can only come from this server, so "unknown state"
    // means a state that was already spent or swept.
    let started = w.start("Acme").await;
    let p = query_of(&started.location);
    let flow = started.cookies["sso_flow"].clone();
    sqlx::query("UPDATE sso_login_state SET created_at = datetime('now', '-11 minutes')").execute(&w.pool).await.unwrap();
    w.refused(&w.callback(&format!("code=c&state={}", p["state"]), Some(&flow)).await, "expired state", "state expired").await;
    assert_eq!(w.count("SELECT COUNT(*) FROM sso_login_state").await, 0, "an expired state is spent, not left lying");
    assert_eq!(w.idp.state.lock().unwrap().token_calls, 0);
}

// Login CSRF: an attacker starts a sign-in and hands the victim the callback.
#[tokio::test]
async fn a_callback_in_a_browser_that_did_not_start_it_is_refused() {
    let w = world().await;
    let started = w.start("Acme").await;
    let p = query_of(&started.location);
    {
        let mut s = w.idp.state.lock().unwrap();
        s.claims = w.good_claims(&p["nonce"]);
        s.expected_challenge = p["code_challenge"].clone();
    }
    let q = format!("code=the-code&state={}", p["state"]);

    w.callback(&q, None).await.assert_refused("no flow cookie");
    // A cookie from the victim's own, different, sign-in does not help.
    let other = w.start("Acme").await.cookies["sso_flow"].clone();
    w.callback(&q, Some(&other)).await.assert_refused("another sign-in's cookie");
    // An unsigned, hand-made cookie carrying the right state is not a cookie this server set.
    w.callback(&q, Some(&p["state"])).await.assert_refused("forged cookie");

    assert_eq!(w.idp.state.lock().unwrap().token_calls, 0, "none of these reached the provider");
    assert_eq!(w.count("SELECT COUNT(*) FROM sso_login_state").await, 2, "the attacker's attempts spent nobody's state");
    // The browser that DID start it can still finish.
    assert!(w.callback(&q, Some(&started.cookies["sso_flow"])).await.signed_in());
}

#[tokio::test]
async fn a_refusal_at_the_provider_is_reported_and_spends_the_state() {
    let w = world().await;
    let started = w.start("Acme").await;
    let p = query_of(&started.location);
    let r = w.callback(&format!("error=access_denied&state={}", p["state"]), Some(&started.cookies["sso_flow"])).await;
    w.refused(&r, "provider error", "provider returned error 'access_denied'").await;
    assert!(r.message().contains("cancelled or refused at your provider"), "{}", r.message());
    assert_eq!(w.count("SELECT COUNT(*) FROM sso_login_state").await, 0);
}

#[tokio::test]
async fn abandoned_sign_ins_are_swept_when_a_new_one_starts() {
    let w = world().await;
    for _ in 0..3 { w.start("Acme").await; }
    sqlx::query("UPDATE sso_login_state SET created_at = datetime('now', '-30 minutes')").execute(&w.pool).await.unwrap();
    w.start("Acme").await;
    assert_eq!(w.count("SELECT COUNT(*) FROM sso_login_state").await, 1, "only the new sign-in remains");
}

// ── who the provider's identity is here ─────────────────────────────────────
#[tokio::test]
async fn someone_with_no_account_is_refused_and_no_account_is_created() {
    let w = world().await;
    let users = w.count("SELECT COUNT(*) FROM users").await;
    let r = w.sign_in(|c| { c["sub"] = json!("a-stranger"); c["email"] = json!("stranger@acme.example"); }).await;
    w.refused(&r, "no matching user", "no user matches this subject or email").await;
    assert!(r.message().contains("there is no OpenSCM account for you"), "{}", r.message());
    assert_eq!(w.count("SELECT COUNT(*) FROM users").await, users, "single sign-on never creates an account");
    assert_eq!(w.count("SELECT COUNT(*) FROM users WHERE sso_subject IS NOT NULL").await, 0);
}

// Without this, a provider where people set their own address lets anyone
// claim another user's account by typing their email.
#[tokio::test]
async fn an_unverified_email_does_not_match_an_account() {
    let w = world().await;
    for unverified in [json!(false), json!("false"), json!(null), json!(0)] {
        w.refused(&w.sign_in(move |c| c["email_verified"] = unverified).await, "email not verified", "has not verified the email").await;
    }
    w.refused(&w.sign_in(|c| { c.as_object_mut().unwrap().remove("email_verified"); }).await, "claim absent", "has not verified the email").await;
    w.refused(&w.sign_in(|c| { c.as_object_mut().unwrap().remove("email"); }).await, "no email at all", "has no email").await;
    assert_eq!(w.subject_of(20).await, None);
    // Some providers send the string.
    assert!(w.sign_in(|c| c["email_verified"] = json!("true")).await.signed_in());
}

// ── "Trust email addresses from this provider" ──────────────────────────────
// Some providers never send email_verified (Microsoft Entra ID's default ID
// token, for one). With the verified-only rule none of their users could ever
// be matched, so a tenant can say its provider's addresses are to be believed.
async fn trust_provider_emails(w: &World) {
    sqlx::query("UPDATE sso_providers SET trust_email = 1 WHERE tenant_id = 'acme'").execute(&w.pool).await.unwrap();
}

fn without_email_verified(c: &mut Value) {
    c.as_object_mut().unwrap().remove("email_verified");
}

#[tokio::test]
async fn a_trusted_provider_matches_by_email_when_it_says_nothing_about_verification() {
    let w = world().await;
    // Off (the default): a silent provider matches nobody.
    w.refused(&w.sign_in(without_email_verified).await, "trust off", "has not verified the email").await;
    assert_eq!(w.subject_of(20).await, None);

    trust_provider_emails(&w).await;
    let r = w.sign_in(without_email_verified).await;
    assert!(r.signed_in(), "{}", r.message());
    assert_eq!(w.whoami(&r.cookies["session"]).await.as_deref(), Some("bob:admin:acme"));
    assert_eq!(w.subject_of(20).await.as_deref(), Some("idp-subject-bob"), "linked, as with a verified address");
    // JSON null is "not stated", the same as absent.
    sqlx::query("UPDATE users SET sso_subject = NULL WHERE id = 20").execute(&w.pool).await.unwrap();
    assert!(w.sign_in(|c| c["email_verified"] = json!(null)).await.signed_in());
}

// Trusting a silent provider is not the same as overruling one that speaks.
#[tokio::test]
async fn a_trusted_provider_that_says_the_address_is_unverified_is_still_refused() {
    let w = world().await;
    trust_provider_emails(&w).await;
    for stated in [json!(false), json!("false"), json!(0)] {
        w.refused(&w.sign_in(move |c| c["email_verified"] = stated).await, "explicitly unverified", "has not verified the email").await;
    }
    assert_eq!(w.subject_of(20).await, None);
    // And a verified address works exactly as before.
    assert!(w.sign_in(|_| {}).await.signed_in());
}

// Trust changes only whether the address is believed. Every other rule holds.
#[tokio::test]
async fn trusting_a_provider_relaxes_nothing_else() {
    let w = world().await;
    trust_provider_emails(&w).await;

    // Still no account → still refused, still nothing created.
    let users = w.count("SELECT COUNT(*) FROM users").await;
    w.refused(&w.sign_in(|c| { without_email_verified(c); c["sub"] = json!("x"); c["email"] = json!("stranger@acme.example"); }).await,
              "no such user", "no user matches this subject or email").await;
    assert_eq!(w.count("SELECT COUNT(*) FROM users").await, users);

    // Still no email → nothing to match on.
    w.refused(&w.sign_in(|c| { without_email_verified(c); c.as_object_mut().unwrap().remove("email"); }).await,
              "no email", "has no email").await;

    // Still never another tenant's user, even with their exact address.
    w.refused(&w.sign_in(|c| { without_email_verified(c); c["sub"] = json!("y"); c["email"] = json!("gina@globex.example"); }).await,
              "another tenant's address", "no user matches this subject or email").await;

    // Still not an account already linked to a different identity.
    assert!(w.sign_in(without_email_verified).await.signed_in());
    w.refused(&w.sign_in(|c| { without_email_verified(c); c["sub"] = json!("someone-else"); }).await,
              "linked account, other identity", "no user matches this subject or email").await;

    // Still not a guess between two users.
    sqlx::query("UPDATE users SET sso_subject = NULL WHERE id = 20").execute(&w.pool).await.unwrap();
    sqlx::query("UPDATE users SET email = 'bob@acme.example' WHERE id = 21").execute(&w.pool).await.unwrap();
    w.refused(&w.sign_in(without_email_verified).await, "shared address", "users share this email").await;

    // And the token itself is checked as strictly as ever.
    w.refused(&w.sign_in_as(Signer::Forged, without_email_verified).await, "forged", "InvalidSignature").await;
}

// The setting belongs to one tenant's provider.
#[tokio::test]
async fn trust_is_per_tenant() {
    let w = world().await;
    sqlx::query("INSERT INTO sso_providers (tenant_id, enabled, name, issuer_url, client_id, client_secret, trust_email)
                 VALUES ('globex', 0, 'Globex', 'https://login.example.com', 'g', 's', 1)").execute(&w.pool).await.unwrap();
    // globex trusts its provider; acme has not said so.
    w.refused(&w.sign_in(without_email_verified).await, "acme did not opt in", "has not verified the email").await;
}

// A trusted address also counts as the account's email verification, or a
// SaaS user who never confirmed theirs would be signed in and then turned away.
#[tokio::test]
async fn a_trusted_address_verifies_the_account_too() {
    let w = world().await;
    trust_provider_emails(&w).await;
    sqlx::query("UPDATE users SET email_verified = 0 WHERE id = 20").execute(&w.pool).await.unwrap();
    let r = w.sign_in(without_email_verified).await;
    assert!(r.signed_in());
    assert_eq!(w.count("SELECT email_verified FROM users WHERE id = 20").await, 1);
    assert!(w.whoami(&r.cookies["session"]).await.is_some());
}

#[tokio::test]
async fn an_address_shared_by_two_users_is_not_guessed_at() {
    let w = world().await;
    sqlx::query("UPDATE users SET email = 'bob@acme.example' WHERE id = 21").execute(&w.pool).await.unwrap();
    let r = w.sign_in(|_| {}).await;
    w.refused(&r, "ambiguous email", "users share this email").await;
    assert_eq!((w.subject_of(20).await, w.subject_of(21).await), (None, None));
}

// A second identity with the same address cannot take over a bound account.
#[tokio::test]
async fn an_account_bound_to_one_identity_is_not_matched_by_email_for_another() {
    let w = world().await;
    assert!(w.sign_in(|_| {}).await.signed_in());
    let r = w.sign_in(|c| c["sub"] = json!("a-different-identity")).await;
    w.refused(&r, "same email, different subject", "no user matches this subject or email").await;
    assert_eq!(w.subject_of(20).await.as_deref(), Some("idp-subject-bob"), "the binding is unchanged");
}

// A subject is only meaningful inside the tenant whose provider issued it.
#[tokio::test]
async fn an_identity_never_resolves_to_a_user_in_another_tenant() {
    let w = world().await;
    sqlx::query("UPDATE users SET sso_subject = 'shared-subject' WHERE id = 30").execute(&w.pool).await.unwrap();
    // Acme's provider issues the same subject, and even gina's verified address.
    let r = w.sign_in(|c| { c["sub"] = json!("shared-subject"); c["email"] = json!("gina@globex.example"); }).await;
    w.refused(&r, "subject and email belong to a user in another tenant", "no user matches this subject or email").await;
    assert_eq!(w.count("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login_success'").await, 0);
}

#[tokio::test]
async fn a_verified_address_from_the_provider_verifies_the_account() {
    let w = world().await;
    // A SaaS user who never clicked their confirmation link.
    sqlx::query("UPDATE users SET email_verified = 0 WHERE id = 20").execute(&w.pool).await.unwrap();
    let r = w.sign_in(|_| {}).await;
    assert!(r.signed_in());
    assert_eq!(w.count("SELECT email_verified FROM users WHERE id = 20").await, 1);
    // …so the session is not turned away by the per-request check.
    assert_eq!(w.whoami(&r.cookies["session"]).await.as_deref(), Some("bob:admin:acme"));
}

#[tokio::test]
async fn a_suspended_organization_cannot_sign_in() {
    let w = world().await;
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = 'acme'").execute(&w.pool).await.unwrap();
    let r = w.sign_in(|_| {}).await;
    w.refused(&r, "suspended tenant", "tenant is suspended").await;
    assert!(r.message().contains("suspended"), "{}", r.message());
    assert_eq!(w.subject_of(20).await, None, "nothing is bound for a suspended organization");
}

// ── the provider misbehaving ────────────────────────────────────────────────
#[tokio::test]
async fn a_failed_or_empty_token_exchange_is_refused() {
    let w = world().await;
    w.idp.state.lock().unwrap().token_status = 401;
    let r = w.sign_in(|_| {}).await;
    w.refused(&r, "token endpoint said 401", "HTTP 401").await;
    assert!(r.message().contains(GENERIC) && !r.message().contains("invalid_client"), "the provider's error is not shown: {}", r.message());
    {
        let mut s = w.idp.state.lock().unwrap();
        s.token_status = 200;
        s.omit_id_token = true;
    }
    w.refused(&w.sign_in(|_| {}).await, "no id_token in the reply", "no id_token").await;
    let reasons: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_log WHERE action = 'auth.login_failure' ORDER BY id")
        .fetch_all(&w.pool).await.unwrap();
    assert!(reasons[0].contains("HTTP 401") && reasons[1].contains("no id_token"), "the audit log has the real reasons: {reasons:?}");
}

// ── starting ────────────────────────────────────────────────────────────────
// Which organizations exist, and which use SSO, is not for strangers to learn.
#[tokio::test]
async fn organizations_without_sso_and_ones_that_do_not_exist_look_the_same() {
    let w = world().await;
    let unknown = w.start("No Such Company").await;
    let no_sso = w.start("Globex").await;
    let empty = w.start("   ").await;
    sqlx::query("UPDATE sso_providers SET enabled = 0").execute(&w.pool).await.unwrap();
    let disabled = w.start("Acme").await;
    for r in [&unknown, &no_sso, &empty, &disabled] {
        r.assert_refused("no provider");
        assert_eq!(r.location, unknown.location, "every case must answer identically");
        assert!(!r.cookies.contains_key("sso_flow"));
    }
    assert!(unknown.message().contains("not set up for this organization"));
    assert_eq!(w.count("SELECT COUNT(*) FROM sso_login_state").await, 0);
}

// A provider switched off mid-sign-in is off.
#[tokio::test]
async fn disabling_the_provider_stops_sign_ins_already_under_way() {
    let w = world().await;
    let started = w.start("Acme").await;
    let p = query_of(&started.location);
    sqlx::query("UPDATE sso_providers SET enabled = 0").execute(&w.pool).await.unwrap();
    w.refused(&w.callback(&format!("code=c&state={}", p["state"]), Some(&started.cookies["sso_flow"])).await, "provider disabled", "disabled or removed during sign-in").await;
    assert_eq!(w.idp.state.lock().unwrap().token_calls, 0);
}

// ── unlink ──────────────────────────────────────────────────────────────────
fn session_for(tenant: &str, role: &str, userid: i32) -> AuthSession {
    AuthSession { username: "x".into(), userid, tenant_id: tenant.into(), role: role.into(), impersonating: None }
}

async fn unlink_reply(w: &World, who: AuthSession, user_id: i64) -> axum::response::Response {
    scmserver::sso::user_unlink(
        who, Extension(w.pool.clone()), scmserver::handlers::ClientIp("127.0.0.1".into()),
        axum_extra::extract::cookie::SignedCookieJar::new(key()), axum::extract::Path(user_id),
    ).await
}

async fn unlink(w: &World, who: AuthSession, user_id: i64) -> String {
    let resp = unlink_reply(w, who, user_id).await;
    urlencoding::decode(resp.headers().get("location").unwrap().to_str().unwrap()).unwrap().into_owned()
}

#[tokio::test]
async fn an_admin_can_unlink_a_user_which_signs_them_out() {
    let w = world().await;
    let r = w.sign_in(|_| {}).await;
    let session = r.cookies["session"].clone();
    assert!(w.whoami(&session).await.is_some());

    // Not for a viewer, and not for another tenant's admin.
    assert!(unlink(&w, session_for("acme", "viewer", 21), 20).await.contains("Unauthorized"));
    assert!(unlink(&w, session_for("globex", "admin", 30), 20).await.contains("not linked"), "another tenant's user is simply not found");
    assert_eq!(w.subject_of(20).await.as_deref(), Some("idp-subject-bob"));

    let to = unlink(&w, session_for("acme", "admin", 21), 20).await;
    assert!(to.starts_with("/users/edit/20?success_message="), "{to}");
    assert_eq!(w.subject_of(20).await, None);
    assert_eq!(w.whoami(&session).await, None, "the linked person's session ends");
    assert_eq!(w.count("SELECT COUNT(*) FROM audit_log WHERE action = 'sso.user_unlink' AND target_id = '20'").await, 1);

    assert!(unlink(&w, session_for("acme", "admin", 21), 20).await.contains("not linked"), "nothing to unlink twice");
    // Signing in again links afresh, by the same rules.
    assert!(w.sign_in(|c| c["sub"] = json!("bobs-new-identity")).await.signed_in());
    assert_eq!(w.subject_of(20).await.as_deref(), Some("bobs-new-identity"));
}

// The rightful owner of an account, unlinking a wrong binding on it, must not
// sign themselves out along with the person who was wrongly linked.
#[tokio::test]
async fn unlinking_your_own_account_keeps_this_browser_signed_in() {
    let w = world().await;
    // Someone signed in to bob's account through the provider…
    let linked_session = w.sign_in(|_| {}).await.cookies["session"].clone();
    assert!(w.whoami(&linked_session).await.is_some());

    // …and bob, an admin, unlinks it from his own session.
    let resp = unlink_reply(&w, session_for("acme", "admin", 20), 20).await;
    let to = urlencoding::decode(resp.headers().get("location").unwrap().to_str().unwrap()).unwrap().into_owned();
    assert!(to.contains("success_message") && to.contains("other sessions"), "{to}");
    let reissued = resp.headers().get_all("set-cookie").iter()
        .map(|c| c.to_str().unwrap().to_string())
        .find(|c| c.starts_with("session="))
        .expect("this browser gets a re-issued session cookie");
    let reissued = reissued.split(';').next().unwrap().trim_start_matches("session=").to_string();

    assert_eq!(w.whoami(&reissued).await.as_deref(), Some("bob:admin:acme"), "the browser that unlinked stays signed in");
    assert_eq!(w.whoami(&linked_session).await, None, "the previously linked session is signed out");
    assert_eq!(w.subject_of(20).await, None);
}
