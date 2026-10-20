// plan_limits.rs — a plan's limits hold wherever a resource is created.
//
// The SaaS middleware enforces plan limits on the ordinary "create" routes.
// Three things created limited resources without passing through it, and so
// were never limited:
//   • the scheduler saving an auto-report        (reports)
//   • policy import and policy-store install     (policies)
//   • an enrollment token approving a system     (systems)
// Each now asks scmserver::plan, the one definition of a plan's limits.
//
// Community Edition has an empty plan_limits table: nothing is limited there.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Extension, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use scmserver::enrollment::{approve_with_token, hash_token, TokenOutcome};
use scmserver::plan::{limit_reached_pool, notify_admins_once};
use sqlx::SqlitePool;
use tower::ServiceExt;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: db
// Tenant 'acme' on the 'free' plan with an admin (id 20). `limits` are that
// plan's caps; pass none for the Community Edition situation.
// ─────────────────────────────────────────────────────────────────────────────
async fn db(limits: &[(&str, i64)]) -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("DELETE FROM plan_limits").execute(&pool).await.unwrap();
    for q in [
        "INSERT INTO tenants (id, name, plan) VALUES ('acme', 'Acme', 'free')",
        "INSERT INTO users (id, tenant_id, username, password, role) VALUES (20, 'acme', 'bob', 'x', 'admin')",
        // Every tenant has a signing key; the server signs its replies to agents with it.
        "INSERT INTO tenant_keys (tenant_id, public_key, private_key, is_active)
         SELECT 'acme', public_key, private_key, 1 FROM tenant_keys WHERE tenant_id = 'default'",
    ] {
        sqlx::query(q).execute(&pool).await.unwrap();
    }
    for (resource, max) in limits {
        sqlx::query("INSERT INTO plan_limits (plan, resource, max_count) VALUES ('free', ?, ?)")
            .bind(resource).bind(max).execute(&pool).await.unwrap();
    }
    pool
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

async fn add_systems(pool: &SqlitePool, n: i64, status: &str) {
    for i in 0..n {
        sqlx::query("INSERT INTO systems (tenant_id, key, name, status) VALUES ('acme', ?, ?, ?)")
            .bind(format!("key-{status}-{i}")).bind(format!("{status}-{i}")).bind(status)
            .execute(pool).await.unwrap();
    }
}

async fn add_policy(pool: &SqlitePool, id: i64, external_id: &str) {
    sqlx::query("INSERT INTO policies (id, tenant_id, name, version, external_id) VALUES (?, 'acme', ?, '1', ?)")
        .bind(id).bind(format!("policy {id}")).bind(external_id).execute(pool).await.unwrap();
}

// ── the limit itself ────────────────────────────────────────────────────────
#[tokio::test]
async fn with_no_limits_configured_nothing_is_limited() {
    let pool = db(&[]).await; // Community Edition
    add_systems(&pool, 50, "active").await;
    for r in ["systems", "policies", "reports"] {
        assert_eq!(limit_reached_pool(&pool, "acme", r).await, None, "{r}");
    }
}

#[tokio::test]
async fn a_limit_is_reached_at_the_cap_and_zero_means_unlimited() {
    let pool = db(&[("systems", 2), ("policies", 0)]).await;
    add_systems(&pool, 1, "active").await;
    assert_eq!(limit_reached_pool(&pool, "acme", "systems").await, None, "1 of 2");

    // Pending systems are not using the plan yet.
    add_systems(&pool, 5, "pending").await;
    assert_eq!(limit_reached_pool(&pool, "acme", "systems").await, None);

    add_systems(&pool, 1, "active").await;
    let hit = limit_reached_pool(&pool, "acme", "systems").await.expect("2 of 2");
    assert_eq!((hit.plan.as_str(), hit.limit, hit.count, hit.resource), ("free", 2, 2, "systems"));
    assert_eq!(hit.message(), "Plan limit reached: your free plan allows 2 systems. Upgrade to add more.");

    add_policy(&pool, 1, "x1").await;
    assert_eq!(limit_reached_pool(&pool, "acme", "policies").await, None, "0 = unlimited");
    assert_eq!(limit_reached_pool(&pool, "acme", "widgets").await, None, "not a limited resource");
    // Another tenant's resources do not count.
    assert_eq!(limit_reached_pool(&pool, "default", "systems").await, None);
}

#[tokio::test]
async fn admins_are_told_once_until_they_clear_it() {
    let pool = db(&[]).await;
    for _ in 0..3 {
        notify_admins_once(&pool, "acme", "warning", "the plan is full").await;
    }
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM notify WHERE owner_id = 20").await, 1);
    notify_admins_once(&pool, "acme", "warning", "a different message").await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM notify WHERE owner_id = 20").await, 2);
    // Once cleared, the same event is announced again.
    sqlx::query("DELETE FROM notify").execute(&pool).await.unwrap();
    notify_admins_once(&pool, "acme", "warning", "the plan is full").await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM notify WHERE owner_id = 20").await, 1);
}

// ── scheduled reports ───────────────────────────────────────────────────────
async fn due_report_schedule(pool: &SqlitePool) {
    add_policy(pool, 1, "x1").await;
    sqlx::query("INSERT INTO policy_schedules (tenant_id, policy_id, schedule_type, enabled, frequency, next_run)
                 VALUES ('acme', 1, 'report', 1, 'daily', '2026-10-05T02:00')")
        .execute(pool).await.unwrap();
}

fn tick() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-05T02:00:30Z").unwrap().with_timezone(&chrono::Utc)
}

async fn next_run(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT CAST(next_run AS TEXT) FROM policy_schedules WHERE policy_id = 1")
        .fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn a_scheduled_report_is_saved_when_there_is_room() {
    let pool = db(&[("reports", 2)]).await;
    due_report_schedule(&pool).await;

    scmserver::scheduler::run_due_schedules(&pool, tick()).await;

    assert_eq!(count(&pool, "SELECT COUNT(*) FROM reports WHERE tenant_id = 'acme'").await, 1);
    assert_eq!(next_run(&pool).await, "2026-10-06T02:00");
}

#[tokio::test]
async fn a_scheduled_report_is_skipped_at_the_plan_limit() {
    let pool = db(&[("reports", 1)]).await;
    due_report_schedule(&pool).await;

    // The first run saves the one report the plan allows.
    scmserver::scheduler::run_due_schedules(&pool, tick()).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM reports").await, 1);
    sqlx::query("DELETE FROM notify").execute(&pool).await.unwrap();

    // The next day's run finds the plan full.
    let day2 = tick() + chrono::Duration::days(1);
    scmserver::scheduler::run_due_schedules(&pool, day2).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM reports").await, 1, "no report past the limit");
    assert_eq!(next_run(&pool).await, "2026-10-07T02:00", "the schedule moves on; it must not retry every minute");

    let msg: String = sqlx::query_scalar("SELECT message FROM notify WHERE owner_id = 20")
        .fetch_one(&pool).await.unwrap();
    assert!(msg.contains("policy 1") && msg.contains("was not saved") && msg.contains("allows 1 reports"), "{msg}");

    // A further skipped run does not add a second copy of the warning.
    scmserver::scheduler::run_due_schedules(&pool, day2 + chrono::Duration::days(1)).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM notify WHERE owner_id = 20").await, 1);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM reports").await, 1);
}

// Scans are not a limited resource: a scan schedule runs regardless.
#[tokio::test]
async fn a_scheduled_scan_is_not_affected_by_the_report_limit() {
    let pool = db(&[("reports", 0)]).await;
    add_policy(&pool, 1, "x1").await;
    sqlx::query("INSERT INTO plan_limits (plan, resource, max_count) VALUES ('free', 'systems', 1)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO policy_schedules (tenant_id, policy_id, schedule_type, enabled, frequency, next_run)
                 VALUES ('acme', 1, 'scan', 1, 'daily', '2026-10-05T02:00')").execute(&pool).await.unwrap();
    scmserver::scheduler::run_due_schedules(&pool, tick()).await;
    assert_eq!(next_run(&pool).await, "2026-10-06T02:00");
    let last: Option<String> = sqlx::query_scalar("SELECT CAST(last_run AS TEXT) FROM policy_schedules").fetch_one(&pool).await.unwrap();
    assert!(last.is_some(), "the scan ran");
}

// ── policy import / store install ───────────────────────────────────────────
fn export(external_id: &str, name: &str) -> scmserver::models::PolicyExport {
    serde_json::from_value(serde_json::json!({
        "format_version": 1,
        "policy": { "external_id": external_id, "name": name, "version": "1", "description": null },
        "tests": []
    })).unwrap()
}

#[tokio::test]
async fn importing_a_new_policy_is_refused_at_the_plan_limit() {
    let pool = db(&[("policies", 1)]).await;
    add_policy(&pool, 1, "x1").await;

    let err = scmserver::policies::apply_policy_import(&pool, "acme", export("x2", "Second")).await.unwrap_err();
    assert_eq!(err, "Plan limit reached: your free plan allows 1 policies. Upgrade to add more.");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM policies WHERE tenant_id = 'acme'").await, 1);
}

// Re-importing a policy the tenant already has adds nothing, so it is allowed.
#[tokio::test]
async fn updating_an_existing_policy_is_allowed_at_the_limit() {
    let pool = db(&[("policies", 1)]).await;
    add_policy(&pool, 1, "x1").await;

    let ok = scmserver::policies::apply_policy_import(&pool, "acme", export("x1", "Renamed")).await;
    assert!(ok.is_ok(), "{:?}", ok.err());
    let name: String = sqlx::query_scalar("SELECT name FROM policies WHERE id = 1").fetch_one(&pool).await.unwrap();
    assert_eq!(name, "Renamed");
}

#[tokio::test]
async fn importing_works_below_the_limit_and_without_one() {
    let pool = db(&[("policies", 2)]).await;
    add_policy(&pool, 1, "x1").await;
    assert!(scmserver::policies::apply_policy_import(&pool, "acme", export("x2", "Second")).await.is_ok());

    let ce = db(&[]).await;
    for i in 0..5 {
        assert!(scmserver::policies::apply_policy_import(&ce, "acme", export(&format!("e{i}"), &format!("P{i}"))).await.is_ok());
    }
}

// ── enrollment tokens ───────────────────────────────────────────────────────
async fn add_token(pool: &SqlitePool, raw: &str) {
    sqlx::query("INSERT INTO enrollment_tokens (tenant_id, name, token_hash, token_prefix, enabled, use_count, created_by)
                 VALUES ('acme', 'golden', ?, 'oscm_test', 1, 0, 'bob')")
        .bind(hash_token(raw)).execute(pool).await.unwrap();
}

#[tokio::test]
async fn a_token_does_not_approve_past_the_system_limit_and_is_not_used_up() {
    let pool = db(&[("systems", 1)]).await;
    add_token(&pool, "oscm_test_secret").await;

    // Room for one.
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(approve_with_token(&mut tx, "acme", "oscm_test_secret").await.unwrap(), TokenOutcome::Approved);
    tx.commit().await.unwrap();
    add_systems(&pool, 1, "active").await;

    // Now full.
    let mut tx = pool.begin().await.unwrap();
    let outcome = approve_with_token(&mut tx, "acme", "oscm_test_secret").await.unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(outcome, TokenOutcome::PlanLimit(ref l) if l.limit == 1), "{outcome:?}");
    assert_eq!(count(&pool, "SELECT use_count FROM enrollment_tokens").await, 1, "a refused approval must not consume a use");

    // A wrong token is simply invalid — it never reaches the plan check.
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(approve_with_token(&mut tx, "acme", "wrong").await.unwrap(), TokenOutcome::Invalid);
}

// Through the real registration endpoint.
async fn register(pool: &SqlitePool, hostname: &str, token: &str) -> String {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let payload = serde_json::json!({
        "id": "0", "organization": "acme", "hostname": hostname, "ver": "0.9.5", "ip": "10.0.0.9",
        "os": "Linux", "arch": "x86_64", "timestamp": "2026-10-05T12:00:00Z",
        "public_key": STANDARD.encode(key.verifying_key().to_bytes()), "enrollment_token": token
    });
    // Signed with the key it presents, as a real agent does: the server
    // checks that at registration since 0.11.0 (design D6).
    let raw = payload.to_string();
    let sig = STANDARD.encode(key.sign(raw.as_bytes()).to_bytes());
    let body = format!(r#"{{"payload":{raw},"signature":"{sig}"}}"#);
    let app = Router::new().route("/send", post(scmserver::client::send)).layer(Extension(pool.clone()));
    let resp = app
        .oneshot(Request::post("/send").header("content-type", "application/json").body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["payload"]["status"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn registration_with_a_token_leaves_the_system_pending_at_the_limit() {
    let pool = db(&[("systems", 2)]).await;
    add_token(&pool, "oscm_test_secret").await;

    assert_eq!(register(&pool, "web1", "oscm_test_secret").await, "active");
    assert_eq!(register(&pool, "web2", "oscm_test_secret").await, "active");
    // The plan is full: a valid token no longer activates.
    assert_eq!(register(&pool, "web3", "oscm_test_secret").await, "pending");
    assert_eq!(register(&pool, "web4", "oscm_test_secret").await, "pending");

    assert_eq!(count(&pool, "SELECT COUNT(*) FROM systems WHERE tenant_id = 'acme' AND status = 'active'").await, 2);
    assert_eq!(count(&pool, "SELECT use_count FROM enrollment_tokens").await, 2);
    // Told once, not once per host; each attempt is in the audit log.
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM notify WHERE owner_id = 20 AND message LIKE '%left pending%'").await, 1);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_log WHERE action = 'enrollment.token_plan_limit'").await, 2);

    // A bogus token at the limit: pending as always, and no plan announcement.
    sqlx::query("DELETE FROM notify").execute(&pool).await.unwrap();
    assert_eq!(register(&pool, "stranger", "not-a-token").await, "pending");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM notify").await, 0);
}

#[tokio::test]
async fn tokens_are_unlimited_without_a_plan_limit() {
    let pool = db(&[]).await;
    add_token(&pool, "oscm_test_secret").await;
    for i in 0..4 {
        assert_eq!(register(&pool, &format!("h{i}"), "oscm_test_secret").await, "active");
    }
}
