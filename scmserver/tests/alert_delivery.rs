// alert_delivery.rs — the outbox, and the SSRF containment on webhooks.
//
// In SaaS a webhook target is supplied by a tenant, so it is attacker-
// controlled: pointing it at http://169.254.169.254/ reads cloud instance
// metadata, and timing replies maps the operator's internal network. The
// guard is checked at save time AND at delivery time, because a hostname that
// resolves publicly when the rule is created can be re-pointed afterwards.

use scmserver::alert_delivery::{deliver_pending, validate_webhook_target};
use sqlx::SqlitePool;

#[test]
fn saas_refuses_targets_that_are_not_public_https() {
    // strict = SaaS
    for bad in [
        "http://example.com/hook",          // plaintext
        "https://127.0.0.1/hook",           // loopback
        "https://169.254.169.254/latest/",  // cloud metadata
        "https://10.0.0.5/hook",            // private
        "https://192.168.1.1/hook",         // private
        "https://172.16.0.1/hook",          // private
        "https://[::1]/hook",               // v6 loopback
        "https://0.0.0.0/hook",             // unspecified
        "https://100.64.0.1/hook",          // carrier-grade NAT
    ] {
        assert!(
            validate_webhook_target(bad, true).is_err(),
            "SaaS must refuse {bad}"
        );
    }
}

#[test]
fn self_hosted_may_post_to_its_own_network() {
    // A self-hosted operator legitimately posts to an internal address.
    assert!(validate_webhook_target("http://10.0.0.5/hook", false).is_ok());
    assert!(validate_webhook_target("https://hooks.example.com/x", false).is_ok());
    // But it must still be a URL.
    assert!(validate_webhook_target("hooks.example.com", false).is_err());
    assert!(validate_webhook_target("file:///etc/passwd", false).is_err());
}

// An address embedded as userinfo must not be mistaken for the host:
// https://public.example.com@169.254.169.254/ connects to the LATTER.
#[test]
fn userinfo_cannot_disguise_the_real_host() {
    assert!(
        validate_webhook_target("https://example.com@169.254.169.254/", true).is_err(),
        "the host is what follows '@', not what precedes it"
    );
}

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, name, email, role)
                 VALUES (1,'default','admin','x','Admin','a@example.com','admin')")
        .execute(&pool).await.unwrap();
    pool
}

async fn queue(pool: &SqlitePool, action: &str, target: Option<&str>) {
    sqlx::query("INSERT INTO alert_deliveries
                   (tenant_id, alert_id, policy_id, alert_name, policy_name,
                    old_score, new_score, action, target, status)
                 VALUES ('default', 1, 1, 'prod drop', 'CIS', 94.0, 61.0, ?, ?, 'pending')")
        .bind(action).bind(target).execute(pool).await.unwrap();
}

async fn status(pool: &SqlitePool) -> (String, i64) {
    sqlx::query_as("SELECT status, attempts FROM alert_deliveries LIMIT 1")
        .fetch_one(pool).await.unwrap()
}

// notify is a local INSERT, which is what makes it usable as the fallback
// when another transport gives up.
#[tokio::test]
async fn notify_delivers_to_the_bell_and_cannot_fail() {
    let pool = db().await;
    queue(&pool, "notify", None).await;

    deliver_pending(&pool).await;

    assert_eq!(status(&pool).await.0, "sent");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notify WHERE owner_id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(n, 1, "the admin should have been notified");
}

// A misconfigured transport must retry, not vanish.
#[tokio::test]
async fn a_transport_with_no_target_retries_then_gives_up() {
    let pool = db().await;
    queue(&pool, "email", None).await;   // no recipient configured

    deliver_pending(&pool).await;
    let (s, a) = status(&pool).await;
    assert_eq!((s.as_str(), a), ("pending", 1), "first failure schedules a retry");

    // Backoff means the row is not due yet; draining again must not touch it.
    deliver_pending(&pool).await;
    assert_eq!(status(&pool).await.1, 1, "a backed-off row is not retried early");
}

// A silently broken webhook is invisible unless someone is told.
#[tokio::test]
async fn permanent_failure_notifies_an_admin() {
    let pool = db().await;
    queue(&pool, "email", None).await;
    // Fast-forward through the attempts.
    sqlx::query("UPDATE alert_deliveries SET attempts = 2, next_retry_at = NULL")
        .execute(&pool).await.unwrap();

    deliver_pending(&pool).await;

    assert_eq!(status(&pool).await.0, "failed");
    let msg: String = sqlx::query_scalar("SELECT message FROM notify WHERE owner_id = 1")
        .fetch_one(&pool).await.unwrap();
    assert!(msg.contains("could not be delivered"), "admin must learn the transport broke: {msg}");
}

#[tokio::test]
async fn an_unknown_action_does_not_hang_the_outbox() {
    let pool = db().await;
    queue(&pool, "carrier-pigeon", None).await;
    deliver_pending(&pool).await;
    assert_eq!(status(&pool).await.1, 1, "it should have been attempted and failed");
}
