// alerting_e2e.rs — evaluation against a real database.
//
// The unit tests pin the decision function; these pin the wiring around it:
// state persistence, cooldown, startup suppression and the queue.

use scmserver::alerts::{evaluate_all, snapshot_scores, AlertMode};
use sqlx::SqlitePool;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO policies (id, tenant_id, name, version, score_test, score_system, compliance_score)
                 VALUES (1, 'default', 'CIS Ubuntu', '1', 94.0, 94.0, 94.0)")
        .execute(&pool).await.unwrap();
    pool
}

async fn add_rule(pool: &SqlitePool, trigger: &str, threshold: f64, cooldown: i64) {
    sqlx::query("INSERT INTO alerts (id, tenant_id, name, scope_type, policy_id,
                                     trigger_type, threshold, score_axis, action, cooldown_minutes)
                 VALUES (1, 'default', 'prod drop', 'policy', 1, ?, ?, 'test', 'notify', ?)")
        .bind(trigger).bind(threshold).bind(cooldown)
        .execute(pool).await.unwrap();
}

async fn set_score(pool: &SqlitePool, score: f64) {
    sqlx::query("UPDATE policies SET score_test = ?, score_system = ? WHERE id = 1")
        .bind(score).bind(score).execute(pool).await.unwrap();
}

async fn deliveries(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM alert_deliveries").fetch_one(pool).await.unwrap()
}

// Drives one recalculation cycle: snapshot, change, snapshot, evaluate.
async fn cycle(pool: &SqlitePool, new_score: f64, mode: AlertMode) {
    let before = snapshot_scores(pool, None).await;
    set_score(pool, new_score).await;
    let after = snapshot_scores(pool, None).await;
    evaluate_all(pool, None, &before, &after, mode).await;
}

#[tokio::test]
async fn a_drop_queues_exactly_one_delivery() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 60).await;

    cycle(&pool, 61.0, AlertMode::Deliver).await;
    assert_eq!(deliveries(&pool).await, 1, "the drop should have queued one delivery");

    let (action, old, new): (String, f64, f64) =
        sqlx::query_as("SELECT action, old_score, new_score FROM alert_deliveries")
            .fetch_one(&pool).await.unwrap();
    assert_eq!(action, "notify");
    assert_eq!((old, new), (94.0, 61.0), "the delivery must carry both scores");
}

// The cooldown is what stops a flapping policy paging someone every minute.
#[tokio::test]
async fn a_second_drop_inside_the_cooldown_is_muted() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 60).await;

    cycle(&pool, 61.0, AlertMode::Deliver).await;
    cycle(&pool, 20.0, AlertMode::Deliver).await;
    assert_eq!(deliveries(&pool).await, 1, "the second drop is inside the cooldown");
}

#[tokio::test]
async fn with_no_cooldown_each_drop_delivers() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 0).await;

    cycle(&pool, 61.0, AlertMode::Deliver).await;
    cycle(&pool, 20.0, AlertMode::Deliver).await;
    assert_eq!(deliveries(&pool).await, 2);
}

// A restart is the absence of observation, not an event.
#[tokio::test]
async fn startup_records_the_baseline_without_notifying() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 60).await;

    cycle(&pool, 61.0, AlertMode::BaselineOnly).await;
    assert_eq!(deliveries(&pool).await, 0, "startup must not deliver");

    let last: f64 = sqlx::query_scalar("SELECT last_score FROM alert_state WHERE alert_id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(last, 61.0, "but it must record the baseline it observed");
}

// After a suppressed startup, the NEXT real change is measured from the
// recorded baseline — not from a score the server never saw.
#[tokio::test]
async fn the_first_change_after_startup_is_measured_correctly() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 0).await;

    cycle(&pool, 61.0, AlertMode::BaselineOnly).await;   // silent
    cycle(&pool, 59.0, AlertMode::Deliver).await;        // only a 2-point fall
    assert_eq!(deliveries(&pool).await, 0, "2 points is below the threshold");

    cycle(&pool, 30.0, AlertMode::Deliver).await;        // 29 points
    assert_eq!(deliveries(&pool).await, 1);
}

// -1 is "never scanned"; it must not read as a catastrophic drop.
#[tokio::test]
async fn a_policy_going_unscanned_does_not_alert() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 0).await;

    cycle(&pool, -1.0, AlertMode::Deliver).await;
    assert_eq!(deliveries(&pool).await, 0, "going unscanned is not a 95-point drop");
}

// A rule watching the system axis must not react to test-axis movement.
#[tokio::test]
async fn a_rule_watches_only_its_own_axis() {
    let pool = db().await;
    sqlx::query("INSERT INTO alerts (id, tenant_id, name, scope_type, policy_id,
                                     trigger_type, threshold, score_axis, action, cooldown_minutes)
                 VALUES (1, 'default', 'system axis', 'policy', 1, 'drop', 10.0, 'system', 'notify', 0)")
        .execute(&pool).await.unwrap();

    let before = snapshot_scores(&pool, None).await;
    sqlx::query("UPDATE policies SET score_test = 10.0 WHERE id = 1")  // test axis only
        .execute(&pool).await.unwrap();
    let after = snapshot_scores(&pool, None).await;
    evaluate_all(&pool, None, &before, &after, AlertMode::Deliver).await;

    assert_eq!(deliveries(&pool).await, 0, "a system-axis rule ignored a test-axis fall");
}

// Deleting a rule must not erase the record of what it already sent.
#[tokio::test]
async fn history_survives_deleting_the_rule() {
    let pool = db().await;
    add_rule(&pool, "drop", 10.0, 0).await;
    cycle(&pool, 61.0, AlertMode::Deliver).await;
    assert_eq!(deliveries(&pool).await, 1);

    sqlx::query("DELETE FROM alerts WHERE id = 1").execute(&pool).await.unwrap();

    assert_eq!(deliveries(&pool).await, 1, "the delivery record must survive");
    let name: Option<String> = sqlx::query_scalar("SELECT alert_name FROM alert_deliveries")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(name.as_deref(), Some("prod drop"), "and stay readable");
}
