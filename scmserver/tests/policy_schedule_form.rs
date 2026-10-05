// policy_schedule_form.rs — what the policy form stores for a schedule.
//
// Until 0.9.5: the form's local time was stored as if it were UTC, so
// schedules ran off by the viewer's UTC offset; "Custom (Cron)" expressions
// were stored unvalidated and never read; and saving the edit form with the
// time cleared reset the schedule to "now", running the policy at once.
//
// The calculations are unit-tested in src/schedule.rs. These tests cover the
// wiring: the real add and edit handlers, posted the fields the form sends.

use axum::extract::{Extension, Path, RawForm};
use axum::response::IntoResponse;
use scmserver::models::AuthSession;
use sqlx::SqlitePool;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    pool
}

fn admin() -> AuthSession {
    AuthSession {
        username: "admin".into(), userid: 1, tenant_id: "default".into(),
        role: "admin".into(), impersonating: None,
    }
}

fn form(fields: &[(&str, &str)]) -> RawForm {
    let body = fields.iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    RawForm(body.into())
}

fn location(resp: axum::response::Response) -> String {
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
}

async fn add(pool: &SqlitePool, fields: &[(&str, &str)]) -> String {
    let mut all = vec![("name", "P"), ("version", "1")];
    all.extend_from_slice(fields);
    location(
        scmserver::policies::policies_add_save(admin(), Extension(pool.clone()), form(&all))
            .await
            .into_response(),
    )
}

async fn edit(pool: &SqlitePool, id: i32, fields: &[(&str, &str)]) -> String {
    let (tx, _rx) = tokio::sync::mpsc::channel::<()>(8);
    let mut all = vec![("name", "P"), ("version", "1")];
    all.extend_from_slice(fields);
    location(
        scmserver::policies::policies_edit_save(admin(), Path(id), Extension(pool.clone()), Extension(tx), form(&all))
            .await
            .into_response(),
    )
}

// (enabled, frequency, cron_expression, next_run) of a policy's schedule.
async fn schedule(pool: &SqlitePool, kind: &str) -> Option<(i64, String, Option<String>, String)> {
    sqlx::query_as(
        "SELECT CAST(enabled AS INTEGER), frequency, cron_expression, CAST(next_run AS TEXT)
           FROM policy_schedules WHERE policy_id = 1 AND schedule_type = ?",
    )
    .bind(kind)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn now_utc() -> chrono::NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

#[tokio::test]
async fn a_picked_local_time_is_stored_in_utc() {
    let pool = db().await;
    // 09:00 in UTC+3: the browser reports an offset of −180 minutes.
    let to = add(&pool, &[
        ("schedule_enabled", "on"), ("frequency", "daily"),
        ("next_run", "2030-01-15T09:00"), ("next_run_tz_offset", "-180"),
        ("report_schedule_enabled", "on"), ("report_frequency", "weekly"),
        ("report_next_run", "2030-01-15T23:30"), ("report_next_run_tz_offset", "300"),
    ]).await;
    assert!(!to.contains("error_message"), "{to}");

    let (enabled, freq, cron, next) = schedule(&pool, "scan").await.unwrap();
    assert_eq!((enabled, freq.as_str(), cron, next.as_str()), (1, "daily", None, "2030-01-15T06:00"));
    // Each picker carries its own offset; this one crosses midnight (UTC−5).
    let (_, freq, _, next) = schedule(&pool, "report").await.unwrap();
    assert_eq!((freq.as_str(), next.as_str()), ("weekly", "2030-01-16T04:30"));
}

#[tokio::test]
async fn with_no_time_picked_a_new_schedule_starts_now() {
    let pool = db().await;
    add(&pool, &[("schedule_enabled", "on"), ("frequency", "daily"), ("next_run", "")]).await;
    let (_, _, _, next) = schedule(&pool, "scan").await.unwrap();
    let next = scmserver::schedule::parse_time(&next).unwrap();
    assert!((now_utc() - next).num_minutes().abs() <= 1, "expected about now, got {next}");
}

// The reviewed bug: clearing the time on the edit page reset it to now.
#[tokio::test]
async fn editing_without_a_time_keeps_the_existing_one() {
    let pool = db().await;
    add(&pool, &[("schedule_enabled", "on"), ("frequency", "daily"),
                 ("next_run", "2030-01-15T09:00"), ("next_run_tz_offset", "-180")]).await;

    let to = edit(&pool, 1, &[("schedule_enabled", "on"), ("frequency", "weekly"), ("next_run", "")]).await;
    assert!(!to.contains("error_message"), "{to}");
    let (enabled, freq, _, next) = schedule(&pool, "scan").await.unwrap();
    assert_eq!((enabled, freq.as_str(), next.as_str()), (1, "weekly", "2030-01-15T06:00"),
               "the interval changes; the next run does not");

    // Re-submitting the time the page displays (local) round-trips unchanged.
    edit(&pool, 1, &[("schedule_enabled", "on"), ("frequency", "weekly"),
                     ("next_run", "2030-01-15T09:00"), ("next_run_tz_offset", "-180")]).await;
    assert_eq!(schedule(&pool, "scan").await.unwrap().3, "2030-01-15T06:00");

    // And a newly picked time replaces it.
    edit(&pool, 1, &[("schedule_enabled", "on"), ("frequency", "weekly"),
                     ("next_run", "2030-02-01T12:00"), ("next_run_tz_offset", "-120")]).await;
    assert_eq!(schedule(&pool, "scan").await.unwrap().3, "2030-02-01T10:00");
}

#[tokio::test]
async fn switching_a_schedule_off_keeps_its_time() {
    let pool = db().await;
    add(&pool, &[("schedule_enabled", "on"), ("frequency", "daily"),
                 ("next_run", "2030-01-15T09:00"), ("next_run_tz_offset", "0")]).await;
    // An unchecked checkbox is simply absent from the post.
    edit(&pool, 1, &[("frequency", "daily"), ("next_run", "")]).await;
    let (enabled, _, _, next) = schedule(&pool, "scan").await.unwrap();
    assert_eq!((enabled, next.as_str()), (0, "2030-01-15T09:00"));
}

#[tokio::test]
async fn a_cron_schedule_takes_its_next_run_from_the_expression() {
    let pool = db().await;
    // The picker is ignored for Custom: 2099 must not be stored.
    let to = add(&pool, &[("schedule_enabled", "on"), ("frequency", "custom"), ("cron_val", "*/5 * * * *"),
                          ("next_run", "2099-01-01T00:00"), ("next_run_tz_offset", "-180")]).await;
    assert!(!to.contains("error_message"), "{to}");

    let (_, freq, cron, next) = schedule(&pool, "scan").await.unwrap();
    assert_eq!((freq.as_str(), cron.as_deref()), ("custom", Some("*/5 * * * *")));
    let next = scmserver::schedule::parse_time(&next).unwrap();
    let wait = (next - now_utc()).num_seconds();
    assert!((0..=300).contains(&wait), "next run should be within 5 minutes, is {wait}s away");
    assert_eq!(chrono::Timelike::minute(&next) % 5, 0, "on a 5-minute boundary");
}

#[tokio::test]
async fn an_invalid_cron_expression_is_refused_and_nothing_is_created() {
    let pool = db().await;
    for bad in ["every day", "", "0 25 * * *", "0 0 31 2 *"] {
        let to = add(&pool, &[("schedule_enabled", "on"), ("frequency", "custom"), ("cron_val", bad)]).await;
        assert!(to.contains("error_message") && to.contains("Auto-scan"), "{bad:?} → {to}");
    }
    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies").fetch_one(&pool).await.unwrap();
    assert_eq!(policies, 0, "a refused form must not leave a policy behind");

    // The report schedule is validated too, and named in the message.
    let to = add(&pool, &[("report_schedule_enabled", "on"), ("report_frequency", "custom"), ("report_cron_val", "nope")]).await;
    assert!(to.contains("Auto-report"), "{to}");
}

#[tokio::test]
async fn an_invalid_edit_changes_nothing() {
    let pool = db().await;
    add(&pool, &[("schedule_enabled", "on"), ("frequency", "daily"),
                 ("next_run", "2030-01-15T09:00"), ("next_run_tz_offset", "0")]).await;
    let before = schedule(&pool, "scan").await;

    let to = edit(&pool, 1, &[("name", "Renamed"), ("schedule_enabled", "on"),
                              ("frequency", "custom"), ("cron_val", "bogus")]).await;
    assert!(to.contains("error_message"), "{to}");
    assert_eq!(schedule(&pool, "scan").await, before);
    let name: String = sqlx::query_scalar("SELECT name FROM policies WHERE id = 1").fetch_one(&pool).await.unwrap();
    assert_eq!(name, "P", "the rest of the edit must not be half-applied");
}
