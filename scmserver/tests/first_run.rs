// first_run.rs — the guided first-run tour.
//
// The load-bearing behaviour here is not the modal, it is WHO gets shown it.
// Two mistakes are easy to make and both are silently wrong in production:
//
//   * backfilling every user to tour_done = 1 on upgrade also catches the
//     administrator a fresh install created moments earlier, because
//     install.rs seeds that user BEFORE it runs migrations;
//   * NOT backfilling greets an operator who has run OpenSCM for a year with
//     "let's register your first system".
//
// The migration threads between the two by putting both the ALTER and the
// backfill behind a column_exists guard. These tests pin that.

use sqlx::SqlitePool;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: fresh_install
// A brand-new database, in the order install.rs actually does it: initialise,
// create the admin, then migrate.
// ─────────────────────────────────────────────────────────────────────────────
async fn fresh_install() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, username, password, name, email, role)
         VALUES (1, 'default', 'admin', 'x', 'Admin User', 'admin@example.com', 'superuser')",
    )
    .execute(&pool)
    .await
    .unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: tour_done_for
// ─────────────────────────────────────────────────────────────────────────────
async fn tour_done_for(pool: &SqlitePool, username: &str) -> i64 {
    sqlx::query_scalar("SELECT tour_done FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await
        .unwrap()
}

// The administrator a fresh install just created is the single person the tour
// exists for. If the backfill catches them, the feature ships doing nothing.
#[tokio::test]
async fn fresh_install_admin_sees_the_tour() {
    let pool = fresh_install().await;
    assert_eq!(
        tour_done_for(&pool, "admin").await,
        0,
        "the admin created during install must still be shown the tour"
    );
}

// Someone who has been using OpenSCM for months must not be welcomed to it.
#[tokio::test]
async fn upgrade_does_not_show_the_tour_to_existing_users() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();

    // Simulate a pre-0.8.0 database: drop the column the migration adds.
    sqlx::query("ALTER TABLE users DROP COLUMN tour_done").execute(&pool).await.unwrap();
    sqlx::query("UPDATE schema_info SET version = 37").execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, username, password, name, email, role)
         VALUES (1, 'default', 'veteran', 'x', 'Long-time User', 'v@example.com', 'admin')",
    )
    .execute(&pool)
    .await
    .unwrap();

    scmserver::schema::run_migrations(&pool).await.unwrap();

    assert_eq!(
        tour_done_for(&pool, "veteran").await,
        1,
        "a user who predates the feature must not be shown the tour"
    );
}

// A user created AFTER the upgrade is genuinely new and must see it — this is
// what would break if the ALTER defaulted to 1 to get the previous test to pass.
#[tokio::test]
async fn users_created_after_the_upgrade_see_the_tour() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    sqlx::query("ALTER TABLE users DROP COLUMN tour_done").execute(&pool).await.unwrap();
    sqlx::query("UPDATE schema_info SET version = 37").execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, username, password, name, email, role)
         VALUES (1, 'default', 'veteran', 'x', 'Long-time User', 'v@example.com', 'admin')",
    )
    .execute(&pool).await.unwrap();

    scmserver::schema::run_migrations(&pool).await.unwrap();

    sqlx::query(
        "INSERT INTO users (id, tenant_id, username, password, name, email, role)
         VALUES (2, 'default', 'newcomer', 'x', 'New Hire', 'n@example.com', 'editor')",
    )
    .execute(&pool).await.unwrap();

    assert_eq!(tour_done_for(&pool, "veteran").await, 1);
    assert_eq!(
        tour_done_for(&pool, "newcomer").await,
        0,
        "a user created after the upgrade is new and must see the tour"
    );
}

// Re-running migrations must not resurrect the tour for someone who dismissed
// it, which is what an unguarded backfill would do on every restart.
#[tokio::test]
async fn rerunning_migrations_does_not_reset_dismissal() {
    let pool = fresh_install().await;
    sqlx::query("UPDATE users SET tour_done = 1 WHERE username = 'admin'")
        .execute(&pool).await.unwrap();

    scmserver::schema::run_migrations(&pool).await.unwrap();

    assert_eq!(
        tour_done_for(&pool, "admin").await,
        1,
        "a dismissed tour must stay dismissed across restarts"
    );
}

// The tour partial must be reachable by `{% include %}`. It lives in a
// subdirectory, and include_dir's file iterator is not recursive — see
// templates_parse.rs for the failure this guards.
#[test]
fn tour_template_is_registered() {
    let tera = scmserver::init_tera().expect("templates must parse");
    assert!(tera.get_template_names().any(|n| n == "partials/tour.html"));
}
