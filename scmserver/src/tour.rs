// tour.rs — the guided first-run walkthrough.
//
// A fresh install shows an empty dashboard: 0 systems, 0 policies, 0%. Nothing
// on screen says that the order is agent → test → policy → run, so the operator
// has to work that out for themselves before the product does anything at all.
// This module supplies the five-screen modal that names those steps and links
// into each one.
//
// The tour appears only on the dashboard, only while users.tour_done is 0, and
// only for roles that can act on what it describes (see `screens_for`). It is
// dismissed explicitly, never by pressing Esc — an accidental close on screen 2
// must not permanently destroy something the user has not read yet.

use axum::{
    extract::Extension,
    http::StatusCode,
    response::Redirect,
};
use serde::Serialize;
use sqlx::SqlitePool;
use tracing::{error, info};

use crate::models::{AuthSession, UserRole};


// ─────────────────────────────────────────────────────────────────────────────
// Struct: TourInfo
// Everything the tour template needs, resolved server-side so the markup stays
// free of logic.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Serialize, Default)]
pub struct TourInfo {
    /// Public URL of this installation, from the `app_url` setting. Empty when
    /// the operator has not set one, in which case the install snippet shows a
    /// placeholder rather than a wrong address.
    pub server_url: String,
    /// True when the tenant already has at least one usable enrollment token,
    /// which changes screen 2 from "create one" to "use one you already have".
    pub has_token: bool,
    /// Which of the five screens to render, by number.
    pub screens: Vec<u8>,
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: screens_for
// Screen selection by role.
//
// A Viewer cannot install agents, author tests or create policies, so showing
// them four screens of buttons they will be denied at is worse than showing
// nothing — they get no tour at all. A Runner cannot author either, but can run
// and schedule, so they get the framing, the policy screen and the run screen.
// ─────────────────────────────────────────────────────────────────────────────
fn screens_for(role: UserRole) -> Vec<u8> {
    if role >= UserRole::Editor {
        vec![1, 2, 3, 4, 5]
    } else if role >= UserRole::Runner {
        vec![1, 4, 5]
    } else {
        Vec::new()
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: tour_info
// Resolves whether to show the tour and what to put in it. Returns None when
// the tour should not appear, so the dashboard handler stays a one-liner.
//
// Note the Viewer case deliberately leaves tour_done at 0 rather than stamping
// it: promoting that Viewer to Editor six months from now should surface the
// tour at the moment it first becomes relevant, not never.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tour_info(pool: &SqlitePool, auth: &AuthSession, force: bool) -> Option<TourInfo> {
    let screens = screens_for(UserRole::from(auth.role.as_str()));
    if screens.is_empty() {
        return None;
    }

    // A superuser viewing another tenant read-only must never be shown a
    // walkthrough addressed to that tenant's administrator, and must certainly
    // never have its dismissal written against their own account.
    if auth.impersonating.is_some() {
        return None;
    }

    if !force {
        let done: i64 = sqlx::query_scalar(
            "SELECT COALESCE(tour_done, 0) FROM users WHERE id = ? AND tenant_id = ?",
        )
        .bind(auth.userid)
        .bind(&auth.tenant_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
        .unwrap_or(1);

        if done != 0 {
            return None;
        }
    }

    let server_url: String = sqlx::query_scalar(
        "SELECT value FROM settings WHERE skey = 'app_url' AND tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .unwrap_or_default();

    // Only tokens that could actually enrol something count: disabled, expired
    // and used-up tokens would make screen 2 lie.
    let has_token: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM enrollment_tokens
         WHERE tenant_id = ?
           AND enabled = 1
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
           AND (max_uses IS NULL OR use_count < max_uses)",
    )
    .bind(&auth.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Some(TourInfo {
        server_url,
        has_token: has_token > 0,
        screens,
    })
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /tour/dismiss
// Marks the tour finished for the current user. Returns 204 so the modal can
// close optimistically without a page reload.
// Role: Viewer (any authenticated user — it only touches their own row)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tour_dismiss(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
) -> StatusCode {
    // Writing this while impersonating would stamp the superuser's own row
    // from inside someone else's tenant context.
    if auth.impersonating.is_some() {
        return StatusCode::FORBIDDEN;
    }

    match sqlx::query("UPDATE users SET tour_done = 1 WHERE id = ? AND tenant_id = ?")
        .bind(auth.userid)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        Ok(_) => {
            info!("User {} dismissed the first-run tour.", auth.username);
            StatusCode::NO_CONTENT
        }
        Err(e) => {
            error!("Failed to dismiss tour for user {}: {}", auth.userid, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /tour/reopen
// Shows the tour again without clearing tour_done. Reached from Quick start in
// the user menu, so dismissing is never a one-way door: the person who clicked
// through it in a hurry on day one is exactly who wants it back on day three.
// Role: Viewer (any authenticated user)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn tour_reopen(_auth: AuthSession) -> Redirect {
    Redirect::to("/?tour=1")
}
