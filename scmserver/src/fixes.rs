// =============================================================================
// fixes.rs — remediation fix runs between server and agent (1.1.0)
//
// docs/design/1.1.0-remediation.md. A fix run is one fix script an Editor
// queued for one failing test on one system (the `fix_runs` table). This
// module hands queued runs to the agent on its heartbeat and records what the
// agent reports back (POST /fix_result, handled in client.rs).
//
// Status flow: queued → sent → done | failed | timeout | refused.
// A queued run nobody picks up within FIX_EXPIRY_HOURS becomes expired.
// =============================================================================

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};

use crate::models::{Test, TestCondition, TestPayload, TestWithConditions};

// How long the agent lets a fix script run before killing it.
pub const FIX_TIMEOUT_SECS: i64 = 300;

// A queued fix not picked up within this many hours is expired.
pub const FIX_EXPIRY_HOURS: i64 = 24;

// The most script output kept per fix run.
pub const FIX_OUTPUT_MAX: usize = 64 * 1024;

// Outcomes an agent may report for a fix run.
pub const FIX_OUTCOMES: [&str; 4] = ["done", "failed", "timeout", "refused"];


// One fix handed to the agent in the heartbeat reply (`fixes` list).
// `test` is the test the fix is for, so the agent can check it again
// straight after the script runs.
#[derive(Debug, Serialize)]
pub struct FixDispatch {
    pub id:           i64,
    pub test_id:      i64,
    pub kind:         String,
    pub script:       String,
    pub sha256:       String,
    pub timeout_secs: i64,
    pub test:         TestPayload,
}

// What the agent reports after running (or refusing) a fix, in the signed
// POST /fix_result body.
#[derive(Debug, Deserialize)]
pub struct FixResult {
    pub client_id: i64,
    #[serde(alias = "tenant_id")]
    pub organization: String,
    pub fix_id: i64,
    pub status: String,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub output: Option<String>,
    #[serde(default)]
    pub protocol: Option<i64>,
    #[serde(default)]
    pub sent_at_ms: Option<i64>,
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: script_sha256
// Lowercase hex SHA-256 of a script, stored at queue time and checked by the
// agent before it runs anything.
// ─────────────────────────────────────────────────────────────────────────────
pub fn script_sha256(script: &str) -> String {
    format!("{:x}", Sha256::digest(script.as_bytes()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: cap_output
// Keeps at most FIX_OUTPUT_MAX bytes of output, cut on a character boundary.
// ─────────────────────────────────────────────────────────────────────────────
pub fn cap_output(output: &str) -> String {
    if output.len() <= FIX_OUTPUT_MAX {
        return output.to_string();
    }
    let mut end = FIX_OUTPUT_MAX;
    while !output.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[output cut at {} KB]", &output[..end], FIX_OUTPUT_MAX / 1024)
}

// ─────────────────────────────────────────────────────────────────────────────
// take_queued_fixes
// Called from the heartbeat of an active system, inside its transaction.
// Expires this system's stale queued runs, then returns the rest and marks
// them sent. Agents before 1.1.0 do not report cmd_enabled / ps_enabled and
// do not know the `fixes` field: they get nothing, and their runs stay
// queued until they expire.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn take_queued_fixes(
    conn:            &mut SqliteConnection,
    tenant_id:       &str,
    system_id:       i64,
    agent_can_fix:   bool,
) -> Result<Vec<FixDispatch>, sqlx::Error> {
    sqlx::query(
        "UPDATE fix_runs SET status = 'expired', finished_at = CURRENT_TIMESTAMP
          WHERE tenant_id = ? AND system_id = ? AND status = 'queued'
            AND requested_at < datetime('now', ?)",
    )
    .bind(tenant_id).bind(system_id).bind(format!("-{FIX_EXPIRY_HOURS} hours"))
    .execute(&mut *conn).await?;

    if !agent_can_fix {
        return Ok(Vec::new());
    }

    let rows = sqlx::query(
        "SELECT id, test_id, kind, script, script_sha256 FROM fix_runs
          WHERE tenant_id = ? AND system_id = ? AND status = 'queued'
          ORDER BY id",
    )
    .bind(tenant_id).bind(system_id)
    .fetch_all(&mut *conn).await?;

    let mut fixes = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.get("id");
        let test_id: i64 = row.get("test_id");
        let test = load_test_payload(conn, tenant_id, test_id).await?;
        sqlx::query("UPDATE fix_runs SET status = 'sent', sent_at = CURRENT_TIMESTAMP WHERE id = ?")
            .bind(id).execute(&mut *conn).await?;
        fixes.push(FixDispatch {
            id,
            test_id,
            kind:         row.get("kind"),
            script:       row.get("script"),
            sha256:       row.get("script_sha256"),
            timeout_secs: FIX_TIMEOUT_SECS,
            test,
        });
    }
    Ok(fixes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: load_test_payload
// One test with its conditions and applicability rules, in the same shape
// the TEST command uses, so the agent checks it the usual way.
// ─────────────────────────────────────────────────────────────────────────────
async fn load_test_payload(
    conn:      &mut SqliteConnection,
    tenant_id: &str,
    test_id:   i64,
) -> Result<TestPayload, sqlx::Error> {
    let test: Test = sqlx::query_as("SELECT * FROM tests WHERE id = ? AND tenant_id = ?")
        .bind(test_id).bind(tenant_id)
        .fetch_one(&mut *conn).await?;
    let all: Vec<TestCondition> = sqlx::query_as(
        "SELECT id, tenant_id, test_id, `type`, element, input, selement, condition, sinput
           FROM test_conditions WHERE tenant_id = ? AND test_id = ? ORDER BY id",
    )
    .bind(tenant_id).bind(test_id)
    .fetch_all(&mut *conn).await?;
    let (applicability, conditions): (Vec<_>, Vec<_>) =
        all.into_iter().partition(|c| c.r#type == "applicability");
    Ok(TestPayload::from(TestWithConditions {
        test,
        conditions,
        applicability: Some(applicability).filter(|v| !v.is_empty()),
    }))
}


// =============================================================================
// WEB UI — the Fix button on the live policy and system reports (step 3)
// =============================================================================

use axum::extract::{Extension, Path};
use axum::response::{IntoResponse, Redirect};
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing::{error, info};

use crate::auth;
use crate::handlers::ClientIp;
use crate::models::{AuthSession, IndividualResult, UserRole};

// What a result row shows about fixing it. Only set on the live reports;
// saved snapshots never carry it.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct FixView {
    /// The button: "ready", "disabled", "queued" (can be cancelled) or "sent"
    /// (running on the agent). None: no button, e.g. a passing result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// "sh" or "ps" — which script this system would run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The script, shown in the confirm dialog (ready only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Why the button is gray (disabled only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The last finished fix for this system and test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<LastFix>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct LastFix {
    pub status:      String,
    pub exit_code:   Option<i64>,
    pub output:      Option<String>,
    pub finished_at: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: kind_for_os
// Windows systems run the PowerShell script, every other system the shell one
// (same OS test as agents::derive_platform).
// ─────────────────────────────────────────────────────────────────────────────
pub fn kind_for_os(os: &str) -> &'static str {
    if os.to_lowercase().contains("windows") { "ps" } else { "sh" }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: why_not
// Why a fix of `kind` cannot be queued on a system whose agent reported
// `cmd` / `ps` (None: an agent before 1.1.0), or None if it can.
// ─────────────────────────────────────────────────────────────────────────────
pub fn why_not(kind: &str, cmd: Option<bool>, ps: Option<bool>, is_editor: bool) -> Option<String> {
    if !is_editor {
        return Some("Editors and above can run fixes".into());
    }
    let (flag, name) = if kind == "ps" { (ps, "ps_enabled") } else { (cmd, "cmd_enabled") };
    match flag {
        None        => Some("This system's agent is older than 1.1.0 and cannot run fixes".into()),
        Some(false) => Some(format!("Fix scripts are off on this system: set {name} = true in its agent config")),
        Some(true)  => None,
    }
}

// The per-system and per-test facts a FixView is built from.
struct SystemFacts { os: String, cmd: Option<bool>, ps: Option<bool> }
struct Run { status: String, exit_code: Option<i64>, output: Option<String>, finished_at: Option<String> }

// ─────────────────────────────────────────────────────────────────────────────
// annotate_results
// Sets `fix` on each host-level result of a live report. Three small reads
// per page: the organization's systems, its tests that have a script, and the
// latest fix run per system and test.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn annotate_results<'a>(
    pool:      &SqlitePool,
    tenant_id: &str,
    is_editor: bool,
    results:   impl IntoIterator<Item = &'a mut IndividualResult>,
) {
    let systems: HashMap<i64, SystemFacts> = sqlx::query(
        "SELECT id, os, cmd_enabled, ps_enabled FROM systems WHERE tenant_id = ?",
    )
    .bind(tenant_id).fetch_all(pool).await
    .unwrap_or_else(|e| { error!("fix view: systems: {}", e); vec![] })
    .into_iter()
    .map(|r| (r.get::<i64, _>("id"), SystemFacts {
        os:  r.try_get::<Option<String>, _>("os").ok().flatten().unwrap_or_default(),
        cmd: r.try_get("cmd_enabled").ok().flatten(),
        ps:  r.try_get("ps_enabled").ok().flatten(),
    }))
    .collect();

    let scripts: HashMap<i64, (Option<String>, Option<String>)> = sqlx::query(
        "SELECT id, fix_sh, fix_ps FROM tests
          WHERE tenant_id = ? AND (fix_sh IS NOT NULL OR fix_ps IS NOT NULL)",
    )
    .bind(tenant_id).fetch_all(pool).await
    .unwrap_or_else(|e| { error!("fix view: tests: {}", e); vec![] })
    .into_iter()
    .map(|r| (r.get::<i64, _>("id"), (r.get("fix_sh"), r.get("fix_ps"))))
    .collect();

    let runs: HashMap<(i64, i64), Run> = sqlx::query(
        "SELECT system_id, test_id, status, exit_code, output, finished_at FROM fix_runs
          WHERE id IN (SELECT MAX(id) FROM fix_runs WHERE tenant_id = ? GROUP BY system_id, test_id)",
    )
    .bind(tenant_id).fetch_all(pool).await
    .unwrap_or_else(|e| { error!("fix view: runs: {}", e); vec![] })
    .into_iter()
    .map(|r| ((r.get::<i64, _>("system_id"), r.get::<i64, _>("test_id")), Run {
        status: r.get("status"), exit_code: r.get("exit_code"),
        output: r.get("output"), finished_at: r.get("finished_at"),
    }))
    .collect();

    for res in results {
        let (Some(sid), Some(tid)) = (res.system_id, res.test_id) else { continue };
        let view = build_view(
            res, systems.get(&sid), scripts.get(&tid), runs.get(&(sid, tid)), is_editor,
        );
        res.fix = Some(view).filter(|v| *v != FixView::default());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build_view
// One row's FixView. An open run shows whatever the result; otherwise only a
// failed, not excluded result whose test has a script for the system's OS
// gets a button.
// ─────────────────────────────────────────────────────────────────────────────
fn build_view(
    res:       &IndividualResult,
    system:    Option<&SystemFacts>,
    scripts:   Option<&(Option<String>, Option<String>)>,
    run:       Option<&Run>,
    is_editor: bool,
) -> FixView {
    let mut view = FixView::default();
    if let Some(r) = run {
        match r.status.as_str() {
            "queued" | "sent" => {
                view.state = Some(r.status.clone());
                return view;
            }
            "cancelled" => {}
            _ => {
                view.last = Some(LastFix {
                    status: r.status.clone(), exit_code: r.exit_code,
                    output: r.output.clone(), finished_at: r.finished_at.clone(),
                });
            }
        }
    }
    let Some(system) = system else { return view };
    if res.status != "FAIL" || res.is_excluded {
        return view;
    }
    let kind = kind_for_os(&system.os);
    let script = scripts.and_then(|(sh, ps)| if kind == "ps" { ps.clone() } else { sh.clone() });
    let Some(script) = script else { return view };
    view.kind = Some(kind.to_string());
    match why_not(kind, system.cmd, system.ps, is_editor) {
        None => {
            view.state = Some("ready".into());
            view.script = Some(script);
        }
        Some(why) => {
            view.state = Some("disabled".into());
            view.reason = Some(why);
        }
    }
    view
}

// ─────────────────────────────────────────────────────────────────────────────
// queue_fix
// Queues the test's script for the system, after checking everything the
// button showed again — the page may be stale, or the request hand-made.
// Ok carries the flash message.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn queue_fix(
    pool: &SqlitePool, auth: &AuthSession, ip: &str, system_id: i64, test_id: i64,
) -> Result<String, String> {
    let tenant = auth.tenant_id.as_str();
    let system = sqlx::query(
        "SELECT name, os, status, cmd_enabled, ps_enabled FROM systems WHERE id = ? AND tenant_id = ?",
    )
    .bind(system_id).bind(tenant).fetch_optional(pool).await
    .map_err(|e| { error!("queue_fix: {}", e); "Database error.".to_string() })?
    .ok_or("System not found.")?;
    if !matches!(system.try_get::<Option<String>, _>("status").ok().flatten().as_deref(), Some("active") | Some("approved")) {
        return Err("This system is not active.".into());
    }

    let result: Option<(String, i64)> = sqlx::query_as(
        "SELECT result, excluded FROM results
          WHERE tenant_id = ? AND system_id = ? AND test_id = ? AND container_id = 0",
    )
    .bind(tenant).bind(system_id).bind(test_id).fetch_optional(pool).await
    .map_err(|e| { error!("queue_fix: {}", e); "Database error.".to_string() })?;
    match result {
        Some((r, 0)) if r.eq_ignore_ascii_case("FAIL") => {}
        Some((_, x)) if x != 0 => return Err("This finding is excluded.".into()),
        _ => return Err("A fix can only be run on a failed result.".into()),
    }

    let os: String = system.try_get::<Option<String>, _>("os").ok().flatten().unwrap_or_default();
    let kind = kind_for_os(&os);
    let (test_name, sh, ps): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT name, fix_sh, fix_ps FROM tests WHERE id = ? AND tenant_id = ?",
    )
    .bind(test_id).bind(tenant).fetch_optional(pool).await
    .map_err(|e| { error!("queue_fix: {}", e); "Database error.".to_string() })?
    .ok_or("Test not found.")?;
    let script = if kind == "ps" { ps } else { sh }
        .ok_or("This test has no fix script for this system's OS.")?;
    let is_editor = auth::authorize(&auth.role, UserRole::Editor).is_none();
    if let Some(why) = why_not(kind, system.try_get("cmd_enabled").ok().flatten(),
                               system.try_get("ps_enabled").ok().flatten(), is_editor) {
        return Err(format!("{why}."));
    }

    let sha = script_sha256(&script);
    // One open fix per system and test, checked in the same statement.
    let inserted = sqlx::query(
        "INSERT INTO fix_runs (tenant_id, system_id, test_id, kind, script, script_sha256, requested_by)
         SELECT ?, ?, ?, ?, ?, ?, ?
          WHERE NOT EXISTS (SELECT 1 FROM fix_runs WHERE tenant_id = ? AND system_id = ? AND test_id = ?
                                AND status IN ('queued', 'sent'))",
    )
    .bind(tenant).bind(system_id).bind(test_id).bind(kind).bind(&script).bind(&sha).bind(auth.userid)
    .bind(tenant).bind(system_id).bind(test_id)
    .execute(pool).await
    .map_err(|e| { error!("queue_fix: {}", e); "Database error.".to_string() })?;
    if inserted.rows_affected() == 0 {
        return Err("A fix for this finding is already queued or running.".into());
    }

    let system_name: String = system.try_get::<Option<String>, _>("name").ok().flatten().unwrap_or_default();
    info!("Fix queued by '{}' — system={} test={} kind={}", auth.username, system_id, test_id, kind);
    crate::audit::record(
        pool, tenant, Some(auth), Some(ip), "fix.queue",
        Some("result"), Some(&format!("sys:{system_id}/test:{test_id}")),
        Some(serde_json::json!({
            "system_id": system_id, "system": system_name,
            "test_id": test_id, "test": test_name,
            "kind": kind, "script_sha256": sha,
        })),
    ).await;
    Ok(format!("Fix queued for {system_name}. It runs when the agent next checks in."))
}

// ─────────────────────────────────────────────────────────────────────────────
// cancel_fix
// Cancels a queued fix. One already sent to the agent cannot be stopped.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn cancel_fix(
    pool: &SqlitePool, auth: &AuthSession, ip: &str, system_id: i64, test_id: i64,
) -> Result<String, String> {
    let tenant = auth.tenant_id.as_str();
    let done = sqlx::query(
        "UPDATE fix_runs SET status = 'cancelled', finished_at = CURRENT_TIMESTAMP
          WHERE tenant_id = ? AND system_id = ? AND test_id = ? AND status = 'queued'",
    )
    .bind(tenant).bind(system_id).bind(test_id)
    .execute(pool).await
    .map_err(|e| { error!("cancel_fix: {}", e); "Database error.".to_string() })?;
    if done.rows_affected() == 0 {
        return Err("No queued fix to cancel — it may already have been sent to the agent.".into());
    }
    info!("Fix cancelled by '{}' — system={} test={}", auth.username, system_id, test_id);
    crate::audit::record(
        pool, tenant, Some(auth), Some(ip), "fix.cancel",
        Some("result"), Some(&format!("sys:{system_id}/test:{test_id}")),
        Some(serde_json::json!({ "system_id": system_id, "test_id": test_id })),
    ).await;
    Ok("Fix cancelled.".into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: back_to
// Redirects to `back` with the outcome as a flash message.
// ─────────────────────────────────────────────────────────────────────────────
fn back_to(back: &str, outcome: Result<String, String>) -> axum::response::Response {
    let (key, msg) = match outcome {
        Ok(m)  => ("success_message", m),
        Err(m) => ("error_message", m),
    };
    Redirect::to(&format!("{back}?{key}={}", urlencoding::encode(&msg))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{system_id}/fix/{test_id}         (and /cancel)
// POST /policies/report/{policy_id}/fix/{system_id}/{test_id} (and /cancel)
// Role: Editor. Back to the report the button was on.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_fix(
    auth: AuthSession, Path((system_id, test_id)): Path<(i64, i64)>,
    Extension(pool): Extension<SqlitePool>, ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) { return redir; }
    back_to(&format!("/systems/report/{system_id}"), queue_fix(&pool, &auth, ip.as_str(), system_id, test_id).await)
}

pub async fn system_report_fix_cancel(
    auth: AuthSession, Path((system_id, test_id)): Path<(i64, i64)>,
    Extension(pool): Extension<SqlitePool>, ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) { return redir; }
    back_to(&format!("/systems/report/{system_id}"), cancel_fix(&pool, &auth, ip.as_str(), system_id, test_id).await)
}

pub async fn policies_report_fix(
    auth: AuthSession, Path((policy_id, system_id, test_id)): Path<(i64, i64, i64)>,
    Extension(pool): Extension<SqlitePool>, ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) { return redir; }
    back_to(&format!("/policies/report/{policy_id}"), queue_fix(&pool, &auth, ip.as_str(), system_id, test_id).await)
}

pub async fn policies_report_fix_cancel(
    auth: AuthSession, Path((policy_id, system_id, test_id)): Path<(i64, i64, i64)>,
    Extension(pool): Extension<SqlitePool>, ip: ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) { return redir; }
    back_to(&format!("/policies/report/{policy_id}"), cancel_fix(&pool, &auth, ip.as_str(), system_id, test_id).await)
}
