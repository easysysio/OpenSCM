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
