// =============================================================================
// fixes.rs — run remediation fix scripts the server queued (1.1.0)
//
// docs/design/1.1.0-remediation.md. The heartbeat reply may carry a `fixes`
// list; each entry is one script an Editor chose to run on this system for a
// failed test. The agent is the last word on whether it runs:
//   • shell scripts need cmd_enabled = true, PowerShell needs ps_enabled = true
//     (checked here against this agent's own config, never the server's view);
//   • shell runs only on Unix-like systems, PowerShell only on Windows;
//   • the script must match the SHA-256 the server sent with it.
// Anything else is reported as `refused`, and nothing runs.
// =============================================================================

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::process::Stdio;
use std::time::Duration;

use crate::models::Test;

// The most output kept and sent back per fix (the server caps it too).
pub const OUTPUT_MAX: usize = 64 * 1024;


// One fix from the heartbeat reply.
#[derive(Debug, Deserialize, Clone)]
pub struct FixJob {
    pub id:           i64,
    pub test_id:      i64,
    pub kind:         String,
    pub script:       String,
    pub sha256:       String,
    pub timeout_secs: u64,
    /// The test the fix is for, checked again once the script has run.
    pub test:         Test,
}

// What happened, sent back signed to POST /fix_result.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FixResult {
    pub client_id:    i64,
    pub organization: String,
    pub fix_id:       i64,
    pub status:       String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code:    Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol:     Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at_ms:   Option<i64>,
}

// The outcome of one fix, before it is wrapped into a FixResult.
#[derive(Debug, PartialEq)]
pub struct Outcome {
    pub status:    &'static str,
    pub exit_code: Option<i64>,
    pub output:    String,
}

impl Outcome {
    fn refused(why: String) -> Self {
        Outcome { status: "refused", exit_code: None, output: why }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// check_job
// Why this agent will not run `job`, or Ok if it will. `windows` is the
// platform the agent runs on (a parameter so both cases can be tested).
// ─────────────────────────────────────────────────────────────────────────────
pub fn check_job(job: &FixJob, cmd_enabled: bool, ps_enabled: bool, windows: bool) -> Result<(), String> {
    match job.kind.as_str() {
        "sh" if windows => return Err("a shell fix cannot run on Windows".into()),
        "ps" if !windows => return Err("a PowerShell fix runs only on Windows".into()),
        "sh" if !cmd_enabled => {
            return Err("fix scripts are disabled: set 'cmd_enabled = true' in the agent's [client] config".into());
        }
        "ps" if !ps_enabled => {
            return Err("fix scripts are disabled: set 'ps_enabled = true' in the agent's [client] config".into());
        }
        "sh" | "ps" => {}
        other => return Err(format!("unknown fix kind '{other}'")),
    }
    let actual = format!("{:x}", Sha256::digest(job.script.as_bytes()));
    if !actual.eq_ignore_ascii_case(job.sha256.trim()) {
        return Err("the script does not match its SHA-256".into());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// run_job
// Checks `job`, then runs its script with the job's timeout. Exit code 0 is
// `done`, any other `failed`; a script still running at the timeout is killed
// and reported as `timeout`.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_job(job: &FixJob, cmd_enabled: bool, ps_enabled: bool) -> Outcome {
    if let Err(why) = check_job(job, cmd_enabled, ps_enabled, cfg!(windows)) {
        return Outcome::refused(why);
    }
    run_script(&job.kind, &job.script, Duration::from_secs(job.timeout_secs.max(1))).await
}

// ─────────────────────────────────────────────────────────────────────────────
// run_script
// Shell scripts run with `/bin/sh -c`, PowerShell ones with
// `powershell -NoProfile -NonInteractive -Command`, as the agent's own user.
// stdout and stderr are combined, as for the CMD element.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_script(kind: &str, script: &str, timeout: Duration) -> Outcome {
    let mut cmd = if kind == "ps" {
        let mut c = tokio::process::Command::new("powershell");
        c.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        c
    } else {
        let mut c = tokio::process::Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Outcome { status: "failed", exit_code: None, output: format!("cannot start the script: {e}") },
    };
    // On timeout the future, and with it the child, is dropped: kill_on_drop
    // kills the script.
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let output = match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
                (false, false) => format!("{}\n{}", stdout.trim_end(), stderr.trim_end()),
                (true,  false) => stderr.trim_end().to_string(),
                _              => stdout.trim_end().to_string(),
            };
            let code = o.status.code().map(i64::from);
            Outcome {
                status: if code == Some(0) { "done" } else { "failed" },
                exit_code: code,
                output: cap(&output),
            }
        }
        Ok(Err(e)) => Outcome { status: "failed", exit_code: None, output: format!("the script could not be run: {e}") },
        Err(_) => Outcome {
            status: "timeout",
            exit_code: None,
            output: format!("stopped after {} seconds", timeout.as_secs()),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: cap
// At most OUTPUT_MAX bytes, cut on a character boundary.
// ─────────────────────────────────────────────────────────────────────────────
fn cap(s: &str) -> String {
    if s.len() <= OUTPUT_MAX {
        return s.to_string();
    }
    let mut end = OUTPUT_MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn job(kind: &str, script: &str) -> FixJob {
        FixJob {
            id: 1, test_id: 2, kind: kind.into(), script: script.into(),
            sha256: format!("{:x}", Sha256::digest(script.as_bytes())),
            timeout_secs: 5, test: Test::default(),
        }
    }

    // The shape scmserver::fixes::FixDispatch serializes to (its tests check
    // the server side of this): the test is a TEST-command test.
    #[test]
    fn a_fix_from_the_server_parses() {
        let v = serde_json::json!({
            "id": 4, "test_id": 7, "kind": "sh", "script": "true\n",
            "sha256": format!("{:x}", Sha256::digest(b"true\n")), "timeout_secs": 300,
            "test": {
                "id": 7, "name": "SSH root login off", "description": null, "rational": null,
                "remediation": null, "severity": "High", "filter": "all", "app_filter": "all",
                "conditions": [{
                    "id": 1, "tenant_id": "default", "test_id": 7, "type": "condition",
                    "element": "FILE", "input": "/etc/ssh/sshd_config", "selement": "CONTENT",
                    "condition": "contains", "sinput": "PermitRootLogin no"
                }],
                "applicability": null
            }
        });
        let job: FixJob = serde_json::from_value(v).unwrap();
        assert_eq!((job.id, job.test_id, job.timeout_secs), (4, 7, 300));
        assert_eq!(job.test.id, Some(7));
        assert_eq!(job.test.conditions.len(), 1);
        assert!(check_job(&job, true, false, false).is_ok());
    }

    #[test]
    fn a_fix_runs_only_where_this_agents_config_allows_it() {
        let sh = job("sh", "true");
        assert!(check_job(&sh, true, false, false).is_ok());
        assert!(check_job(&sh, false, true, false).unwrap_err().contains("cmd_enabled"));
        assert!(check_job(&sh, true, true, true).unwrap_err().contains("Windows"));

        let ps = job("ps", "Write-Output ok");
        assert!(check_job(&ps, false, true, true).is_ok());
        assert!(check_job(&ps, true, false, true).unwrap_err().contains("ps_enabled"));
        assert!(check_job(&ps, true, true, false).unwrap_err().contains("only on Windows"));

        assert!(check_job(&job("bat", "x"), true, true, false).unwrap_err().contains("unknown"));
    }

    #[test]
    fn a_script_that_does_not_match_its_hash_is_refused() {
        let mut j = job("sh", "echo hi");
        j.script = "rm -rf /tmp/whatever".into();
        assert!(check_job(&j, true, true, false).unwrap_err().contains("SHA-256"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_refused_fix_runs_nothing() {
        let marker = std::env::temp_dir().join(format!("oscm-fix-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let j = job("sh", &format!("touch {}", marker.display()));
        let out = run_job(&j, false, false).await;
        assert_eq!(out.status, "refused");
        assert!(!marker.exists(), "the script ran although cmd_enabled is off");

        let out = run_job(&j, true, false).await;
        assert_eq!(out.status, "done");
        assert!(marker.exists());
        let _ = std::fs::remove_file(&marker);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exit_code_and_output_are_reported() {
        let out = run_script("sh", "echo fixed\necho warn >&2", Duration::from_secs(5)).await;
        assert_eq!(out, Outcome { status: "done", exit_code: Some(0), output: "fixed\nwarn".into() });

        let out = run_script("sh", "echo nope; exit 3", Duration::from_secs(5)).await;
        assert_eq!(out, Outcome { status: "failed", exit_code: Some(3), output: "nope".into() });
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_script_that_runs_too_long_is_stopped() {
        let started = std::time::Instant::now();
        let out = run_script("sh", "sleep 30", Duration::from_secs(1)).await;
        assert_eq!(out.status, "timeout");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_is_capped() {
        let out = run_script("sh", "head -c 200000 /dev/zero | tr '\\0' x", Duration::from_secs(5)).await;
        assert_eq!(out.status, "done");
        assert_eq!(out.output.len(), OUTPUT_MAX);
    }
}
