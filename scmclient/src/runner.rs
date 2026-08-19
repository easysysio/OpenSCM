// =============================================================================
// runner.rs — local policy runner (offline CLI mode)
//
// Evaluates a standard OpenSCM policy JSON file against the local host without
// any server interaction. Reuses the existing compliance engine — only the
// network / heartbeat layer is bypassed. Output is either human-readable text
// (default) or structured JSON for CI/scripting use.
// =============================================================================

use std::fs;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use tracing::warn;

use crate::compliance::{evaluate, EvalResult};

// ============================================================
// Policy file format — mirrors the OpenSCM-store JSON shape.
// Kept separate from the network-protocol structs in models.rs
// so changes to either don't pull the other along by accident.
// ============================================================

#[derive(Debug, Deserialize)]
pub struct LocalPolicyFile {
    pub policy: LocalPolicyMeta,
    pub tests: Vec<LocalTest>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LocalPolicyMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LocalTest {
    pub external_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub app_filter: Option<String>,
    #[serde(default)]
    pub conditions: Vec<LocalCondition>,
    #[serde(default)]
    pub applicability: Vec<LocalCondition>,
}

#[derive(Debug, Deserialize)]
pub struct LocalCondition {
    pub element: String,
    #[serde(default)]
    pub input: String,
    pub selement: String,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub sinput: Option<String>,
}

// ============================================================
// Output structures (JSON mode)
// ============================================================

#[derive(Debug, Serialize)]
struct RunReport {
    policy: LocalPolicyMeta,
    system: SystemMeta,
    run_at: String,
    summary: RunSummary,
    results: Vec<TestOutcome>,
}

#[derive(Debug, Serialize)]
struct SystemMeta {
    hostname: String,
    os: String,
    arch: String,
}

#[derive(Debug, Serialize, Clone)]
struct RunSummary {
    total: usize,
    pass: usize,
    fail: usize,
    na: usize,
    compliance_pct: f32,
}

#[derive(Debug, Serialize)]
struct TestOutcome {
    external_id: Option<String>,
    name: String,
    result: String,
    severity: Option<String>,
    /// Container name when this outcome is per-container (IMAGE / NETWORK
    /// test fired against a specific container). None for host-level outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    container: Option<String>,
}

// ============================================================
// Public entry point
// ============================================================

pub struct RunOptions {
    pub policy_path: String,
    pub format: OutputFormat,
    pub strict: bool,
    pub failed_only: bool,
    pub cmd_enabled: bool,
    pub ps_enabled: bool,
}

#[derive(PartialEq)]
pub enum OutputFormat { Text, Json }

/// Returns an exit code: 0 = success, 1 = strict-mode FAIL, 2 = usage / I/O error.
pub fn run(opts: RunOptions) -> u8 {
    // Same scan-scoped CMD cache as the managed path.
    crate::compliance::reset_cmd_cache();
    let bytes = match fs::read(&opts.policy_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: cannot read policy file '{}': {}", opts.policy_path, e);
            return 2;
        }
    };

    let policy: LocalPolicyFile = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: policy file '{}' is not valid OpenSCM JSON: {}", opts.policy_path, e);
            return 2;
        }
    };

    let outcomes: Vec<TestOutcome> = policy.tests.iter()
        .flat_map(|t| evaluate_test(t, opts.cmd_enabled, opts.ps_enabled))
        .collect();

    let summary = summarize(&outcomes);
    let any_fail = summary.fail > 0;

    match opts.format {
        OutputFormat::Text => print_text(&policy.policy, &outcomes, &summary, opts.failed_only),
        OutputFormat::Json => print_json(&policy.policy, &outcomes, &summary),
    }

    if opts.strict && any_fail { 1 } else { 0 }
}

// ============================================================
// Single-test evaluator — mirrors agent.rs::process_compliance_tests
// without the network / signing layer.
// ============================================================

fn evaluate_test(t: &LocalTest, cmd_enabled: bool, ps_enabled: bool) -> Vec<TestOutcome> {
    // Applicability check — host-level, container=None. If not applicable,
    // the test produces a single NA outcome regardless of how many
    // containers exist.
    if !t.applicability.is_empty() {
        let app_results: Vec<EvalResult> = t.applicability.iter()
            .map(|c| evaluate(
                &c.element, &c.input, &c.selement,
                c.condition.as_deref().unwrap_or(""),
                c.sinput.as_deref().unwrap_or(""),
                cmd_enabled, ps_enabled,
                None,
            ))
            .collect();

        let is_applicable = match t.app_filter.as_deref().unwrap_or("all") {
            "any" => app_results.iter().any(|r| *r == EvalResult::Pass),
            _ => {
                app_results.iter().all(|r| *r == EvalResult::Pass || *r == EvalResult::Na)
                    && app_results.iter().any(|r| *r == EvalResult::Pass)
            }
        };

        if !is_applicable {
            return vec![host_outcome(t, "NA".into())];
        }
    }

    let conds: Vec<&LocalCondition> = t.conditions.iter()
        .filter(|c| !c.element.is_empty() && c.element != "None"
                 && !c.selement.is_empty() && c.selement != "None")
        .collect();

    // Per-container elements (EXEC + metadata) fan out across containers;
    // everything else runs once on the host. Mirrors the agent dispatch.
    let is_per_container = conds.iter()
        .any(|c| crate::compliance::is_per_container_element(&c.element));

    if is_per_container {
        let containers = crate::containers::enumerate().unwrap_or_default();
        if containers.is_empty() {
            return vec![host_outcome(t, "NA".into())];
        }
        return containers.iter().map(|container| {
            let results: Vec<EvalResult> = conds.iter().map(|c| evaluate(
                &c.element, &c.input, &c.selement,
                c.condition.as_deref().unwrap_or(""),
                c.sinput.as_deref().unwrap_or(""),
                cmd_enabled, ps_enabled,
                Some(container),
            )).collect();
            TestOutcome {
                external_id: t.external_id.clone(),
                name: t.name.clone(),
                result: crate::compliance::combine_verdict(&results, t.filter.as_deref().unwrap_or("all")),
                severity: t.severity.clone(),
                container: Some(container.name.clone()),
            }
        }).collect();
    }

    // Host-scope test — single outcome.
    let results: Vec<EvalResult> = conds.iter().map(|c| evaluate(
        &c.element, &c.input, &c.selement,
        c.condition.as_deref().unwrap_or(""),
        c.sinput.as_deref().unwrap_or(""),
        cmd_enabled, ps_enabled,
        None,
    )).collect();
    vec![host_outcome(t, crate::compliance::combine_verdict(&results, t.filter.as_deref().unwrap_or("all")))]
}

fn host_outcome(t: &LocalTest, result: String) -> TestOutcome {
    TestOutcome {
        external_id: t.external_id.clone(),
        name: t.name.clone(),
        result,
        severity: t.severity.clone(),
        container: None,
    }
}

// ============================================================
// Summary + output rendering
// ============================================================

fn summarize(outcomes: &[TestOutcome]) -> RunSummary {
    let total = outcomes.len();
    let pass = outcomes.iter().filter(|o| o.result == "PASS").count();
    let fail = outcomes.iter().filter(|o| o.result == "FAIL").count();
    let na   = outcomes.iter().filter(|o| o.result == "NA").count();
    let in_scope = (pass + fail) as f32;
    let compliance_pct = if in_scope > 0.0 {
        (pass as f32 / in_scope * 100.0 * 10.0).round() / 10.0
    } else { 0.0 };
    RunSummary { total, pass, fail, na, compliance_pct }
}

fn print_text(meta: &LocalPolicyMeta, outcomes: &[TestOutcome], summary: &RunSummary, failed_only: bool) {
    println!("{} v{} — {} tests\n", meta.name, meta.version, summary.total);

    for o in outcomes {
        if failed_only && o.result != "FAIL" { continue; }
        let marker = match o.result.as_str() {
            "PASS" => "PASS",
            "FAIL" => "FAIL",
            _      => "NA  ",
        };
        match &o.container {
            Some(c) => println!("  [{}] {}  [container:{}]", marker, o.name, c),
            None    => println!("  [{}] {}", marker, o.name),
        }
    }

    println!("\nSummary: {} PASS, {} FAIL, {} NA  →  {}% compliant",
        summary.pass, summary.fail, summary.na, summary.compliance_pct);
}

fn print_json(meta: &LocalPolicyMeta, outcomes: &[TestOutcome], summary: &RunSummary) {
    let osinfo = os_info::get();
    let report = RunReport {
        policy: meta.clone(),
        system: SystemMeta {
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            os: format!("{} {}", osinfo.os_type(), osinfo.version()),
            arch: std::env::consts::ARCH.into(),
        },
        run_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        summary: summary.clone(),
        results: outcomes.iter().map(|o| TestOutcome {
            external_id: o.external_id.clone(),
            name: o.name.clone(),
            result: o.result.clone(),
            severity: o.severity.clone(),
            container: o.container.clone(),
        }).collect(),
    };
    match serde_json::to_string_pretty(&report) {
        Ok(s) => println!("{}", s),
        Err(e) => { warn!("Failed to serialize report: {}", e); }
    }
}

