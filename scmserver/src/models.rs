// =============================================================================
// models.rs — all data model structs and enums
//
// These are pure data types shared across all route modules. No business logic
// lives here — only field definitions and standard trait derivations.
// =============================================================================

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sqlx::FromRow;
use chrono::{DateTime, Utc};


// Query parameters used on pages that show flash messages.
#[derive(Deserialize)]
pub struct ErrorQuery {
    pub error_message: Option<String>,
    pub success_message: Option<String>,
    /// Trend-chart bucketing on the report pages (hourly/daily/weekly/monthly/
    /// yearly), mirroring the dashboard's ?range=. None elsewhere — harmless.
    pub range: Option<String>,
}


// A portal user account (id, username, role, display name, email).
#[derive(Deserialize, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub name: Option<String>,
    pub email: Option<String>,
}


// A managed agent system as stored in the systems table.
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct System {
    pub id: Option<i32>,
    pub name: String,
    pub ver: Option<String>,
    pub ip: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    /// Normalised "{arch}-{os_type}" platform string (e.g. "x86_64-linux").
    /// Derived server-side from arch + os on every heartbeat; used to match
    /// the system against the agent_packages table for upgrade availability.
    pub platform: Option<String>,
    pub status: Option<String>,
    pub groups: Option<String>,
    pub auth_signature: Option<String>,
    pub auth_public_key: Option<String>,
    pub trust_challenge: Option<String>,
    pub trust_proof: Option<String>,
    pub created_date: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Computed server-side: true when last_seen is older than offline_threshold.
    #[serde(default)]
    pub is_offline: bool,
    /// Set server-side: true when agent_packages has a newer version for this platform.
    #[serde(default)]
    pub upgrade_available: bool,
    /// The newer version available for this system, if any.
    pub upgrade_version: Option<String>,
    // Live telemetry — updated on every heartbeat; None if agent hasn't reported yet.
    pub cpu_usage:    Option<f32>,
    pub mem_used_mb:  Option<i64>,
    pub mem_total_mb: Option<i64>,
    pub disk_used_gb: Option<i64>,
    pub disk_total_gb: Option<i64>,
    pub uptime_secs:  Option<i64>,
    /// True when at least cpu_usage is present — used as a reliable Tera gate.
    #[serde(default)]
    pub has_telemetry: bool,
}


// A row from the agent_packages table.
// One entry per supported client platform, upserted each time the server starts.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentPackage {
    pub platform: String,
    pub version:  String,
    pub sha256:   String,
    pub url:      String,
}

// A named group of systems used to link systems to policies.
#[derive(Serialize, Deserialize, Default)]
pub struct SystemGroup {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub systems: Option<String>,
    /// 0 = manual (admin-curated), 1 = auto (membership reconciled by a rule
    /// in auto_group_rules). Immutable after group creation. See
    /// docs/design/0.5.2-auto-groups.md.
    #[serde(default)]
    pub auto_managed: i64,
    /// Number of systems in the group, for the groups list. Only the list page
    /// computes it; other callers leave it 0 and never display it.
    #[serde(default)]
    pub system_count: i64,
}


// Many-to-many join row: a system assigned to a group.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInsideGroup {
    pub system_id: i32,
    pub group_id:  i32,
}

// A compliance test definition (name, severity, filter, remediation, etc.).
#[derive(Debug, Serialize, Deserialize, FromRow, Default, Clone)]
pub struct Test {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    pub app_filter: Option<String>,
}


// One condition (or applicability rule) row in the test_conditions table.
#[derive(Debug, sqlx::FromRow, Serialize, Deserialize, Clone)]
pub struct TestCondition {
    pub id: i64,
    pub tenant_id: String,
    pub test_id: i64,
    pub r#type: String,
    pub element: String,
    pub input: String,
    pub selement: String,
    pub condition: Option<String>,
    pub sinput: Option<String>,
}


// A test bundled with its conditions and applicability rules (sent to agents).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestWithConditions {
    #[serde(flatten)]
    pub test: Test,
    pub conditions: Vec<TestCondition>,
    pub applicability: Option<Vec<TestCondition>>,
}

// Flat wire-format for sending a test + conditions to an agent.
// Mirrors the client's Test struct exactly — no #[serde(flatten)] so
// serialization is deterministic and the Ed25519 signature round-trips cleanly.
#[derive(Debug, Serialize, Clone)]
pub struct TestPayload {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    pub app_filter: Option<String>,
    pub conditions: Vec<TestCondition>,
    pub applicability: Option<Vec<TestCondition>>,
}

impl From<TestWithConditions> for TestPayload {
    fn from(twc: TestWithConditions) -> Self {
        TestPayload {
            id:          twc.test.id.map(|i| i as i64),
            name:        twc.test.name,
            description: twc.test.description,
            rational:    twc.test.rational,
            remediation: twc.test.remediation,
            severity:    twc.test.severity,
            filter:      twc.test.filter,
            app_filter:  twc.test.app_filter,
            conditions:  twc.conditions,
            applicability: twc.applicability,
        }
    }
}


// A security policy (name, version, description).
#[derive(Serialize, Deserialize)]
pub struct Policy {
    pub id: Option<i32>,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub external_id: Option<String>,
}

// Wire format for a single test inside an export file.  Strips DB-internal
// fields (id, tenant_id, test_id) — they are regenerated on import.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyExportTestCondition {
    pub r#type: String,
    pub element: String,
    pub input: String,
    pub selement: String,
    pub condition: Option<String>,
    pub sinput: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyExportTest {
    #[serde(default)]
    pub external_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    pub app_filter: Option<String>,
    #[serde(default)]
    pub conditions: Vec<PolicyExportTestCondition>,
    #[serde(default)]
    pub applicability: Vec<PolicyExportTestCondition>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyExportPolicy {
    #[serde(default)]
    pub external_id: Option<String>,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyExport {
    pub format_version: u32,
    pub policy: PolicyExportPolicy,
    pub tests: Vec<PolicyExportTest>,
}

// Summary returned by apply_policy_import — surfaced in flash messages and
// re-used by SaaS handlers (e.g. /store/install) that wrap the same logic.
#[derive(Debug, Clone)]
pub struct PolicyImportSummary {
    pub policy_id:      i64,
    pub action:         &'static str, // "imported" or "updated"
    pub inserted_tests: usize,
    pub updated_tests:  usize,
    pub unlinked_tests: u64,
}

// An automated scan or report schedule for a policy.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PolicySchedule {
    pub id: i32,
    pub tenant_id: String,
    pub policy_id: i32,
    pub enabled: i64, // SQLite returns INTEGER; Tera treats 0/1 as falsy/truthy
    pub schedule_type: String, // "scan" or "report"
    pub frequency: String, // "daily", "weekly", "monthly", "custom"
    pub cron_expression: Option<String>, // Only used for "custom"
    pub next_run: String, // Stored as ISO 8601 string in SQLite
    pub last_run: Option<String>, // Null until the first successful execution
}



// One row from the compliance_history table used by dashboard trend charts.
#[derive(sqlx::FromRow, serde::Serialize, Clone)]
pub struct ComplianceHistoryRow {
    pub check_date: String,
    pub systems_score: f64,
    pub policies_score: f64,
}


// Many-to-many join row: a test assigned to a policy.
#[derive(Debug, Serialize, Deserialize)]
pub struct TestInsidePolicy {
    pub policy_id: i32,
    pub test_id:  i32,
}

// Many-to-many join row: a system group assigned to a policy.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInsidePolicy {
    pub policy_id: i32,
    pub group_id:  i32,
}

// A user notification row from the notify table.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Notification {
    pub id: i64,
    pub tenant_id: String,
    pub ntype: String,
    pub nts: String,
    pub owner_id: i32,
    pub message: String,
}


// The deserialized body of an agent's heartbeat or registration request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnsignedPayload {
    pub id: String,
    #[serde(alias = "tenant_id")]
    pub organization: String,
    pub hostname: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
    pub timestamp: String,
    pub public_key: Option<String>,
    /// Golden enrollment token, sent only at first registration (id = 0). When
    /// valid, the server brings the system up `active` instead of `pending`.
    /// Approval bypass only — see docs/design/0.6.0-enrollment-tokens.md.
    #[serde(default)]
    pub enrollment_token: Option<String>,
    // Telemetry — all optional; absent from old clients defaults to None.
    #[serde(default)]
    pub cpu_usage:    Option<f32>,
    #[serde(default)]
    pub mem_used_mb:  Option<i64>,
    #[serde(default)]
    pub mem_total_mb: Option<i64>,
    #[serde(default)]
    pub disk_used_gb: Option<i64>,
    #[serde(default)]
    pub disk_total_gb: Option<i64>,
    #[serde(default)]
    pub uptime_secs:  Option<i64>,
    /// App-container inventory shipped by the Linux agent. None = field absent
    /// (old agent or non-Linux); we leave existing container rows alone.
    /// Some([]) = explicit "no containers right now", so we delete the host's rows.
    /// Some([...]) = full current list; we upsert each and delete anything not in it.
    #[serde(default)]
    pub containers:   Option<Vec<IncomingContainer>>,
}


// One container as reported by a Linux agent. Mirrors the columns of the
// `containers` table 1-to-1; metadata fields are optional so partial reports
// (e.g. inspect failed for one container) still ingest cleanly.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IncomingContainer {
    pub runtime:         String,
    pub runtime_id:      String,
    pub name:            String,
    pub image:           Option<String>,
    pub image_digest:    Option<String>,
    pub status:          Option<String>,
    pub ip:              Option<String>,
    pub is_privileged:   Option<bool>,
    pub run_user:        Option<String>,
    pub network_mode:    Option<String>,
    pub exposed_ports:   Option<String>,
    pub mounts:          Option<String>,
    pub capabilities_add: Option<String>,
    pub read_only_fs:    Option<bool>,
    pub restart_policy:  Option<String>,
    pub health_check:    Option<bool>,
}


// An agent heartbeat/registration request with a raw JSON payload and signature.
// payload is stored as RawValue to preserve byte order for signature verification.
#[derive(Debug, Deserialize)]
pub struct SignedRequest {
    pub payload: Box<RawValue>,
    pub signature: String,
}


// An agent compliance result submission with a raw JSON payload and signature.
#[derive(Deserialize)]
pub struct SignedResult {
    pub payload: Box<RawValue>,
    pub signature: String,
}

// The server's signed response sent back to the agent.
#[derive(Serialize, Deserialize)]
pub struct SignedResponse {
    pub payload: serde_json::Value,
    pub signature: String,
}

// The deserialized body of an agent compliance result (POST /result).
#[derive(Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    #[serde(alias = "tenant_id")]
    pub organization: String,
    pub test_id: i64,
    pub result: String,
    /// Per-container result identifier (e.g. Docker's container hash).
    /// None = host-level result; container_id will resolve to 0.
    /// Some = the result handler looks up containers.id via
    /// (host_system_id, runtime_id) and binds it on the result row.
    #[serde(default)]
    pub container_runtime_id: Option<String>,
    /// Per-condition evidence (JSON array) explaining the verdict. None from
    /// pre-0.6.4 agents — stored as NULL, reports just show no detail panel.
    #[serde(default)]
    pub evidence: Option<String>,
}


// Aggregated compliance data for a single policy (used by the policies list page).
#[derive(FromRow, Serialize, Deserialize)]
pub struct PolicyCompliance {
    pub policy_id: i64,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_description: Option<String>,
    pub author: Option<String>,
    pub compliance: f64,
    pub test_count: i64,
    pub system_count: i64,
    pub systems_passed: Option<i64>,
    pub systems_failed: Option<i64>,
}


// A row in the "highest risk assets" dashboard query result.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct SystemFailRow {
    pub system_id: i32,
    pub system_name: String,
    pub os: String,
    pub compliance: f64,
    pub tests_passed: i32,
    pub tests_failed: i32,
    pub tests_na: i64,
}

// One policy's worth of compliance results for a single system.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResultGroup {
    pub policy_id: i32,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_description: Option<String>,
    pub results: Vec<IndividualResult>,
    pub is_passed: bool,
    pub pass_count: usize,
    pub fail_count: usize,
    /// NA results (status == "NA" or "NOT_SCANNED"; excludes excluded findings).
    #[serde(default)]
    pub na_count: usize,
    /// EXCLUDED results — admin-suppressed findings, treated as NA in scoring.
    #[serde(default)]
    pub excluded_count: usize,
}

// One container's worth of per-container test results, nested under its host
// in a report. Containers are scored on their own axis (design §11), so this
// carries its own compliance_score independent of the host's. Reuses
// IndividualResult for the per-test rows (incl. the evidence "why?" payload).
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerReportGroup {
    pub container_id: i64,
    pub name: String,
    pub runtime: String,
    pub image: Option<String>,
    pub compliance_score: f64,
    pub pass_count: usize,
    pub fail_count: usize,
    #[serde(default)]
    pub na_count: usize,
    pub results: Vec<IndividualResult>,
}

// All data needed to render the system live-report page or a saved snapshot.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemReportData {
    pub system_id: i32,
    pub system_name: String,
    pub os: String,
    pub arch: Option<String>,
    pub ip: Option<String>,
    pub compliance_score: f64,
    pub last_seen: Option<String>,
    pub policy_groups: Vec<PolicyResultGroup>,
    pub total_pass: usize,
    pub total_fail: usize,
    pub total_na: usize,
    /// Per-container test results for containers on this host (separate axis).
    /// Empty for hosts with no containers / no container tests; default keeps
    /// older saved snapshots deserialising cleanly.
    #[serde(default)]
    pub containers: Vec<ContainerReportGroup>,
}

// A row in the "critical policy failures" dashboard query result.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct PolicyFailRow {
    pub policy_id: i32,
    pub policy_name: String,
    pub policy_version: String,
    pub compliance: f64,
    pub systems_passed: i32,
    pub systems_failed: i32,
}



// A test condition element (e.g. FILE, REGISTRY, CMD) from the elements table.
#[derive(Serialize, Deserialize, Clone)]
pub struct Element {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}


// A secondary element modifier (e.g. EXISTS, CONTENT) from the selements table.
#[derive(Serialize, Deserialize)]
pub struct SElement {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

// A comparison operator (e.g. EQUALS, CONTAINS) from the conditions table.
#[derive(Serialize, Deserialize)]
pub struct Condition {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}


// Full policy compliance report data (used for both HTML view and PDF export).
#[derive(Serialize, Deserialize)]
pub struct ReportData {
    pub policy_id: i32,
    pub policy_name: String,
    pub version: String,
    pub description: String,
    pub submission_date: String,
    pub submitter_name: String,
    pub tests_metadata: Vec<TestMeta>,
    pub system_reports: Vec<SystemReport>,
    /// Totals across all systems — same shape as SystemReportData so the policy
    /// report's top card can mirror the system report's layout. All four default
    /// to 0 in older saved snapshots that lack the field.
    #[serde(default)]
    pub total_pass: usize,
    #[serde(default)]
    pub total_fail: usize,
    #[serde(default)]
    pub total_na: usize,
    #[serde(default)]
    pub total_excluded: usize,
    /// % of in-scope systems that are COMPLIANT (pass>0 && fail==0). -1.0 means
    /// no in-scope systems with any non-excluded results (all-NA, "Not Scanned").
    #[serde(default = "neg_one")]
    pub compliance_score: f64,
}

fn neg_one() -> f64 { -1.0 }



// Metadata for a single test as stored in a saved report (name, description, etc.).
#[derive(Serialize, Deserialize)]
pub struct TestMeta {
    pub name: String,
    pub description: String,
    pub rational: String,
    pub remediation: String,
}

// One system's compliance results grouped into a report.
#[derive(Serialize, Deserialize)]
pub struct SystemReport {
    pub system_name: String,
    pub results: Vec<IndividualResult>,
    pub is_passed: bool,
    /// Number of PASS results — used by templates for the all-NA "exempt" check.
    /// #[serde(default)] keeps old saved reports (which lack this field) deserializing cleanly.
    #[serde(default)]
    pub pass_count: usize,
    /// Number of FAIL results — used by templates for the all-NA "exempt" check.
    #[serde(default)]
    pub fail_count: usize,
    /// Number of NA results (excluded from both numerator and denominator in scoring).
    #[serde(default)]
    pub na_count: usize,
    /// Number of EXCLUDED results — admin-suppressed findings, also treated as NA.
    #[serde(default)]
    pub excluded_count: usize,
    /// Per-container test results for containers on this host, nested under the
    /// system row in the policy report. Separate compliance axis (design §11).
    #[serde(default)]
    pub containers: Vec<ContainerReportGroup>,
}

// A single test result (test name + PASS/FAIL/NA status) inside a report.
//
// is_excluded mirrors the `results.excluded` column for a (system, test) pair;
// excluded results render with an "Excluded" badge and
// are treated as NA in compliance scoring. Default false so deserialising
// older archive snapshots (saved before the field existed) still works.
// is_excludable is a render hint — true on the live policy report (right-click
// menu should appear), false on archived snapshots (frozen, no menu).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IndividualResult {
    pub test_name: String,
    pub status: String,
    #[serde(default)]
    pub is_excluded: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_excludable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_id: Option<i64>,
    /// Per-condition evidence JSON (which conditions matched/failed + a generic
    /// note) explaining the verdict. None for pre-0.6.4 results / not-scanned.
    /// Parsed and rendered by the report template's "why" panel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Why this finding was excluded, recorded at exclusion time. None for
    /// findings that are not excluded, and for exclusions made before 0.8.2 —
    /// those genuinely have no reason on record. #[serde(default)] keeps saved
    /// reports from before the field existed deserialising cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_reason: Option<String>,
}


// A saved system compliance report snapshot row from the system_reports table.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SavedSystemReport {
    pub id: i32,
    pub tenant_id: String,
    pub submission_date: String,
    pub system_id: i32,
    pub system_name: String,
    pub submitter_name: Option<String>,
    pub report_data: Option<String>, // JSON-serialised SystemReportData
}

// A saved policy compliance report row from the reports table.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Report {
    pub id: i32,
    pub tenant_id: String,
    pub submission_date: String,
    pub policy_name: String,
    pub policy_version: Option<String>,
    pub policy_description: Option<String>,
    pub submitter_name: Option<String>,
    pub tests_metadata: Option<String>,
    pub report_results: Option<String>,
}




// The authenticated session extracted from the signed cookie on every request.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub username: String,
    pub userid: i32,
    /// The tenant every query in this request scopes to. While a superuser is
    /// impersonating, this is the TARGET tenant — that is what makes every
    /// existing page work unchanged.
    pub tenant_id: String,
    /// The effective role. While impersonating this is forced to "viewer", so
    /// the ordinary authorize() checks reject any privileged action without
    /// each handler needing to know impersonation exists.
    pub role: String,
    /// Present only while a superuser is viewing another tenant. Keeps the
    /// real identity so audit entries attribute actions to the human rather
    /// than to the tenant being viewed, and so we know where to return to.
    pub impersonating: Option<Impersonation>,
}

/// Who the operator really is while impersonating another tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Impersonation {
    pub real_tenant_id: String,
    pub real_role: String,
}

// One row from the audit_log table — used by the /admin/audit-log viewer.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub tenant_id: String,
    pub actor_user_id: Option<i64>,
    pub actor_username: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id:   Option<String>,
    pub details:     Option<String>,
    pub ip_address:  Option<String>,
    pub created_at:  String,
}


// Role hierarchy used for authorization checks (Viewer < Runner < Editor < Admin < Superuser).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserRole {
    Viewer = 0,
    Runner = 1,
    Editor = 2,
    Admin = 3,
    Superuser = 4,
}


impl From<&str> for UserRole {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "superuser" => UserRole::Superuser,
            "admin" => UserRole::Admin,
            "editor" => UserRole::Editor,
            "runner" => UserRole::Runner,
            _ => UserRole::Viewer,
        }
    }
}

