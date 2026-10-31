// =============================================================================
// api/shape.rs — how /api/v1 writes its answers (docs/design/1.0.0-api-v1.md)
//
// The API shares its queries with the pages, PDFs and saved reports, but not
// their output: those structs hold display strings, -1 for "not scanned" and
// evidence as stored text. This module turns them into the v1 shapes:
//   • score       — 2 decimals; null when there is nothing to score (D3)
//   • timestamp   — ISO 8601 UTC with Z, whatever the stored format (D4)
//   • evidence    — the JSON array itself, not a string (D5)
//   • Checked     — when each result was last reported (checked_at, D6)
//   • audit_details — always an object (D8)
//   • typed structs for the compliance and report bodies (D2, D10): built
//     field by field, so renaming an internal field fails the build instead
//     of quietly changing the frozen API.
// Field names follow v1beta1 except where the design changes them.
// =============================================================================

use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};

use crate::models::{
    ContainerReportGroup, IndividualResult, PolicyResultGroup, ReportData, SystemReport,
    SystemReportData, TestMeta,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: score — rounded to 2 decimals; None for "not scanned" (stored as -1
// or NULL) and anything that is not a number.
// ─────────────────────────────────────────────────────────────────────────────
pub fn score(v: f64) -> Option<f64> {
    if !v.is_finite() || v < 0.0 { None } else { Some((v * 100.0).round() / 100.0) }
}

pub fn opt_score(v: Option<f64>) -> Option<f64> {
    v.and_then(score)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: text — optional free text, None when absent or blank, so an empty
// test description is null whether it was stored as NULL or as "".
// ─────────────────────────────────────────────────────────────────────────────
pub fn text(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: timestamp — any format OpenSCM has stored a UTC time in, as
// "YYYY-MM-DDTHH:MM:SSZ". None for empty or unreadable values.
// ─────────────────────────────────────────────────────────────────────────────
pub fn timestamp(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() { return None; }
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.with_timezone(&Utc).format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    for f in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S%.f",
              "%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M UTC", "%Y-%m-%d %H:%M"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(t, f) {
            return Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        }
    }
    None
}

pub fn opt_timestamp(v: Option<&str>) -> Option<String> {
    v.and_then(timestamp)
}

// The current time, as v1 writes it.
pub fn now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: evidence — the stored evidence text as the array it holds. None
// when there is none or it does not parse to an array.
// ─────────────────────────────────────────────────────────────────────────────
pub fn evidence(raw: Option<&str>) -> Option<Value> {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok()).filter(Value::is_array)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: audit_details — an object, or None. Entries written as plain text
// (or as JSON that is not an object) come back as {"message": "<text>"}.
// ─────────────────────────────────────────────────────────────────────────────
pub fn audit_details(raw: Option<String>) -> Option<Value> {
    let raw = raw.filter(|s| !s.trim().is_empty())?;
    match serde_json::from_str::<Value>(&raw) {
        Ok(v @ Value::Object(_)) => Some(v),
        _ => Some(json!({"message": raw})),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checked — results.last_updated by (system, test) for host results and by
// (container, test) for container results: when the server last received
// the agent's verdict.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Default)]
pub struct Checked {
    hosts: HashMap<(i64, i64), Option<String>>,
    containers: HashMap<(i64, i64), Option<String>>,
}

impl Checked {
    // Every result of one system.
    pub async fn for_system(pool: &SqlitePool, tenant_id: &str, system_id: i64) -> Result<Self, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT system_id, container_id, test_id, CAST(last_updated AS TEXT) AS at
               FROM results WHERE tenant_id = ? AND system_id = ?")
            .bind(tenant_id).bind(system_id).fetch_all(pool).await?;
        Ok(Self::from_rows(rows))
    }

    // Every result of one policy's tests.
    pub async fn for_policy(pool: &SqlitePool, tenant_id: &str, policy_id: i64) -> Result<Self, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT system_id, container_id, test_id, CAST(last_updated AS TEXT) AS at
               FROM results
              WHERE tenant_id = ?
                AND test_id IN (SELECT test_id FROM tests_in_policy WHERE tenant_id = ? AND policy_id = ?)")
            .bind(tenant_id).bind(tenant_id).bind(policy_id).fetch_all(pool).await?;
        Ok(Self::from_rows(rows))
    }

    fn from_rows(rows: Vec<sqlx::sqlite::SqliteRow>) -> Self {
        let mut c = Checked::default();
        for r in rows {
            let (sid, cid, tid): (i64, i64, i64) = (r.get("system_id"), r.get("container_id"), r.get("test_id"));
            let at = opt_timestamp(r.get::<Option<String>, _>("at").as_deref());
            if cid == 0 { c.hosts.insert((sid, tid), at); } else { c.containers.insert((cid, tid), at); }
        }
        c
    }
}

// Live results say when they were checked; saved snapshots never stored it,
// so their results have no checked_at at all.
#[derive(Clone, Copy)]
pub enum When<'a> {
    Live(&'a Checked),
    Saved,
}

// Where a result sits: on a host, or in one of its containers.
#[derive(Clone, Copy)]
enum On {
    Host(Option<i64>),
    Container(i64),
}

// ── Typed v1 bodies ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ResultV1 {
    pub test_id: Option<i64>,
    pub test_name: String,
    pub system_id: Option<i64>,
    pub status: String,
    pub is_excluded: bool,
    pub excluded_reason: Option<String>,
    pub evidence: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<Option<String>>,
}

fn result(r: IndividualResult, when: When, on: On) -> ResultV1 {
    let checked_at = match when {
        When::Saved => None,
        When::Live(c) => Some(r.test_id.and_then(|tid| match on {
            On::Container(cid) => c.containers.get(&(cid, tid)).cloned().flatten(),
            On::Host(sid) => r.system_id.or(sid)
                .and_then(|sid| c.hosts.get(&(sid, tid)).cloned().flatten()),
        })),
    };
    ResultV1 {
        test_id: r.test_id,
        test_name: r.test_name,
        system_id: r.system_id,
        status: r.status,
        is_excluded: r.is_excluded,
        excluded_reason: r.excluded_reason,
        evidence: evidence(r.evidence.as_deref()),
        checked_at,
    }
}

fn results(rs: Vec<IndividualResult>, when: When, on: On) -> Vec<ResultV1> {
    rs.into_iter().map(|r| result(r, when, on)).collect()
}

#[derive(Serialize)]
pub struct ContainerV1 {
    pub container_id: i64,
    pub name: String,
    pub runtime: String,
    pub image: Option<String>,
    pub compliance_score: Option<f64>,
    pub pass_count: usize,
    pub fail_count: usize,
    pub na_count: usize,
    pub results: Vec<ResultV1>,
}

fn container(c: ContainerReportGroup, when: When) -> ContainerV1 {
    ContainerV1 {
        container_id: c.container_id,
        name: c.name,
        runtime: c.runtime,
        image: c.image,
        compliance_score: score(c.compliance_score),
        pass_count: c.pass_count,
        fail_count: c.fail_count,
        na_count: c.na_count,
        results: results(c.results, when, On::Container(c.container_id)),
    }
}

#[derive(Serialize)]
pub struct PolicyGroupV1 {
    pub policy_id: i32,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_description: Option<String>,
    pub is_passed: bool,
    pub pass_count: usize,
    pub fail_count: usize,
    pub na_count: usize,
    pub excluded_count: usize,
    pub results: Vec<ResultV1>,
}

fn policy_group(g: PolicyResultGroup, when: When, system_id: i64) -> PolicyGroupV1 {
    PolicyGroupV1 {
        policy_id: g.policy_id,
        policy_name: g.policy_name,
        policy_version: g.policy_version,
        policy_description: g.policy_description,
        is_passed: g.is_passed,
        pass_count: g.pass_count,
        fail_count: g.fail_count,
        na_count: g.na_count,
        excluded_count: g.excluded_count,
        results: results(g.results, when, On::Host(Some(system_id))),
    }
}

// GET /systems/{id}/compliance, and the body of a saved system report.
#[derive(Serialize)]
pub struct SystemComplianceV1 {
    pub system_id: i32,
    pub system_name: String,
    pub os: String,
    pub arch: Option<String>,
    pub ip: Option<String>,
    pub compliance_score: Option<f64>,
    pub last_seen_at: Option<String>,
    pub total_pass: usize,
    pub total_fail: usize,
    pub total_na: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub policy_groups: Vec<PolicyGroupV1>,
    pub containers: Vec<ContainerV1>,
}

// `generated_at` for a live report; None for a saved one (its time is the
// report's saved_at).
pub fn system_compliance(d: SystemReportData, when: When, generated_at: Option<String>) -> SystemComplianceV1 {
    let sid = d.system_id as i64;
    SystemComplianceV1 {
        system_id: d.system_id,
        system_name: d.system_name,
        os: d.os,
        arch: d.arch,
        ip: d.ip,
        compliance_score: score(d.compliance_score),
        last_seen_at: opt_timestamp(d.last_seen.as_deref()),
        total_pass: d.total_pass,
        total_fail: d.total_fail,
        total_na: d.total_na,
        generated_at,
        policy_groups: d.policy_groups.into_iter().map(|g| policy_group(g, when, sid)).collect(),
        containers: d.containers.into_iter().map(|c| container(c, when)).collect(),
    }
}

#[derive(Serialize)]
pub struct TestMetaV1 {
    pub name: String,
    pub description: Option<String>,
    pub rationale: Option<String>,
    pub remediation: Option<String>,
}

pub fn test_meta(t: Vec<TestMeta>) -> Vec<TestMetaV1> {
    t.into_iter().map(|t| TestMetaV1 {
        name: t.name,
        description: text(Some(t.description)),
        rationale: text(Some(t.rational)),
        remediation: text(Some(t.remediation)),
    }).collect()
}

#[derive(Serialize)]
pub struct SystemReportV1 {
    pub system_id: Option<i64>,
    pub system_name: String,
    pub is_passed: bool,
    pub pass_count: usize,
    pub fail_count: usize,
    pub na_count: usize,
    pub excluded_count: usize,
    pub results: Vec<ResultV1>,
    pub containers: Vec<ContainerV1>,
}

// One system's row in a policy report, live or saved.
pub fn system_report(s: SystemReport, when: When) -> SystemReportV1 {
    let sid = s.results.iter().find_map(|r| r.system_id);
    SystemReportV1 {
        system_id: sid,
        system_name: s.system_name,
        is_passed: s.is_passed,
        pass_count: s.pass_count,
        fail_count: s.fail_count,
        na_count: s.na_count,
        excluded_count: s.excluded_count,
        results: results(s.results, when, On::Host(sid)),
        containers: s.containers.into_iter().map(|c| container(c, when)).collect(),
    }
}

// GET /policies/{id}/compliance — the live policy report, without the
// submitter fields a report nobody saved cannot have.
#[derive(Serialize)]
pub struct PolicyComplianceV1 {
    pub policy_id: i32,
    pub policy_name: String,
    pub version: String,
    pub description: String,
    pub generated_at: String,
    pub compliance_score: Option<f64>,
    pub total_pass: usize,
    pub total_fail: usize,
    pub total_na: usize,
    pub total_excluded: usize,
    pub tests_metadata: Vec<TestMetaV1>,
    pub system_reports: Vec<SystemReportV1>,
}

pub fn policy_compliance(d: ReportData, checked: &Checked) -> PolicyComplianceV1 {
    PolicyComplianceV1 {
        policy_id: d.policy_id,
        policy_name: d.policy_name,
        version: d.version,
        description: d.description,
        generated_at: now(),
        compliance_score: score(d.compliance_score),
        total_pass: d.total_pass,
        total_fail: d.total_fail,
        total_na: d.total_na,
        total_excluded: d.total_excluded,
        tests_metadata: test_meta(d.tests_metadata),
        system_reports: d.system_reports.into_iter().map(|s| system_report(s, When::Live(checked))).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_round_and_not_scanned_is_none() {
        assert_eq!(score(66.66666666666666), Some(66.67));
        assert_eq!(score(100.0), Some(100.0));
        assert_eq!(score(0.0), Some(0.0));
        assert_eq!(score(-1.0), None);
        assert_eq!(score(f64::NAN), None);
        assert_eq!(opt_score(None), None);
    }

    #[test]
    fn every_stored_time_format_becomes_iso() {
        for raw in ["2026-10-29 19:43:00", "2026-10-29T19:43:00", "2026-10-29 19:43 UTC",
                    "2026-10-29T19:43:00Z", "2026-10-29T21:43:00+02:00", "2026-10-29 19:43:00.123"] {
            assert_eq!(timestamp(raw).as_deref(), Some("2026-10-29T19:43:00Z"), "{raw}");
        }
        assert_eq!(timestamp(""), None);
        assert_eq!(timestamp("yesterday"), None);
    }

    #[test]
    fn evidence_is_the_array_and_details_an_object() {
        assert_eq!(evidence(Some(r#"[{"result":"PASS"}]"#)), Some(json!([{"result": "PASS"}])));
        assert_eq!(evidence(Some("not json")), None);
        assert_eq!(evidence(None), None);
        assert_eq!(audit_details(Some(r#"{"via":"api"}"#.into())), Some(json!({"via": "api"})));
        assert_eq!(audit_details(Some("Logged in".into())), Some(json!({"message": "Logged in"})));
        assert_eq!(audit_details(Some("42".into())), Some(json!({"message": "42"})));
        assert_eq!(audit_details(None), None);
    }
}
