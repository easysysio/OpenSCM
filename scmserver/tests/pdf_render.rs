// pdf_render.rs — golden-fixture harness for the three PDF report builders.
//
// The PDF builders are being ported off `genpdf` (unmaintained since 2021 and
// the sole root of every current `cargo audit` finding) onto `printpdf`. That
// swap trades a layout engine for a lower-level writer, so pagination, table
// geometry and text wrapping are all re-implemented — and a regression there
// is invisible to any assertion about bytes. A column silently 3mm too narrow,
// a page break landing mid-table, a wrapped line clipped at the margin: every
// one of those still produces a structurally valid PDF.
//
// So this harness does two things:
//
//   1. Asserts the builders return structurally sane PDFs (magic bytes, EOF
//      marker, plausible size). Cheap, runs in CI, catches hard breakage.
//   2. Writes every fixture to `target/pdf-fixtures/` so the output can be
//      opened and compared by eye before and after the port. That is the part
//      that actually catches layout regressions.
//
// Run it, keep the PDFs, port the renderer, run it again, diff visually:
//
//     cargo test -p scmserver --test pdf_render
//     open target/pdf-fixtures/
//
// Fixtures deliberately include the awkward cases rather than a tidy happy
// path — long unwrappable strings, a table long enough to force pagination,
// empty collections, non-ASCII text, and the -1.0 "never scanned" score — so
// a layout bug surfaces here instead of in a customer's audit pack.

use scmserver::models::{
    ContainerReportGroup, IndividualResult, PolicyResultGroup, Report, ReportData,
    SystemReport, SystemReportData, TestMeta,
};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: out_dir
// Fixture output lives under target/ so it is git-ignored and wiped by
// `cargo clean`, but survives between runs for before/after comparison.
// ─────────────────────────────────────────────────────────────────────────────
fn out_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/pdf-fixtures");
    std::fs::create_dir_all(&dir).expect("create fixture output dir");
    dir
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_and_write
// Structural assertions shared by every fixture, then persist for eyeballing.
// ─────────────────────────────────────────────────────────────────────────────
fn check_and_write(name: &str, bytes: &[u8]) {
    assert!(
        bytes.starts_with(b"%PDF-"),
        "{name}: missing %PDF- header — got {:?}",
        &bytes[..bytes.len().min(8)]
    );
    // A trailing %%EOF is what makes a reader treat the file as complete;
    // a truncated write is otherwise silently accepted by some viewers.
    let tail = &bytes[bytes.len().saturating_sub(64)..];
    assert!(
        tail.windows(5).any(|w| w == b"%%EOF"),
        "{name}: no %%EOF marker in the last 64 bytes — truncated document?"
    );
    // Embedded fonts alone put a real report well above 10 KB. Anything
    // smaller means the content elements were dropped and only the page
    // skeleton survived — the exact shape of a silent layout failure.
    assert!(
        bytes.len() > 10_000,
        "{name}: {} bytes is too small to contain fonts and content",
        bytes.len()
    );

    let path = out_dir().join(format!("{name}.pdf"));
    std::fs::write(&path, bytes).expect("write fixture");
    eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: result
// One IndividualResult with the fields the PDF builders actually read.
// ─────────────────────────────────────────────────────────────────────────────
fn result(test_name: &str, status: &str, excluded: bool) -> IndividualResult {
    IndividualResult {
        test_name: test_name.to_string(),
        status: status.to_string(),
        is_excluded: excluded,
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: mixed_results
// `n` results cycling through PASS / FAIL / NA plus one excluded, with test
// names long enough to exercise wrapping and one that cannot be wrapped at
// all (no spaces) — the classic overflow case for a naive layout engine.
// ─────────────────────────────────────────────────────────────────────────────
fn mixed_results(n: usize) -> Vec<IndividualResult> {
    (0..n)
        .map(|i| match i % 4 {
            0 => result(&format!("{i:03} Ensure permissions on /etc/passwd are configured correctly"), "PASS", false),
            1 => result(&format!("{i:03} Ensure SSH root login is disabled and the daemon rejects password authentication entirely"), "FAIL", false),
            2 => result(&format!("{i:03} /very/long/unbreakable/path/without/any/spaces/at/all/that/cannot/wrap/nicely"), "NA", false),
            _ => result(&format!("{i:03} Ensure auditd is installed — vérification en français, ключевая проверка"), "FAIL", true),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: test_meta
// Metadata rows carrying the long prose fields (description / rationale /
// remediation) that dominate the back half of a policy report.
// ─────────────────────────────────────────────────────────────────────────────
fn test_meta(n: usize) -> Vec<TestMeta> {
    (0..n)
        .map(|i| TestMeta {
            name: format!("{i:03} Ensure permissions on /etc/passwd are configured"),
            description: "The /etc/passwd file contains user account information \
                that is used by many system utilities and therefore must be readable \
                by all users, while remaining writable only by root."
                .to_string(),
            rational: "If the file is writable by non-root users, an attacker can \
                add an account with UID 0 and obtain a trivial path to full \
                privilege escalation on the host."
                .to_string(),
            remediation: "Run: chown root:root /etc/passwd && chmod 644 /etc/passwd"
                .to_string(),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: system_report
// One system's block inside a policy report.
// ─────────────────────────────────────────────────────────────────────────────
fn system_report(name: &str, n: usize, containers: Vec<ContainerReportGroup>) -> SystemReport {
    let results = mixed_results(n);
    let pass = results.iter().filter(|r| r.status == "PASS").count();
    let fail = results.iter().filter(|r| r.status == "FAIL" && !r.is_excluded).count();
    let na = results.iter().filter(|r| r.status == "NA").count();
    let excluded = results.iter().filter(|r| r.is_excluded).count();
    SystemReport {
        system_name: name.to_string(),
        results,
        is_passed: fail == 0,
        pass_count: pass,
        fail_count: fail,
        na_count: na,
        excluded_count: excluded,
        containers,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: container
// A container group nested under a system row (separate compliance axis).
// ─────────────────────────────────────────────────────────────────────────────
fn container(name: &str, n: usize) -> ContainerReportGroup {
    let results = mixed_results(n);
    ContainerReportGroup {
        container_id: 1,
        name: name.to_string(),
        runtime: "docker".to_string(),
        image: Some("registry.example.com/team/app:1.4.2-alpine".to_string()),
        compliance_score: 66.67,
        pass_count: results.iter().filter(|r| r.status == "PASS").count(),
        fail_count: results.iter().filter(|r| r.status == "FAIL").count(),
        na_count: results.iter().filter(|r| r.status == "NA").count(),
        results,
    }
}


// ============================================================
// FIXTURE: SYSTEM REPORT
// ============================================================

// A system report with several policy groups, containers, and enough rows to
// force pagination. This is the densest of the three layouts.
#[test]
fn system_report_pdf_renders() {
    let data = SystemReportData {
        system_id: 42,
        system_name: "prod-db-01.internal.example.com".to_string(),
        os: "Ubuntu 22.04.5 LTS".to_string(),
        arch: Some("x86_64".to_string()),
        ip: Some("10.24.8.117".to_string()),
        compliance_score: 73.91,
        last_seen: Some("2026-08-20 14:05:11".to_string()),
        policy_groups: vec![
            PolicyResultGroup {
                policy_id: 1,
                policy_name: "CIS Ubuntu Linux 22.04 LTS Benchmark".to_string(),
                policy_version: "2.0.1".to_string(),
                policy_description: Some(
                    "Centre for Internet Security benchmark, level 1 server profile."
                        .to_string(),
                ),
                results: mixed_results(38),
                is_passed: false,
                pass_count: 10,
                fail_count: 19,
                na_count: 9,
                excluded_count: 9,
            },
            PolicyResultGroup {
                policy_id: 2,
                policy_name: "Internal Hardening Baseline".to_string(),
                policy_version: "1.0".to_string(),
                policy_description: None,
                results: mixed_results(5),
                is_passed: true,
                pass_count: 2,
                fail_count: 0,
                na_count: 2,
                excluded_count: 1,
            },
        ],
        total_pass: 12,
        total_fail: 19,
        total_na: 11,
        containers: vec![container("app-web-1", 6), container("app-worker-2", 3)],
    };

    let bytes = scmserver::reports::build_system_report_pdf(&data, "Live report")
        .expect("system report PDF must build");
    check_and_write("system_report", &bytes);
}

// A never-scanned system: score -1.0, no policy groups, no containers. Every
// aggregate the layout divides by is zero here, which is where a naive port
// panics or emits an empty page.
#[test]
fn system_report_pdf_renders_when_never_scanned() {
    let data = SystemReportData {
        system_id: 7,
        system_name: "new-host-unscanned".to_string(),
        os: "Debian GNU/Linux 12 (bookworm)".to_string(),
        arch: Some("aarch64".to_string()),
        ip: None,
        compliance_score: -1.0,
        last_seen: None,
        policy_groups: vec![],
        total_pass: 0,
        total_fail: 0,
        total_na: 0,
        containers: vec![],
    };

    let bytes = scmserver::reports::build_system_report_pdf(&data, "Never scanned")
        .expect("empty system report PDF must build");
    check_and_write("system_report_empty", &bytes);
}


// ============================================================
// FIXTURE: LIVE POLICY REPORT
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: live_report_data
// Shared shape for the live-policy fixture.
// ─────────────────────────────────────────────────────────────────────────────
fn live_report_data(systems: Vec<SystemReport>, metas: usize) -> ReportData {
    ReportData {
        policy_id: 3,
        policy_name: "CIS Ubuntu Linux 22.04 LTS Benchmark — Level 1 Server".to_string(),
        version: "2.0.1".to_string(),
        description: "Full CIS level 1 server profile applied to the production \
            database tier. Exceptions are tracked in the change-management system \
            and re-reviewed each quarter."
            .to_string(),
        submission_date: "2026-08-20 14:05:11".to_string(),
        submitter_name: "yariv".to_string(),
        tests_metadata: test_meta(metas),
        system_reports: systems,
        total_pass: 24,
        total_fail: 38,
        total_na: 22,
        total_excluded: 18,
        compliance_score: 38.71,
    }
}

// Multi-system live policy report, long enough to paginate, with containers
// nested under one of the systems.
#[test]
fn live_policy_pdf_renders() {
    let data = live_report_data(
        vec![
            system_report("prod-db-01.internal.example.com", 24, vec![container("pg-primary", 4)]),
            system_report("prod-db-02.internal.example.com", 24, vec![]),
            system_report("prod-app-01.internal.example.com", 16, vec![]),
        ],
        12,
    );

    let bytes = scmserver::policies::build_live_policy_pdf(&data)
        .expect("live policy PDF must build");
    check_and_write("policy_report_live", &bytes);
}

// A policy with no systems in scope — the "nothing to report" layout.
#[test]
fn live_policy_pdf_renders_with_no_systems() {
    let mut data = live_report_data(vec![], 0);
    data.total_pass = 0;
    data.total_fail = 0;
    data.total_na = 0;
    data.total_excluded = 0;
    data.compliance_score = -1.0;

    let bytes = scmserver::policies::build_live_policy_pdf(&data)
        .expect("empty live policy PDF must build");
    check_and_write("policy_report_live_empty", &bytes);
}


// ============================================================
// FIXTURE: ARCHIVED POLICY REPORT
// ============================================================

// The saved-snapshot builder takes its metadata pre-split rather than as one
// ReportData, so it gets its own fixture even though the page layout is a
// near-twin of the live report.
#[test]
fn archive_policy_pdf_renders() {
    let report = Report {
        id: 918,
        tenant_id: "default".to_string(),
        submission_date: "2026-08-20 14:05:11".to_string(),
        policy_name: "CIS Ubuntu Linux 22.04 LTS Benchmark — Level 1 Server".to_string(),
        policy_version: Some("2.0.1".to_string()),
        policy_description: Some(
            "Quarterly audit snapshot. Frozen at save time; results here are \
             immutable and must not change if the live policy is edited."
                .to_string(),
        ),
        submitter_name: Some("yariv".to_string()),
        // The builder is handed the parsed collections, so the raw JSON
        // columns stay None in the fixture.
        tests_metadata: None,
        report_results: None,
    };

    let systems = vec![
        system_report("prod-db-01.internal.example.com", 24, vec![container("pg-primary", 4)]),
        system_report("prod-db-02.internal.example.com", 20, vec![]),
    ];

    let bytes = scmserver::reports::build_archive_policy_pdf(&report, &systems, &test_meta(12))
        .expect("archive policy PDF must build");
    check_and_write("policy_report_archive", &bytes);
}

// Optional metadata absent (no version, no description, no submitter) — older
// snapshots genuinely have these as NULL, so the layout must tolerate it.
#[test]
fn archive_policy_pdf_renders_without_optional_metadata() {
    let report = Report {
        id: 12,
        tenant_id: "default".to_string(),
        submission_date: "2025-01-04 09:00:00".to_string(),
        policy_name: "Legacy Snapshot".to_string(),
        policy_version: None,
        policy_description: None,
        submitter_name: None,
        tests_metadata: None,
        report_results: None,
    };

    let systems = vec![system_report("legacy-host", 3, vec![])];

    let bytes = scmserver::reports::build_archive_policy_pdf(&report, &systems, &[])
        .expect("archive policy PDF must build without optional metadata");
    check_and_write("policy_report_archive_minimal", &bytes);
}
