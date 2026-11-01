// =============================================================================
// auto_groups.rs — automatic group assignment: rule evaluator + reconciler
//
// Auto groups (system_groups.auto_managed = 1) have exactly one rule in
// auto_group_rules.  Membership is fully determined by the rule and is
// reconciled by apply_auto_groups() — called from the heartbeat handler when
// rule-relevant metadata changed, and from the auto-group rule editor when
// the admin saves a new / edited rule.
//
// Privacy stance: every input field is something already collected for an
// unrelated operational reason (heartbeat metadata, container inventory,
// telemetry).  No process or package inventory.  See
// docs/design/0.5.2-auto-groups.md for the full spec.
//
// Public surface:
//
//   • Condition / Rule                — strongly-typed wrappers around the
//                                       JSON stored in auto_group_rules.conditions
//   • SystemSnapshot                  — rule-input fields loaded fresh from the DB
//   • load_enabled_rules(...)         — pulls all enabled rules for a tenant
//   • load_system_snapshot(...)       — pulls one system's snapshot
//   • apply_auto_groups(...)          — reconciles auto-group membership for
//                                       a single system; sets compliance_dirty=1
//                                       if anything changed
//   • validate_conditions_json(...)   — parses + validates a conditions JSON
//                                       blob (called from the rule-save handler)
// =============================================================================

use std::collections::HashSet;
use serde::Deserialize;
use sqlx::{Row, SqlitePool, Sqlite, Transaction};
use tracing::warn;

// ─────────────────────────────────────────────────────────────────────────────
// Type — Operator
// All operators we accept in a rule condition.  Mapped from the JSON
// "operator" string by Operator::parse.  Each operator names a target value
// type (string / number / bool / cidr / semver); validate_conditions_json
// enforces that the supplied value parses for the operator's type and that
// the operator is valid for the field's type.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operator {
    // String
    Equals, NotEquals, Contains, NotContains, StartsWith, EndsWith, Regex,
    // Numeric  (also reused for semver compare on the `ver` field)
    Eq, Ne, Lt, Le, Gt, Ge,
    // Enum / set
    In, NotIn,
    // IP / CIDR
    InCidr,
}

impl Operator {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "equals"       => Some(Operator::Equals),
            "not_equals"   => Some(Operator::NotEquals),
            "contains"     => Some(Operator::Contains),
            "not_contains" => Some(Operator::NotContains),
            "starts_with"  => Some(Operator::StartsWith),
            "ends_with"    => Some(Operator::EndsWith),
            "regex"        => Some(Operator::Regex),
            "eq" => Some(Operator::Eq),
            "ne" => Some(Operator::Ne),
            "lt" => Some(Operator::Lt),
            "le" => Some(Operator::Le),
            "gt" => Some(Operator::Gt),
            "ge" => Some(Operator::Ge),
            "in"     => Some(Operator::In),
            "not_in" => Some(Operator::NotIn),
            "in_cidr" => Some(Operator::InCidr),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — Field
// All fields a rule can target.  Keep in sync with the parameter catalog in
// docs/design/0.5.2-auto-groups.md §4.  Adding a new field means: (a) extend
// this enum, (b) extend SystemSnapshot, (c) extend extract_value, (d) extend
// the admin UI's field picker.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field {
    Hostname, Ip, Os, OsFamily, Arch, Platform, Ver, Status,
    MemTotalMb, DiskTotalGb, UptimeSecs,
    ContainersExists, HasRuntime, AnyContainerImage,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "hostname"            => Some(Field::Hostname),
            "ip"                  => Some(Field::Ip),
            "os"                  => Some(Field::Os),
            "os_family"           => Some(Field::OsFamily),
            "arch"                => Some(Field::Arch),
            "platform"            => Some(Field::Platform),
            "ver"                 => Some(Field::Ver),
            "status"              => Some(Field::Status),
            "mem_total_mb"        => Some(Field::MemTotalMb),
            "disk_total_gb"       => Some(Field::DiskTotalGb),
            "uptime_secs"         => Some(Field::UptimeSecs),
            "containers_exists"   => Some(Field::ContainersExists),
            "has_runtime"         => Some(Field::HasRuntime),
            "any_container_image" => Some(Field::AnyContainerImage),
            _ => None,
        }
    }

    /// Returns true if the operator is valid for this field's value type.
    fn accepts(&self, op: Operator) -> bool {
        use Field::*;
        use Operator::*;
        match self {
            // String-typed fields (including IP, which also gets InCidr).
            Hostname | Os | Platform | AnyContainerImage =>
                matches!(op, Equals | NotEquals | Contains | NotContains
                              | StartsWith | EndsWith | Regex),

            Ip => matches!(op, Equals | NotEquals | Contains | NotContains
                              | StartsWith | EndsWith | Regex | InCidr),

            // Enum-style strings — equality, membership, plus substring
            // matching. Contains / NotContains widens these from a strict
            // exact-match set to "partial token" matching, useful for cases
            // like `os_family contains "bsd"` or `status contains "pend"`
            // where the admin doesn't want to enumerate every variant.
            OsFamily | Arch | Status =>
                matches!(op, Equals | NotEquals | Contains | NotContains | In | NotIn),

            // has_runtime is evaluated against the set of runtimes present
            // on this host (docker / podman / …). match_string runs against
            // each runtime individually, so Contains here means "ANY runtime
            // string contains the value" — useful for `contains "docker"`
            // matching both `docker` and a hypothetical `docker-ce`.
            HasRuntime =>
                matches!(op, Equals | NotEquals | Contains | NotContains | In | NotIn),

            // Numeric fields — comparison operators.
            MemTotalMb | DiskTotalGb | UptimeSecs =>
                matches!(op, Eq | Ne | Lt | Le | Gt | Ge),

            // Boolean field — only equality.
            ContainersExists => matches!(op, Equals | NotEquals),

            // Semver-string — both string ops and ordered semver compare.
            Ver => matches!(op,
                Equals | NotEquals | Contains | NotContains | StartsWith | EndsWith
                | Regex | Eq | Ne | Lt | Le | Gt | Ge),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — Condition
// One condition inside a rule: `field op value`.  All conditions in a rule
// AND together; OR is expressed by defining a second auto group with a
// second rule (see design doc §14, resolved Q1).
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize)]
pub struct CondJson {
    pub field:    String,
    pub operator: String,
    pub value:    serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub field: Field,
    pub op:    Operator,
    pub value: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — Rule
// One rule = one auto group.  conditions is non-empty (validator rejects
// empty rules — those would silently match every system).
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Rule {
    pub id:         i64,
    pub group_id:   i64,
    pub conditions: Vec<Condition>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — SystemSnapshot
// All rule-input fields for a single system, loaded fresh from the DB on
// every apply_auto_groups call.  Cheap (one SELECT against systems + one
// against containers); avoids stale-data races with concurrent heartbeats.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub system_id:         i64,
    pub hostname:          Option<String>,
    pub ip:                Option<String>,
    pub os:                Option<String>,
    pub os_family:         Option<String>,   // derived from os
    pub arch:              Option<String>,
    pub platform:          Option<String>,   // derived: "{arch}-{os_family}"
    pub ver:               Option<String>,
    pub status:            Option<String>,
    pub mem_total_mb:      Option<i64>,
    pub disk_total_gb:     Option<i64>,
    pub uptime_secs:       Option<i64>,
    pub containers_exists: bool,
    pub runtimes:          Vec<String>,      // distinct runtimes on this host
    pub container_images:  Vec<String>,      // distinct images on this host
    /// Stored fingerprint from the DB (systems.auto_group_fp) — the hash this
    /// system was last evaluated against.  None until first evaluation.
    pub auto_group_fp:     Option<String>,
}

impl SystemSnapshot {
    /// Compact summary of the rule-relevant fields.  Returning a tuple keeps
    /// the comparison trivially derivable and feeds fingerprint_hash().
    ///
    /// NOTE: every field a rule can target (see the `Field` enum) must appear
    /// here, or a change to that field would not invalidate the fingerprint
    /// and the heartbeat short-circuit would wrongly skip re-evaluation.
    /// `uptime_secs` is deliberately EXCLUDED — it changes on every heartbeat,
    /// so including it would defeat the short-circuit entirely.  A rule on
    /// `uptime_secs` therefore relies on the once-per-tick recalc cadence
    /// rather than instant reconciliation; acceptable given uptime crosses
    /// any threshold exactly once (it's monotonic between reboots).
    // Only ever compared for equality, so a named type would add nothing.
    #[allow(clippy::type_complexity)]
    pub fn rule_relevant_fingerprint(&self) -> (
        Option<&str>, Option<&str>, Option<&str>, Option<&str>, Option<&str>, Option<&str>,
        Option<i64>, Option<i64>, bool, Vec<&str>, Vec<&str>,
    ) {
        (
            self.hostname.as_deref(),
            self.ip.as_deref(),
            self.os.as_deref(),
            self.arch.as_deref(),
            self.ver.as_deref(),
            self.status.as_deref(),
            self.mem_total_mb,
            self.disk_total_gb,
            self.containers_exists,
            self.runtimes.iter().map(String::as_str).collect(),
            self.container_images.iter().map(String::as_str).collect(),
        )
    }

    /// Stable SHA-256 (hex) of the rule-relevant fields.  Deterministic for
    /// the same field values (the Vecs are sorted at load time, and `{:?}`
    /// formatting of the tuple is order-stable).  Stored in
    /// systems.auto_group_fp and compared on each heartbeat to decide whether
    /// rule re-evaluation can be skipped.
    pub fn fingerprint_hash(&self) -> String {
        use sha2::{Sha256, Digest};
        let canon = format!("{:?}", self.rule_relevant_fingerprint());
        let mut h = Sha256::new();
        h.update(canon.as_bytes());
        format!("{:x}", h.finalize())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — derive_os_family
// Maps a free-form `systems.os` string to a stable enum-ish lowercase tag.
// Substring sniffing on lowercase os.  Examples of inputs seen in the wild:
//
//   Linux:   "Ubuntu 24.04", "Debian GNU/Linux 12", "Rocky Linux 9.3", …
//   macOS:   "Mac OS 26.5.0"   ← os_info 3.x display name on Apple Silicon
//            "Mac OS X 10.15.7" ← older macOS via os_info
//            "macOS 14.5"
//            "Darwin 23.5.0"    ← falls through to uname-style on some setups
//   Windows: "Microsoft Windows Server 2022", "Windows 11"
//   BSDs:    "FreeBSD 14.0", "OpenBSD 7.4", "NetBSD 10.0"
//
// The macOS branch checks `"mac"` (which covers both "mac os" with the space
// that os_info actually emits, and the no-space "macos" some agents send)
// plus `"darwin"`.  `"mac"` is broad enough to hit anything starting Mac…
// while still being safe — no Linux distro string contains it.
// ─────────────────────────────────────────────────────────────────────────────
fn derive_os_family(os: Option<&str>) -> Option<String> {
    let s = os?.to_ascii_lowercase();
    let fam = if s.contains("windows")                              { "windows" }
              else if s.contains("darwin") || s.contains("macos")
                   || s.contains("mac os") || s.starts_with("mac")  { "macos" }
              else if s.contains("freebsd")                          { "freebsd" }
              else if s.contains("openbsd")                          { "openbsd" }
              else if s.contains("netbsd")                           { "netbsd" }
              else if s.contains("linux")  || s.contains("ubuntu")
                   || s.contains("debian") || s.contains("rhel")
                   || s.contains("centos") || s.contains("fedora")
                   || s.contains("alpine") || s.contains("suse")
                   || s.contains("arch")   || s.contains("rocky")
                   || s.contains("alma")                             { "linux" }
              else                                                   { "other" };
    Some(fam.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — derive_platform
// "{arch}-{os_family}", or None if either component is missing.  Mirrors
// derive_platform in client.rs but takes already-derived os_family.
// ─────────────────────────────────────────────────────────────────────────────
fn derive_platform(arch: Option<&str>, os_family: Option<&str>) -> Option<String> {
    Some(format!("{}-{}", arch?, os_family?))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — load_system_snapshot
// Builds a SystemSnapshot from `systems` + `containers` for one system.
// Tenant-scoped.  Returns Ok(None) if the system doesn't exist (e.g. was
// deleted between the heartbeat START and the eval call — safe no-op).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_system_snapshot(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    system_id: i64,
) -> Result<Option<SystemSnapshot>, sqlx::Error> {
    let Some(row) = sqlx::query(
        "SELECT id, name, ip, os, arch, ver, status,
                mem_total_mb, disk_total_gb, uptime_secs, auto_group_fp
         FROM systems
         WHERE id = ? AND tenant_id = ?"
    )
    .bind(system_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await? else { return Ok(None); };

    let os: Option<String> = row.try_get("os").ok().flatten();
    let arch: Option<String> = row.try_get("arch").ok().flatten();
    let os_family = derive_os_family(os.as_deref());
    let platform = derive_platform(arch.as_deref(), os_family.as_deref());

    // Distinct runtimes + images on this host.
    let container_rows = sqlx::query(
        "SELECT runtime, image FROM containers
         WHERE host_system_id = ? AND tenant_id = ?"
    )
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut runtime_set: HashSet<String> = HashSet::new();
    let mut image_set:   HashSet<String> = HashSet::new();
    for c in &container_rows {
        if let Ok(Some(r)) = c.try_get::<Option<String>, _>("runtime") { runtime_set.insert(r); }
        if let Ok(Some(i)) = c.try_get::<Option<String>, _>("image")   { image_set.insert(i); }
    }
    let mut runtimes: Vec<String>         = runtime_set.into_iter().collect();
    let mut container_images: Vec<String> = image_set.into_iter().collect();
    runtimes.sort();
    container_images.sort();

    Ok(Some(SystemSnapshot {
        system_id:         row.try_get::<i64, _>("id").unwrap_or(system_id),
        hostname:          row.try_get("name").ok().flatten(),
        ip:                row.try_get("ip").ok().flatten(),
        os,
        os_family,
        arch,
        platform,
        ver:               row.try_get("ver").ok().flatten(),
        status:            row.try_get("status").ok().flatten(),
        mem_total_mb:      row.try_get("mem_total_mb").ok().flatten(),
        disk_total_gb:     row.try_get("disk_total_gb").ok().flatten(),
        uptime_secs:       row.try_get("uptime_secs").ok().flatten(),
        containers_exists: !container_rows.is_empty(),
        runtimes,
        container_images,
        auto_group_fp:     row.try_get("auto_group_fp").ok().flatten(),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — load_enabled_rules
// Loads every enabled auto-group rule for a tenant, parsing each row's
// conditions JSON.  Rows whose JSON fails to validate are skipped with a
// WARN (admin will see them as not-matching anything until they re-save) —
// preferable to taking down the heartbeat path because one rule got
// corrupted.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_enabled_rules(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
) -> Result<Vec<Rule>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, group_id, conditions
         FROM auto_group_rules
         WHERE tenant_id = ? AND enabled = 1"
    )
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id:       i64    = r.try_get("id").unwrap_or(0);
        let group_id: i64    = r.try_get("group_id").unwrap_or(0);
        let raw:      String = r.try_get("conditions").unwrap_or_default();

        match parse_conditions(&raw) {
            Ok(conditions) if !conditions.is_empty() => {
                out.push(Rule { id, group_id, conditions });
            }
            Ok(_) => {
                warn!("auto_group_rules.id={} has empty conditions — skipped", id);
            }
            Err(e) => {
                warn!("auto_group_rules.id={} has invalid conditions JSON ({}) — skipped",
                      id, e);
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — parse_conditions
// Parses + validates a `conditions` JSON blob.  Errors carry a human-readable
// reason so the rule-editor handler can surface them inline.  An empty array
// is allowed at the parse layer; the validator (validate_conditions_json)
// rejects it because saving an empty rule would silently match all systems.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_conditions(raw: &str) -> Result<Vec<Condition>, String> {
    let parsed: Vec<CondJson> = serde_json::from_str(raw)
        .map_err(|e| format!("invalid JSON: {}", e))?;

    let mut out = Vec::with_capacity(parsed.len());
    for (i, c) in parsed.into_iter().enumerate() {
        let field = Field::parse(&c.field)
            .ok_or_else(|| format!("condition #{}: unknown field '{}'", i + 1, c.field))?;
        let op = Operator::parse(&c.operator)
            .ok_or_else(|| format!("condition #{}: unknown operator '{}'", i + 1, c.operator))?;
        if !field.accepts(op) {
            return Err(format!(
                "condition #{}: operator '{}' not valid for field '{}'",
                i + 1, c.operator, c.field));
        }
        // Per-operator value-shape check.
        validate_value(&c.value, op)
            .map_err(|e| format!("condition #{}: {}", i + 1, e))?;
        out.push(Condition { field, op, value: c.value });
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — build_conditions_json_from_form
// Assembles the canonical `conditions` JSON blob from the indexed form fields
// posted by the click-based rule editor (auto_groups_add.html /
// auto_groups_edit.html).  For each i ∈ 1..=max_rows it reads form keys
// `field_i`, `op_i`, `value_i`; rows where all three are blank are dropped
// (the UI uses hidden empty rows that the admin reveals via "Add Condition").
//
// Value coercion is driven by the operator:
//
//   • `in` / `not_in`  → split the raw value on commas, trim, build a JSON
//                        array of strings.
//   • numeric ops (`eq`/`ne`/`lt`/`le`/`gt`/`ge`) on a numeric field
//                        (mem/disk/uptime)
//                      → parse as i64 / f64, build JSON number.
//   • semver numeric ops on the `ver` field  → keep as string (validator
//                        accepts string values for semver-compare ops).
//   • bool ops on `containers_exists`        → parse "true" / "1" / "yes" → true,
//                        anything else → false.
//   • everything else  → JSON string (the universal fallback; matches the
//                        string-typed validation path in validate_value).
//
// The resulting string is the same shape validate_conditions_json already
// accepts, so the handler can pipe it straight through that validator for
// the final shape / regex / CIDR checks.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_conditions_json_from_form(
    form: &std::collections::HashMap<String, Vec<String>>,
    max_rows: usize,
) -> Result<String, String> {
    let mut out: Vec<serde_json::Value> = Vec::new();

    for i in 1..=max_rows {
        let field = form.get(&format!("field_{}", i))
            .and_then(|v| v.first()).cloned().unwrap_or_default();
        let op    = form.get(&format!("op_{}", i))
            .and_then(|v| v.first()).cloned().unwrap_or_default();
        let value = form.get(&format!("value_{}", i))
            .and_then(|v| v.first()).cloned().unwrap_or_default();

        // Drop fully-blank rows so the hidden template scaffolding doesn't
        // bleed into the saved rule.  A partial row (one of the three set)
        // is treated as an error so we don't silently keep half-finished
        // input.
        let any_set = !field.is_empty() || !op.is_empty() || !value.is_empty();
        let all_set = !field.is_empty() && !op.is_empty() && !value.is_empty();
        if !any_set { continue; }
        if !all_set {
            return Err(format!(
                "condition #{} is incomplete — pick a field, operator, and value",
                i
            ));
        }

        let v_json = coerce_value(&field, &op, &value)?;
        out.push(serde_json::json!({
            "field":    field,
            "operator": op,
            "value":    v_json,
        }));
    }

    if out.is_empty() {
        return Err("rule must contain at least one condition".to_string());
    }

    serde_json::to_string(&out)
        .map_err(|e| format!("could not serialise conditions: {}", e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — explode_conditions_for_form
// Inverse of build_conditions_json_from_form.  Parses a stored conditions
// JSON blob into per-row (field, operator, display_value) triples suitable
// for pre-filling the click-based edit form.  Display value is the
// human-typed form the admin originally entered:
//   • arrays           → comma-joined string (matches the `in`/`not_in` UI)
//   • numbers / bools  → their text form
//   • strings          → as-is
//
// Tolerates malformed JSON (returns empty Vec) so the edit form is still
// usable to repair a broken rule.
// ─────────────────────────────────────────────────────────────────────────────
pub fn explode_conditions_for_form(raw: &str) -> Vec<(String, String, String)> {
    let parsed: Vec<CondJson> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parsed.into_iter().map(|c| {
        let display = match &c.value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b)   => b.to_string(),
            serde_json::Value::Array(a)  => a.iter().filter_map(|v| v.as_str().map(str::to_string))
                                            .collect::<Vec<_>>().join(", "),
            _ => String::new(),
        };
        (c.field, c.operator, display)
    }).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — coerce_value
// Per-operator + per-field type coercion used by build_conditions_json_from_form.
// See that function's doc-comment for the full rule table.  Errors carry the
// row-position context from the caller; this helper only knows about the
// triple it was handed.
// ─────────────────────────────────────────────────────────────────────────────
fn coerce_value(field: &str, op: &str, raw: &str)
    -> Result<serde_json::Value, String>
{
    // Membership ops always take an array of strings.
    if op == "in" || op == "not_in" {
        let parts: Vec<serde_json::Value> = raw.split(',')
            .map(|s| s.trim()).filter(|s| !s.is_empty())
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect();
        if parts.is_empty() {
            return Err(format!("operator '{}' needs at least one comma-separated value", op));
        }
        return Ok(serde_json::Value::Array(parts));
    }

    // Boolean field — coerce common truthy / falsy strings.
    if field == "containers_exists" {
        let truthy = matches!(raw.to_ascii_lowercase().as_str(),
                              "true" | "1" | "yes" | "on");
        return Ok(serde_json::Value::Bool(truthy));
    }

    // Numeric fields with numeric-compare ops → JSON number.
    let is_numeric_field = matches!(field, "mem_total_mb" | "disk_total_gb" | "uptime_secs");
    let is_numeric_op    = matches!(op, "eq" | "ne" | "lt" | "le" | "gt" | "ge");
    if is_numeric_field && is_numeric_op {
        if let Ok(n) = raw.parse::<i64>() {
            return Ok(serde_json::json!(n));
        }
        if let Ok(n) = raw.parse::<f64>() {
            // serde_json::Number::from_f64 returns None for NaN / inf.
            return serde_json::Number::from_f64(n)
                .map(serde_json::Value::Number)
                .ok_or_else(|| "value must be a finite number".to_string());
        }
        return Err(format!("'{}' is not a number", raw));
    }

    // Everything else — pass through as a string. Validators downstream check
    // regex compilability, CIDR parsing, etc.
    Ok(serde_json::Value::String(raw.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — validate_conditions_json
// Stricter wrapper around parse_conditions for the rule-save handler:
// additionally requires at least one condition.  Use this on POST /auto_groups
// from the admin UI.
// ─────────────────────────────────────────────────────────────────────────────
pub fn validate_conditions_json(raw: &str) -> Result<Vec<Condition>, String> {
    let parsed = parse_conditions(raw)?;
    if parsed.is_empty() {
        return Err("rule must contain at least one condition".to_string());
    }
    Ok(parsed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — validate_value
// Shape-checks the JSON value against what each operator expects.  Doesn't
// check that the value is *meaningful* for the field (e.g. that an os_family
// equals-value is one of the known families) — admins can write arbitrary
// strings, they just won't match anything.
// ─────────────────────────────────────────────────────────────────────────────
fn validate_value(v: &serde_json::Value, op: Operator) -> Result<(), String> {
    use Operator::*;
    match op {
        Equals | NotEquals => {
            if !(v.is_string() || v.is_number() || v.is_boolean()) {
                return Err("value must be string, number, or boolean".into());
            }
        }
        Contains | NotContains | StartsWith | EndsWith => {
            v.as_str().ok_or("value must be a string")?;
        }
        Regex => {
            let s = v.as_str().ok_or("value must be a string")?;
            regex::Regex::new(s).map_err(|e| format!("invalid regex: {}", e))?;
        }
        Eq | Ne | Lt | Le | Gt | Ge => {
            // Either a number (numeric fields) or a string (semver compare on ver).
            if !(v.is_number() || v.is_string()) {
                return Err("value must be a number or version string".into());
            }
        }
        In | NotIn => {
            let arr = v.as_array().ok_or("value must be an array")?;
            if arr.is_empty() {
                return Err("array must not be empty".into());
            }
            for x in arr {
                if !(x.is_string() || x.is_number() || x.is_boolean()) {
                    return Err("array elements must be string/number/boolean".into());
                }
            }
        }
        InCidr => {
            let s = v.as_str().ok_or("value must be a CIDR string")?;
            s.parse::<ipnet::IpNet>().map_err(|e| format!("invalid CIDR: {}", e))?;
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — apply_auto_groups
// Reconciles auto-group membership for one system.  Returns true if any row
// in systems_in_groups was inserted or deleted (the heartbeat caller can use
// this to decide whether to also mark compliance_dirty — which is set inside
// this function as well, but the bool is useful for audit logging).
//
// Only touches auto-managed groups.  Manual group memberships are completely
// untouched, satisfying the "manual is immune to rule churn" invariant.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn apply_auto_groups(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    system_id: i64,
) -> Result<bool, sqlx::Error> {
    // Heartbeat path: load the tenant's enabled rules, then reconcile with
    // the fingerprint short-circuit enabled (skip when nothing changed).
    let rules = load_enabled_rules(tx, tenant_id).await?;
    apply_auto_groups_with_rules(tx, tenant_id, system_id, &rules, true).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — apply_auto_groups_with_rules
// Core reconciliation for one system against an already-parsed rule slice.
//
//   • Heartbeat path passes `check_fingerprint = true` — when the system's
//     rule-relevant fields are byte-identical to the last evaluation
//     (systems.auto_group_fp), rule evaluation + the membership query are
//     skipped entirely.
//   • The full-tenant sweep passes `check_fingerprint = false` — the RULES
//     changed, so every system must be re-evaluated regardless of whether
//     its own fields moved.  The sweep also parses the rules ONCE and reuses
//     the slice across all systems (no per-system regex recompilation).
//
// Returns true iff a membership row was inserted or deleted (caller uses
// this for audit counting; compliance_dirty is set internally when true).
// The fingerprint is re-stamped whenever it drifts, on both paths.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn apply_auto_groups_with_rules(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    system_id: i64,
    rules: &[Rule],
    check_fingerprint: bool,
) -> Result<bool, sqlx::Error> {
    // ── P1: rules-first short-circuit ───────────────────────────────────────
    // The overwhelmingly common case is "tenant has no auto rules at all".
    // When there are no enabled rules, the only reason to do any work is to
    // clean up stale auto memberships left behind (e.g. a rule was disabled
    // out-of-band, or a prior disable-sweep failed partway).  A single
    // indexed EXISTS check lets us bail BEFORE loading the system snapshot
    // (which scans the containers table) for the no-rules / no-membership
    // case — keeping the heartbeat hot path nearly free for installs that
    // don't use auto-groups.
    if rules.is_empty() {
        let has_stale_auto: Option<i64> = sqlx::query_scalar(
            "SELECT 1
             FROM systems_in_groups sig
             JOIN system_groups sg ON sg.id = sig.group_id
             WHERE sig.system_id = ? AND sig.tenant_id = ? AND sg.auto_managed = 1
             LIMIT 1"
        )
        .bind(system_id)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await?;
        if has_stale_auto.is_none() {
            return Ok(false);  // nothing to do — snapshot never loaded
        }
        // else fall through: empty target set will remove the stale rows.
    }

    // Load snapshot (incl. the stored fingerprint).  Bail if the row vanished.
    let Some(snapshot) = load_system_snapshot(tx, tenant_id, system_id).await? else {
        return Ok(false);
    };

    // ── P3: fingerprint short-circuit (heartbeat path only) ─────────────────
    // If the rule-relevant fields are unchanged since the last evaluation,
    // neither the target set nor the membership can have changed, so skip the
    // membership query, rule eval, and writes.  The sweep passes
    // check_fingerprint=false to force re-eval after a rule change.
    let new_fp = snapshot.fingerprint_hash();
    if check_fingerprint && snapshot.auto_group_fp.as_deref() == Some(new_fp.as_str()) {
        return Ok(false);
    }

    // Evaluate rules → target group set.
    let target_groups: HashSet<i64> = rules.iter()
        .filter(|r| eval_rule(r, &snapshot))
        .map(|r| r.group_id)
        .collect();

    // Current auto-group membership (auto_managed=1 only).
    let current_rows = sqlx::query(
        "SELECT sig.group_id
         FROM systems_in_groups sig
         JOIN system_groups sg ON sg.id = sig.group_id
         WHERE sig.system_id = ? AND sig.tenant_id = ? AND sg.auto_managed = 1"
    )
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let current_auto: HashSet<i64> = current_rows.iter()
        .filter_map(|r| r.try_get::<i64, _>("group_id").ok())
        .collect();

    let to_add: Vec<i64>    = target_groups.difference(&current_auto).copied().collect();
    let to_remove: Vec<i64> = current_auto.difference(&target_groups).copied().collect();

    let membership_changed = !(to_add.is_empty() && to_remove.is_empty());

    // Apply additions.
    for gid in &to_add {
        sqlx::query(
            "INSERT OR IGNORE INTO systems_in_groups (tenant_id, system_id, group_id)
             VALUES (?, ?, ?)"
        )
        .bind(tenant_id).bind(system_id).bind(gid)
        .execute(&mut **tx).await?;
    }

    // Apply removals (the JOIN above already restricted current_auto to
    // auto-managed groups, so every gid here is safe to delete).
    for gid in &to_remove {
        sqlx::query(
            "DELETE FROM systems_in_groups
             WHERE tenant_id = ? AND system_id = ? AND group_id = ?"
        )
        .bind(tenant_id).bind(system_id).bind(gid)
        .execute(&mut **tx).await?;
    }

    // Re-stamp the fingerprint whenever it drifted (both paths).  This is what
    // lets the NEXT heartbeat with identical fields hit the P3 short-circuit.
    // Done even when membership didn't change (a field moved but didn't cross
    // any rule boundary) so we don't re-evaluate that same unchanged state
    // again next tick.
    if snapshot.auto_group_fp.as_deref() != Some(new_fp.as_str()) {
        sqlx::query(
            "UPDATE systems SET auto_group_fp = ? WHERE id = ? AND tenant_id = ?"
        )
        .bind(&new_fp).bind(system_id).bind(tenant_id)
        .execute(&mut **tx).await?;
    }

    if !membership_changed {
        return Ok(false);
    }

    // Membership changed → mark compliance dirty for the next scheduler tick.
    sqlx::query(
        "UPDATE systems SET compliance_dirty = 1 WHERE id = ? AND tenant_id = ?"
    )
    .bind(system_id).bind(tenant_id)
    .execute(&mut **tx).await?;

    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — apply_auto_groups_for_tenant
// Full sweep — re-evaluate every system in the tenant.  Used by the rule
// editor on create / edit / toggle.  Returns the count of systems whose
// membership changed (for the audit trail).
//
// P2: the enabled rules are loaded and parsed exactly ONCE here (one JSON
// parse + regex compile pass), then reused across every system via
// apply_auto_groups_with_rules.  Previously each system re-ran
// load_enabled_rules → parse_conditions → regex compile, making the sweep
// O(N×R) in regex compilation; it's now O(R) compile + O(N) eval.
//
// check_fingerprint = false: the rules just changed, so every system must be
// re-evaluated regardless of whether its own fields drifted.  Each call also
// re-stamps the fingerprint, so subsequent heartbeats can short-circuit.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn apply_auto_groups_for_tenant(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<usize, sqlx::Error> {
    // Parse the rule set once, up front, in its own short transaction.
    let rules = {
        let mut tx = pool.begin().await?;
        let r = load_enabled_rules(&mut tx, tenant_id).await?;
        tx.commit().await?;
        r
    };

    // Invalidate every fingerprint in the tenant BEFORE sweeping.  The rules
    // just changed, so all stored fingerprints (which encode "last evaluated
    // against the OLD rule set") are stale.  Nulling them guarantees that any
    // system the inline sweep errors on (rare DB hiccup → that one tx rolls
    // back) will still be re-evaluated on its NEXT heartbeat — the P3
    // short-circuit can't fire against a NULL fingerprint.  Successfully-swept
    // systems get their fingerprint re-stamped immediately by the loop below.
    // Restores the pre-P3 self-healing property without giving up the
    // steady-state skip.
    sqlx::query("UPDATE systems SET auto_group_fp = NULL WHERE tenant_id = ?")
        .bind(tenant_id)
        .execute(pool)
        .await?;

    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM systems WHERE tenant_id = ?"
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mut changed = 0usize;
    for sid in ids {
        let mut tx = pool.begin().await?;
        match apply_auto_groups_with_rules(&mut tx, tenant_id, sid, &rules, false).await {
            Ok(true)  => { tx.commit().await?; changed += 1; }
            Ok(false) => { tx.commit().await?; }
            Err(e)    => { warn!("apply_auto_groups failed for system {}: {}", sid, e);
                           let _ = tx.rollback().await; }
        }
    }
    Ok(changed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — eval_rule
// Rule matches iff every condition matches (AND semantics).
// ─────────────────────────────────────────────────────────────────────────────
fn eval_rule(rule: &Rule, sys: &SystemSnapshot) -> bool {
    rule.conditions.iter().all(|c| eval_condition(c, sys))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — eval_condition
// Dispatch on operator + value type.  Returns false on any mismatch (the
// rule simply doesn't match — never an error path).  Regex compile failures
// at eval time return false; the validator should have caught them on save.
// ─────────────────────────────────────────────────────────────────────────────
fn eval_condition(c: &Condition, sys: &SystemSnapshot) -> bool {
    use Operator::*;
    match c.field {
        // ── Multi-value fields ──────────────────────────────────────────────
        Field::HasRuntime => {
            // Match if ANY runtime on this host matches the condition.
            sys.runtimes.iter().any(|r| match_string(r, c.op, &c.value))
        }
        Field::AnyContainerImage => {
            sys.container_images.iter().any(|img| match_string(img, c.op, &c.value))
        }

        // ── Boolean ────────────────────────────────────────────────────────
        Field::ContainersExists => {
            let want = c.value.as_bool().unwrap_or(false);
            let got  = sys.containers_exists;
            matches!((c.op, want == got), (Equals, true) | (NotEquals, false))
        }

        // ── Numeric ────────────────────────────────────────────────────────
        Field::MemTotalMb   => num_cmp(sys.mem_total_mb,   c.op, &c.value),
        Field::DiskTotalGb  => num_cmp(sys.disk_total_gb,  c.op, &c.value),
        Field::UptimeSecs   => num_cmp(sys.uptime_secs,    c.op, &c.value),

        // ── IP (string ops + InCidr) ───────────────────────────────────────
        Field::Ip => {
            let Some(ip_str) = sys.ip.as_deref() else { return false; };
            if c.op == InCidr {
                let Some(cidr_str) = c.value.as_str() else { return false; };
                let (Ok(cidr), Ok(ip)) = (
                    cidr_str.parse::<ipnet::IpNet>(),
                    ip_str.parse::<std::net::IpAddr>(),
                ) else { return false; };
                return cidr.contains(&ip);
            }
            match_string(ip_str, c.op, &c.value)
        }

        // ── Semver / mixed (ver) ───────────────────────────────────────────
        Field::Ver => {
            let Some(v) = sys.ver.as_deref() else { return false; };
            match c.op {
                Eq | Ne | Lt | Le | Gt | Ge => semver_cmp(v, c.op, &c.value),
                _                            => match_string(v, c.op, &c.value),
            }
        }

        // ── Plain string fields ────────────────────────────────────────────
        Field::Hostname => match_opt_string(sys.hostname.as_deref(), c.op, &c.value),
        Field::Os       => match_opt_string(sys.os.as_deref(),       c.op, &c.value),
        Field::OsFamily => match_opt_string(sys.os_family.as_deref(),c.op, &c.value),
        Field::Arch     => match_opt_string(sys.arch.as_deref(),     c.op, &c.value),
        Field::Platform => match_opt_string(sys.platform.as_deref(), c.op, &c.value),
        Field::Status   => match_opt_string(sys.status.as_deref(),   c.op, &c.value),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — match_opt_string / match_string
// Field-value can be None (column NULL); treat that as "no match" for every
// string operator (including not_equals — a missing value is not "not equal
// to X", it's simply absent).  Errs on the side of admins having to write
// rules that handle the explicit case.
// ─────────────────────────────────────────────────────────────────────────────
fn match_opt_string(field: Option<&str>, op: Operator, value: &serde_json::Value) -> bool {
    match field {
        Some(s) => match_string(s, op, value),
        None    => false,
    }
}

fn match_string(field: &str, op: Operator, value: &serde_json::Value) -> bool {
    use Operator::*;
    // Substring / prefix / suffix matches are CASE-INSENSITIVE. This matches
    // the universal admin-UI expectation ("contains 'mac'" should match
    // "Mac OS 14.5" without forcing the admin to know the exact casing the
    // agent reports) and side-steps the case mismatch between the normalized
    // os_family ("macos", "linux") and the human capitalisation an admin
    // would naturally type ("Mac", "Linux").  For case-sensitive matching
    // an admin can fall back to `regex` (Rust's `regex` crate is
    // case-sensitive by default; `(?i)` inside the pattern opts back in).
    //
    // `equals` / `not_equals` stay case-sensitive — exact-match semantics
    // are explicit, and changing them would silently broaden existing rules.
    let ci_contains    = |haystack: &str, needle: &str|
        haystack.to_lowercase().contains(&needle.to_lowercase());
    let ci_starts_with = |haystack: &str, needle: &str|
        haystack.to_lowercase().starts_with(&needle.to_lowercase());
    let ci_ends_with   = |haystack: &str, needle: &str|
        haystack.to_lowercase().ends_with(&needle.to_lowercase());

    match op {
        Equals     => value.as_str().is_some_and(|v| field == v),
        NotEquals  => value.as_str().is_some_and(|v| field != v),
        Contains   => value.as_str().is_some_and(|v| ci_contains(field, v)),
        NotContains=> value.as_str().is_some_and(|v| !ci_contains(field, v)),
        StartsWith => value.as_str().is_some_and(|v| ci_starts_with(field, v)),
        EndsWith   => value.as_str().is_some_and(|v| ci_ends_with(field, v)),
        Regex => {
            let Some(pat) = value.as_str() else { return false; };
            regex::Regex::new(pat).map(|r| r.is_match(field)).unwrap_or(false)
        }
        In => value.as_array().is_some_and(|arr|
            arr.iter().any(|x| x.as_str() == Some(field))),
        NotIn => value.as_array().is_some_and(|arr|
            !arr.iter().any(|x| x.as_str() == Some(field))),
        _ => false, // numeric / cidr ops not valid here
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — num_cmp
// Returns false if the field is NULL.  Value side accepts JSON number or
// JSON string (string parsed as i64).
// ─────────────────────────────────────────────────────────────────────────────
fn num_cmp(field: Option<i64>, op: Operator, value: &serde_json::Value) -> bool {
    use Operator::*;
    let Some(a) = field else { return false; };
    let Some(b) = value.as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<i64>().ok()))
        else { return false; };
    match op {
        Eq => a == b, Ne => a != b,
        Lt => a <  b, Le => a <= b,
        Gt => a >  b, Ge => a >= b,
        _  => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — semver_cmp
// Compares the system's version string against the rule value using
// semver::Version.  Both sides must parse; otherwise no match.
// ─────────────────────────────────────────────────────────────────────────────
fn semver_cmp(field: &str, op: Operator, value: &serde_json::Value) -> bool {
    use Operator::*;
    let Some(v_str) = value.as_str() else { return false; };
    let (Ok(a), Ok(b)) = (
        semver::Version::parse(field),
        semver::Version::parse(v_str),
    ) else { return false; };
    match op {
        Eq => a == b, Ne => a != b,
        Lt => a <  b, Le => a <= b,
        Gt => a >  b, Ge => a >= b,
        _  => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap() -> SystemSnapshot {
        SystemSnapshot {
            system_id: 1,
            hostname: Some("web-prod-01".into()),
            ip:       Some("10.10.5.7".into()),
            os:       Some("Ubuntu 24.04".into()),
            os_family: Some("linux".into()),
            arch:     Some("x86_64".into()),
            platform: Some("x86_64-linux".into()),
            ver:      Some("0.5.1".into()),
            status:   Some("active".into()),
            mem_total_mb:  Some(32_000),
            disk_total_gb: Some(500),
            uptime_secs:   Some(120_000),
            containers_exists: true,
            runtimes:         vec!["docker".into()],
            container_images: vec!["nginx:1.25".into(), "redis:7".into()],
            auto_group_fp:    None,
        }
    }

    fn cond(field: &str, op: &str, value: serde_json::Value) -> Condition {
        let raw = json!([{"field": field, "operator": op, "value": value}]).to_string();
        parse_conditions(&raw).unwrap().into_iter().next().unwrap()
    }

    #[test]
    fn string_equals_and_regex() {
        let s = snap();
        assert!(eval_condition(&cond("hostname", "starts_with", json!("web-")), &s));
        assert!(eval_condition(&cond("hostname", "regex", json!(r"^web-prod-\d+$")), &s));
        assert!(!eval_condition(&cond("hostname", "equals", json!("db-01")), &s));
    }

    #[test]
    fn cidr_match() {
        let s = snap();
        assert!(eval_condition(&cond("ip", "in_cidr", json!("10.10.0.0/16")), &s));
        assert!(!eval_condition(&cond("ip", "in_cidr", json!("192.168.0.0/16")), &s));
    }

    #[test]
    fn numeric_and_semver() {
        let s = snap();
        assert!(eval_condition(&cond("mem_total_mb", "ge", json!(16000)), &s));
        assert!(!eval_condition(&cond("mem_total_mb", "lt", json!(16000)), &s));
        assert!(eval_condition(&cond("ver", "ge", json!("0.5.0")), &s));
        assert!(eval_condition(&cond("ver", "lt", json!("1.0.0")), &s));
    }

    #[test]
    fn boolean_and_runtime() {
        let s = snap();
        assert!(eval_condition(&cond("containers_exists", "equals", json!(true)), &s));
        assert!(eval_condition(&cond("has_runtime", "equals", json!("docker")), &s));
        assert!(!eval_condition(&cond("has_runtime", "equals", json!("podman")), &s));
        assert!(eval_condition(&cond("any_container_image", "contains", json!("nginx")), &s));
    }

    #[test]
    fn os_family_enum() {
        let s = snap();
        assert!(eval_condition(&cond("os_family", "in",
            json!(["linux", "freebsd"])), &s));
        assert!(!eval_condition(&cond("os_family", "equals", json!("windows")), &s));
    }

    #[test]
    fn derive_os_family_macos_variants() {
        // Regression — user report: `os = "Mac OS 26.5.0"` (the literal string
        // os_info 3.x emits on Apple Silicon) was deriving os_family = "other"
        // because the matcher only checked for "darwin" / "macos" with no space.
        assert_eq!(derive_os_family(Some("Mac OS 26.5.0")),    Some("macos".into()));
        assert_eq!(derive_os_family(Some("Mac OS X 10.15.7")), Some("macos".into()));
        assert_eq!(derive_os_family(Some("macOS 14.5")),       Some("macos".into()));
        assert_eq!(derive_os_family(Some("Darwin 23.5.0")),    Some("macos".into()));
        assert_eq!(derive_os_family(Some("Macintosh")),        Some("macos".into()));

        // Negative cases — make sure the broadened "mac" / "mac os" prefix
        // doesn't catch unrelated strings.
        assert_eq!(derive_os_family(Some("Ubuntu 24.04")),     Some("linux".into()));
        assert_eq!(derive_os_family(Some("Microsoft Windows Server 2022")), Some("windows".into()));
        assert_eq!(derive_os_family(Some("FreeBSD 14.0")),     Some("freebsd".into()));
    }

    #[test]
    fn null_field_never_matches() {
        let mut s = snap();
        s.mem_total_mb = None;
        assert!(!eval_condition(&cond("mem_total_mb", "ge", json!(1)), &s));
    }

    // ─── fingerprint (P3 short-circuit) ─────────────────────────────────────

    #[test]
    fn fingerprint_is_stable_and_ignores_stored_fp() {
        // Same field values → same hash, regardless of the stored auto_group_fp
        // (the stored value must NOT feed into the hash, or comparison is moot).
        let a = snap();
        let mut b = snap();
        b.auto_group_fp = Some("whatever-old-hash".into());
        assert_eq!(a.fingerprint_hash(), b.fingerprint_hash());
    }

    #[test]
    fn fingerprint_changes_on_each_rule_relevant_field() {
        let base = snap().fingerprint_hash();

        let mut s = snap(); s.hostname = Some("db-01".into());
        assert_ne!(base, s.fingerprint_hash(), "hostname must affect fp");

        let mut s = snap(); s.ip = Some("10.0.0.1".into());
        assert_ne!(base, s.fingerprint_hash(), "ip must affect fp");

        let mut s = snap(); s.os = Some("Debian 12".into());
        assert_ne!(base, s.fingerprint_hash(), "os must affect fp");

        let mut s = snap(); s.arch = Some("aarch64".into());
        assert_ne!(base, s.fingerprint_hash(), "arch must affect fp");

        let mut s = snap(); s.ver = Some("0.5.3".into());
        assert_ne!(base, s.fingerprint_hash(), "ver must affect fp");

        let mut s = snap(); s.status = Some("pending".into());
        assert_ne!(base, s.fingerprint_hash(), "status must affect fp");

        let mut s = snap(); s.mem_total_mb = Some(16_000);
        assert_ne!(base, s.fingerprint_hash(), "mem_total_mb must affect fp");

        let mut s = snap(); s.disk_total_gb = Some(1000);
        assert_ne!(base, s.fingerprint_hash(), "disk_total_gb must affect fp");

        let mut s = snap(); s.containers_exists = false;
        assert_ne!(base, s.fingerprint_hash(), "containers_exists must affect fp");

        let mut s = snap(); s.runtimes = vec!["podman".into()];
        assert_ne!(base, s.fingerprint_hash(), "runtimes must affect fp");

        let mut s = snap(); s.container_images = vec!["nginx:1.26".into()];
        assert_ne!(base, s.fingerprint_hash(), "container_images must affect fp");
    }

    #[test]
    fn fingerprint_ignores_uptime() {
        // uptime_secs is deliberately excluded — it changes every heartbeat and
        // would defeat the short-circuit if it fed the hash.
        let base = snap().fingerprint_hash();
        let mut s = snap();
        s.uptime_secs = Some(999_999);
        assert_eq!(base, s.fingerprint_hash(), "uptime_secs must NOT affect fp");
    }

    #[test]
    fn validator_rejects_empty_rule() {
        assert!(validate_conditions_json("[]").is_err());
    }

    #[test]
    fn validator_rejects_bad_operator_for_field() {
        assert!(parse_conditions(
            &json!([{"field":"mem_total_mb","operator":"contains","value":"x"}]).to_string()
        ).is_err());
    }

    #[test]
    fn validator_rejects_bad_regex() {
        assert!(parse_conditions(
            &json!([{"field":"hostname","operator":"regex","value":"["}]).to_string()
        ).is_err());
    }

    #[test]
    fn string_substring_ops_are_case_insensitive() {
        // Regression — contains / not_contains / starts_with / ends_with
        // all fold case so an admin writing `os contains "Mac"` matches an
        // agent that reported `"Mac OS 14.5"`, and `os_family contains
        // "Linux"` matches the normalized lowercase `"linux"`.  equals
        // remains case-sensitive (explicit-match semantics).
        let mut s = snap();
        s.os = Some("Mac OS 14.5".into());
        s.os_family = Some("macos".into());

        assert!(eval_condition(&cond("os", "contains",    json!("mac")), &s),
                "lowercase needle should match mixed-case haystack");
        assert!(eval_condition(&cond("os", "contains",    json!("MAC")), &s),
                "uppercase needle should match mixed-case haystack");
        assert!(eval_condition(&cond("os_family", "contains", json!("Mac")), &s),
                "capitalised needle should match normalised lowercase field");
        assert!(eval_condition(&cond("os", "starts_with", json!("mac")), &s));
        assert!(eval_condition(&cond("os", "ends_with",   json!("14.5")), &s));
        assert!(eval_condition(&cond("os", "not_contains", json!("windows")), &s));

        // equals is still strict.
        assert!(!eval_condition(&cond("os_family", "equals", json!("Mac")), &s),
                "equals must remain case-sensitive");
        assert!(eval_condition(&cond("os_family", "equals", json!("macos")), &s));
    }

    #[test]
    fn enum_fields_accept_contains() {
        // os_family / arch / status / has_runtime previously only accepted
        // equals / not_equals / in / not_in. Verify Contains / NotContains
        // are now accepted by the validator and actually match at eval time.
        let s = snap();
        assert!(eval_condition(
            &cond("os_family", "contains", json!("inu")), &s));
        assert!(eval_condition(
            &cond("arch",      "not_contains", json!("arm")), &s));
        assert!(eval_condition(
            &cond("has_runtime","contains", json!("dock")), &s));
        // Validator round-trip.
        validate_conditions_json(
            &json!([{"field":"status","operator":"contains","value":"act"}]).to_string()
        ).unwrap();
    }

    #[test]
    fn validator_rejects_bad_cidr() {
        assert!(parse_conditions(
            &json!([{"field":"ip","operator":"in_cidr","value":"not-a-cidr"}]).to_string()
        ).is_err());
    }

    // ─── build / explode form helpers (click editor) ────────────────────────

    fn form(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, Vec<String>> {
        let mut m = std::collections::HashMap::new();
        for (k, v) in pairs {
            m.entry(k.to_string()).or_insert_with(Vec::new).push(v.to_string());
        }
        m
    }

    #[test]
    fn form_builds_string_condition() {
        let f = form(&[("field_1", "hostname"), ("op_1", "equals"), ("value_1", "web-01")]);
        let s = build_conditions_json_from_form(&f, 4).unwrap();
        // Round-trips through the validator cleanly.
        validate_conditions_json(&s).unwrap();
        assert!(s.contains("\"hostname\""));
        assert!(s.contains("\"web-01\""));
    }

    #[test]
    fn form_coerces_numeric_value_to_number() {
        let f = form(&[("field_1", "mem_total_mb"), ("op_1", "ge"), ("value_1", "16000")]);
        let s = build_conditions_json_from_form(&f, 4).unwrap();
        // Number, not string.
        assert!(s.contains("\"value\":16000"));
        validate_conditions_json(&s).unwrap();
    }

    #[test]
    fn form_coerces_bool_value() {
        let f = form(&[("field_1", "containers_exists"), ("op_1", "equals"), ("value_1", "True")]);
        let s = build_conditions_json_from_form(&f, 4).unwrap();
        assert!(s.contains("\"value\":true"));
        validate_conditions_json(&s).unwrap();
    }

    #[test]
    fn form_splits_in_list_on_commas() {
        let f = form(&[("field_1", "arch"), ("op_1", "in"),
                       ("value_1", "x86_64, aarch64 , arm64")]);
        let s = build_conditions_json_from_form(&f, 4).unwrap();
        // All three values present, trimmed.
        assert!(s.contains("\"x86_64\""));
        assert!(s.contains("\"aarch64\""));
        assert!(s.contains("\"arm64\""));
        validate_conditions_json(&s).unwrap();
    }

    #[test]
    fn form_skips_fully_blank_rows() {
        let f = form(&[
            ("field_1", "hostname"), ("op_1", "equals"), ("value_1", "x"),
            ("field_2", ""),         ("op_2", ""),       ("value_2", ""),
            ("field_3", "os_family"), ("op_3", "equals"), ("value_3", "linux"),
        ]);
        let s = build_conditions_json_from_form(&f, 4).unwrap();
        // Two conditions, blank middle row dropped.
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn form_rejects_partial_rows() {
        let f = form(&[("field_1", "hostname"), ("op_1", "equals"), ("value_1", "")]);
        assert!(build_conditions_json_from_form(&f, 4).is_err());
    }

    #[test]
    fn form_rejects_empty_rule() {
        let f = form(&[]);
        assert!(build_conditions_json_from_form(&f, 4).is_err());
    }

    #[test]
    fn explode_roundtrips_string() {
        let raw = json!([{"field":"hostname","operator":"equals","value":"web-01"}]).to_string();
        let out = explode_conditions_for_form(&raw);
        assert_eq!(out, vec![("hostname".into(), "equals".into(), "web-01".into())]);
    }

    #[test]
    fn explode_flattens_array_to_csv() {
        let raw = json!([{"field":"arch","operator":"in","value":["x86_64","aarch64"]}]).to_string();
        let out = explode_conditions_for_form(&raw);
        assert_eq!(out[0].2, "x86_64, aarch64");
    }

    #[test]
    fn explode_stringifies_number_and_bool() {
        let raw = json!([
            {"field":"mem_total_mb","operator":"ge","value":16000},
            {"field":"containers_exists","operator":"equals","value":true},
        ]).to_string();
        let out = explode_conditions_for_form(&raw);
        assert_eq!(out[0].2, "16000");
        assert_eq!(out[1].2, "true");
    }
}
