// =============================================================================
// schema.rs — database initialisation and incremental migrations
//
// initialize_database creates all tables and seeds default data on a fresh
// install. run_migrations applies version-gated ALTER TABLE / data fixes to
// existing databases without re-running the full schema.
//
// SQLite-only since v0.3.1. All SQL is plain SQLite syntax with no compatibility wrappers.
// =============================================================================
use sqlx::SqlitePool;
use sqlx::Row;
use tracing::{info, warn};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: column_exists
// Returns true if `column` is present in `table`.
// Uses pragma_table_info which is a virtual table readable via plain SQL.
// ─────────────────────────────────────────────────────────────────────────────
async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> bool {
    let sql = format!(
        "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name = '{}'",
        table, column
    );
    let count: i64 = sqlx::query_scalar(&sql)
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    count > 0
}

async fn table_exists(pool: &SqlitePool, table: &str) -> bool {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?"
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    count > 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create_tables
// Issues all CREATE TABLE IF NOT EXISTS statements for a fresh database.
// Called exclusively by initialize_database; safe to call again (idempotent).
// ─────────────────────────────────────────────────────────────────────────────
async fn create_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Tenants Table (no AUTOINCREMENT — VARCHAR(191) PK so MySQL can index it)
    // status and plan are EE/SaaS fields present in base schema so all editions
    // share an identical table structure.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (
            id         VARCHAR(191) PRIMARY KEY,
            name       VARCHAR(191) NOT NULL UNIQUE,
            status     TEXT NOT NULL DEFAULT 'active',
            plan       TEXT NOT NULL DEFAULT 'free',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;

    // Tenant Keys Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settings (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            skey VARCHAR(191) NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            PRIMARY KEY (tenant_id, skey),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Notify Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notify (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            ntype TEXT,
            nts TEXT,
            owner_id INTEGER,
            message TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Users Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            username VARCHAR(191) NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            email TEXT,
            role TEXT,
            email_verified INTEGER NOT NULL DEFAULT 1,
            directory_id INTEGER,
            external_username TEXT,
            -- 0 = show the guided first-run tour on the dashboard. See the
            -- v37 → v38 migration for why fresh installs must default to 0.
            tour_done INTEGER NOT NULL DEFAULT 0,
            UNIQUE(username, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Systems Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT,
            ver TEXT,
            key TEXT,
            ip TEXT,
            os TEXT,
            arch TEXT,
            status VARCHAR(32),
            groups TEXT,
            auth_public_key TEXT,
            auth_signature TEXT,
            trust_challenge TEXT,
            trust_proof TEXT,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            compliance_score REAL DEFAULT -1.0,
            score_test REAL DEFAULT -1.0,
            score_policy REAL DEFAULT -1.0,
            tests_passed INTEGER DEFAULT 0,
            tests_failed INTEGER DEFAULT 0,
            total_tests INTEGER DEFAULT 0,
            compliance_dirty INTEGER NOT NULL DEFAULT 0,
            auto_group_fp TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // System Groups Table — auto_managed flag distinguishes manual
    // (admin-curated) groups from auto groups whose membership is
    // determined by a rule in auto_group_rules.  Immutable after create.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name VARCHAR(191) NOT NULL,
            description TEXT,
            auto_managed INTEGER NOT NULL DEFAULT 0,
            UNIQUE(name, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Systems-in-Groups join table (no AUTOINCREMENT — composite PK)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_groups (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            system_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (tenant_id, system_id, group_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Auto-Group Rules Table — one rule per auto group (UNIQUE(group_id)).
    // `conditions` holds a JSON array of {field, op, value} objects evaluated
    // with AND semantics.  Membership is reconciled by apply_auto_groups()
    // on heartbeat (when a rule-relevant field changes) and on rule edit.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS auto_group_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            group_id INTEGER NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            conditions TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Enrollment Tokens Table — "golden tokens" that auto-approve enrolling
    // systems (status active instead of pending). Approval bypass only, not an
    // auth bypass: the ed25519 handshake still happens. Secret is stored as a
    // SHA-256 hash; token_prefix is a non-secret display id. See
    // docs/design/0.6.0-enrollment-tokens.md.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS enrollment_tokens (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id    VARCHAR(191) NOT NULL DEFAULT 'default',
            name         TEXT NOT NULL,
            token_hash   TEXT NOT NULL,
            token_prefix TEXT,
            enabled      INTEGER NOT NULL DEFAULT 1,
            expires_at   DATETIME,
            max_uses     INTEGER,
            use_count    INTEGER NOT NULL DEFAULT 0,
            created_by   TEXT,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_lookup ON enrollment_tokens (tenant_id, enabled)")
        .execute(pool).await?;

    // Tests Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            description TEXT,
            rational TEXT,
            remediation TEXT,
            severity TEXT,
            app_filter TEXT DEFAULT 'all',
            filter TEXT DEFAULT 'all',
            external_id TEXT,
            compliance_score REAL DEFAULT -1.0,
            systems_passed INTEGER DEFAULT 0,
            systems_failed INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Test Conditions Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            test_id INTEGER NOT NULL,
            name TEXT,
            description TEXT,
            `type` TEXT NOT NULL,
            element TEXT NOT NULL,
            input TEXT NOT NULL,
            selement TEXT NOT NULL,
            condition TEXT,
            sinput TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Policies Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            description TEXT,
            version TEXT,
            author TEXT,
            external_id TEXT,
            compliance_score REAL DEFAULT -1.0,
            score_test REAL DEFAULT -1.0,
            score_system REAL DEFAULT -1.0,
            score_container REAL DEFAULT -1.0,
            systems_passed INTEGER DEFAULT 0,
            systems_failed INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Policy Schedules Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policy_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            policy_id INTEGER NOT NULL,
            schedule_type VARCHAR(32) NOT NULL DEFAULT 'scan',
            enabled BOOLEAN NOT NULL DEFAULT 1,
            frequency TEXT NOT NULL,
            cron_expression TEXT,
            next_run DATETIME NOT NULL,
            last_run DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(policy_id, schedule_type),
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Tests-in-Policy join table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tests_in_policy (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            policy_id INTEGER,
            test_id INTEGER,
            PRIMARY KEY (tenant_id, policy_id, test_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Systems-in-Policy join table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_policy (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            policy_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (tenant_id, policy_id, group_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Commands table — pending agent actions, dispatched on the next heartbeat.
    //   command_type = 'TEST'    → test_id is the FK into tests, queued by a policy run.
    //   command_type = 'UPGRADE' → test_id is NULL, queued by an admin from the Systems list.
    // The compound PK (tenant_id, system_id, test_id) enforces per-test uniqueness for
    // TEST rows; the partial unique index below enforces at most one UPGRADE per system.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commands (
            tenant_id    VARCHAR(191) NOT NULL DEFAULT 'default',
            system_id    INTEGER,
            test_id      INTEGER,
            command_type TEXT NOT NULL DEFAULT 'TEST',
            PRIMARY KEY (tenant_id, system_id, test_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id)   REFERENCES tests   (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cmd_upgrade_uniq
            ON commands(tenant_id, system_id) WHERE command_type = 'UPGRADE'",
    )
    .execute(pool)
    .await?;

    // Results table
    // The excluded* columns are per-(system, test) finding suppression set by
    // an Editor from the live policy report (right-click → Exclude). Excluded
    // rows are treated as NA at scoring/render time. The heartbeat UPSERT
    // only writes `result` + `last_updated`, so re-running the policy never
    // resets an exclusion. ON DELETE CASCADE on system / test removes them.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS results (
            tenant_id    VARCHAR(191) NOT NULL DEFAULT 'default',
            system_id    INTEGER,
            test_id      INTEGER,
            result       TEXT,
            last_updated TEXT,
            excluded     INTEGER NOT NULL DEFAULT 0,
            excluded_by  TEXT,
            excluded_at  DATETIME,
            -- Why the finding was excluded. Nullable: exclusions predating the
            -- v38 → v39 migration have no recorded reason.
            excluded_reason TEXT,
            container_id INTEGER NOT NULL DEFAULT 0,
            evidence     TEXT,
            PRIMARY KEY (tenant_id, system_id, test_id, container_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Audit log — immutable record of state-changing admin actions.
    // Written by handlers via crate::audit::record(...). Visible from
    // /admin/audit-log (Admin role only). Retention is governed by the
    // settings.audit_log_retention_days value (see seed below); the actual
    // cleanup tick will be added by Task #9 (retention/cleanup policy).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id       VARCHAR(191) NOT NULL DEFAULT 'default',
            actor_user_id   INTEGER,
            actor_username  TEXT NOT NULL,
            action          TEXT NOT NULL,
            target_type     TEXT,
            target_id       TEXT,
            details         TEXT,
            ip_address      TEXT,
            created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
            ON audit_log(tenant_id, created_at DESC)",
    )
    .execute(pool)
    .await?;

    // Directories table — configured external identity providers (LDAP in v1).
    // Users reference a directory via users.directory_id (NULL = local).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS directories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            dir_type TEXT NOT NULL DEFAULT 'ldap',
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            use_tls INTEGER NOT NULL DEFAULT 0,
            skip_tls_verify INTEGER NOT NULL DEFAULT 0,
            base_dn TEXT NOT NULL,
            bind_dn TEXT NOT NULL DEFAULT '',
            bind_password TEXT NOT NULL DEFAULT '',
            user_attribute TEXT NOT NULL DEFAULT 'uid',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_directories_tenant ON directories (tenant_id)")
        .execute(pool)
        .await?;

    // Containers table — per-host inventory of app containers (Docker, Podman,
    // later Kubernetes pods). Replaced on every heartbeat by the host's agent;
    // stale rows pruned by container_retention_days. See docs/design/0.5.0-containers.md.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS containers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id       VARCHAR(191) NOT NULL DEFAULT 'default',
            host_system_id  INTEGER NOT NULL,
            runtime         TEXT NOT NULL,
            runtime_id      TEXT NOT NULL,
            name            TEXT NOT NULL,
            image           TEXT,
            image_digest    TEXT,
            status          TEXT,
            ip              TEXT,
            is_privileged   INTEGER,
            run_user        TEXT,
            network_mode    TEXT,
            exposed_ports   TEXT,
            mounts          TEXT,
            capabilities_add TEXT,
            read_only_fs    INTEGER,
            restart_policy  TEXT,
            health_check    INTEGER,
            tests_passed    INTEGER DEFAULT 0,
            tests_failed    INTEGER DEFAULT 0,
            compliance_score REAL DEFAULT -1.0,
            first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(host_system_id, runtime, name),
            FOREIGN KEY (host_system_id) REFERENCES systems(id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_containers_host  ON containers(host_system_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_containers_image ON containers(image)")
        .execute(pool).await?;

    // Reports table
    // tests_metadata and report_results store arbitrary-size JSON — use MEDIUMTEXT
    // so MySQL does not impose a row-size limit.  They are decoded via row_get_string().
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            submission_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            policy_name TEXT NOT NULL,
            policy_version TEXT,
            policy_description TEXT,
            submitter_name TEXT,
            tests_metadata MEDIUMTEXT NOT NULL,
            report_results MEDIUMTEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // System Reports table
    // report_data stores arbitrary-size JSON — use MEDIUMTEXT decoded via row_get_string().
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            submission_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            system_id INTEGER NOT NULL,
            system_name TEXT NOT NULL,
            submitter_name TEXT,
            report_data MEDIUMTEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Compliance History table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            check_date DATE DEFAULT CURRENT_TIMESTAMP,
            systems_score REAL DEFAULT 0.0,
            policies_score REAL DEFAULT 0.0,
            systems_score_test REAL DEFAULT 0.0,
            systems_score_policy REAL DEFAULT 0.0,
            policies_score_test REAL DEFAULT 0.0,
            policies_score_system REAL DEFAULT 0.0,
            total_systems INTEGER,
            failed_systems INTEGER,
            total_policies INTEGER,
            failed_policies INTEGER,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Per-entity compliance history — hourly snapshots per system and per
    // policy, powering the trend charts on the live report pages (design:
    // 0.7.2-entity-trends.md). Both compliance axes are stored per row so a
    // mode-toggle flip re-renders the whole history: a system's score_strict
    // is its per-policy axis, a policy's is its per-system axis. entity_id is
    // deliberately NOT a foreign key — history must not block entity deletion
    // (delete handlers clean up; retention reaps the rest).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS entity_compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            check_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            score_test REAL,
            score_strict REAL,
            tests_passed INTEGER,
            tests_failed INTEGER,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    // Covers the chart query (tenant, type, id, ordered by date) and makes
    // the retention prune (check_date < cutoff) a range scan.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_entity_history_lookup
         ON entity_compliance_history (tenant_id, entity_type, entity_id, check_date)",
    )
    .execute(pool)
    .await?;

    // Elements Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS elements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(191) NOT NULL UNIQUE,
            description TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Selements Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS selements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(191) NOT NULL UNIQUE,
            description TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Conditions Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(191) NOT NULL UNIQUE,
            description TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Agent Packages table — one row per supported client platform, upserted on startup.
    // Used by the auto-upgrade feature: the server scans its agents directory, records
    // the version + SHA256 of each binary, and surfaces an Upgrade button in the
    // Systems list when a system's reported version is older than the available one.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_packages (
            platform   TEXT PRIMARY KEY,
            version    TEXT NOT NULL,
            sha256     TEXT NOT NULL,
            url        TEXT NOT NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;

    // Email Verification Tokens (used by SaaS registration; harmless in CE/EE)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tenant_id VARCHAR(191) NOT NULL,
            token VARCHAR(191) NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .execute(pool).await?;

    // Password Reset Tokens (used by SaaS; harmless in CE/EE)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      VARCHAR(191) NOT NULL UNIQUE,
            expires_at TEXT    NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .execute(pool).await?;

    // Plan Limits (used by SaaS to enforce per-plan resource caps; harmless in CE/EE)
    // max_count = 0 means unlimited
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plan_limits (
            plan      VARCHAR(191) NOT NULL,
            resource  VARCHAR(191) NOT NULL,
            max_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (plan, resource)
        )",
    )
    .execute(pool).await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create_indexes
// Issues all CREATE INDEX IF NOT EXISTS statements for a fresh database.
// Called exclusively by initialize_database; safe to call again (idempotent).
// ─────────────────────────────────────────────────────────────────────────────
async fn create_indexes(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_next_run ON policy_schedules (enabled, next_run)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_results_tenant_test ON results (tenant_id, test_id)")
        .execute(pool).await?;
    // Covering index for the compliance-recalc correlated subqueries
    // (update_test_stats): everything they filter/count on lives in the index,
    // so the COUNT(*) per test is an index range scan rather than a heap fetch.
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_results_recalc_cover ON results (tenant_id, test_id, result, excluded, system_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_test_conditions_tenant_test ON test_conditions (tenant_id, test_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_systems_tenant_status ON systems (tenant_id, status)")
        .execute(pool).await?;
    // Supports the auto-prune-inactive sweep (runs every 60s): once the prune
    // query is sargable (last_seen < cutoff), this turns its full scan of a
    // tenant's active systems into a range scan.
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_systems_prune ON systems (tenant_id, status, last_seen)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_systems_tenant_score ON systems (tenant_id, compliance_score)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sig_tenant_group ON systems_in_groups (tenant_id, group_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sip_tenant_group ON systems_in_policy (tenant_id, group_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tip_tenant_test ON tests_in_policy (tenant_id, test_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_history_tenant_date ON compliance_history (tenant_id, check_date)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_notify_tenant_owner ON notify (tenant_id, owner_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_active ON tenant_keys (tenant_id, is_active)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_tenant_date ON reports (tenant_id, submission_date)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_email_verif_token ON email_verifications (token)")
        .execute(pool).await.ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets (token)")
        .execute(pool).await.ok();
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_system_reports_tenant_date
         ON system_reports (tenant_id, submission_date)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: seed_lookup_data
// Inserts the default tenant, default settings, and lookup table rows
// (elements, selements, conditions) using INSERT OR IGNORE (idempotent).
// Called exclusively by initialize_database on a fresh install.
// ─────────────────────────────────────────────────────────────────────────────
async fn seed_lookup_data(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Default tenant
    sqlx::query(
        "INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', 'Default Tenant')"
    )
    .execute(pool)
    .await?;

    // NOTE: the admin user is NOT seeded here — created by /install with the
    // administrator's chosen password so no default credentials exist on disk.

    // Default settings
    sqlx::query(
        "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description) VALUES
        ('default', 'offline_threshold', '60', 'Minutes without activity before system is marked offline'),
        ('default', 'auto_prune_inactive', '0', 'Minutes without activity before an inactive system is auto-deleted (0 = disabled)'),
        ('default', 'compliance_sat', '80', 'Minimum compliance percentage for SAT status'),
        ('default', 'compliance_marginal', '60', 'Minimum compliance percentage for MARGINAL status'),
        ('default', 'smtp_host', '', 'SMTP relay hostname'),
        ('default', 'smtp_port', '587', 'SMTP relay port'),
        ('default', 'smtp_username', '', 'SMTP relay username'),
        ('default', 'smtp_password', '', 'SMTP relay password'),
        ('default', 'smtp_from', '', 'From address for outgoing emails'),
        ('default', 'smtp_tls', 'starttls', 'TLS mode: starttls, tls, or none'),
        ('default', 'app_url', '', 'Public URL of this installation (used in email links)'),
        ('default', 'audit_log_retention_days', '730', 'Days to keep audit_log rows before auto-pruning (0 = keep forever)'),
        ('default', 'report_retention_days', '0', 'Days to keep saved policy/system report snapshots before auto-pruning (0 = keep forever)'),
        ('default', 'notification_retention_days', '30', 'Days to keep bell-icon notifications before auto-pruning (0 = keep forever)'),
        ('default', 'container_retention_days', '7', 'Days to keep container inventory rows after last_seen before auto-pruning (0 = keep forever)'),
        ('default', 'entity_trend_retention_days', '90', 'Days to keep per-system/per-policy trend snapshots before auto-pruning (0 = keep forever)'),
        ('default', 'fleet_trend_retention_days', '365', 'Days to keep fleet-wide compliance trend snapshots before auto-pruning (0 = keep forever)')"
    )
    .execute(pool)
    .await?;

    // Elements — every element is evaluated agent-side via the standard
    // compliance dispatch (commands table → heartbeat → result POST).
    // Container-related elements (CONTAINER, IMAGE, NETWORK) work like
    // any other: the agent enumerates its local container inventory and
    // evaluates against it.
    for name in &[
        "AGENT", "OS", "HOSTNAME", "IP", "DOMAIN", "ARCHITECTURE", "USER", "GROUP",
        "FILE", "DIRECTORY", "PROCESS", "PACKAGE", "REGISTRY", "PORT", "CMD",
        "POWERSHELL", "SERVICE",
        // Container-related — agent-side, evaluated against the local
        // container inventory.
        "CONTAINER", "IMAGE", "NETWORK", "PRIVILEGED", "RUN_USER",
        "MOUNT", "EXPOSED_PORT", "READ_ONLY_FS", "HEALTH_CHECK",
    ] {
        sqlx::query("INSERT OR IGNORE INTO elements (name) VALUES (?)")
            .bind(name)
            .execute(pool)
            .await?;
    }

    // Selements
    for name in &[
        "EXISTS", "NOT EXISTS", "CONTENT", "VERSION", "PERMISSION",
        "OWNER", "GROUP", "SHA1", "SHA2", "OUTPUT", "EXIT CODE",
        "COUNT", "ACTIVE", "INACTIVE", "ENABLED", "DISABLED",
        "NAME", "TAG", "DIGEST", "SOURCE", "MODE",
    ] {
        sqlx::query(
            "INSERT OR IGNORE INTO selements (name) VALUES (?)"
        )
        .bind(name)
        .execute(pool)
        .await?;
    }

    // Conditions
    for name in &[
        "CONTAINS", "NOT CONTAINS", "EQUALS", "NOT EQUALS",
        "MORE THAN", "LESS THAN", "REGEX",
    ] {
        sqlx::query(
            "INSERT OR IGNORE INTO conditions (name) VALUES (?)"
        )
        .bind(name)
        .execute(pool)
        .await?;
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: initialize_database
// Creates all tables, indexes, triggers, and seed data for a fresh install.
// Stamps schema_info.version = 13 so run_migrations skips all steps.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn initialize_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {

    info!("Init Database......");

    create_tables(pool).await?;
    create_indexes(pool).await?;
    seed_lookup_data(pool).await?;

    // Generate Ed25519 keypair for the default tenant if it doesn't exist yet
    let existing_key = sqlx::query("SELECT id FROM tenant_keys WHERE tenant_id = 'default' LIMIT 1")
        .fetch_optional(pool)
        .await?;

    if existing_key.is_none() {
        info!("Generating new Ed25519 pair for default tenant...");
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let public_base64  = general_purpose::STANDARD.encode(verifying_key.as_bytes());
        let private_base64 = general_purpose::STANDARD.encode(signing_key.to_bytes());

        sqlx::query(
            "INSERT INTO tenant_keys (tenant_id, public_key, private_key) VALUES ('default', ?, ?)"
        )
        .bind(public_base64)
        .bind(private_base64)
        .execute(pool)
        .await?;

        info!("Default keys generated and secured in database.");
    }

    // schema_info table (no AUTOINCREMENT — single-row sentinel)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_info (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Bootstrap admin role protection trigger.
    // The NEW.role != OLD.role guard matters: SQLite's `BEFORE UPDATE OF role`
    // fires whenever `role` appears in the UPDATE statement's SET clause,
    // not only when the value actually changes — so without it, a routine
    // edit of name/email that re-passes the current role would abort.
    sqlx::query(
        "CREATE TRIGGER IF NOT EXISTS protect_bootstrap_admin_role
       BEFORE UPDATE OF role ON users
       WHEN OLD.id = 1 AND OLD.tenant_id = 'default' AND NEW.role != OLD.role
       BEGIN
           SELECT RAISE(ABORT, 'The bootstrap admin role cannot be changed');
       END"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO schema_info (id, version) VALUES (1, 13)"
    )
    .execute(pool)
    .await?;

    info!("Schema version stamped at 11 (fresh install).");

    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: seed_plan_limits
// Inserts the default per-plan resource caps into `plan_limits`.
// Uses INSERT OR IGNORE so it is safe to call on every startup (idempotent).
// Called by SaaS on every startup; CE/EE deliberately do NOT call this so
// the table stays empty and the dashboard hides the limit counters.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn seed_plan_limits(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for (plan, resource, max_count) in &[
        ("free",       "systems",   5i64),
        ("free",       "groups",    3),
        ("free",       "policies",  3),
        ("free",       "reports",   10),
        ("starter",    "systems",   25),
        ("starter",    "groups",    10),
        ("starter",    "policies",  10),
        ("starter",    "reports",   100),
        ("pro",        "systems",   100),
        ("pro",        "groups",    50),
        ("pro",        "policies",  50),
        ("pro",        "reports",   500),
        ("enterprise", "systems",   0),
        ("enterprise", "groups",    0),
        ("enterprise", "policies",  0),
        ("enterprise", "reports",   0),
    ] {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO plan_limits (plan, resource, max_count) VALUES (?, ?, ?)",
        )
        .bind(plan)
        .bind(resource)
        .bind(*max_count)
        .execute(pool)
        .await;
    }
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: run_migrations
// Applies incremental schema migrations to existing installations. Each step
// is guarded by a version check so it runs exactly once.
//
// CONVENTION — multi-statement DDL must use a single connection.
// `&SqlitePool` is shared across the connection pool; sqlx is free to grab a
// different pooled connection for each `.execute(pool)`. For DDL that issues
// two or more statements where a later one depends on the schema effect of
// an earlier one — e.g. DROP+CREATE of the same object name, ALTER ADD
// COLUMN followed by an UPDATE that references the new column, or RENAME
// COLUMN followed by a SELECT on the new name — the schema change on the
// first connection may not be visible to the second, and the second
// statement can fail with confusing "X already exists" / "no such column"
// errors even though the first returned Ok.
//
// Choose one of:
//   (a) `let mut tx = pool.begin().await?;`   — preferred; gives atomic
//       rollback on failure AND pins to one connection. Use for any step
//       that mutates user data alongside DDL.
//   (b) `let mut conn = pool.acquire().await?;` — lighter; pin to one
//       connection without the all-or-nothing semantics. Use only when
//       individual statements are idempotent and partial progress is fine.
//
// Single-statement migrations (one `INSERT OR IGNORE`, one `ALTER ADD COLUMN`
// followed only by an unrelated `UPDATE schema_info`, etc.) are safe via
// the `pool` reference — no cross-connection schema dependency.
//
// ENFORCED SINCE 0.9.4 — the convention above was not followed everywhere,
// and it broke every fresh install. The v25 → v26 `results` rebuild issues
// DROP TABLE results and then ALTER TABLE results_new RENAME TO results on
// whatever connections the pool hands out; on a file database in WAL mode the
// rename landed on a connection that still saw the old `results`, failed with
// "there is already another table or index with this name", and left the
// database at v25 with no `results` table. /install logged the error and
// carried on; the next start returned it from main() and the server could not
// start again. In-memory test databases do not behave this way, so no test
// saw it.
//
// run_migrations therefore no longer runs migrations on the caller's pool. It
// opens a dedicated pool of exactly ONE connection to the same database and
// runs the whole chain there, so every statement sees the one before it and
// connection-scoped pragmas (the v26 `foreign_keys = OFF`) actually apply to
// the statements that follow. The rule above still describes how to write a
// migration; this makes a slip in it harmless.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let single = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let result = run_migrations_on(&single).await;
    single.close().await;
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: run_migrations_on
// The migration chain itself. Only ever called by run_migrations, with a
// single-connection pool.
// ─────────────────────────────────────────────────────────────────────────────
async fn run_migrations_on(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // schema_info sentinel table (no AUTOINCREMENT)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_info (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Seed with version 0 if the table is empty
    sqlx::query(
        "INSERT OR IGNORE INTO schema_info (id, version) VALUES (1, 0)"
    )
    .execute(pool)
    .await?;

    // ── Pre-migration: rename settings.key → settings.skey ────────────────────
    // `key` is a MySQL/MariaDB reserved word.  The rename was applied to the
    // CREATE TABLE in initialize_database (so fresh installs are fine), but
    // existing SQLite/PostgreSQL databases still carry the old column name.
    // This must run BEFORE any version-gated INSERT into settings so that
    // "no such column: skey" errors can never occur at any schema version.
    // On MySQL the old column never existed, so column_exists returns false
    // and the block is skipped.
    if column_exists(pool, "settings", "key").await {
        let _ = sqlx::query(
            "ALTER TABLE settings RENAME COLUMN \"key\" TO skey"
        ).execute(pool).await;
        info!("Pre-migration: renamed settings.key → settings.skey");
    }
    // ──────────────────────────────────────────────────────────────────────────

    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(pool)
        .await?;

    info!("Current schema version: {}", version);

    // v0 → v1: bump only; base schema already applied by initialize_database
    if version < 1 {
        sqlx::query("UPDATE schema_info SET version = 1")
            .execute(pool)
            .await?;
        info!("Schema version set to 1.");
    }

    // v1 → v2 (0.1.5 → 0.1.6): add app_filter to tests
    if version < 2 {
        info!("Running schema migration v1 → v2...");

        // Ignore error if column already exists (fresh install)
        let _ = sqlx::query("ALTER TABLE tests ADD COLUMN app_filter TEXT DEFAULT 'all'")
            .execute(pool)
            .await;

        sqlx::query("UPDATE schema_info SET version = 2")
            .execute(pool)
            .await?;

        info!("Schema migration v1 → v2 complete.");
    }

    // v2 → v3: rebuild policy_schedules with schedule_type column
    if version < 3 {
        info!("Running schema migration v2 → v3...");

        let mut migration_tx = pool.begin().await?;

        sqlx::query("DROP TABLE IF EXISTS policy_schedules_old")
            .execute(&mut *migration_tx).await?;
        sqlx::query("ALTER TABLE policy_schedules RENAME TO policy_schedules_old")
            .execute(&mut *migration_tx).await?;

        sqlx::query(
            "CREATE TABLE policy_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
                policy_id INTEGER NOT NULL,
                schedule_type VARCHAR(32) NOT NULL DEFAULT 'scan',
                enabled BOOLEAN NOT NULL DEFAULT 1,
                frequency TEXT NOT NULL,
                cron_expression TEXT,
                next_run DATETIME NOT NULL,
                last_run DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(policy_id, schedule_type),
                FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "INSERT INTO policy_schedules
                (id, tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run, last_run, created_at)
             SELECT id, tenant_id, policy_id, 'scan', enabled, frequency, cron_expression, next_run, last_run, created_at
             FROM policy_schedules_old"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query("DROP TABLE policy_schedules_old")
            .execute(&mut *migration_tx).await?;
        sqlx::query("UPDATE schema_info SET version = 3")
            .execute(&mut *migration_tx).await?;

        migration_tx.commit().await?;
        info!("Schema migration v2 → v3 complete.");
    }

    // v3 → v4: move flat condition columns into test_conditions table
    if version < 4 {
        info!("Running schema migration v3 → v4...");

        let mut migration_tx = pool.begin().await?;

        // Check column existence via pragma_table_info.
        // Read-only schema check — safe to run against the pool, not the tx.
        let has_flat_columns = column_exists(pool, "tests", "element_1").await;

        if has_flat_columns {
            info!("Migrating flat condition columns into test_conditions...");

            let test_rows = sqlx::query(
                "SELECT id, tenant_id,
                 element_1, input_1, selement_1, condition_1, sinput_1,
                 element_2, input_2, selement_2, condition_2, sinput_2,
                 element_3, input_3, selement_3, condition_3, sinput_3,
                 element_4, input_4, selement_4, condition_4, sinput_4,
                 element_5, input_5, selement_5, condition_5, sinput_5
                 FROM tests"
            )
            .fetch_all(&mut *migration_tx)
            .await?;

            for row in &test_rows {
                let test_id: i64    = row.get("id");
                let tenant_id: String = row.get("tenant_id");

                for (ecol, icol, scol, ccol, sicol) in [
                    ("element_1","input_1","selement_1","condition_1","sinput_1"),
                    ("element_2","input_2","selement_2","condition_2","sinput_2"),
                    ("element_3","input_3","selement_3","condition_3","sinput_3"),
                    ("element_4","input_4","selement_4","condition_4","sinput_4"),
                    ("element_5","input_5","selement_5","condition_5","sinput_5"),
                ] {
                    let element: Option<String> = row.try_get(ecol).ok().flatten();
                    let element = match element {
                        Some(e) if !e.is_empty() && e != "None" => e,
                        _ => continue,
                    };
                    let input: String = row.try_get(icol).ok().flatten().unwrap_or_default();
                    let selement: String = row.try_get(scol).ok().flatten()
                        .filter(|s: &String| !s.is_empty() && s != "None")
                        .unwrap_or_else(|| "None".to_string());
                    let condition: Option<String> = row.try_get(ccol).ok().flatten()
                        .filter(|s: &String| !s.is_empty() && s != "None");
                    let sinput: Option<String> = row.try_get(sicol).ok().flatten()
                        .filter(|s: &String| !s.is_empty());

                    sqlx::query(
                        "INSERT INTO test_conditions
                             (tenant_id, test_id, `type`, element, input, selement, condition, sinput)
                         VALUES (?, ?, 'condition', ?, ?, ?, ?, ?)"
                    )
                    .bind(&tenant_id)
                    .bind(test_id)
                    .bind(&element)
                    .bind(&input)
                    .bind(&selement)
                    .bind(condition)
                    .bind(sinput)
                    .execute(&mut *migration_tx)
                    .await?;
                }
            }

            for sql in [
                "ALTER TABLE tests DROP COLUMN element_1",
                "ALTER TABLE tests DROP COLUMN input_1",
                "ALTER TABLE tests DROP COLUMN selement_1",
                "ALTER TABLE tests DROP COLUMN condition_1",
                "ALTER TABLE tests DROP COLUMN sinput_1",
                "ALTER TABLE tests DROP COLUMN element_2",
                "ALTER TABLE tests DROP COLUMN input_2",
                "ALTER TABLE tests DROP COLUMN selement_2",
                "ALTER TABLE tests DROP COLUMN condition_2",
                "ALTER TABLE tests DROP COLUMN sinput_2",
                "ALTER TABLE tests DROP COLUMN element_3",
                "ALTER TABLE tests DROP COLUMN input_3",
                "ALTER TABLE tests DROP COLUMN selement_3",
                "ALTER TABLE tests DROP COLUMN condition_3",
                "ALTER TABLE tests DROP COLUMN sinput_3",
                "ALTER TABLE tests DROP COLUMN element_4",
                "ALTER TABLE tests DROP COLUMN input_4",
                "ALTER TABLE tests DROP COLUMN selement_4",
                "ALTER TABLE tests DROP COLUMN condition_4",
                "ALTER TABLE tests DROP COLUMN sinput_4",
                "ALTER TABLE tests DROP COLUMN element_5",
                "ALTER TABLE tests DROP COLUMN input_5",
                "ALTER TABLE tests DROP COLUMN selement_5",
                "ALTER TABLE tests DROP COLUMN condition_5",
                "ALTER TABLE tests DROP COLUMN sinput_5",
            ] {
                // Ignore error — column may have been dropped in a previous
                // partial run (the migration is designed to be re-entrant).
                let _ = sqlx::query(sql).execute(&mut *migration_tx).await;
            }
        }

        sqlx::query("UPDATE schema_info SET version = 4")
            .execute(&mut *migration_tx).await?;
        migration_tx.commit().await?;
        info!("Schema migration v3 → v4 complete.");
    }

    // v4 → v5: fix compliance_score DEFAULT 0.0 → -1.0 for unscanned rows
    if version < 5 {
        info!("Running schema migration v4 → v5 (fix unscanned compliance_score 0.0 → -1.0)...");

        let mut migration_tx = pool.begin().await?;

        sqlx::query(
            "UPDATE systems SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND total_tests = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results
                   WHERE results.system_id = systems.id
                     AND results.tenant_id = systems.tenant_id
               )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "UPDATE tests SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND systems_passed = 0
               AND systems_failed = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results
                   WHERE results.test_id  = tests.id
                     AND results.tenant_id = tests.tenant_id
               )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "UPDATE policies SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND systems_passed = 0
               AND systems_failed = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results r
                   JOIN tests_in_policy tip ON tip.test_id  = r.test_id
                     AND tip.tenant_id = r.tenant_id
                   WHERE tip.policy_id  = policies.id
                     AND r.tenant_id    = policies.tenant_id
               )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query("UPDATE schema_info SET version = 5")
            .execute(&mut *migration_tx).await?;
        migration_tx.commit().await?;
        info!("Schema migration v4 → v5 complete.");
    }

    // v5 → v6: add email_verified to users (default 1 — CE/EE users unaffected)
    if version < 6 {
        info!("Running schema migration v5 → v6 (email_verified)...");

        let _ = sqlx::query(
            "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"
        )
        .execute(pool)
        .await;

        sqlx::query("UPDATE schema_info SET version = 6")
            .execute(pool).await?;
        info!("Schema migration v5 → v6 complete.");
    }

    // v6 → v7: system_reports table + all composite indexes
    if version < 7 {
        info!("Running schema migration v6 → v7 (system_reports + indexes)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS system_reports (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id        VARCHAR(191) NOT NULL DEFAULT 'default',
                submission_date  DATETIME DEFAULT CURRENT_TIMESTAMP,
                system_id        INTEGER NOT NULL,
                system_name      TEXT    NOT NULL,
                submitter_name   TEXT,
                report_data      TEXT    NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )"
        )
        .execute(pool).await?;

        for idx in &[
            "CREATE INDEX IF NOT EXISTS idx_next_run ON policy_schedules (enabled, next_run)",
            "CREATE INDEX IF NOT EXISTS idx_results_tenant_test ON results (tenant_id, test_id)",
            "CREATE INDEX IF NOT EXISTS idx_test_conditions_tenant_test ON test_conditions (tenant_id, test_id)",
            "CREATE INDEX IF NOT EXISTS idx_systems_tenant_status ON systems (tenant_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_systems_tenant_score ON systems (tenant_id, compliance_score)",
            "CREATE INDEX IF NOT EXISTS idx_sig_tenant_group ON systems_in_groups (tenant_id, group_id)",
            "CREATE INDEX IF NOT EXISTS idx_sip_tenant_group ON systems_in_policy (tenant_id, group_id)",
            "CREATE INDEX IF NOT EXISTS idx_tip_tenant_test ON tests_in_policy (tenant_id, test_id)",
            "CREATE INDEX IF NOT EXISTS idx_compliance_history_tenant_date ON compliance_history (tenant_id, check_date)",
            "CREATE INDEX IF NOT EXISTS idx_notify_tenant_owner ON notify (tenant_id, owner_id)",
            "CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_active ON tenant_keys (tenant_id, is_active)",
            "CREATE INDEX IF NOT EXISTS idx_reports_tenant_date ON reports (tenant_id, submission_date)",
            "CREATE INDEX IF NOT EXISTS idx_system_reports_tenant_date ON system_reports (tenant_id, submission_date)",
        ] {
            sqlx::query(idx).execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 7")
            .execute(pool).await?;
        info!("Schema migration v6 → v7 complete.");
    }

    // v7 → v8: seed SMTP settings for all existing tenants
    if version < 8 {
        info!("Running schema migration v7 → v8 (SMTP settings)...");

        for sql in &[
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_host', '', 'SMTP relay hostname' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_port', '587', 'SMTP relay port' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_username', '', 'SMTP relay username' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_password', '', 'SMTP relay password' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_from', '', 'From address for outgoing emails' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_tls', 'starttls', 'TLS mode: starttls, tls, or none' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'app_url', '', 'Public URL of this installation (used in email links)' FROM tenants t",
        ] {
            sqlx::query(sql).execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 8")
            .execute(pool).await?;
        info!("Schema migration v7 → v8 complete.");
    }

    // v8 → v9: bootstrap admin role protection trigger (SQLite only)
    if version < 9 {
        info!("Running schema migration v8 → v9 (protect bootstrap admin role)...");

        // NEW.role != OLD.role guard — see initialize_database for rationale.
        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS protect_bootstrap_admin_role
       BEFORE UPDATE OF role ON users
       WHEN OLD.id = 1 AND OLD.tenant_id = 'default' AND NEW.role != OLD.role
       BEGIN
           SELECT RAISE(ABORT, 'The bootstrap admin role cannot be changed');
       END"
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 9")
            .execute(pool).await?;
        info!("Schema migration v8 → v9 complete.");
    }

    // v9 → v10: backfill columns and tables that belong in the base schema but
    // were missing from initialize_database on installs stamped at v9.
    //   • users.email_verified  — added for SaaS registration/login
    //   • tenants.status        — added for EE/SaaS tenant management
    //   • tenants.plan          — added for EE/SaaS plan enforcement
    //   • email_verifications   — SaaS registration tokens
    //   • password_resets       — SaaS password reset tokens
    //   • plan_limits           — SaaS per-plan resource caps
    if version < 10 {
        info!("Running schema migration v9 → v10 (unified base schema backfill)...");

        if !column_exists(pool, "users", "email_verified").await {
            let _ = sqlx::query(
                "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"
            ).execute(pool).await;
        }

        if !column_exists(pool, "tenants", "status").await {
            let _ = sqlx::query(
                "ALTER TABLE tenants ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
            ).execute(pool).await;
        }

        if !column_exists(pool, "tenants", "plan").await {
            let _ = sqlx::query(
                "ALTER TABLE tenants ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'"
            ).execute(pool).await;
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS email_verifications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                tenant_id  VARCHAR(191) NOT NULL,
                token      VARCHAR(191) NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                created_at TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )"
        ).execute(pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS password_resets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token      VARCHAR(191) NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )"
        ).execute(pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS plan_limits (
                plan      VARCHAR(191) NOT NULL,
                resource  VARCHAR(191) NOT NULL,
                max_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (plan, resource)
            )"
        ).execute(pool).await?;

        sqlx::query("UPDATE schema_info SET version = 10")
            .execute(pool).await?;
        info!("Schema migration v9 → v10 complete.");
    }

    // v10 → v11: rename MySQL/MariaDB reserved-word columns.
    //   test_conditions.type      → ctype      (TYPE is reserved in some MariaDB versions)
    //   test_conditions.condition → comparison  (CONDITION is reserved in MySQL/MariaDB)
    //   notify.type               → ntype
    //   notify.timestamp          → nts         (TIMESTAMP is a MySQL/MariaDB type keyword)
    // MySQL installs never had these old column names (the schema creation failed before
    // this fix), so on MySQL the column_exists checks return false and nothing is renamed.
    if version < 11 {
        info!("Running schema migration v10 → v11 (rename reserved-word columns)...");

        if column_exists(pool, "test_conditions", "type").await {
            let _ = sqlx::query(
                "ALTER TABLE test_conditions RENAME COLUMN \"type\" TO ctype",
            ).execute(pool).await;
        }
        if column_exists(pool, "test_conditions", "condition").await {
            let _ = sqlx::query(
                "ALTER TABLE test_conditions RENAME COLUMN \"condition\" TO comparison",
            ).execute(pool).await;
        }
        if column_exists(pool, "notify", "type").await {
            let _ = sqlx::query(
                "ALTER TABLE notify RENAME COLUMN \"type\" TO ntype",
            ).execute(pool).await;
        }
        if column_exists(pool, "notify", "timestamp").await {
            let _ = sqlx::query(
                "ALTER TABLE notify RENAME COLUMN \"timestamp\" TO nts",
            ).execute(pool).await;
        }

        sqlx::query("UPDATE schema_info SET version = 11")
            .execute(pool).await?;
        info!("Schema migration v10 → v11 complete.");
    }

    // v11 → v12: revert MySQL-era column renames in test_conditions now that
    // MySQL support is dropped. Restores "type" and "condition" so the JSON
    // wire format to the scmclient agent matches without serde rename shims.
    if version < 12 {
        info!("Running schema migration v11 → v12 (restore test_conditions column names)...");

        if column_exists(pool, "test_conditions", "ctype").await {
            let _ = sqlx::query(
                "ALTER TABLE test_conditions RENAME COLUMN ctype TO \"type\"",
            ).execute(pool).await;
        }
        if column_exists(pool, "test_conditions", "comparison").await {
            let _ = sqlx::query(
                "ALTER TABLE test_conditions RENAME COLUMN comparison TO condition",
            ).execute(pool).await;
        }

        sqlx::query("UPDATE schema_info SET version = 12")
            .execute(pool).await?;
        info!("Schema migration v11 → v12 complete.");
    }

    // v12 → v13: seed auto_prune_inactive for all existing tenants.
    if version < 13 {
        info!("Running schema migration v12 → v13 (seed auto_prune_inactive)...");
        sqlx::query(
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT id, 'auto_prune_inactive', '0',
                    'Minutes without activity before an inactive system is auto-deleted (0 = disabled)'
             FROM tenants",
        )
        .execute(pool).await?;
        sqlx::query("UPDATE schema_info SET version = 13")
            .execute(pool).await?;
        info!("Schema migration v12 → v13 complete.");
    }

    // v13 → v18 stamp is skipped on this code path (see initialize_database comment above)
    // so existing installs that were stamped at 13 by an older initialize_database will
    // run v14 through v18 here on their first upgrade.

    // v13 → v14: add policies.author + policies.external_id; backfill external_id for existing rows.
    // Wrapped in a transaction so the ALTER ADD COLUMN + per-row backfill +
    // version stamp all land on one connection (and one atomic commit) — the
    // backfill UPDATE references the column the ALTER just added, which is
    // exactly the cross-connection-schema-visibility shape the v16→v17 fix
    // also addresses. See the convention block at the top of this function.
    if version < 14 {
        info!("Running schema migration v13 → v14 (policies.author, policies.external_id)...");
        // column_exists reads through &pool which is fine — it doesn't depend on
        // the in-flight transaction's schema state and runs before tx open.
        let need_author      = !column_exists(pool, "policies", "author").await;
        let need_external_id = !column_exists(pool, "policies", "external_id").await;

        let mut tx = pool.begin().await?;
        if need_author {
            sqlx::query("ALTER TABLE policies ADD COLUMN author TEXT")
                .execute(&mut *tx).await?;
        }
        if need_external_id {
            sqlx::query("ALTER TABLE policies ADD COLUMN external_id TEXT")
                .execute(&mut *tx).await?;
        }
        // Backfill external_id for existing policies that don't have one.
        let rows = sqlx::query("SELECT id FROM policies WHERE external_id IS NULL OR external_id = ''")
            .fetch_all(&mut *tx).await?;
        for row in rows {
            let id: i64 = row.get("id");
            sqlx::query("UPDATE policies SET external_id = ? WHERE id = ?")
                .bind(generate_external_id())
                .bind(id)
                .execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE schema_info SET version = 14")
            .execute(&mut *tx).await?;
        tx.commit().await?;
        info!("Schema migration v13 → v14 complete.");
    }

    // v14 → v15: add tests.external_id; backfill external_id for existing rows.
    // Wrapped in a transaction for the same reason as v13→v14.
    if version < 15 {
        info!("Running schema migration v14 → v15 (tests.external_id)...");
        let need_external_id = !column_exists(pool, "tests", "external_id").await;

        let mut tx = pool.begin().await?;
        if need_external_id {
            sqlx::query("ALTER TABLE tests ADD COLUMN external_id TEXT")
                .execute(&mut *tx).await?;
        }
        let rows = sqlx::query("SELECT id FROM tests WHERE external_id IS NULL OR external_id = ''")
            .fetch_all(&mut *tx).await?;
        for row in rows {
            let id: i64 = row.get("id");
            sqlx::query("UPDATE tests SET external_id = ? WHERE id = ?")
                .bind(generate_external_id())
                .bind(id)
                .execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE schema_info SET version = 15")
            .execute(&mut *tx).await?;
        tx.commit().await?;
        info!("Schema migration v14 → v15 complete.");
    }

    // v15 → v16: convert every tenant's offline_threshold from seconds to minutes.
    // Before this migration the setting was stored as seconds (default 3600); from
    // here it is stored as minutes (default 60) so it lines up with the
    // auto_prune_inactive setting, which was always minutes. We round to whole
    // minutes by integer division and clamp anything below 1 minute back up to 1
    // so the column never lands on zero.
    if version < 16 {
        info!("Running schema migration v15 → v16 (offline_threshold seconds → minutes)...");
        sqlx::query(
            "UPDATE settings
                SET value = CASE
                    WHEN CAST(value AS INTEGER) / 60 < 1 THEN '1'
                    ELSE CAST(CAST(value AS INTEGER) / 60 AS TEXT)
                END,
                description = 'Minutes without activity before system is marked offline'
              WHERE skey = 'offline_threshold'",
        )
        .execute(pool).await?;
        sqlx::query("UPDATE schema_info SET version = 16")
            .execute(pool).await?;
        info!("Schema migration v15 → v16 complete.");
    }

    // v16 → v17: rebuild the bootstrap-admin role-protection trigger so it
    // only fires when NEW.role actually differs from OLD.role. The v9
    // version of the trigger fired on any UPDATE that mentioned `role` in
    // its SET clause, which broke routine name/email edits of the bootstrap
    // admin: the handler always re-passes the current role to keep the SQL
    // shape uniform, and the trigger then aborted with "The bootstrap admin
    // role cannot be changed" even though no role was actually changing.
    // Drop + recreate is safe — both versions cover exactly the same case
    // (genuine role mutations of users.id=1 in the default tenant).
    if version < 17 {
        info!("Running schema migration v16 → v17 (rebuild bootstrap-admin trigger)...");
        // Pin to a single connection so the DROP and CREATE land on the same
        // SQLite session — running them through `pool` would let sqlx grab
        // different pooled connections, and the second one's prepared-
        // statement cache could still see the old trigger and fail the
        // CREATE with "trigger ... already exists" even though the DROP had
        // succeeded on the first connection.
        let mut conn = pool.acquire().await?;
        sqlx::query("DROP TRIGGER IF EXISTS protect_bootstrap_admin_role")
            .execute(&mut *conn).await?;
        sqlx::query(
            "CREATE TRIGGER protect_bootstrap_admin_role
       BEFORE UPDATE OF role ON users
       WHEN OLD.id = 1 AND OLD.tenant_id = 'default' AND NEW.role != OLD.role
       BEGIN
           SELECT RAISE(ABORT, 'The bootstrap admin role cannot be changed');
       END"
        )
        .execute(&mut *conn).await?;
        sqlx::query("UPDATE schema_info SET version = 17")
            .execute(&mut *conn).await?;
        info!("Schema migration v16 → v17 complete.");
    }

    // v17 → v18: agent auto-upgrade support.
    //   • agent_packages table       — one row per client platform; upserted on startup.
    //   • commands.command_type      — extends the existing test-dispatch queue to also
    //                                  carry UPGRADE rows (test_id = NULL for those).
    //   • idx_cmd_upgrade_uniq       — partial unique index so each system can have at
    //                                  most one queued UPGRADE row.
    if version < 18 {
        info!("Running schema migration v17 → v18 (agent_packages + commands.command_type)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS agent_packages (
                platform   TEXT PRIMARY KEY,
                version    TEXT NOT NULL,
                sha256     TEXT NOT NULL,
                url        TEXT NOT NULL,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(pool)
        .await?;

        if !column_exists(pool, "commands", "command_type").await {
            sqlx::query(
                "ALTER TABLE commands ADD COLUMN command_type TEXT NOT NULL DEFAULT 'TEST'",
            )
            .execute(pool)
            .await?;
        }

        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_cmd_upgrade_uniq
                ON commands(tenant_id, system_id) WHERE command_type = 'UPGRADE'",
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 18")
            .execute(pool)
            .await?;
        info!("Schema migration v17 → v18 complete.");
    }

    // v18 → v19: per-finding exclusions.
    //   • results.excluded / excluded_by / excluded_at — Editor-set suppression
    //     of a (system, test) result; treated as NA in scoring. The heartbeat
    //     UPSERT only touches `result` + `last_updated`, so re-running tests
    //     never clears the flag — it sticks until the system or test is deleted.
    if version < 19 {
        info!("Running schema migration v18 → v19 (results.excluded)...");

        if !column_exists(pool, "results", "excluded").await {
            sqlx::query("ALTER TABLE results ADD COLUMN excluded INTEGER NOT NULL DEFAULT 0")
                .execute(pool)
                .await?;
        }
        if !column_exists(pool, "results", "excluded_by").await {
            sqlx::query("ALTER TABLE results ADD COLUMN excluded_by TEXT")
                .execute(pool)
                .await?;
        }
        if !column_exists(pool, "results", "excluded_at").await {
            sqlx::query("ALTER TABLE results ADD COLUMN excluded_at DATETIME")
                .execute(pool)
                .await?;
        }

        sqlx::query("UPDATE schema_info SET version = 19")
            .execute(pool)
            .await?;
        info!("Schema migration v18 → v19 complete.");
    }

    // v19 → v20: audit log table + retention setting.
    //   • audit_log table — written by crate::audit::record() from every
    //     state-changing handler; read by the Admin → Audit Log viewer.
    //   • settings.audit_log_retention_days — number of days to keep rows
    //     (0 = forever). The background cleanup tick that consumes this
    //     value will land with Task #9 (retention/cleanup policy).
    if version < 20 {
        info!("Running schema migration v19 → v20 (audit_log + retention setting)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id       VARCHAR(191) NOT NULL DEFAULT 'default',
                actor_user_id   INTEGER,
                actor_username  TEXT NOT NULL,
                action          TEXT NOT NULL,
                target_type     TEXT,
                target_id       TEXT,
                details         TEXT,
                ip_address      TEXT,
                created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
                ON audit_log(tenant_id, created_at DESC)",
        )
        .execute(pool)
        .await?;

        // Seed the retention setting for every existing tenant. INSERT OR IGNORE
        // means re-running this migration on a partially-populated DB is safe.
        sqlx::query(
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT id, 'audit_log_retention_days', '730',
                    'Days to keep audit_log rows before auto-pruning (0 = keep forever)'
             FROM tenants",
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 20")
            .execute(pool)
            .await?;
        info!("Schema migration v19 → v20 complete.");
    }

    // v20 → v21: add POWERSHELL element and EXIT CODE selement to lookup tables.
    if version < 21 {
        info!("Running schema migration v20 → v21 (POWERSHELL element + EXIT CODE selement)...");

        sqlx::query("INSERT OR IGNORE INTO elements (name) VALUES ('POWERSHELL')")
            .execute(pool)
            .await?;

        sqlx::query("INSERT OR IGNORE INTO selements (name) VALUES ('EXIT CODE')")
            .execute(pool)
            .await?;

        sqlx::query("UPDATE schema_info SET version = 21")
            .execute(pool)
            .await?;
        info!("Schema migration v20 → v21 complete.");
    }

    // v21 → v22: add live telemetry columns to systems table.
    if version < 22 {
        info!("Running schema migration v21 → v22 (live telemetry columns)...");

        for col in &[
            "cpu_usage    REAL",
            "mem_used_mb  INTEGER",
            "mem_total_mb INTEGER",
            "disk_used_gb  INTEGER",
            "disk_total_gb INTEGER",
            "uptime_secs  INTEGER",
        ] {
            if !column_exists(pool, "systems", col.split_whitespace().next().unwrap_or("")).await {
                sqlx::query(&format!("ALTER TABLE systems ADD COLUMN {}", col))
                    .execute(pool)
                    .await?;
            }
        }

        sqlx::query("UPDATE schema_info SET version = 22")
            .execute(pool)
            .await?;
        info!("Schema migration v21 → v22 complete.");
    }

    // v22 → v23: add retention settings for reports and notifications.
    if version < 23 {
        info!("Running schema migration v22 → v23 (report + notification retention)...");

        sqlx::query(
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description) VALUES
            ('default', 'report_retention_days', '0',
                'Days to keep saved policy/system report snapshots before auto-pruning (0 = keep forever)'),
            ('default', 'notification_retention_days', '30',
                'Days to keep bell-icon notifications before auto-pruning (0 = keep forever)')",
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 23")
            .execute(pool)
            .await?;
        info!("Schema migration v22 → v23 complete.");
    }

    // v23 → v24: add SERVICE element and COUNT/ACTIVE/INACTIVE/ENABLED/DISABLED selements.
    if version < 24 {
        info!("Running schema migration v23 → v24 (SERVICE element + new selements)...");

        sqlx::query("INSERT OR IGNORE INTO elements (name) VALUES ('SERVICE')")
            .execute(pool)
            .await?;

        for name in &["COUNT", "ACTIVE", "INACTIVE", "ENABLED", "DISABLED"] {
            sqlx::query("INSERT OR IGNORE INTO selements (name) VALUES (?)")
                .bind(name)
                .execute(pool)
                .await?;
        }

        sqlx::query("UPDATE schema_info SET version = 24")
            .execute(pool)
            .await?;
        info!("Schema migration v23 → v24 complete.");
    }

    // v24 → v25: LDAP directory support.
    //   - new `directories` table for configured LDAP servers per tenant
    //   - `users.directory_id` (NULL = local user) + `users.external_username`
    if version < 25 {
        info!("Running schema migration v24 → v25 (LDAP directories)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS directories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
                name TEXT NOT NULL,
                dir_type TEXT NOT NULL DEFAULT 'ldap',
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                use_tls INTEGER NOT NULL DEFAULT 0,
                skip_tls_verify INTEGER NOT NULL DEFAULT 0,
                base_dn TEXT NOT NULL,
                bind_dn TEXT NOT NULL DEFAULT '',
                bind_password TEXT NOT NULL DEFAULT '',
                user_attribute TEXT NOT NULL DEFAULT 'uid',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )"
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_directories_tenant ON directories (tenant_id)")
            .execute(pool)
            .await?;

        if !column_exists(pool, "users", "directory_id").await {
            sqlx::query("ALTER TABLE users ADD COLUMN directory_id INTEGER")
                .execute(pool)
                .await?;
        }
        if !column_exists(pool, "users", "external_username").await {
            sqlx::query("ALTER TABLE users ADD COLUMN external_username TEXT")
                .execute(pool)
                .await?;
        }

        sqlx::query("UPDATE schema_info SET version = 25")
            .execute(pool)
            .await?;
        info!("Schema migration v24 → v25 complete.");
    }

    // v25 → v26: container support groundwork.
    //   - new `containers` table (per-host inventory of running app containers)
    //   - widen `results` primary key with `container_id` (0 for host results,
    //     resolved containers.id for per-container results)
    //   - seed CONTAINER, IMAGE, NETWORK elements + their sub-elements
    //   - new per-tenant `container_retention_days` setting (default 7)
    //
    // No code reads or writes these yet — this is structural groundwork the
    // agent/server/UI work in later steps will build on.
    if version < 26 {
        info!("Running schema migration v25 → v26 (container groundwork)...");

        // Recovery for databases left half-migrated by 0.9.3 and earlier (see
        // run_migrations): the copy into results_new had completed and
        // `results` had been dropped, but the rename failed. The data is in
        // results_new; put it back under its real name and let the rebuild
        // below run normally.
        if !table_exists(pool, "results").await && table_exists(pool, "results_new").await {
            warn!("Recovering from an interrupted v25 → v26 migration: restoring results from results_new");
            sqlx::query("ALTER TABLE results_new RENAME TO results").execute(pool).await?;
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS containers (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id       VARCHAR(191) NOT NULL DEFAULT 'default',
                host_system_id  INTEGER NOT NULL,
                runtime         TEXT NOT NULL,
                runtime_id      TEXT NOT NULL,
                name            TEXT NOT NULL,
                image           TEXT,
                image_digest    TEXT,
                status          TEXT,
                ip              TEXT,
                is_privileged   INTEGER,
                run_user        TEXT,
                network_mode    TEXT,
                exposed_ports   TEXT,
                mounts          TEXT,
                capabilities_add TEXT,
                read_only_fs    INTEGER,
                restart_policy  TEXT,
                health_check    INTEGER,
                first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host_system_id, runtime, name),
                FOREIGN KEY (host_system_id) REFERENCES systems(id) ON DELETE CASCADE
            )"
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_containers_host  ON containers(host_system_id)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_containers_image ON containers(image)")
            .execute(pool).await?;

        // Rebuild `results` with a widened primary key that includes
        // `container_id` so per-container results can coexist with host
        // results. SQLite can't ALTER PRIMARY KEY in place, so we copy
        // into a fresh table and rename. `container_id` defaults to 0 for
        // host results (NULL would break the PK uniqueness).
        if !column_exists(pool, "results", "container_id").await {
            // Brand-new column path — used when the v25→v26 migration runs
            // for the first time. ADD COLUMN first so the SELECT below works,
            // then rebuild the table to widen the PK.
            sqlx::query("ALTER TABLE results ADD COLUMN container_id INTEGER")
                .execute(pool)
                .await?;
        }
        // Always rebuild the table — covers both the fresh-column case above
        // and any earlier-tester case where the column already exists but is
        // still nullable / not part of the PK.
        sqlx::query("PRAGMA foreign_keys = OFF").execute(pool).await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS results_new (
                tenant_id    VARCHAR(191) NOT NULL DEFAULT 'default',
                system_id    INTEGER,
                test_id      INTEGER,
                result       TEXT,
                last_updated TEXT,
                excluded     INTEGER NOT NULL DEFAULT 0,
                excluded_by  TEXT,
                excluded_at  DATETIME,
                container_id INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, system_id, test_id, container_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
                FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
                FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
            )"
        ).execute(pool).await?;
        sqlx::query(
            "INSERT INTO results_new
              (tenant_id, system_id, test_id, result, last_updated,
               excluded, excluded_by, excluded_at, container_id)
             SELECT tenant_id, system_id, test_id, result, last_updated,
                    excluded, excluded_by, excluded_at,
                    COALESCE(container_id, 0)
             FROM results"
        ).execute(pool).await?;
        sqlx::query("DROP TABLE results").execute(pool).await?;
        sqlx::query("ALTER TABLE results_new RENAME TO results").execute(pool).await?;
        sqlx::query("PRAGMA foreign_keys = ON").execute(pool).await?;

        // Container-related elements — all agent-side, evaluated locally
        // by the client against its discovered container inventory.
        //   CONTAINER     — host-level "is a runtime installed" (EXISTS/NOT EXISTS)
        //   IMAGE         — per-container image identity (NAME/TAG/DIGEST/SOURCE)
        //   NETWORK       — per-container network configuration (MODE)
        //   PRIVILEGED    — per-container --privileged flag (EXISTS/NOT EXISTS)
        //   RUN_USER      — per-container running user (CONTENT)
        //   MOUNT         — per-container bind mount source path (EXISTS/NOT EXISTS)
        //   EXPOSED_PORT  — per-container published port (EXISTS/NOT EXISTS/COUNT)
        //   READ_ONLY_FS  — per-container --read-only flag (EXISTS/NOT EXISTS)
        //   HEALTH_CHECK  — per-container HEALTHCHECK defined (EXISTS/NOT EXISTS)
        for name in &[
            "CONTAINER", "IMAGE", "NETWORK", "PRIVILEGED", "RUN_USER",
            "MOUNT", "EXPOSED_PORT", "READ_ONLY_FS", "HEALTH_CHECK", "EXEC",
        ] {
            sqlx::query("INSERT OR IGNORE INTO elements (name) VALUES (?)")
                .bind(name)
                .execute(pool)
                .await?;
        }

        // Sub-elements: NAME/TAG/DIGEST/REGISTRY for IMAGE; MODE for NETWORK.
        // EQUALS / NOT EQUALS / CONTAINS already exist as conditions.
        for name in &["NAME", "TAG", "DIGEST", "SOURCE", "MODE"] {
            sqlx::query("INSERT OR IGNORE INTO selements (name) VALUES (?)")
                .bind(name)
                .execute(pool)
                .await?;
        }

        // Per-tenant retention setting (default 7 days). 0 = keep forever.
        sqlx::query(
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             VALUES ('default', 'container_retention_days', '7',
                     'Days to keep container inventory rows after last_seen before auto-pruning (0 = keep forever)')"
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 26")
            .execute(pool)
            .await?;
        info!("Schema migration v25 → v26 complete.");
    }

    // v26 → v27: catch-up migration for deployments that landed at v26
    // during early 0.5.0 dev before the in-place edits to the v26 block
    // settled. Idempotent on fresh installs — the seeds are INSERT OR
    // IGNORE and the results-table rebuild is gated on "PK does not
    // include container_id". A clean v26 install passes both checks
    // without touching anything; a stale v26 install gains whatever
    // was added to the v26 block after it ran the first time.
    if version < 27 {
        info!("Running schema migration v26 → v27 (catch-up: container elements + results PK)...");

        // 1. Re-seed every container-related element. Stale v26 installs
        //    may be missing CONTAINER + the six metadata elements added
        //    after IMAGE / NETWORK shipped.
        for name in &[
            "CONTAINER", "IMAGE", "NETWORK", "PRIVILEGED", "RUN_USER",
            "MOUNT", "EXPOSED_PORT", "READ_ONLY_FS", "HEALTH_CHECK",
        ] {
            sqlx::query("INSERT OR IGNORE INTO elements (name) VALUES (?)")
                .bind(name).execute(pool).await?;
        }

        // 2. Make sure `results` exists with the new shape. Defensive against
        //    every state we've seen in the wild during 0.5.0 dev:
        //      (a) results exists with old 3-col PK  — common stale case
        //      (b) results exists with new 4-col PK  — clean v26 install (no-op)
        //      (c) results missing; results_new left over   — prior v26 attempt
        //                                                     died after DROP results
        //      (d) results missing; results_v27_backup left — prior v27 attempt
        //                                                     died after DROP results
        //      (e) results missing entirely                  — DB inconsistent
        let results_sql: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='results'"
        )
        .fetch_optional(pool).await
        .ok().flatten().flatten();
        let already_widened = results_sql.as_deref()
            .map(|sql| sql.to_lowercase().contains("primary key (tenant_id, system_id, test_id, container_id)"))
            .unwrap_or(false);

        if !already_widened {
            info!("Rebuilding results table with widened primary key");

            sqlx::query("PRAGMA foreign_keys = OFF").execute(pool).await?;

            // Pick whichever table actually holds our data right now. Order
            // of preference reflects which is most likely to be the freshest
            // snapshot if multiple exist.
            let source: Option<&str> =
                if table_exists(pool, "results").await { Some("results") }
                else if table_exists(pool, "results_v27_backup").await { Some("results_v27_backup") }
                else if table_exists(pool, "results_new").await { Some("results_new") }
                else { None };

            // Stage data (if any) into a transient holding table.
            sqlx::query("DROP TABLE IF EXISTS _results_staging").execute(pool).await?;
            if let Some(src) = source {
                let has_cid = column_exists(pool, src, "container_id").await;
                let cid_expr = if has_cid { "COALESCE(container_id, 0)" } else { "0" };
                let stage_sql = format!(
                    "CREATE TABLE _results_staging AS
                     SELECT tenant_id, system_id, test_id, result, last_updated,
                            excluded, excluded_by, excluded_at,
                            {} AS container_id
                     FROM {}", cid_expr, src
                );
                sqlx::query(&stage_sql).execute(pool).await?;
            }

            // Clean every table name we might collide with.
            sqlx::query("DROP TABLE IF EXISTS results").execute(pool).await?;
            sqlx::query("DROP TABLE IF EXISTS results_new").execute(pool).await?;
            sqlx::query("DROP TABLE IF EXISTS results_v27_backup").execute(pool).await?;

            // Recreate the canonical table with the new shape.
            sqlx::query(
                "CREATE TABLE results (
                    tenant_id    VARCHAR(191) NOT NULL DEFAULT 'default',
                    system_id    INTEGER,
                    test_id      INTEGER,
                    result       TEXT,
                    last_updated TEXT,
                    excluded     INTEGER NOT NULL DEFAULT 0,
                    excluded_by  TEXT,
                    excluded_at  DATETIME,
                    container_id INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (tenant_id, system_id, test_id, container_id),
                    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
                    FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
                    FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
                )"
            ).execute(pool).await?;

            // Restore from staging if we had any data to preserve.
            if source.is_some() {
                sqlx::query(
                    "INSERT INTO results
                       (tenant_id, system_id, test_id, result, last_updated,
                        excluded, excluded_by, excluded_at, container_id)
                     SELECT tenant_id, system_id, test_id, result, last_updated,
                            excluded, excluded_by, excluded_at, container_id
                     FROM _results_staging"
                ).execute(pool).await?;
                sqlx::query("DROP TABLE _results_staging").execute(pool).await?;
            }

            sqlx::query("PRAGMA foreign_keys = ON").execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 27")
            .execute(pool)
            .await?;
        info!("Schema migration v26 → v27 complete.");
    }

    // v27 → v28: automatic group assignment.
    //
    //   • system_groups.auto_managed  — group type (0 = manual, 1 = auto)
    //   • systems.compliance_dirty    — set when a system's auto-group
    //                                   membership changed and its current
    //                                   compliance needs a recalc on the
    //                                   next scheduler tick.
    //   • auto_group_rules            — one rule per auto group, UNIQUE(group_id).
    //
    // All three columns/tables are nullable-safe and back-compat: existing
    // groups stay auto_managed = 0 (manual), existing systems stay
    // compliance_dirty = 0, and no auto_group_rules rows exist until an
    // admin creates an auto group.
    if version < 28 {
        info!("Running schema migration v27 → v28 (automatic group assignment)...");

        if !column_exists(pool, "system_groups", "auto_managed").await {
            sqlx::query(
                "ALTER TABLE system_groups
                    ADD COLUMN auto_managed INTEGER NOT NULL DEFAULT 0"
            ).execute(pool).await?;
        }

        if !column_exists(pool, "systems", "compliance_dirty").await {
            sqlx::query(
                "ALTER TABLE systems
                    ADD COLUMN compliance_dirty INTEGER NOT NULL DEFAULT 0"
            ).execute(pool).await?;
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS auto_group_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
                group_id INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                conditions TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
            )"
        ).execute(pool).await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_agr_tenant_enabled
                ON auto_group_rules (tenant_id, enabled)"
        ).execute(pool).await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_systems_compliance_dirty
                ON systems (tenant_id, compliance_dirty)
                WHERE compliance_dirty = 1"
        ).execute(pool).await?;

        sqlx::query("UPDATE schema_info SET version = 28")
            .execute(pool)
            .await?;
        info!("Schema migration v27 → v28 complete.");
    }

    // v28 → v29: auto-group reconciliation fingerprint.
    //
    //   • systems.auto_group_fp — SHA-256 (hex) of the rule-relevant fields
    //     of the system at the time apply_auto_groups last evaluated it.
    //     The heartbeat path compares the freshly-computed fingerprint
    //     against this column and skips rule evaluation + the membership
    //     query entirely when nothing rule-relevant changed since the last
    //     heartbeat.  NULL until first evaluation; the full-tenant sweep
    //     (rule create/edit/toggle) always re-evaluates and re-stamps it.
    //
    // Back-compat: NULL default means every system is treated as "changed"
    // on its first post-upgrade heartbeat, so memberships are reconciled
    // exactly once and the fingerprint is populated from then on.
    if version < 29 {
        info!("Running schema migration v28 → v29 (auto-group fingerprint)...");

        if !column_exists(pool, "systems", "auto_group_fp").await {
            sqlx::query(
                "ALTER TABLE systems ADD COLUMN auto_group_fp TEXT"
            ).execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 29")
            .execute(pool)
            .await?;
        info!("Schema migration v28 → v29 complete.");
    }

    // v29 → v30: performance indexes surfaced by slow-statement logging.
    //
    //   • idx_results_recalc_cover — covering index for the compliance-recalc
    //     correlated subqueries (update_test_stats). The COUNT(*) per test now
    //     scans the index instead of fetching rows.
    //   • idx_systems_prune — supports the sargable auto-prune sweep
    //     (last_seen < cutoff), which runs every 60s. Turns a full scan of a
    //     tenant's active systems into a range scan.
    //
    // Pure index additions — no data change, fully idempotent.
    if version < 30 {
        info!("Running schema migration v29 → v30 (performance indexes)...");

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_results_recalc_cover
                ON results (tenant_id, test_id, result, excluded, system_id)"
        ).execute(pool).await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_systems_prune
                ON systems (tenant_id, status, last_seen)"
        ).execute(pool).await?;

        sqlx::query("UPDATE schema_info SET version = 30")
            .execute(pool)
            .await?;
        info!("Schema migration v29 → v30 complete.");
    }

    // v30 → v31: golden enrollment tokens.
    //
    //   • enrollment_tokens — admin-minted tokens that auto-approve enrolling
    //     systems (status active instead of pending). Approval bypass only,
    //     not auth bypass. Secret stored as SHA-256 hash. See
    //     docs/design/0.6.0-enrollment-tokens.md.
    //
    // New table only — fully back-compat (no tokens exist until an admin
    // mints one, so enrollment behaviour is unchanged until then).
    if version < 31 {
        info!("Running schema migration v30 → v31 (enrollment tokens)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS enrollment_tokens (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id    VARCHAR(191) NOT NULL DEFAULT 'default',
                name         TEXT NOT NULL,
                token_hash   TEXT NOT NULL,
                token_prefix TEXT,
                enabled      INTEGER NOT NULL DEFAULT 1,
                expires_at   DATETIME,
                max_uses     INTEGER,
                use_count    INTEGER NOT NULL DEFAULT 0,
                created_by   TEXT,
                created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )"
        ).execute(pool).await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_lookup
                ON enrollment_tokens (tenant_id, enabled)"
        ).execute(pool).await?;

        sqlx::query("UPDATE schema_info SET version = 31")
            .execute(pool)
            .await?;
        info!("Schema migration v30 → v31 complete.");
    }

    // v31 → v32: per-result evidence.
    //
    //   • results.evidence — JSON array of per-condition outcomes (which
    //     conditions matched / failed + a generic, content-free note)
    //     explaining a test verdict. Written by the result handler from the
    //     agent's payload; NULL for results from pre-0.6.4 agents. See the
    //     0.6.4 evidence feature.
    //
    // New nullable column only — back-compat (old agents simply don't send
    // evidence, so the column stays NULL and reports show no detail panel).
    if version < 32 {
        info!("Running schema migration v31 → v32 (result evidence)...");

        if !column_exists(pool, "results", "evidence").await {
            sqlx::query("ALTER TABLE results ADD COLUMN evidence TEXT")
                .execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 32")
            .execute(pool)
            .await?;
        info!("Schema migration v31 → v32 complete.");
    }

    // v32 → v33: dual-mode compliance scores.
    //
    // Both the per-test and per-(system|policy) score are now stored for every
    // policy, system, and history snapshot, so the Per-test / Per-system /
    // Per-policy toggles switch instantly AND the trend chart re-renders the
    // WHOLE history in the chosen mode (no artificial jump at the switch).
    //   • policies.score_test / score_system
    //   • systems.score_test  / score_policy
    //   • compliance_history.{systems,policies}_score_{test,system|policy}
    // All nullable-safe with -1.0 / 0.0 defaults; populated on the next recalc.
    if version < 33 {
        info!("Running schema migration v32 → v33 (dual-mode compliance scores)...");

        for (table, col) in &[
            ("policies", "score_test"),    ("policies", "score_system"),
            ("systems",  "score_test"),    ("systems",  "score_policy"),
        ] {
            if !column_exists(pool, table, col).await {
                sqlx::query(&format!("ALTER TABLE {} ADD COLUMN {} REAL DEFAULT -1.0", table, col))
                    .execute(pool).await?;
            }
        }
        for col in &[
            "systems_score_test", "systems_score_policy",
            "policies_score_test", "policies_score_system",
        ] {
            if !column_exists(pool, "compliance_history", col).await {
                sqlx::query(&format!("ALTER TABLE compliance_history ADD COLUMN {} REAL DEFAULT 0.0", col))
                    .execute(pool).await?;
            }
        }

        sqlx::query("UPDATE schema_info SET version = 33")
            .execute(pool)
            .await?;
        info!("Schema migration v32 → v33 complete.");
    }

    // v33 → v34: backfill dual-mode history columns.
    //
    // v33 added the per-mode history columns with DEFAULT 0.0 but did NOT
    // backfill them, so every snapshot recorded BEFORE the upgrade reads 0 in
    // the new columns — collapsing the trend chart to a flat-zero line (the
    // real values still live in the legacy systems_score / policies_score).
    // Copy the recorded value into BOTH new mode-columns, but ONLY for those
    // pre-upgrade rows (new col still at its 0 default AND legacy col > 0), so
    // genuine post-upgrade snapshots are never clobbered. Idempotent: once
    // filled the WHERE clause no longer matches.
    if version < 34 {
        info!("Running schema migration v33 → v34 (backfill dual-mode history)...");

        sqlx::query(
            "UPDATE compliance_history
             SET systems_score_test = systems_score,
                 systems_score_policy = systems_score
             WHERE systems_score > 0
               AND systems_score_test = 0
               AND systems_score_policy = 0",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "UPDATE compliance_history
             SET policies_score_test = policies_score,
                 policies_score_system = policies_score
             WHERE policies_score > 0
               AND policies_score_test = 0
               AND policies_score_system = 0",
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 34")
            .execute(pool)
            .await?;
        info!("Schema migration v33 → v34 complete.");
    }

    // v34 → v35: per-container compliance axis.
    //
    // Containers now carry their own compliance score, computed from results
    // whose container_id points at the row (the host axis uses container_id = 0).
    // Keeping container compliance on a separate axis stops per-container results
    // from distorting host/system/policy scores (design §11). Columns are
    // populated by update_container_stats on the next recalc after upgrade.
    if version < 35 {
        info!("Running schema migration v34 → v35 (per-container compliance axis)...");

        for (col, decl) in &[
            ("tests_passed",     "INTEGER DEFAULT 0"),
            ("tests_failed",     "INTEGER DEFAULT 0"),
            ("compliance_score", "REAL DEFAULT -1.0"),
        ] {
            if !column_exists(pool, "containers", col).await {
                sqlx::query(&format!("ALTER TABLE containers ADD COLUMN {} {}", col, decl))
                    .execute(pool).await?;
            }
        }
        // Container-axis aggregate for a policy — the report/list headline falls
        // back to this when the host axis is "Not Scanned" (pure-container policy).
        if !column_exists(pool, "policies", "score_container").await {
            sqlx::query("ALTER TABLE policies ADD COLUMN score_container REAL DEFAULT -1.0")
                .execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 35")
            .execute(pool)
            .await?;
        info!("Schema migration v34 → v35 complete.");
    }

    // v35 → v36: seed the EXEC container element.
    //
    // EXEC runs a command inside each container via `<runtime> exec` — the
    // container-side counterpart to the host-only CMD element. Existing DBs
    // need it added to the elements table so it appears in the test editor.
    // Also drops the unused `tests.target_type` column if present: an earlier
    // 0.7.0 design used that column before it was replaced by EXEC; the drop
    // is harmless (and a no-op) on databases that never had it.
    if version < 36 {
        info!("Running schema migration v35 → v36 (seed EXEC element)...");

        sqlx::query("INSERT OR IGNORE INTO elements (name) VALUES ('EXEC')")
            .execute(pool).await?;

        if column_exists(pool, "tests", "target_type").await {
            // DROP COLUMN needs SQLite ≥ 3.35; non-fatal if the runtime is older
            // — the unused column is harmless, so don't block startup over it.
            if let Err(e) = sqlx::query("ALTER TABLE tests DROP COLUMN target_type")
                .execute(pool).await
            {
                info!("Could not drop unused tests.target_type (harmless, leaving it): {}", e);
            }
        }

        sqlx::query("UPDATE schema_info SET version = 36")
            .execute(pool)
            .await?;
        info!("Schema migration v35 → v36 complete.");
    }

    // v36 → v37: per-entity compliance trend history (0.7.2).
    //
    // Hourly snapshots per system and per policy (both compliance axes per
    // row — see the fresh-install CREATE for column semantics), powering the
    // trend charts on the live report pages. Also seeds the two trend
    // retention settings; fleet_trend_retention_days brings the existing
    // compliance_history table under retention for the first time (was
    // keep-forever; set 0 to restore that).
    if version < 37 {
        info!("Running schema migration v36 → v37 (entity compliance trends)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS entity_compliance_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                check_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                score_test REAL,
                score_strict REAL,
                tests_passed INTEGER,
                tests_failed INTEGER,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_entity_history_lookup
             ON entity_compliance_history (tenant_id, entity_type, entity_id, check_date)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description) VALUES
            ('default', 'entity_trend_retention_days', '90', 'Days to keep per-system/per-policy trend snapshots before auto-pruning (0 = keep forever)'),
            ('default', 'fleet_trend_retention_days', '365', 'Days to keep fleet-wide compliance trend snapshots before auto-pruning (0 = keep forever)')"
        )
        .execute(pool)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 37")
            .execute(pool)
            .await?;
        info!("Schema migration v36 → v37 complete.");
    }

    // v37 → v38: guided first-run tour (0.8.0).
    //
    // users.tour_done drives the five-screen walkthrough on the dashboard.
    //
    // Both statements sit INSIDE the column_exists guard, and that is the
    // whole subtlety of this migration. A fresh install already carries the
    // column from initialize_database's CREATE TABLE (defaulting to 0), so the
    // guard is false and neither statement runs — which matters because
    // install.rs creates the first admin BEFORE calling run_migrations, so an
    // unguarded backfill would mark the brand-new administrator as having
    // already seen the tour. The one person the tour exists for.
    //
    // On a genuine upgrade the column is absent, so it is added and every
    // pre-existing user is stamped 1: someone who has been running OpenSCM for
    // months should not be greeted by "let's register your first system".
    // Users created after the upgrade pick up the column DEFAULT of 0 and do
    // see it.
    if version < 38 {
        info!("Running schema migration v37 → v38 (guided first-run tour)...");

        // table_exists as well as column_exists: migrations must survive a
        // partial schema. Test fixtures (and any hand-built database) can
        // reach this point without a users table at all, and an unguarded
        // ALTER would abort the whole migration run for everything after it.
        if table_exists(pool, "users").await && !column_exists(pool, "users", "tour_done").await {
            sqlx::query("ALTER TABLE users ADD COLUMN tour_done INTEGER NOT NULL DEFAULT 0")
                .execute(pool)
                .await?;
            sqlx::query("UPDATE users SET tour_done = 1")
                .execute(pool)
                .await?;
        }

        sqlx::query("UPDATE schema_info SET version = 38")
            .execute(pool)
            .await?;
        info!("Schema migration v37 → v38 complete.");
    }

    // v38 → v39: why a finding was excluded (0.8.2).
    //
    // results already recorded WHO excluded a finding and WHEN, but not WHY.
    // A suppressed control with no recorded rationale is the first thing an
    // auditor challenges, and the person who excluded it has usually forgotten
    // by the time anyone asks.
    //
    // Nullable with no backfill: exclusions made before this release genuinely
    // have no recorded reason, and inventing one ("Legacy exclusion") would put
    // words in an operator's mouth in an audit trail. The UI shows those as
    // "no reason recorded", which is the truth.
    if version < 39 {
        info!("Running schema migration v38 → v39 (exclusion reason)...");

        if table_exists(pool, "results").await
            && !column_exists(pool, "results", "excluded_reason").await
        {
            sqlx::query("ALTER TABLE results ADD COLUMN excluded_reason TEXT")
                .execute(pool)
                .await?;
        }

        sqlx::query("UPDATE schema_info SET version = 39")
            .execute(pool)
            .await?;
        info!("Schema migration v38 → v39 complete.");
    }

    // v39 → v40: compliance alerting (0.9.0).
    //
    // Design: docs/design/0.9.0-alerting.md. Three tables:
    //   alerts            — the rule
    //   alert_state       — edge detection, keyed (alert, policy)
    //   alert_deliveries  — the outbox and the audit trail
    if version < 40 {
        info!("Running schema migration v39 → v40 (compliance alerting)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alerts (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id        VARCHAR(191) NOT NULL DEFAULT 'default',
                name             TEXT    NOT NULL,
                enabled          INTEGER NOT NULL DEFAULT 1,
                scope_type       TEXT    NOT NULL DEFAULT 'policy',
                policy_id        INTEGER,
                trigger_type     TEXT    NOT NULL,
                threshold        REAL    NOT NULL,
                -- Which compliance axis this rule watches, pinned at creation.
                -- The tenant's display toggle must not silently change what an
                -- existing alert means (the 0.6.6 dual-mode lesson).
                score_axis       TEXT    NOT NULL DEFAULT 'test',
                -- Actions live in alert_actions: a rule may have several.
                cooldown_minutes INTEGER NOT NULL DEFAULT 60,
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by       INTEGER,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id)  ON DELETE CASCADE,
                FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE
            )",
        ).execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alerts_tenant_enabled ON alerts (tenant_id, enabled)")
            .execute(pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alert_actions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id      INTEGER NOT NULL,
                action        TEXT    NOT NULL,
                target        TEXT,
                target_secret TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
            )",
        ).execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alert_actions_alert ON alert_actions (alert_id)")
            .execute(pool).await?;

        // Keyed (alert, policy), not on the alert row: an all_policies rule
        // tracks each policy independently, so one policy sitting below a
        // threshold must not suppress the alert for another.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alert_state (
                alert_id      INTEGER NOT NULL,
                policy_id     INTEGER NOT NULL,
                last_score    REAL,
                state         TEXT NOT NULL DEFAULT 'ok',
                last_fired_at DATETIME,
                PRIMARY KEY (alert_id, policy_id),
                FOREIGN KEY (alert_id)  REFERENCES alerts (id)   ON DELETE CASCADE,
                FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE
            )",
        ).execute(pool).await?;

        // alert_id is deliberately NOT cascaded: deleting a rule must not erase
        // the record of alerts it already sent. The column goes NULL and the
        // row survives with its action, target and scores intact.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alert_deliveries (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id     VARCHAR(191) NOT NULL DEFAULT 'default',
                alert_id      INTEGER,
                policy_id     INTEGER,
                alert_name    TEXT,
                policy_name   TEXT,
                fired_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
                old_score     REAL,
                new_score     REAL,
                action        TEXT NOT NULL,
                target        TEXT,
                status        TEXT NOT NULL DEFAULT 'pending',
                attempts      INTEGER NOT NULL DEFAULT 0,
                last_error    TEXT,
                next_retry_at DATETIME,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )",
        ).execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alert_deliv_retry ON alert_deliveries (status, next_retry_at)")
            .execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alert_deliv_tenant ON alert_deliveries (tenant_id, fired_at)")
            .execute(pool).await?;

        sqlx::query(
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description) VALUES
             ('default', 'alert_history_retention_days', '90',
              'Days to keep alert delivery history before auto-pruning (0 = keep forever)')"
        ).execute(pool).await?;

        sqlx::query("UPDATE schema_info SET version = 40").execute(pool).await?;
        info!("Schema migration v39 → v40 complete.");
    }

    // v40 → v41: an alert may have several actions (0.9.2).
    //
    // Originally one rule carried exactly one action. Wanting both an email and
    // an in-app notification meant creating two rules watching the same policy
    // — with independent cooldowns and independent edge state, so the two could
    // drift apart and describe the same event differently, or one could fire
    // while the other was muted.
    //
    // Actions move to a child table. Cooldown and edge state stay on the RULE,
    // so one event still mutes all of its actions together; only delivery is
    // per action, which means a failing webhook does not hold up the email
    // beside it.
    //
    // alerts.action / target / target_secret are dropped after their contents
    // are copied across. Leaving them looked safer, but `action` is NOT NULL:
    // every new insert would have to keep populating a column nothing reads,
    // and the two copies would drift the first time someone forgot. History is
    // unaffected — alert_deliveries snapshots the action and target when a
    // delivery is queued.
    if version < 41 {
        info!("Running schema migration v40 → v41 (multiple actions per alert)...");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alert_actions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id      INTEGER NOT NULL,
                action        TEXT    NOT NULL,
                target        TEXT,
                target_secret TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
            )",
        ).execute(pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alert_actions_alert ON alert_actions (alert_id)")
            .execute(pool).await?;

        // Carry every existing rule's single action across, so alerts that were
        // already configured keep firing without being re-created.
        // Only when the legacy column is actually present: a fresh install
        // creates the alerts table without it, so this copy has nothing to read.
        if table_exists(pool, "alerts").await
            && column_exists(pool, "alerts", "action").await
        {
            sqlx::query(
                "INSERT INTO alert_actions (alert_id, action, target, target_secret)
                 SELECT id, action, target, target_secret FROM alerts
                 WHERE action IS NOT NULL AND action <> ''
                   AND NOT EXISTS (SELECT 1 FROM alert_actions x WHERE x.alert_id = alerts.id)",
            ).execute(pool).await?;
        }

        // Which configured action a delivery came from, so the webhook secret
        // can be looked up for THAT action rather than for the rule.
        if table_exists(pool, "alert_deliveries").await
            && !column_exists(pool, "alert_deliveries", "action_id").await
        {
            sqlx::query("ALTER TABLE alert_deliveries ADD COLUMN action_id INTEGER")
                .execute(pool).await?;
        }

        // SQLite has supported DROP COLUMN since 3.35. Ignore failures: an
        // older engine simply keeps the unused columns, and the INSERT path
        // below tolerates that.
        for col in ["action", "target", "target_secret"] {
            if column_exists(pool, "alerts", col).await {
                let _ = sqlx::query(&format!("ALTER TABLE alerts DROP COLUMN {col}"))
                    .execute(pool).await;
            }
        }

        sqlx::query("UPDATE schema_info SET version = 41").execute(pool).await?;
        info!("Schema migration v40 → v41 complete.");
    }

    // ─────────────────────────────────────────────────────────────────────
    // v41 → v42: revocable sessions (0.9.4).
    //
    // Sessions are signed cookies with no server-side record, so nothing a
    // server does can end one early. session_epoch is copied into every
    // cookie at issue and compared on every request; bumping it (password
    // change, password reset) invalidates every session that user holds
    // without a sessions table. Default 0 covers existing rows.
    // ─────────────────────────────────────────────────────────────────────
    if version < 42 {
        info!("Running schema migration v41 → v42 (session epoch)...");
        if table_exists(pool, "users").await && !column_exists(pool, "users", "session_epoch").await {
            sqlx::query("ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0")
                .execute(pool).await?;
        }
        sqlx::query("UPDATE schema_info SET version = 42").execute(pool).await?;
        info!("Schema migration v41 → v42 complete.");
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: generate_external_id
// Returns a 32-character lowercase hex string (16 random bytes) suitable as
// a stable identifier for exported/imported policies.  Generated with the
// thread-safe RNG; collision probability is negligible.
// ─────────────────────────────────────────────────────────────────────────────
pub fn generate_external_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
