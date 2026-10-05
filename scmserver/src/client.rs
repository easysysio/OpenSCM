// =============================================================================
// client.rs — agent API endpoints: register, heartbeat, and compliance results
//
// All routes are unauthenticated (no session cookie). Requests are validated
// by Ed25519 signature over the raw JSON payload bytes. A tenant must exist
// before any agent can register or submit results for it.
// =============================================================================

use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use tokio::sync::mpsc;
use sqlx::{SqlitePool, QueryBuilder, Row};
use std::collections::HashMap;
use tracing::{info, error, debug, warn};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey, Signature, SigningKey, Signer};

use serde_json::value::RawValue;
use crate::models::{SignedRequest, SignedResult, UnsignedPayload, ComplianceResult, SignedResponse, Test, TestCondition, TestWithConditions, TestPayload};


use crate::agents::derive_platform;


#[derive(sqlx::FromRow)]
struct AuthCheck {
    pub key: String,
    pub status: Option<String>,
}



// ============================================================
// HELPERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: sign_response
// Signs a JSON payload with the tenant's active Ed25519 private key.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn sign_response(
    pool: &SqlitePool,
    tenant_id: &str,
    payload: serde_json::Value,
) -> Result<SignedResponse, Box<dyn std::error::Error>> {
    let priv_base64 = sqlx::query_scalar::<_, String>(
        "SELECT private_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| format!("CRITICAL: No signing key found for tenant '{}'", tenant_id))?;

    let priv_bytes = general_purpose::STANDARD.decode(priv_base64.trim())?;
    let key_array: [u8; 32] = priv_bytes
        .try_into()
        .map_err(|_| "Invalid private key length: expected 32 bytes")?;

    let signing_key = SigningKey::from_bytes(&key_array);

    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = signing_key.sign(&payload_bytes);
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

    Ok(SignedResponse {
        payload,
        signature: signature_base64,
    })
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: decode_public_key
// Decodes a base64-encoded Ed25519 verifying key.
// ─────────────────────────────────────────────────────────────────────────────
fn decode_public_key(base64_key: &str) -> Result<VerifyingKey, String> {
    let bytes = general_purpose::STANDARD
        .decode(base64_key)
        .map_err(|e| format!("Invalid base64 in public key: {}", e))?;

    let key_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;

    VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Invalid Ed25519 public key: {}", e))
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: decode_signature
// Decodes a base64-encoded Ed25519 signature into a Signature value.
// ─────────────────────────────────────────────────────────────────────────────
fn decode_signature(base64_sig: &str) -> Result<Signature, String> {
    let bytes = general_purpose::STANDARD
        .decode(base64_sig)
        .map_err(|e| format!("Invalid base64 in signature: {}", e))?;

    let sig_array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes".to_string())?;

    Ok(Signature::from_bytes(&sig_array))
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: verify_signature
// Verifies an Ed25519 signature against the raw, unmodified payload bytes.
// raw_payload is a RawValue so key order is preserved exactly as received,
// matching what the client signed regardless of field-name version (tenant_id
// vs organization).
// ─────────────────────────────────────────────────────────────────────────────
fn verify_signature(
    raw_payload: &RawValue,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), String> {
    let verifier = decode_public_key(public_key_b64)?;
    let signature = decode_signature(signature_b64)?;
    let payload_bytes = raw_payload.get().as_bytes(); // exact original bytes — no re-serialisation

    verifier
        .verify(payload_bytes, &signature)
        .map_err(|_| "Signature verification failed".to_string())
}


// ============================================================
// HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// POST /send  [Agent API — no session auth, Ed25519 signed]
// Handles agent registration (id=0) and heartbeat (id>0).
// Returns pending test commands for approved agents.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn send(
    Extension(pool): Extension<SqlitePool>,
    Json(signed_req): Json<SignedRequest>,
) -> impl IntoResponse {
    // Parse the typed payload from the raw bytes.
    // `signed_req.payload` is a RawValue — exact bytes as received.
    // Parsing into UnsignedPayload here only to extract fields; signature
    // verification always uses the original raw bytes so key order is preserved.
    let payload: UnsignedPayload = match serde_json::from_str(signed_req.payload.get()) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to parse payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid payload"})),
            ).into_response();
        }
    };

    let tenant_id = if payload.organization.is_empty() {
        "default"
    } else {
        &payload.organization
    };

    let id = match payload.id.parse::<i64>() {
        Ok(val) => val,
        Err(_) => {
            warn!("Rejected request with invalid ID from host '{}'", payload.hostname);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid ID"})),
            )
                .into_response();
        }
    };

    // =========================================================
    // STEP 1: VALIDATE TENANT EXISTENCE
    // =========================================================
    let tenant_exists = match sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM tenants WHERE id = ?",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    {
        Ok(count) => count > 0,
        Err(e) => {
            error!("Database error checking tenant '{}': {}", tenant_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if !tenant_exists {
        warn!(
            "REJECTED: Agent '{}' attempted to connect to non-existent tenant '{}'.",
            payload.hostname, tenant_id
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Unauthorized: Tenant does not exist"})),
        )
            .into_response();
    }

    let mut response_data = serde_json::json!({});

    // =========================================================
    // STEP 2: REGISTRATION (ID == 0)
    // =========================================================
    if id == 0 {
        if let Some(ref pub_key) = payload.public_key {
            if decode_public_key(pub_key).is_err() {
                warn!(
                    "REJECTED: Agent '{}' provided malformed public key during registration.",
                    payload.hostname
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid public key format"})),
                )
                    .into_response();
            }
        }

        // Golden enrollment token (optional, registration only). Computed once
        // here so both the re-registration and new-registration paths can use
        // it. Empty string is treated as absent.
        let token_opt = payload.enrollment_token.as_deref().filter(|s| !s.is_empty());

        // If this public key already exists (e.g. client lost its stored ID),
        // return the existing system rather than creating a duplicate row.
        if let Some(ref pub_key) = payload.public_key {
            match sqlx::query("SELECT id, status FROM systems WHERE key = ? AND tenant_id = ?")
                .bind(pub_key)
                .bind(tenant_id)
                .fetch_optional(&pool)
                .await
            {
                Ok(Some(row)) => {
                    let existing_id: i64 = row.get("id");
                    let mut existing_status: String = row.try_get("status").unwrap_or_else(|_| "pending".into());

                    // Promote an already-pending system to active if it now
                    // presents a valid token (covers "enrolled before minting
                    // the token, then added it"). Runs in its own short tx so
                    // the token use is consumed atomically with the status flip.
                    if existing_status == "pending" {
                        if let Some(tok) = token_opt {
                            if let Ok(mut tx) = pool.begin().await {
                                match crate::enrollment::validate_and_consume_token(&mut tx, tenant_id, tok).await {
                                    Ok(true) => {
                                        if sqlx::query("UPDATE systems SET status = 'active' WHERE id = ? AND tenant_id = ?")
                                            .bind(existing_id).bind(tenant_id)
                                            .execute(&mut *tx).await.is_ok()
                                            && tx.commit().await.is_ok()
                                        {
                                            existing_status = "active".into();
                                            info!("Agent '{}' (ID {}) auto-approved via enrollment token on re-registration.",
                                                  payload.hostname, existing_id);
                                            crate::audit::record(
                                                &pool, tenant_id, None, Some(payload.ip.as_str()),
                                                "enrollment.token_approve",
                                                Some("system"), Some(&existing_id.to_string()),
                                                Some(&format!("host={:?} auto-approved on re-registration", payload.hostname)),
                                            ).await;
                                        }
                                    }
                                    _ => { let _ = tx.rollback().await; }
                                }
                            }
                        }
                    }

                    debug!(
                        "Agent '{}' re-registration: returning existing system ID {} (status: {})",
                        payload.hostname, existing_id, existing_status
                    );
                    let mut rereg_data = serde_json::json!({
                        "status": existing_status,
                        "id": existing_id,
                        "tenant_id": tenant_id,
                        "command": "REGISTER"
                    });
                    // Include server public key so the client can verify signatures
                    if let Ok(Some(pub_key)) = sqlx::query_scalar::<_, String>(
                        "SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
                    )
                    .bind(tenant_id)
                    .fetch_optional(&pool)
                    .await
                    {
                        rereg_data["server_public_key"] = serde_json::json!(pub_key);
                    }
                    // Must go through sign_response — client verifies the signature on every response.
                    return match sign_response(&pool, tenant_id, rereg_data).await {
                        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
                        Err(e) => {
                            error!("Failed to sign re-registration response for '{}': {}", payload.hostname, e);
                            (StatusCode::INTERNAL_SERVER_ERROR,
                             Json(serde_json::json!({"error": "Signing error"}))).into_response()
                        }
                    };
                }
                Ok(None) => { /* not found — proceed with normal insert */ }
                Err(e) => {
                    error!("Failed to check existing registration for '{}': {}", payload.hostname, e);
                }
            }
        }

        info!(
            "New agent registration: '{}' (Tenant: {})",
            payload.hostname, tenant_id
        );

        // `token_opt` was computed above (shared with the re-registration
        // path). When a valid token is presented the system comes up `active`
        // instead of `pending` — approval bypass only, the ed25519 handshake
        // above still ran. See docs/design/0.6.0-enrollment-tokens.md.

        // Use a transaction so token-consume, INSERT, and last_insert_rowid()
        // run atomically on the same connection.
        let reg_result: Result<(i64, bool), sqlx::Error> = async {
            let mut tx = pool.begin().await?;
            let auto_approved = match token_opt {
                Some(tok) => crate::enrollment::validate_and_consume_token(&mut tx, tenant_id, tok).await?,
                None      => false,
            };
            let status = if auto_approved { "active" } else { "pending" };
            sqlx::query(
                "INSERT INTO systems (tenant_id, key, name, ver, os, ip, arch, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(tenant_id)
            .bind(&payload.public_key)
            .bind(&payload.hostname)
            .bind(&payload.ver)
            .bind(&payload.os)
            .bind(&payload.ip)
            .bind(&payload.arch)
            .bind(status)
            .execute(&mut *tx)
            .await?;
            let id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok((id, auto_approved))
        }.await;

        match reg_result {
            Ok((new_id, auto_approved)) => {
                let status_str = if auto_approved { "active" } else { "pending" };
                info!(
                    "Agent '{}' registered with ID {} ({}).",
                    payload.hostname, new_id,
                    if auto_approved { "auto-approved via enrollment token" } else { "pending approval" }
                );

                // Audit the token outcome. A presented-but-invalid token is
                // logged (lenient — the system still enrolled as pending) so a
                // bad/expired token attempt is visible.
                if auto_approved {
                    crate::audit::record(
                        &pool, tenant_id, None, Some(payload.ip.as_str()),
                        "enrollment.token_approve",
                        Some("system"), Some(&new_id.to_string()),
                        Some(&format!("host={:?} auto-approved at enrollment", payload.hostname)),
                    ).await;
                } else if token_opt.is_some() {
                    warn!("Agent '{}' presented an invalid/expired enrollment token — enrolled as pending.",
                          payload.hostname);
                    crate::audit::record(
                        &pool, tenant_id, None, Some(payload.ip.as_str()),
                        "enrollment.token_rejected",
                        Some("system"), Some(&new_id.to_string()),
                        Some(&format!("host={:?} invalid/expired token", payload.hostname)),
                    ).await;
                }

                response_data = serde_json::json!({
                    "status": status_str,
                    "id": new_id,
                    "tenant_id": tenant_id,
                    "command": "REGISTER"
                });

                // Send server public key on registration so the client can
                // verify signatures immediately without waiting for the next heartbeat.
                match sqlx::query_scalar::<_, String>(
                    "SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
                )
                .bind(tenant_id)
                .fetch_optional(&pool)
                .await
                {
                    Ok(Some(pub_key)) => {
                        response_data["server_public_key"] = serde_json::json!(pub_key);
                    }
                    Ok(None) => warn!("No active public key found for tenant '{}' during registration.", tenant_id),
                    Err(e)  => error!("Failed to fetch server public key for tenant '{}': {}", tenant_id, e),
                }
            }
            Err(e) => {
                error!("Failed to register agent '{}': {}", payload.hostname, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    } else {
        // =========================================================
        // STEP 3: HEARTBEAT (ID > 0)
        // =========================================================
        let auth_result = sqlx::query_as::<_, AuthCheck>(
            "SELECT key, status FROM systems WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await;

        let auth = match auth_result {
            Ok(Some(a)) => a,
            Ok(None) => {
                warn!(
                    "Identity Check: Agent ID {} not found for tenant '{}'.",
                    id, tenant_id
                );
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Agent not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error fetching agent {} for tenant '{}': {}", id, tenant_id, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };

        // M8: Check denied BEFORE signature verification — no benefit verifying a denied agent,
        // and doing so leaks status information (denied → 200 vs pending → 200 vs bad sig → 401).
        if auth.status.as_deref() == Some("denied") {
            info!("Agent ID {} is denied — request rejected without signature check.", id);
            response_data = serde_json::json!({
                "status": "denied",
                "command": "NONE"
            });
        } else {

        debug!("Verifying signature for Agent ID {} (Tenant: {}).", id, tenant_id);
        if let Err(err) = verify_signature(&signed_req.payload, &signed_req.signature, &auth.key) {
            warn!(
                "SECURITY: Invalid signature from Agent ID {} (Tenant: '{}'): {}",
                id, tenant_id, err
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid Signature"})),
            )
                .into_response();
        }
        debug!("Signature verified for Agent ID {}.", id);

        match auth.status.as_deref().unwrap_or("pending") {
            "approved" | "active" => {
                let mut tx = match pool.begin().await {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("Failed to begin transaction for agent {}: {}", id, e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Database error"})),
                        )
                            .into_response();
                    }
                };

                // Update system info. Platform is derived from arch + os on every read
                // rather than persisted — keeps the schema simple and means a binary
                // rebuild can't get out of sync with stale stored data.
                if let Err(e) = sqlx::query(
                    "UPDATE systems SET name=?, ver=?, os=?, ip=?, arch=?, status='active', last_seen=CURRENT_TIMESTAMP,
                     cpu_usage=?, mem_used_mb=?, mem_total_mb=?, disk_used_gb=?, disk_total_gb=?, uptime_secs=?
                     WHERE id=? AND tenant_id=?",
                )
                .bind(&payload.hostname)
                .bind(&payload.ver)
                .bind(&payload.os)
                .bind(&payload.ip)
                .bind(&payload.arch)
                .bind(payload.cpu_usage)
                .bind(payload.mem_used_mb)
                .bind(payload.mem_total_mb)
                .bind(payload.disk_used_gb)
                .bind(payload.disk_total_gb)
                .bind(payload.uptime_secs)
                .bind(id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                {
                    error!("Failed to update system info for agent {}: {}", id, e);
                    tx.rollback().await.ok();
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                // Container inventory — only act when the agent sent the field
                // (None = old agent / non-Linux, leave existing rows alone).
                // Some([...]) including the empty case ingests as design doc §3.
                if let Some(ref containers) = payload.containers {
                    if let Err(e) = ingest_containers(&mut tx, tenant_id, id, containers).await {
                        error!("Failed to ingest containers for agent {}: {}", id, e);
                        tx.rollback().await.ok();
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Database error"})),
                        )
                            .into_response();
                    }
                }

                // Automatic group assignment — reconcile this system's
                // auto-group membership against the tenant's enabled rules.
                // Called on every heartbeat; the evaluator no-ops cheaply when
                // there are no enabled rules (one short SELECT against an
                // empty / tiny auto_group_rules) or when nothing changed.
                // Membership churn flips systems.compliance_dirty = 1 so the
                // existing scheduler picks up the recalc on its next tick —
                // no synchronous compliance work on the heartbeat hot path.
                // See docs/design/0.5.2-auto-groups.md.
                match crate::auto_groups::apply_auto_groups(&mut tx, tenant_id, id).await {
                    Ok(true)  => {
                        debug!("auto-groups: membership changed for system {}", id);
                    }
                    Ok(false) => { /* no change — common path */ }
                    Err(e) => {
                        // Don't fail the heartbeat — auto-group reconciliation
                        // is best-effort. Log and continue; the next heartbeat
                        // will retry. The systems UPDATE + container ingest
                        // above are the user-visible operations and must not
                        // be rolled back over a rule-eval glitch.
                        warn!("auto-groups: apply_auto_groups failed for system {}: {}",
                              id, e);
                    }
                }

                // Check whether an admin has queued an UPGRADE for this system — that
                // shows up as a row in the commands table with command_type='UPGRADE'.
                // The matching agent_packages row gives us the URL / SHA256 / version
                // to ship in the heartbeat response.
                let platform = derive_platform(&payload.arch, &payload.os);
                let has_upgrade: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM commands
                     WHERE tenant_id = ? AND system_id = ? AND command_type = 'UPGRADE'",
                )
                .bind(tenant_id)
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(0);

                let upgrade_pkg = if has_upgrade > 0 {
                    sqlx::query_as::<_, crate::models::AgentPackage>(
                        "SELECT platform, version, sha256, url FROM agent_packages WHERE platform = ?",
                    )
                    .bind(&platform)
                    .fetch_optional(&pool)
                    .await
                    .unwrap_or(None)
                } else {
                    None
                };

                // Fetch pending test commands. The INNER JOIN on tests.id naturally
                // skips UPGRADE rows (test_id IS NULL).
                let tests: Vec<Test> = match sqlx::query_as::<_, Test>(
                    "SELECT t.* FROM commands c
                     JOIN tests t ON c.test_id = t.id
                     WHERE c.system_id = ? AND c.tenant_id = ? AND c.command_type = 'TEST'
                     ORDER BY c.test_id
                     LIMIT 500",
                )
                .bind(id)
                .bind(tenant_id)
                .fetch_all(&mut *tx)
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to fetch commands for agent {}: {}", id, e);
                        tx.rollback().await.ok();
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Database error"})),
                        )
                            .into_response();
                    }
                };

                // M1: Batch-fetch ALL conditions for ALL tests in one query instead of N+1.
                let test_ids: Vec<i64> = tests.iter().map(|t| t.id.unwrap_or(0) as i64).collect();

                let all_conditions: Vec<TestCondition> = if test_ids.is_empty() {
                    vec![]
                } else {
                    let mut qb = QueryBuilder::new(
                        "SELECT id, tenant_id, test_id, `type`, element, input, selement, condition, sinput
                         FROM test_conditions WHERE tenant_id = ",
                    );
                    qb.push_bind(tenant_id);
                    qb.push(" AND test_id IN (");
                    let mut sep = qb.separated(", ");
                    for tid in &test_ids { sep.push_bind(*tid); }
                    qb.push(") ORDER BY test_id ASC, id ASC");

                    qb.build_query_as::<TestCondition>()
                        .fetch_all(&pool)
                        .await
                        .unwrap_or_else(|e| {
                            error!("Failed to batch-fetch conditions for agent {}: {}", id, e);
                            vec![]
                        })
                };

                // Group by (test_id, type)
                let mut cond_map: HashMap<(i64, &str), Vec<TestCondition>> = HashMap::new();
                for c in all_conditions {
                    let key = (c.test_id, if c.r#type == "applicability" { "applicability" } else { "condition" });
                    cond_map.entry(key).or_default().push(c);
                }

                let mut tests_with_conditions: Vec<TestWithConditions> = Vec::new();
                for test in tests {
                    let test_id = test.id.unwrap_or(0) as i64;
                    let conditions = cond_map.remove(&(test_id, "condition")).unwrap_or_default();
                    let applicability = cond_map.remove(&(test_id, "applicability")).filter(|v| !v.is_empty());
                    tests_with_conditions.push(TestWithConditions { test, conditions, applicability });
                }

                // Clear only the commands we're about to deliver in this heartbeat:
                //   • UPGRADE dispatch → wipe the UPGRADE row, KEEP the TEST rows so
                //     they get re-dispatched after the client restarts on the new
                //     binary. (Without this, an upgrade silently drops in-flight tests.)
                //   • Otherwise        → wipe TEST rows as before. Any queued UPGRADE
                //     row stays put for a future heartbeat once a matching package
                //     becomes available.
                //
                // "The TEST rows" means the ones in THIS response, not every TEST
                // row the system has. The SELECT above is capped at 500, but the
                // DELETE used to clear the whole queue, so a system with more
                // than 500 queued tests had the rest discarded unsent — they
                // never ran, and nothing was logged. Only what is dispatched is
                // removed; the remainder goes out on the following heartbeats.
                let dispatched: Vec<i64> = tests_with_conditions
                    .iter()
                    .map(|t| t.test.id.unwrap_or(0) as i64)
                    .collect();
                let clear_result = if upgrade_pkg.is_some() {
                    sqlx::query(
                        "DELETE FROM commands WHERE system_id = ? AND tenant_id = ? AND command_type = 'UPGRADE'",
                    )
                    .bind(id)
                    .bind(tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map(|_| ())
                } else if dispatched.is_empty() {
                    Ok(())
                } else {
                    let mut qb = QueryBuilder::new("DELETE FROM commands WHERE system_id = ");
                    qb.push_bind(id);
                    qb.push(" AND tenant_id = ");
                    qb.push_bind(tenant_id);
                    qb.push(" AND command_type = 'TEST' AND test_id IN (");
                    let mut sep = qb.separated(", ");
                    for tid in &dispatched { sep.push_bind(*tid); }
                    qb.push(")");
                    qb.build().execute(&mut *tx).await.map(|_| ())
                };
                if let Err(e) = clear_result {
                    error!("Failed to clear commands for agent {}: {}", id, e);
                    tx.rollback().await.ok();
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                // How many tests are still waiting (0 in the usual case). On
                // an UPGRADE dispatch nothing was sent, so all of them are.
                let remaining: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM commands
                     WHERE system_id = ? AND tenant_id = ? AND command_type = 'TEST'",
                )
                .bind(id)
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(0);

                if let Err(e) = tx.commit().await {
                    error!("Failed to commit heartbeat transaction for agent {}: {}", id, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                if upgrade_pkg.is_some() {
                    info!(
                        "Heartbeat from Agent ID {} — upgrade dispatched, {} test(s) held for after it.",
                        id, remaining
                    );
                } else if remaining > 0 {
                    info!(
                        "Heartbeat from Agent ID {} — {} test(s) dispatched, {} more queued for the next heartbeat.",
                        id, tests_with_conditions.len(), remaining
                    );
                } else {
                    info!(
                        "Heartbeat from Agent ID {} — {} test(s) dispatched.",
                        id,
                        tests_with_conditions.len()
                    );
                }

                // Convert to flat TestPayload (mirrors client struct) — eliminates
                // #[serde(flatten)] and ensures deterministic JSON for Ed25519 signing.
                let test_payloads: Vec<TestPayload> = tests_with_conditions
                    .into_iter()
                    .map(TestPayload::from)
                    .collect();

                // UPGRADE takes priority over TEST — the client will replace itself
                // and restart; pending tests are re-queued on the next heartbeat from
                // the new binary.
                if let Some(pkg) = upgrade_pkg {
                    response_data = serde_json::json!({
                        "status": "approved",
                        "id": id,
                        "tenant_id": tenant_id,
                        "command": "UPGRADE",
                        "upgrade_url":     pkg.url,
                        "upgrade_sha256":  pkg.sha256,
                        "upgrade_version": pkg.version,
                    });
                    info!(
                        "UPGRADE command dispatched to Agent ID {} (platform: {}, version: {}).",
                        id, platform, pkg.version
                    );
                } else {
                    response_data = serde_json::json!({
                        "status": "approved",
                        "id": id,
                        "tenant_id": tenant_id,
                        "command": if test_payloads.is_empty() { "NONE" } else { "TEST" },
                        "data": test_payloads
                    });
                }

                // Only send the server public key when the client explicitly
                // requests it — indicated by the client including its own
                // public_key in the payload (needs_handshake path in the agent).
                // This covers two cases: first heartbeat after registration
                // (server key not yet saved) and key file loss/corruption.
                // On normal heartbeats public_key is None so we skip the DB
                // lookup entirely.
                if payload.public_key.is_some() {
                    match sqlx::query_scalar::<_, String>(
                        "SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
                    )
                    .bind(tenant_id)
                    .fetch_optional(&pool)
                    .await
                    {
                        Ok(Some(pub_key)) => {
                            response_data["server_public_key"] = serde_json::json!(pub_key);
                            debug!("Server public key included in response for Agent ID {} (re-handshake).", id);
                        }
                        Ok(None) => warn!("No active public key found for tenant '{}'.", tenant_id),
                        Err(e)  => error!("Failed to fetch server public key for tenant '{}': {}", tenant_id, e),
                    }
                }
            }

            _ => {
                // Pending (or any other unrecognised status): update last_seen only.
                if let Err(e) = sqlx::query(
                    "UPDATE systems SET last_seen=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?",
                )
                .bind(id)
                .bind(tenant_id)
                .execute(&pool)
                .await
                {
                    error!("Failed to update last_seen for pending agent {}: {}", id, e);
                }

                response_data = serde_json::json!({
                    "status": "pending",
                    "command": "NONE"
                });
            }
        }
        } // end else (not denied)
    } // end else (id > 0 heartbeat path)

    // Sign and return response
    match sign_response(&pool, tenant_id, response_data).await {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => {
            error!("Failed to sign response for tenant '{}': {}", tenant_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Signing Error"})),
            )
                .into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /result  [Agent API — no session auth, Ed25519 signed]
// Stores a single PASS/FAIL/NA compliance result from an approved agent.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn receive_result(
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    Json(signed_req): Json<SignedResult>,
) -> impl IntoResponse {
    // Parse typed payload from raw bytes — same pattern as /send
    let payload: ComplianceResult = match serde_json::from_str(signed_req.payload.get()) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to parse result payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid payload"})),
            ).into_response();
        }
    };

    let tenant_id = if payload.organization.is_empty() {
        "default"
    } else {
        &payload.organization
    };

    info!(
        "Result received from Agent ID {} (Tenant: '{}', Test ID: {})",
        payload.client_id, tenant_id, payload.test_id
    );

    // H-new-1: Fetch key AND status together — denied/pending agents must not be able
    // to submit results even if they still hold valid signing keys from a prior active period.
    let auth_check = match sqlx::query_as::<_, AuthCheck>(
        "SELECT key, status FROM systems WHERE id = ? AND tenant_id = ?",
    )
    .bind(payload.client_id)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(a)) => a,
        Ok(None) => {
            warn!(
                "Result Rejected: Unknown Agent ID {} for tenant '{}'.",
                payload.client_id, tenant_id
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Unknown Agent"})),
            )
                .into_response();
        }
        Err(e) => {
            error!(
                "DB error fetching key for Agent ID {} (Tenant: '{}'): {}",
                payload.client_id, tenant_id, e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    // Reject results from agents that are not active/approved
    match auth_check.status.as_deref().unwrap_or("pending") {
        "active" | "approved" => {}
        "denied" => {
            warn!(
                "Result Rejected: Agent ID {} (Tenant: '{}') is denied.",
                payload.client_id, tenant_id
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Agent is denied"})),
            )
                .into_response();
        }
        _ => {
            warn!(
                "Result Rejected: Agent ID {} (Tenant: '{}') is pending approval.",
                payload.client_id, tenant_id
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Agent not yet approved"})),
            )
                .into_response();
        }
    }

    // H-new-2: Validate result value — only PASS/FAIL/NA are meaningful;
    // an agent cannot write arbitrary strings into the compliance results table.
    let normalized_result = match payload.result.to_uppercase().as_str() {
        "PASS" => "PASS",
        "FAIL" => "FAIL",
        "NA"   => "NA",
        other  => {
            warn!(
                "Result Rejected: Agent ID {} sent invalid result value '{}'.",
                payload.client_id, other
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid result value"})),
            )
                .into_response();
        }
    };

    if let Err(err) = verify_signature(&signed_req.payload, &signed_req.signature, &auth_check.key) {
        error!(
            "SECURITY ALERT: Invalid signature on results from Agent ID {} (Tenant: '{}'): {}",
            payload.client_id, tenant_id, err
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Result Auth Failed"})),
        )
            .into_response();
    }

    debug!(
        "Signature verified for Agent ID {} (Tenant: '{}').",
        payload.client_id, tenant_id
    );

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();

    // Resolve container scope. The agent ships `container_runtime_id` when
    // the result is per-container; the server looks up the matching row in
    // `containers` to get its surrogate id. If the lookup misses (rare —
    // would require the container to have vanished between heartbeat ingest
    // and the result POST), fall back to container_id=0 so the row is still
    // recorded but at host scope.
    let container_id: i64 = match payload.container_runtime_id.as_deref().filter(|s| !s.is_empty()) {
        Some(rid) => sqlx::query_scalar::<_, i64>(
            "SELECT id FROM containers
             WHERE host_system_id = ? AND runtime_id = ? AND tenant_id = ?",
        )
        .bind(payload.client_id).bind(rid).bind(tenant_id)
        .fetch_optional(&pool).await
        .ok().flatten()
        .unwrap_or(0),
        None => 0,
    };

    // IMPORTANT: the DO UPDATE clause lists ONLY `result` and `last_updated`.
    // Per-finding exclusions live in the same row (excluded / excluded_by /
    // excluded_at) and must NEVER be touched by a client heartbeat — that's
    // the whole guarantee that re-running a policy cannot clear an exclusion.
    // Do not change this to `INSERT OR REPLACE` (which would delete + re-insert
    // and silently wipe the exclusion flag).
    // container_id is part of the results PK (schema v26): 0 for host results,
    // the resolved containers.id for per-container results.
    if let Err(e) = sqlx::query(
        "INSERT INTO results (tenant_id, system_id, test_id, container_id, result, last_updated, evidence)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(tenant_id, system_id, test_id, container_id)
     DO UPDATE SET result = excluded.result, last_updated = excluded.last_updated, evidence = excluded.evidence"
    )
    .bind(tenant_id)
    .bind(payload.client_id)
    .bind(payload.test_id)
    .bind(container_id)
    .bind(normalized_result)
    .bind(&now)
    .bind(&payload.evidence)
    .execute(&pool)
    .await
    {
        error!(
            "Failed to store result from Agent ID {} (Tenant: '{}'): {}",
            payload.client_id, tenant_id, e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Storage Error"})),
        )
            .into_response();
    }

    info!(
        "Result stored: Agent ID {} | Test ID {} | Result: {} (Tenant: '{}')",
        payload.client_id, payload.test_id, normalized_result, tenant_id
    );

    let _ = sync_tx.send(()).await;

    let response_data = serde_json::json!({"status": "ok"});
    match sign_response(&pool, tenant_id, response_data).await {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => {
            error!(
                "Failed to sign response for Agent ID {} (Tenant: '{}'): {}",
                payload.client_id, tenant_id, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Signing Error"})),
            )
                .into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: ingest_containers
// Apply a heartbeat's container list to the `containers` table for this host.
// Semantics matching the design doc (§3, "Lifecycle"):
//
//   - `payload.containers == None`  → do nothing (old agent / non-Linux);
//     existing rows continue to age out via the retention prune.
//
//   - `payload.containers == Some([])` → agent explicitly reports no
//     containers; delete every row for this host so the UI matches reality
//     immediately.
//
//   - `payload.containers == Some([...])` → upsert each entry keyed on
//     `(host_system_id, runtime, name)`, preserving `first_seen`; delete any
//     row for this host whose `(runtime, name)` is no longer in the list.
//
// Runs inside the heartbeat transaction so a transient DB error rolls back
// the systems-table UPDATE too — the agent will retry the whole payload
// on the next tick.
// ─────────────────────────────────────────────────────────────────────────────
async fn ingest_containers(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: &str,
    host_system_id: i64,
    incoming: &[crate::models::IncomingContainer],
) -> Result<(), sqlx::Error> {
    // Single stable timestamp for this scan boundary so the DELETE-stragglers
    // step is monotonic (any row we just touched has last_seen >= now_str).
    let now_str = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    for c in incoming {
        sqlx::query(
            "INSERT INTO containers
               (tenant_id, host_system_id, runtime, runtime_id, name, image, image_digest,
                status, ip, is_privileged, run_user, network_mode, exposed_ports, mounts,
                capabilities_add, read_only_fs, restart_policy, health_check,
                first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(host_system_id, runtime, name) DO UPDATE SET
                runtime_id       = excluded.runtime_id,
                image            = excluded.image,
                image_digest     = excluded.image_digest,
                status           = excluded.status,
                ip               = excluded.ip,
                is_privileged    = excluded.is_privileged,
                run_user         = excluded.run_user,
                network_mode     = excluded.network_mode,
                exposed_ports    = excluded.exposed_ports,
                mounts           = excluded.mounts,
                capabilities_add = excluded.capabilities_add,
                read_only_fs     = excluded.read_only_fs,
                restart_policy   = excluded.restart_policy,
                health_check     = excluded.health_check,
                last_seen        = excluded.last_seen",
        )
        .bind(tenant_id)
        .bind(host_system_id)
        .bind(&c.runtime)
        .bind(&c.runtime_id)
        .bind(&c.name)
        .bind(&c.image)
        .bind(&c.image_digest)
        .bind(&c.status)
        .bind(&c.ip)
        .bind(c.is_privileged.map(|b| if b { 1i64 } else { 0 }))
        .bind(&c.run_user)
        .bind(&c.network_mode)
        .bind(&c.exposed_ports)
        .bind(&c.mounts)
        .bind(&c.capabilities_add)
        .bind(c.read_only_fs.map(|b| if b { 1i64 } else { 0 }))
        .bind(&c.restart_policy)
        .bind(c.health_check.map(|b| if b { 1i64 } else { 0 }))
        .bind(&now_str)
        .bind(&now_str)
        .execute(&mut **tx)
        .await?;
    }

    // Delete stragglers — rows for this host that the agent didn't report this
    // tick. Either the container was removed since the last heartbeat, or
    // (when `incoming` is empty) the runtime is gone entirely. The retention
    // prune is for stale rows from hosts that stop checking in altogether.
    sqlx::query("DELETE FROM containers WHERE host_system_id = ? AND last_seen < ?")
        .bind(host_system_id)
        .bind(&now_str)
        .execute(&mut **tx)
        .await?;

    Ok(())
}
