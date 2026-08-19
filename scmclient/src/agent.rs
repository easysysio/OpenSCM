use tracing::{info, warn, error, debug};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use std::fs;
use std::path::PathBuf;
use base64::{engine::general_purpose, Engine as _};
use reqwest;
use chrono;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use self_replace;

use crate::models::{UnsignedPayload, SignedRequest, SignedResponse, Test, ComplianceResult};
use crate::config::{Config, key_path};
use crate::compliance::{evaluate, EvalResult};


// ============================================================
// HELPERS
// ============================================================

/// Generate a consistent 8-character hex prefix based on the server URL.
/// Used to namespace key and identity files per server.
fn get_url_namespace(url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.trim_end_matches('/').as_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..8].to_string()
}


/// Decode a base64-encoded Ed25519 public key into a VerifyingKey.
fn decode_public_key(base64_key: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes = general_purpose::STANDARD.decode(base64_key.trim())?;
    let key_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&key_array)?)
}


/// Decode a base64-encoded Ed25519 signature.
fn decode_signature(base64_sig: &str) -> Result<Signature, Box<dyn std::error::Error>> {
    let bytes = general_purpose::STANDARD.decode(base64_sig.trim())?;
    let sig_array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;
    Ok(Signature::from_bytes(&sig_array))
}


/// Sign a serializable payload using serde_json for cross-platform determinism.
fn sign_payload<T: serde::Serialize>(
    payload: &T,
    signing_key: &SigningKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(payload)?;
    let signature = signing_key.sign(&bytes);
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
}


/// Verify a server response signature using serde_json serialization.
fn verify_server_response(
    payload: &serde_json::Value,
    signature_b64: &str,
    verifier: &VerifyingKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let signature = decode_signature(signature_b64)?;
    verifier
        .verify(&payload_bytes, &signature)
        .map_err(|_| "Server signature verification failed".into())
}


/// Write a file with restricted permissions (0o600) on Unix.
/// On non-Unix platforms falls back to a regular write.
fn write_private_file(path: &PathBuf, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true).mode(0o600);
        let mut file = options.open(path)?;
        use std::io::Write;
        file.write_all(contents.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
    }

    Ok(())
}


/// Send a compliance result to the server.
async fn send_result(
    client_id_int: i64,
    organization: &str,
    test_id: i64,
    result: &str,
    container_runtime_id: Option<String>,
    evidence: Option<String>,
    signing_key: &SigningKey,
    http_client: &reqwest::Client,
    result_url: &str,
) {
    let payload = ComplianceResult {
        client_id: client_id_int,
        organization: organization.to_string(),
        test_id,
        result: result.to_string(),
        container_runtime_id,
        evidence,
    };

    let signature = match sign_payload(&payload, signing_key) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to sign result for test {}: {}", test_id, e);
            return;
        }
    };

    let req = SignedRequest { payload, signature };

    match http_client.post(result_url).json(&req).send().await {
        Ok(resp) if resp.status().is_success() => {
            debug!("Test {} result sent successfully.", test_id);
        }
        Ok(resp) => {
            error!(
                "Server rejected result for test {} with status: {}",
                test_id,
                resp.status()
            );
        }
        Err(e) => {
            error!("Failed to send result for test {}: {}", test_id, e);
        }
    }
}


// ============================================================
// COMPLIANCE TEST PROCESSING
// ============================================================

async fn process_compliance_tests(
    tests: Vec<Test>,
    client_id: &str,
    organization: &str,
    signing_key: &SigningKey,
    http_client: &reqwest::Client,
    result_url: &str,
    cmd_enabled: bool,
    ps_enabled:  bool,
) {
    info!("Processing {} compliance test(s).", tests.len());

    // Parse client_id once — reject if invalid
    let client_id_int: i64 = match client_id.parse() {
        Ok(id) if id > 0 => id,
        _ => {
            error!("Invalid client_id '{}' — cannot send results.", client_id);
            return;
        }
    };

    for test in tests {
        // A test with no id is unaddressable — sending test_id=0 would be
        // silently dropped by the server, so skip with a warning instead.
        let test_id = match test.id {
            Some(id) if id > 0 => id,
            _ => {
                warn!("Server sent test '{}' with no id — skipping.", test.name);
                continue;
            }
        };
        debug!("Starting evaluation of test ID {}", test_id);

        // =====================================================
        // APPLICABILITY CHECK
        // =====================================================
        if let Some(app_conditions) = &test.applicability {
            for c in app_conditions {
                debug!("Applicability condition: element='{}', selement='{}', condition='{}', sinput='{:?}'",
                    c.element, c.selement, c.condition.as_deref().unwrap_or(""), c.sinput);
            }
            if !app_conditions.is_empty() {
                // Applicability is always host-level — applies to the system as a
                // whole, not to individual containers. Evaluate with container=None.
                let app_results: Vec<EvalResult> = app_conditions.iter()
                    .map(|c| evaluate(
                        &c.element,
                        &c.input,
                        &c.selement,
                        c.condition.as_deref().unwrap_or(""),
                        c.sinput.as_deref().unwrap_or(""),
                        cmd_enabled,
                        ps_enabled,
                        None,
                    ))
                    .collect();
                
                for (i, r) in app_results.iter().enumerate() {
                    debug!("Applicability result {}: {:?}", i, r);
                }

                let is_applicable = match test.app_filter.as_deref().unwrap_or("all") {
                    "any" => app_results.iter().any(|r| *r == EvalResult::Pass),
                    _ => {
                        app_results.iter().all(|r| *r == EvalResult::Pass || *r == EvalResult::Na)
                        && app_results.iter().any(|r| *r == EvalResult::Pass)
                    }
                };

                debug!("Test ID {} is_applicable: {}", test_id, is_applicable);

                if !is_applicable {
                    debug!("Test ID {} is not applicable — sending NA.", test_id);
                    // Evidence: which applicability condition(s) gated it out.
                    let app_refs: Vec<&crate::models::TestCondition> = app_conditions.iter().collect();
                    let evidence = crate::compliance::build_evidence("applicability", &app_refs, &app_results);
                    send_result(client_id_int, organization, test_id, "NA", None, evidence, signing_key, http_client, result_url).await;
                    debug!("Completed evaluation of test ID {}", test_id);
                    continue;
                }
            }
        }

        // =====================================================
        // TEST EVALUATION
        // =====================================================
        // Drop conditions with empty element/selement up front so both
        // dispatch paths see only the real ones.
        let conds: Vec<&crate::models::TestCondition> = test.conditions.iter()
            .filter(|c| !c.element.is_empty() && c.element != "None"
                     && !c.selement.is_empty() && c.selement != "None")
            .collect();

        // Print the test shape — filter, every condition, the dispatch decision.
        // Gives the operator an at-a-glance view of what the agent is about to
        // do without having to trace through individual condition logs.
        debug!(
            "Test ID {} '{}' — filter='{}', {} condition(s):",
            test_id,
            test.name,
            test.filter.as_deref().unwrap_or("all"),
            conds.len()
        );
        for (i, c) in conds.iter().enumerate() {
            debug!(
                "  cond[{}]: element='{}' selement='{}' input='{}' condition='{}' sinput='{}' (per-container={})",
                i,
                c.element,
                c.selement,
                c.input,
                c.condition.as_deref().unwrap_or(""),
                c.sinput.as_deref().unwrap_or(""),
                crate::compliance::is_per_container_element(&c.element),
            );
        }

        // Per-container elements (EXEC + the metadata elements IMAGE,
        // PRIVILEGED, …) fan the test out across every container; everything
        // else runs once on the host. See compliance::is_per_container_element.
        let is_per_container = conds.iter()
            .any(|c| crate::compliance::is_per_container_element(&c.element));

        if is_per_container {
            // Enumerate containers ONCE and iterate. Each container produces a
            // separate result row identified by its runtime_id (the server
            // resolves it to containers.id at result-receive time).
            let containers = crate::containers::enumerate().unwrap_or_default();
            debug!("Test ID {} dispatch: per-container — {} container(s)", test_id, containers.len());
            if containers.is_empty() {
                debug!("Test ID {} is per-container but host has zero containers — sending NA.", test_id);
                send_result(client_id_int, organization, test_id, "NA", None, None, signing_key, http_client, result_url).await;
            } else {
                for container in &containers {
                    debug!(
                        "Test ID {} evaluating against container '{}' (runtime={}, runtime_id={}, image={:?}, run_user={:?}, net_mode={:?}, privileged={:?})",
                        test_id, container.name, container.runtime, &container.runtime_id[..container.runtime_id.len().min(12)],
                        container.image, container.run_user, container.network_mode, container.is_privileged
                    );
                    let results: Vec<EvalResult> = conds.iter().enumerate().map(|(i, c)| {
                        let r = evaluate(
                            &c.element, &c.input, &c.selement,
                            c.condition.as_deref().unwrap_or(""),
                            c.sinput.as_deref().unwrap_or(""),
                            cmd_enabled, ps_enabled,
                            Some(container),
                        );
                        debug!("  cond[{}] {} {} → {:?}", i, c.element, c.selement, r);
                        r
                    }).collect();
                    let verdict = crate::compliance::combine_verdict(&results, test.filter.as_deref().unwrap_or("all"));
                    debug!("Test ID {} container '{}' final verdict: {}", test_id, container.name, verdict);
                    let evidence = crate::compliance::build_evidence("condition", &conds, &results);
                    send_result(client_id_int, organization, test_id, &verdict,
                                Some(container.runtime_id.clone()), evidence,
                                signing_key, http_client, result_url).await;
                }
            }
        } else {
            // Host-scope test — single result, no container context.
            debug!("Test ID {} dispatch: host-scope", test_id);
            let results: Vec<EvalResult> = conds.iter().enumerate().map(|(i, c)| {
                let r = evaluate(
                    &c.element, &c.input, &c.selement,
                    c.condition.as_deref().unwrap_or(""),
                    c.sinput.as_deref().unwrap_or(""),
                    cmd_enabled, ps_enabled,
                    None,
                );
                debug!("  cond[{}] {} {} → {:?}", i, c.element, c.selement, r);
                r
            }).collect();
            let verdict = crate::compliance::combine_verdict(&results, test.filter.as_deref().unwrap_or("all"));
            debug!("Test ID {} final verdict: {}", test_id, verdict);
            let evidence = crate::compliance::build_evidence("condition", &conds, &results);
            send_result(client_id_int, organization, test_id, &verdict, None, evidence, signing_key, http_client, result_url).await;
        }
        debug!("Completed evaluation of test ID {}", test_id);
    }
}


// ============================================================
// AGENT IDENTITY + SYSTEM INFO + HEARTBEAT
//
// The four steps of a heartbeat — load identity, collect host info,
// post the signed payload, dispatch the server's command — were
// previously a single 200-line function. Each step is now in its own
// helper so the top-level send_system_info reads as a flow.
// ============================================================

// Per-server identity: filesystem paths + loaded signing key + current id.
struct AgentIdentity {
    namespace:       String,
    id_path:         PathBuf,
    server_pub_path: PathBuf,
    signing_key:     SigningKey,
    public_base64:   String,
    current_id:      String,
}

// Snapshot of host attributes reported to the server.
struct SystemInfo {
    hostname:     String,
    ip:           String,
    os:           String,
    arch:         String,
    ver:          String,
    // Telemetry
    cpu_usage:    Option<f32>,
    mem_used_mb:  Option<u64>,
    mem_total_mb: Option<u64>,
    disk_used_gb: Option<u64>,
    disk_total_gb: Option<u64>,
    uptime_secs:  Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Load (or create) the per-server agent identity.
// ─────────────────────────────────────────────────────────────────────────────
fn load_or_create_identity(config: &Config) -> Result<AgentIdentity, Box<dyn std::error::Error>> {
    let namespace = get_url_namespace(&config.server.url);
    let key_dir = std::path::Path::new(key_path())
        .parent()
        .expect("Core key directory must have a parent path");

    let id_path         = key_dir.join(format!("client_{}.id",  namespace));
    let priv_path       = key_dir.join(format!("client_{}.key", namespace));
    let pub_path        = key_dir.join(format!("client_{}.pub", namespace));
    let server_pub_path = key_dir.join(format!("server_{}.pub", namespace));

    // Generate keys on first run for this namespace.
    if !priv_path.exists() {
        info!("No identity found for namespace '{}'. Generating new Ed25519 keypair...", namespace);
        let mut csprng = OsRng;
        let signing_key   = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);

        write_private_file(&priv_path, &general_purpose::STANDARD.encode(signing_key.to_bytes()))?;
        fs::write(&pub_path, general_purpose::STANDARD.encode(verifying_key.to_bytes()))?;
        info!("New keypair generated for namespace '{}'.", namespace);
    }

    let current_id = if id_path.exists() {
        fs::read_to_string(&id_path)?.trim().to_string()
    } else {
        "0".to_string()
    };

    let private_base64 = fs::read_to_string(&priv_path)?;
    let private_bytes  = general_purpose::STANDARD.decode(private_base64.trim())?;
    let key_array: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| "Invalid private key length: expected 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let public_base64 = fs::read_to_string(&pub_path)?.trim().to_string();

    Ok(AgentIdentity {
        namespace,
        id_path,
        server_pub_path,
        signing_key,
        public_base64,
        current_id,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Collect host metadata for the heartbeat payload.
// ─────────────────────────────────────────────────────────────────────────────
fn collect_system_info() -> SystemInfo {
    use sysinfo::{System, Disks, RefreshKind, CpuRefreshKind, MemoryRefreshKind};

    let osinfo = os_info::get();
    let ip = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|e| {
            warn!("Could not determine local IP address: {} — reporting 0.0.0.0", e);
            "0.0.0.0".to_string()
        });

    // Collect telemetry via sysinfo.
    //
    // Refresh ONLY cpu + memory. The previous System::new_all() + refresh_all()
    // enumerated every process on the host — twice — for data this function
    // never reads: it uses cpus(), total_memory() and used_memory() and nothing
    // else. On a container host that walk covers every process in every
    // container (they share the host PID namespace), so it allocated thousands
    // of process structs and their command lines every heartbeat and dropped
    // them again. The agent is a static musl binary and musl's allocator
    // returns very little of that to the OS, so RSS climbed steadily —
    // ~2.9 GB after a week on a busy hypervisor — and it burned CPU doing it.
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::new().with_cpu_usage())
            .with_memory(MemoryRefreshKind::new().with_ram()),
    );
    // CPU usage is a delta between two samples, so take the second one after a
    // brief pause. Only the CPU figures need re-reading here.
    std::thread::sleep(std::time::Duration::from_millis(500));
    sys.refresh_cpu_usage();

    // System-wide CPU usage: average across all logical CPUs.
    let cpu_usage = {
        let cpus = sys.cpus();
        if cpus.is_empty() {
            None
        } else {
            let avg = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32;
            Some((avg * 10.0).round() / 10.0) // round to 1 decimal
        }
    };

    let mem_total_mb = if sys.total_memory() > 0 { Some(sys.total_memory() / 1024 / 1024) } else { None };
    let mem_used_mb  = mem_total_mb.map(|_| sys.used_memory() / 1024 / 1024);

    // Root disk (largest mount or C:\ on Windows).
    let disks = Disks::new_with_refreshed_list();
    let (disk_used_gb, disk_total_gb) = {
        // Pick the disk mounted at "/" (Unix) or with the most total space (Windows/fallback).
        let root = disks.iter()
            .find(|d| d.mount_point().to_str() == Some("/"))
            .or_else(|| disks.iter().max_by_key(|d| d.total_space()));

        if let Some(d) = root {
            let total = d.total_space();
            let avail = d.available_space();
            let used  = total.saturating_sub(avail);
            (Some(used / 1024 / 1024 / 1024), Some(total / 1024 / 1024 / 1024))
        } else {
            (None, None)
        }
    };

    let uptime_secs = Some(System::uptime());

    SystemInfo {
        hostname:     gethostname::gethostname().to_string_lossy().into_owned(),
        ip,
        os:           format!("{} {}", osinfo.os_type(), osinfo.version()),
        arch:         std::env::consts::ARCH.to_string(),
        ver:          env!("CARGO_PKG_VERSION").to_string(),
        cpu_usage,
        mem_used_mb,
        mem_total_mb,
        disk_used_gb,
        disk_total_gb,
        uptime_secs,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Post the signed heartbeat to /send. Returns the parsed SignedResponse on
// success; Ok(None) on transient/recoverable failures (404 → identity reset,
// non-2xx → log+skip) so the caller treats them as "this cycle is over".
// ─────────────────────────────────────────────────────────────────────────────
async fn post_heartbeat(
    http_client:   &reqwest::Client,
    config:        &Config,
    identity:      &AgentIdentity,
    sys:           &SystemInfo,
    send_url:      &str,
    base_url:      &str,
) -> Result<Option<SignedResponse>, Box<dyn std::error::Error>> {
    let needs_handshake = identity.current_id == "0" || !identity.server_pub_path.exists();

    // Container discovery — Linux only, soft-fails on missing runtime / no
    // enumerate() already returns the correct Option semantics:
    //   None      → no runtime / daemon unreachable: omitted from the payload,
    //               server leaves existing rows alone (old servers see nothing).
    //   Some([])  → runtime present, zero running containers: server prunes all
    //               of this host's rows (THIS is what removes a stopped
    //               container's last entry).
    //   Some([…]) → current running set: server upserts + prunes stragglers.
    let containers = crate::containers::enumerate();

    let unsigned = UnsignedPayload {
        id:           identity.current_id.clone(),
        organization: config.server.organization.clone(),
        hostname:     sys.hostname.clone(),
        ver:          sys.ver.clone(),
        ip:           sys.ip.clone(),
        os:           sys.os.clone(),
        arch:         sys.arch.clone(),
        timestamp:    chrono::Utc::now().timestamp().to_string(),
        public_key:   if needs_handshake { Some(identity.public_base64.clone()) } else { None },
        // Send the enrollment token only at registration (alongside the public
        // key handshake) — never on routine heartbeats, so the secret isn't
        // repeatedly transmitted once the system has an ID.
        enrollment_token: if needs_handshake {
            config.server.enrollment_token.clone()
        } else { None },
        cpu_usage:    sys.cpu_usage,
        mem_used_mb:  sys.mem_used_mb,
        mem_total_mb: sys.mem_total_mb,
        disk_used_gb: sys.disk_used_gb,
        disk_total_gb: sys.disk_total_gb,
        uptime_secs:  sys.uptime_secs,
        containers,
    };

    let signature = sign_payload(&unsigned, &identity.signing_key)?;
    let request = SignedRequest { payload: unsigned, signature };

    let response = http_client.post(send_url).json(&request).send().await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        warn!(
            "Server at '{}' rejected ID '{}'. Resetting identity for re-registration.",
            base_url, identity.current_id
        );
        let _ = fs::remove_file(&identity.id_path);
        let _ = fs::remove_file(&identity.server_pub_path);
        return Ok(None);
    }
    if !response.status().is_success() {
        error!("Server returned error status: {}", response.status());
        return Ok(None);
    }

    Ok(Some(response.json::<SignedResponse>().await?))
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify server signature when we have a cached server public key.
// Returns Ok(true) if verified (or no key cached yet — first handshake),
// Ok(false) if verification failed (caller should abort this cycle), or
// Err on I/O failures we cannot recover from.
// ─────────────────────────────────────────────────────────────────────────────
fn verify_response(
    identity:    &AgentIdentity,
    signed_res:  &SignedResponse,
    base_url:    &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !identity.server_pub_path.exists() {
        return Ok(true);
    }

    let server_pub_b64 = fs::read_to_string(&identity.server_pub_path)?;
    let verifier = match decode_public_key(&server_pub_b64) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to load server public key: {}", e);
            return Ok(false);
        }
    };

    if let Err(e) = verify_server_response(&signed_res.payload, &signed_res.signature, &verifier) {
        error!(
            "SECURITY ALERT: Invalid server signature from '{}': {}. \
             Dropping cached server key — will re-handshake next cycle.",
            base_url, e
        );
        let _ = fs::remove_file(&identity.server_pub_path);
        return Ok(false);
    }
    debug!("Server signature verified for '{}'.", base_url);
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch a server response: persist the server public key if included,
// then act on the embedded command (REGISTER / TEST / NONE / unknown).
// ─────────────────────────────────────────────────────────────────────────────
async fn dispatch_server_command(
    config:      &Config,
    identity:    &AgentIdentity,
    http_client: &reqwest::Client,
    result_url:  &str,
    base_url:    &str,
    inner_json:  &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // Save server public key if the server included one this cycle.
    if let Some(server_key) = inner_json.get("server_public_key").and_then(|k| k.as_str()) {
        fs::write(&identity.server_pub_path, server_key.trim())?;
        info!("Server public key saved for namespace '{}'.", identity.namespace);
    }

    match inner_json.get("command").and_then(|c| c.as_str()) {
        Some("REGISTER") => {
            if let Some(new_id) = inner_json.get("id").and_then(|id| id.as_i64()) {
                fs::write(&identity.id_path, new_id.to_string())?;
                info!("Registered with server '{}' as Agent ID: {}.", base_url, new_id);
            } else {
                error!("REGISTER command received but no ID in response.");
            }
        }
        Some("TEST") => {
            if let Some(tests_val) = inner_json.get("data") {
                match serde_json::from_value::<Vec<Test>>(tests_val.clone()) {
                    Ok(tests) => {
                        let cmd_enabled = config.client.cmd_enabled.unwrap_or(false);
                        let ps_enabled  = config.client.ps_enabled.unwrap_or(false);
                        process_compliance_tests(
                            tests,
                            &identity.current_id,
                            &config.server.organization,
                            &identity.signing_key,
                            http_client,
                            result_url,
                            cmd_enabled,
                            ps_enabled,
                        ).await;
                    }
                    Err(e) => error!("Failed to deserialize test data: {}", e),
                }
            } else {
                warn!("TEST command received but no data in response.");
            }
        }
        Some("UPGRADE") => {
            let url = inner_json.get("upgrade_url")
                .and_then(|u| u.as_str())
                .unwrap_or("");
            let expected_sha256 = inner_json.get("upgrade_sha256")
                .and_then(|h| h.as_str())
                .unwrap_or("");
            let version = inner_json.get("upgrade_version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            if url.is_empty() || expected_sha256.is_empty() {
                error!("UPGRADE command missing url or sha256 — ignoring.");
                return Ok(());
            }

            info!("Upgrade to v{} requested — downloading from {}", version, url);

            // Build full URL: relative paths are resolved against the server base.
            let full_url = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("{}{}", base_url, url)
            };

            let bytes = match http_client.get(&full_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Failed to read upgrade download body: {}", e);
                            return Ok(());
                        }
                    }
                }
                Ok(resp) => {
                    error!("Upgrade download failed with HTTP {}", resp.status());
                    return Ok(());
                }
                Err(e) => {
                    error!("Upgrade download request failed: {}", e);
                    return Ok(());
                }
            };

            // Verify SHA256 before touching disk.
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let actual_sha256 = format!("{:x}", hasher.finalize());

            if actual_sha256 != expected_sha256 {
                error!(
                    "Upgrade SHA256 mismatch — expected {} got {}. Aborting.",
                    expected_sha256, actual_sha256
                );
                return Ok(());
            }
            info!("SHA256 verified ({}…)", &actual_sha256[..12]);

            // Write to a temp file next to the current binary (same filesystem →
            // atomic rename). The .new suffix is cleaned up after self_replace.
            let current_exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => {
                    error!("Cannot determine current executable path: {}", e);
                    return Ok(());
                }
            };
            let tmp_path = current_exe.with_extension("new");

            if let Err(e) = fs::write(&tmp_path, &bytes) {
                error!("Failed to write upgrade binary to {:?}: {}", tmp_path, e);
                return Ok(());
            }

            // Make the temp file executable on Unix before replacing.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755));
            }

            // Atomically replace the running binary on disk.
            if let Err(e) = self_replace::self_replace(&tmp_path) {
                error!("self_replace failed: {}", e);
                let _ = fs::remove_file(&tmp_path);
                return Ok(());
            }
            let _ = fs::remove_file(&tmp_path);

            info!("Binary replaced with v{}. Restarting...", version);

            // Restart: exec() replaces the current process image on Unix (systemd
            // detects the restart cleanly). On Windows we spawn a new process and exit.
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(&current_exe)
                    .args(std::env::args().skip(1))
                    .exec();
                // exec() only returns on error.
                error!("exec failed after upgrade: {}", err);
            }

            #[cfg(not(unix))]
            {
                let _ = std::process::Command::new(&current_exe)
                    .args(std::env::args().skip(1))
                    .spawn();
                std::process::exit(0);
            }
        }
        Some("NONE") | None => debug!("Heartbeat OK — no commands pending."),
        Some(unknown)       => warn!("Unknown command received from server: '{}'.", unknown),
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level heartbeat: orchestrates the four steps above. Kept small and
// readable as a flow; each step is testable in isolation.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn send_system_info(
    config:      &Config,
    http_client: &reqwest::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_or_create_identity(config)?;
    let sys      = collect_system_info();

    let base_url   = config.server.url.trim_end_matches('/').to_string();
    let send_url   = format!("{}/send",   base_url);
    let result_url = format!("{}/result", base_url);

    let signed_res = match post_heartbeat(http_client, config, &identity, &sys, &send_url, &base_url).await? {
        Some(r) => r,
        None    => return Ok(()),  // 404 reset or non-2xx — cycle ends here.
    };

    if !verify_response(&identity, &signed_res, &base_url)? {
        return Ok(());
    }

    dispatch_server_command(config, &identity, http_client, &result_url, &base_url, &signed_res.payload).await
}
