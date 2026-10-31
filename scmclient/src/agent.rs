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

// The agent protocol this agent speaks (docs/design/0.11.0-agent-protocol.md,
// D5). 1: requests carry protocol, nonce and sent_at_ms, and replies must
// repeat the nonce.
pub(crate) const PROTOCOL: i64 = 1;

// How long an upgrade download may take, start to finish. The 15-second
// client timeout covers everything else.
const UPGRADE_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

static LAST_SENT_AT_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// next_sent_at_ms — the send time for the next request: now in ms, but always
// later than the previous one. The server refuses a request that is not newer
// than the last it accepted (design D3), and heartbeats and results share this
// clock, so two results in the same millisecond, or a clock stepped back by
// NTP, must not make the agent send an older time.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn next_sent_at_ms() -> i64 {
    use std::sync::atomic::Ordering;
    let now = chrono::Utc::now().timestamp_millis();
    let mut prev = LAST_SENT_AT_MS.load(Ordering::SeqCst);
    loop {
        let next = now.max(prev + 1);
        match LAST_SENT_AT_MS.compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(actual) => prev = actual,
        }
    }
}

// A fresh random nonce (128 bits, hex).
fn new_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// check_binding — whether a reply answers the request that carried `nonce`
// (design D3). A reply that says it speaks a protocol must repeat our nonce.
// One that does not is from a server older than protocol 1 — acceptable only
// until this agent has seen its server speak protocol 1 (`ratcheted`); after
// that, a reply without a protocol can only be a recording of an old one.
// Ok(true): the server speaks protocol 1.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn check_binding(reply: &serde_json::Value, nonce: &str, ratcheted: bool) -> Result<bool, String> {
    match reply.get("protocol").and_then(|p| p.as_i64()) {
        Some(_) => match reply.get("nonce").and_then(|n| n.as_str()) {
            Some(n) if n == nonce => Ok(true),
            _ => Err("the reply does not carry this request's nonce (a replayed reply?)".into()),
        },
        None if ratcheted => Err("the server speaks protocol 1 but this reply has no protocol (a replayed old reply?)".into()),
        None => Ok(false),
    }
}

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
        protocol: Some(PROTOCOL),
        sent_at_ms: Some(next_sent_at_ms()),
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
            let status = resp.status();
            error!(
                "Server rejected result for test {} with status {}: {}",
                test_id, status, server_error(resp).await
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

    // Start each scan from a clean CMD cache. Within one scan a repeated
    // command runs once (the CIS Debian profile asks `sshd -T` twenty
    // separate questions); across scans nothing is reused, so a remediation
    // applied between two scans shows up in the next one.
    crate::compliance::reset_cmd_cache();

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
    protocol_path:   PathBuf,
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
    // Present once the server has been seen speaking protocol 1 (check_binding).
    let protocol_path   = key_dir.join(format!("server_{}.protocol", namespace));

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
        protocol_path,
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
    nonce:         &str,
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
        server_key:   fs::read_to_string(&identity.server_pub_path).ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty()),
        protocol:     Some(PROTOCOL),
        nonce:        Some(nonce.to_string()),
        sent_at_ms:   Some(next_sent_at_ms()),
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
        // The system was deleted on the server: register again. The pinned
        // server key is KEPT — an unsigned 404 is not a reason to trust a new
        // one (design D1); the registration reply must verify against it.
        warn!(
            "Server at '{}' rejected ID '{}'. Resetting the ID for re-registration.",
            base_url, identity.current_id
        );
        let _ = fs::remove_file(&identity.id_path);
        return Ok(None);
    }
    if !response.status().is_success() {
        let status = response.status();
        error!("Server returned error status {}: {}", status, server_error(response).await);
        return Ok(None);
    }

    Ok(Some(response.json::<SignedResponse>().await?))
}

// ─────────────────────────────────────────────────────────────────────────────
// download_upgrade — fetch an upgrade binary within `limit`. The agent's
// client allows 15 s per request, right for a check-in but not for an ~10 MB
// binary over a slow link: the download was cut off, and reported as "error
// decoding response body" (the body arrives compressed). A per-request
// timeout replaces the client's for this one request, connect to last byte.
// ─────────────────────────────────────────────────────────────────────────────
async fn download_upgrade(
    http_client: &reqwest::Client,
    url: &str,
    limit: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let resp = http_client.get(url).timeout(limit).send().await
        .map_err(|e| format!("Upgrade download request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Upgrade download failed with HTTP {}", resp.status()));
    }
    resp.bytes().await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read upgrade download body: {e} (gave up after {}s)", limit.as_secs()))
}

// ─────────────────────────────────────────────────────────────────────────────
// server_error — the server's `{"error": "..."}` message, for the log. The
// server says what to fix (clock out of sync, unsupported protocol, rate
// limit), so it is worth showing rather than just the status code.
// ─────────────────────────────────────────────────────────────────────────────
async fn server_error(resp: reqwest::Response) -> String {
    resp.json::<serde_json::Value>().await.ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| "(no detail)".into())
}

// ─────────────────────────────────────────────────────────────────────────────
// How far a server reply can be trusted.
//   Verified — signed by the server key pinned on disk.
//   Unpinned — no key pinned yet (first registration, or after
//              `scmclient --reset-server-key`): the reply may only register
//              us and hand over the key to pin. It cannot run anything.
//   Rejected — a key is pinned and the reply is not signed by it. Refused and
//              the pinned key KEPT: dropping it on a bad reply is what let
//              anyone on the network make the agent trust a key of their
//              choosing (docs/design/0.11.0-agent-protocol.md, D1).
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq)]
pub(crate) enum Trust {
    Verified,
    Unpinned,
    Rejected,
}

// ─────────────────────────────────────────────────────────────────────────────
// check_trust — the decision above, for a reply and the pinned key (if any).
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn check_trust(pinned_b64: Option<&str>, signed_res: &SignedResponse) -> Trust {
    let Some(pinned) = pinned_b64.map(str::trim).filter(|k| !k.is_empty()) else {
        return Trust::Unpinned;
    };
    match decode_public_key(pinned) {
        Ok(verifier) => match verify_server_response(&signed_res.payload, &signed_res.signature, &verifier) {
            Ok(()) => Trust::Verified,
            Err(_) => Trust::Rejected,
        },
        // A pinned key we cannot read is not "no key": refuse, never re-pin.
        Err(_) => Trust::Rejected,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// command_allowed — whether a reply at this trust level may carry `command`.
// Without a pinned key only registration (and doing nothing) is accepted.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn command_allowed(trust: &Trust, command: Option<&str>) -> bool {
    match trust {
        Trust::Verified => true,
        Trust::Unpinned => matches!(command, None | Some("REGISTER") | Some("NONE")),
        Trust::Rejected => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Read the pinned key and judge the reply; logs a refusal.
// ─────────────────────────────────────────────────────────────────────────────
fn verify_response(
    identity:    &AgentIdentity,
    signed_res:  &SignedResponse,
    base_url:    &str,
) -> Trust {
    let pinned = fs::read_to_string(&identity.server_pub_path).ok();
    let trust = check_trust(pinned.as_deref(), signed_res);
    match trust {
        Trust::Verified => debug!("Server signature verified for '{}'.", base_url),
        Trust::Unpinned => info!("No server key pinned for '{}' yet; accepting registration only.", base_url),
        Trust::Rejected => error!(
            "SECURITY ALERT: reply from '{}' is not signed by the pinned server key. Refused; \
             the pinned key is kept. If the server was reinstalled or its key replaced, run \
             `scmclient --reset-server-key` on this host to trust the new one.",
            base_url
        ),
    }
    trust
}

// ─────────────────────────────────────────────────────────────────────────────
// reset_server_key — `scmclient --reset-server-key`: forget the pinned key for
// the configured server so the next registration reply pins a new one.
// Returns the removed file, or None if none was pinned.
// ─────────────────────────────────────────────────────────────────────────────
pub fn reset_server_key(config: &Config) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let identity = load_or_create_identity(config)?;
    // A new server may speak an older protocol; it is learned again too.
    let _ = fs::remove_file(&identity.protocol_path);
    if identity.server_pub_path.exists() {
        fs::remove_file(&identity.server_pub_path)?;
        Ok(Some(identity.server_pub_path))
    } else {
        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// upgrade_source — where an UPGRADE may be downloaded from, or why not.
//   • Only from our own server: a path, or a URL with the same scheme, host
//     and port as base_url. Never an address the reply merely names.
//   • Only to a newer version than the running one (no downgrades, which a
//     replayed old reply could otherwise cause).
// docs/design/0.11.0-agent-protocol.md, D4.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn upgrade_source(base_url: &str, url: &str, current: &str, target: &str) -> Result<String, String> {
    match (parse_version(current), parse_version(target)) {
        (Some(c), Some(t)) if t > c => {}
        (Some(_), Some(_)) => return Err(format!("v{target} is not newer than the running v{current}")),
        _ => return Err(format!("cannot compare versions '{current}' and '{target}'")),
    }
    let base = reqwest::Url::parse(base_url).map_err(|e| format!("bad server URL: {e}"))?;
    if url.starts_with('/') && !url.starts_with("//") {
        return Ok(format!("{}{}", base_url.trim_end_matches('/'), url));
    }
    let target_url = reqwest::Url::parse(url).map_err(|e| format!("bad upgrade URL: {e}"))?;
    if target_url.scheme() == base.scheme()
        && target_url.host_str() == base.host_str()
        && target_url.port_or_known_default() == base.port_or_known_default()
    {
        Ok(url.to_string())
    } else {
        Err(format!("{url} is not on this agent's server"))
    }
}

// "1.2.3" (anything after a '-' or '+' ignored) → (1, 2, 3).
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    if it.next().is_some() { return None; }
    Some(v)
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
    trust:       &Trust,
) -> Result<(), Box<dyn std::error::Error>> {
    let command = inner_json.get("command").and_then(|c| c.as_str());

    match trust {
        // Nothing pinned yet: the registration reply hands us the key to pin
        // (trust on first use — the one moment it is unavoidable).
        Trust::Unpinned => {
            if let Some(server_key) = inner_json.get("server_public_key").and_then(|k| k.as_str()) {
                if decode_public_key(server_key.trim()).is_ok() {
                    fs::write(&identity.server_pub_path, server_key.trim())?;
                    info!("Server public key pinned for namespace '{}'.", identity.namespace);
                }
            }
        }
        // A reply signed by the key we trust may hand over its successor
        // (rotation, design D2). `server_public_key` is never taken from a
        // verified reply: the pin only changes this way.
        Trust::Verified => {
            if let Some(next) = inner_json.get("next_server_public_key").and_then(|k| k.as_str()) {
                if decode_public_key(next.trim()).is_ok() {
                    fs::write(&identity.server_pub_path, next.trim())?;
                    info!("Server signing key rotated; now trusting the new key for namespace '{}'.",
                          identity.namespace);
                }
            }
        }
        Trust::Rejected => return Ok(()),
    }

    if !command_allowed(trust, command) {
        warn!(
            "Ignoring '{}' from '{}': no server key is pinned yet, so only registration is accepted.",
            command.unwrap_or(""), base_url
        );
        return Ok(());
    }

    match command {
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

            let full_url = match upgrade_source(base_url, url, env!("CARGO_PKG_VERSION"), version) {
                Ok(u) => u,
                Err(why) => {
                    error!("UPGRADE to v{} refused: {}.", version, why);
                    return Ok(());
                }
            };
            info!("Upgrade to v{} requested — downloading from {}", version, full_url);

            let bytes = match download_upgrade(http_client, &full_url, UPGRADE_DOWNLOAD_TIMEOUT).await {
                Ok(b) => b,
                Err(why) => {
                    error!("{}", why);
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

            // Give the new binary the mode of the one it replaces, so the
            // upgrade keeps whatever the package installed, minus any
            // setuid/setgid bits. 0o700 only if that cannot be read: the agent
            // runs it as its own user.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&current_exe)
                    .map(|m| m.permissions().mode() & 0o777)
                    .unwrap_or(0o700);
                let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode));
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

    let nonce = new_nonce();
    let signed_res = match post_heartbeat(http_client, config, &identity, &sys, &send_url, &base_url, &nonce).await? {
        Some(r) => r,
        None    => return Ok(()),  // 404 reset or non-2xx — cycle ends here.
    };

    let trust = verify_response(&identity, &signed_res, &base_url);
    if trust == Trust::Rejected {
        return Ok(());
    }

    // The reply must answer THIS request (design D3).
    match check_binding(&signed_res.payload, &nonce, identity.protocol_path.exists()) {
        Ok(speaks_protocol) => {
            // Remember, from a reply signed by the pinned key only, that this
            // server speaks protocol 1: from then on old-style replies are refused.
            if speaks_protocol && trust == Trust::Verified && !identity.protocol_path.exists() {
                let _ = fs::write(&identity.protocol_path, PROTOCOL.to_string());
                info!("Server '{}' speaks agent protocol {}; replies are now bound to their request.", base_url, PROTOCOL);
            }
        }
        Err(why) => {
            error!("SECURITY ALERT: reply from '{}' refused: {}.", base_url, why);
            return Ok(());
        }
    }

    dispatch_server_command(config, &identity, http_client, &result_url, &base_url, &signed_res.payload, &trust).await
}


#[cfg(test)]
mod tests {
    use super::*;

    // A reply signed by `key`, the way the server signs: serde_json bytes of
    // the payload value.
    fn reply(key: &SigningKey, payload: serde_json::Value) -> SignedResponse {
        let sig = key.sign(&serde_json::to_vec(&payload).unwrap());
        SignedResponse { payload, signature: general_purpose::STANDARD.encode(sig.to_bytes()) }
    }
    fn pub_b64(key: &SigningKey) -> String {
        general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
    }

    #[test]
    fn a_reply_signed_by_the_pinned_key_is_verified() {
        let server = SigningKey::from_bytes(&[1u8; 32]);
        let r = reply(&server, serde_json::json!({"command": "TEST"}));
        assert_eq!(check_trust(Some(&pub_b64(&server)), &r), Trust::Verified);
    }

    #[test]
    fn a_reply_signed_by_any_other_key_is_rejected_not_re_trusted() {
        let server = SigningKey::from_bytes(&[1u8; 32]);
        let attacker = SigningKey::from_bytes(&[2u8; 32]);
        let r = reply(&attacker, serde_json::json!({"command": "UPGRADE", "server_public_key": pub_b64(&attacker)}));
        assert_eq!(check_trust(Some(&pub_b64(&server)), &r), Trust::Rejected);
        // Garbage instead of a signature, or an unreadable pin, is no better.
        let mut bad = reply(&server, serde_json::json!({"command": "NONE"}));
        bad.signature = "not-a-signature".into();
        assert_eq!(check_trust(Some(&pub_b64(&server)), &bad), Trust::Rejected);
        assert_eq!(check_trust(Some("corrupt-pin"), &reply(&server, serde_json::json!({}))), Trust::Rejected);
    }

    #[test]
    fn without_a_pin_a_reply_may_only_register() {
        let anyone = SigningKey::from_bytes(&[3u8; 32]);
        let r = reply(&anyone, serde_json::json!({"command": "REGISTER"}));
        let t = check_trust(None, &r);
        assert_eq!(t, Trust::Unpinned);
        assert!(command_allowed(&t, Some("REGISTER")));
        assert!(command_allowed(&t, Some("NONE")));
        assert!(command_allowed(&t, None));
        assert!(!command_allowed(&t, Some("TEST")), "tests must not run on an unverified reply");
        assert!(!command_allowed(&t, Some("UPGRADE")), "upgrades must not run on an unverified reply");
        assert!(!command_allowed(&Trust::Rejected, Some("NONE")));
        assert!(command_allowed(&Trust::Verified, Some("UPGRADE")));
    }

    #[test]
    fn upgrades_come_only_from_our_own_server() {
        let base = "https://scm.example.com";
        assert_eq!(upgrade_source(base, "/agents/scmclient-x86_64-linux", "0.10.3", "0.10.4").unwrap(),
                   "https://scm.example.com/agents/scmclient-x86_64-linux");
        assert_eq!(upgrade_source("https://scm.example.com/", "/agents/a", "0.10.3", "0.10.4").unwrap(),
                   "https://scm.example.com/agents/a");
        assert!(upgrade_source(base, "https://scm.example.com:443/agents/a", "0.10.3", "0.10.4").is_ok());
        for evil in [
            "https://evil.example/agents/a",
            "http://scm.example.com/agents/a",        // scheme differs
            "https://scm.example.com:8443/agents/a",  // port differs
            "//evil.example/agents/a",                 // protocol-relative
            "https://scm.example.com.evil.example/a",
        ] {
            assert!(upgrade_source(base, evil, "0.10.3", "0.10.4").is_err(), "{evil} accepted");
        }
    }

    #[test]
    fn a_reply_must_carry_this_requests_nonce() {
        let ok = serde_json::json!({"protocol": 1, "nonce": "abc", "command": "TEST"});
        assert_eq!(check_binding(&ok, "abc", false), Ok(true));
        assert_eq!(check_binding(&ok, "abc", true), Ok(true));
        // A recording of a reply to an earlier request.
        let old = serde_json::json!({"protocol": 1, "nonce": "zzz", "command": "TEST"});
        assert!(check_binding(&old, "abc", true).is_err());
        let missing = serde_json::json!({"protocol": 1, "command": "TEST"});
        assert!(check_binding(&missing, "abc", false).is_err());
    }

    #[test]
    fn old_style_replies_are_accepted_only_until_the_server_spoke_protocol_1() {
        let legacy = serde_json::json!({"command": "TEST"});
        assert_eq!(check_binding(&legacy, "abc", false), Ok(false), "a server older than protocol 1");
        assert!(check_binding(&legacy, "abc", true).is_err(), "a replayed pre-upgrade reply");
    }

    #[test]
    fn the_send_clock_never_goes_backwards() {
        let mut prev = next_sent_at_ms();
        for _ in 0..10_000 {
            let t = next_sent_at_ms();
            assert!(t > prev, "{t} is not after {prev}");
            prev = t;
        }
        // Even if the wall clock falls far behind the last value sent.
        LAST_SENT_AT_MS.store(i64::MAX / 2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(next_sent_at_ms(), i64::MAX / 2 + 1);
    }

    // The fix for slow links: a download that takes longer than the agent's
    // 15-second request timeout still completes. Takes ~17 s to run.
    #[tokio::test]
    async fn an_upgrade_download_may_outlast_the_check_in_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let body = vec![b'x'; 17];
            s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            // One byte a second: 17 s in all.
            for b in body {
                s.write_all(&[b]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        // The agent's real client settings (main.rs), which installs the
        // TLS provider first, as main does.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().unwrap();
        let got = download_upgrade(&client, &format!("http://{addr}/agents/x"), UPGRADE_DOWNLOAD_TIMEOUT).await;
        assert_eq!(got.map(|b| b.len()), Ok(17));
    }

    #[test]
    fn upgrades_never_go_backwards() {
        let base = "http://10.0.0.5:8000";
        assert!(upgrade_source(base, "/agents/a", "0.10.4", "0.10.4").is_err(), "same version");
        assert!(upgrade_source(base, "/agents/a", "0.10.4", "0.9.9").is_err(), "downgrade");
        assert!(upgrade_source(base, "/agents/a", "0.9.9", "0.10.0").is_ok(), "numeric, not text, order");
        assert!(upgrade_source(base, "/agents/a", "0.10.4", "unknown").is_err());
    }
}
