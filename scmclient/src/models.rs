use serde::{Serialize, Deserialize};

use crate::containers::DiscoveredContainer;

// =========================
// 1. IDENTITY & HEARTBEAT
// =========================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnsignedPayload {
    pub id: String,
    pub organization: String,
    pub hostname: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
    pub timestamp: String,
    pub public_key: Option<String>,
    /// Golden enrollment token — sent only at first registration (id = 0).
    /// Omitted entirely otherwise so heartbeats never carry the secret and old
    /// servers see no new field. See docs/design/0.6.0-enrollment-tokens.md.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    /// The server public key this agent has pinned (base64), so during a key
    /// rotation the server signs with the key we trust and hands us the new
    /// one. Omitted until a key is pinned. See
    /// docs/design/0.11.0-agent-protocol.md, D2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_key: Option<String>,
    /// Agent protocol version; see agent::PROTOCOL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
    /// Random per request; the server repeats it inside its signed reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Send time in ms since the epoch, never going backwards (agent::next_sent_at_ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at_ms: Option<i64>,
    // Telemetry — optional so old servers ignore unknown fields gracefully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_usage:    Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_mb:  Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_used_gb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total_gb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs:  Option<u64>,
    /// App-container inventory (Docker / Podman). Omitted entirely on non-Linux
    /// or when no runtime is installed so old servers see no new field at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers:   Option<Vec<DiscoveredContainer>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRequest<T> {
    pub payload: T,
    pub signature: String,
}

// =========================
// 2. SERVER COMMANDS
// =========================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedResponse {
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Test {
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


#[derive(Debug, Serialize, Deserialize, Clone)]
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


// =========================
// 3. RESULTS
// =========================

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    pub organization: String,
    pub test_id: i64,
    pub result: String, // "PASS", "FAIL", or "NA"
    /// Container runtime ID (e.g. Docker's sha256 container ID) when this
    /// result is per-container. Omitted for host-level results. Server
    /// resolves to containers.id via (host_system_id, runtime_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_runtime_id: Option<String>,
    /// Per-condition evidence (JSON array of ConditionOutcome) explaining the
    /// verdict — which conditions matched/failed and a generic, content-free
    /// note. Omitted when absent so old servers ignore the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// See UnsignedPayload. Results share the heartbeat's increasing clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at_ms: Option<i64>,
}

