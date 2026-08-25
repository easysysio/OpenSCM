// alert_delivery.rs — getting a fired alert to a person.
//
// Deliveries are queued as `pending` by the evaluator and drained here from
// the scheduler's minute loop. That indirection is deliberate: a slow webhook
// must not delay a compliance recalculation, a restart mid-delivery must lose
// nothing (the row is still pending), and retries are naturally rate-limited
// to the tick.
//
// Four transports. `notify` is a local INSERT and cannot fail, which is what
// makes it usable as the fallback when another transport gives up.

use sqlx::{Row, SqlitePool};
use std::net::IpAddr;
use tracing::{error, info, warn};

use crate::alerts::{summary_line, Observation};

/// Give up after this many attempts; backoff below is indexed by attempt.
const MAX_ATTEMPTS: i64 = 3;
/// 1 minute, then 5, then 15.
const BACKOFF_MINUTES: [i64; 3] = [1, 5, 15];
/// A webhook that has not answered by now is not going to.
const HTTP_TIMEOUT_SECS: u64 = 10;


// ─────────────────────────────────────────────────────────────────────────────
// Helper: is_public_ip
// Rejects addresses that a tenant should never be able to make the server talk
// to.
//
// In SaaS the webhook target is attacker-controlled: a tenant can point it at
// http://169.254.169.254/ and read cloud instance metadata out of the response,
// or map the operator's internal network by timing replies. Loopback,
// link-local, private and unspecified ranges are refused.
// ─────────────────────────────────────────────────────────────────────────────
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT — reaches other tenants on
                // some hosting providers.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                // 0.0.0.0/8
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local, fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: validate_webhook_target
// Checks a webhook URL. `strict` is on in SaaS, where the target is supplied
// by a tenant; a self-hosted operator legitimately posts to http://10.0.0.5.
//
// Called at SAVE time and again at DELIVERY time. Checking only once would be
// bypassable: a hostname that resolves publicly when the rule is saved can be
// re-pointed at 169.254.169.254 afterwards.
// ─────────────────────────────────────────────────────────────────────────────
pub fn validate_webhook_target(url: &str, strict: bool) -> Result<(), String> {
    let parsed = url.trim();
    if !strict {
        return if parsed.starts_with("http://") || parsed.starts_with("https://") {
            Ok(())
        } else {
            Err("Webhook URL must start with http:// or https://".into())
        };
    }

    if !parsed.starts_with("https://") {
        return Err("Webhook URL must use https://".into());
    }

    let host = parsed
        .trim_start_matches("https://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return Err("Webhook URL has no host".into());
    }

    // A literal address is checked directly; a name is resolved, and every
    // address it answers with must be acceptable — one public and one private
    // answer is a rebinding attempt.
    let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => std::net::ToSocketAddrs::to_socket_addrs(&(host, 443u16))
            .map_err(|e| format!("Could not resolve {host}: {e}"))?
            .map(|s| s.ip())
            .collect(),
    };
    if addrs.is_empty() {
        return Err(format!("Could not resolve {host}"));
    }
    for ip in addrs {
        if !is_public_ip(ip) {
            return Err(format!(
                "{host} resolves to {ip}, which is not a public address"
            ));
        }
    }
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: tenant_admins
// ─────────────────────────────────────────────────────────────────────────────
async fn tenant_admins(pool: &SqlitePool, tenant_id: &str) -> Vec<i32> {
    sqlx::query_scalar("SELECT id FROM users WHERE tenant_id = ? AND role IN ('admin','superuser')")
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: app_url
// ─────────────────────────────────────────────────────────────────────────────
async fn app_url(pool: &SqlitePool, tenant_id: &str) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE skey = 'app_url' AND tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_default()
}


// ─────────────────────────────────────────────────────────────────────────────
// Struct: Pending
// One queued delivery.
// ─────────────────────────────────────────────────────────────────────────────
struct Pending {
    id: i64,
    tenant_id: String,
    alert_id: Option<i64>,
    policy_id: Option<i64>,
    alert_name: String,
    policy_name: String,
    old_score: f64,
    new_score: f64,
    action: String,
    target: Option<String>,
    attempts: i64,
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: deliver_pending
// Drains the outbox. Called once per scheduler tick.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn deliver_pending(pool: &SqlitePool) {
    let rows = match sqlx::query(
        "SELECT id, tenant_id, alert_id, policy_id, alert_name, policy_name,
                old_score, new_score, action, target, attempts
         FROM alert_deliveries
         WHERE status = 'pending'
           AND (next_retry_at IS NULL OR next_retry_at <= CURRENT_TIMESTAMP)
         ORDER BY fired_at
         LIMIT 50",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to read the alert outbox: {}", e);
            return;
        }
    };

    for row in rows {
        let d = Pending {
            id: row.try_get("id").unwrap_or_default(),
            tenant_id: row.try_get("tenant_id").unwrap_or_default(),
            alert_id: row.try_get("alert_id").ok().flatten(),
            policy_id: row.try_get("policy_id").ok().flatten(),
            alert_name: row.try_get("alert_name").unwrap_or_default(),
            policy_name: row.try_get("policy_name").unwrap_or_default(),
            old_score: row.try_get("old_score").unwrap_or(-1.0),
            new_score: row.try_get("new_score").unwrap_or(-1.0),
            action: row.try_get("action").unwrap_or_else(|_| "notify".into()),
            target: row.try_get("target").ok().flatten(),
            attempts: row.try_get("attempts").unwrap_or(0),
        };

        match dispatch(pool, &d).await {
            Ok(()) => {
                let _ = sqlx::query(
                    "UPDATE alert_deliveries SET status = 'sent', attempts = attempts + 1,
                                                 last_error = NULL
                     WHERE id = ?",
                )
                .bind(d.id)
                .execute(pool)
                .await;
                info!("Alert delivery {} sent via {}", d.id, d.action);
            }
            Err(e) => record_failure(pool, &d, &e).await,
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: record_failure
// Backs off, and on the final attempt tells someone through the one transport
// that cannot itself fail — a silently broken webhook is otherwise invisible.
// ─────────────────────────────────────────────────────────────────────────────
async fn record_failure(pool: &SqlitePool, d: &Pending, err: &str) {
    let next = d.attempts + 1;
    if next >= MAX_ATTEMPTS {
        let _ = sqlx::query(
            "UPDATE alert_deliveries SET status = 'failed', attempts = ?, last_error = ?
             WHERE id = ?",
        )
        .bind(next).bind(err).bind(d.id)
        .execute(pool).await;

        warn!("Alert delivery {} failed permanently via {}: {}", d.id, d.action, err);
        let msg = format!(
            "Alert '{}' could not be delivered via {} after {} attempts: {}",
            d.alert_name, d.action, next, err
        );
        for uid in tenant_admins(pool, &d.tenant_id).await {
            crate::handlers::add_notification(pool, &d.tenant_id, "warning", uid, &msg).await;
        }
        return;
    }

    let mins = BACKOFF_MINUTES[next.clamp(0, 2) as usize];
    let _ = sqlx::query(
        "UPDATE alert_deliveries
         SET attempts = ?, last_error = ?, next_retry_at = datetime('now', ?)
         WHERE id = ?",
    )
    .bind(next).bind(err).bind(format!("+{mins} minutes")).bind(d.id)
    .execute(pool).await;
    warn!("Alert delivery {} failed ({}), retrying in {}m", d.id, err, mins);
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: dispatch
// ─────────────────────────────────────────────────────────────────────────────
async fn dispatch(pool: &SqlitePool, d: &Pending) -> Result<(), String> {
    let obs = Observation { previous: d.old_score, current: d.new_score };
    let summary = summary_line(&d.policy_name, obs);

    match d.action.as_str() {
        "notify" => {
            let admins = tenant_admins(pool, &d.tenant_id).await;
            if admins.is_empty() {
                return Err("no admin users to notify".into());
            }
            let msg = format!("{} — {}", d.alert_name, summary);
            for uid in admins {
                crate::handlers::add_notification(pool, &d.tenant_id, "warning", uid, &msg).await;
            }
            Ok(())
        }

        "email" => {
            let to = d.target.clone().unwrap_or_default();
            if to.trim().is_empty() {
                return Err("no recipient address configured".into());
            }
            let mailer = crate::email::Mailer::from_db(pool)
                .await
                .ok_or("SMTP is not configured")?;
            let base = app_url(pool, &d.tenant_id).await;
            let link = d.policy_id
                .map(|p| format!("{}/policies/report/{}", base.trim_end_matches('/'), p))
                .unwrap_or_default();
            let subject = format!("[OpenSCM] {}", summary);
            let body = format!(
                "<p><strong>{}</strong></p><p>{}</p>{}",
                html_escape(&d.alert_name),
                html_escape(&summary),
                if link.is_empty() { String::new() }
                else { format!("<p><a href=\"{link}\">View the compliance report</a></p>") }
            );
            for addr in to.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                mailer.send(addr, &subject, &body).await?;
            }
            Ok(())
        }

        "webhook" => {
            let url = d.target.clone().unwrap_or_default();
            if url.trim().is_empty() {
                return Err("no webhook URL configured".into());
            }
            // Re-validated here, not just at save time: a hostname that
            // resolved publicly when the rule was created can be re-pointed
            // at an internal address afterwards.
            validate_webhook_target(&url, crate::handlers::is_saas_mode())?;

            let payload = serde_json::json!({
                "version": 1,
                "event": "compliance.alert",
                "tenant": d.tenant_id,
                "alert":  { "id": d.alert_id, "name": d.alert_name },
                "policy": { "id": d.policy_id, "name": d.policy_name },
                "score":  {
                    "previous": d.old_score,
                    "current":  d.new_score,
                    "delta": ((d.new_score - d.old_score) * 100.0).round() / 100.0
                },
            });

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
                // A redirect is a second request to an address that was never
                // validated, which is the whole SSRF trick.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| e.to_string())?;

            let secret: Option<String> = sqlx::query_scalar(
                "SELECT target_secret FROM alerts WHERE id = ?",
            )
            .bind(d.alert_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

            let mut req = client.post(url.trim()).json(&payload);
            if let Some(s) = secret.filter(|s| !s.trim().is_empty()) {
                req = req.header("Authorization", s);
            }
            let resp = req.send().await.map_err(|e| e.to_string())?;
            if resp.status().is_success() {
                Ok(())
            } else {
                // The body is deliberately not read or surfaced: in SaaS it
                // would be a channel for reading whatever the target returns.
                Err(format!("HTTP {}", resp.status().as_u16()))
            }
        }

        "syslog" => {
            let target = d.target.clone().unwrap_or_default();
            if target.trim().is_empty() {
                return Err("no syslog server configured".into());
            }
            send_syslog(&target, &d.alert_name, &d.policy_name, obs).await
        }

        other => Err(format!("unknown action '{other}'")),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: html_escape
// The alert and policy names reach an HTML email body.
// ─────────────────────────────────────────────────────────────────────────────
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: send_syslog
// RFC 5424 over UDP. No crate needed — a datagram and a format string.
//
// UDP delivery is fire-and-forget: a successful socket write is as much
// confirmation as the protocol offers, and the UI says so rather than implying
// the message arrived.
// ─────────────────────────────────────────────────────────────────────────────
async fn send_syslog(
    target: &str,
    alert_name: &str,
    policy_name: &str,
    obs: Observation,
) -> Result<(), String> {
    let addr = if target.contains(':') { target.to_string() } else { format!("{target}:514") };

    // facility 13 (log audit) * 8 + severity. A large fall is a warning, a
    // smaller move a notice, an improvement merely informational.
    let delta = obs.current - obs.previous;
    let severity = if delta <= -25.0 { 4 } else if delta < 0.0 { 5 } else { 6 };
    let pri = 13 * 8 + severity;

    let host = gethostname_string();
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let msg = format!(
        "<{pri}>1 {ts} {host} openscm - COMPLIANCE [openscm@99999 policy=\"{}\" prev=\"{:.2}\" curr=\"{:.2}\"] {} — {}",
        escape_sd(policy_name), obs.previous, obs.current,
        escape_sd(alert_name), summary_line(policy_name, obs)
    );

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("syslog socket: {e}"))?;
    sock.send_to(msg.as_bytes(), &addr)
        .await
        .map_err(|e| format!("syslog send to {addr}: {e}"))?;
    Ok(())
}

// RFC 5424 structured data escapes ", \ and ].
fn escape_sd(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace(']', "\\]")
}

fn gethostname_string() -> String {
    std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "openscm".into())
}
