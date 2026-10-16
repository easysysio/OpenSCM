// =============================================================================
// email.rs — SMTP mailer backed by DB settings
//
// Reads smtp_* keys from the `settings` table (default tenant) and builds an
// async lettre transport.  All three editions share this module:
//   - CE/EE: uses it for the test-email handler in settings.rs
//   - SaaS:  uses it for verification, password-reset, and support emails
// =============================================================================
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
    message::{
        header::ContentType,
        Attachment, MultiPart, SinglePart,
    },
};
use sqlx::{SqlitePool, Row};
use tracing::{error, info};

// ─────────────────────────────────────────────────────────────────────────────
// Mailer
// Holds a ready-to-use SMTP transport and the configured from-address / app URL.
// ─────────────────────────────────────────────────────────────────────────────
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    pub from:    String,
    pub app_url: String,
}

impl Mailer {
    // ─────────────────────────────────────────────────────────────────────────
    // from_db
    // Load SMTP settings from the `settings` table (default tenant).
    // Returns None when smtp_host is not configured.
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn from_db(pool: &SqlitePool) -> Option<Self> {
        let rows = sqlx::query(
            "SELECT skey, value FROM settings WHERE tenant_id = 'default'
             AND skey IN ('smtp_host','smtp_port','smtp_username','smtp_password',
                         'smtp_from','smtp_tls','app_url')"
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        let mut map = std::collections::HashMap::new();
        for row in rows {
            let key: String = row.get("skey");
            let val: String = row.get("value");
            map.insert(key, val);
        }

        let host = map.get("smtp_host").cloned().unwrap_or_default();
        if host.is_empty() {
            return None;
        }

        let port: u16  = map.get("smtp_port").and_then(|v| v.parse().ok()).unwrap_or(587);
        let username   = map.get("smtp_username").cloned().unwrap_or_default();
        let password   = crate::secrets::open_or_empty(
            crate::secrets::COL_SMTP_PASSWORD,
            &map.get("smtp_password").cloned().unwrap_or_default(),
        );
        let from       = map.get("smtp_from").cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("OpenSCM <noreply@{}>", host));
        let tls_mode   = map.get("smtp_tls").cloned().unwrap_or_else(|| "starttls".into());
        let app_url    = map.get("app_url").cloned().unwrap_or_default();

        let transport = match build_transport(&host, port, &tls_mode, &username, &password) {
            Ok(t) => t,
            Err(e) => { error!("Failed to build SMTP transport: {}", e); return None; }
        };

        Some(Mailer { transport, from, app_url })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // send — internal generic helper
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), String> {
        let message = Message::builder()
            .from(self.from.parse().map_err(|e| format!("Invalid from address: {}", e))?)
            .to(to.parse().map_err(|e| format!("Invalid to address: {}", e))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| format!("Failed to build message: {}", e))?;

        self.transport.send(message).await.map_err(|e| {
            let msg = format!("SMTP send error: {}", e);
            error!("{}", msg);
            msg
        })?;

        info!("Email sent to {}", to);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // send_with_attachment — HTML body + a single binary attachment.
    // Used by the "Email Me PDF" buttons on the report view pages. `mime`
    // should be a parsable Content-Type like "application/pdf".
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn send_with_attachment(
        &self,
        to: &str,
        subject: &str,
        html_body: &str,
        filename: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        let mime_parsed: ContentType = mime.parse()
            .map_err(|e| format!("Invalid attachment MIME '{}': {}", mime, e))?;

        let html_part = SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string());

        // Attachment::new builds a SinglePart with Content-Disposition: attachment
        // and the filename baked in.
        let attachment = Attachment::new(filename.to_string())
            .body(bytes, mime_parsed);

        let multipart = MultiPart::mixed()
            .singlepart(html_part)
            .singlepart(attachment);

        let message = Message::builder()
            .from(self.from.parse().map_err(|e| format!("Invalid from address: {}", e))?)
            .to(to.parse().map_err(|e| format!("Invalid to address: {}", e))?)
            .subject(subject)
            .multipart(multipart)
            .map_err(|e| format!("Failed to build message: {}", e))?;

        self.transport.send(message).await.map_err(|e| {
            let msg = format!("SMTP send error: {}", e);
            error!("{}", msg);
            msg
        })?;

        info!("Email with attachment '{}' sent to {}", filename, to);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // send_verification — email address verification link
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn send_verification(&self, to: &str, token: &str) -> Result<(), String> {
        let url = format!("{}/verify-email?token={}", self.app_url.trim_end_matches('/'), token);
        let html = format!(
            r#"<p>Welcome to OpenSCM!</p>
<p>Click the link below to verify your email address and activate your account:</p>
<p><a href="{url}" style="font-size:16px">{url}</a></p>
<p>This link expires in <strong>24 hours</strong>.</p>
<p>If you did not create an OpenSCM account, you can safely ignore this email.</p>"#
        );
        self.send(to, "Verify your OpenSCM account", &html).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // send_password_reset — password-reset link
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn send_password_reset(&self, to: &str, token: &str) -> Result<(), String> {
        let url = format!("{}/reset-password?token={}", self.app_url.trim_end_matches('/'), token);
        let html = format!(
            r#"<p>You requested a password reset for your OpenSCM account.</p>
<p>Click the link below to set a new password:</p>
<p><a href="{url}" style="font-size:16px">{url}</a></p>
<p>This link expires in <strong>1 hour</strong>.</p>
<p>If you did not request this reset, you can safely ignore this email.</p>"#
        );
        self.send(to, "Reset your OpenSCM password", &html).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // send_support_ticket — internal forwarding to support inbox
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn send_support_ticket(
        &self,
        user_name:  &str,
        user_email: &str,
        org_name:   &str,
        subject:    &str,
        priority:   &str,
        message:    &str,
    ) -> Result<(), String> {
        let html = format!(
            r#"<p><strong>Support ticket from OpenSCM SaaS</strong></p>
<hr>
<table style="font-family:monospace;font-size:14px;border-collapse:collapse">
  <tr><td style="padding:4px 12px 4px 0"><strong>User:</strong></td><td>{user_name}</td></tr>
  <tr><td style="padding:4px 12px 4px 0"><strong>Email:</strong></td><td>{user_email}</td></tr>
  <tr><td style="padding:4px 12px 4px 0"><strong>Organization:</strong></td><td>{org_name}</td></tr>
  <tr><td style="padding:4px 12px 4px 0"><strong>Priority:</strong></td><td>{priority}</td></tr>
</table>
<hr>
<p><strong>Message:</strong></p>
<p style="white-space:pre-wrap">{message}</p>"#
        );
        let full_subject = format!("[Support] [{}] {}", priority, subject);

        let mut builder = Message::builder()
            .from(self.from.parse().map_err(|e| format!("Invalid from address: {}", e))?)
            .to("OpenSCM Support <support@openscm.io>".parse().map_err(|e| format!("Invalid to: {}", e))?)
            .subject(full_subject)
            .header(ContentType::TEXT_HTML);

        if !user_email.is_empty() {
            if let Ok(addr) = user_email.parse() { builder = builder.reply_to(addr); }
            if let Ok(addr) = user_email.parse() { builder = builder.cc(addr); }
        }

        let msg = builder.body(html).map_err(|e| format!("Failed to build message: {}", e))?;

        self.transport.send(msg).await.map_err(|e| {
            let err = format!("SMTP send error: {}", e);
            error!("{}", err);
            err
        })?;

        info!("Support ticket sent for user '{}' org '{}'", user_name, org_name);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// build_transport — construct a lettre async SMTP transport
// Shared by Mailer::from_db and the settings test-email handler.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_transport(
    host:     &str,
    port:     u16,
    tls_mode: &str,
    username: &str,
    password: &str,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let creds = if !username.is_empty() {
        Some(Credentials::new(username.to_string(), password.to_string()))
    } else {
        None
    };

    let transport = match tls_mode {
        "tls" => {
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| format!("SMTP relay error: {}", e))?
                .port(port);
            if let Some(c) = creds { b = b.credentials(c); }
            b.build()
        }
        "none" => {
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port);
            if let Some(c) = creds { b = b.credentials(c); }
            b.build()
        }
        _ => {
            // "starttls" (default) or anything else
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| format!("SMTP starttls relay error: {}", e))?
                .port(port);
            if let Some(c) = creds { b = b.credentials(c); }
            b.build()
        }
    };

    Ok(transport)
}
