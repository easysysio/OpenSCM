// =============================================================================
// net_guard.rs — outbound requests to addresses someone else chose
//
// Alert webhooks and SSO providers both make the server fetch a URL that a
// tenant typed in. In SaaS that is an attacker-controlled destination: pointed
// at http://169.254.169.254/ it reads cloud instance metadata back out of the
// response, and pointed around the operator's network it maps it by timing.
//
// One definition of "an address a tenant may make us talk to", used by both:
//
//   check_url    validates a URL and resolves its host, refusing (in strict
//                mode) anything that is not https to a public address.
//   client_for   builds the HTTP client for the request itself, PINNED to the
//                addresses check_url accepted and with redirects off.
//
// Pinning is the point of returning the addresses. Validating a name and then
// letting the HTTP client resolve it again is two lookups, and a hostname can
// answer the first with a public address and the second with 169.254.169.254.
// =============================================================================

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Public: is_public_ip
// False for addresses a tenant should never be able to make the server talk
// to: loopback, private, link-local, unspecified, carrier-grade NAT and the
// like.
//
// An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is judged as the IPv4 address
// it maps to. It used to be judged as IPv6 — where none of the IPv6 rules
// match it — so a AAAA record answering ::ffff:169.254.169.254 was "public",
// while a connection to it goes to 169.254.169.254.
// ─────────────────────────────────────────────────────────────────────────────
pub fn is_public_ip(ip: IpAddr) -> bool {
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
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local, fe80::/10 link-local
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xffc0) == 0xfe80
                // ::a.b.c.d, the deprecated IPv4-compatible form
                || (seg[0..6] == [0, 0, 0, 0, 0, 0] && (seg[6] != 0 || seg[7] > 1))
                // 64:ff9b::/96, NAT64 — an IPv4 address behind a translator
                || (seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0]))
        }
    }
}

/// A URL that passed check_url, with what is needed to request it safely.
#[derive(Debug, Clone)]
pub struct Target {
    pub url:  String,
    pub host: String,
    /// The addresses the host resolved to and that were checked. Empty in
    /// non-strict mode, where nothing is resolved or pinned.
    pub addrs: Vec<SocketAddr>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: check_url
// Validates an outbound URL. `what` names it in messages ("Webhook URL").
//
// Non-strict (self-hosted): any http:// or https:// URL with a host. An
// operator legitimately posts to http://10.0.0.5 or federates with an internal
// Keycloak.
//
// Strict (SaaS, where the URL comes from a tenant): https only, and EVERY
// address the host resolves to must be public — one public and one private
// answer is a rebinding attempt, not a mistake.
//
// Call it when the URL is saved and again immediately before each request, and
// make the request with client_for(&target).
// ─────────────────────────────────────────────────────────────────────────────
pub fn check_url(url: &str, strict: bool, what: &str) -> Result<Target, String> {
    let trimmed = url.trim();
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|_| format!("{what} must start with http:// or https://"))?;

    match parsed.scheme() {
        "https" => {}
        "http" if !strict => {}
        "http" => return Err(format!("{what} must use https://")),
        _ => return Err(format!("{what} must start with http:// or https://")),
    }

    // host_str() brackets an IPv6 literal; keep the bare form. A literal
    // address is checked as it stands; a name is resolved below.
    let host_name = parsed
        .host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host_name.is_empty() {
        return Err(format!("{what} has no host"));
    }

    if !strict {
        return Ok(Target { url: trimmed.to_string(), host: host_name, addrs: Vec::new() });
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = match host_name.parse::<IpAddr>() {
        Ok(literal) => vec![SocketAddr::new(literal, port)],
        Err(_) => std::net::ToSocketAddrs::to_socket_addrs(&(host_name.as_str(), port))
            .map_err(|e| format!("Could not resolve {host_name}: {e}"))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(format!("Could not resolve {host_name}"));
    }
    for a in &addrs {
        if !is_public_ip(a.ip()) {
            return Err(format!(
                "{host_name} resolves to {}, which is not a public address",
                a.ip()
            ));
        }
    }

    Ok(Target { url: trimmed.to_string(), host: host_name, addrs })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: client_for
// The HTTP client for a request to `target`.
//
//   • Redirects are off: a redirect is a second request to an address nobody
//     validated, which is the whole SSRF trick.
//   • When check_url resolved the host (strict mode), the client is pinned to
//     exactly those addresses, so the name cannot be re-pointed between the
//     check and the request.
// ─────────────────────────────────────────────────────────────────────────────
pub fn client_for(target: &Target, timeout: Duration) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if !target.addrs.is_empty() {
        builder = builder.resolve_to_addrs(&target.host, &target.addrs);
    }
    builder.build().map_err(|e| e.to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn ordinary_public_addresses_are_public() {
        for a in ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(is_public_ip(ip(a)), "{a}");
        }
    }

    #[test]
    fn internal_addresses_are_not_public() {
        for a in ["127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                  "0.0.0.0", "0.1.2.3", "100.64.0.1", "100.127.255.254", "255.255.255.255",
                  "192.0.2.1", "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1"] {
            assert!(!is_public_ip(ip(a)), "{a}");
        }
        // Just outside carrier-grade NAT.
        assert!(is_public_ip(ip("100.63.255.255")) && is_public_ip(ip("100.128.0.1")));
    }

    // The gap this module closes: these connect to the IPv4 address they embed.
    #[test]
    fn ipv6_forms_of_internal_ipv4_addresses_are_not_public() {
        for a in ["::ffff:169.254.169.254", "::ffff:10.0.0.5", "::ffff:127.0.0.1", "::ffff:192.168.1.1",
                  "::169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1"] {
            assert!(!is_public_ip(ip(a)), "{a}");
        }
        assert!(is_public_ip(ip("::ffff:8.8.8.8")), "a mapped public address is still public");
    }

    #[test]
    fn strict_mode_requires_https_to_a_public_address() {
        for bad in [
            "http://example.com/hook",            // not https
            "https://127.0.0.1/x",
            "https://10.0.0.5/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/x",
            "https://[::ffff:169.254.169.254]/x", // mapped metadata address
            "https://[fd00::1]/x",
            "https://localhost/x",
            "https://example.com@169.254.169.254/", // userinfo is not the host
            "https://169.254.169.254:8443/x",
            "ftp://example.com/x",
            "file:///etc/passwd",
            "example.com/x",
            "https:///nohost",
            "",
        ] {
            assert!(check_url(bad, true, "URL").is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn strict_mode_returns_the_checked_addresses_for_pinning() {
        let t = check_url("https://8.8.8.8:8443/x?y=1", true, "URL").unwrap();
        assert_eq!(t.host, "8.8.8.8");
        assert_eq!(t.addrs, vec!["8.8.8.8:8443".parse::<SocketAddr>().unwrap()]);
        let t = check_url("  https://[2606:4700:4700::1111]/x  ", true, "URL").unwrap();
        assert_eq!(t.addrs, vec!["[2606:4700:4700::1111]:443".parse::<SocketAddr>().unwrap()]);
        assert_eq!(t.url, "https://[2606:4700:4700::1111]/x", "stored trimmed");
        // The server installs its TLS provider at startup (main.rs).
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(client_for(&t, Duration::from_secs(5)).is_ok());
    }

    // The request goes to the address that was checked, whatever DNS says:
    // this hostname does not resolve at all, and the request still arrives.
    #[tokio::test]
    async fn a_pinned_client_connects_to_the_checked_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\npinned").await;
        });

        let _ = rustls::crypto::ring::default_provider().install_default();
        let target = Target {
            url: format!("http://pinned.invalid:{}/x", addr.port()),
            host: "pinned.invalid".to_string(),
            addrs: vec![addr],
        };
        let client = client_for(&target, Duration::from_secs(5)).unwrap();
        let body = client.get(&target.url).send().await.expect("request reaches the pinned address")
            .text().await.unwrap();
        assert_eq!(body, "pinned");

        // Unpinned, the same name goes nowhere.
        let unpinned = Target { addrs: Vec::new(), ..target.clone() };
        let client = client_for(&unpinned, Duration::from_secs(5)).unwrap();
        assert!(client.get(&unpinned.url).send().await.is_err());
    }

    // A redirect would be a second, unchecked request.
    #[tokio::test]
    async fn redirects_are_not_followed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(b"HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        let target = check_url(&format!("http://127.0.0.1:{}/x", addr.port()), false, "URL").unwrap();
        let resp = client_for(&target, Duration::from_secs(5)).unwrap().get(&target.url).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 302, "the redirect is returned, not followed");
    }

    #[test]
    fn self_hosted_mode_allows_internal_addresses_and_http() {
        for ok in ["http://10.0.0.5/hook", "https://keycloak.internal/realms/x", "http://localhost:8080/", "https://[::1]:8443/x"] {
            let t = check_url(ok, false, "URL").unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert!(t.addrs.is_empty(), "nothing is resolved or pinned in self-hosted mode");
        }
        for bad in ["hooks.example.com", "file:///etc/passwd", "ftp://x/y", ""] {
            assert!(check_url(bad, false, "URL").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn messages_name_the_thing_being_checked() {
        assert_eq!(check_url("http://example.com", true, "Issuer URL").unwrap_err(), "Issuer URL must use https://");
        assert_eq!(check_url("nope", false, "Webhook URL").unwrap_err(), "Webhook URL must start with http:// or https://");
        let e = check_url("https://10.0.0.5/x", true, "Webhook URL").unwrap_err();
        assert_eq!(e, "10.0.0.5 resolves to 10.0.0.5, which is not a public address");
    }
}
