// client_ip.rs — X-Forwarded-For is believed only from a trusted proxy.
//
// Before 0.10.1 the leftmost X-Forwarded-For entry was taken from anyone, so
// a client could put any address in the audit log, and any limit counted per
// address could be dodged by changing the header on every request.

use scmserver::handlers::{parse_proxy_list, resolve_client_ip, DEFAULT_TRUSTED_PROXIES};
use std::net::IpAddr;

fn defaults() -> Vec<ipnet::IpNet> {
    parse_proxy_list(&DEFAULT_TRUSTED_PROXIES.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

fn ip(s: &str) -> Option<IpAddr> { Some(s.parse().unwrap()) }

#[test]
fn a_direct_client_cannot_choose_its_address() {
    let t = defaults();
    assert_eq!(resolve_client_ip(ip("203.0.113.9"), Some("1.2.3.4"), None, &t), "203.0.113.9");
    assert_eq!(resolve_client_ip(ip("203.0.113.9"), None, Some("1.2.3.4"), &t), "203.0.113.9");
}

#[test]
fn a_local_proxy_is_believed() {
    let t = defaults();
    assert_eq!(resolve_client_ip(ip("127.0.0.1"), Some("198.51.100.7"), None, &t), "198.51.100.7");
    assert_eq!(resolve_client_ip(ip("172.17.0.1"), None, Some("198.51.100.7"), &t), "198.51.100.7");
}

#[test]
fn entries_the_client_prepended_are_skipped() {
    // nginx appends the real peer to whatever the client sent.
    let t = defaults();
    assert_eq!(
        resolve_client_ip(ip("127.0.0.1"), Some("1.2.3.4, 198.51.100.7"), None, &t),
        "198.51.100.7"
    );
    // Two trusted hops in front of us.
    assert_eq!(
        resolve_client_ip(ip("10.0.0.2"), Some("1.2.3.4, 198.51.100.7, 10.0.0.5"), None, &t),
        "198.51.100.7"
    );
}

#[test]
fn garbage_in_the_chain_stops_at_the_last_verified_hop() {
    let t = defaults();
    assert_eq!(resolve_client_ip(ip("127.0.0.1"), Some("not-an-ip"), None, &t), "127.0.0.1");
    assert_eq!(resolve_client_ip(ip("127.0.0.1"), Some("x, 10.0.0.5"), None, &t), "10.0.0.5");
}

#[test]
fn an_all_internal_chain_names_the_leftmost_hop() {
    let t = defaults();
    assert_eq!(resolve_client_ip(ip("127.0.0.1"), Some("192.168.1.20"), None, &t), "192.168.1.20");
}

#[test]
fn ipv4_mapped_peers_are_judged_as_ipv4() {
    let t = defaults();
    assert_eq!(resolve_client_ip(ip("::ffff:127.0.0.1"), Some("198.51.100.7"), None, &t), "198.51.100.7");
    assert_eq!(resolve_client_ip(ip("::ffff:203.0.113.9"), Some("1.2.3.4"), None, &t), "203.0.113.9");
}

#[test]
fn a_configured_cdn_range_is_trusted_and_an_empty_list_trusts_nobody() {
    let cdn = parse_proxy_list(&["127.0.0.1".into(), "173.245.48.0/20".into(), "bogus".into()]);
    assert_eq!(cdn.len(), 2, "the bad entry is skipped");
    assert_eq!(
        resolve_client_ip(ip("127.0.0.1"), Some("198.51.100.7, 173.245.48.10"), None, &cdn),
        "198.51.100.7"
    );
    // Without the CDN listed, the edge server is what we see.
    assert_eq!(
        resolve_client_ip(ip("127.0.0.1"), Some("198.51.100.7, 173.245.48.10"), None, &defaults()),
        "173.245.48.10"
    );
    assert_eq!(resolve_client_ip(ip("127.0.0.1"), Some("198.51.100.7"), None, &[]), "127.0.0.1");
}

#[test]
fn no_peer_address_is_unknown_whatever_the_headers_say() {
    assert_eq!(resolve_client_ip(None, Some("1.2.3.4"), Some("1.2.3.4"), &defaults()), "unknown");
}
