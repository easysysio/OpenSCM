// syslog_delivery.rs — does a syslog alert actually leave the server?
//
// UDP is fire-and-forget, so a send that "succeeds" proves only that the socket
// accepted the bytes. This binds a real listener and checks the datagram
// arrives, and that it is RFC 5424 shaped.

use scmserver::alert_delivery::deliver_pending;
use sqlx::SqlitePool;
use tokio::net::UdpSocket;

async fn db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    scmserver::schema::initialize_database(&pool).await.unwrap();
    scmserver::schema::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, username, password, name, email, role)
                 VALUES (1,'default','admin','x','Admin','a@example.com','admin')")
        .execute(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn a_syslog_alert_reaches_the_listener() {
    // A real listener on an ephemeral port.
    let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let pool = db().await;
    sqlx::query("INSERT INTO alert_deliveries
                   (tenant_id, alert_id, policy_id, alert_name, policy_name,
                    old_score, new_score, action, target, status)
                 VALUES ('default',1,1,'prod drop','CIS Ubuntu',94.0,61.0,'syslog',?, 'pending')")
        .bind(format!("127.0.0.1:{port}"))
        .execute(&pool).await.unwrap();

    deliver_pending(&pool).await;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), listener.recv(&mut buf))
        .await
        .expect("no datagram arrived within 3s — the server did not send syslog")
        .expect("recv failed");
    let msg = String::from_utf8_lossy(&buf[..n]).to_string();
    eprintln!("  received: {msg}");

    // facility 13 (log audit) * 8 + severity 4 (warning, a fall of 33 points).
    assert!(msg.starts_with("<108>1 "), "not RFC 5424 with the expected priority: {msg}");
    assert!(msg.contains("CIS Ubuntu"), "policy name missing");
    assert!(msg.contains("prev=\"94.00\"") && msg.contains("curr=\"61.00\""), "scores missing");

    let status: String = sqlx::query_scalar("SELECT status FROM alert_deliveries")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(status, "sent");
}

// A hostname that does not resolve must fail the delivery, not panic or hang.
#[tokio::test]
async fn an_unresolvable_syslog_target_fails_cleanly() {
    let pool = db().await;
    sqlx::query("INSERT INTO alert_deliveries
                   (tenant_id, alert_id, policy_id, alert_name, policy_name,
                    old_score, new_score, action, target, status)
                 VALUES ('default',1,1,'x','y',94.0,61.0,'syslog',
                         'no-such-host.invalid:514','pending')")
        .execute(&pool).await.unwrap();

    deliver_pending(&pool).await;

    let (status, attempts): (String, i64) =
        sqlx::query_as("SELECT status, attempts FROM alert_deliveries")
            .fetch_one(&pool).await.unwrap();
    assert_eq!((status.as_str(), attempts), ("pending", 1), "should have failed and scheduled a retry");
}
