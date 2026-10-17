use currawong_testkit::{read_banner, send_eml, spawn_gateway};

#[tokio::test]
async fn spawned_gateway_sends_a_banner_and_accepts_mail() {
    let gateway = spawn_gateway(|_| {}).await;
    let banner = read_banner(gateway.addr).await;
    assert!(banner.starts_with("220 "), "{banner}");
    let eml = b"From: a@outside.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\nhello\r\n";
    let result = send_eml(gateway.addr, "a@outside.test", &["b@example.test"], eml).await;
    assert_eq!(result.code, 250, "{result:?}");
    let queued = gateway
        .spool
        .list(currawong_spool::SpoolState::Incoming)
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
}

#[tokio::test]
async fn send_eml_reports_the_real_refusal() {
    let gateway = spawn_gateway(|_| {}).await;
    let eml = b"From: a@outside.test\r\nTo: b@elsewhere.test\r\nSubject: hi\r\n\r\nhello\r\n";
    let result = send_eml(gateway.addr, "a@outside.test", &["b@elsewhere.test"], eml).await;
    assert!((500..600).contains(&result.code), "{result:?}");
    assert!(!result.accepted());
    assert!(!result.message.is_empty());
    assert!(gateway.outcomes().await.is_empty());
}

#[tokio::test]
async fn the_configured_listener_is_used() {
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    let gateway = spawn_gateway(|cfg| cfg.listeners[0].bind = format!("127.0.0.1:{port}")).await;
    assert_eq!(gateway.addr.port(), port);
    assert!(read_banner(gateway.addr).await.starts_with("220 "));
}
