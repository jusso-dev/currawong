use currawong_testkit::{read_banner, send_eml, spawn_gateway};

#[tokio::test]
async fn spawned_gateway_sends_a_banner_and_accepts_mail() {
    let gateway = spawn_gateway(|_| {}).await;
    let banner = read_banner(gateway.addr).await;
    assert!(banner.starts_with("220"), "{banner}");
    let eml = b"From: a@outside.test\r\nTo: b@example.test\r\nSubject: hi\r\n\r\nhello\r\n";
    let result = send_eml(gateway.addr, "a@outside.test", &["b@example.test"], eml).await;
    assert_eq!(result.code, 250);
    let queued = gateway
        .spool
        .list(currawong_spool::SpoolState::Incoming)
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
}
