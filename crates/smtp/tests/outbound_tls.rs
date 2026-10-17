//! Outbound TLS policy: DANE, MTA-STS and opportunistic STARTTLS, through
//! `Deliverer::deliver` against in-process STARTTLS sinks. DNS, DNSSEC state
//! and the MTA-STS policy fetch are fakes; the TLS is real.
use async_trait::async_trait;
use currawong_core::config::{Config, DomainRoute, ExchangeVersion, MailboxPlatform};
use currawong_smtp::{
    delivery::{
        mta_sts::{MtaSts, PolicyFetcher},
        Deliverer, DeliveryOutcome, OutboundTls,
    },
    dns::{MapDns, Tlsa},
    tls::build_server_config,
    tlsrpt::TlsRpt,
};
use currawong_spool::{Envelope, Spool, SpoolState};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    RootCertStore,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

const MX: &str = "mx.example.test";

struct Pki {
    ca: CertificateDer<'static>,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
}

impl Pki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Currawong test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = params.self_signed(&ca_key).unwrap();
        Self {
            ca: ca_cert.der().clone(),
            ca_cert,
            ca_key,
        }
    }

    /// A leaf for `name` signed by the CA, served with the CA in the chain.
    fn leaf(&self, name: &str) -> Identity {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key).unwrap();
        Identity {
            chain: vec![cert.der().clone(), self.ca.clone()],
            key,
        }
    }

    fn roots(&self) -> OutboundTls {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        OutboundTls::with_roots(roots)
    }
}

struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: KeyPair,
}

impl Identity {
    fn self_signed(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Self {
            chain: vec![cert.der().clone()],
            key,
        }
    }

    fn spki_sha256(&self) -> Vec<u8> {
        Sha256::digest(self.key.public_key_der()).to_vec()
    }

    fn acceptor(&self) -> TlsAcceptor {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()));
        let config = build_server_config(self.chain.clone(), key).unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
}

#[derive(Debug, Default)]
struct Session {
    tls: bool,
    /// The leaf certificate the client presented, if the sink asked for one.
    client_cert: Option<Vec<u8>>,
    commands: Vec<String>,
}

impl Session {
    fn sent_mail(&self) -> bool {
        self.commands.iter().any(|cmd| cmd.starts_with("MAIL"))
    }
}

struct Sink {
    addr: SocketAddr,
    sessions: mpsc::UnboundedReceiver<Session>,
}

impl Sink {
    async fn next(&mut self) -> Session {
        self.sessions.recv().await.unwrap()
    }

    async fn drain(&mut self) -> Vec<Session> {
        // Let the sink finish the sessions the client has just dropped.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut out = Vec::new();
        while let Ok(session) = self.sessions.try_recv() {
            out.push(session);
        }
        out
    }
}

/// An SMTP sink. With an identity it offers STARTTLS.
async fn sink(identity: Option<Identity>) -> Sink {
    sink_with(identity.map(|identity| identity.acceptor())).await
}

/// An SMTP sink with a given TLS acceptor, which may ask for a client certificate.
async fn sink_with(acceptor: Option<TlsAcceptor>) -> Sink {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, sessions) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut session = Session::default();
                let mut plain = BufReader::new(sock);
                let _ = plain.get_mut().write_all(b"220 sink ESMTP\r\n").await;
                if converse(&mut plain, &mut session, acceptor.is_some()).await {
                    let tcp = plain.into_inner();
                    if let Ok(stream) = acceptor.unwrap().accept(tcp).await {
                        session.tls = true;
                        session.client_cert = stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .map(|cert| cert.to_vec());
                        let mut secure = BufReader::new(stream);
                        converse(&mut secure, &mut session, false).await;
                    }
                }
                let _ = tx.send(session);
            });
        }
    });
    Sink { addr, sessions }
}

/// Speak SMTP until QUIT or EOF. Returns true when the client asked for
/// STARTTLS and was told to go ahead.
async fn converse<S>(io: &mut BufReader<S>, session: &mut Session, offer_tls: bool) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut line = Vec::new();
        if io.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
            return false;
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        session.commands.push(text.clone());
        let verb = text
            .split([' ', ':', '\r', '\n'])
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let reply: &[u8] = match verb.as_str() {
            "EHLO" if offer_tls => b"250-sink\r\n250 STARTTLS\r\n",
            "EHLO" => b"250-sink\r\n250 8BITMIME\r\n",
            "STARTTLS" if offer_tls => {
                let _ = io.get_mut().write_all(b"220 2.0.0 go ahead\r\n").await;
                return true;
            }
            "MAIL" | "RCPT" => b"250 ok\r\n",
            "DATA" => {
                let _ = io.get_mut().write_all(b"354 go\r\n").await;
                loop {
                    let mut line = Vec::new();
                    if io.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 || line == b".\r\n" {
                        break;
                    }
                }
                b"250 queued\r\n"
            }
            "QUIT" => {
                let _ = io.get_mut().write_all(b"221 bye\r\n").await;
                return false;
            }
            _ => b"502 no\r\n",
        };
        let _ = io.get_mut().write_all(reply).await;
    }
}

struct FixedPolicy(String);

#[async_trait]
impl PolicyFetcher for FixedPolicy {
    async fn fetch(&self, _domain: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

fn policy(mode: &str, mx: &str) -> String {
    format!("version: STSv1\nmode: {mode}\nmx: {mx}\nmax_age: 86400\n")
}

struct Setup {
    cfg: Config,
    spool: Arc<Spool>,
    _dir: tempfile::TempDir,
    dns: MapDns,
    policy: Option<String>,
    /// Send a TLS-RPT report (null sender, TLS-Report-Domain header).
    report_mail: bool,
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.spool.dir = dir.path().join("spool");
    cfg.gateway.hostname = "gw.currawong.test".into();
    cfg.delivery.allow_private_mx = true;
    cfg.delivery.tls_database = dir.path().join("tls.sqlite");
    let spool = Arc::new(Spool::open(&cfg.spool.dir).await.unwrap());
    let mut dns = MapDns::new();
    dns.mx.insert("example.test".into(), vec![(10, MX.into())]);
    dns.ips
        .insert(MX.into(), vec!["127.0.0.1".parse().unwrap()]);
    Setup {
        cfg,
        spool,
        _dir: dir,
        dns,
        policy: None,
        report_mail: false,
    }
}

struct Done {
    outcome: DeliveryOutcome,
    cfg: Config,
    _setup: Setup,
}

impl Done {
    fn detail(&self) -> String {
        match &self.outcome {
            DeliveryOutcome::Delivered => String::new(),
            DeliveryOutcome::TempFail(detail) | DeliveryOutcome::PermFail(detail) => detail.clone(),
        }
    }

    /// Today's TLS-RPT report for example.test, as JSON.
    async fn report(&self) -> serde_json::Value {
        let store = TlsRpt::new(self.cfg.delivery.tls_database.clone());
        let today = time::OffsetDateTime::now_utc().date();
        let report = store
            .report(
                today,
                "example.test",
                "Org",
                "postmaster@gw.test",
                "gw.test",
            )
            .await
            .unwrap()
            .expect("results recorded");
        serde_json::from_str(&report.to_json()).unwrap()
    }
}

impl Setup {
    /// Publish DNSSEC-secure MX, address and TLSA answers.
    fn dane(&mut self, tlsa: Vec<Tlsa>) {
        let name = format!("_25._tcp.{MX}");
        self.dns.tlsa.insert(name.clone(), tlsa);
        for name in ["example.test", MX, &name] {
            self.dns.secure.insert(name.to_string());
        }
    }

    fn sts(&mut self, body: String) {
        self.dns.txt.insert(
            "_mta-sts.example.test".into(),
            vec!["v=STSv1; id=1;".into()],
        );
        self.policy = Some(body);
    }

    async fn deliver(mut self, sink: &Sink, tls: OutboundTls) -> Done {
        let env = Envelope {
            id: Envelope::new_id(),
            tenant_id: None,
            authenticated_as: None,
            mail_from: if self.report_mail {
                String::new()
            } else {
                "sender@outside.test".into()
            },
            rcpt_to: vec!["user@example.test".into()],
            received_at: time::OffsetDateTime::now_utc(),
            remote_ip: "203.0.113.8".parse().unwrap(),
            helo: "client.test".into(),
            attempts: 0,
            next_attempt_at: None,
            state: SpoolState::Incoming,
            direction: currawong_core::Direction::Outbound,
            tls_version: None,
            tls_cipher: None,
            rcpt_status: Vec::new(),
            prepend_headers: Vec::new(),
            dsn_sent: false,
            pipeline: "deliver".into(),
        };
        let body: &[u8] = if self.report_mail {
            b"TLS-Report-Domain: example.test\r\nSubject: x\r\n\r\nx\r\n"
        } else {
            b"Subject: x\r\n\r\nx\r\n"
        };
        self.spool
            .accept(env.clone(), std::io::Cursor::new(body.to_vec()))
            .await
            .unwrap();
        let dns = std::mem::take(&mut self.dns);
        let mut deliverer = Deliverer::new(
            Arc::clone(&self.spool),
            Arc::new(self.cfg.clone()),
            Arc::new(dns),
        );
        deliverer.mx_port = sink.addr.port();
        deliverer.tls = tls;
        deliverer.mta_sts = self.policy.clone().map(|body| {
            Arc::new(MtaSts::new(
                Box::new(FixedPolicy(body)),
                self.cfg.delivery.tls_database.clone(),
            ))
        });
        let outcome = deliverer.deliver(&env.id).await.unwrap();
        Done {
            outcome,
            cfg: self.cfg.clone(),
            _setup: self,
        }
    }
}

fn tlsa(usage: u8, selector: u8, data: Vec<u8>) -> Tlsa {
    Tlsa {
        usage,
        selector,
        matching: 1,
        data,
    }
}

fn failure_types(report: &serde_json::Value) -> Vec<String> {
    report["policies"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|policy| policy["failure-details"].as_array().unwrap().clone())
        .map(|detail| detail["result-type"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn mta_sts_enforce_with_mismatched_cert_defers() {
    let pki = Pki::new();
    let mut sink = sink(Some(pki.leaf("wrong.example.test"))).await;
    let mut setup = setup().await;
    setup.sts(policy("enforce", MX));
    let done = setup.deliver(&sink, pki.roots()).await;
    assert!(
        matches!(done.outcome, DeliveryOutcome::TempFail(_)),
        "{:?}",
        done.outcome
    );
    let detail = done.detail();
    assert!(
        detail.contains("MTA-STS policy for example.test requires TLS with mx.example.test"),
        "{detail}"
    );
    assert!(detail.contains("certificate"), "{detail}");
    let sessions = sink.drain().await;
    assert!(!sessions.is_empty());
    assert!(
        sessions.iter().all(|session| !session.sent_mail()),
        "no clear-text fallback under enforce: {sessions:?}"
    );
    let report = done.report().await;
    assert_eq!(report["policies"][0]["policy"]["policy-type"], "sts");
    assert_eq!(
        failure_types(&report),
        vec!["certificate-host-mismatch".to_string()]
    );
    let _ = sink.sessions.try_recv();
}

#[tokio::test]
async fn mta_sts_enforce_with_valid_cert_delivers_over_tls() {
    let pki = Pki::new();
    let mut sink = sink(Some(pki.leaf(MX))).await;
    let mut setup = setup().await;
    setup.sts(policy("enforce", MX));
    let done = setup.deliver(&sink, pki.roots()).await;
    assert_eq!(done.outcome, DeliveryOutcome::Delivered);
    let session = sink.next().await;
    assert!(session.tls && session.sent_mail(), "{session:?}");
    let report = done.report().await;
    assert_eq!(
        report["policies"][0]["summary"]["total-successful-session-count"],
        1
    );
}

#[tokio::test]
async fn mta_sts_enforce_skips_unlisted_mx() {
    let pki = Pki::new();
    let mut sink = sink(Some(pki.leaf(MX))).await;
    let mut setup = setup().await;
    setup.sts(policy("enforce", "other.example.test"));
    let done = setup.deliver(&sink, pki.roots()).await;
    assert!(
        done.detail()
            .contains("does not list MX host mx.example.test"),
        "{}",
        done.detail()
    );
    assert!(
        sink.drain().await.is_empty(),
        "the unlisted MX was contacted"
    );
}

#[tokio::test]
async fn mta_sts_testing_reports_and_delivers_without_tls() {
    let pki = Pki::new();
    let mut sink = sink(Some(pki.leaf("wrong.example.test"))).await;
    let mut setup = setup().await;
    setup.sts(policy("testing", MX));
    let done = setup.deliver(&sink, pki.roots()).await;
    assert_eq!(done.outcome, DeliveryOutcome::Delivered);
    let first = sink.next().await;
    let second = sink.next().await;
    assert!(!first.sent_mail());
    assert!(!second.tls && second.sent_mail(), "{second:?}");
    assert_eq!(
        failure_types(&done.report().await),
        vec!["certificate-host-mismatch".to_string()]
    );
}

#[tokio::test]
async fn dane_ee_match_delivers() {
    // Self-signed and untrusted by WebPKI: only the TLSA record vouches for it.
    let identity = Identity::self_signed("anything.invalid");
    let record = tlsa(3, 1, identity.spki_sha256());
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert_eq!(done.outcome, DeliveryOutcome::Delivered);
    let session = sink.next().await;
    assert!(session.tls && session.sent_mail(), "{session:?}");
    let report = done.report().await;
    assert_eq!(report["policies"][0]["policy"]["policy-type"], "tlsa");
    assert_eq!(
        report["policies"][0]["summary"]["total-successful-session-count"],
        1
    );
}

#[tokio::test]
async fn dane_mismatch_defers() {
    let identity = Identity::self_signed(MX);
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![tlsa(3, 1, vec![7; 32])]);
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert!(
        matches!(done.outcome, DeliveryOutcome::TempFail(_)),
        "{:?}",
        done.outcome
    );
    assert!(
        done.detail().contains("DANE for mx.example.test"),
        "{}",
        done.detail()
    );
    let sessions = sink.drain().await;
    assert!(!sessions.is_empty());
    assert!(
        sessions.iter().all(|session| !session.sent_mail()),
        "{sessions:?}"
    );
    assert_eq!(
        failure_types(&done.report().await),
        vec!["validation-failure".to_string()]
    );
}

#[tokio::test]
async fn dane_ta_match_delivers() {
    let pki = Pki::new();
    let record = tlsa(2, 0, Sha256::digest(&pki.ca).to_vec());
    let mut sink = sink(Some(pki.leaf(MX))).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    // The CA is not in the WebPKI store; the TLSA record makes it the anchor.
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    assert!(sink.next().await.tls);
}

#[tokio::test]
async fn dane_ta_still_checks_the_name() {
    let pki = Pki::new();
    let record = tlsa(2, 0, Sha256::digest(&pki.ca).to_vec());
    let mut sink = sink(Some(pki.leaf("wrong.example.test"))).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert!(matches!(done.outcome, DeliveryOutcome::TempFail(_)));
    assert!(sink
        .drain()
        .await
        .iter()
        .all(|session| !session.sent_mail()));
}

#[tokio::test]
async fn dane_bogus_tlsa_defers_without_connecting() {
    let mut sink = sink(Some(Identity::self_signed(MX))).await;
    let mut setup = setup().await;
    setup.dane(vec![]);
    setup.dns.bogus.insert(format!("_25._tcp.{MX}"));
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert!(
        done.detail().contains("DANE: TLSA lookup"),
        "{}",
        done.detail()
    );
    assert!(sink.drain().await.is_empty());
    assert_eq!(
        failure_types(&done.report().await),
        vec!["dnssec-invalid".to_string()]
    );
}

#[tokio::test]
async fn dane_requires_starttls() {
    let identity = Identity::self_signed(MX);
    let record = tlsa(3, 1, identity.spki_sha256());
    let mut sink = sink(None).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert!(
        done.detail().contains("STARTTLS not offered"),
        "{}",
        done.detail()
    );
    assert!(!sink.next().await.sent_mail());
}

#[tokio::test]
async fn dane_with_only_unusable_tlsa_records_defers() {
    let identity = Identity::self_signed(MX);
    // PKIX-EE(1): published, signed, and not usable for SMTP.
    let record = tlsa(1, 1, identity.spki_sha256());
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert!(
        matches!(done.outcome, DeliveryOutcome::TempFail(_)),
        "{:?}",
        done.outcome
    );
    assert!(
        done.detail().contains("no usable TLSA record"),
        "{}",
        done.detail()
    );
    assert!(sink.drain().await.is_empty(), "the host was contacted");
    assert_eq!(
        failure_types(&done.report().await),
        vec!["tlsa-invalid".to_string()]
    );
}

#[tokio::test]
async fn dane_follows_a_secure_cname_to_its_tlsa() {
    let identity = Identity::self_signed("anything.invalid");
    let record = tlsa(3, 1, identity.spki_sha256());
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![]);
    let target = "host.provider.test";
    setup.dns.cname.insert(MX.into(), target.into());
    setup
        .dns
        .ips
        .insert(target.into(), vec!["127.0.0.1".parse().unwrap()]);
    let expanded = format!("_25._tcp.{target}");
    setup.dns.tlsa.insert(expanded.clone(), vec![record]);
    for name in [target, expanded.as_str()] {
        setup.dns.secure.insert(name.to_string());
    }
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    assert!(sink.next().await.tls);
}

#[tokio::test]
async fn tlsrpt_report_deliveries_are_not_themselves_reported() {
    let identity = Identity::self_signed(MX);
    let record = tlsa(3, 1, identity.spki_sha256());
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    setup.report_mail = true;
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    assert!(sink.next().await.tls);
    let store = TlsRpt::new(done.cfg.delivery.tls_database.clone());
    let today = time::OffsetDateTime::now_utc().date();
    let report = store
        .report(
            today,
            "example.test",
            "Org",
            "postmaster@gw.test",
            "gw.test",
        )
        .await
        .unwrap();
    assert!(report.is_none(), "{report:?}");
}

#[tokio::test]
async fn dane_ignores_tlsa_from_an_insecure_zone() {
    let identity = Identity::self_signed(MX);
    let record = tlsa(3, 1, vec![7; 32]);
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    // The MX answer itself is not signed, so DANE does not apply.
    setup.dns.secure.remove("example.test");
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert_eq!(done.outcome, DeliveryOutcome::Delivered);
    // Opportunistic: the untrusted certificate is not used, the mail goes in clear.
    let first = sink.next().await;
    let second = sink.next().await;
    assert!(!first.sent_mail());
    assert!(!second.tls && second.sent_mail());
}

#[tokio::test]
async fn dane_takes_precedence_over_mta_sts() {
    // MTA-STS alone would refuse this self-signed certificate.
    let identity = Identity::self_signed("anything.invalid");
    let record = tlsa(3, 1, identity.spki_sha256());
    let mut sink = sink(Some(identity)).await;
    let mut setup = setup().await;
    setup.dane(vec![record]);
    setup.sts(policy("enforce", MX));
    let done = setup.deliver(&sink, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    assert!(sink.next().await.tls);
}

#[tokio::test]
async fn opportunistic_tls_is_verified_or_not_used() {
    let pki = Pki::new();
    let mut trusted = sink(Some(pki.leaf(MX))).await;
    let mut setup = setup().await;
    setup.cfg.domains.routes.push(DomainRoute {
        domain: "example.test".into(),
        next_hop: format!("{MX}:{}", trusted.addr.port()),
        platform: None,
    });
    let done = setup.deliver(&trusted, pki.roots()).await;
    assert_eq!(done.outcome, DeliveryOutcome::Delivered);
    assert!(trusted.next().await.tls);

    let mut untrusted = sink(Some(Identity::self_signed(MX))).await;
    let mut again = self::setup().await;
    again.cfg.domains.routes.push(DomainRoute {
        domain: "example.test".into(),
        next_hop: format!("{MX}:{}", untrusted.addr.port()),
        platform: None,
    });
    let done = again.deliver(&untrusted, pki.roots()).await;
    assert_eq!(done.outcome, DeliveryOutcome::Delivered);
    assert!(!untrusted.next().await.sent_mail());
    let fallback = untrusted.next().await;
    assert!(!fallback.tls && fallback.sent_mail());
}

#[tokio::test]
async fn require_tls_refuses_unverified_certificates() {
    let pki = Pki::new();
    let mut sink = sink(Some(Identity::self_signed(MX))).await;
    let mut setup = setup().await;
    setup.cfg.delivery.require_tls = true;
    setup.cfg.domains.routes.push(DomainRoute {
        domain: "example.test".into(),
        next_hop: format!("{MX}:{}", sink.addr.port()),
        platform: None,
    });
    let done = setup.deliver(&sink, pki.roots()).await;
    assert!(
        done.detail().contains("delivery.require_tls requires TLS"),
        "{}",
        done.detail()
    );
    assert!(sink
        .drain()
        .await
        .iter()
        .all(|session| !session.sent_mail()));
}

/// #47: an Exchange on-premises route with two Mailbox servers. The
/// certificate names `tls_cert_name`, not the host, and chains to a CA that is
/// trusted only through the route's `ca_file`.
async fn exchange_setup(hosts: &[String], ca_pem: Option<&str>) -> Setup {
    let mut setup = setup().await;
    // No gateway certificate, so no client certificate, unless a test sets one.
    setup.cfg.tls.cert = None;
    setup.cfg.tls.key = None;
    let ca_file = ca_pem.map(|pem| {
        let path = setup._dir.path().join("exchange-ca.pem");
        std::fs::write(&path, pem).unwrap();
        path
    });
    for host in ["exch01.example.test", "exch02.example.test"] {
        setup
            .dns
            .ips
            .insert(host.into(), vec!["127.0.0.1".parse().unwrap()]);
    }
    setup.cfg.domains.routes.push(DomainRoute {
        domain: "example.test".into(),
        next_hop: String::new(),
        platform: Some(MailboxPlatform::ExchangeOnPrem {
            version: ExchangeVersion::Ex2019,
            mailbox_hosts: hosts.to_vec(),
            tls_cert_name: "mail.example.test".into(),
            ca_file,
            client_cert: None,
            client_key: None,
        }),
    });
    setup
}

/// A port nothing listens on, so connecting is refused.
async fn refused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn exchange_delivery_uses_tls_and_fails_over_to_the_second_host() {
    let pki = Pki::new();
    let mut second = sink(Some(pki.leaf("mail.example.test"))).await;
    let hosts = [
        format!("exch01.example.test:{}", refused_port().await),
        format!("exch02.example.test:{}", second.addr.port()),
    ];
    let setup = exchange_setup(&hosts, Some(&pki.ca_cert.pem())).await;
    let done = setup.deliver(&second, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    let session = second.next().await;
    assert!(session.tls && session.sent_mail(), "{session:?}");
}

#[tokio::test]
async fn exchange_delivery_refuses_plaintext_and_defers_with_the_reason() {
    let mut plain = sink(None).await;
    let hosts = [format!("exch01.example.test:{}", plain.addr.port())];
    let setup = exchange_setup(&hosts, None).await;
    let done = setup.deliver(&plain, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::TempFail(
            "4.7.5 Exchange route for example.test requires TLS with mail.example.test: STARTTLS not offered"
                .into()
        )
    );
    assert!(plain.drain().await.iter().all(|s| !s.sent_mail()));
    let deferred = done._setup.spool.list(SpoolState::Deferred).await.unwrap();
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].rcpt_status[0].status, "temp");
}

#[tokio::test]
async fn exchange_delivery_checks_the_certificate_name_and_ca() {
    let pki = Pki::new();
    // Valid chain, but for the host name rather than tls_cert_name.
    let mut wrong_name = sink(Some(pki.leaf("exch01.example.test"))).await;
    let hosts = [format!("exch01.example.test:{}", wrong_name.addr.port())];
    let setup = exchange_setup(&hosts, Some(&pki.ca_cert.pem())).await;
    let done = setup.deliver(&wrong_name, OutboundTls::webpki()).await;
    assert!(
        matches!(&done.outcome, DeliveryOutcome::TempFail(d) if d.contains("requires TLS with mail.example.test")),
        "{:?}",
        done.outcome
    );
    assert!(wrong_name.drain().await.iter().all(|s| !s.sent_mail()));

    // Right name, but the CA is not in ca_file or the WebPKI roots.
    let mut untrusted = sink(Some(pki.leaf("mail.example.test"))).await;
    let hosts = [format!("exch01.example.test:{}", untrusted.addr.port())];
    let setup = exchange_setup(&hosts, None).await;
    let done = setup.deliver(&untrusted, OutboundTls::webpki()).await;
    assert!(
        matches!(&done.outcome, DeliveryOutcome::TempFail(_)),
        "{:?}",
        done.outcome
    );
    assert!(untrusted.drain().await.iter().all(|s| !s.sent_mail()));
}

#[tokio::test]
async fn exchange_delivery_fails_over_after_a_tls_failure() {
    let pki = Pki::new();
    let mut plain = sink(None).await;
    let mut good = sink(Some(pki.leaf("mail.example.test"))).await;
    let hosts = [
        format!("exch01.example.test:{}", plain.addr.port()),
        format!("exch02.example.test:{}", good.addr.port()),
    ];
    let setup = exchange_setup(&hosts, Some(&pki.ca_cert.pem())).await;
    let done = setup.deliver(&good, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    assert!(plain.drain().await.iter().all(|s| !s.sent_mail()));
    let session = good.next().await;
    assert!(session.tls && session.sent_mail(), "{session:?}");
}

/// A route domain written with other case and a trailing dot is still an
/// Exchange route for TLS, not only for routing.
#[tokio::test]
async fn exchange_delivery_route_domain_is_normalised_for_tls_too() {
    let mut plain = sink(None).await;
    let hosts = [format!("exch01.example.test:{}", plain.addr.port())];
    let mut setup = exchange_setup(&hosts, None).await;
    setup.cfg.domains.routes[0].domain = " Example.TEST. ".into();
    let done = setup.deliver(&plain, OutboundTls::webpki()).await;
    assert!(
        done.detail()
            .contains("Exchange route for example.test requires TLS"),
        "{}",
        done.detail()
    );
    assert!(plain.drain().await.iter().all(|s| !s.sent_mail()));
}

/// The gateway's inbound certificate is presented to a Receive connector that
/// asks for one (domain secure mail), unless the route names its own pair.
#[tokio::test]
async fn exchange_delivery_presents_the_gateway_client_certificate() {
    let pki = Pki::new();
    // The fake Exchange server requires a client certificate from the CA.
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let server = pki.leaf("mail.example.test");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_client_cert_verifier(verifier)
    .with_single_cert(server.chain.clone(), key)
    .unwrap();
    let mut exchange = sink_with(Some(TlsAcceptor::from(Arc::new(config)))).await;

    // Currawong's inbound certificate, usable as a client certificate too.
    let gw_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["gw.currawong.test".to_string()]).unwrap();
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let gw_cert = params
        .signed_by(&gw_key, &pki.ca_cert, &pki.ca_key)
        .unwrap();

    let hosts = [format!("exch01.example.test:{}", exchange.addr.port())];
    let mut setup = exchange_setup(&hosts, Some(&pki.ca_cert.pem())).await;
    let cert_path = setup._dir.path().join("gw.pem");
    let key_path = setup._dir.path().join("gw.key");
    std::fs::write(&cert_path, gw_cert.pem()).unwrap();
    std::fs::write(&key_path, gw_key.serialize_pem()).unwrap();
    setup.cfg.tls.cert = Some(cert_path);
    setup.cfg.tls.key = Some(key_path);
    let done = setup.deliver(&exchange, OutboundTls::webpki()).await;
    assert_eq!(
        done.outcome,
        DeliveryOutcome::Delivered,
        "{}",
        done.detail()
    );
    let session = exchange.next().await;
    assert!(session.sent_mail(), "{session:?}");
    assert_eq!(session.client_cert.as_deref(), Some(gw_cert.der().as_ref()));

    // Without a client certificate the same server refuses the session (TLS
    // 1.3 reports it on the first read), and the message defers rather than
    // going in plaintext.
    let hosts = [format!("exch01.example.test:{}", exchange.addr.port())];
    let setup = exchange_setup(&hosts, Some(&pki.ca_cert.pem())).await;
    let done = setup.deliver(&exchange, OutboundTls::webpki()).await;
    assert!(
        matches!(&done.outcome, DeliveryOutcome::TempFail(d) if d.contains("CertificateRequired")),
        "{:?}",
        done.outcome
    );
    assert!(exchange.drain().await.iter().all(|s| !s.sent_mail()));
}
