//! Policy TLS and encryption actions through the classify pass.
use currawong_admin::routes::portal::CodeMailer;
use currawong_auth::AuthChecker;
use currawong_core::{
    config::{Config, TenantConfig},
    Direction, MessageId, TlsRequirement,
};
use currawong_dlp::encrypt::{PortalStore, Route};
use currawong_policy::{default_pack, Action, Condition, Policy, PolicySet, Scope};
use currawong_quarantine::QuarantineStore;
use currawong_spool::{Envelope, Spool, SpoolState};
use currawongd::{classify_pending, Pipeline, SpoolMailer};
use std::{io::Cursor, sync::Arc};
use time::OffsetDateTime;

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RAW: &[u8] = b"From: payroll@example.test\r\nTo: ops@partner.test\r\nSubject: Payroll\r\n\
Content-Type: text/plain\r\n\r\nPayroll run attached.\r\n";

fn envelope() -> Envelope {
    Envelope {
        id: MessageId(ID.into()),
        tenant_id: Some("t1".into()),
        authenticated_as: Some("payroll@example.test".into()),
        mail_from: "payroll@example.test".into(),
        rcpt_to: vec!["ops@partner.test".into()],
        received_at: OffsetDateTime::now_utc(),
        remote_ip: "192.0.2.10".parse().unwrap(),
        helo: "client.example.test".into(),
        attempts: 0,
        next_attempt_at: None,
        state: SpoolState::Incoming,
        direction: Direction::Outbound,
        tls_version: None,
        tls_cipher: None,
        rcpt_status: Vec::new(),
        prepend_headers: Vec::new(),
        dsn_sent: false,
        tls: TlsRequirement::None,
        pipeline: "pending".into(),
    }
}

fn pack(actions: Vec<Action>) -> PolicySet {
    let mut set = default_pack().clone();
    set.policies.push(Policy {
        id: "partner".into(),
        tenant_id: None,
        scope: Scope::Global,
        priority: 10,
        enabled: true,
        dry_run: false,
        mandatory: false,
        override_floor: Vec::new(),
        conditions: vec![Condition::Recipient("*@partner.test".into())],
        actions,
    });
    set
}

/// The parser worker built beside this test binary.
fn worker_bin() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    let worker = exe
        .parent()
        .and_then(|deps| deps.parent())
        .map(|dir| dir.join("currawong-parser-worker"))
        .unwrap();
    assert!(worker.is_file(), "build the parser worker first");
    worker
}

struct Harness {
    _dir: tempfile::TempDir,
    cfg: Config,
    spool: Spool,
    pipeline: Pipeline,
    quarantine: QuarantineStore,
}

impl Harness {
    async fn new(actions: Vec<Action>, edit: impl FnOnce(&mut Config, &std::path::Path)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.spool.dir = dir.path().join("spool");
        cfg.scanner.clamd.address.clear();
        cfg.scanner.clamd.required = false;
        cfg.scanner.worker_binary = Some(worker_bin());
        cfg.gateway.hostname = "gw.example.test".into();
        cfg.relay.tenants = vec![TenantConfig {
            id: "t1".into(),
            domains: vec!["example.test".into()],
            trusted_cidrs: Vec::new(),
        }];
        edit(&mut cfg, dir.path());
        let spool = Spool::open(&cfg.spool.dir).await.unwrap();
        spool
            .accept(envelope(), Cursor::new(RAW.to_vec()))
            .await
            .unwrap();
        let auth = AuthChecker::offline("currawong.example.test").unwrap();
        let mut pipeline = Pipeline::new(Arc::new(cfg.clone()), auth).with_policies(pack(actions));
        if cfg.encrypt.portal.enabled {
            let portal = &cfg.encrypt.portal;
            let store = PortalStore::open(&portal.dir, &portal.key_path, 30).unwrap();
            pipeline = pipeline.with_portal(Arc::new(store));
        }
        let quarantine = QuarantineStore::open(dir.path().join("held")).unwrap();
        Self {
            _dir: dir,
            cfg,
            spool,
            pipeline,
            quarantine,
        }
    }

    async fn classify(&mut self) {
        classify_pending(&self.spool, &mut self.pipeline, &self.quarantine)
            .await
            .unwrap();
    }

    /// Envelopes waiting for delivery other than the original.
    async fn outgoing(&self) -> Vec<(Envelope, Vec<u8>)> {
        let mut out = Vec::new();
        for env in self.spool.list(SpoolState::Incoming).await.unwrap() {
            if env.id.as_str() != ID && env.pipeline == "deliver" {
                let body = self.spool.read_body(&env.id).await.unwrap();
                out.push((env, body));
            }
        }
        out
    }

    async fn original(&self) -> Envelope {
        self.spool.load(&MessageId(ID.into())).await.unwrap()
    }
}

#[tokio::test]
async fn require_tls_and_require_dane_policies_mark_the_envelope_for_delivery() {
    let mut h = Harness::new(vec![Action::RequireTls], |_, _| {}).await;
    h.classify().await;
    let env = h.original().await;
    assert_eq!(env.pipeline, "deliver");
    assert_eq!(env.tls, TlsRequirement::Required);

    let mut h = Harness::new(vec![Action::RequireDane, Action::RequireTls], |_, _| {}).await;
    h.classify().await;
    assert_eq!(h.original().await.tls, TlsRequirement::Dane);
}

#[tokio::test]
async fn encrypt_portal_holds_the_message_and_sends_a_link() {
    let mut h = Harness::new(
        vec![Action::EncryptPortal, Action::RequireTls],
        |cfg, dir| {
            cfg.encrypt.portal.enabled = true;
            cfg.encrypt.portal.dir = dir.join("portal");
            cfg.encrypt.portal.key_path = dir.join("portal.key");
            cfg.encrypt.portal.base_url = "https://secure.example.test/".into();
        },
    )
    .await;
    h.classify().await;
    let original = h.original().await;
    assert_eq!(original.state, SpoolState::Done);
    assert_eq!(original.pipeline, "encrypted");
    let outgoing = h.outgoing().await;
    assert_eq!(outgoing.len(), 1);
    let (notice, body) = &outgoing[0];
    assert_eq!(notice.rcpt_to, ["ops@partner.test"]);
    assert_eq!(notice.mail_from, "postmaster@gw.example.test");
    // The notice keeps the policy's TLS requirement.
    assert_eq!(notice.tls, TlsRequirement::Required);
    let text = String::from_utf8_lossy(body);
    assert!(!text.contains("Payroll run attached"), "{text}");
    let token = text
        .split("https://secure.example.test/portal/")
        .nth(1)
        .expect("link in the notice")[..64]
        .to_string();

    // The portal holds the original and opens it with the code only.
    let portal = &h.cfg.encrypt.portal;
    let store = PortalStore::open(&portal.dir, &portal.key_path, 30).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let issued = store.issue_code(&token, now).unwrap();
    assert_eq!(issued.recipient, "ops@partner.test");
    assert_eq!(
        issued.route,
        Route {
            tenant_id: Some("t1".into()),
            tls: TlsRequirement::Required,
        }
    );
    assert_eq!(store.open_message(&token, &issued.code, now).unwrap(), RAW);

    // Classifying again sends nothing more.
    h.classify().await;
    assert_eq!(h.outgoing().await.len(), 1);
}

#[tokio::test]
async fn portal_code_mail_follows_the_route_and_never_goes_in_clear() {
    let h = Harness::new(Vec::new(), |_, _| {}).await;
    let mailer = SpoolMailer {
        spool: Arc::new(Spool::open(&h.cfg.spool.dir).await.unwrap()),
        cfg: Arc::new(h.cfg.clone()),
    };
    for (asked, sent) in [
        (TlsRequirement::None, TlsRequirement::Required),
        (TlsRequirement::Dane, TlsRequirement::Dane),
    ] {
        let issued = currawong_dlp::encrypt::Issued {
            recipient: "ops@partner.test".into(),
            code: "123456".into(),
            route: Route {
                tenant_id: Some("t1".into()),
                tls: asked,
            },
        };
        mailer.send_code(&issued).await.unwrap();
        let outgoing = h.outgoing().await;
        let (env, body) = outgoing
            .iter()
            .find(|(env, _)| env.tls == sent)
            .expect("code mail spooled");
        assert_eq!(env.rcpt_to, ["ops@partner.test"]);
        assert_eq!(env.tenant_id.as_deref(), Some("t1"));
        assert_eq!(env.direction, Direction::Outbound);
        assert!(String::from_utf8_lossy(body).contains("123456"));
    }
}

#[tokio::test]
async fn encrypt_with_neither_a_certificate_nor_the_portal_is_quarantined() {
    for action in [Action::Encrypt, Action::EncryptSmime, Action::EncryptPortal] {
        let mut h = Harness::new(vec![action.clone()], |cfg, dir| {
            cfg.encrypt.smime_certs_dir = Some(dir.join("certs"));
        })
        .await;
        h.classify().await;
        let original = h.original().await;
        assert_eq!(original.pipeline, "quarantine", "{action:?}");
        assert!(h.outgoing().await.is_empty());
        let reason = h.quarantine.reason(ID).unwrap();
        assert!(reason.starts_with("encrypt"), "{reason}");
    }
}

#[tokio::test]
async fn encrypt_sends_smime_when_the_recipient_certificate_is_known() {
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let pem = key.to_pkcs8_pem(Default::default()).unwrap();
    let pair = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let cert = params.self_signed(&pair).unwrap();
    let mut h = Harness::new(vec![Action::Encrypt], |cfg, dir| {
        let certs = dir.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("ops@partner.test.pem"), cert.pem()).unwrap();
        cfg.encrypt.smime_certs_dir = Some(certs);
    })
    .await;
    h.classify().await;
    assert_eq!(h.original().await.pipeline, "encrypted");
    let outgoing = h.outgoing().await;
    assert_eq!(outgoing.len(), 1);
    let (env, body) = &outgoing[0];
    assert_eq!(env.rcpt_to, ["ops@partner.test"]);
    assert_eq!(env.mail_from, "payroll@example.test");
    let text = String::from_utf8_lossy(body);
    assert!(text.contains("Subject: Payroll\r\n"));
    assert!(text.contains("application/pkcs7-mime; smime-type=enveloped-data"));
    assert!(!text.contains("Payroll run attached"));
}
